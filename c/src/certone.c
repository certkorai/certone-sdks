/*
 * CertOne C SDK: control-plane client over libcurl (SPEC.md).
 */
#define _POSIX_C_SOURCE 200809L

#include "internal.h"

#include <curl/curl.h>

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define DEFAULT_CONNECT_TIMEOUT_MS 5000L
#define DEFAULT_TIMEOUT_MS 30000L
#define DEFAULT_MAX_RESPONSE ((size_t)64 * 1024 * 1024)
#define DEFAULT_POLL_INTERVAL_MS 2000L
#define DEFAULT_WAIT_TIMEOUT_MS 900000L
#define ERROR_MESSAGE_SIZE 1024

#if defined(__GNUC__)
#define CERTONE_PRINTF(fmt, args) __attribute__((format(printf, fmt, args)))
#else
#define CERTONE_PRINTF(fmt, args)
#endif

struct certone_client {
    CURL *curl;
    char *base_url;    /* without trailing '/' */
    char *auth_header; /* "Authorization: Bearer <token>" or NULL; wiped on free */
    char *user_agent;
    char *ca_bundle;
    long connect_timeout_ms;
    long timeout_ms;
    size_t max_response;
    long last_http_status;
    char last_error[ERROR_MESSAGE_SIZE];
    char curl_error[CURL_ERROR_SIZE];
};

/* ---- small utilities ------------------------------------------------------------------- */

static void secure_wipe(void *p, size_t n)
{
    volatile unsigned char *v = (volatile unsigned char *)p;
    while (n-- > 0) {
        *v++ = 0;
    }
}

static char *dup_str(const char *s)
{
    size_t n = strlen(s) + 1;
    char *d = (char *)malloc(n);
    if (d != NULL) {
        memcpy(d, s, n);
    }
    return d;
}

/* 1 if s contains no ASCII control character (header-injection guard). */
static int is_header_safe(const char *s)
{
    for (; *s != '\0'; s++) {
        unsigned char c = (unsigned char)*s;
        if (c < 0x20 || c == 0x7F) {
            return 0;
        }
    }
    return 1;
}

static CERTONE_PRINTF(3, 4) certone_status fail(certone_client *c, certone_status st,
                                                const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(c->last_error, sizeof c->last_error, fmt, ap);
    va_end(ap);
    return st;
}

const char *certone_status_str(certone_status status)
{
    switch (status) {
    case CERTONE_OK: return "CERTONE_OK: success";
    case CERTONE_E_INVALID_ARG: return "CERTONE_E_INVALID_ARG: invalid argument";
    case CERTONE_E_NOMEM: return "CERTONE_E_NOMEM: out of memory";
    case CERTONE_E_IO: return "CERTONE_E_IO: local I/O error";
    case CERTONE_E_NETWORK: return "CERTONE_E_NETWORK: network error";
    case CERTONE_E_TIMEOUT: return "CERTONE_E_TIMEOUT: timed out";
    case CERTONE_E_HTTP: return "CERTONE_E_HTTP: HTTP error";
    case CERTONE_E_SCAN_FAILED: return "CERTONE_E_SCAN_FAILED: scan failed";
    case CERTONE_E_JSON: return "CERTONE_E_JSON: malformed JSON";
    case CERTONE_E_NOT_FOUND: return "CERTONE_E_NOT_FOUND: JSON path not found";
    case CERTONE_E_TYPE: return "CERTONE_E_TYPE: JSON value has another type";
    case CERTONE_E_RANGE: return "CERTONE_E_RANGE: JSON number out of range";
    case CERTONE_E_TOO_LARGE: return "CERTONE_E_TOO_LARGE: response too large";
    }
    return "CERTONE_E_UNKNOWN: unknown status";
}

const char *certone_version(void)
{
    return CERTONE_VERSION_STRING;
}

void certone_free(void *ptr)
{
    free(ptr);
}

/* ---- buffer ---------------------------------------------------------------------------- */

void certone__buf_free(certone_buf *b)
{
    free(b->data);
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

certone_status certone__buf_append(certone_buf *b, const void *data, size_t len)
{
    size_t need;

    if (b->limit != 0 && (len > b->limit || b->len > b->limit - len)) {
        b->overflow = 1;
        return CERTONE_E_TOO_LARGE;
    }
    if (len > ((size_t)-1) - b->len - 1) {
        b->nomem = 1;
        return CERTONE_E_NOMEM;
    }
    need = b->len + len + 1;
    if (need > b->cap) {
        size_t cap = b->cap == 0 ? 256 : b->cap;
        char *grown;
        while (cap < need) {
            if (cap > ((size_t)-1) / 2) {
                cap = need;
                break;
            }
            cap *= 2;
        }
        grown = (char *)realloc(b->data, cap);
        if (grown == NULL) {
            b->nomem = 1;
            return CERTONE_E_NOMEM;
        }
        b->data = grown;
        b->cap = cap;
    }
    if (len > 0) {
        memcpy(b->data + b->len, data, len);
    }
    b->len += len;
    b->data[b->len] = '\0';
    return CERTONE_OK;
}

certone_status certone__buf_append_str(certone_buf *b, const char *s)
{
    return certone__buf_append(b, s, strlen(s));
}

certone_status certone__buf_append_json_string(certone_buf *b, const char *s)
{
    static const char hex[] = "0123456789abcdef";
    size_t n = strlen(s);
    size_t i;
    size_t run = 0; /* start of the pending run of bytes that need no escaping */
    certone_status st;

    if (!certone__utf8_valid(s, n)) {
        return CERTONE_E_INVALID_ARG;
    }
    st = certone__buf_append(b, "\"", 1);
    for (i = 0; st == CERTONE_OK && i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        char esc[7];
        size_t esc_len = 0;
        if (c == '"' || c == '\\') {
            esc[0] = '\\';
            esc[1] = (char)c;
            esc_len = 2;
        } else if (c == '\n') {
            memcpy(esc, "\\n", 2);
            esc_len = 2;
        } else if (c == '\r') {
            memcpy(esc, "\\r", 2);
            esc_len = 2;
        } else if (c == '\t') {
            memcpy(esc, "\\t", 2);
            esc_len = 2;
        } else if (c < 0x20 || c == 0x7F) {
            esc[0] = '\\';
            esc[1] = 'u';
            esc[2] = '0';
            esc[3] = '0';
            esc[4] = hex[c >> 4];
            esc[5] = hex[c & 0x0F];
            esc_len = 6;
        }
        if (esc_len > 0) {
            st = certone__buf_append(b, s + run, i - run);
            if (st == CERTONE_OK) {
                st = certone__buf_append(b, esc, esc_len);
            }
            run = i + 1;
        }
    }
    if (st == CERTONE_OK) {
        st = certone__buf_append(b, s + run, n - run);
    }
    if (st == CERTONE_OK) {
        st = certone__buf_append(b, "\"", 1);
    }
    return st;
}

/* ---- request building (pure, unit-tested) ---------------------------------------------- */

certone_status certone__percent_encode(const char *segment, char **out)
{
    static const char hex[] = "0123456789ABCDEF";
    size_t n;
    size_t i;
    size_t j = 0;
    char *enc;

    if (segment == NULL || out == NULL) {
        return CERTONE_E_INVALID_ARG;
    }
    *out = NULL;
    n = strlen(segment);
    if (n == 0 || n > ((size_t)-1 - 1) / 3) {
        return CERTONE_E_INVALID_ARG;
    }
    enc = (char *)malloc(3 * n + 1);
    if (enc == NULL) {
        return CERTONE_E_NOMEM;
    }
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)segment[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
            c == '-' || c == '.' || c == '_' || c == '~') {
            enc[j++] = (char)c;
        } else {
            enc[j++] = '%';
            enc[j++] = hex[c >> 4];
            enc[j++] = hex[c & 0x0F];
        }
    }
    enc[j] = '\0';
    *out = enc;
    return CERTONE_OK;
}

static certone_status append_field(certone_buf *b, const char *name, const char *value)
{
    certone_status st;
    if (value == NULL) {
        return CERTONE_OK;
    }
    st = certone__buf_append_str(b, ",\"");
    if (st == CERTONE_OK) {
        st = certone__buf_append_str(b, name);
    }
    if (st == CERTONE_OK) {
        st = certone__buf_append_str(b, "\":");
    }
    if (st == CERTONE_OK) {
        st = certone__buf_append_json_string(b, value);
    }
    return st;
}

certone_status certone__build_ingest_body(const char *report_json,
                                          const certone_ingest_options *options, char **out)
{
    certone_buf b;
    certone_status st;
    certone_json_type type;
    size_t start;
    size_t end;

    if (report_json == NULL || out == NULL) {
        return CERTONE_E_INVALID_ARG;
    }
    *out = NULL;
    st = certone_json_type_at(report_json, "", &type);
    if (st != CERTONE_OK) {
        return st;
    }
    if (type != CERTONE_JSON_OBJECT) {
        return CERTONE_E_TYPE;
    }
    /* Embed the report verbatim, without its surrounding whitespace. */
    start = 0;
    while (report_json[start] == ' ' || report_json[start] == '\t' ||
           report_json[start] == '\n' || report_json[start] == '\r') {
        start++;
    }
    end = strlen(report_json);
    while (end > start && (report_json[end - 1] == ' ' || report_json[end - 1] == '\t' ||
                           report_json[end - 1] == '\n' || report_json[end - 1] == '\r')) {
        end--;
    }
    memset(&b, 0, sizeof b);
    st = certone__buf_append_str(&b, "{\"report\":");
    if (st == CERTONE_OK) {
        st = certone__buf_append(&b, report_json + start, end - start);
    }
    if (options != NULL) {
        if (st == CERTONE_OK) {
            st = append_field(&b, "asset", options->asset);
        }
        if (st == CERTONE_OK) {
            st = append_field(&b, "environment", options->environment);
        }
        if (st == CERTONE_OK) {
            st = append_field(&b, "country_code", options->country_code);
        }
        if (st == CERTONE_OK) {
            st = append_field(&b, "snapshot_ref", options->snapshot_ref);
        }
        if (st == CERTONE_OK) {
            st = append_field(&b, "input_digest", options->input_digest);
        }
        if (st == CERTONE_OK) {
            st = append_field(&b, "repo", options->repo);
        }
        if (st == CERTONE_OK) {
            st = append_field(&b, "commit_hash", options->commit_hash);
        }
    }
    if (st == CERTONE_OK) {
        st = certone__buf_append_str(&b, "}");
    }
    if (st != CERTONE_OK) {
        certone__buf_free(&b);
        return st;
    }
    *out = b.data;
    return CERTONE_OK;
}

size_t certone__scan_fields(const certone_scan_options *o, int include_tee, const char *names[8],
                            const char *values[8])
{
    size_t n = 0;

    if (o == NULL) {
        return 0;
    }
#define CERTONE_FIELD(field)                                                                   \
    do {                                                                                       \
        if (o->field != NULL) {                                                                \
            names[n] = #field;                                                                 \
            values[n] = o->field;                                                              \
            n++;                                                                               \
        }                                                                                      \
    } while (0)
    CERTONE_FIELD(asset);
    CERTONE_FIELD(environment);
    CERTONE_FIELD(country_code);
    CERTONE_FIELD(fail_on);
    CERTONE_FIELD(packs);
    CERTONE_FIELD(snapshot_ref);
    CERTONE_FIELD(commit_hash);
    if (include_tee) {
        CERTONE_FIELD(tee);
    }
#undef CERTONE_FIELD
    return n;
}

/* Copy src (len bytes) into out, mapping control characters to spaces and truncating on a
 * UTF-8 sequence boundary. */
static void copy_sanitized(const char *src, size_t len, char *out, size_t out_size)
{
    size_t i;
    size_t n = len < out_size - 1 ? len : out_size - 1;

    if (n < len) {
        /* Do not cut a multi-byte sequence: back off over continuation bytes. */
        while (n > 0 && ((unsigned char)src[n] & 0xC0) == 0x80) {
            n--;
        }
    }
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)src[i];
        out[i] = (c < 0x20 || c == 0x7F) ? ' ' : (char)c;
    }
    out[n] = '\0';
}

void certone__error_detail(const char *body, size_t body_len, char *out, size_t out_size)
{
    certone_json_type type;
    char *detail = NULL;

    if (out == NULL || out_size == 0) {
        return;
    }
    out[0] = '\0';
    if (body == NULL || body_len == 0) {
        return;
    }
    if (strlen(body) == body_len && certone_json_type_at(body, "detail", &type) == CERTONE_OK) {
        certone_status st = type == CERTONE_JSON_STRING
                                ? certone_json_get_string(body, "detail", &detail)
                                : certone_json_get_raw(body, "detail", &detail);
        if (st == CERTONE_OK) {
            copy_sanitized(detail, strlen(detail), out, out_size);
            free(detail);
            return;
        }
    }
    copy_sanitized(body, body_len, out, out_size);
}

/* ---- lifecycle ------------------------------------------------------------------------- */

certone_status certone_global_init(void)
{
    return curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK ? CERTONE_OK : CERTONE_E_NETWORK;
}

void certone_global_cleanup(void)
{
    curl_global_cleanup();
}

static int has_http_scheme(const char *url)
{
    size_t i;
    static const char http[] = "http://";
    static const char https[] = "https://";
    for (i = 0; i < sizeof https - 1; i++) {
        if (url[i] == '\0' || tolower((unsigned char)url[i]) != https[i]) {
            break;
        }
    }
    if (i == sizeof https - 1) {
        return url[i] != '\0';
    }
    for (i = 0; i < sizeof http - 1; i++) {
        if (url[i] == '\0' || tolower((unsigned char)url[i]) != http[i]) {
            return 0;
        }
    }
    return url[i] != '\0';
}

void certone_client_free(certone_client *c)
{
    if (c == NULL) {
        return;
    }
    if (c->curl != NULL) {
        curl_easy_cleanup(c->curl);
    }
    if (c->auth_header != NULL) {
        secure_wipe(c->auth_header, strlen(c->auth_header));
        free(c->auth_header);
    }
    free(c->base_url);
    free(c->user_agent);
    free(c->ca_bundle);
    free(c);
}

certone_status certone_client_new(const certone_config *cfg, certone_client **out)
{
    certone_client *c;
    size_t n;

    if (out == NULL) {
        return CERTONE_E_INVALID_ARG;
    }
    *out = NULL;
    if (cfg == NULL || cfg->base_url == NULL || !has_http_scheme(cfg->base_url) ||
        !is_header_safe(cfg->base_url) || strchr(cfg->base_url, ' ') != NULL) {
        return CERTONE_E_INVALID_ARG;
    }
    if ((cfg->token != NULL && (cfg->token[0] == '\0' || !is_header_safe(cfg->token))) ||
        (cfg->user_agent != NULL && !is_header_safe(cfg->user_agent)) ||
        cfg->connect_timeout_ms < 0 || cfg->timeout_ms < 0) {
        return CERTONE_E_INVALID_ARG;
    }
    c = (certone_client *)calloc(1, sizeof *c);
    if (c == NULL) {
        return CERTONE_E_NOMEM;
    }
    c->connect_timeout_ms = cfg->connect_timeout_ms > 0 ? cfg->connect_timeout_ms
                                                        : DEFAULT_CONNECT_TIMEOUT_MS;
    c->timeout_ms = cfg->timeout_ms > 0 ? cfg->timeout_ms : DEFAULT_TIMEOUT_MS;
    c->max_response = cfg->max_response_bytes > 0 ? cfg->max_response_bytes
                                                  : DEFAULT_MAX_RESPONSE;
    c->base_url = dup_str(cfg->base_url);
    c->user_agent = dup_str(cfg->user_agent != NULL ? cfg->user_agent
                                                    : "certone-c/" CERTONE_VERSION_STRING);
    if (cfg->ca_bundle_path != NULL) {
        c->ca_bundle = dup_str(cfg->ca_bundle_path);
    }
    if (cfg->token != NULL) {
        static const char prefix[] = "Authorization: Bearer ";
        size_t tlen = strlen(cfg->token);
        c->auth_header = (char *)malloc(sizeof prefix + tlen);
        if (c->auth_header != NULL) {
            memcpy(c->auth_header, prefix, sizeof prefix - 1);
            memcpy(c->auth_header + sizeof prefix - 1, cfg->token, tlen + 1);
        }
    }
    c->curl = curl_easy_init();
    if (c->base_url == NULL || c->user_agent == NULL ||
        (cfg->ca_bundle_path != NULL && c->ca_bundle == NULL) ||
        (cfg->token != NULL && c->auth_header == NULL) || c->curl == NULL) {
        certone_client_free(c);
        return CERTONE_E_NOMEM;
    }
    n = strlen(c->base_url);
    while (n > 0 && c->base_url[n - 1] == '/') {
        c->base_url[--n] = '\0';
    }
    *out = c;
    return CERTONE_OK;
}

const char *certone_last_error(const certone_client *c)
{
    return c != NULL ? c->last_error : "";
}

long certone_last_http_status(const certone_client *c)
{
    return c != NULL ? c->last_http_status : 0;
}

/* ---- HTTP core ------------------------------------------------------------------------- */

static size_t write_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    certone_buf *b = (certone_buf *)userdata;
    size_t total;

    if (size != 0 && nmemb > ((size_t)-1) / size) {
        b->overflow = 1;
        return 0;
    }
    total = size * nmemb;
    if (certone__buf_append(b, ptr, total) != CERTONE_OK) {
        return 0; /* abort the transfer; overflow/nomem flag says why */
    }
    return total;
}

/* In-memory snapshot upload source (streamed, so the bytes are not copied). */
typedef struct mem_source {
    const unsigned char *data;
    size_t size;
    size_t pos;
} mem_source;

static size_t mem_read_cb(char *buffer, size_t size, size_t nitems, void *arg)
{
    mem_source *m = (mem_source *)arg;
    size_t room = size * nitems;
    size_t left = m->size - m->pos;
    size_t n = left < room ? left : room;
    memcpy(buffer, m->data + m->pos, n);
    m->pos += n;
    return n;
}

static int mem_seek_cb(void *arg, curl_off_t offset, int origin)
{
    mem_source *m = (mem_source *)arg;
    curl_off_t base;
    curl_off_t target;

    switch (origin) {
    case SEEK_SET: base = 0; break;
    case SEEK_CUR: base = (curl_off_t)m->pos; break;
    case SEEK_END: base = (curl_off_t)m->size; break;
    default: return CURL_SEEKFUNC_FAIL;
    }
    target = base + offset;
    if (target < 0 || (unsigned long long)target > (unsigned long long)m->size) {
        return CURL_SEEKFUNC_FAIL;
    }
    m->pos = (size_t)target;
    return CURL_SEEKFUNC_OK;
}

static certone_status setopt_failed(certone_client *c, CURLcode rc, const char *what)
{
    certone_status st = rc == CURLE_OUT_OF_MEMORY ? CERTONE_E_NOMEM : CERTONE_E_NETWORK;
    return fail(c, st, "libcurl option %s rejected: %s", what, curl_easy_strerror(rc));
}

#define SETOPT(opt, val)                                                                       \
    do {                                                                                       \
        CURLcode rc_ = curl_easy_setopt(c->curl, opt, val);                                    \
        if (rc_ != CURLE_OK) {                                                                 \
            st = setopt_failed(c, rc_, #opt);                                                  \
            goto done;                                                                         \
        }                                                                                      \
    } while (0)

static void begin(certone_client *c)
{
    c->last_error[0] = '\0';
    c->curl_error[0] = '\0';
    c->last_http_status = 0;
}

/* Perform one request. json_body (POST JSON) and mime (POST multipart) are mutually exclusive;
 * neither means GET. On success *out_json receives the validated JSON body. */
static certone_status perform(certone_client *c, const char *method, const char *path,
                              const char *json_body, curl_mime *mime, char **out_json)
{
    certone_status st = CERTONE_OK;
    struct curl_slist *headers = NULL;
    struct curl_slist *tmp;
    certone_buf url;
    certone_buf body;
    CURLcode rc;
    long http_status = 0;

    memset(&url, 0, sizeof url);
    memset(&body, 0, sizeof body);
    body.limit = c->max_response;

    st = certone__buf_append_str(&url, c->base_url);
    if (st == CERTONE_OK) {
        st = certone__buf_append_str(&url, path);
    }
    if (st != CERTONE_OK) {
        st = fail(c, CERTONE_E_NOMEM, "out of memory building the request URL");
        goto done;
    }

#define ADD_HEADER(h)                                                                          \
    do {                                                                                       \
        tmp = curl_slist_append(headers, h);                                                   \
        if (tmp == NULL) {                                                                     \
            st = fail(c, CERTONE_E_NOMEM, "out of memory building request headers");           \
            goto done;                                                                         \
        }                                                                                      \
        headers = tmp;                                                                         \
    } while (0)
    ADD_HEADER("Accept: application/json");
    ADD_HEADER("Expect:"); /* no 100-continue round trip on uploads */
    if (json_body != NULL) {
        ADD_HEADER("Content-Type: application/json");
    }
    if (c->auth_header != NULL) {
        ADD_HEADER(c->auth_header);
    }
#undef ADD_HEADER

    curl_easy_reset(c->curl);
    SETOPT(CURLOPT_ERRORBUFFER, c->curl_error);
    SETOPT(CURLOPT_URL, url.data);
#if LIBCURL_VERSION_NUM >= 0x075500
    SETOPT(CURLOPT_PROTOCOLS_STR, "http,https");
#else
    SETOPT(CURLOPT_PROTOCOLS, (long)(CURLPROTO_HTTP | CURLPROTO_HTTPS));
#endif
    SETOPT(CURLOPT_NOSIGNAL, 1L);
    SETOPT(CURLOPT_FOLLOWLOCATION, 0L); /* never forward the token to another location */
    SETOPT(CURLOPT_SSL_VERIFYPEER, 1L);
    SETOPT(CURLOPT_SSL_VERIFYHOST, 2L);
    SETOPT(CURLOPT_CONNECTTIMEOUT_MS, c->connect_timeout_ms);
    SETOPT(CURLOPT_TIMEOUT_MS, c->timeout_ms);
    SETOPT(CURLOPT_USERAGENT, c->user_agent);
    SETOPT(CURLOPT_HTTPHEADER, headers);
    SETOPT(CURLOPT_WRITEFUNCTION, write_cb);
    SETOPT(CURLOPT_WRITEDATA, &body);
    if (c->ca_bundle != NULL) {
        SETOPT(CURLOPT_CAINFO, c->ca_bundle);
    }
    if (json_body != NULL) {
        SETOPT(CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)strlen(json_body));
        SETOPT(CURLOPT_POSTFIELDS, json_body);
    } else if (mime != NULL) {
        SETOPT(CURLOPT_MIMEPOST, mime);
    } else {
        SETOPT(CURLOPT_HTTPGET, 1L);
    }

    rc = curl_easy_perform(c->curl);
    if (rc != CURLE_OK) {
        if (body.overflow) {
            st = fail(c, CERTONE_E_TOO_LARGE, "%s %s: response exceeds %zu bytes", method, path,
                      c->max_response);
        } else if (body.nomem || rc == CURLE_OUT_OF_MEMORY) {
            st = fail(c, CERTONE_E_NOMEM, "%s %s: out of memory", method, path);
        } else if (rc == CURLE_OPERATION_TIMEDOUT) {
            st = fail(c, CERTONE_E_TIMEOUT, "%s %s: timed out: %s", method, path,
                      c->curl_error[0] != '\0' ? c->curl_error : curl_easy_strerror(rc));
        } else if (rc == CURLE_READ_ERROR) {
            st = fail(c, CERTONE_E_IO, "%s %s: reading the upload failed: %s", method, path,
                      c->curl_error[0] != '\0' ? c->curl_error : curl_easy_strerror(rc));
        } else {
            st = fail(c, CERTONE_E_NETWORK, "%s %s: %s", method, path,
                      c->curl_error[0] != '\0' ? c->curl_error : curl_easy_strerror(rc));
        }
        goto done;
    }
    rc = curl_easy_getinfo(c->curl, CURLINFO_RESPONSE_CODE, &http_status);
    if (rc != CURLE_OK) {
        st = fail(c, CERTONE_E_NETWORK, "%s %s: no HTTP status: %s", method, path,
                  curl_easy_strerror(rc));
        goto done;
    }
    c->last_http_status = http_status;
    if (http_status < 200 || http_status >= 300) {
        char detail[ERROR_MESSAGE_SIZE - 32];
        certone__error_detail(body.data, body.len, detail, sizeof detail);
        st = fail(c, CERTONE_E_HTTP, "HTTP %ld: %s", http_status, detail);
        goto done;
    }
    if (body.data == NULL || certone_json_validate(body.data) != CERTONE_OK) {
        st = fail(c, CERTONE_E_JSON, "%s %s: HTTP %ld response is not valid JSON", method, path,
                  http_status);
        goto done;
    }
    *out_json = body.data;
    body.data = NULL;
    st = CERTONE_OK;

done:
    /* Detach caller-owned objects from the handle before they are freed. */
    curl_easy_reset(c->curl);
    curl_slist_free_all(headers);
    certone__buf_free(&url);
    certone__buf_free(&body);
    return st;
}

#undef SETOPT

/* "/v1/<prefix>/<id-encoded><suffix>" */
static certone_status id_path(certone_client *c, const char *prefix, const char *id,
                              const char *suffix, char **out)
{
    certone_buf b;
    char *enc = NULL;
    certone_status st;

    *out = NULL;
    if (id == NULL || id[0] == '\0') {
        return fail(c, CERTONE_E_INVALID_ARG, "an id is required");
    }
    st = certone__percent_encode(id, &enc);
    if (st != CERTONE_OK) {
        return fail(c, st, "cannot encode id");
    }
    memset(&b, 0, sizeof b);
    st = certone__buf_append_str(&b, prefix);
    if (st == CERTONE_OK) {
        st = certone__buf_append_str(&b, enc);
    }
    if (st == CERTONE_OK) {
        st = certone__buf_append_str(&b, suffix);
    }
    free(enc);
    if (st != CERTONE_OK) {
        certone__buf_free(&b);
        return fail(c, CERTONE_E_NOMEM, "out of memory building the request path");
    }
    *out = b.data;
    return CERTONE_OK;
}

static certone_status get_json(certone_client *c, const char *path, char **out_json)
{
    return perform(c, "GET", path, NULL, NULL, out_json);
}

static certone_status get_by_id(certone_client *c, const char *prefix, const char *id,
                                const char *suffix, char **out_json)
{
    char *path = NULL;
    certone_status st = id_path(c, prefix, id, suffix, &path);
    if (st == CERTONE_OK) {
        st = get_json(c, path, out_json);
        free(path);
    }
    return st;
}

static int check_out(certone_client *c, char **out_json)
{
    if (c == NULL) {
        return 0;
    }
    begin(c);
    if (out_json == NULL) {
        fail(c, CERTONE_E_INVALID_ARG, "out_json is required");
        return 0;
    }
    *out_json = NULL;
    return 1;
}

/* ---- multipart scan submission ---------------------------------------------------------- */

static int filename_safe(const char *s)
{
    return is_header_safe(s) && strchr(s, '"') == NULL && strchr(s, '\\') == NULL;
}

static certone_status submit_scan(certone_client *c, const char *endpoint, int include_tee,
                                  const certone_snapshot *snap, const certone_scan_options *opts,
                                  char **out_json)
{
    curl_mime *mime = NULL;
    curl_mimepart *part;
    mem_source src;
    const char *names[8];
    const char *values[8];
    size_t nfields;
    size_t i;
    CURLcode rc;
    certone_status st;

    if (!check_out(c, out_json)) {
        return CERTONE_E_INVALID_ARG;
    }
    if (snap == NULL || (snap->path == NULL && snap->data == NULL) ||
        (snap->path != NULL && snap->data != NULL) || (snap->path != NULL && snap->path[0] == '\0') ||
        (snap->data != NULL && snap->size == 0)) {
        return fail(c, CERTONE_E_INVALID_ARG,
                    "snapshot: set exactly one of path or data (with a non-zero size)");
    }
    if (snap->filename != NULL && (snap->filename[0] == '\0' || !filename_safe(snap->filename))) {
        return fail(c, CERTONE_E_INVALID_ARG, "snapshot filename contains forbidden characters");
    }
    if (snap->path != NULL) {
        FILE *f = fopen(snap->path, "rb");
        if (f == NULL) {
            return fail(c, CERTONE_E_IO, "cannot open snapshot %s: %s", snap->path,
                        strerror(errno));
        }
        fclose(f);
    }

    mime = curl_mime_init(c->curl);
    if (mime == NULL) {
        return fail(c, CERTONE_E_NOMEM, "out of memory building the multipart body");
    }
    nfields = certone__scan_fields(opts, include_tee, names, values);
    for (i = 0; i < nfields; i++) {
        part = curl_mime_addpart(mime);
        if (part == NULL) {
            st = fail(c, CERTONE_E_NOMEM, "out of memory building the multipart body");
            goto done;
        }
        rc = curl_mime_name(part, names[i]);
        if (rc == CURLE_OK) {
            rc = curl_mime_data(part, values[i], CURL_ZERO_TERMINATED);
        }
        if (rc != CURLE_OK) {
            st = setopt_failed(c, rc, names[i]);
            goto done;
        }
    }
    part = curl_mime_addpart(mime);
    if (part == NULL) {
        st = fail(c, CERTONE_E_NOMEM, "out of memory building the multipart body");
        goto done;
    }
    rc = curl_mime_name(part, "snapshot");
    if (rc == CURLE_OK) {
        if (snap->path != NULL) {
            rc = curl_mime_filedata(part, snap->path); /* also sets filename = basename */
        } else {
            src.data = (const unsigned char *)snap->data;
            src.size = snap->size;
            src.pos = 0;
            rc = curl_mime_data_cb(part, (curl_off_t)snap->size, mem_read_cb, mem_seek_cb, NULL,
                                   &src);
            if (rc == CURLE_OK && snap->filename == NULL) {
                rc = curl_mime_filename(part, "snapshot.tar.gz");
            }
        }
    }
    if (rc == CURLE_OK && snap->filename != NULL) {
        rc = curl_mime_filename(part, snap->filename);
    }
    if (rc == CURLE_OK) {
        rc = curl_mime_type(part, "application/gzip");
    }
    if (rc != CURLE_OK) {
        st = rc == CURLE_READ_ERROR ? fail(c, CERTONE_E_IO, "cannot read snapshot %s",
                                           snap->path != NULL ? snap->path : "(memory)")
                                    : setopt_failed(c, rc, "snapshot part");
        goto done;
    }
    st = perform(c, "POST", endpoint, NULL, mime, out_json);

done:
    curl_mime_free(mime);
    return st;
}

certone_status certone_submit_check(certone_client *c, const certone_snapshot *snapshot,
                                    const certone_scan_options *options, char **out_json)
{
    return submit_scan(c, "/v1/checks", 0, snapshot, options, out_json);
}

certone_status certone_submit_process(certone_client *c, const certone_snapshot *snapshot,
                                      const certone_scan_options *options, char **out_json)
{
    return submit_scan(c, "/v1/process", 1, snapshot, options, out_json);
}

/* ---- reads ------------------------------------------------------------------------------ */

certone_status certone_get_scan(certone_client *c, const char *scan_id, char **out_json)
{
    if (!check_out(c, out_json)) {
        return CERTONE_E_INVALID_ARG;
    }
    return get_by_id(c, "/v1/scans/", scan_id, "", out_json);
}

certone_status certone_get_report_document(certone_client *c, const char *report_id,
                                           char **out_json)
{
    if (!check_out(c, out_json)) {
        return CERTONE_E_INVALID_ARG;
    }
    return get_by_id(c, "/v1/reports/", report_id, "/document", out_json);
}

certone_status certone_get_attestation(certone_client *c, const char *report_id, char **out_json)
{
    if (!check_out(c, out_json)) {
        return CERTONE_E_INVALID_ARG;
    }
    return get_by_id(c, "/v1/reports/", report_id, "/attestation", out_json);
}

certone_status certone_list_systems(certone_client *c, char **out_json)
{
    if (!check_out(c, out_json)) {
        return CERTONE_E_INVALID_ARG;
    }
    return get_json(c, "/v1/systems", out_json);
}

certone_status certone_ingest_report(certone_client *c, const char *report_json,
                                     const certone_ingest_options *options, char **out_json)
{
    char *body = NULL;
    certone_status st;

    if (!check_out(c, out_json)) {
        return CERTONE_E_INVALID_ARG;
    }
    st = certone__build_ingest_body(report_json, options, &body);
    switch (st) {
    case CERTONE_OK: break;
    case CERTONE_E_NOMEM: return fail(c, st, "out of memory building the ingest body");
    case CERTONE_E_INVALID_ARG:
        return fail(c, st, "report is required and option strings must be valid UTF-8");
    case CERTONE_E_TYPE: return fail(c, st, "report must be a JSON object");
    default: return fail(c, CERTONE_E_JSON, "report is not valid JSON");
    }
    st = perform(c, "POST", "/v1/checks/report", body, NULL, out_json);
    free(body);
    return st;
}

/* ---- wait_for_report ------------------------------------------------------------------- */

static long long monotonic_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000L;
}

static void sleep_ms(long long ms)
{
    struct timespec req;
    struct timespec rem;
    if (ms <= 0) {
        return;
    }
    req.tv_sec = (time_t)(ms / 1000);
    req.tv_nsec = (long)(ms % 1000) * 1000000L;
    while (nanosleep(&req, &rem) != 0 && errno == EINTR) {
        req = rem;
    }
}

certone_status certone_wait_for_report(certone_client *c, const char *scan_id, long timeout_ms,
                                       long interval_ms, char **out_json)
{
    long long deadline;
    char last_status[64] = "unknown";

    if (!check_out(c, out_json)) {
        return CERTONE_E_INVALID_ARG;
    }
    if (timeout_ms < 0 || interval_ms < 0) {
        return fail(c, CERTONE_E_INVALID_ARG, "timeout and interval must be >= 0");
    }
    if (timeout_ms == 0) {
        timeout_ms = DEFAULT_WAIT_TIMEOUT_MS;
    }
    if (interval_ms == 0) {
        interval_ms = DEFAULT_POLL_INTERVAL_MS;
    }
    deadline = monotonic_ms() + timeout_ms;
    for (;;) {
        char *scan = NULL;
        char *status = NULL;
        certone_status st = get_by_id(c, "/v1/scans/", scan_id, "", &scan);
        long long now;

        if (st != CERTONE_OK) {
            return st;
        }
        st = certone_json_get_string(scan, "status", &status);
        if (st != CERTONE_OK) {
            free(scan);
            return fail(c, st == CERTONE_E_NOMEM ? st : CERTONE_E_JSON,
                        "scan %s: response has no string \"status\"", scan_id);
        }
        if (strcmp(status, "succeeded") == 0) {
            free(status);
            free(scan);
            return get_by_id(c, "/v1/scans/", scan_id, "/report", out_json);
        }
        if (strcmp(status, "failed") == 0) {
            char *error = NULL;
            certone_status est = certone_json_get_string(scan, "error", &error);
            fail(c, CERTONE_E_SCAN_FAILED, "scan %s failed: %s", scan_id,
                 est == CERTONE_OK && error[0] != '\0' ? error : "(no error message)");
            free(error);
            free(status);
            free(scan);
            return CERTONE_E_SCAN_FAILED;
        }
        copy_sanitized(status, strlen(status), last_status, sizeof last_status);
        free(status);
        free(scan);
        now = monotonic_ms();
        if (now >= deadline) {
            return fail(c, CERTONE_E_TIMEOUT, "scan %s did not finish within %ld ms (status %s)",
                        scan_id, timeout_ms, last_status);
        }
        sleep_ms(deadline - now < interval_ms ? deadline - now : interval_ms);
    }
}
