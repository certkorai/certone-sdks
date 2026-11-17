/*
 * Minimal, allocation-free JSON reader for the CertOne C SDK: validation (RFC 8259) plus
 * path-based access to values inside a response body. No DOM is built; every accessor walks
 * the text directly, so memory use is bounded by the size of the value being returned.
 */
#include "internal.h"

#include <errno.h>
#include <locale.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

#define CERTONE_JSON_MAX_DEPTH 256

typedef struct jparser {
    const char *s; /* NUL-terminated: JSON text cannot contain a raw NUL */
    size_t pos;
} jparser;

/* Receives the decoded bytes of a string: copies them and/or compares them to a key. */
typedef struct str_sink {
    char *out;         /* if non-NULL, decoded bytes are written here */
    size_t out_len;
    const char *cmp;   /* if non-NULL, decoded bytes are compared against cmp[0..cmp_len) */
    size_t cmp_len;
    size_t cmp_pos;
    int cmp_mismatch;
    int has_nul;       /* an escaped \u0000 was seen */
    int bad_surrogate; /* an unpaired UTF-16 surrogate escape was seen */
} str_sink;

static void skip_ws(jparser *p)
{
    for (;;) {
        char c = p->s[p->pos];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            p->pos++;
        } else {
            return;
        }
    }
}

static void sink_byte(str_sink *k, unsigned char b)
{
    if (k == NULL) {
        return;
    }
    if (k->out != NULL) {
        k->out[k->out_len++] = (char)b;
    }
    if (k->cmp != NULL && !k->cmp_mismatch) {
        if (k->cmp_pos < k->cmp_len && (unsigned char)k->cmp[k->cmp_pos] == b) {
            k->cmp_pos++;
        } else {
            k->cmp_mismatch = 1;
        }
    }
}

static void sink_codepoint(str_sink *k, unsigned long cp)
{
    if (cp < 0x80) {
        sink_byte(k, (unsigned char)cp);
    } else if (cp < 0x800) {
        sink_byte(k, (unsigned char)(0xC0 | (cp >> 6)));
        sink_byte(k, (unsigned char)(0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
        sink_byte(k, (unsigned char)(0xE0 | (cp >> 12)));
        sink_byte(k, (unsigned char)(0x80 | ((cp >> 6) & 0x3F)));
        sink_byte(k, (unsigned char)(0x80 | (cp & 0x3F)));
    } else {
        sink_byte(k, (unsigned char)(0xF0 | (cp >> 18)));
        sink_byte(k, (unsigned char)(0x80 | ((cp >> 12) & 0x3F)));
        sink_byte(k, (unsigned char)(0x80 | ((cp >> 6) & 0x3F)));
        sink_byte(k, (unsigned char)(0x80 | (cp & 0x3F)));
    }
}

/* Length of the well-formed UTF-8 sequence at s (lead byte >= 0x80), or 0 if ill-formed.
 * s must be readable up to its NUL terminator; a NUL never matches a continuation range. */
static size_t utf8_seq_len(const unsigned char *s)
{
    unsigned char c = s[0];
    unsigned char lo = 0x80;
    unsigned char hi = 0xBF;
    size_t n;
    size_t i;

    if (c >= 0xC2 && c <= 0xDF) {
        n = 2;
    } else if (c == 0xE0) {
        n = 3;
        lo = 0xA0;
    } else if ((c >= 0xE1 && c <= 0xEC) || c == 0xEE || c == 0xEF) {
        n = 3;
    } else if (c == 0xED) {
        n = 3;
        hi = 0x9F;
    } else if (c == 0xF0) {
        n = 4;
        lo = 0x90;
    } else if (c >= 0xF1 && c <= 0xF3) {
        n = 4;
    } else if (c == 0xF4) {
        n = 4;
        hi = 0x8F;
    } else {
        return 0;
    }
    if (s[1] < lo || s[1] > hi) {
        return 0;
    }
    for (i = 2; i < n; i++) {
        if (s[i] < 0x80 || s[i] > 0xBF) {
            return 0;
        }
    }
    return n;
}

int certone__utf8_valid(const char *s, size_t len)
{
    const unsigned char *u = (const unsigned char *)s;
    size_t i = 0;

    while (i < len) {
        unsigned char c = u[i];
        if (c < 0x80) {
            i++;
            continue;
        }
        {
            /* Bounded re-implementation of utf8_seq_len that never reads past len. */
            unsigned char lo = 0x80;
            unsigned char hi = 0xBF;
            size_t n;
            size_t j;
            if (c >= 0xC2 && c <= 0xDF) {
                n = 2;
            } else if (c == 0xE0) {
                n = 3;
                lo = 0xA0;
            } else if ((c >= 0xE1 && c <= 0xEC) || c == 0xEE || c == 0xEF) {
                n = 3;
            } else if (c == 0xED) {
                n = 3;
                hi = 0x9F;
            } else if (c == 0xF0) {
                n = 4;
                lo = 0x90;
            } else if (c >= 0xF1 && c <= 0xF3) {
                n = 4;
            } else if (c == 0xF4) {
                n = 4;
                hi = 0x8F;
            } else {
                return 0;
            }
            if (len - i < n || u[i + 1] < lo || u[i + 1] > hi) {
                return 0;
            }
            for (j = 2; j < n; j++) {
                if (u[i + j] < 0x80 || u[i + j] > 0xBF) {
                    return 0;
                }
            }
            i += n;
        }
    }
    return 1;
}

static int hex4(const char *s, unsigned long *out)
{
    unsigned long v = 0;
    int i;
    for (i = 0; i < 4; i++) {
        char c = s[i];
        v <<= 4;
        if (c >= '0' && c <= '9') {
            v |= (unsigned long)(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            v |= (unsigned long)(c - 'a' + 10);
        } else if (c >= 'A' && c <= 'F') {
            v |= (unsigned long)(c - 'A' + 10);
        } else {
            return -1;
        }
    }
    *out = v;
    return 0;
}

/* p->s[p->pos] == '"'. Validates and (optionally) decodes the string into k. */
static int scan_string(jparser *p, str_sink *k)
{
    const char *s = p->s;
    size_t i = p->pos + 1;

    for (;;) {
        unsigned char c = (unsigned char)s[i];
        if (c == '"') {
            p->pos = i + 1;
            return 0;
        }
        if (c < 0x20) { /* includes the NUL terminator: unterminated string */
            return -1;
        }
        if (c == '\\') {
            char e = s[i + 1];
            unsigned long cp;
            switch (e) {
            case '"': sink_byte(k, '"'); i += 2; continue;
            case '\\': sink_byte(k, '\\'); i += 2; continue;
            case '/': sink_byte(k, '/'); i += 2; continue;
            case 'b': sink_byte(k, '\b'); i += 2; continue;
            case 'f': sink_byte(k, '\f'); i += 2; continue;
            case 'n': sink_byte(k, '\n'); i += 2; continue;
            case 'r': sink_byte(k, '\r'); i += 2; continue;
            case 't': sink_byte(k, '\t'); i += 2; continue;
            case 'u': break;
            default: return -1;
            }
            /* hex4 stops at the first non-hex character, so it never reads past the NUL. */
            if (hex4(s + i + 2, &cp) != 0) {
                return -1;
            }
            i += 6;
            if (cp >= 0xD800 && cp <= 0xDBFF) {
                unsigned long lo;
                if (s[i] == '\\' && s[i + 1] == 'u' && hex4(s + i + 2, &lo) == 0 && lo >= 0xDC00 &&
                    lo <= 0xDFFF) {
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    i += 6;
                } else {
                    if (k != NULL) {
                        k->bad_surrogate = 1;
                    }
                    continue;
                }
            } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                if (k != NULL) {
                    k->bad_surrogate = 1;
                }
                continue;
            }
            if (cp == 0 && k != NULL) {
                k->has_nul = 1;
            }
            sink_codepoint(k, cp);
            continue;
        }
        if (c < 0x80) {
            sink_byte(k, c);
            i++;
            continue;
        }
        {
            size_t n = utf8_seq_len((const unsigned char *)s + i);
            size_t j;
            if (n == 0) {
                return -1;
            }
            for (j = 0; j < n; j++) {
                sink_byte(k, (unsigned char)s[i + j]);
            }
            i += n;
        }
    }
}

static int is_digit(char c)
{
    return c >= '0' && c <= '9';
}

/* Validates a number token. *is_integer is set when it has no fraction and no exponent. */
static int scan_number(jparser *p, int *is_integer)
{
    const char *s = p->s;
    size_t i = p->pos;
    int integer = 1;

    if (s[i] == '-') {
        i++;
    }
    if (s[i] == '0') {
        i++;
    } else if (s[i] >= '1' && s[i] <= '9') {
        while (is_digit(s[i])) {
            i++;
        }
    } else {
        return -1;
    }
    if (s[i] == '.') {
        integer = 0;
        i++;
        if (!is_digit(s[i])) {
            return -1;
        }
        while (is_digit(s[i])) {
            i++;
        }
    }
    if (s[i] == 'e' || s[i] == 'E') {
        integer = 0;
        i++;
        if (s[i] == '+' || s[i] == '-') {
            i++;
        }
        if (!is_digit(s[i])) {
            return -1;
        }
        while (is_digit(s[i])) {
            i++;
        }
    }
    if (is_integer != NULL) {
        *is_integer = integer;
    }
    p->pos = i;
    return 0;
}

static int scan_literal(jparser *p, const char *lit)
{
    size_t n = strlen(lit);
    if (strncmp(p->s + p->pos, lit, n) != 0) {
        return -1;
    }
    p->pos += n;
    return 0;
}

static int skip_value(jparser *p, int depth);

static int skip_array(jparser *p, int depth)
{
    p->pos++; /* '[' */
    skip_ws(p);
    if (p->s[p->pos] == ']') {
        p->pos++;
        return 0;
    }
    for (;;) {
        if (skip_value(p, depth + 1) != 0) {
            return -1;
        }
        skip_ws(p);
        if (p->s[p->pos] == ',') {
            p->pos++;
            skip_ws(p);
            continue;
        }
        if (p->s[p->pos] == ']') {
            p->pos++;
            return 0;
        }
        return -1;
    }
}

static int skip_object(jparser *p, int depth)
{
    p->pos++; /* '{' */
    skip_ws(p);
    if (p->s[p->pos] == '}') {
        p->pos++;
        return 0;
    }
    for (;;) {
        if (p->s[p->pos] != '"' || scan_string(p, NULL) != 0) {
            return -1;
        }
        skip_ws(p);
        if (p->s[p->pos] != ':') {
            return -1;
        }
        p->pos++;
        skip_ws(p);
        if (skip_value(p, depth + 1) != 0) {
            return -1;
        }
        skip_ws(p);
        if (p->s[p->pos] == ',') {
            p->pos++;
            skip_ws(p);
            continue;
        }
        if (p->s[p->pos] == '}') {
            p->pos++;
            return 0;
        }
        return -1;
    }
}

/* p is at the first character of a value (whitespace already skipped). */
static int skip_value(jparser *p, int depth)
{
    if (depth >= CERTONE_JSON_MAX_DEPTH) {
        return -1;
    }
    switch (p->s[p->pos]) {
    case '{': return skip_object(p, depth);
    case '[': return skip_array(p, depth);
    case '"': return scan_string(p, NULL);
    case 't': return scan_literal(p, "true");
    case 'f': return scan_literal(p, "false");
    case 'n': return scan_literal(p, "null");
    default: return scan_number(p, NULL);
    }
}

certone_status certone_json_validate(const char *json)
{
    jparser p;
    if (json == NULL) {
        return CERTONE_E_INVALID_ARG;
    }
    p.s = json;
    p.pos = 0;
    skip_ws(&p);
    if (p.s[p.pos] == '\0' || skip_value(&p, 0) != 0) {
        return CERTONE_E_JSON;
    }
    skip_ws(&p);
    return p.s[p.pos] == '\0' ? CERTONE_OK : CERTONE_E_JSON;
}

/* ---- path resolution ------------------------------------------------------------------- */

typedef struct path_seg {
    int is_index;
    size_t index;
    char *key; /* decoded key, in a scratch buffer owned by the caller */
    size_t key_len;
} path_seg;

/* Parse the next segment of *pp into seg (key bytes are written to scratch). Returns 1 when a
 * segment was read, 0 at the end of the path, -1 on a malformed path. */
static int next_segment(const char **pp, int first, char *scratch, path_seg *seg)
{
    const char *p = *pp;

    if (*p == '\0') {
        return 0;
    }
    if (*p == '[') {
        size_t v = 0;
        p++;
        if (!is_digit(*p)) {
            return -1;
        }
        while (is_digit(*p)) {
            size_t d = (size_t)(*p - '0');
            if (v > ((size_t)-1 - d) / 10) {
                return -1;
            }
            v = v * 10 + d;
            p++;
        }
        if (*p != ']') {
            return -1;
        }
        p++;
        seg->is_index = 1;
        seg->index = v;
        *pp = p;
        return 1;
    }
    if (*p == '.') {
        if (first) {
            return -1;
        }
        p++;
    } else if (!first) {
        return -1; /* after a key or index, only '.', '[' or the end may follow */
    }
    seg->is_index = 0;
    seg->key = scratch;
    seg->key_len = 0;
    while (*p != '\0' && *p != '.' && *p != '[') {
        if (*p == '\\') {
            p++;
            if (*p == '\0') {
                return -1;
            }
        }
        scratch[seg->key_len++] = *p++;
    }
    if (seg->key_len == 0) {
        return -1;
    }
    *pp = p;
    return 1;
}

/* With p at an object, move p to the value of the last member named key. */
static certone_status find_member(jparser *p, const char *key, size_t key_len)
{
    size_t found = 0;
    int have = 0;

    p->pos++; /* '{' */
    skip_ws(p);
    if (p->s[p->pos] == '}') {
        return CERTONE_E_NOT_FOUND;
    }
    for (;;) {
        str_sink k;
        memset(&k, 0, sizeof k);
        k.cmp = key;
        k.cmp_len = key_len;
        if (p->s[p->pos] != '"' || scan_string(p, &k) != 0) {
            return CERTONE_E_JSON;
        }
        skip_ws(p);
        if (p->s[p->pos] != ':') {
            return CERTONE_E_JSON;
        }
        p->pos++;
        skip_ws(p);
        if (!k.cmp_mismatch && k.cmp_pos == key_len) {
            found = p->pos;
            have = 1;
        }
        if (skip_value(p, 0) != 0) {
            return CERTONE_E_JSON;
        }
        skip_ws(p);
        if (p->s[p->pos] == ',') {
            p->pos++;
            skip_ws(p);
            continue;
        }
        if (p->s[p->pos] == '}') {
            break;
        }
        return CERTONE_E_JSON;
    }
    if (!have) {
        return CERTONE_E_NOT_FOUND;
    }
    p->pos = found;
    return CERTONE_OK;
}

/* With p at an array, move p to its index-th element. */
static certone_status find_element(jparser *p, size_t index)
{
    size_t i = 0;

    p->pos++; /* '[' */
    skip_ws(p);
    if (p->s[p->pos] == ']') {
        return CERTONE_E_NOT_FOUND;
    }
    for (;;) {
        if (i == index) {
            return CERTONE_OK;
        }
        if (skip_value(p, 0) != 0) {
            return CERTONE_E_JSON;
        }
        skip_ws(p);
        if (p->s[p->pos] == ',') {
            p->pos++;
            skip_ws(p);
            i++;
            continue;
        }
        if (p->s[p->pos] == ']') {
            return CERTONE_E_NOT_FOUND;
        }
        return CERTONE_E_JSON;
    }
}

/* Validate json, then find the value at path: its text is json[*start, *end). */
static certone_status locate(const char *json, const char *path, size_t *start, size_t *end)
{
    jparser p;
    char *scratch;
    const char *pp = path;
    int first = 1;
    certone_status st;

    if (json == NULL || path == NULL) {
        return CERTONE_E_INVALID_ARG;
    }
    st = certone_json_validate(json);
    if (st != CERTONE_OK) {
        return st;
    }
    scratch = (char *)malloc(strlen(path) + 1);
    if (scratch == NULL) {
        return CERTONE_E_NOMEM;
    }
    /* Reject a malformed path up front, whatever the document contains. */
    for (;;) {
        path_seg seg;
        int r = next_segment(&pp, first, scratch, &seg);
        first = 0;
        if (r < 0) {
            free(scratch);
            return CERTONE_E_INVALID_ARG;
        }
        if (r == 0) {
            break;
        }
    }
    pp = path;
    first = 1;
    p.s = json;
    p.pos = 0;
    skip_ws(&p);
    for (;;) {
        path_seg seg;
        int r = next_segment(&pp, first, scratch, &seg);
        first = 0;
        if (r < 0) {
            st = CERTONE_E_INVALID_ARG;
            break;
        }
        if (r == 0) {
            st = CERTONE_OK;
            break;
        }
        if (seg.is_index) {
            st = p.s[p.pos] == '[' ? find_element(&p, seg.index) : CERTONE_E_NOT_FOUND;
        } else {
            st = p.s[p.pos] == '{' ? find_member(&p, seg.key, seg.key_len) : CERTONE_E_NOT_FOUND;
        }
        if (st != CERTONE_OK) {
            break;
        }
    }
    free(scratch);
    if (st != CERTONE_OK) {
        return st;
    }
    *start = p.pos;
    if (skip_value(&p, 0) != 0) {
        return CERTONE_E_JSON;
    }
    *end = p.pos;
    return CERTONE_OK;
}

static certone_json_type type_of(char c)
{
    switch (c) {
    case '{': return CERTONE_JSON_OBJECT;
    case '[': return CERTONE_JSON_ARRAY;
    case '"': return CERTONE_JSON_STRING;
    case 't':
    case 'f': return CERTONE_JSON_BOOL;
    case 'n': return CERTONE_JSON_NULL;
    default: return CERTONE_JSON_NUMBER;
    }
}

certone_status certone_json_type_at(const char *json, const char *path,
                                    certone_json_type *out_type)
{
    size_t start;
    size_t end;
    certone_status st;

    if (out_type == NULL) {
        return CERTONE_E_INVALID_ARG;
    }
    st = locate(json, path, &start, &end);
    if (st == CERTONE_OK) {
        *out_type = type_of(json[start]);
    }
    return st;
}

certone_status certone_json_get_string(const char *json, const char *path, char **out)
{
    size_t start;
    size_t end;
    certone_status st;
    jparser p;
    str_sink k;

    if (out == NULL) {
        return CERTONE_E_INVALID_ARG;
    }
    *out = NULL;
    st = locate(json, path, &start, &end);
    if (st != CERTONE_OK) {
        return st;
    }
    if (json[start] != '"') {
        return CERTONE_E_TYPE;
    }
    memset(&k, 0, sizeof k);
    /* Decoded text is never longer than its escaped form. */
    k.out = (char *)malloc(end - start + 1);
    if (k.out == NULL) {
        return CERTONE_E_NOMEM;
    }
    p.s = json;
    p.pos = start;
    if (scan_string(&p, &k) != 0) {
        free(k.out);
        return CERTONE_E_JSON;
    }
    if (k.has_nul || k.bad_surrogate) {
        free(k.out);
        return CERTONE_E_TYPE;
    }
    k.out[k.out_len] = '\0';
    *out = k.out;
    return CERTONE_OK;
}

certone_status certone_json_get_int(const char *json, const char *path, int64_t *out)
{
    size_t start;
    size_t end;
    size_t i;
    int negative = 0;
    uint64_t v = 0;
    uint64_t limit;
    certone_status st;
    jparser p;
    int is_integer = 0;

    if (out == NULL) {
        return CERTONE_E_INVALID_ARG;
    }
    st = locate(json, path, &start, &end);
    if (st != CERTONE_OK) {
        return st;
    }
    if (type_of(json[start]) != CERTONE_JSON_NUMBER) {
        return CERTONE_E_TYPE;
    }
    p.s = json;
    p.pos = start;
    if (scan_number(&p, &is_integer) != 0) {
        return CERTONE_E_JSON;
    }
    if (!is_integer) {
        return CERTONE_E_TYPE;
    }
    i = start;
    if (json[i] == '-') {
        negative = 1;
        i++;
    }
    limit = negative ? (uint64_t)INT64_MAX + 1u : (uint64_t)INT64_MAX;
    for (; i < p.pos; i++) {
        uint64_t d = (uint64_t)(json[i] - '0');
        if (v > (limit - d) / 10) {
            return CERTONE_E_RANGE;
        }
        v = v * 10 + d;
    }
    if (negative) {
        *out = v == (uint64_t)INT64_MAX + 1u ? INT64_MIN : -(int64_t)v;
    } else {
        *out = (int64_t)v;
    }
    return CERTONE_OK;
}

certone_status certone_json_get_double(const char *json, const char *path, double *out)
{
    size_t start;
    size_t end;
    size_t n;
    size_t i;
    size_t j;
    certone_status st;
    const char *dp;
    size_t dp_len;
    char *tmp;
    char *endp = NULL;
    double v;

    if (out == NULL) {
        return CERTONE_E_INVALID_ARG;
    }
    st = locate(json, path, &start, &end);
    if (st != CERTONE_OK) {
        return st;
    }
    if (type_of(json[start]) != CERTONE_JSON_NUMBER) {
        return CERTONE_E_TYPE;
    }
    /* strtod honours LC_NUMERIC: substitute the locale's decimal separator for '.'. */
    dp = localeconv()->decimal_point;
    if (dp == NULL || dp[0] == '\0') {
        dp = ".";
    }
    dp_len = strlen(dp);
    n = end - start;
    tmp = (char *)malloc(n * dp_len + 1);
    if (tmp == NULL) {
        return CERTONE_E_NOMEM;
    }
    for (i = start, j = 0; i < end; i++) {
        if (json[i] == '.') {
            memcpy(tmp + j, dp, dp_len);
            j += dp_len;
        } else {
            tmp[j++] = json[i];
        }
    }
    tmp[j] = '\0';
    errno = 0;
    v = strtod(tmp, &endp);
    st = CERTONE_OK;
    if (endp != tmp + j) {
        st = CERTONE_E_JSON;
    } else if (errno == ERANGE && (v == HUGE_VAL || v == -HUGE_VAL)) {
        st = CERTONE_E_RANGE;
    }
    free(tmp);
    if (st == CERTONE_OK) {
        *out = v;
    }
    return st;
}

certone_status certone_json_get_bool(const char *json, const char *path, int *out)
{
    size_t start;
    size_t end;
    certone_status st;

    if (out == NULL) {
        return CERTONE_E_INVALID_ARG;
    }
    st = locate(json, path, &start, &end);
    if (st != CERTONE_OK) {
        return st;
    }
    if (json[start] == 't') {
        *out = 1;
    } else if (json[start] == 'f') {
        *out = 0;
    } else {
        return CERTONE_E_TYPE;
    }
    return CERTONE_OK;
}

/* Visit the members/elements of the container at start. For objects, when key_index matches
 * the member ordinal, its decoded key is written to *key_out (malloc'd). */
static certone_status walk_container(const char *json, size_t start, size_t *count,
                                     size_t key_index, char **key_out)
{
    jparser p;
    char open = json[start];
    char close = open == '{' ? '}' : ']';
    size_t n = 0;

    p.s = json;
    p.pos = start + 1;
    skip_ws(&p);
    if (p.s[p.pos] == close) {
        *count = 0;
        return CERTONE_OK;
    }
    for (;;) {
        if (open == '{') {
            size_t kstart = p.pos;
            if (p.s[p.pos] != '"' || scan_string(&p, NULL) != 0) {
                return CERTONE_E_JSON;
            }
            if (key_out != NULL && n == key_index) {
                jparser kp;
                str_sink k;
                memset(&k, 0, sizeof k);
                k.out = (char *)malloc(p.pos - kstart + 1);
                if (k.out == NULL) {
                    return CERTONE_E_NOMEM;
                }
                kp.s = json;
                kp.pos = kstart;
                if (scan_string(&kp, &k) != 0) {
                    free(k.out);
                    return CERTONE_E_JSON;
                }
                if (k.has_nul || k.bad_surrogate) {
                    free(k.out);
                    return CERTONE_E_TYPE;
                }
                k.out[k.out_len] = '\0';
                *key_out = k.out;
            }
            skip_ws(&p);
            if (p.s[p.pos] != ':') {
                if (key_out != NULL && *key_out != NULL) {
                    free(*key_out);
                    *key_out = NULL;
                }
                return CERTONE_E_JSON;
            }
            p.pos++;
            skip_ws(&p);
        }
        if (skip_value(&p, 0) != 0) {
            if (key_out != NULL && *key_out != NULL) {
                free(*key_out);
                *key_out = NULL;
            }
            return CERTONE_E_JSON;
        }
        n++;
        skip_ws(&p);
        if (p.s[p.pos] == ',') {
            p.pos++;
            skip_ws(&p);
            continue;
        }
        if (p.s[p.pos] == close) {
            *count = n;
            return CERTONE_OK;
        }
        if (key_out != NULL && *key_out != NULL) {
            free(*key_out);
            *key_out = NULL;
        }
        return CERTONE_E_JSON;
    }
}

certone_status certone_json_get_size(const char *json, const char *path, size_t *out)
{
    size_t start;
    size_t end;
    certone_status st;

    if (out == NULL) {
        return CERTONE_E_INVALID_ARG;
    }
    st = locate(json, path, &start, &end);
    if (st != CERTONE_OK) {
        return st;
    }
    if (json[start] != '{' && json[start] != '[') {
        return CERTONE_E_TYPE;
    }
    return walk_container(json, start, out, 0, NULL);
}

certone_status certone_json_get_key(const char *json, const char *path, size_t index, char **out)
{
    size_t start;
    size_t end;
    size_t count = 0;
    certone_status st;

    if (out == NULL) {
        return CERTONE_E_INVALID_ARG;
    }
    *out = NULL;
    st = locate(json, path, &start, &end);
    if (st != CERTONE_OK) {
        return st;
    }
    if (json[start] != '{') {
        return CERTONE_E_TYPE;
    }
    st = walk_container(json, start, &count, index, out);
    if (st != CERTONE_OK) {
        return st;
    }
    if (*out == NULL) {
        return CERTONE_E_NOT_FOUND; /* index >= member count */
    }
    return CERTONE_OK;
}

certone_status certone_json_get_raw(const char *json, const char *path, char **out)
{
    size_t start;
    size_t end;
    certone_status st;
    char *copy;

    if (out == NULL) {
        return CERTONE_E_INVALID_ARG;
    }
    *out = NULL;
    st = locate(json, path, &start, &end);
    if (st != CERTONE_OK) {
        return st;
    }
    copy = (char *)malloc(end - start + 1);
    if (copy == NULL) {
        return CERTONE_E_NOMEM;
    }
    memcpy(copy, json + start, end - start);
    copy[end - start] = '\0';
    *out = copy;
    return CERTONE_OK;
}
