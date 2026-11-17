/*
 * Offline client tests against an in-process loopback HTTP server (127.0.0.1, ephemeral port):
 * the exact requests the SDK sends (method, path, headers, multipart and JSON bodies) and how
 * it maps responses, HTTP errors, timeouts and oversize bodies. No external network is used.
 */
#define _POSIX_C_SOURCE 200809L

#include "certone.h"
#include "test_util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

#define TOKEN "ck_test_token_do_not_leak"
#define MAX_REQUESTS 16

typedef struct mock_response {
    int status;
    const char *body;
    int hang; /* read the request, then never answer */
} mock_response;

typedef struct mock_server {
    int listen_fd;
    int port;
    const mock_response *responses;
    size_t nresponses;
    int repeat_last;
    pthread_t thread;
    pthread_mutex_t lock;
    int stop;
    char *requests[MAX_REQUESTS];
    size_t nrequests;
} mock_server;

static int server_stopping(mock_server *s)
{
    int stop;
    pthread_mutex_lock(&s->lock);
    stop = s->stop;
    pthread_mutex_unlock(&s->lock);
    return stop;
}

/* Read one HTTP request (headers + Content-Length body) into a NUL-terminated buffer. */
static char *read_request(int fd)
{
    size_t cap = 1 << 16;
    size_t len = 0;
    char *buf = (char *)malloc(cap + 1);
    size_t need = 0;

    if (buf == NULL) {
        return NULL;
    }
    for (;;) {
        ssize_t n;
        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLIN;
        if (poll(&pfd, 1, 5000) <= 0) {
            break;
        }
        if (len == cap) {
            char *grown = (char *)realloc(buf, cap * 2 + 1);
            if (grown == NULL) {
                break;
            }
            buf = grown;
            cap *= 2;
        }
        n = recv(fd, buf + len, cap - len, 0);
        if (n <= 0) {
            break;
        }
        len += (size_t)n;
        buf[len] = '\0';
        if (need == 0) {
            char *end = strstr(buf, "\r\n\r\n");
            if (end != NULL) {
                size_t header_len = (size_t)(end - buf) + 4;
                size_t content_length = 0;
                char *line = buf;
                while (line < end) {
                    if (strncasecmp(line, "Content-Length:", 15) == 0) {
                        content_length = (size_t)strtoul(line + 15, NULL, 10);
                    }
                    line = strstr(line, "\r\n");
                    if (line == NULL) {
                        break;
                    }
                    line += 2;
                }
                need = header_len + content_length;
            }
        }
        if (need != 0 && len >= need) {
            break;
        }
    }
    buf[len] = '\0';
    return buf;
}

static void send_all(int fd, const char *data, size_t len)
{
    while (len > 0) {
        ssize_t n = send(fd, data, len, 0);
        if (n <= 0) {
            return;
        }
        data += n;
        len -= (size_t)n;
    }
}

static void *server_main(void *arg)
{
    mock_server *s = (mock_server *)arg;
    size_t served = 0;

    while (!server_stopping(s)) {
        struct pollfd pfd;
        const mock_response *r;
        char *req;
        int fd;

        if (served >= s->nresponses && !s->repeat_last) {
            break;
        }
        pfd.fd = s->listen_fd;
        pfd.events = POLLIN;
        if (poll(&pfd, 1, 50) <= 0) {
            continue;
        }
        fd = accept(s->listen_fd, NULL, NULL);
        if (fd < 0) {
            continue;
        }
        r = &s->responses[served < s->nresponses ? served : s->nresponses - 1];
        served++;
        req = read_request(fd);
        pthread_mutex_lock(&s->lock);
        if (req != NULL && s->nrequests < MAX_REQUESTS) {
            s->requests[s->nrequests++] = req;
            req = NULL;
        }
        pthread_mutex_unlock(&s->lock);
        free(req);
        if (r->hang) {
            /* Wait for the client to give up (it closes the socket) or for shutdown. */
            int i;
            for (i = 0; i < 100 && !server_stopping(s); i++) {
                char tmp[256];
                struct pollfd cp;
                cp.fd = fd;
                cp.events = POLLIN;
                if (poll(&cp, 1, 50) > 0 && recv(fd, tmp, sizeof tmp, 0) <= 0) {
                    break;
                }
            }
        } else {
            char head[256];
            size_t blen = strlen(r->body);
            int hlen = snprintf(head, sizeof head,
                                "HTTP/1.1 %d X\r\nContent-Type: application/json\r\n"
                                "Content-Length: %zu\r\nConnection: close\r\n\r\n",
                                r->status, blen);
            send_all(fd, head, (size_t)hlen);
            send_all(fd, r->body, blen);
        }
        close(fd);
    }
    return NULL;
}

static int server_start(mock_server *s, const mock_response *responses, size_t n, int repeat)
{
    struct sockaddr_in addr;
    socklen_t alen = sizeof addr;
    int one = 1;

    memset(s, 0, sizeof *s);
    s->responses = responses;
    s->nresponses = n;
    s->repeat_last = repeat;
    s->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (s->listen_fd < 0) {
        return -1;
    }
    setsockopt(s->listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(s->listen_fd, (struct sockaddr *)&addr, sizeof addr) != 0 ||
        listen(s->listen_fd, 8) != 0 ||
        getsockname(s->listen_fd, (struct sockaddr *)&addr, &alen) != 0) {
        close(s->listen_fd);
        return -1;
    }
    s->port = ntohs(addr.sin_port);
    pthread_mutex_init(&s->lock, NULL);
    if (pthread_create(&s->thread, NULL, server_main, s) != 0) {
        pthread_mutex_destroy(&s->lock);
        close(s->listen_fd);
        return -1;
    }
    return 0;
}

/* Stop the server thread; the recorded requests stay readable until server_release. */
static void server_stop(mock_server *s)
{
    pthread_mutex_lock(&s->lock);
    s->stop = 1;
    pthread_mutex_unlock(&s->lock);
    pthread_join(s->thread, NULL);
    pthread_mutex_destroy(&s->lock);
    close(s->listen_fd);
}

static void server_release(mock_server *s)
{
    size_t i;
    for (i = 0; i < s->nrequests; i++) {
        free(s->requests[i]);
        s->requests[i] = NULL;
    }
    s->nrequests = 0;
}

static certone_client *make_client(const mock_server *s, long timeout_ms, size_t max_response)
{
    char url[64];
    certone_config cfg;
    certone_client *c = NULL;

    snprintf(url, sizeof url, "http://127.0.0.1:%d/", s->port);
    memset(&cfg, 0, sizeof cfg);
    cfg.base_url = url;
    cfg.token = TOKEN;
    cfg.timeout_ms = timeout_ms;
    cfg.max_response_bytes = max_response;
    if (certone_client_new(&cfg, &c) != CERTONE_OK) {
        return NULL;
    }
    return c;
}

/* Request bodies are binary-safe here only up to the first NUL; the tests send text. */
static const char *body_of(const char *request)
{
    const char *p = strstr(request, "\r\n\r\n");
    return p != NULL ? p + 4 : "";
}

static void test_get_scan_request_and_response(void)
{
    static const mock_response resp[] = {{200, "{\"id\":\"abc/def\",\"status\":\"running\"}", 0}};
    mock_server s;
    certone_client *c;
    char *out = NULL;
    char *status = NULL;

    if (server_start(&s, resp, 1, 0) != 0) {
        CHECK(!"mock server failed to start");
        return;
    }
    c = make_client(&s, 0, 0);
    CHECK(c != NULL);
    if (c != NULL) {
        CHECK_ST(certone_get_scan(c, "abc/def", &out), CERTONE_OK);
        CHECK_STR(out, "{\"id\":\"abc/def\",\"status\":\"running\"}");
        CHECK_ST(certone_json_get_string(out, "status", &status), CERTONE_OK);
        CHECK_STR(status, "running");
        CHECK(certone_last_http_status(c) == 200);
        CHECK_STR(certone_last_error(c), "");
        certone_free(status);
        certone_free(out);
        certone_client_free(c);
    }
    server_stop(&s);
    CHECK(s.nrequests == 1);
    if (s.nrequests == 1) {
        const char *r = s.requests[0];
        CHECK_PREFIX(r, "GET /v1/scans/abc%2Fdef HTTP/1.1\r\n");
        CHECK_CONTAINS(r, "\r\nAuthorization: Bearer " TOKEN "\r\n");
        CHECK_CONTAINS(r, "\r\nAccept: application/json\r\n");
        CHECK_CONTAINS(r, "\r\nUser-Agent: certone-c/" CERTONE_VERSION_STRING "\r\n");
    }
    server_release(&s);
}

static void test_submit_check_multipart_from_file(void)
{
    static const mock_response resp[] = {
        {201, "{\"scan_run\":{\"id\":\"s1\"},\"report\":{\"verdict_status\":\"fail\"},\"queued\":false}",
         0}};
    const char *path = "certone_client_snap.tar.gz";
    mock_server s;
    certone_client *c;
    certone_snapshot snap;
    certone_scan_options opts;
    char *out = NULL;
    FILE *f = fopen(path, "wb");

    CHECK(f != NULL);
    if (f == NULL) {
        return;
    }
    fputs("SNAPSHOT-BYTES", f);
    fclose(f);
    memset(&snap, 0, sizeof snap);
    snap.path = path;
    memset(&opts, 0, sizeof opts);
    opts.asset = "C SDK quickstart";
    opts.fail_on = "high";
    opts.environment = "ci";
    opts.tee = "intel_tdx"; /* not sent by submit_check */

    if (server_start(&s, resp, 1, 0) != 0) {
        CHECK(!"mock server failed to start");
        remove(path);
        return;
    }
    c = make_client(&s, 0, 0);
    CHECK(c != NULL);
    if (c != NULL) {
        CHECK_ST(certone_submit_check(c, &snap, &opts, &out), CERTONE_OK);
        CHECK_CONTAINS(out, "\"verdict_status\":\"fail\"");
        CHECK(certone_last_http_status(c) == 201);
        certone_free(out);
        certone_client_free(c);
    }
    server_stop(&s);
    remove(path);
    CHECK(s.nrequests == 1);
    if (s.nrequests == 1) {
        const char *r = s.requests[0];
        CHECK_PREFIX(r, "POST /v1/checks HTTP/1.1\r\n");
        CHECK_CONTAINS(r, "\r\nContent-Type: multipart/form-data; boundary=");
        CHECK(strstr(r, "\r\nExpect:") == NULL);
        CHECK_CONTAINS(r, "name=\"asset\"\r\n\r\nC SDK quickstart\r\n");
        CHECK_CONTAINS(r, "name=\"fail_on\"\r\n\r\nhigh\r\n");
        CHECK_CONTAINS(r, "name=\"environment\"\r\n\r\nci\r\n");
        CHECK(strstr(r, "name=\"tee\"") == NULL);
        CHECK_CONTAINS(r, "name=\"snapshot\"; filename=\"certone_client_snap.tar.gz\"\r\n"
                          "Content-Type: application/gzip\r\n\r\nSNAPSHOT-BYTES\r\n");
    }
    server_release(&s);
}

static void test_submit_process_multipart_from_memory(void)
{
    static const mock_response resp[] = {
        {201, "{\"scan_run\":{\"id\":\"s2\",\"status\":\"queued\"},\"report\":null,\"queued\":true}",
         0}};
    mock_server s;
    certone_client *c;
    certone_snapshot snap;
    certone_scan_options opts;
    char *out = NULL;
    int queued = 0;

    memset(&snap, 0, sizeof snap);
    snap.data = "IN-MEMORY";
    snap.size = 9;
    memset(&opts, 0, sizeof opts);
    opts.tee = "amd_sev_snp";
    opts.country_code = "EU";

    if (server_start(&s, resp, 1, 0) != 0) {
        CHECK(!"mock server failed to start");
        return;
    }
    c = make_client(&s, 0, 0);
    CHECK(c != NULL);
    if (c != NULL) {
        CHECK_ST(certone_submit_process(c, &snap, &opts, &out), CERTONE_OK);
        CHECK_ST(certone_json_get_bool(out, "queued", &queued), CERTONE_OK);
        CHECK(queued == 1);
        certone_free(out);
        certone_client_free(c);
    }
    server_stop(&s);
    CHECK(s.nrequests == 1);
    if (s.nrequests == 1) {
        const char *r = s.requests[0];
        CHECK_PREFIX(r, "POST /v1/process HTTP/1.1\r\n");
        CHECK_CONTAINS(r, "name=\"country_code\"\r\n\r\nEU\r\n");
        CHECK_CONTAINS(r, "name=\"tee\"\r\n\r\namd_sev_snp\r\n");
        CHECK_CONTAINS(r, "name=\"snapshot\"; filename=\"snapshot.tar.gz\"\r\n"
                          "Content-Type: application/gzip\r\n\r\nIN-MEMORY\r\n");
    }
    server_release(&s);
}

static void test_ingest_report_json_body(void)
{
    static const mock_response resp[] = {
        {201, "{\"scan_run\":{\"id\":\"s3\"},\"report\":{\"id\":\"r3\",\"verdict_status\":\"pass\"}}",
         0}};
    mock_server s;
    certone_client *c;
    certone_ingest_options o;
    char *out = NULL;

    memset(&o, 0, sizeof o);
    o.environment = "edge";
    o.country_code = "EU";
    o.input_digest = "sha256:ab";
    if (server_start(&s, resp, 1, 0) != 0) {
        CHECK(!"mock server failed to start");
        return;
    }
    c = make_client(&s, 0, 0);
    CHECK(c != NULL);
    if (c != NULL) {
        CHECK_ST(certone_ingest_report(c, "{\"report_id\":\"rat-1\"}", &o, &out), CERTONE_OK);
        CHECK_CONTAINS(out, "\"pass\"");
        certone_free(out);
        certone_client_free(c);
    }
    server_stop(&s);
    CHECK(s.nrequests == 1);
    if (s.nrequests == 1) {
        const char *r = s.requests[0];
        CHECK_PREFIX(r, "POST /v1/checks/report HTTP/1.1\r\n");
        CHECK_CONTAINS(r, "\r\nContent-Type: application/json\r\n");
        CHECK_STR(body_of(r), "{\"report\":{\"report_id\":\"rat-1\"},\"environment\":\"edge\","
                              "\"country_code\":\"EU\",\"input_digest\":\"sha256:ab\"}");
    }
    server_release(&s);
}

static void test_http_errors_carry_status_and_detail(void)
{
    static const mock_response resp[] = {
        {404, "{\"detail\":\"no attestation (the input did not pass, so none was issued)\"}", 0},
        {422, "{\"detail\":[{\"msg\":\"Field required\"}]}", 0},
        {502, "upstream\nunavailable", 0},
        {200, "not json", 0},
    };
    mock_server s;
    certone_client *c;
    char *out = (char *)1;

    if (server_start(&s, resp, 4, 0) != 0) {
        CHECK(!"mock server failed to start");
        return;
    }
    c = make_client(&s, 0, 0);
    CHECK(c != NULL);
    if (c != NULL) {
        CHECK_ST(certone_get_attestation(c, "r1", &out), CERTONE_E_HTTP);
        CHECK(out == NULL);
        CHECK(certone_last_http_status(c) == 404);
        CHECK_STR(certone_last_error(c),
                  "HTTP 404: no attestation (the input did not pass, so none was issued)");
        CHECK_ST(certone_list_systems(c, &out), CERTONE_E_HTTP);
        CHECK(certone_last_http_status(c) == 422);
        CHECK_STR(certone_last_error(c), "HTTP 422: [{\"msg\":\"Field required\"}]");
        CHECK_ST(certone_get_report_document(c, "r1", &out), CERTONE_E_HTTP);
        CHECK_STR(certone_last_error(c), "HTTP 502: upstream unavailable");
        CHECK(strstr(certone_last_error(c), TOKEN) == NULL);
        CHECK_ST(certone_get_scan(c, "s1", &out), CERTONE_E_JSON);
        CHECK(out == NULL);
        CHECK_CONTAINS(certone_last_error(c), "not valid JSON");
        certone_client_free(c);
    }
    server_stop(&s);
    CHECK(s.nrequests == 4);
    if (s.nrequests == 4) {
        CHECK_PREFIX(s.requests[0], "GET /v1/reports/r1/attestation ");
        CHECK_PREFIX(s.requests[1], "GET /v1/systems ");
        CHECK_PREFIX(s.requests[2], "GET /v1/reports/r1/document ");
    }
    server_release(&s);
}

static void test_wait_for_report_polls_until_succeeded(void)
{
    static const mock_response resp[] = {
        {200, "{\"id\":\"s1\",\"status\":\"queued\",\"error\":null}", 0},
        {200, "{\"id\":\"s1\",\"status\":\"running\",\"error\":null}", 0},
        {200, "{\"id\":\"s1\",\"status\":\"succeeded\",\"error\":null}", 0},
        {200, "{\"id\":\"r1\",\"scan_run_id\":\"s1\",\"verdict_status\":\"fail\"}", 0},
    };
    mock_server s;
    certone_client *c;
    char *out = NULL;
    char *v = NULL;

    if (server_start(&s, resp, 4, 0) != 0) {
        CHECK(!"mock server failed to start");
        return;
    }
    c = make_client(&s, 0, 0);
    CHECK(c != NULL);
    if (c != NULL) {
        CHECK_ST(certone_wait_for_report(c, "s1", 10000, 10, &out), CERTONE_OK);
        CHECK_ST(certone_json_get_string(out, "verdict_status", &v), CERTONE_OK);
        CHECK_STR(v, "fail");
        certone_free(v);
        certone_free(out);
        certone_client_free(c);
    }
    server_stop(&s);
    CHECK(s.nrequests == 4);
    if (s.nrequests == 4) {
        CHECK_PREFIX(s.requests[0], "GET /v1/scans/s1 ");
        CHECK_PREFIX(s.requests[2], "GET /v1/scans/s1 ");
        CHECK_PREFIX(s.requests[3], "GET /v1/scans/s1/report ");
    }
    server_release(&s);
}

static void test_wait_for_report_failed_scan(void)
{
    static const mock_response resp[] = {
        {200, "{\"id\":\"s1\",\"status\":\"failed\",\"error\":\"worker lost: TEE attestation failed\"}",
         0}};
    mock_server s;
    certone_client *c;
    char *out = NULL;

    if (server_start(&s, resp, 1, 0) != 0) {
        CHECK(!"mock server failed to start");
        return;
    }
    c = make_client(&s, 0, 0);
    CHECK(c != NULL);
    if (c != NULL) {
        CHECK_ST(certone_wait_for_report(c, "s1", 10000, 10, &out), CERTONE_E_SCAN_FAILED);
        CHECK(out == NULL);
        CHECK_STR(certone_last_error(c), "scan s1 failed: worker lost: TEE attestation failed");
        certone_client_free(c);
    }
    server_stop(&s);
    server_release(&s);
}

static void test_wait_for_report_deadline(void)
{
    static const mock_response resp[] = {{200, "{\"id\":\"s1\",\"status\":\"running\"}", 0}};
    mock_server s;
    certone_client *c;
    char *out = NULL;

    if (server_start(&s, resp, 1, 1) != 0) {
        CHECK(!"mock server failed to start");
        return;
    }
    c = make_client(&s, 0, 0);
    CHECK(c != NULL);
    if (c != NULL) {
        CHECK_ST(certone_wait_for_report(c, "s1", 120, 25, &out), CERTONE_E_TIMEOUT);
        CHECK(out == NULL);
        CHECK_CONTAINS(certone_last_error(c), "did not finish within 120 ms (status running)");
        certone_client_free(c);
    }
    server_stop(&s);
    CHECK(s.nrequests >= 2);
    server_release(&s);
}

static void test_request_timeout(void)
{
    static const mock_response resp[] = {{0, "", 1}};
    mock_server s;
    certone_client *c;
    char *out = NULL;

    if (server_start(&s, resp, 1, 0) != 0) {
        CHECK(!"mock server failed to start");
        return;
    }
    c = make_client(&s, 300, 0);
    CHECK(c != NULL);
    if (c != NULL) {
        CHECK_ST(certone_list_systems(c, &out), CERTONE_E_TIMEOUT);
        CHECK(out == NULL);
        CHECK_CONTAINS(certone_last_error(c), "timed out");
        CHECK(certone_last_http_status(c) == 0);
        certone_client_free(c);
    }
    server_stop(&s);
    server_release(&s);
}

static void test_response_size_limit(void)
{
    static const mock_response resp[] = {
        {200, "[\"0123456789\",\"0123456789\",\"0123456789\",\"0123456789\",\"0123456789\"]", 0}};
    mock_server s;
    certone_client *c;
    char *out = NULL;

    if (server_start(&s, resp, 1, 0) != 0) {
        CHECK(!"mock server failed to start");
        return;
    }
    c = make_client(&s, 0, 32);
    CHECK(c != NULL);
    if (c != NULL) {
        CHECK_ST(certone_list_systems(c, &out), CERTONE_E_TOO_LARGE);
        CHECK(out == NULL);
        CHECK_CONTAINS(certone_last_error(c), "exceeds 32 bytes");
        certone_client_free(c);
    }
    server_stop(&s);
    server_release(&s);
}

static void test_connection_refused(void)
{
    struct sockaddr_in addr;
    socklen_t alen = sizeof addr;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int port = 0;
    char url[64];
    certone_config cfg;
    certone_client *c = NULL;
    char *out = NULL;

    /* Reserve an ephemeral port, then close it so nothing listens there. */
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (fd >= 0 && bind(fd, (struct sockaddr *)&addr, sizeof addr) == 0 &&
        getsockname(fd, (struct sockaddr *)&addr, &alen) == 0) {
        port = ntohs(addr.sin_port);
    }
    if (fd >= 0) {
        close(fd);
    }
    CHECK(port != 0);
    snprintf(url, sizeof url, "http://127.0.0.1:%d", port);
    memset(&cfg, 0, sizeof cfg);
    cfg.base_url = url;
    cfg.token = TOKEN;
    cfg.connect_timeout_ms = 2000;
    CHECK_ST(certone_client_new(&cfg, &c), CERTONE_OK);
    if (c != NULL) {
        CHECK_ST(certone_list_systems(c, &out), CERTONE_E_NETWORK);
        CHECK(out == NULL);
        CHECK_CONTAINS(certone_last_error(c), "GET /v1/systems: ");
        CHECK(strstr(certone_last_error(c), TOKEN) == NULL);
        certone_client_free(c);
    }
}

int main(int argc, char **argv)
{
    if (argc > 1) {
        g_fixtures_dir = argv[1];
    }
    if (certone_global_init() != CERTONE_OK) {
        fprintf(stderr, "certone_global_init failed\n");
        return 1;
    }
    RUN(test_get_scan_request_and_response);
    RUN(test_submit_check_multipart_from_file);
    RUN(test_submit_process_multipart_from_memory);
    RUN(test_ingest_report_json_body);
    RUN(test_http_errors_carry_status_and_detail);
    RUN(test_wait_for_report_polls_until_succeeded);
    RUN(test_wait_for_report_failed_scan);
    RUN(test_wait_for_report_deadline);
    RUN(test_request_timeout);
    RUN(test_response_size_limit);
    RUN(test_connection_refused);
    certone_global_cleanup();
    return test_summary("test_client");
}
