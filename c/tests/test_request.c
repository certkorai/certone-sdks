/* Offline tests for request building: path encoding, ingest body, form fields, error details,
 * JSON string escaping and client argument validation. */
#include "certone.h"
#include "internal.h"
#include "test_util.h"

static void test_percent_encode(void)
{
    char *s = NULL;
    CHECK_ST(certone__percent_encode("64ff3a4afb5e40f5b8ae5e38071c9145", &s), CERTONE_OK);
    CHECK_STR(s, "64ff3a4afb5e40f5b8ae5e38071c9145");
    certone_free(s);
    CHECK_ST(certone__percent_encode("A-z_0.9~", &s), CERTONE_OK);
    CHECK_STR(s, "A-z_0.9~");
    certone_free(s);
    CHECK_ST(certone__percent_encode("../a b/?#%", &s), CERTONE_OK);
    CHECK_STR(s, "..%2Fa%20b%2F%3F%23%25");
    certone_free(s);
    CHECK_ST(certone__percent_encode("\xc3\xa9", &s), CERTONE_OK);
    CHECK_STR(s, "%C3%A9");
    certone_free(s);
    CHECK_ST(certone__percent_encode("", &s), CERTONE_E_INVALID_ARG);
    CHECK(s == NULL);
    CHECK_ST(certone__percent_encode(NULL, &s), CERTONE_E_INVALID_ARG);
}

static void test_ingest_body_all_fields(void)
{
    certone_ingest_options o;
    char *body = NULL;
    char *s = NULL;

    memset(&o, 0, sizeof o);
    o.asset = "Fraud \"Scorer\"";
    o.environment = "edge";
    o.country_code = "EU";
    o.snapshot_ref = "git:org/repo@abc";
    o.input_digest = "sha256:00ff";
    o.repo = "org/repo";
    o.commit_hash = "abc";
    CHECK_ST(certone__build_ingest_body("\n  {\"report_id\": \"r1\", \"issues\": []}\t\n", &o,
                                        &body),
             CERTONE_OK);
    CHECK_STR(body, "{\"report\":{\"report_id\": \"r1\", \"issues\": []},"
                    "\"asset\":\"Fraud \\\"Scorer\\\"\",\"environment\":\"edge\","
                    "\"country_code\":\"EU\",\"snapshot_ref\":\"git:org/repo@abc\","
                    "\"input_digest\":\"sha256:00ff\",\"repo\":\"org/repo\","
                    "\"commit_hash\":\"abc\"}");
    CHECK_ST(certone_json_validate(body), CERTONE_OK);
    CHECK_ST(certone_json_get_string(body, "asset", &s), CERTONE_OK);
    CHECK_STR(s, "Fraud \"Scorer\"");
    certone_free(s);
    CHECK_ST(certone_json_get_string(body, "report.report_id", &s), CERTONE_OK);
    CHECK_STR(s, "r1");
    certone_free(s);
    certone_free(body);
}

static void test_ingest_body_omits_unset_fields(void)
{
    certone_ingest_options o;
    char *body = NULL;

    CHECK_ST(certone__build_ingest_body("{}", NULL, &body), CERTONE_OK);
    CHECK_STR(body, "{\"report\":{}}");
    certone_free(body);
    memset(&o, 0, sizeof o);
    o.environment = "edge";
    CHECK_ST(certone__build_ingest_body("{\"a\":1}", &o, &body), CERTONE_OK);
    CHECK_STR(body, "{\"report\":{\"a\":1},\"environment\":\"edge\"}");
    certone_free(body);
}

static void test_ingest_body_rejects_bad_input(void)
{
    certone_ingest_options o;
    char *body = (char *)1;

    CHECK_ST(certone__build_ingest_body("[1]", NULL, &body), CERTONE_E_TYPE);
    CHECK(body == NULL);
    CHECK_ST(certone__build_ingest_body("\"report\"", NULL, &body), CERTONE_E_TYPE);
    CHECK_ST(certone__build_ingest_body("{\"a\":", NULL, &body), CERTONE_E_JSON);
    CHECK_ST(certone__build_ingest_body("{} trailing", NULL, &body), CERTONE_E_JSON);
    CHECK_ST(certone__build_ingest_body(NULL, NULL, &body), CERTONE_E_INVALID_ARG);
    memset(&o, 0, sizeof o);
    o.asset = "bad \xff utf8";
    CHECK_ST(certone__build_ingest_body("{}", &o, &body), CERTONE_E_INVALID_ARG);
    CHECK(body == NULL);
}

static void test_json_string_escaping(void)
{
    certone_buf b;
    char *s = NULL;

    memset(&b, 0, sizeof b);
    CHECK_ST(certone__buf_append_json_string(&b, "a\"b\\c\nd\re\tf\x01g\x7fh\xc3\xa9/"),
             CERTONE_OK);
    CHECK_STR(b.data, "\"a\\\"b\\\\c\\nd\\re\\tf\\u0001g\\u007fh\xc3\xa9/\"");
    CHECK_ST(certone_json_get_string(b.data, "", &s), CERTONE_OK);
    CHECK_STR(s, "a\"b\\c\nd\re\tf\x01g\x7fh\xc3\xa9/");
    certone_free(s);
    certone__buf_free(&b);

    memset(&b, 0, sizeof b);
    CHECK_ST(certone__buf_append_json_string(&b, ""), CERTONE_OK);
    CHECK_STR(b.data, "\"\"");
    certone__buf_free(&b);

    CHECK(certone__utf8_valid("\xf0\x9f\x98\x80", 4) == 1);
    CHECK(certone__utf8_valid("\xf0\x9f\x98", 3) == 0);
    CHECK(certone__utf8_valid("\xc0\xaf", 2) == 0);
    CHECK(certone__utf8_valid("\xed\xb0\x80", 3) == 0);
}

static void test_buffer_limit(void)
{
    certone_buf b;
    memset(&b, 0, sizeof b);
    b.limit = 8;
    CHECK_ST(certone__buf_append(&b, "12345", 5), CERTONE_OK);
    CHECK_ST(certone__buf_append(&b, "678", 3), CERTONE_OK);
    CHECK_ST(certone__buf_append(&b, "9", 1), CERTONE_E_TOO_LARGE);
    CHECK(b.overflow == 1);
    CHECK(b.len == 8);
    CHECK_STR(b.data, "12345678");
    certone__buf_free(&b);
    CHECK(b.data == NULL);
}

static void test_scan_fields(void)
{
    certone_scan_options o;
    const char *names[8];
    const char *values[8];
    size_t n;

    CHECK(certone__scan_fields(NULL, 1, names, values) == 0);
    memset(&o, 0, sizeof o);
    CHECK(certone__scan_fields(&o, 1, names, values) == 0);
    o.asset = "C SDK quickstart";
    o.fail_on = "high";
    o.tee = "amd_sev_snp";
    o.commit_hash = "abc";
    n = certone__scan_fields(&o, 0, names, values);
    CHECK(n == 3);
    if (n == 3) {
        CHECK_STR(names[0], "asset");
        CHECK_STR(values[0], "C SDK quickstart");
        CHECK_STR(names[1], "fail_on");
        CHECK_STR(names[2], "commit_hash");
    }
    n = certone__scan_fields(&o, 1, names, values);
    CHECK(n == 4);
    if (n == 4) {
        CHECK_STR(names[3], "tee");
        CHECK_STR(values[3], "amd_sev_snp");
    }
    o.environment = "edge";
    o.country_code = "EU";
    o.packs = "eu-ai-act-core";
    o.snapshot_ref = "git:x@y";
    CHECK(certone__scan_fields(&o, 1, names, values) == 8);
}

static void test_error_detail(void)
{
    char out[64];
    const char *b;

    b = "{\"detail\":\"scan not found\"}";
    certone__error_detail(b, strlen(b), out, sizeof out);
    CHECK_STR(out, "scan not found");
    b = "{\"detail\":[{\"loc\":[\"body\",\"report\"],\"msg\":\"Field required\"}]}";
    certone__error_detail(b, strlen(b), out, sizeof out);
    CHECK_STR(out, "[{\"loc\":[\"body\",\"report\"],\"msg\":\"Field required\"}]");
    b = "<html>Bad\r\nGateway</html>";
    certone__error_detail(b, strlen(b), out, sizeof out);
    CHECK_STR(out, "<html>Bad  Gateway</html>");
    b = "{\"error\":\"x\"}";
    certone__error_detail(b, strlen(b), out, sizeof out);
    CHECK_STR(out, "{\"error\":\"x\"}");
    certone__error_detail("", 0, out, sizeof out);
    CHECK_STR(out, "");
    certone__error_detail(NULL, 0, out, sizeof out);
    CHECK_STR(out, "");
    /* Truncation never splits a UTF-8 sequence: 10 x "é" (20 bytes) into 8 bytes of room. */
    {
        char small[8];
        b = "{\"detail\":\"\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9"
            "\xc3\xa9\"}";
        certone__error_detail(b, strlen(b), small, sizeof small);
        CHECK_STR(small, "\xc3\xa9\xc3\xa9\xc3\xa9");
    }
}

static void test_client_argument_validation(void)
{
    certone_config cfg;
    certone_client *c = (certone_client *)1;

    memset(&cfg, 0, sizeof cfg);
    CHECK_ST(certone_client_new(&cfg, &c), CERTONE_E_INVALID_ARG);
    CHECK(c == NULL);
    CHECK_ST(certone_client_new(NULL, &c), CERTONE_E_INVALID_ARG);
    cfg.base_url = "ftp://example.com";
    CHECK_ST(certone_client_new(&cfg, &c), CERTONE_E_INVALID_ARG);
    cfg.base_url = "https://";
    CHECK_ST(certone_client_new(&cfg, &c), CERTONE_E_INVALID_ARG);
    cfg.base_url = "https://example.com\r\nX: y";
    CHECK_ST(certone_client_new(&cfg, &c), CERTONE_E_INVALID_ARG);
    cfg.base_url = "https://example.com";
    cfg.token = "ck_abc\r\nX-Injected: 1";
    CHECK_ST(certone_client_new(&cfg, &c), CERTONE_E_INVALID_ARG);
    cfg.token = "";
    CHECK_ST(certone_client_new(&cfg, &c), CERTONE_E_INVALID_ARG);
    cfg.token = "ck_abc";
    cfg.timeout_ms = -1;
    CHECK_ST(certone_client_new(&cfg, &c), CERTONE_E_INVALID_ARG);
    cfg.timeout_ms = 0;
    cfg.base_url = "HTTPS://Example.com///";
    CHECK_ST(certone_client_new(&cfg, &c), CERTONE_OK);
    CHECK(c != NULL);
    CHECK_STR(certone_last_error(c), "");
    CHECK(certone_last_http_status(c) == 0);
    {
        char *out = (char *)1;
        CHECK_ST(certone_get_scan(c, "", &out), CERTONE_E_INVALID_ARG);
        CHECK(out == NULL);
        CHECK_CONTAINS(certone_last_error(c), "id is required");
        CHECK_ST(certone_get_scan(c, NULL, &out), CERTONE_E_INVALID_ARG);
        CHECK_ST(certone_get_scan(c, "x", NULL), CERTONE_E_INVALID_ARG);
        CHECK_ST(certone_get_scan(NULL, "x", &out), CERTONE_E_INVALID_ARG);
        CHECK_ST(certone_ingest_report(c, "[]", NULL, &out), CERTONE_E_TYPE);
        CHECK_CONTAINS(certone_last_error(c), "JSON object");
        CHECK_ST(certone_ingest_report(c, "{", NULL, &out), CERTONE_E_JSON);
        CHECK_ST(certone_wait_for_report(c, "x", -1, 0, &out), CERTONE_E_INVALID_ARG);
        CHECK_ST(certone_submit_check(c, NULL, NULL, &out), CERTONE_E_INVALID_ARG);
    }
    {
        certone_snapshot snap;
        char *out = NULL;
        memset(&snap, 0, sizeof snap);
        snap.path = "/nonexistent/certone/snapshot.tar.gz";
        CHECK_ST(certone_submit_check(c, &snap, NULL, &out), CERTONE_E_IO);
        CHECK_CONTAINS(certone_last_error(c), "cannot open snapshot");
        snap.data = "x";
        snap.size = 1;
        CHECK_ST(certone_submit_check(c, &snap, NULL, &out), CERTONE_E_INVALID_ARG);
        snap.path = NULL;
        snap.filename = "a\"b.tar.gz";
        CHECK_ST(certone_submit_check(c, &snap, NULL, &out), CERTONE_E_INVALID_ARG);
        snap.filename = NULL;
        snap.size = 0;
        CHECK_ST(certone_submit_process(c, &snap, NULL, &out), CERTONE_E_INVALID_ARG);
    }
    certone_client_free(c);
    certone_client_free(NULL);
}

static void test_status_strings(void)
{
    int st;
    for (st = CERTONE_E_TOO_LARGE; st <= CERTONE_OK; st++) {
        const char *s = certone_status_str((certone_status)st);
        CHECK(s != NULL && strncmp(s, "CERTONE_", 8) == 0);
    }
    CHECK_STR(certone_version(), CERTONE_VERSION_STRING);
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
    RUN(test_percent_encode);
    RUN(test_ingest_body_all_fields);
    RUN(test_ingest_body_omits_unset_fields);
    RUN(test_ingest_body_rejects_bad_input);
    RUN(test_json_string_escaping);
    RUN(test_buffer_limit);
    RUN(test_scan_fields);
    RUN(test_error_detail);
    RUN(test_client_argument_validation);
    RUN(test_status_strings);
    certone_global_cleanup();
    return test_summary("test_request");
}
