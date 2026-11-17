/* Offline tests for the JSON validator and path accessors, including the real API fixtures. */
#include "certone.h"
#include "test_util.h"

#include <locale.h>
#include <stdint.h>

static void test_validate_accepts_valid_documents(void)
{
    static const char *valid[] = {
        "{}", "[]", "0", "-0", "1.5e10", "-1E-7", "\"\"", "true", "false", "null",
        "  {\"a\" : [1, 2.5, -3e+2, true, false, null, \"x\", {}, []] }  \n",
        "\"\\\"\\\\\\/\\b\\f\\n\\r\\t\\u00e9\\ud83d\\ude00\"",
        "\"caf\xc3\xa9 \xe2\x82\xac \xf0\x9f\x98\x80\"",
        "\"\\ud800\"", /* syntactically valid; rejected only when decoded */
    };
    size_t i;
    for (i = 0; i < sizeof valid / sizeof valid[0]; i++) {
        CHECK_ST(certone_json_validate(valid[i]), CERTONE_OK);
    }
}

static void test_validate_rejects_invalid_documents(void)
{
    static const char *invalid[] = {
        "", "   ", "{", "}", "[1,]", "{\"a\":1,}", "{\"a\" 1}", "{a:1}", "01", "-", "1.", ".5",
        "1e", "1e+", "+1", "tru", "nul", "NaN", "Infinity", "\"abc", "\"a\nb\"", "\"\\x\"",
        "\"\\u12G4\"", "\"\\u12\"", "[1 2]", "{} {}", "1 2", "[\"a\"]x", "'a'",
        "\"\xc0\x80\"",         /* overlong NUL */
        "\"\xed\xa0\x80\"",     /* UTF-8 encoded surrogate */
        "\"\xf5\x80\x80\x80\"", /* beyond U+10FFFF */
        "\"\xe2\x82\"",         /* truncated sequence */
        "\"\x80\"",             /* stray continuation byte */
    };
    size_t i;
    for (i = 0; i < sizeof invalid / sizeof invalid[0]; i++) {
        int st = certone_json_validate(invalid[i]);
        if (st != CERTONE_E_JSON) {
            fprintf(stderr, "  accepted invalid document #%zu\n", i);
        }
        CHECK_ST(st, CERTONE_E_JSON);
    }
    CHECK_ST(certone_json_validate(NULL), CERTONE_E_INVALID_ARG);
}

static void test_nesting_depth_limit(void)
{
    char doc[1201];
    size_t i;
    for (i = 0; i < 200; i++) {
        doc[i] = '[';
        doc[200 + i] = ']';
    }
    doc[400] = '\0';
    CHECK_ST(certone_json_validate(doc), CERTONE_OK);
    for (i = 0; i < 600; i++) {
        doc[i] = '[';
        doc[600 + i] = ']';
    }
    doc[1200] = '\0';
    CHECK_ST(certone_json_validate(doc), CERTONE_E_JSON);
}

static void test_get_string_decodes_escapes(void)
{
    const char *doc = "{\"s\":\"a\\u00e9\\ud83d\\ude00\\n\\\"q\\\" \\/\",\"lone\":\"\\udc00\","
                      "\"nul\":\"a\\u0000b\",\"raw\":\"\xe2\x82\xac\",\"n\":1}";
    char *s = NULL;

    CHECK_ST(certone_json_get_string(doc, "s", &s), CERTONE_OK);
    CHECK_STR(s, "a\xc3\xa9\xf0\x9f\x98\x80\n\"q\" /");
    certone_free(s);
    CHECK_ST(certone_json_get_string(doc, "raw", &s), CERTONE_OK);
    CHECK_STR(s, "\xe2\x82\xac");
    certone_free(s);
    s = (char *)1;
    CHECK_ST(certone_json_get_string(doc, "lone", &s), CERTONE_E_TYPE);
    CHECK(s == NULL);
    CHECK_ST(certone_json_get_string(doc, "nul", &s), CERTONE_E_TYPE);
    CHECK_ST(certone_json_get_string(doc, "n", &s), CERTONE_E_TYPE);
    CHECK_ST(certone_json_get_string(doc, "missing", &s), CERTONE_E_NOT_FOUND);
    CHECK_ST(certone_json_get_string(doc, "s", NULL), CERTONE_E_INVALID_ARG);
    CHECK_ST(certone_json_get_string(NULL, "s", &s), CERTONE_E_INVALID_ARG);
    CHECK_ST(certone_json_get_string("{\"s\":", "s", &s), CERTONE_E_JSON);
}

static void test_paths(void)
{
    const char *doc = "{\"report\":{\"verdict_status\":\"fail\",\"issues\":[{\"severity\":\"high\"},"
                      "{\"severity\":\"low\",\"tags\":[\"a\",\"b\"]}]},\"a.b\":1,\"x[0]\":2,"
                      "\"caf\\u00e9\":3,\"dup\":1,\"dup\":2,\"nothing\":null,\"1\":4}";
    char *s = NULL;
    int64_t v = 0;

    CHECK_ST(certone_json_get_string(doc, "report.verdict_status", &s), CERTONE_OK);
    CHECK_STR(s, "fail");
    certone_free(s);
    CHECK_ST(certone_json_get_string(doc, "report.issues[1].severity", &s), CERTONE_OK);
    CHECK_STR(s, "low");
    certone_free(s);
    CHECK_ST(certone_json_get_string(doc, "report.issues[1].tags[1]", &s), CERTONE_OK);
    CHECK_STR(s, "b");
    certone_free(s);
    CHECK_ST(certone_json_get_int(doc, "a\\.b", &v), CERTONE_OK);
    CHECK(v == 1);
    CHECK_ST(certone_json_get_int(doc, "x\\[0]", &v), CERTONE_OK);
    CHECK(v == 2);
    CHECK_ST(certone_json_get_int(doc, "caf\xc3\xa9", &v), CERTONE_OK);
    CHECK(v == 3);
    CHECK_ST(certone_json_get_int(doc, "dup", &v), CERTONE_OK);
    CHECK(v == 2); /* last occurrence wins */
    CHECK_ST(certone_json_get_int(doc, "1", &v), CERTONE_OK);
    CHECK(v == 4);

    CHECK_ST(certone_json_get_string(doc, "report.issues[2].severity", &s), CERTONE_E_NOT_FOUND);
    CHECK_ST(certone_json_get_string(doc, "report.nope", &s), CERTONE_E_NOT_FOUND);
    CHECK_ST(certone_json_get_string(doc, "nothing.inner", &s), CERTONE_E_NOT_FOUND);
    CHECK_ST(certone_json_get_string(doc, "report[0]", &s), CERTONE_E_NOT_FOUND);
    CHECK_ST(certone_json_get_string(doc, "report.issues.severity", &s), CERTONE_E_NOT_FOUND);
    CHECK_ST(certone_json_get_string(doc, "re", &s), CERTONE_E_NOT_FOUND);
    CHECK_ST(certone_json_get_string(doc, "reportx", &s), CERTONE_E_NOT_FOUND);

    CHECK_ST(certone_json_get_string(doc, "a..b", &s), CERTONE_E_INVALID_ARG);
    CHECK_ST(certone_json_get_string(doc, ".report", &s), CERTONE_E_INVALID_ARG);
    CHECK_ST(certone_json_get_string(doc, "report.", &s), CERTONE_E_INVALID_ARG);
    CHECK_ST(certone_json_get_string(doc, "report.issues[", &s), CERTONE_E_INVALID_ARG);
    CHECK_ST(certone_json_get_string(doc, "report.issues[x]", &s), CERTONE_E_INVALID_ARG);
    CHECK_ST(certone_json_get_string(doc, "report.issues[0]x", &s), CERTONE_E_INVALID_ARG);
    CHECK_ST(certone_json_get_string(doc, "report.issues[99999999999999999999999]", &s),
             CERTONE_E_INVALID_ARG);
    CHECK_ST(certone_json_get_string(doc, "trailing\\", &s), CERTONE_E_INVALID_ARG);
}

static void test_top_level_array_and_type(void)
{
    const char *doc = " [ {\"name\":\"one\"}, {\"name\":\"two\"}, 3, null ] ";
    char *s = NULL;
    certone_json_type t;
    size_t n = 0;

    CHECK_ST(certone_json_get_string(doc, "[1].name", &s), CERTONE_OK);
    CHECK_STR(s, "two");
    certone_free(s);
    CHECK_ST(certone_json_get_size(doc, "", &n), CERTONE_OK);
    CHECK(n == 4);
    CHECK_ST(certone_json_type_at(doc, "", &t), CERTONE_OK);
    CHECK(t == CERTONE_JSON_ARRAY);
    CHECK_ST(certone_json_type_at(doc, "[0]", &t), CERTONE_OK);
    CHECK(t == CERTONE_JSON_OBJECT);
    CHECK_ST(certone_json_type_at(doc, "[0].name", &t), CERTONE_OK);
    CHECK(t == CERTONE_JSON_STRING);
    CHECK_ST(certone_json_type_at(doc, "[2]", &t), CERTONE_OK);
    CHECK(t == CERTONE_JSON_NUMBER);
    CHECK_ST(certone_json_type_at(doc, "[3]", &t), CERTONE_OK);
    CHECK(t == CERTONE_JSON_NULL);
    CHECK_ST(certone_json_type_at(doc, "[4]", &t), CERTONE_E_NOT_FOUND);
    CHECK_ST(certone_json_type_at(doc, "name", &t), CERTONE_E_NOT_FOUND);
    CHECK_ST(certone_json_type_at("[]", "[0]", &t), CERTONE_E_NOT_FOUND);
    CHECK_ST(certone_json_type_at("{}", "a", &t), CERTONE_E_NOT_FOUND);
}

static void test_get_int(void)
{
    const char *doc = "{\"z\":0,\"nz\":-0,\"max\":9223372036854775807,\"min\":-9223372036854775808,"
                      "\"over\":9223372036854775808,\"under\":-9223372036854775809,"
                      "\"f\":1.5,\"e\":1e2,\"s\":\"1\",\"b\":true,\"neg\":-42}";
    int64_t v = 7;

    CHECK_ST(certone_json_get_int(doc, "z", &v), CERTONE_OK);
    CHECK(v == 0);
    CHECK_ST(certone_json_get_int(doc, "nz", &v), CERTONE_OK);
    CHECK(v == 0);
    CHECK_ST(certone_json_get_int(doc, "max", &v), CERTONE_OK);
    CHECK(v == INT64_MAX);
    CHECK_ST(certone_json_get_int(doc, "min", &v), CERTONE_OK);
    CHECK(v == INT64_MIN);
    CHECK_ST(certone_json_get_int(doc, "neg", &v), CERTONE_OK);
    CHECK(v == -42);
    CHECK_ST(certone_json_get_int(doc, "over", &v), CERTONE_E_RANGE);
    CHECK_ST(certone_json_get_int(doc, "under", &v), CERTONE_E_RANGE);
    CHECK_ST(certone_json_get_int(doc, "f", &v), CERTONE_E_TYPE);
    CHECK_ST(certone_json_get_int(doc, "e", &v), CERTONE_E_TYPE);
    CHECK_ST(certone_json_get_int(doc, "s", &v), CERTONE_E_TYPE);
    CHECK_ST(certone_json_get_int(doc, "b", &v), CERTONE_E_TYPE);
}

static void test_get_double_bool(void)
{
    const char *doc = "{\"a\":1.5,\"b\":-2.5e-3,\"c\":12,\"big\":1e400,\"tiny\":1e-400,"
                      "\"t\":true,\"f\":false,\"s\":\"x\"}";
    double d = 0;
    int b = -1;

    setlocale(LC_NUMERIC, "C");
    CHECK_ST(certone_json_get_double(doc, "a", &d), CERTONE_OK);
    CHECK(d == 1.5);
    CHECK_ST(certone_json_get_double(doc, "b", &d), CERTONE_OK);
    CHECK(d == -2.5e-3);
    CHECK_ST(certone_json_get_double(doc, "c", &d), CERTONE_OK);
    CHECK(d == 12.0);
    CHECK_ST(certone_json_get_double(doc, "big", &d), CERTONE_E_RANGE);
    CHECK_ST(certone_json_get_double(doc, "tiny", &d), CERTONE_OK);
    CHECK(d >= 0.0 && d < 1e-300);
    CHECK_ST(certone_json_get_double(doc, "s", &d), CERTONE_E_TYPE);
    CHECK_ST(certone_json_get_bool(doc, "t", &b), CERTONE_OK);
    CHECK(b == 1);
    CHECK_ST(certone_json_get_bool(doc, "f", &b), CERTONE_OK);
    CHECK(b == 0);
    CHECK_ST(certone_json_get_bool(doc, "a", &b), CERTONE_E_TYPE);
}

static void test_size_key_raw(void)
{
    const char *doc = "{\"by\":{\"low\":0,\"medium\":3,\"high\":3},\"e\":{},\"arr\":[1,[2,3],{}],"
                      "\"k\":{\"\\u00e9t\\u00e9\":1},\"n\":5}";
    size_t n = 0;
    char *s = NULL;

    CHECK_ST(certone_json_get_size(doc, "by", &n), CERTONE_OK);
    CHECK(n == 3);
    CHECK_ST(certone_json_get_size(doc, "e", &n), CERTONE_OK);
    CHECK(n == 0);
    CHECK_ST(certone_json_get_size(doc, "arr", &n), CERTONE_OK);
    CHECK(n == 3);
    CHECK_ST(certone_json_get_size(doc, "arr[1]", &n), CERTONE_OK);
    CHECK(n == 2);
    CHECK_ST(certone_json_get_size(doc, "n", &n), CERTONE_E_TYPE);

    CHECK_ST(certone_json_get_key(doc, "by", 0, &s), CERTONE_OK);
    CHECK_STR(s, "low");
    certone_free(s);
    CHECK_ST(certone_json_get_key(doc, "by", 2, &s), CERTONE_OK);
    CHECK_STR(s, "high");
    certone_free(s);
    CHECK_ST(certone_json_get_key(doc, "k", 0, &s), CERTONE_OK);
    CHECK_STR(s, "\xc3\xa9t\xc3\xa9");
    certone_free(s);
    CHECK_ST(certone_json_get_key(doc, "by", 3, &s), CERTONE_E_NOT_FOUND);
    CHECK(s == NULL);
    CHECK_ST(certone_json_get_key(doc, "e", 0, &s), CERTONE_E_NOT_FOUND);
    CHECK_ST(certone_json_get_key(doc, "arr", 0, &s), CERTONE_E_TYPE);

    CHECK_ST(certone_json_get_raw(doc, "arr[1]", &s), CERTONE_OK);
    CHECK_STR(s, "[2,3]");
    certone_free(s);
    CHECK_ST(certone_json_get_raw(doc, "by", &s), CERTONE_OK);
    CHECK_STR(s, "{\"low\":0,\"medium\":3,\"high\":3}");
    certone_free(s);
    CHECK_ST(certone_json_get_raw("  \"x\"  ", "", &s), CERTONE_OK);
    CHECK_STR(s, "\"x\"");
    certone_free(s);
}

static void test_fixture_check_result(void)
{
    char *doc = read_fixture("check_result.json");
    char *s = NULL;
    int64_t v = 0;
    int b = 1;
    size_t n = 0;
    certone_json_type t;

    CHECK(doc != NULL);
    if (doc == NULL) {
        return;
    }
    CHECK_ST(certone_json_validate(doc), CERTONE_OK);
    CHECK_ST(certone_json_get_string(doc, "scan_run.id", &s), CERTONE_OK);
    CHECK_STR(s, "64ff3a4afb5e40f5b8ae5e38071c9145");
    certone_free(s);
    CHECK_ST(certone_json_get_string(doc, "report.verdict_status", &s), CERTONE_OK);
    CHECK_STR(s, "fail");
    certone_free(s);
    CHECK_ST(certone_json_get_string(doc, "report.id", &s), CERTONE_OK);
    CHECK_STR(s, "88b35a6b07bb456aa5159c32831f6bf4");
    certone_free(s);
    CHECK_ST(certone_json_get_int(doc, "report.total_issues", &v), CERTONE_OK);
    CHECK(v == 6);
    CHECK_ST(certone_json_get_int(doc, "report.by_severity.high", &v), CERTONE_OK);
    CHECK(v == 3);
    CHECK_ST(certone_json_get_size(doc, "report.by_severity", &n), CERTONE_OK);
    CHECK(n == 3);
    CHECK_ST(certone_json_get_key(doc, "report.by_severity", 1, &s), CERTONE_OK);
    CHECK_STR(s, "medium");
    certone_free(s);
    CHECK_ST(certone_json_get_bool(doc, "queued", &b), CERTONE_OK);
    CHECK(b == 0);
    CHECK_ST(certone_json_type_at(doc, "scan_run.error", &t), CERTONE_OK);
    CHECK(t == CERTONE_JSON_NULL);
    CHECK_ST(certone_json_get_string(doc, "scan_run.error", &s), CERTONE_E_TYPE);
    free(doc);
}

static void test_fixture_documents(void)
{
    char *systems = read_fixture("systems.json");
    char *document = read_fixture("report_document_excerpt.json");
    char *attestation = read_fixture("attestation.json");
    char *ingest = read_fixture("ingest_result.json");
    char *scan = read_fixture("scan.json");
    char *s = NULL;
    size_t n = 0;
    int b = 0;

    CHECK(systems != NULL && document != NULL && attestation != NULL && ingest != NULL &&
          scan != NULL);
    if (systems != NULL) {
        CHECK_ST(certone_json_get_size(systems, "", &n), CERTONE_OK);
        CHECK(n == 3);
        CHECK_ST(certone_json_get_string(systems, "[0].regions[0]", &s), CERTONE_OK);
        CHECK_STR(s, "EU");
        certone_free(s);
        CHECK_ST(certone_json_get_bool(systems, "[1].attested", &b), CERTONE_OK);
        CHECK(b == 0);
        CHECK_ST(certone_json_get_string(systems, "[2].slug", &s), CERTONE_OK);
        CHECK_STR(s, "default");
        certone_free(s);
    }
    if (document != NULL) {
        CHECK_ST(certone_json_get_string(document, "verdict.status", &s), CERTONE_OK);
        CHECK_STR(s, "fail");
        certone_free(s);
        CHECK_ST(certone_json_get_string(document, "issues[0].regulatory_references[1].framework",
                                         &s),
                 CERTONE_OK);
        CHECK_STR(s, "GDPR");
        certone_free(s);
        CHECK_ST(certone_json_get_string(document, "issues[0].location.artifact", &s),
                 CERTONE_OK);
        CHECK_STR(s, "sample-project/data/train.csv");
        certone_free(s);
        CHECK_ST(certone_json_get_size(document, "summary.by_topic", &n), CERTONE_OK);
        CHECK(n == 4);
    }
    if (attestation != NULL) {
        CHECK_ST(certone_json_get_string(attestation, "attestation_id", &s), CERTONE_OK);
        CHECK_STR(s, "att-43d463ff6d874d1a92be85ed768b762f");
        certone_free(s);
        CHECK_ST(certone_json_get_string(attestation, "signature_algorithm", &s), CERTONE_OK);
        CHECK_STR(s, "HMAC-SHA256");
        certone_free(s);
        CHECK_ST(certone_json_get_bool(attestation, "conditional_validity.valid", &b), CERTONE_OK);
        CHECK(b == 1);
        CHECK_ST(certone_json_get_size(attestation, "log", &n), CERTONE_OK);
        CHECK(n == 0);
    }
    if (ingest != NULL) {
        CHECK_ST(certone_json_get_string(ingest, "report.verdict_status", &s), CERTONE_OK);
        CHECK_STR(s, "pass");
        certone_free(s);
        CHECK_ST(certone_json_get_size(ingest, "report.by_severity", &n), CERTONE_OK);
        CHECK(n == 0);
    }
    if (scan != NULL) {
        CHECK_ST(certone_json_get_string(scan, "status", &s), CERTONE_OK);
        CHECK_STR(s, "succeeded");
        certone_free(s);
    }
    free(systems);
    free(document);
    free(attestation);
    free(ingest);
    free(scan);
}

int main(int argc, char **argv)
{
    if (argc > 1) {
        g_fixtures_dir = argv[1];
    }
    RUN(test_validate_accepts_valid_documents);
    RUN(test_validate_rejects_invalid_documents);
    RUN(test_nesting_depth_limit);
    RUN(test_get_string_decodes_escapes);
    RUN(test_paths);
    RUN(test_top_level_array_and_type);
    RUN(test_get_int);
    RUN(test_get_double_bool);
    RUN(test_size_key_raw);
    RUN(test_fixture_check_result);
    RUN(test_fixture_documents);
    return test_summary("test_json");
}
