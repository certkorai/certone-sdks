/*
 * CertOne C SDK quickstart: the 7-step conformance flow from SPEC.md.
 *
 *   CERTONE_API_URL=https://api.example.com CERTONE_API_KEY=ck_... \
 *   CERTONE_SNAPSHOT=sample-project.tar.gz CERTONE_REPORT_JSON=run-at-source-report.json \
 *   ./quickstart
 *
 * Exits 0 on success, or 1 with the error on stderr.
 */
#include "certone.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ASSET "C SDK quickstart"

typedef struct state {
    certone_client *client;
    char *check;      /* submit_check response */
    char *report;     /* wait_for_report response */
    char *document;   /* get_report_document response */
    char *report_doc; /* run-at-source report read from disk */
    char *ingest;     /* ingest_report response */
    char *attestation;
    char *systems;
} state;

static void cleanup(state *s)
{
    certone_free(s->check);
    certone_free(s->report);
    certone_free(s->document);
    free(s->report_doc);
    certone_free(s->ingest);
    certone_free(s->attestation);
    certone_free(s->systems);
    certone_client_free(s->client);
    certone_global_cleanup();
}

static int fail_api(state *s, const char *step, certone_status st)
{
    fprintf(stderr, "error: %s: %s", step, certone_status_str(st));
    if (s->client != NULL && certone_last_error(s->client)[0] != '\0') {
        fprintf(stderr, ": %s", certone_last_error(s->client));
    }
    fputc('\n', stderr);
    cleanup(s);
    return 1;
}

static int fail_json(state *s, const char *what, certone_status st)
{
    fprintf(stderr, "error: reading %s from the response: %s\n", what, certone_status_str(st));
    cleanup(s);
    return 1;
}

static const char *require_env(const char *name)
{
    const char *v = getenv(name);
    if (v == NULL || v[0] == '\0') {
        fprintf(stderr, "error: environment variable %s is not set\n", name);
        return NULL;
    }
    return v;
}

static char *read_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    char *data = NULL;
    size_t len = 0;
    size_t cap = 0;
    size_t n;
    char chunk[8192];

    if (f == NULL) {
        return NULL;
    }
    while ((n = fread(chunk, 1, sizeof chunk, f)) > 0) {
        if (len + n + 1 > cap) {
            size_t ncap = 2 * (len + n + 1);
            char *grown = (char *)realloc(data, ncap);
            if (grown == NULL) {
                free(data);
                fclose(f);
                return NULL;
            }
            data = grown;
            cap = ncap;
        }
        memcpy(data + len, chunk, n);
        len += n;
    }
    if (ferror(f) || data == NULL) {
        free(data);
        fclose(f);
        return NULL;
    }
    fclose(f);
    data[len] = '\0';
    return data;
}

/* Append c to out[*j], keeping room for the terminator. 0 if it does not fit. */
static int put(char *out, size_t size, size_t *j, char c)
{
    if (*j + 1 >= size) {
        return 0;
    }
    out[(*j)++] = c;
    return 1;
}

/* "<path>.<key>", escaping '.', '[' and backslash inside key. 0 if it does not fit. */
static int join_path(char *out, size_t size, const char *path, const char *key)
{
    size_t j = 0;
    const char *p;

    for (p = path; *p != '\0'; p++) {
        if (!put(out, size, &j, *p)) {
            return 0;
        }
    }
    if (!put(out, size, &j, '.')) {
        return 0;
    }
    for (p = key; *p != '\0'; p++) {
        if ((*p == '.' || *p == '[' || *p == '\\') && !put(out, size, &j, '\\')) {
            return 0;
        }
        if (!put(out, size, &j, *p)) {
            return 0;
        }
    }
    out[j] = '\0';
    return 1;
}

/* Print `<key>=<int>` for every member of the object at path, e.g. "low=0 medium=3 high=3". */
static certone_status print_counts(const char *json, const char *path)
{
    size_t n = 0;
    size_t i;
    certone_status st = certone_json_get_size(json, path, &n);

    if (st != CERTONE_OK) {
        return st;
    }
    if (n == 0) {
        printf("none");
    }
    for (i = 0; i < n; i++) {
        char *key = NULL;
        char sub[256];
        int64_t count = 0;
        st = certone_json_get_key(json, path, i, &key);
        if (st != CERTONE_OK) {
            return st;
        }
        if (!join_path(sub, sizeof sub, path, key)) {
            certone_free(key);
            return CERTONE_E_INVALID_ARG;
        }
        st = certone_json_get_int(json, sub, &count);
        if (st == CERTONE_OK) {
            printf("%s%s=%" PRId64, i > 0 ? " " : "", key, count);
        }
        certone_free(key);
        if (st != CERTONE_OK) {
            return st;
        }
    }
    return CERTONE_OK;
}

int main(void)
{
    state s;
    certone_config cfg;
    certone_snapshot snap;
    certone_scan_options scan_opts;
    certone_ingest_options ingest_opts;
    certone_status st;
    char digest[CERTONE_INPUT_DIGEST_SIZE];
    char *scan_id = NULL;
    char *text = NULL;
    char *report_id = NULL;
    size_t n = 0;
    const char *api_url = require_env("CERTONE_API_URL");
    const char *api_key = require_env("CERTONE_API_KEY");
    const char *snapshot = require_env("CERTONE_SNAPSHOT");
    const char *report_json = require_env("CERTONE_REPORT_JSON");

    if (api_url == NULL || api_key == NULL || snapshot == NULL || report_json == NULL) {
        return 1;
    }
    memset(&s, 0, sizeof s);
    if (certone_global_init() != CERTONE_OK) {
        fprintf(stderr, "error: libcurl initialisation failed\n");
        return 1;
    }

    /* 1. Client from the environment (the key is never printed). */
    memset(&cfg, 0, sizeof cfg);
    cfg.base_url = api_url;
    cfg.token = api_key;
    st = certone_client_new(&cfg, &s.client);
    if (st != CERTONE_OK) {
        return fail_api(&s, "create client", st);
    }
    printf("[1] CertOne C SDK %s, API %s\n", certone_version(), api_url);

    /* 2. submit_check of the sample project. */
    memset(&snap, 0, sizeof snap);
    snap.path = snapshot;
    memset(&scan_opts, 0, sizeof scan_opts);
    scan_opts.asset = ASSET;
    scan_opts.fail_on = "high";
    st = certone_submit_check(s.client, &snap, &scan_opts, &s.check);
    if (st != CERTONE_OK) {
        return fail_api(&s, "submit_check", st);
    }
    st = certone_json_get_string(s.check, "scan_run.id", &scan_id);
    if (st != CERTONE_OK) {
        return fail_json(&s, "scan_run.id", st);
    }
    printf("[2] submit_check: scan %s\n", scan_id);
    st = certone_json_get_string(s.check, "report.verdict_status", &text);
    if (st == CERTONE_OK) {
        printf("    verdict: %s\n    findings by severity: ", text);
        certone_free(text);
        text = NULL;
        st = print_counts(s.check, "report.by_severity");
        printf("\n");
    } else if (st == CERTONE_E_NOT_FOUND) {
        printf("    queued: the report is produced asynchronously\n");
        st = CERTONE_OK;
    }
    if (st != CERTONE_OK) {
        certone_free(scan_id);
        return fail_json(&s, "report.verdict_status / report.by_severity", st);
    }

    /* 3. wait_for_report, then the full engine document and its first finding. */
    st = certone_wait_for_report(s.client, scan_id, 0, 0, &s.report);
    certone_free(scan_id);
    if (st != CERTONE_OK) {
        return fail_api(&s, "wait_for_report", st);
    }
    st = certone_json_get_string(s.report, "id", &report_id);
    if (st != CERTONE_OK) {
        return fail_json(&s, "report id", st);
    }
    st = certone_get_report_document(s.client, report_id, &s.document);
    if (st != CERTONE_OK) {
        certone_free(report_id);
        return fail_api(&s, "get_report_document", st);
    }
    st = certone_json_get_size(s.document, "issues", &n);
    if (st != CERTONE_OK) {
        certone_free(report_id);
        return fail_json(&s, "issues", st);
    }
    printf("[3] wait_for_report: report %s, document has %zu issue(s)\n", report_id, n);
    certone_free(report_id);
    report_id = NULL;
    if (n > 0) {
        char *sev = NULL;
        char *topic = NULL;
        char *desc = NULL;
        st = certone_json_get_string(s.document, "issues[0].severity", &sev);
        if (st == CERTONE_OK) {
            st = certone_json_get_string(s.document, "issues[0].compliance_topic", &topic);
        }
        if (st == CERTONE_OK) {
            st = certone_json_get_string(s.document, "issues[0].description", &desc);
        }
        if (st == CERTONE_OK) {
            printf("    first finding: [%s] %s: %s\n", sev, topic, desc);
        }
        certone_free(sev);
        certone_free(topic);
        certone_free(desc);
        if (st != CERTONE_OK) {
            return fail_json(&s, "issues[0]", st);
        }
    }

    /* 4. ingest_report (run-at-source) bound to the snapshot's SHA-256. */
    s.report_doc = read_file(report_json);
    if (s.report_doc == NULL) {
        fprintf(stderr, "error: cannot read %s\n", report_json);
        cleanup(&s);
        return 1;
    }
    st = certone_input_digest_file(snapshot, digest);
    if (st != CERTONE_OK) {
        fprintf(stderr, "error: cannot hash %s: %s\n", snapshot, certone_status_str(st));
        cleanup(&s);
        return 1;
    }
    memset(&ingest_opts, 0, sizeof ingest_opts);
    ingest_opts.asset = ASSET;
    ingest_opts.environment = "edge";
    ingest_opts.country_code = "EU";
    ingest_opts.input_digest = digest;
    st = certone_ingest_report(s.client, s.report_doc, &ingest_opts, &s.ingest);
    if (st != CERTONE_OK) {
        return fail_api(&s, "ingest_report", st);
    }
    st = certone_json_get_string(s.ingest, "report.verdict_status", &text);
    if (st != CERTONE_OK) {
        return fail_json(&s, "report.verdict_status", st);
    }
    printf("[4] ingest_report: verdict %s (input_digest %s)\n", text, digest);
    certone_free(text);
    text = NULL;

    /* 5. get_attestation for the ingested report. */
    st = certone_json_get_string(s.ingest, "report.id", &report_id);
    if (st != CERTONE_OK) {
        return fail_json(&s, "report.id", st);
    }
    st = certone_get_attestation(s.client, report_id, &s.attestation);
    certone_free(report_id);
    if (st != CERTONE_OK) {
        return fail_api(&s, "get_attestation", st);
    }
    {
        char *att_id = NULL;
        char *version = NULL;
        char *alg = NULL;
        st = certone_json_get_string(s.attestation, "attestation_id", &att_id);
        if (st == CERTONE_OK) {
            st = certone_json_get_string(s.attestation, "input_version", &version);
        }
        if (st == CERTONE_OK) {
            st = certone_json_get_string(s.attestation, "signature_algorithm", &alg);
        }
        if (st == CERTONE_OK) {
            printf("[5] get_attestation: attestation_id %s, input_version %s, "
                   "signature_algorithm %s\n",
                   att_id, version, alg);
        }
        certone_free(att_id);
        certone_free(version);
        certone_free(alg);
        if (st != CERTONE_OK) {
            return fail_json(&s, "attestation fields", st);
        }
    }

    /* 6. list_systems. */
    st = certone_list_systems(s.client, &s.systems);
    if (st != CERTONE_OK) {
        return fail_api(&s, "list_systems", st);
    }
    st = certone_json_get_size(s.systems, "", &n);
    if (st != CERTONE_OK) {
        return fail_json(&s, "systems", st);
    }
    printf("[6] list_systems: %zu AI system(s) in the tenant\n", n);

    /* 7. Done. */
    printf("[7] quickstart OK\n");
    cleanup(&s);
    return 0;
}
