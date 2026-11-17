/*
 * CertOne C SDK -- a small client for the CertOne control-plane REST API (see SPEC.md).
 *
 * Depends only on libcurl (>= 7.56). C11. Intended for embedded Linux devices and gateways
 * (ARM64, RISC-V) and for native build tooling on Linux/macOS.
 *
 * Conventions
 *   - Every operation returns a certone_status. CERTONE_OK (0) is success; errors are negative.
 *   - On failure the client keeps a human-readable message (certone_last_error) and, for HTTP
 *     errors, the status code (certone_last_http_status). The message carries the API's `detail`.
 *   - Successful responses are returned as the raw JSON body in a NUL-terminated, heap-allocated
 *     buffer owned by the caller. Release it with certone_free(). On failure *out_json is NULL.
 *   - The certone_json_* accessors read scalar fields from such a buffer by path, for example
 *     "report.verdict_status", "issues[0].severity" or "[2].name" (see certone_json_get_string).
 *   - A certone_client is not thread-safe: use one client per thread. Call certone_global_init()
 *     once at program start, before any thread creates a client, and certone_global_cleanup()
 *     once at exit.
 *   - The API token is sent only in the Authorization header and is never written to error
 *     messages.
 */
#ifndef CERTONE_H
#define CERTONE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(CERTONE_SHARED) && defined(__GNUC__)
#define CERTONE_API __attribute__((visibility("default")))
#else
#define CERTONE_API
#endif

#define CERTONE_VERSION_MAJOR 0
#define CERTONE_VERSION_MINOR 1
#define CERTONE_VERSION_PATCH 0
#define CERTONE_VERSION_STRING "0.1.0"

/* ------------------------------------------------------------------------------------------ */
/* Status codes                                                                               */
/* ------------------------------------------------------------------------------------------ */

typedef enum certone_status {
    CERTONE_OK = 0,
    CERTONE_E_INVALID_ARG = -1, /* NULL/empty required argument, or a value with CR/LF/NUL      */
    CERTONE_E_NOMEM = -2,       /* allocation failed                                             */
    CERTONE_E_IO = -3,          /* reading a local file (snapshot) failed                        */
    CERTONE_E_NETWORK = -4,     /* transport error: DNS, connect, TLS, reset ...                 */
    CERTONE_E_TIMEOUT = -5,     /* request timeout, or wait_for_report deadline reached          */
    CERTONE_E_HTTP = -6,        /* HTTP status >= 300; see certone_last_http_status/last_error   */
    CERTONE_E_SCAN_FAILED = -7, /* wait_for_report: the scan finished with status "failed"       */
    CERTONE_E_JSON = -8,        /* malformed JSON (response body, report argument or accessor)   */
    CERTONE_E_NOT_FOUND = -9,   /* JSON accessor: the path does not exist                        */
    CERTONE_E_TYPE = -10,       /* JSON accessor: the value has a different type                 */
    CERTONE_E_RANGE = -11,      /* JSON accessor: number out of range for the requested type     */
    CERTONE_E_TOO_LARGE = -12   /* response body larger than certone_config.max_response_bytes   */
} certone_status;

/* Static, human-readable name of a status code ("CERTONE_E_HTTP: HTTP error", ...). */
CERTONE_API const char *certone_status_str(certone_status status);

/* Library version string, e.g. "0.1.0". */
CERTONE_API const char *certone_version(void);

/* ------------------------------------------------------------------------------------------ */
/* Library and client lifecycle                                                               */
/* ------------------------------------------------------------------------------------------ */

/* Initialise libcurl. Call once before creating clients (not thread-safe on old libcurl). */
CERTONE_API certone_status certone_global_init(void);
/* Release libcurl global state. Call once after all clients are freed. */
CERTONE_API void certone_global_cleanup(void);

typedef struct certone_config {
    const char *base_url;       /* required, e.g. "https://api.example.com" (trailing '/' ok) */
    const char *token;          /* tenant API key (ck_...) or OIDC ID token; NULL = no auth    */
    long connect_timeout_ms;    /* 0 = default 5000                                            */
    long timeout_ms;            /* whole request, including upload; 0 = default 30000          */
    size_t max_response_bytes;  /* 0 = default 64 MiB                                          */
    const char *ca_bundle_path; /* optional PEM CA bundle for TLS verification                 */
    const char *user_agent;     /* optional; default "certone-c/<version>"                     */
} certone_config;

typedef struct certone_client certone_client;

/* Create a client. Strings in *config are copied. Returns CERTONE_E_INVALID_ARG for a missing
 * base_url, a base_url that is not http(s), or a token/user agent containing CR, LF or NUL. */
CERTONE_API certone_status certone_client_new(const certone_config *config, certone_client **out);
CERTONE_API void certone_client_free(certone_client *client);

/* Message describing the last failed operation on this client ("" if none). Valid until the
 * next operation on the client. For HTTP errors: "HTTP <status>: <detail>". */
CERTONE_API const char *certone_last_error(const certone_client *client);
/* HTTP status of the last response (0 if no response was received). */
CERTONE_API long certone_last_http_status(const certone_client *client);

/* Free a buffer returned by this library (response bodies, accessor strings). NULL is ok. */
CERTONE_API void certone_free(void *ptr);

/* ------------------------------------------------------------------------------------------ */
/* Operations (SPEC.md)                                                                   */
/* ------------------------------------------------------------------------------------------ */

/* A project snapshot (.tar.gz) to upload: either a file path or an in-memory buffer. */
typedef struct certone_snapshot {
    const char *path;     /* read from this file, or NULL to use data/size              */
    const void *data;     /* in-memory snapshot bytes (used when path is NULL)           */
    size_t size;          /* number of bytes at data                                     */
    const char *filename; /* multipart filename; default basename(path) or "snapshot.tar.gz" */
} certone_snapshot;

/* Multipart form fields; NULL fields are omitted and the server default applies. */
typedef struct certone_scan_options {
    const char *asset;        /* AI system name (auto-registered on first scan)            */
    const char *environment;  /* ci|jupyter|vscode|edge|api|cloud|cli (default api)        */
    const char *country_code; /* origin region, e.g. "EU" (default ZZ)                     */
    const char *fail_on;      /* low|medium|high|none (default high)                       */
    const char *packs;        /* comma-separated policy packs (default: matched from BOM)  */
    const char *snapshot_ref; /* stable source reference, e.g. "git:org/repo@sha"          */
    const char *commit_hash;  /* commit the scan is about                                  */
    const char *tee;          /* submit_process only: confidential-compute backend         */
} certone_scan_options;

/* POST /v1/checks -> CheckResult JSON {scan_run, report, queued}. options may be NULL. */
CERTONE_API certone_status certone_submit_check(certone_client *client,
                                                const certone_snapshot *snapshot,
                                                const certone_scan_options *options,
                                                char **out_json);

/* POST /v1/process -> CheckResult JSON; on the confidential worker pool queued=true and
 * report=null: use certone_wait_for_report on scan_run.id. options may be NULL. */
CERTONE_API certone_status certone_submit_process(certone_client *client,
                                                  const certone_snapshot *snapshot,
                                                  const certone_scan_options *options,
                                                  char **out_json);

/* GET /v1/scans/{scan_id} -> ScanRun JSON. */
CERTONE_API certone_status certone_get_scan(certone_client *client, const char *scan_id,
                                            char **out_json);

/* Poll GET /v1/scans/{scan_id} every interval_ms until status is "succeeded" or "failed", then
 * GET /v1/scans/{scan_id}/report -> Report JSON. A failed scan returns CERTONE_E_SCAN_FAILED with
 * the scan's `error` in certone_last_error. Defaults when 0: interval 2000 ms, timeout 900000 ms.
 * Reaching the timeout returns CERTONE_E_TIMEOUT. */
CERTONE_API certone_status certone_wait_for_report(certone_client *client, const char *scan_id,
                                                   long timeout_ms, long interval_ms,
                                                   char **out_json);

/* GET /v1/reports/{report_id}/document -> full engine report {verdict, summary, issues[]}.
 * report_id is the report record's `id` (e.g. "report.id"), not the engine's report_id. */
CERTONE_API certone_status certone_get_report_document(certone_client *client,
                                                       const char *report_id, char **out_json);

/* GET /v1/reports/{report_id}/attestation -> attestation JSON (HTTP 404 if it did not pass). */
CERTONE_API certone_status certone_get_attestation(certone_client *client, const char *report_id,
                                                   char **out_json);

/* Run-at-source body fields; NULL fields are omitted and the server default applies. */
typedef struct certone_ingest_options {
    const char *asset;
    const char *environment;  /* default api   */
    const char *country_code; /* default ZZ    */
    const char *snapshot_ref;
    const char *input_digest; /* "sha256:<hex>" of the artifact; see certone_input_digest_file */
    const char *repo;         /* e.g. "org/repo" */
    const char *commit_hash;
} certone_ingest_options;

/* POST /v1/checks/report with {"report": <report_json>, ...options} -> CheckResult JSON.
 * report_json must be a JSON object (it is validated and embedded verbatim). */
CERTONE_API certone_status certone_ingest_report(certone_client *client, const char *report_json,
                                                 const certone_ingest_options *options,
                                                 char **out_json);

/* GET /v1/systems -> JSON array of AI systems. */
CERTONE_API certone_status certone_list_systems(certone_client *client, char **out_json);

/* ------------------------------------------------------------------------------------------ */
/* JSON accessors                                                                             */
/* ------------------------------------------------------------------------------------------ */
/*
 * Path syntax: object keys separated by '.', array elements as "[index]".
 *   ""                       the whole document
 *   "report.verdict_status"  nested object member
 *   "issues[0].severity"     first element of the "issues" array, then its member
 *   "[1].name"               element of a top-level array
 * A backslash escapes the next character inside a key ("a\.b" is the key "a.b").
 * The whole document is validated (RFC 8259, UTF-8, nesting depth < 256) on every call.
 * If an object repeats a key, the last occurrence wins.
 * Errors: CERTONE_E_INVALID_ARG (NULL arg or malformed path), CERTONE_E_JSON (malformed
 * document), CERTONE_E_NOT_FOUND, CERTONE_E_TYPE, CERTONE_E_RANGE, CERTONE_E_NOMEM.
 */

typedef enum certone_json_type {
    CERTONE_JSON_NULL = 1,
    CERTONE_JSON_BOOL = 2,
    CERTONE_JSON_NUMBER = 3,
    CERTONE_JSON_STRING = 4,
    CERTONE_JSON_ARRAY = 5,
    CERTONE_JSON_OBJECT = 6
} certone_json_type;

/* Check that json is a single valid JSON value (surrounded only by whitespace). */
CERTONE_API certone_status certone_json_validate(const char *json);

/* Type of the value at path. */
CERTONE_API certone_status certone_json_type_at(const char *json, const char *path,
                                                certone_json_type *out_type);

/* Decoded UTF-8 copy of a string value (free with certone_free). A string containing an
 * escaped NUL (\u0000) or an unpaired surrogate is rejected with CERTONE_E_TYPE. */
CERTONE_API certone_status certone_json_get_string(const char *json, const char *path,
                                                   char **out);

/* Integer value. Fractions/exponents are CERTONE_E_TYPE; overflow is CERTONE_E_RANGE. */
CERTONE_API certone_status certone_json_get_int(const char *json, const char *path,
                                                int64_t *out);

/* Any JSON number as double (locale-independent). Overflow is CERTONE_E_RANGE. */
CERTONE_API certone_status certone_json_get_double(const char *json, const char *path,
                                                   double *out);

/* true/false as 1/0. */
CERTONE_API certone_status certone_json_get_bool(const char *json, const char *path, int *out);

/* Number of elements of an array, or of members of an object. */
CERTONE_API certone_status certone_json_get_size(const char *json, const char *path,
                                                 size_t *out);

/* Decoded name of the index-th member (document order) of the object at path. Free with
 * certone_free. Use with certone_json_get_size to iterate an object such as "by_severity". */
CERTONE_API certone_status certone_json_get_key(const char *json, const char *path, size_t index,
                                                char **out);

/* Copy of the raw JSON text of the value at path (free with certone_free), e.g. to pass a
 * sub-object on or to parse it with another library. */
CERTONE_API certone_status certone_json_get_raw(const char *json, const char *path, char **out);

/* ------------------------------------------------------------------------------------------ */
/* SHA-256 (FIPS 180-4) and input_digest                                                      */
/* ------------------------------------------------------------------------------------------ */

#define CERTONE_SHA256_DIGEST_SIZE 32
/* "sha256:" + 64 hex digits + NUL */
#define CERTONE_INPUT_DIGEST_SIZE 72

typedef struct certone_sha256_ctx {
    uint32_t state[8];
    uint64_t bit_count;
    uint8_t buffer[64];
    size_t buffer_len;
} certone_sha256_ctx;

CERTONE_API void certone_sha256_init(certone_sha256_ctx *ctx);
CERTONE_API void certone_sha256_update(certone_sha256_ctx *ctx, const void *data, size_t len);
CERTONE_API void certone_sha256_final(certone_sha256_ctx *ctx,
                                      uint8_t digest[CERTONE_SHA256_DIGEST_SIZE]);
/* One-shot digest of a buffer. */
CERTONE_API void certone_sha256(const void *data, size_t len,
                                uint8_t digest[CERTONE_SHA256_DIGEST_SIZE]);

/* "sha256:<lowercase hex>" of a buffer, written to out (CERTONE_INPUT_DIGEST_SIZE bytes). */
CERTONE_API void certone_input_digest(const void *data, size_t len,
                                      char out[CERTONE_INPUT_DIGEST_SIZE]);
/* "sha256:<lowercase hex>" of a file's bytes (streamed). CERTONE_E_IO if it cannot be read. */
CERTONE_API certone_status certone_input_digest_file(const char *path,
                                                     char out[CERTONE_INPUT_DIGEST_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* CERTONE_H */
