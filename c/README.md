# CertOne C SDK

A C11 client for the CertOne control-plane API, for embedded Linux devices and
gateways (ARM64, RISC-V) and native build tooling. It depends only on **libcurl** (>= 7.56): JSON
reading and SHA-256 are built in.

## Build and install

```bash
# CMake: static + shared library, tests, quickstart
cmake -S c -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build               # offline unit tests
cmake --install build --prefix /usr/local

# or plain make (needs only make, cc and pkg-config for libcurl)
make -C c                        # build/libcertone.a, build/libcertone.so
make -C c check
make -C c install PREFIX=/usr/local
```

Consume it with `find_package(certone)` and `target_link_libraries(app certone::certone)`, or with
`pkg-config --cflags --libs certone`.

## Usage

```c
#include <certone.h>

certone_global_init();
certone_config cfg = {.base_url = "https://api.yourco.com", .token = getenv("CERTONE_API_KEY")};
certone_client *c;
if (certone_client_new(&cfg, &c) != CERTONE_OK) return 1;
certone_snapshot snap = {.path = "project.tar.gz"};
certone_scan_options opts = {.asset = "Fraud Scorer", .environment = "ci", .fail_on = "high"};
char *json = NULL, *verdict = NULL;
if (certone_submit_check(c, &snap, &opts, &json) == CERTONE_OK &&
    certone_json_get_string(json, "report.verdict_status", &verdict) == CERTONE_OK)
    printf("verdict: %s\n", verdict);
else
    fprintf(stderr, "error: %s\n", certone_last_error(c));
certone_free(verdict); certone_free(json); certone_client_free(c); certone_global_cleanup();
```

`examples/quickstart.c` runs the full conformance flow: check, wait for the report, read the first
finding, run-at-source ingest with `input_digest`, attestation, AI systems.

## Operations

| Function | API |
|---|---|
| `certone_submit_check(c, &snapshot, &options, &json)` | `POST /v1/checks` (multipart) |
| `certone_submit_process(c, &snapshot, &options, &json)` | `POST /v1/process` (`options.tee` is sent) |
| `certone_get_scan(c, scan_id, &json)` | `GET /v1/scans/{id}` |
| `certone_wait_for_report(c, scan_id, timeout_ms, interval_ms, &json)` | polls the scan, then `GET /v1/scans/{id}/report` |
| `certone_get_report_document(c, report_id, &json)` | `GET /v1/reports/{id}/document` |
| `certone_get_attestation(c, report_id, &json)` | `GET /v1/reports/{id}/attestation` |
| `certone_ingest_report(c, report_json, &options, &json)` | `POST /v1/checks/report` |
| `certone_list_systems(c, &json)` | `GET /v1/systems` |

A snapshot is either a file (`.path`, streamed from disk) or a buffer (`.data` + `.size`, not
copied). `NULL` option fields are not sent, so the server defaults apply. `report_id` is the report
record's `id` (`report.id`), not the engine's `report_id`.

Every response is returned as the raw JSON body in a heap buffer you own: free it with
`certone_free()`. Read fields with the built-in accessors:

```c
certone_json_get_string(json, "scan_run.id", &s);          /* decoded UTF-8, free with certone_free */
certone_json_get_int(json, "report.by_severity.high", &n);  /* int64_t */
certone_json_get_string(doc, "issues[0].severity", &s);     /* array index */
certone_json_get_size(systems, "", &count);                 /* top-level array length */
certone_json_get_key(json, "report.by_severity", i, &key);  /* iterate object members */
certone_json_get_raw(json, "report", &sub);                 /* sub-document as JSON text */
```

Paths are keys joined by `.` with `[n]` for array elements; `\` escapes a `.` or `[` inside a key.
Accessors validate the whole document (RFC 8259, UTF-8, depth < 256) and return
`CERTONE_E_NOT_FOUND`, `CERTONE_E_TYPE` or `CERTONE_E_RANGE` rather than guessing.

`certone_input_digest_file(path, out)` writes `sha256:<hex>` of a file, the `input_digest` that
binds a run-at-source attestation to its input. `certone_sha256_init/update/final` stream it.

## Errors and timeouts

Every call returns a `certone_status`; `CERTONE_OK` is 0 and errors are negative. After a failure,
`certone_last_error(c)` holds the message and `certone_last_http_status(c)` the HTTP status:

| Status | When |
|---|---|
| `CERTONE_E_HTTP` | HTTP status >= 300; message is `HTTP <status>: <API detail>` |
| `CERTONE_E_NETWORK` | DNS, connect, TLS or transport failure |
| `CERTONE_E_TIMEOUT` | request timeout, or `wait_for_report` deadline |
| `CERTONE_E_SCAN_FAILED` | `wait_for_report`: the scan failed; message carries the scan's `error` |
| `CERTONE_E_JSON` / `CERTONE_E_TOO_LARGE` | malformed response, or larger than `max_response_bytes` (64 MiB) |
| `CERTONE_E_IO` / `CERTONE_E_INVALID_ARG` / `CERTONE_E_NOMEM` | local file, argument or allocation failure |

Defaults: connect timeout 5 s, request timeout 30 s (`connect_timeout_ms`, `timeout_ms` in
`certone_config`), `wait_for_report` interval 2 s and timeout 900 s (pass 0 for the defaults).
TLS peer and host verification are always on; set `ca_bundle_path` for a private CA. Redirects
are not followed, so the token is only ever sent to `base_url`, and it never appears in error
messages. A client is not thread-safe: use one per thread, and call `certone_global_init()` once
before starting threads.

## Cross-compiling

The library is plain C11 + libcurl, so any cross toolchain with the target's libcurl works. With
Debian multiarch:

```bash
apt-get install gcc-aarch64-linux-gnu libcurl4-openssl-dev:arm64
PKG_CONFIG_LIBDIR=/usr/lib/aarch64-linux-gnu/pkgconfig \
  make -C c CC=aarch64-linux-gnu-gcc AR=aarch64-linux-gnu-ar BUILD=build-arm64
```

Use `riscv64-linux-gnu-gcc` and `libcurl4-openssl-dev:riscv64` for RISC-V. Without pkg-config for
the target, pass `CURL_CFLAGS` and `CURL_LIBS` to `make`. `cpp/ci/cross-toolchain.cmake` is a
CMake toolchain file for the same setup.

## CI

```bash
The live conformance run needs a CertOne test environment; Certkor AI provides one to partners on request. The offline tests (`ci/run.sh --offline`) need nothing else.
bash c/ci/run.sh                                                  # everything below, in Docker
CERTONE_SKIP_QUICKSTART=1 bash c/ci/run.sh                        # offline only
```

`ci/run.sh` builds `ci/Dockerfile` (Debian trixie: gcc, CMake, libcurl, valgrind, aarch64 and
riscv64 cross toolchains with their libcurl, qemu-user) and runs `ci/ci.sh`: the CMake and make
builds with `-Werror`, the unit tests, ASan + UBSan and valgrind runs of the tests and the
quickstart, aarch64 and riscv64 cross builds whose tests and quickstart run under qemu-user, and
the quickstart against the conformance control plane.
