# CertOne C++ SDK

A C++17 client for the CertOne control-plane API (`SPEC.md`): an RAII wrapper over the C SDK
(`c`) with `std::string`, `std::optional` and exceptions. It depends only on libcurl.

## Build and install

```bash
# builds the C core from ../c alongside (static) and links it in
cmake -S cpp -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build               # offline unit tests
cmake --install build --prefix /usr/local

# or against an installed C SDK (find_package(certone))
cmake -S cpp -B build -DCERTONE_CPP_USE_INSTALLED_C=ON -DCMAKE_PREFIX_PATH=/usr/local
```

Link `certone::cpp` (`add_subdirectory(cpp)`) or `-lcertone++ -lcertone -lcurl`, and include
`<certone/certone.hpp>`.

## Usage

```cpp
#include <certone/certone.hpp>
#include <cstdlib>
#include <iostream>

int main() try {
    const char *key = std::getenv("CERTONE_API_KEY");
    certone::Client client("https://api.yourco.com", key != nullptr ? key : "");
    certone::ScanOptions opts;
    opts.asset = "Fraud Scorer";
    opts.environment = "ci";
    auto result = client.submit_check(certone::Snapshot::file("project.tar.gz"), opts);
    std::cout << "verdict: " << result.get_string("report.verdict_status") << "\n";
    return 0;
} catch (const certone::Error &e) {
    std::cerr << "error: " << e.what() << " (HTTP " << e.http_status() << ")\n";
    return 1;
}
```

`examples/quickstart.cpp` runs the full conformance flow: check, wait for the report, read the
first finding, run-at-source ingest with `input_digest`, attestation, AI systems.

## API

| Method | API |
|---|---|
| `submit_check(Snapshot, ScanOptions)` | `POST /v1/checks` |
| `submit_process(Snapshot, ScanOptions)` | `POST /v1/process` (`ScanOptions::tee` is sent) |
| `get_scan(scan_id)` | `GET /v1/scans/{id}` |
| `wait_for_report(scan_id, timeout = 15 min, interval = 2 s)` | polls the scan, then `GET /v1/scans/{id}/report` |
| `get_report_document(report_id)` | `GET /v1/reports/{id}/document` |
| `get_attestation(report_id)` | `GET /v1/reports/{id}/attestation` |
| `ingest_report(Json report, IngestOptions)` | `POST /v1/checks/report` |
| `list_systems()` | `GET /v1/systems` |

`Snapshot::file(path)` streams a file; `Snapshot::memory(bytes)` uploads a buffer without copying
it. Unset `std::optional` fields in `ScanOptions` / `IngestOptions` are not sent, so the server
defaults apply. `certone::input_digest_file(path)` returns the `sha256:<hex>` input digest.

Every call returns a `certone::Json`, a validated, immutable JSON document:

```cpp
json.get_string("report.verdict_status");     // throws if absent or not a string
json.get_int("report.by_severity.high");      // std::int64_t
json.find_string("scan_run.error");           // std::optional: nullopt if absent or null
json.size("issues");  json.keys("report.by_severity");  json.at("report");  json.dump();
```

Paths are the C SDK's: keys joined by `.`, `[n]` for array elements, `Json::escape_key()` for keys
containing `.` or `[`.

## Errors

Every failure throws `certone::Error` (a `std::runtime_error`): `status()` is the C status code
(`CERTONE_E_HTTP`, `CERTONE_E_TIMEOUT`, `CERTONE_E_SCAN_FAILED`, `CERTONE_E_NOT_FOUND`, ...),
`http_status()` the HTTP status (0 when no response was received), and `what()` the message; for
HTTP errors that is `HTTP <status>: <API detail>`. Timeouts (connect 5 s, request 30 s) are set in
`certone::Config`. The token is never included in messages and redirects are not followed.

`Client` is move-only and not thread-safe: use one per thread. libcurl is initialised on first use.

## Cross-compiling

```bash
apt-get install g++-aarch64-linux-gnu libcurl4-openssl-dev:arm64
CERTONE_CROSS_TRIPLE=aarch64-linux-gnu cmake -S cpp -B build-arm64 \
  -DCMAKE_TOOLCHAIN_FILE=cpp/ci/cross-toolchain.cmake
cmake --build build-arm64
```

Use `riscv64-linux-gnu` (and `libcurl4-openssl-dev:riscv64`) for RISC-V.

## CI

```bash
The live conformance run needs a CertOne test environment; Certkor AI provides one to partners on request. The offline tests (`ci/run.sh --offline`) need nothing else.
bash cpp/ci/run.sh                                                # everything below, in Docker
CERTONE_SKIP_QUICKSTART=1 bash cpp/ci/run.sh                      # offline only
```

`ci/ci.sh` builds with `-Werror` (bundled and installed C core), runs the unit tests, ASan + UBSan
and valgrind runs of the quickstart, aarch64 and riscv64 cross builds whose tests and quickstart
run under qemu-user, and the quickstart against the conformance control plane.
