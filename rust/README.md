# CertOne Rust SDK

A blocking Rust client for the CertOne control-plane API (crate `certone`). It implements the
contract steps: submit a compliance check, wait for the verdict, read the full report, ingest a report computed at the source, and fetch the attestation.

TLS is rustls (no OpenSSL). No async runtime is required.

## Install

The crate ships in the CertOne repository (it is not on crates.io). Depend on it by path:

```toml
[dependencies]
certone = { path = "CertOne/rust" }
```

## Usage

```rust
use certone::{Client, Environment, FailOn, IngestOptions, ScanOptions, Snapshot};

let client = Client::new("https://api.yourco.com", std::env::var("CERTONE_API_KEY")?)?;
let snapshot = Snapshot::from_path("project.tar.gz")?;
let check = client.submit_check(&snapshot, &ScanOptions::new().asset("Fraud Scorer").fail_on(FailOn::High))?;
let report = client.wait_for_report(&check.scan_run.id, certone::DEFAULT_WAIT_TIMEOUT, certone::DEFAULT_POLL_INTERVAL)?;
let document = client.get_report_document(&report.id)?;          // verdict, summary, issues[]
let local = serde_json::from_str(&std::fs::read_to_string("report.json")?)?;
let opts = IngestOptions::new().environment(Environment::Edge).country_code("EU").input_digest(snapshot.input_digest());
let ingested = client.ingest_report(&local, &opts)?;           // run-at-source: the model stays local
let attestation = client.get_attestation(&ingested.require_report()?.id)?;
```

Operations: `submit_check`, `submit_process` (confidential processing; set `ScanOptions::tee`),
`get_scan`, `wait_for_report`, `get_report_document`, `get_attestation`, `ingest_report`,
`list_systems`. The token is an API key (`ck_...`) or an OIDC ID token; it is sent as
`Authorization: Bearer` and never appears in `Debug` output or errors.

Timeouts: connect 5 s and request 30 s by default; change them with
`Client::builder(url, token).connect_timeout(..).request_timeout(..).build()`.

## Errors

Every operation returns `certone::Result<T>`; the error type is `certone::Error`.

| Variant | When |
|---|---|
| `Api { status, detail }` | HTTP status >= 400; `detail` is the API's message |
| `Transport { message, timeout, .. }` | DNS, connect, TLS or I/O failure, or a timeout |
| `ScanFailed { scan_id, message }` | `wait_for_report` saw the scan fail |
| `WaitTimeout { scan_id, waited, last_status }` | `wait_for_report` deadline elapsed |
| `Queued { scan_id }` | `require_report()` on a queued submission |
| `Decode`, `Io`, `Config` | unexpected response body, local file error, invalid configuration |

Helpers: `status()`, `detail()`, `is_not_found()` (for example no attestation because the verdict
did not pass), `is_auth()`, `is_timeout()`.

## Quickstart and CI

`examples/quickstart.rs` runs the seven contract steps against a live
control plane:

```bash
The live conformance run needs a CertOne test environment; Certkor AI provides one to partners on request. The offline tests (`ci/run.sh --offline`) need nothing else.
bash rust/ci/run.sh       # in rust:1-bookworm: fmt, clippy, tests, quickstart
```

`SKIP_QUICKSTART=1 bash rust/ci/run.sh` runs only the offline checks (format, lint, unit and
HTTP tests).
