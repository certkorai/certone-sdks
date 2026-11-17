# CertOne SDK specification (all languages)

Every CertOne SDK (Python, C, C++, Rust, Java, C#, JavaScript/TypeScript) implements the same small
client over the control-plane REST API, so an organisation can wire CertOne into its own platform,
from embedded build tooling to cloud MLOps. The Python SDK ([`certone-sdk` on PyPI](https://pypi.org/project/certone-sdk/)) is the reference.

## Authentication

Every request sends `Authorization: Bearer <token>`. The token is a tenant **API key**
(`ck_…`, created in the console under Developer Hub, then API keys, or `POST /v1/tenants/{slug}/apikeys`)
or an OIDC ID token. Never log the token.

## Operations

| SDK operation | HTTP | Body | Response (fixture) |
|---|---|---|---|
| `submit_check(snapshot, options)` | `POST /v1/checks` | multipart: `snapshot` (file, `.tar.gz`) + form fields | `CheckResult` (`fixtures/check_result.json`) |
| `submit_process(snapshot, options)` | `POST /v1/process` | multipart: `snapshot` + form fields (+ `tee`) | `CheckResult`; on the confidential worker pool `queued=true` and `report=null` |
| `get_scan(scan_id)` | `GET /v1/scans/{id}` | | `ScanRun` (`fixtures/scan.json`) |
| `wait_for_report(scan_id, timeout, interval)` | polls `GET /v1/scans/{id}` until `status` is `succeeded` or `failed`, then `GET /v1/scans/{id}/report` | | `Report` (`fixtures/report.json`); a `failed` scan raises an error carrying the scan's `error` |
| `get_report_document(report_id)` | `GET /v1/reports/{id}/document` | | full engine report: `verdict`, `summary`, `issues[]` (`fixtures/report_document_excerpt.json`) |
| `get_attestation(report_id)` | `GET /v1/reports/{id}/attestation` | | attestation (`fixtures/attestation.json`); 404 when the verdict did not pass |
| `ingest_report(report, options)` | `POST /v1/checks/report` | JSON (below) | `CheckResult` (`fixtures/ingest_result.json`) |
| `list_systems()` | `GET /v1/systems` | | AI systems (`fixtures/systems.json`) |

`report_id` in the paths above is the report record's `id` (for example `report.id`), not the
engine's `report_id` string.

### Scan options (multipart form fields, all optional)

| Field | Default | Meaning |
|---|---|---|
| `asset` | derived | AI system name (auto-registered on first scan) |
| `environment` | `api` | `ci` \| `jupyter` \| `vscode` \| `edge` \| `api` \| `cloud` \| `cli` |
| `country_code` | `ZZ` | origin region, for example `EU`, `US` |
| `fail_on` | `high` | `low` \| `medium` \| `high` \| `none` |
| `packs` | auto-matched from the AI BOM | comma-separated policy packs |
| `snapshot_ref` | | stable source reference, for example `git:org/repo@sha` |
| `commit_hash` | | commit the scan is about |
| `tee` | `amd_sev_snp` | (`submit_process` only) confidential-compute backend |

### Run-at-source ingest body (`POST /v1/checks/report`, JSON)

```json
{
  "report": { "...": "an engine report computed where the model lives" },
  "asset": "Fraud Scorer", "environment": "edge", "country_code": "EU",
  "snapshot_ref": "git:org/repo@sha",
  "input_digest": "sha256:<hex of the artifact the report covers>",
  "repo": "org/repo", "commit_hash": "<sha>"
}
```

`input_digest` binds the attestation to the exact input: compute it as SHA-256 over the snapshot
bytes. The model and code never leave the caller's environment.

### Errors

Any HTTP status ≥ 400 becomes the SDK's error type carrying the status code and the API's `detail`
message. Network errors and timeouts surface as the same error type. Default request timeout: 30 s
(connect 5 s). `wait_for_report` defaults: interval 2 s, timeout 900 s.

## Conformance

`conformance/` runs a real control plane locally (the production image in dev mode):

```bash
The live conformance run needs a CertOne test environment; Certkor AI provides one to partners on request. The offline tests (`ci/run.sh --offline`) need nothing else.
```

Each SDK ships `examples/quickstart` that, against the seeded control plane:

1. reads `CERTONE_API_URL`, `CERTONE_API_KEY`, `CERTONE_SNAPSHOT`, `CERTONE_REPORT_JSON`;
2. `submit_check` of the sample project (`asset` = "<Language> SDK quickstart", `fail_on` = high);
   prints the scan id, the verdict (`fail`) and the findings by severity;
3. `wait_for_report` on that scan, then `get_report_document` and prints the first finding;
4. `ingest_report` of `run-at-source-report.json` with `environment=edge`, `country_code=EU` and
   `input_digest` = SHA-256 of the snapshot bytes; prints the verdict (`pass`);
5. `get_attestation` for the ingested report; prints `attestation_id`, `input_version` and
   `signature_algorithm`;
6. `list_systems`; prints how many AI systems the tenant has;
7. exits 0, or non-zero with the error on any failure.

Inside a container on the `certone-sdk` network use `CERTONE_API_URL=http://certone-cp:8000`.
