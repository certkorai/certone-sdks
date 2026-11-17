# CertOne JavaScript/TypeScript SDK

A typed client for the CertOne control-plane API, for Node.js (18 or later) and browsers. It
implements the contract steps: submit a compliance check, wait for the verdict, read the full report, ingest a report computed at the source, and fetch the attestation. No runtime dependencies:
it uses the platform `fetch`, `FormData`, `Blob` and Web Crypto (or `node:crypto` on Node.js).
Ships ESM and CommonJS builds with type declarations.

## Install

```bash
npm install @certkor/certone
```

## Node.js

```ts
import { readFile } from "node:fs/promises";
import { CertOneClient, inputDigest } from "@certkor/certone";

const certone = new CertOneClient({ baseUrl: "https://api.yourco.com", token: process.env.CERTONE_API_KEY });
const snapshot = await readFile("project.tar.gz");

const check = await certone.submitCheck(snapshot, { asset: "Fraud Scorer", environment: "ci", failOn: "high" });
const report = await certone.waitForReport(check.scan_run.id);   // also covers queued scans
const doc = await certone.getReportDocument(report.id);          // verdict, summary, issues[]
console.log(report.verdict_status, report.by_severity, doc.issues[0]?.description);
```

CommonJS works the same way: `const { CertOneClient } = require("@certkor/certone")`.

## Browser

```ts
import { CertOneClient } from "@certkor/certone";

const certone = new CertOneClient({ baseUrl: "https://api.yourco.com", token: () => session.idToken() });
const file = fileInput.files[0];                         // a .tar.gz picked in <input type="file">
const check = await certone.submitCheck(file, { asset: "Fraud Scorer", environment: "api" });
const systems = await certone.listSystems();
```

Bundlers pick the browser build automatically (no Node.js imports). Use an OIDC ID token from your
identity provider in the browser rather than a long-lived API key. The control plane must allow
your origin (CORS). `inputDigest`/`sha256Hex` need a secure context (`https`) in browsers.

## Authentication

`token` is a tenant API key (`ck_…`, Organization → API keys in the console) or an OIDC ID token,
sent as `Authorization: Bearer <token>`. Pass a function instead of a string to supply a fresh
token on every request. The token is kept in a private field and never appears in errors, logs or
`JSON.stringify(client)`; a token with whitespace or control characters (for example a trailing
`\r` from a CRLF env file) is rejected before any request is sent.

## Operations

| Method | HTTP | Returns |
|---|---|---|
| `submitCheck(snapshot, options?)` | `POST /v1/checks` (multipart) | `CheckResult` |
| `submitProcess(snapshot, options?)` | `POST /v1/process` (multipart, `tee`) | `ProcessResult` (`queued: true`, `report: null` on the confidential pool) |
| `getScan(scanId)` | `GET /v1/scans/{id}` | `ScanRun` |
| `waitForReport(scanId, { timeoutMs, intervalMs, signal })` | polls the scan, then `GET /v1/scans/{id}/report` | `Report` |
| `getReportDocument(reportId)` | `GET /v1/reports/{id}/document` | `ReportDocument` |
| `getAttestation(reportId)` | `GET /v1/reports/{id}/attestation` | `Attestation` (404 when the verdict did not pass) |
| `ingestReport(report, options?)` | `POST /v1/checks/report` (JSON) | `CheckResult` |
| `listSystems()` | `GET /v1/systems` | `AISystem[]` |

`reportId` is the report record's `id` (for example `report.id`), not the engine's `report_id`.
A snapshot is a `.tar.gz` given as a `Blob`/`File`, `ArrayBuffer`, `Uint8Array` or Node `Buffer`.
Response objects keep the API's snake_case field names and ISO-8601 timestamps, and are checked
at runtime against the documented shape.

Scan options (all optional, server defaults apply when omitted): `asset`, `environment`
(`ci | jupyter | vscode | edge | api | cloud | cli`, default `api`), `countryCode` (default `ZZ`),
`failOn` (`low | medium | high | none`, default `high`), `packs` (array or comma-separated),
`snapshotRef`, `commitHash`, `filename`; `submitProcess` adds `tee` (default `amd_sev_snp`).

## Run at source

Evaluate where the model lives and submit only the report. `inputDigest` binds the attestation to
the exact bytes the report covers:

```ts
const result = await certone.ingestReport(engineReport, {
  asset: "Fraud Scorer", environment: "edge", countryCode: "EU",
  inputDigest: await inputDigest(snapshot),           // "sha256:<hex>"
});
const attestation = await certone.getAttestation(result.report!.id);
```

## Errors, timeouts and cancellation

Every failure rejects with `CertOneError`:

```ts
import { CertOneError } from "@certkor/certone";

try {
  await certone.getAttestation(report.id);
} catch (err) {
  if (CertOneError.is(err) && err.kind === "http" && err.status === 404) {
    console.log("no attestation:", err.detail);         // the verdict did not pass
  } else {
    throw err;
  }
}
```

| `kind` | When | Fields |
|---|---|---|
| `http` | status >= 400 | `status`, `detail` (the API's `detail`), `responseBody` |
| `network` | no response (DNS, TLS, connection refused, CORS) | `cause` |
| `timeout` | request timeout, or the `waitForReport` deadline | `scanId` for waits |
| `aborted` | your `AbortSignal` fired | `cause` = the abort reason |
| `scan_failed` | `waitForReport` saw the scan fail | `detail` = the scan's `error`, `scanId` |
| `invalid_response` | a 2xx body that is not the documented JSON | `status`, `responseBody` |

`method` and `url` identify the request. `CertOneError.is(err)` also recognises errors from another
copy of the package (for example the CJS and ESM builds side by side). Invalid arguments throw
`TypeError`/`RangeError` before anything is sent.

Each request times out after 30 s (`timeoutMs` on the client or per call). `waitForReport` polls
every 2 s for up to 900 s. Every method accepts `{ signal }` to cancel. Inject `fetch` to add a
proxy, retries or custom TLS:

```ts
new CertOneClient({ baseUrl, token, timeoutMs: 120_000, fetch: myFetch, headers: { "x-request-id": id } });
```

## Quickstart and development

`examples/quickstart.mjs` (and the typed `examples/quickstart.ts`) run the SPEC conformance flow:
check, wait, document, run-at-source ingest, attestation, systems. Configure with
`CERTONE_API_URL`, `CERTONE_API_KEY`, `CERTONE_SNAPSHOT` and `CERTONE_REPORT_JSON`.

```bash
npm ci && npm run check     # strict typecheck, ESM+CJS build, unit tests, package type lint
js/ci/run.sh            # the same plus the live quickstart, in Docker on Node 18/20/22/24
js/ci/run.sh --offline  # without the conformance control plane
```

The live conformance run needs a CertOne test environment; Certkor AI provides one to partners on request. The offline tests (`ci/run.sh --offline`) need nothing else.
