# CertOne Java SDK

A typed, thread-safe Java client for the CertOne control-plane API (Java 17+). It implements the
contract steps (submit a compliance check, wait for the verdict, read the full report, ingest a report computed at the source, and fetch the attestation) on `java.net.http.HttpClient`; Jackson is the only runtime
dependency.

## Install

```xml
<dependency>
  <groupId>ai.certkor</groupId>
  <artifactId>certone-sdk</artifactId>
  <version>0.1.0</version>
</dependency>
```

Gradle: `implementation("ai.certkor:certone-sdk:0.1.0")`. JPMS module name: `ai.certkor.certone`.

## Usage

```java
CertOneClient client = CertOneClient.create("https://api.yourco.com", System.getenv("CERTONE_API_KEY"));

CheckResult check = client.submitCheck(Path.of("project.tar.gz"),
    ScanOptions.builder().asset("Fraud Scorer").environment(Environment.CI).failOn(FailOn.HIGH).build());
Report report = client.waitForReport(check.scanRun().id());           // polls every 2 s, up to 900 s
JsonNode document = client.getReportDocument(report.id());           // verdict, summary, issues[]

CheckResult ingested = client.ingestReport(Path.of("report.json"),    // run at the source
    IngestOptions.builder().environment(Environment.EDGE).countryCode("EU")
        .inputDigest(Digests.sha256(Path.of("project.tar.gz"))).build());
JsonNode attestation = client.getAttestation(ingested.report().id()); // 404 unless the verdict passed
```

| Method | HTTP |
|---|---|
| `submitCheck(snapshot, options)` | `POST /v1/checks` (multipart, the file is streamed) |
| `submitProcess(snapshot, options)` | `POST /v1/process` (`queued=true`, `report=null` on the confidential pool) |
| `getScan(scanId)` / `getScanReport(scanId)` | `GET /v1/scans/{id}` / `GET /v1/scans/{id}/report` |
| `waitForReport(scanId, timeout, interval)` | polls the scan until `succeeded` or `failed`, then fetches the report |
| `getReportDocument(reportId)` | `GET /v1/reports/{id}/document` |
| `getAttestation(reportId)` | `GET /v1/reports/{id}/attestation` |
| `ingestReport(report, options)` | `POST /v1/checks/report` (JSON) |
| `listSystems()` | `GET /v1/systems` |

`reportId` is the report record's `Report.id()`, not the engine's `reportId()`. `ScanRun`, `Report`,
`CheckResult` and `AiSystem` are immutable records that ignore unknown fields; report documents and
attestations are Jackson `JsonNode` trees.

Configuration: `CertOneClient.builder(url).token(key).connectTimeout(...).requestTimeout(...)`
(defaults 5 s and 30 s), or `.httpClient(...)` for a proxy, a private CA or mutual TLS. The client
does not follow redirects and never logs or prints the token. Share one instance across threads.

## Errors

Every failure is an unchecked `CertOneException`:

- HTTP status >= 400: `statusCode()` is the status and `detail()` the API's `detail` (for a 422,
  the field errors as `body.report: Field required; ...`);
- network errors and timeouts: `statusCode()` is 0, the cause is the `IOException`
  (`HttpTimeoutException` for a timeout);
- `waitForReport` on a failed scan: `ScanFailedException` with the scan's `error` as `detail()`; past
  its deadline: `statusCode()` 0 with a `TimeoutException` cause. Transient polling errors
  (network, 429/502/503/504) are retried until the deadline.

```java
try {
  client.getAttestation(report.id());
} catch (CertOneException e) {
  if (e.statusCode() == 404) { /* the verdict did not pass: no attestation */ }
}
```

## Build and test

```bash
mvn -B verify                      # compile (lint warnings fail), 60 offline unit tests, javadoc, jars
bash ci/run.sh                     # the above + examples/Quickstart.java against the conformance control plane, in Docker
```

The live conformance run needs a CertOne test environment; Certkor AI provides one to partners on request. The offline tests (`ci/run.sh --offline`) need nothing else.
runs `mvn -B -Pquickstart clean verify` in `maven:3-eclipse-temurin-17` on the `certone-sdk` network.
To run the quickstart yourself, set `CERTONE_API_URL`, `CERTONE_API_KEY`, `CERTONE_SNAPSHOT` and
`CERTONE_REPORT_JSON`, then `mvn -B -Pquickstart verify`.
