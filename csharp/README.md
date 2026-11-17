# CertOne SDK for .NET

A typed async client for the CertOne control-plane API (`Certkor.CertOne`, .NET 8+). Submit AI-system
snapshots for compliance checks or confidential processing, wait for verdicts, fetch report documents
and attestations, ingest run-at-source reports and list AI systems. No runtime dependencies beyond the
.NET base library; trimming and AOT safe. It implements the contract in [`SPEC.md`](../SPEC.md).

## Install

```bash
dotnet add package Certkor.CertOne
```

## Usage

```csharp
using Certkor.CertOne;

using var client = new CertOneClient("https://api.yourco.com", Environment.GetEnvironmentVariable("CERTONE_API_KEY"));

var check = await client.SubmitCheckAsync("model.tar.gz", new ScanOptions { Asset = "Fraud Scorer", CountryCode = "EU" });
var report = check.Report ?? await client.WaitForReportAsync(check.ScanRun.Id);
Console.WriteLine($"{report.VerdictStatus}: {report.TotalIssues} findings");

var document = await client.GetReportDocumentAsync(report.Id);   // full engine report (JsonElement)
var systems = await client.ListSystemsAsync();
```

`report.Id` (the report record id) is what `GetReportDocumentAsync` and `GetAttestationAsync` take, not
the engine's `report.ReportId`.

### Run at the source

Evaluate where the model lives and submit only the report, bound to the exact input by its digest:

```csharp
using var engineReport = JsonDocument.Parse(File.ReadAllBytes("report.json"));
var result = await client.IngestReportAsync(engineReport.RootElement, new IngestOptions
{
    Asset = "Fraud Scorer",
    Environment = ScanEnvironments.Edge,
    CountryCode = "EU",
    InputDigest = await InputDigest.ComputeFileAsync("model.tar.gz"),   // sha256:<hex>
});
var attestation = await client.GetAttestationAsync(result.Report!.Id);
```

### Confidential processing

`SubmitProcessAsync` runs static and dynamic evaluation on an attested worker (`ScanOptions.Tee`,
default `amd_sev_snp`). On the confidential worker pool the result is queued (`Queued == true`,
`Report == null`); call `WaitForReportAsync(scanId, timeout, interval)` (defaults 900 s and 2 s).

### Dependency injection

The client takes an injected `HttpClient`, so it works as a typed client with `IHttpClientFactory`:

```csharp
services.AddSingleton(new CertOneClientOptions { BaseUrl = new Uri("https://api.yourco.com"), ApiKey = apiKey });
services.AddHttpClient<ICertOneClient, CertOneClient>();
```

An injected `HttpClient` is never disposed or modified by the SDK. A client created from a URL owns its
`HttpClient` (5 s connect timeout) and should be reused and disposed once.

## Errors

Every operation throws `CertOneException` when:

- the API answers with HTTP status 400 or above: `StatusCode` is set and `Detail` is the API's
  `detail` message (for example `HTTP 404: scan not found`);
- the request fails on the network or exceeds the request timeout (default 30 s,
  `CertOneClientOptions.RequestTimeout`): `StatusCode` is null and `InnerException` holds the cause
  (`TimeoutException` for timeouts);
- the response is not valid JSON;
- `WaitForReportAsync` sees the scan fail (`Detail` is the scan's `error`) or run past its timeout;
  `Scan` holds the last scan seen.

`GetAttestationAsync` returns 404 when the verdict did not pass. Cancelling the `CancellationToken`
you pass throws `OperationCanceledException`, as usual in .NET. The API key is never logged or included
in exception messages.

## Develop

```bash
cd csharp
dotnet build -warnaserror
dotnet test
```

`bash csharp/ci/run.sh` builds, tests and packs in the `mcr.microsoft.com/dotnet/sdk:8.0` container
and runs `examples/Quickstart` against the local conformance control plane
The live conformance run needs a CertOne test environment; Certkor AI provides one to partners on request. The offline tests (`ci/run.sh --offline`) need nothing else.
