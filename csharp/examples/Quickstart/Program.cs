// CertOne C# SDK quickstart: the 7-step conformance flow from SPEC.md, against a real control plane.
//
//   CERTONE_API_URL      control-plane base URL, for example http://localhost:8088
//   CERTONE_API_KEY      tenant API key (ck_...), never printed
//   CERTONE_SNAPSHOT     project snapshot (.tar.gz) to check
//   CERTONE_REPORT_JSON  engine report computed at the source, to ingest
using System.Text.Json;
using Certkor.CertOne;

try
{
    // 1. Configuration.
    var apiUrl = Required("CERTONE_API_URL");
    var apiKey = Required("CERTONE_API_KEY");
    var snapshotPath = Required("CERTONE_SNAPSHOT");
    var reportPath = Required("CERTONE_REPORT_JSON");

    using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(20));
    Console.CancelKeyPress += (_, e) =>
    {
        e.Cancel = true;
        cts.Cancel();
    };
    var ct = cts.Token;

    using var client = new CertOneClient(apiUrl, apiKey);
    Console.WriteLine($"CertOne C# SDK quickstart -> {client.BaseUrl}");

    // 2. Static compliance check of the sample project.
    var check = await client.SubmitCheckAsync(
        snapshotPath,
        new ScanOptions { Asset = "C# SDK quickstart", FailOn = FailOnLevels.High },
        ct);
    Console.WriteLine($"[check] scan {check.ScanRun.Id}");
    if (check.Report is { } checkReport)
    {
        Console.WriteLine($"[check] verdict: {checkReport.VerdictStatus}");
        Console.WriteLine($"[check] findings: {FormatSeverities(checkReport)}");
    }
    else
    {
        Console.WriteLine("[check] queued; the report follows when the scan finishes");
    }

    // 3. Wait for the report, then fetch the full engine document.
    var report = await client.WaitForReportAsync(check.ScanRun.Id, cancellationToken: ct);
    if (check.Report is null)
    {
        Console.WriteLine($"[check] verdict: {report.VerdictStatus}");
        Console.WriteLine($"[check] findings: {FormatSeverities(report)}");
    }

    var document = await client.GetReportDocumentAsync(report.Id, ct);
    if (document.TryGetProperty("issues", out var issues)
        && issues.ValueKind == JsonValueKind.Array
        && issues.GetArrayLength() > 0)
    {
        var first = issues[0];
        Console.WriteLine(
            $"[report] first finding: {Text(first, "issue_id")} [{Text(first, "severity")}] " +
            $"{Text(first, "compliance_topic")}: {Text(first, "description")}");
    }
    else
    {
        Console.WriteLine("[report] no findings");
    }

    // 4. Run-at-source: ingest a report computed where the model lives, bound to the snapshot's digest.
    using var sourceReport = JsonDocument.Parse(await File.ReadAllBytesAsync(reportPath, ct));
    var digest = await InputDigest.ComputeFileAsync(snapshotPath, ct);
    var ingest = await client.IngestReportAsync(
        sourceReport.RootElement,
        new IngestOptions
        {
            Environment = ScanEnvironments.Edge,
            CountryCode = "EU",
            InputDigest = digest,
        },
        ct);
    var ingested = ingest.Report ?? await client.WaitForReportAsync(ingest.ScanRun.Id, cancellationToken: ct);
    Console.WriteLine($"[ingest] input_digest: {digest}");
    Console.WriteLine($"[ingest] verdict: {ingested.VerdictStatus}");

    // 5. Attestation of the ingested (passing) report.
    var attestation = await client.GetAttestationAsync(ingested.Id, ct);
    Console.WriteLine($"[attestation] attestation_id: {Text(attestation, "attestation_id")}");
    Console.WriteLine($"[attestation] input_version: {Text(attestation, "input_version")}");
    Console.WriteLine($"[attestation] signature_algorithm: {Text(attestation, "signature_algorithm")}");

    // 6. AI system inventory.
    var systems = await client.ListSystemsAsync(ct);
    Console.WriteLine($"[systems] {systems.Count} AI system(s) in the tenant");

    // 7. Success.
    Console.WriteLine("quickstart OK");
    return 0;
}
catch (CertOneException ex)
{
    var status = ex.StatusCode is { } code ? $" (HTTP {(int)code})" : string.Empty;
    Console.Error.WriteLine($"quickstart failed{status}: {ex.Message}");
    return 1;
}
catch (Exception ex) when (ex is ArgumentException or IOException or JsonException or UnauthorizedAccessException or OperationCanceledException)
{
    Console.Error.WriteLine($"quickstart failed: {ex.Message}");
    return 1;
}

static string Required(string name) =>
    Environment.GetEnvironmentVariable(name) is { Length: > 0 } value
        ? value
        : throw new ArgumentException($"environment variable {name} is not set");

static string FormatSeverities(Report report)
{
    string[] order = ["critical", "high", "medium", "low"];
    var counts = report.BySeverity
        .OrderBy(kv => Array.IndexOf(order, kv.Key) is var i && i < 0 ? order.Length : i)
        .ThenBy(kv => kv.Key, StringComparer.Ordinal)
        .Select(kv => $"{kv.Key}={kv.Value}");
    var joined = string.Join(' ', counts);
    return joined.Length == 0 ? $"none (total {report.TotalIssues})" : $"{joined} (total {report.TotalIssues})";
}

static string Text(JsonElement element, string property) =>
    element.ValueKind == JsonValueKind.Object && element.TryGetProperty(property, out var value)
        ? value.ValueKind == JsonValueKind.String ? value.GetString() ?? string.Empty : value.GetRawText()
        : "<missing>";
