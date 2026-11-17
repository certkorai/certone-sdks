using System.Text.Json;
using System.Text.Json.Serialization;

namespace Certkor.CertOne;

/// <summary>
/// A scan run (<c>GET /v1/scans/{id}</c>). Unknown fields returned by newer control planes are kept in
/// <see cref="AdditionalProperties"/>.
/// </summary>
public sealed record ScanRun
{
    /// <summary>Scan identifier.</summary>
    public string Id { get; init; } = string.Empty;

    /// <summary>Scan kind, for example <c>check</c> or <c>process</c>.</summary>
    public string Kind { get; init; } = string.Empty;

    /// <summary>Lifecycle status; see <see cref="ScanStatuses"/>.</summary>
    public string Status { get; init; } = string.Empty;

    /// <summary>Stable source reference supplied at submission, if any.</summary>
    public string? SnapshotRef { get; init; }

    /// <summary>Principal that created the scan, for example <c>apikey:&lt;id&gt;</c>.</summary>
    public string? CreatedBy { get; init; }

    /// <summary>When the scan was created (UTC).</summary>
    public DateTimeOffset CreatedAt { get; init; }

    /// <summary>When the scan reached a terminal status (UTC), or <see langword="null"/> while running.</summary>
    public DateTimeOffset? FinishedAt { get; init; }

    /// <summary>The failure reason when <see cref="Status"/> is <c>failed</c>.</summary>
    public string? Error { get; init; }

    /// <summary><see langword="true"/> once the scan has succeeded or failed.</summary>
    [JsonIgnore]
    public bool IsTerminal => Status is ScanStatuses.Succeeded or ScanStatuses.Failed;

    /// <summary>Fields not modelled by this SDK version.</summary>
    [JsonExtensionData]
    [JsonInclude]
    public IDictionary<string, JsonElement>? AdditionalProperties { get; internal set; }
}

/// <summary>
/// A report summary record (<c>GET /v1/scans/{id}/report</c>). Use <see cref="Id"/> with
/// <see cref="ICertOneClient.GetReportDocumentAsync"/> and <see cref="ICertOneClient.GetAttestationAsync"/>.
/// </summary>
public sealed record Report
{
    /// <summary>Report record identifier: the id the <c>/v1/reports/{id}</c> endpoints take.</summary>
    public string Id { get; init; } = string.Empty;

    /// <summary>The scan that produced this report.</summary>
    public string ScanRunId { get; init; } = string.Empty;

    /// <summary>The engine's own report identifier (for example <c>report-bce1fa3cd2cd</c>).</summary>
    public string ReportId { get; init; } = string.Empty;

    /// <summary>Verdict: <c>pass</c> or <c>fail</c>; see <see cref="Verdicts"/>.</summary>
    public string VerdictStatus { get; init; } = string.Empty;

    /// <summary>Severity threshold the verdict was computed against.</summary>
    public string FailOn { get; init; } = string.Empty;

    /// <summary>Total number of findings.</summary>
    public int TotalIssues { get; init; }

    /// <summary>Finding counts keyed by severity (<c>low</c>, <c>medium</c>, <c>high</c>, ...).</summary>
    public IReadOnlyDictionary<string, int> BySeverity { get; init; } = new Dictionary<string, int>();

    /// <summary>Origin region of the evaluated system.</summary>
    public string? CountryCode { get; init; }

    /// <summary>When the report was recorded (UTC).</summary>
    public DateTimeOffset CreatedAt { get; init; }

    /// <summary><see langword="true"/> when <see cref="VerdictStatus"/> is <c>pass</c>.</summary>
    [JsonIgnore]
    public bool Passed => string.Equals(VerdictStatus, Verdicts.Pass, StringComparison.OrdinalIgnoreCase);

    /// <summary>Fields not modelled by this SDK version.</summary>
    [JsonExtensionData]
    [JsonInclude]
    public IDictionary<string, JsonElement>? AdditionalProperties { get; internal set; }
}

/// <summary>
/// Result of <c>POST /v1/checks</c>, <c>POST /v1/process</c> and <c>POST /v1/checks/report</c>.
/// When <see cref="Queued"/> is <see langword="true"/> the report is produced asynchronously:
/// call <see cref="ICertOneClient.WaitForReportAsync"/> with <see cref="ScanRun"/>'s id.
/// </summary>
public sealed record CheckResult
{
    /// <summary>The scan run created by the submission.</summary>
    public ScanRun ScanRun { get; init; } = new();

    /// <summary>The report, or <see langword="null"/> when the submission was queued.</summary>
    public Report? Report { get; init; }

    /// <summary><see langword="true"/> when the scan was queued for the confidential worker pool.</summary>
    public bool Queued { get; init; }

    /// <summary>Processing job counts (<c>submit_process</c> only).</summary>
    public IReadOnlyDictionary<string, int>? Jobs { get; init; }

    /// <summary>Worker health signals (<c>submit_process</c> only).</summary>
    public JsonElement? Health { get; init; }

    /// <summary>Energy measurements (<c>submit_process</c> only).</summary>
    public IReadOnlyDictionary<string, double>? Energy { get; init; }

    /// <summary>Fields not modelled by this SDK version.</summary>
    [JsonExtensionData]
    [JsonInclude]
    public IDictionary<string, JsonElement>? AdditionalProperties { get; internal set; }
}

/// <summary>An AI system registered in the tenant inventory (<c>GET /v1/systems</c>).</summary>
public sealed record AiSystem
{
    /// <summary>System identifier.</summary>
    public string Id { get; init; } = string.Empty;

    /// <summary>URL-safe slug.</summary>
    public string Slug { get; init; } = string.Empty;

    /// <summary>Display name (the scan <c>asset</c>).</summary>
    public string Name { get; init; } = string.Empty;

    /// <summary>Lifecycle stage, for example <c>prod</c>.</summary>
    public string? Lifecycle { get; init; }

    /// <summary>Owning team, if assigned.</summary>
    public string? OwnerTeamId { get; init; }

    /// <summary>Free-text description.</summary>
    public string? Description { get; init; }

    /// <summary>When the system was registered (UTC).</summary>
    public DateTimeOffset CreatedAt { get; init; }

    /// <summary>Regions the system has been evaluated in.</summary>
    public IReadOnlyList<string> Regions { get; init; } = [];

    /// <summary>Environments the system has been evaluated in.</summary>
    public IReadOnlyList<string> Environments { get; init; } = [];

    /// <summary>Standards the system has been assessed against.</summary>
    public IReadOnlyList<string> Standards { get; init; } = [];

    /// <summary>Number of scans.</summary>
    public int Scans { get; init; }

    /// <summary>Open findings from the latest evaluation.</summary>
    public int OpenIssues { get; init; }

    /// <summary>Latest verdict (<c>pass</c> / <c>fail</c>), if evaluated.</summary>
    public string? LastVerdict { get; init; }

    /// <summary>Whether a valid attestation exists.</summary>
    public bool Attested { get; init; }

    /// <summary>Attestation status, for example <c>valid</c> or <c>none</c>.</summary>
    public string? AttestationStatus { get; init; }

    /// <summary>Risk rating, for example <c>low</c> or <c>high</c>.</summary>
    public string? Risk { get; init; }

    /// <summary>When the system was last evaluated (UTC).</summary>
    public DateTimeOffset? LastEvaluated { get; init; }

    /// <summary>Fields not modelled by this SDK version.</summary>
    [JsonExtensionData]
    [JsonInclude]
    public IDictionary<string, JsonElement>? AdditionalProperties { get; internal set; }
}

/// <summary>Scan lifecycle statuses.</summary>
public static class ScanStatuses
{
    /// <summary>Enqueued for the worker pool.</summary>
    public const string Queued = "queued";

    /// <summary>Being evaluated.</summary>
    public const string Running = "running";

    /// <summary>Finished with a report.</summary>
    public const string Succeeded = "succeeded";

    /// <summary>Finished without a report; see <see cref="ScanRun.Error"/>.</summary>
    public const string Failed = "failed";
}

/// <summary>Verdict values.</summary>
public static class Verdicts
{
    /// <summary>No finding at or above the <c>fail_on</c> threshold.</summary>
    public const string Pass = "pass";

    /// <summary>At least one finding at or above the <c>fail_on</c> threshold.</summary>
    public const string Fail = "fail";
}

/// <summary>Values accepted by <see cref="ScanOptions.FailOn"/>.</summary>
public static class FailOnLevels
{
    /// <summary>Fail on any finding.</summary>
    public const string Low = "low";

    /// <summary>Fail on medium or high findings.</summary>
    public const string Medium = "medium";

    /// <summary>Fail on high findings (the server default).</summary>
    public const string High = "high";

    /// <summary>Never fail; report only.</summary>
    public const string None = "none";
}

/// <summary>Values accepted by <see cref="ScanOptions.Environment"/> and <see cref="IngestOptions.Environment"/>.</summary>
public static class ScanEnvironments
{
    /// <summary>Continuous integration.</summary>
    public const string Ci = "ci";

    /// <summary>Jupyter notebook.</summary>
    public const string Jupyter = "jupyter";

    /// <summary>VS Code extension.</summary>
    public const string VsCode = "vscode";

    /// <summary>Edge / embedded device.</summary>
    public const string Edge = "edge";

    /// <summary>Direct API use (the server default).</summary>
    public const string Api = "api";

    /// <summary>Cloud workload.</summary>
    public const string Cloud = "cloud";

    /// <summary>Command-line tooling.</summary>
    public const string Cli = "cli";
}
