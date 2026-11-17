using System.Text.Json;

namespace Certkor.CertOne;

/// <summary>
/// The CertOne control-plane API. Every operation throws <see cref="CertOneException"/> on an HTTP status
/// of 400 or above, a network failure, a request timeout or an invalid response, and
/// <see cref="OperationCanceledException"/> when the caller's <see cref="CancellationToken"/> is cancelled.
/// </summary>
public interface ICertOneClient
{
    /// <summary>
    /// Submits a project snapshot (<c>.tar.gz</c>) for a static compliance check (<c>POST /v1/checks</c>).
    /// The stream is read from its current position and is not disposed.
    /// </summary>
    Task<CheckResult> SubmitCheckAsync(Stream snapshot, ScanOptions? options = null, CancellationToken cancellationToken = default);

    /// <summary>Submits the snapshot file at <paramref name="snapshotPath"/> for a static compliance check.</summary>
    Task<CheckResult> SubmitCheckAsync(string snapshotPath, ScanOptions? options = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Submits a project snapshot for confidential processing (<c>POST /v1/process</c>), static plus dynamic
    /// evaluation on the attested worker selected by <see cref="ScanOptions.Tee"/>. On the confidential worker
    /// pool the result is queued (<see cref="CheckResult.Queued"/>) with no report: use
    /// <see cref="WaitForReportAsync"/>. The stream is read from its current position and is not disposed.
    /// </summary>
    Task<CheckResult> SubmitProcessAsync(Stream snapshot, ScanOptions? options = null, CancellationToken cancellationToken = default);

    /// <summary>Submits the snapshot file at <paramref name="snapshotPath"/> for confidential processing.</summary>
    Task<CheckResult> SubmitProcessAsync(string snapshotPath, ScanOptions? options = null, CancellationToken cancellationToken = default);

    /// <summary>Fetches a scan run (<c>GET /v1/scans/{id}</c>).</summary>
    Task<ScanRun> GetScanAsync(string scanId, CancellationToken cancellationToken = default);

    /// <summary>Fetches the report a finished scan produced (<c>GET /v1/scans/{id}/report</c>).</summary>
    Task<Report> GetScanReportAsync(string scanId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Polls the scan every <paramref name="interval"/> (default 2 s) until it succeeds or fails, then returns
    /// its report. A failed scan, or one still running after <paramref name="timeout"/> (default 900 s), throws
    /// <see cref="CertOneException"/> with <see cref="CertOneException.Scan"/> set.
    /// </summary>
    Task<Report> WaitForReportAsync(
        string scanId,
        TimeSpan? timeout = null,
        TimeSpan? interval = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Fetches the full engine report (<c>verdict</c>, <c>summary</c>, <c>issues[]</c>) for the report record
    /// <paramref name="reportId"/> (<see cref="Report.Id"/>), via <c>GET /v1/reports/{id}/document</c>.
    /// </summary>
    Task<JsonElement> GetReportDocumentAsync(string reportId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Fetches the attestation for the report record <paramref name="reportId"/> (<see cref="Report.Id"/>), via
    /// <c>GET /v1/reports/{id}/attestation</c>. Throws <see cref="CertOneException"/> with status 404 when the
    /// verdict did not pass.
    /// </summary>
    Task<JsonElement> GetAttestationAsync(string reportId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Run-at-source: submits an engine report computed where the model lives (<c>POST /v1/checks/report</c>).
    /// The model and code never leave the caller's environment.
    /// </summary>
    /// <param name="report">The engine report; must be a JSON object.</param>
    /// <param name="options">Where the report was computed and what it covers.</param>
    /// <param name="cancellationToken">Cancels the request.</param>
    Task<CheckResult> IngestReportAsync(JsonElement report, IngestOptions? options = null, CancellationToken cancellationToken = default);

    /// <summary>Lists the tenant's AI systems (<c>GET /v1/systems</c>).</summary>
    Task<IReadOnlyList<AiSystem>> ListSystemsAsync(CancellationToken cancellationToken = default);
}
