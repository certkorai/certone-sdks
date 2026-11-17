namespace Certkor.CertOne;

/// <summary>
/// Optional form fields for <see cref="ICertOneClient.SubmitCheckAsync(Stream, ScanOptions?, CancellationToken)"/>
/// and <see cref="ICertOneClient.SubmitProcessAsync(Stream, ScanOptions?, CancellationToken)"/>.
/// Unset properties are not sent, so the control plane applies its defaults.
/// </summary>
public sealed class ScanOptions
{
    /// <summary>AI system name; auto-registered on first scan. Server default: derived from the snapshot.</summary>
    public string? Asset { get; set; }

    /// <summary>Where the scan runs; see <see cref="ScanEnvironments"/>. Server default: <c>api</c>.</summary>
    public string? Environment { get; set; }

    /// <summary>Origin region, for example <c>EU</c> or <c>US</c>. Server default: <c>ZZ</c>.</summary>
    public string? CountryCode { get; set; }

    /// <summary>Severity threshold that fails the verdict; see <see cref="FailOnLevels"/>. Server default: <c>high</c>.</summary>
    public string? FailOn { get; set; }

    /// <summary>Policy packs to evaluate. Server default: auto-matched from the AI BOM.</summary>
    public IList<string> Packs { get; } = new List<string>();

    /// <summary>Stable source reference, for example <c>git:org/repo@sha</c>.</summary>
    public string? SnapshotRef { get; set; }

    /// <summary>Commit the scan is about.</summary>
    public string? CommitHash { get; set; }

    /// <summary>
    /// Confidential-compute backend for <c>SubmitProcessAsync</c>, for example <c>amd_sev_snp</c> (the server
    /// default). Ignored by <c>SubmitCheckAsync</c>.
    /// </summary>
    public string? Tee { get; set; }

    /// <summary>The multipart form fields these options produce, in a stable order.</summary>
    internal IEnumerable<KeyValuePair<string, string>> ToFormFields(bool includeTee)
    {
        if (Asset is not null) yield return new("asset", Asset);
        if (Environment is not null) yield return new("environment", Environment);
        if (CountryCode is not null) yield return new("country_code", CountryCode);
        if (FailOn is not null) yield return new("fail_on", FailOn);

        var packs = string.Join(',', Packs.Select(p => p.Trim()).Where(p => p.Length > 0));
        if (packs.Length > 0) yield return new("packs", packs);

        if (SnapshotRef is not null) yield return new("snapshot_ref", SnapshotRef);
        if (CommitHash is not null) yield return new("commit_hash", CommitHash);
        if (includeTee && Tee is not null) yield return new("tee", Tee);
    }
}

/// <summary>
/// Context for <see cref="ICertOneClient.IngestReportAsync"/> (run-at-source). Unset properties are not
/// sent, so the control plane applies its defaults.
/// </summary>
public sealed class IngestOptions
{
    /// <summary>AI system name; auto-registered on first ingest.</summary>
    public string? Asset { get; set; }

    /// <summary>Where the report was computed; see <see cref="ScanEnvironments"/>. Server default: <c>api</c>.</summary>
    public string? Environment { get; set; }

    /// <summary>Origin region, for example <c>EU</c>. Server default: <c>ZZ</c>.</summary>
    public string? CountryCode { get; set; }

    /// <summary>Stable source reference, for example <c>git:org/repo@sha</c>.</summary>
    public string? SnapshotRef { get; set; }

    /// <summary>
    /// <c>sha256:&lt;hex&gt;</c> of the artifact the report covers; binds the attestation to that exact input.
    /// Compute it with <see cref="InputDigest"/>.
    /// </summary>
    public string? InputDigest { get; set; }

    /// <summary>Repository the report is about, for example <c>org/repo</c>.</summary>
    public string? Repo { get; set; }

    /// <summary>Commit the report is about.</summary>
    public string? CommitHash { get; set; }
}

/// <summary>Settings for a <see cref="CertOneClient"/> built around an injected <see cref="HttpClient"/>.</summary>
public sealed class CertOneClientOptions
{
    /// <summary>
    /// Control-plane base URL, for example <c>https://api.yourco.com</c>. When <see langword="null"/>, the
    /// injected <see cref="HttpClient.BaseAddress"/> is used.
    /// </summary>
    public Uri? BaseUrl { get; set; }

    /// <summary>Tenant API key (<c>ck_…</c>) or OIDC ID token, sent as a bearer token. Never logged.</summary>
    public string? ApiKey { get; set; }

    /// <summary>Per-request timeout. Default: 30 seconds.</summary>
    public TimeSpan RequestTimeout { get; set; } = CertOneClient.DefaultRequestTimeout;
}
