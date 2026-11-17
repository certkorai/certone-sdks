using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

namespace Certkor.CertOne;

/// <summary>
/// Async client for the CertOne control-plane REST API. Thread-safe; create one per base URL and API key
/// and reuse it.
/// </summary>
/// <example>
/// <code>
/// using var client = new CertOneClient("https://api.yourco.com", Environment.GetEnvironmentVariable("CERTONE_API_KEY"));
/// var result = await client.SubmitCheckAsync("model.tar.gz", new ScanOptions { Asset = "Fraud Scorer" });
/// Console.WriteLine(result.Report?.VerdictStatus);
/// </code>
/// </example>
public sealed class CertOneClient : ICertOneClient, IDisposable
{
    /// <summary>Default per-request timeout (30 s).</summary>
    public static readonly TimeSpan DefaultRequestTimeout = TimeSpan.FromSeconds(30);

    /// <summary>Default TCP connect timeout of the client-owned <see cref="HttpClient"/> (5 s).</summary>
    public static readonly TimeSpan DefaultConnectTimeout = TimeSpan.FromSeconds(5);

    /// <summary>Default <see cref="WaitForReportAsync"/> polling interval (2 s).</summary>
    public static readonly TimeSpan DefaultPollInterval = TimeSpan.FromSeconds(2);

    /// <summary>Default <see cref="WaitForReportAsync"/> timeout (900 s).</summary>
    public static readonly TimeSpan DefaultWaitTimeout = TimeSpan.FromSeconds(900);

    private const string SnapshotMediaType = "application/gzip";
    private const string DefaultSnapshotFileName = "snapshot.tar.gz";
    private const int MaxErrorDetailLength = 4096;

    private static readonly ProductInfoHeaderValue UserAgent = new("certone-sdk-dotnet", SdkVersion());
    private static readonly MediaTypeWithQualityHeaderValue AcceptJson = new("application/json");

    private readonly HttpClient _http;
    private readonly bool _ownsHttpClient;
    private readonly string _baseUrl;
    private readonly AuthenticationHeaderValue? _authorization;
    private readonly TimeSpan _requestTimeout;

    /// <summary>Creates a client that owns its <see cref="HttpClient"/> (5 s connect, 30 s request timeout).</summary>
    /// <param name="baseUrl">Control-plane base URL, for example <c>https://api.yourco.com</c>.</param>
    /// <param name="apiKey">Tenant API key (<c>ck_…</c>) or OIDC ID token; <see langword="null"/> for no auth.</param>
    public CertOneClient(Uri baseUrl, string? apiKey)
        : this(new CertOneClientOptions { BaseUrl = baseUrl, ApiKey = apiKey }, httpClient: null)
    {
    }

    /// <summary>Creates a client that owns its <see cref="HttpClient"/> (5 s connect, 30 s request timeout).</summary>
    /// <param name="baseUrl">Control-plane base URL, for example <c>https://api.yourco.com</c>.</param>
    /// <param name="apiKey">Tenant API key (<c>ck_…</c>) or OIDC ID token; <see langword="null"/> for no auth.</param>
    public CertOneClient(string baseUrl, string? apiKey)
        : this(ParseBaseUrl(baseUrl), apiKey)
    {
    }

    /// <summary>
    /// Creates a client over an injected <see cref="HttpClient"/>, for example a typed client from
    /// <c>IHttpClientFactory</c>. The injected client is not disposed by this instance and its default
    /// headers are not modified.
    /// </summary>
    /// <param name="httpClient">The HTTP client to send requests with.</param>
    /// <param name="options">Base URL (falls back to <see cref="HttpClient.BaseAddress"/>), API key and timeout.</param>
    public CertOneClient(HttpClient httpClient, CertOneClientOptions options)
        : this(options, httpClient ?? throw new ArgumentNullException(nameof(httpClient)))
    {
    }

    private CertOneClient(CertOneClientOptions options, HttpClient? httpClient)
    {
        ArgumentNullException.ThrowIfNull(options);

        var baseUrl = options.BaseUrl ?? httpClient?.BaseAddress
            ?? throw new ArgumentException("A base URL is required: set CertOneClientOptions.BaseUrl or HttpClient.BaseAddress.", nameof(options));
        if (!baseUrl.IsAbsoluteUri || (baseUrl.Scheme != Uri.UriSchemeHttps && baseUrl.Scheme != Uri.UriSchemeHttp))
        {
            throw new ArgumentException("The base URL must be an absolute http(s) URL.", nameof(options));
        }

        if (options.RequestTimeout <= TimeSpan.Zero && options.RequestTimeout != Timeout.InfiniteTimeSpan)
        {
            throw new ArgumentOutOfRangeException(nameof(options), "RequestTimeout must be positive or Timeout.InfiniteTimeSpan.");
        }

        _authorization = CreateAuthorization(options.ApiKey);
        _baseUrl = baseUrl.GetLeftPart(UriPartial.Path).TrimEnd('/');
        _requestTimeout = options.RequestTimeout;
        _ownsHttpClient = httpClient is null;
        _http = httpClient ?? CreateDefaultHttpClient();
    }

    /// <summary>The control-plane base URL requests are sent to.</summary>
    public Uri BaseUrl => new(_baseUrl, UriKind.Absolute);

    /// <inheritdoc />
    public Task<CheckResult> SubmitCheckAsync(Stream snapshot, ScanOptions? options = null, CancellationToken cancellationToken = default) =>
        SubmitSnapshotAsync("/v1/checks", snapshot, DefaultSnapshotFileName, options, includeTee: false, cancellationToken);

    /// <inheritdoc />
    public Task<CheckResult> SubmitCheckAsync(string snapshotPath, ScanOptions? options = null, CancellationToken cancellationToken = default) =>
        SubmitSnapshotFileAsync("/v1/checks", snapshotPath, options, includeTee: false, cancellationToken);

    /// <inheritdoc />
    public Task<CheckResult> SubmitProcessAsync(Stream snapshot, ScanOptions? options = null, CancellationToken cancellationToken = default) =>
        SubmitSnapshotAsync("/v1/process", snapshot, DefaultSnapshotFileName, options, includeTee: true, cancellationToken);

    /// <inheritdoc />
    public Task<CheckResult> SubmitProcessAsync(string snapshotPath, ScanOptions? options = null, CancellationToken cancellationToken = default) =>
        SubmitSnapshotFileAsync("/v1/process", snapshotPath, options, includeTee: true, cancellationToken);

    /// <inheritdoc />
    public Task<ScanRun> GetScanAsync(string scanId, CancellationToken cancellationToken = default) =>
        GetAsync($"/v1/scans/{Segment(scanId, nameof(scanId))}", CertOneJsonContext.Default.ScanRun, cancellationToken);

    /// <inheritdoc />
    public Task<Report> GetScanReportAsync(string scanId, CancellationToken cancellationToken = default) =>
        GetAsync($"/v1/scans/{Segment(scanId, nameof(scanId))}/report", CertOneJsonContext.Default.Report, cancellationToken);

    /// <inheritdoc />
    public async Task<Report> WaitForReportAsync(
        string scanId,
        TimeSpan? timeout = null,
        TimeSpan? interval = null,
        CancellationToken cancellationToken = default)
    {
        Segment(scanId, nameof(scanId));
        var waitTimeout = timeout ?? DefaultWaitTimeout;
        var pollInterval = interval ?? DefaultPollInterval;
        if (waitTimeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(timeout), "The timeout must be positive.");
        }

        if (pollInterval <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(interval), "The interval must be positive.");
        }

        var started = Stopwatch.GetTimestamp();
        while (true)
        {
            var scan = await GetScanAsync(scanId, cancellationToken).ConfigureAwait(false);
            if (scan.Status == ScanStatuses.Succeeded)
            {
                return await GetScanReportAsync(scanId, cancellationToken).ConfigureAwait(false);
            }

            if (scan.Status == ScanStatuses.Failed)
            {
                var error = string.IsNullOrWhiteSpace(scan.Error) ? "scan failed without an error message" : scan.Error;
                throw new CertOneException($"scan {scanId} failed: {error}", statusCode: null, detail: error, scan: scan);
            }

            var remaining = waitTimeout - Stopwatch.GetElapsedTime(started);
            if (remaining <= TimeSpan.Zero)
            {
                var detail = string.Create(
                    CultureInfo.InvariantCulture,
                    $"scan {scanId} did not finish within {waitTimeout.TotalSeconds:0.###} s (status: {scan.Status})");
                throw new CertOneException(detail, statusCode: null, detail: detail, scan: scan, innerException: new TimeoutException(detail));
            }

            await Task.Delay(remaining < pollInterval ? remaining : pollInterval, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <inheritdoc />
    public Task<JsonElement> GetReportDocumentAsync(string reportId, CancellationToken cancellationToken = default) =>
        GetAsync($"/v1/reports/{Segment(reportId, nameof(reportId))}/document", CertOneJsonContext.Default.JsonElement, cancellationToken);

    /// <inheritdoc />
    public Task<JsonElement> GetAttestationAsync(string reportId, CancellationToken cancellationToken = default) =>
        GetAsync($"/v1/reports/{Segment(reportId, nameof(reportId))}/attestation", CertOneJsonContext.Default.JsonElement, cancellationToken);

    /// <inheritdoc />
    public Task<CheckResult> IngestReportAsync(JsonElement report, IngestOptions? options = null, CancellationToken cancellationToken = default)
    {
        if (report.ValueKind != JsonValueKind.Object)
        {
            throw new ArgumentException("The report must be a JSON object.", nameof(report));
        }

        var body = new IngestRequest(
            report,
            options?.Asset,
            options?.Environment,
            options?.CountryCode,
            options?.SnapshotRef,
            options?.InputDigest,
            options?.Repo,
            options?.CommitHash);
        var payload = JsonSerializer.SerializeToUtf8Bytes(body, CertOneJsonContext.Default.IngestRequest);

        return SendAsync(
            HttpMethod.Post,
            "/v1/checks/report",
            () =>
            {
                var content = new ByteArrayContent(payload);
                content.Headers.ContentType = new MediaTypeHeaderValue("application/json") { CharSet = "utf-8" };
                return content;
            },
            CertOneJsonContext.Default.CheckResult,
            cancellationToken);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<AiSystem>> ListSystemsAsync(CancellationToken cancellationToken = default) =>
        await GetAsync("/v1/systems", CertOneJsonContext.Default.ListAiSystem, cancellationToken).ConfigureAwait(false);

    /// <summary>Disposes the <see cref="HttpClient"/> if this instance created it.</summary>
    public void Dispose()
    {
        if (_ownsHttpClient)
        {
            _http.Dispose();
        }
    }

    private async Task<CheckResult> SubmitSnapshotFileAsync(
        string path,
        string snapshotPath,
        ScanOptions? options,
        bool includeTee,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(snapshotPath);
        var stream = new FileStream(snapshotPath, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, useAsync: true);
        await using (stream.ConfigureAwait(false))
        {
            return await SubmitSnapshotAsync(path, stream, Path.GetFileName(snapshotPath), options, includeTee, cancellationToken)
                .ConfigureAwait(false);
        }
    }

    private Task<CheckResult> SubmitSnapshotAsync(
        string path,
        Stream snapshot,
        string fileName,
        ScanOptions? options,
        bool includeTee,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        if (!snapshot.CanRead)
        {
            throw new ArgumentException("The snapshot stream must be readable.", nameof(snapshot));
        }

        var fields = options?.ToFormFields(includeTee).ToList() ?? [];
        return SendAsync(
            HttpMethod.Post,
            path,
            () =>
            {
                var form = new MultipartFormDataContent();
                var file = new NonOwningStreamContent(snapshot);
                file.Headers.ContentType = new MediaTypeHeaderValue(SnapshotMediaType);
                form.Add(file, "snapshot", fileName);
                foreach (var (name, value) in fields)
                {
                    form.Add(new StringContent(value, Encoding.UTF8), name);
                }

                return form;
            },
            CertOneJsonContext.Default.CheckResult,
            cancellationToken);
    }

    private Task<T> GetAsync<T>(string path, JsonTypeInfo<T> typeInfo, CancellationToken cancellationToken) =>
        SendAsync(HttpMethod.Get, path, content: null, typeInfo, cancellationToken);

    private async Task<T> SendAsync<T>(
        HttpMethod method,
        string path,
        Func<HttpContent>? content,
        JsonTypeInfo<T> typeInfo,
        CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        if (_requestTimeout != Timeout.InfiniteTimeSpan)
        {
            timeout.CancelAfter(_requestTimeout);
        }

        using var request = new HttpRequestMessage(method, _baseUrl + path);
        request.Headers.Authorization = _authorization;
        request.Headers.Accept.Add(AcceptJson);
        request.Headers.UserAgent.Add(UserAgent);
        request.Content = content?.Invoke();

        HttpStatusCode? status = null;
        try
        {
            using var response = await _http
                .SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token)
                .ConfigureAwait(false);
            status = response.StatusCode;

            if ((int)response.StatusCode >= 400)
            {
                throw await CreateHttpErrorAsync(response, timeout.Token).ConfigureAwait(false);
            }

            var stream = await response.Content.ReadAsStreamAsync(timeout.Token).ConfigureAwait(false);
            await using (stream.ConfigureAwait(false))
            {
                var value = await JsonSerializer.DeserializeAsync(stream, typeInfo, timeout.Token).ConfigureAwait(false);
                return value ?? throw new CertOneException(
                    $"{method} {path} returned an empty (null) response body.",
                    status,
                    "empty response body");
            }
        }
        catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            var detail = string.Create(
                CultureInfo.InvariantCulture,
                $"{method} {path} timed out after {_requestTimeout.TotalSeconds:0.###} s");
            throw new CertOneException(detail, status, detail, innerException: new TimeoutException(detail, ex));
        }
        catch (HttpRequestException ex)
        {
            var detail = $"{method} {path} failed: {ex.Message}";
            throw new CertOneException(detail, status ?? ex.StatusCode, detail, innerException: ex);
        }
        catch (IOException ex)
        {
            var detail = $"{method} {path} failed while reading the response: {ex.Message}";
            throw new CertOneException(detail, status, detail, innerException: ex);
        }
        catch (JsonException ex)
        {
            var detail = $"{method} {path} returned an invalid JSON response: {ex.Message}";
            throw new CertOneException(detail, status, detail, innerException: ex);
        }
    }

    private static async Task<CertOneException> CreateHttpErrorAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        string body;
        try
        {
            body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException)
        {
            body = string.Empty;
        }

        var detail = ExtractDetail(body) ?? response.ReasonPhrase ?? string.Empty;
        var code = ((int)response.StatusCode).ToString(CultureInfo.InvariantCulture);
        return new CertOneException($"HTTP {code}: {detail}", response.StatusCode, detail);
    }

    /// <summary>
    /// The API's <c>detail</c>: a string as-is, a structured detail (for example validation errors) as raw JSON,
    /// or a non-JSON body as (truncated) text. <see langword="null"/> for an empty body.
    /// </summary>
    internal static string? ExtractDetail(string body)
    {
        if (string.IsNullOrWhiteSpace(body))
        {
            return null;
        }

        try
        {
            using var document = JsonDocument.Parse(body);
            if (document.RootElement.ValueKind == JsonValueKind.Object
                && document.RootElement.TryGetProperty("detail", out var detail))
            {
                return detail.ValueKind == JsonValueKind.String ? detail.GetString() ?? string.Empty : detail.GetRawText();
            }
        }
        catch (JsonException)
        {
            // Not JSON (for example a proxy's HTML error page): fall through to the raw text.
        }

        var text = body.Trim();
        return text.Length <= MaxErrorDetailLength ? text : string.Concat(text.AsSpan(0, MaxErrorDetailLength), "…");
    }

    private static string Segment(string value, string paramName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value, paramName);
        return Uri.EscapeDataString(value);
    }

    private static Uri ParseBaseUrl(string baseUrl)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(baseUrl);
        return Uri.TryCreate(baseUrl, UriKind.Absolute, out var uri)
            ? uri
            : throw new ArgumentException("The base URL must be an absolute http(s) URL.", nameof(baseUrl));
    }

    private static AuthenticationHeaderValue? CreateAuthorization(string? apiKey)
    {
        if (string.IsNullOrEmpty(apiKey))
        {
            return null;
        }

        // Validate without echoing the secret in the exception message.
        foreach (var c in apiKey)
        {
            if (char.IsWhiteSpace(c) || char.IsControl(c) || c > '~')
            {
                throw new ArgumentException("The API key contains whitespace, control or non-ASCII characters.", nameof(apiKey));
            }
        }

        return new AuthenticationHeaderValue("Bearer", apiKey);
    }

    private static HttpClient CreateDefaultHttpClient()
    {
        var handler = new SocketsHttpHandler
        {
            ConnectTimeout = DefaultConnectTimeout,
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            AutomaticDecompression = DecompressionMethods.All,
        };

        // Per-request timeouts are enforced by SendAsync so they also apply to injected clients.
        return new HttpClient(handler, disposeHandler: true) { Timeout = Timeout.InfiniteTimeSpan };
    }

    private static string SdkVersion()
    {
        var informational = typeof(CertOneClient).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        if (string.IsNullOrEmpty(informational))
        {
            return "0.0.0";
        }

        var plus = informational.IndexOf('+', StringComparison.Ordinal);
        return plus < 0 ? informational : informational[..plus];
    }

    /// <summary>Streams a caller-owned stream as request content without disposing it.</summary>
    private sealed class NonOwningStreamContent : HttpContent
    {
        private readonly Stream _stream;
        private readonly long _start;

        public NonOwningStreamContent(Stream stream)
        {
            _stream = stream;
            _start = stream.CanSeek ? stream.Position : -1;
        }

        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) =>
            SerializeToStreamAsync(stream, context, CancellationToken.None);

        protected override async Task SerializeToStreamAsync(Stream stream, TransportContext? context, CancellationToken cancellationToken)
        {
            if (_start >= 0)
            {
                _stream.Position = _start; // a seekable snapshot can be re-sent (for example after a redirect)
            }

            await _stream.CopyToAsync(stream, cancellationToken).ConfigureAwait(false);
        }

        protected override bool TryComputeLength(out long length)
        {
            if (_start >= 0)
            {
                length = _stream.Length - _start;
                return true;
            }

            length = 0;
            return false;
        }
    }
}
