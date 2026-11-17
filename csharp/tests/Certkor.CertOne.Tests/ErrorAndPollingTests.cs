using System.Net;
using System.Text;

namespace Certkor.CertOne.Tests;

public sealed class ErrorAndPollingTests
{
    private const string Base = "https://cp.test";

    private static CertOneClient Client(HttpMessageHandler handler, TimeSpan? requestTimeout = null) =>
        new(new HttpClient(handler), new CertOneClientOptions
        {
            BaseUrl = new Uri(Base),
            ApiKey = "ck_secret_value",
            RequestTimeout = requestTimeout ?? CertOneClient.DefaultRequestTimeout,
        });

    private static string ScanJson(string status, string? error = null) =>
        $$"""
        {"id":"s1","kind":"process","status":"{{status}}","snapshot_ref":null,"created_by":null,
         "created_at":"2026-11-08T19:43:23","finished_at":null,"error":{{(error is null ? "null" : $"\"{error}\"")}}}
        """;

    [Fact]
    public async Task Http_error_carries_status_and_string_detail()
    {
        using var client = Client(StubHttpMessageHandler.Json(HttpStatusCode.NotFound, """{"detail":"scan not found"}"""));

        var ex = await Assert.ThrowsAsync<CertOneException>(() => client.GetScanAsync("missing"));

        Assert.Equal(HttpStatusCode.NotFound, ex.StatusCode);
        Assert.Equal("scan not found", ex.Detail);
        Assert.Equal("HTTP 404: scan not found", ex.Message);
        Assert.Null(ex.Scan);
    }

    [Fact]
    public async Task Attestation_of_a_failing_verdict_is_a_404()
    {
        using var client = Client(StubHttpMessageHandler.Json(HttpStatusCode.NotFound, """{"detail":"no attestation: verdict did not pass"}"""));

        var ex = await Assert.ThrowsAsync<CertOneException>(() => client.GetAttestationAsync("r1"));

        Assert.Equal(HttpStatusCode.NotFound, ex.StatusCode);
        Assert.Equal("no attestation: verdict did not pass", ex.Detail);
    }

    [Fact]
    public async Task Structured_validation_detail_is_kept_as_json()
    {
        const string body = """{"detail":[{"type":"missing","loc":["body","snapshot"],"msg":"Field required"}]}""";
        using var client = Client(StubHttpMessageHandler.Json(HttpStatusCode.UnprocessableEntity, body));

        var ex = await Assert.ThrowsAsync<CertOneException>(() => client.SubmitCheckAsync(new MemoryStream([1])));

        Assert.Equal(HttpStatusCode.UnprocessableEntity, ex.StatusCode);
        Assert.Equal("""[{"type":"missing","loc":["body","snapshot"],"msg":"Field required"}]""", ex.Detail);
    }

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized, """{"detail":"invalid API key"}""", "invalid API key")]
    [InlineData(HttpStatusCode.Forbidden, """{"detail":"role 'member' required"}""", "role 'member' required")]
    [InlineData(HttpStatusCode.BadRequest, """{"detail":"fail_on must be low|medium|high|none"}""", "fail_on must be low|medium|high|none")]
    [InlineData(HttpStatusCode.TooManyRequests, """{"message":"slow down"}""", """{"message":"slow down"}""")]
    [InlineData(HttpStatusCode.BadGateway, "<html>Bad gateway</html>", "<html>Bad gateway</html>")]
    public async Task Every_status_at_or_above_400_maps_to_CertOneException(HttpStatusCode status, string body, string detail)
    {
        using var client = Client(new StubHttpMessageHandler((_, _) => Task.FromResult(
            new HttpResponseMessage(status) { Content = new StringContent(body, Encoding.UTF8, "text/plain") })));

        var ex = await Assert.ThrowsAsync<CertOneException>(() => client.ListSystemsAsync());

        Assert.Equal(status, ex.StatusCode);
        Assert.Equal(detail, ex.Detail);
        Assert.DoesNotContain("ck_secret_value", ex.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Empty_error_body_falls_back_to_the_reason_phrase()
    {
        using var client = Client(new StubHttpMessageHandler((_, _) => Task.FromResult(
            new HttpResponseMessage(HttpStatusCode.ServiceUnavailable) { ReasonPhrase = "Service Unavailable" })));

        var ex = await Assert.ThrowsAsync<CertOneException>(() => client.ListSystemsAsync());

        Assert.Equal("Service Unavailable", ex.Detail);
        Assert.Equal("HTTP 503: Service Unavailable", ex.Message);
    }

    [Fact]
    public void Long_non_json_error_bodies_are_truncated()
    {
        var detail = CertOneClient.ExtractDetail(new string('x', 10_000));

        Assert.Equal(4097, detail!.Length);
        Assert.EndsWith("…", detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Network_failure_maps_to_CertOneException_without_status()
    {
        var failure = new HttpRequestException("Connection refused (cp.test:443)");
        using var client = Client(new StubHttpMessageHandler((_, _) => throw failure));

        var ex = await Assert.ThrowsAsync<CertOneException>(() => client.GetScanAsync("s1"));

        Assert.Null(ex.StatusCode);
        Assert.Same(failure, ex.InnerException);
        Assert.Contains("GET /v1/scans/s1 failed: Connection refused", ex.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Request_timeout_maps_to_CertOneException_with_TimeoutException()
    {
        using var client = Client(
            new StubHttpMessageHandler(async (_, ct) =>
            {
                await Task.Delay(Timeout.Infinite, ct);
                throw new InvalidOperationException("unreachable");
            }),
            requestTimeout: TimeSpan.FromMilliseconds(50));

        var ex = await Assert.ThrowsAsync<CertOneException>(() => client.GetScanAsync("s1"));

        Assert.Null(ex.StatusCode);
        Assert.IsType<TimeoutException>(ex.InnerException);
        Assert.Contains("timed out", ex.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Caller_cancellation_surfaces_as_OperationCanceledException()
    {
        using var cts = new CancellationTokenSource();
        using var client = Client(new StubHttpMessageHandler(async (_, ct) =>
        {
            await cts.CancelAsync();
            await Task.Delay(Timeout.Infinite, ct);
            throw new InvalidOperationException("unreachable");
        }));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.GetScanAsync("s1", cts.Token));
    }

    [Fact]
    public async Task Invalid_json_response_maps_to_CertOneException()
    {
        using var client = Client(StubHttpMessageHandler.Json(HttpStatusCode.OK, "{not json"));

        var ex = await Assert.ThrowsAsync<CertOneException>(() => client.GetScanAsync("s1"));

        Assert.Equal(HttpStatusCode.OK, ex.StatusCode);
        Assert.IsAssignableFrom<System.Text.Json.JsonException>(ex.InnerException);
    }

    [Fact]
    public async Task Null_response_body_maps_to_CertOneException()
    {
        using var client = Client(StubHttpMessageHandler.Json(HttpStatusCode.OK, "null"));

        var ex = await Assert.ThrowsAsync<CertOneException>(() => client.GetScanAsync("s1"));

        Assert.Equal("empty response body", ex.Detail);
    }

    [Fact]
    public async Task WaitForReport_polls_until_succeeded_then_fetches_the_report()
    {
        var handler = StubHttpMessageHandler.Sequence(
            (HttpStatusCode.OK, ScanJson("queued")),
            (HttpStatusCode.OK, ScanJson("running")),
            (HttpStatusCode.OK, ScanJson("succeeded")),
            (HttpStatusCode.OK, Fixtures.Read("report.json")));
        using var client = Client(handler);

        var report = await client.WaitForReportAsync("s1", TimeSpan.FromSeconds(10), TimeSpan.FromMilliseconds(5));

        Assert.Equal("88b35a6b07bb456aa5159c32831f6bf4", report.Id);
        Assert.Equal(
            ["/v1/scans/s1", "/v1/scans/s1", "/v1/scans/s1", "/v1/scans/s1/report"],
            handler.Requests.Select(r => r.Uri.AbsolutePath));
    }

    [Fact]
    public async Task WaitForReport_raises_the_scan_error_when_the_scan_fails()
    {
        using var client = Client(StubHttpMessageHandler.Sequence(
            (HttpStatusCode.OK, ScanJson("running")),
            (HttpStatusCode.OK, ScanJson("failed", "worker attestation rejected"))));

        var ex = await Assert.ThrowsAsync<CertOneException>(
            () => client.WaitForReportAsync("s1", TimeSpan.FromSeconds(10), TimeSpan.FromMilliseconds(5)));

        Assert.Null(ex.StatusCode);
        Assert.Equal("worker attestation rejected", ex.Detail);
        Assert.Equal("scan s1 failed: worker attestation rejected", ex.Message);
        Assert.Equal(ScanStatuses.Failed, ex.Scan!.Status);
    }

    [Fact]
    public async Task WaitForReport_times_out_with_the_last_seen_scan()
    {
        var handler = StubHttpMessageHandler.Json(HttpStatusCode.OK, ScanJson("running"));
        using var client = Client(handler);

        var ex = await Assert.ThrowsAsync<CertOneException>(
            () => client.WaitForReportAsync("s1", TimeSpan.FromMilliseconds(100), TimeSpan.FromMilliseconds(20)));

        Assert.IsType<TimeoutException>(ex.InnerException);
        Assert.Equal(ScanStatuses.Running, ex.Scan!.Status);
        Assert.Contains("did not finish within 0.1 s", ex.Detail, StringComparison.Ordinal);
        Assert.True(handler.Requests.Count >= 2);
    }

    [Fact]
    public async Task WaitForReport_propagates_http_errors()
    {
        using var client = Client(StubHttpMessageHandler.Json(HttpStatusCode.NotFound, """{"detail":"scan not found"}"""));

        var ex = await Assert.ThrowsAsync<CertOneException>(() => client.WaitForReportAsync("nope"));

        Assert.Equal(HttpStatusCode.NotFound, ex.StatusCode);
    }

    [Fact]
    public async Task WaitForReport_validates_its_durations()
    {
        using var client = Client(StubHttpMessageHandler.Json(HttpStatusCode.OK, ScanJson("running")));

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => client.WaitForReportAsync("s1", TimeSpan.Zero));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => client.WaitForReportAsync("s1", interval: TimeSpan.FromSeconds(-1)));
    }
}
