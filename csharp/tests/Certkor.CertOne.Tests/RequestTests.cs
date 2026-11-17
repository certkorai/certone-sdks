using System.Net;
using System.Text;
using System.Text.Json;

namespace Certkor.CertOne.Tests;

public sealed class RequestTests
{
    private const string Key = "ck_test_0123456789abcdef";
    private static readonly byte[] Snapshot = [0x1f, 0x8b, 0x08, 0x00, 0x42, 0x43, 0x44];

    private static (CertOneClient Client, StubHttpMessageHandler Handler, HttpClient Http) Create(string body, string baseUrl = "https://cp.test")
    {
        var handler = StubHttpMessageHandler.Json(HttpStatusCode.Created, body);
        var http = new HttpClient(handler);
        return (new CertOneClient(http, new CertOneClientOptions { BaseUrl = new Uri(baseUrl), ApiKey = Key }), handler, http);
    }

    [Fact]
    public async Task SubmitCheck_posts_multipart_snapshot_and_every_option()
    {
        var (client, handler, http) = Create(Fixtures.Read("check_result.json"));
        using (http)
        using (client)
        {
            var options = new ScanOptions
            {
                Asset = "C# SDK quickstart",
                Environment = ScanEnvironments.Ci,
                CountryCode = "EU",
                FailOn = FailOnLevels.Medium,
                SnapshotRef = "git:acme/fraud@abc123",
                CommitHash = "abc123",
                Tee = "intel_tdx",
            };
            options.Packs.Add("eu-ai-act-core");
            options.Packs.Add(" iso-42001-core ");
            options.Packs.Add("");

            await client.SubmitCheckAsync(new MemoryStream(Snapshot), options);
        }

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal("https://cp.test/v1/checks", request.Uri.ToString());
        Assert.Equal($"Bearer {Key}", request.Authorization);
        Assert.StartsWith("multipart/form-data", request.ContentType, StringComparison.Ordinal);

        var snapshot = request.Parts[0];
        Assert.Equal("snapshot", snapshot.Name);
        Assert.Equal("snapshot.tar.gz", snapshot.FileName);
        Assert.Equal("application/gzip", snapshot.ContentType);
        Assert.Equal(Snapshot, snapshot.Body);

        var fields = request.Parts.Skip(1).ToDictionary(p => p.Name, p => p.Text);
        Assert.Equal(
            new Dictionary<string, string>
            {
                ["asset"] = "C# SDK quickstart",
                ["environment"] = "ci",
                ["country_code"] = "EU",
                ["fail_on"] = "medium",
                ["packs"] = "eu-ai-act-core,iso-42001-core",
                ["snapshot_ref"] = "git:acme/fraud@abc123",
                ["commit_hash"] = "abc123",
            },
            fields);
        Assert.DoesNotContain(request.Parts, p => p.Name == "tee");
    }

    [Fact]
    public async Task SubmitProcess_posts_to_process_and_sends_tee()
    {
        var (client, handler, http) = Create(Fixtures.Read("check_result.json"));
        using (http)
        using (client)
        {
            await client.SubmitProcessAsync(new MemoryStream(Snapshot), new ScanOptions { Tee = "amd_sev_snp" });
        }

        var request = Assert.Single(handler.Requests);
        Assert.Equal("/v1/process", request.Uri.AbsolutePath);
        Assert.Equal(["snapshot", "tee"], request.Parts.Select(p => p.Name));
        Assert.Equal("amd_sev_snp", request.Parts[1].Text);
    }

    [Fact]
    public async Task Without_options_only_the_snapshot_is_sent_so_server_defaults_apply()
    {
        var (client, handler, http) = Create(Fixtures.Read("check_result.json"));
        using (http)
        using (client)
        {
            await client.SubmitCheckAsync(new MemoryStream(Snapshot));
        }

        Assert.Equal(["snapshot"], Assert.Single(handler.Requests).Parts.Select(p => p.Name));
    }

    [Fact]
    public async Task Snapshot_stream_is_read_from_its_position_and_left_open()
    {
        var (client, handler, http) = Create(Fixtures.Read("check_result.json"));
        var stream = new MemoryStream([0xAA, .. Snapshot]) { Position = 1 };
        using (http)
        using (client)
        {
            await client.SubmitCheckAsync(stream);
        }

        Assert.Equal(Snapshot, Assert.Single(handler.Requests).Parts[0].Body);
        Assert.True(stream.CanRead, "the caller's stream must not be disposed");
    }

    [Fact]
    public async Task Snapshot_path_overload_uploads_the_file_under_its_name()
    {
        var path = Path.Combine(Path.GetTempPath(), $"certone-{Guid.NewGuid():N}.tar.gz");
        await File.WriteAllBytesAsync(path, Snapshot);
        try
        {
            var (client, handler, http) = Create(Fixtures.Read("check_result.json"));
            using (http)
            using (client)
            {
                await client.SubmitCheckAsync(path);
            }

            var part = Assert.Single(handler.Requests).Parts[0];
            Assert.Equal(Path.GetFileName(path), part.FileName);
            Assert.Equal(Snapshot, part.Body);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task IngestReport_posts_snake_case_json_and_omits_unset_fields()
    {
        var (client, handler, http) = Create(Fixtures.Read("ingest_result.json"));
        using var report = JsonDocument.Parse("""{"report_id":"rat-sdk-0001","verdict":{"status":"pass"},"issues":[]}""");
        using (http)
        using (client)
        {
            await client.IngestReportAsync(
                report.RootElement,
                new IngestOptions
                {
                    Asset = "Fraud Scorer",
                    Environment = ScanEnvironments.Edge,
                    CountryCode = "EU",
                    InputDigest = "sha256:" + new string('a', 64),
                    Repo = "acme/fraud",
                });
        }

        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal("/v1/checks/report", request.Uri.AbsolutePath);
        Assert.Equal("application/json; charset=utf-8", request.ContentType);

        using var body = JsonDocument.Parse(request.Body);
        var root = body.RootElement;
        Assert.Equal(
            ["report", "asset", "environment", "country_code", "input_digest", "repo"],
            root.EnumerateObject().Select(p => p.Name));
        Assert.Equal("rat-sdk-0001", root.GetProperty("report").GetProperty("report_id").GetString());
        Assert.Equal("edge", root.GetProperty("environment").GetString());
        Assert.Equal("sha256:" + new string('a', 64), root.GetProperty("input_digest").GetString());
    }

    [Fact]
    public async Task IngestReport_rejects_a_non_object_report()
    {
        var (client, handler, http) = Create("{}");
        using (http)
        using (client)
        {
            await Assert.ThrowsAsync<ArgumentException>(() => client.IngestReportAsync(JsonDocument.Parse("[]").RootElement));
        }

        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task Get_operations_use_the_spec_paths_and_escape_ids()
    {
        var handler = new StubHttpMessageHandler((request, _) => Task.FromResult(StubHttpMessageHandler.JsonResponse(
            HttpStatusCode.OK,
            request.Uri.AbsolutePath switch
            {
                "/api/v1/systems" => "[]",
                var p when p.EndsWith("/report", StringComparison.Ordinal) => Fixtures.Read("report.json"),
                var p when p.StartsWith("/api/v1/scans/", StringComparison.Ordinal) => Fixtures.Read("scan.json"),
                _ => "{}",
            })));
        using var http = new HttpClient(handler);
        using var client = new CertOneClient(http, new CertOneClientOptions { BaseUrl = new Uri("https://cp.test/api/"), ApiKey = Key });

        await client.GetScanAsync("a/b c");
        await client.GetScanReportAsync("s1");
        await client.GetReportDocumentAsync("r1");
        await client.GetAttestationAsync("r1");
        await client.ListSystemsAsync();

        Assert.Equal(
            [
                "https://cp.test/api/v1/scans/a%2Fb%20c",
                "https://cp.test/api/v1/scans/s1/report",
                "https://cp.test/api/v1/reports/r1/document",
                "https://cp.test/api/v1/reports/r1/attestation",
                "https://cp.test/api/v1/systems",
            ],
            handler.Requests.Select(r => r.Uri.AbsoluteUri));
        Assert.All(handler.Requests, r => Assert.Equal(HttpMethod.Get, r.Method));
        Assert.All(handler.Requests, r => Assert.Equal($"Bearer {Key}", r.Authorization));
    }

    [Fact]
    public async Task Base_address_of_an_injected_client_is_used_when_no_base_url_is_given()
    {
        var handler = StubHttpMessageHandler.Json(HttpStatusCode.OK, "[]");
        using var http = new HttpClient(handler) { BaseAddress = new Uri("https://factory.test/") };
        using var client = new CertOneClient(http, new CertOneClientOptions());

        await client.ListSystemsAsync();

        var request = Assert.Single(handler.Requests);
        Assert.Equal("https://factory.test/v1/systems", request.Uri.AbsoluteUri);
        Assert.Null(request.Authorization);
        Assert.Equal(new Uri("https://factory.test"), client.BaseUrl);
    }

    [Fact]
    public async Task Disposing_the_client_leaves_an_injected_HttpClient_usable()
    {
        var handler = StubHttpMessageHandler.Json(HttpStatusCode.OK, "[]");
        using var http = new HttpClient(handler);
        new CertOneClient(http, new CertOneClientOptions { BaseUrl = new Uri("https://cp.test") }).Dispose();

        using var response = await http.GetAsync(new Uri("https://cp.test/v1/systems"));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Theory]
    [InlineData("ck_bad key")]
    [InlineData("ck_bad\r\nX-Injected: 1")]
    [InlineData("ck_bäd")]
    public void Invalid_api_keys_are_rejected_without_echoing_the_secret(string apiKey)
    {
        var ex = Assert.Throws<ArgumentException>(() => new CertOneClient("https://cp.test", apiKey));

        Assert.DoesNotContain("ck_b", ex.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("not a url")]
    [InlineData("ftp://cp.test")]
    [InlineData("/relative")]
    public void Invalid_base_urls_are_rejected(string baseUrl)
    {
        Assert.Throws<ArgumentException>(() => new CertOneClient(baseUrl, null));
    }

    [Fact]
    public void A_base_url_is_required()
    {
        using var http = new HttpClient();

        Assert.Throws<ArgumentException>(() => new CertOneClient(http, new CertOneClientOptions()));
    }

    [Fact]
    public void Owned_client_normalises_the_base_url()
    {
        using var client = new CertOneClient("https://api.yourco.com/", "ck_x");

        Assert.Equal(new Uri("https://api.yourco.com"), client.BaseUrl);
    }

    [Fact]
    public async Task Blank_ids_are_rejected_before_any_request()
    {
        var (client, handler, http) = Create("{}");
        using (http)
        using (client)
        {
            await Assert.ThrowsAsync<ArgumentException>(() => client.GetScanAsync(" "));
            await Assert.ThrowsAsync<ArgumentNullException>(() => client.GetAttestationAsync(null!));
            await Assert.ThrowsAsync<ArgumentException>(() => client.WaitForReportAsync(""));
        }

        Assert.Empty(handler.Requests);
    }

    [Fact]
    public void Scan_options_produce_no_fields_by_default()
    {
        Assert.Empty(new ScanOptions().ToFormFields(includeTee: true));
    }

    [Fact]
    public async Task Input_digest_is_lowercase_sha256_of_the_bytes()
    {
        var abc = Encoding.ASCII.GetBytes("abc");
        const string expected = "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

        Assert.Equal(expected, InputDigest.Compute(abc));
        Assert.Equal(expected, await InputDigest.ComputeAsync(new MemoryStream(abc)));

        var path = Path.GetTempFileName();
        try
        {
            await File.WriteAllBytesAsync(path, abc);
            Assert.Equal(expected, await InputDigest.ComputeFileAsync(path));
        }
        finally
        {
            File.Delete(path);
        }
    }
}
