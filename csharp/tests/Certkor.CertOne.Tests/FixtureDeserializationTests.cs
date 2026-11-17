using System.Net;
using System.Text.Json;

namespace Certkor.CertOne.Tests;

public sealed class FixtureDeserializationTests
{
    private const string Base = "http://cp.test";

    /// <summary>Each fixture, fetched through the SDK operation that returns it, must deserialize.</summary>
    private static readonly Dictionary<string, Func<CertOneClient, Task<object>>> Operations = new(StringComparer.Ordinal)
    {
        ["attestation.json"] = async c => await c.GetAttestationAsync("r1"),
        ["check_result.json"] = async c => await c.SubmitCheckAsync(new MemoryStream([1, 2, 3])),
        ["ingest_result.json"] = async c => await c.IngestReportAsync(JsonDocument.Parse("{}").RootElement),
        ["report.json"] = async c => await c.GetScanReportAsync("s1"),
        ["report_document_excerpt.json"] = async c => await c.GetReportDocumentAsync("r1"),
        ["scan.json"] = async c => await c.GetScanAsync("s1"),
        ["systems.json"] = async c => await c.ListSystemsAsync(),
    };

    public static TheoryData<string> FixtureNames()
    {
        var data = new TheoryData<string>();
        foreach (var name in Fixtures.All())
        {
            data.Add(name);
        }

        return data;
    }

    [Fact]
    public void Every_fixture_is_covered_by_an_sdk_operation()
    {
        Assert.Equal(Operations.Keys.Order(StringComparer.Ordinal), Fixtures.All());
    }

    [Theory]
    [MemberData(nameof(FixtureNames))]
    public async Task Fixture_deserializes_through_its_operation(string fixture)
    {
        using var http = new HttpClient(StubHttpMessageHandler.Json(HttpStatusCode.OK, Fixtures.Read(fixture)));
        using var client = new CertOneClient(http, new CertOneClientOptions { BaseUrl = new Uri(Base) });

        var result = await Operations[fixture](client);

        Assert.NotNull(result);
    }

    [Fact]
    public async Task Scan_fixture_maps_every_field_and_reads_naive_timestamps_as_utc()
    {
        using var http = new HttpClient(StubHttpMessageHandler.Json(HttpStatusCode.OK, Fixtures.Read("scan.json")));
        using var client = new CertOneClient(http, new CertOneClientOptions { BaseUrl = new Uri(Base) });

        var scan = await client.GetScanAsync("64ff3a4afb5e40f5b8ae5e38071c9145");

        Assert.Equal("64ff3a4afb5e40f5b8ae5e38071c9145", scan.Id);
        Assert.Equal("check", scan.Kind);
        Assert.Equal(ScanStatuses.Succeeded, scan.Status);
        Assert.True(scan.IsTerminal);
        Assert.Null(scan.SnapshotRef);
        Assert.Equal("apikey:3a58fad90b314f52a37068c0c3d80e32", scan.CreatedBy);
        Assert.Equal(new DateTimeOffset(2026, 11, 8, 19, 43, 23, TimeSpan.Zero).AddTicks(1053330), scan.CreatedAt);
        Assert.Equal(TimeSpan.Zero, scan.CreatedAt.Offset);
        Assert.Equal(new DateTimeOffset(2026, 11, 8, 19, 43, 23, TimeSpan.Zero).AddTicks(1676880), scan.FinishedAt);
        Assert.Null(scan.Error);
        Assert.Null(scan.AdditionalProperties);
    }

    [Fact]
    public async Task Check_result_fixture_maps_scan_report_and_severities()
    {
        using var http = new HttpClient(StubHttpMessageHandler.Json(HttpStatusCode.Created, Fixtures.Read("check_result.json")));
        using var client = new CertOneClient(http, new CertOneClientOptions { BaseUrl = new Uri(Base) });

        var result = await client.SubmitCheckAsync(new MemoryStream([0x1f, 0x8b]));

        Assert.False(result.Queued);
        Assert.Equal("64ff3a4afb5e40f5b8ae5e38071c9145", result.ScanRun.Id);
        Assert.Equal(new DateTimeOffset(2026, 11, 8, 19, 43, 23, TimeSpan.Zero).AddTicks(1053330), result.ScanRun.CreatedAt);
        var report = Assert.IsType<Report>(result.Report);
        Assert.Equal("88b35a6b07bb456aa5159c32831f6bf4", report.Id);
        Assert.Equal("64ff3a4afb5e40f5b8ae5e38071c9145", report.ScanRunId);
        Assert.Equal("report-bce1fa3cd2cd", report.ReportId);
        Assert.Equal(Verdicts.Fail, report.VerdictStatus);
        Assert.False(report.Passed);
        Assert.Equal(FailOnLevels.High, report.FailOn);
        Assert.Equal(6, report.TotalIssues);
        Assert.Equal(new Dictionary<string, int> { ["low"] = 0, ["medium"] = 3, ["high"] = 3 }, report.BySeverity);
        Assert.Equal("ZZ", report.CountryCode);
        Assert.Null(result.Jobs);
        Assert.Null(result.Energy);
    }

    [Fact]
    public async Task Ingest_result_fixture_maps_a_passing_report_with_no_findings()
    {
        using var http = new HttpClient(StubHttpMessageHandler.Json(HttpStatusCode.Created, Fixtures.Read("ingest_result.json")));
        using var client = new CertOneClient(http, new CertOneClientOptions { BaseUrl = new Uri(Base) });

        var result = await client.IngestReportAsync(JsonDocument.Parse("""{"report_id":"rat-sdk-0001"}""").RootElement);

        var report = Assert.IsType<Report>(result.Report);
        Assert.Equal(Verdicts.Pass, report.VerdictStatus);
        Assert.True(report.Passed);
        Assert.Equal("rat-sdk-0001", report.ReportId);
        Assert.Equal("041376f586ae4f1d9d54f529f5f3e9ba", report.Id);
        Assert.Equal(0, report.TotalIssues);
        Assert.Empty(report.BySeverity);
        Assert.Equal("EU", report.CountryCode);
    }

    [Fact]
    public async Task Report_fixture_maps_every_field()
    {
        using var http = new HttpClient(StubHttpMessageHandler.Json(HttpStatusCode.OK, Fixtures.Read("report.json")));
        using var client = new CertOneClient(http, new CertOneClientOptions { BaseUrl = new Uri(Base) });

        var report = await client.GetScanReportAsync("64ff3a4afb5e40f5b8ae5e38071c9145");

        Assert.Equal("88b35a6b07bb456aa5159c32831f6bf4", report.Id);
        Assert.Equal("fail", report.VerdictStatus);
        Assert.Equal(3, report.BySeverity["high"]);
        Assert.Equal(new DateTimeOffset(2026, 11, 8, 19, 43, 23, TimeSpan.Zero).AddTicks(1688770), report.CreatedAt);
    }

    [Fact]
    public async Task Report_document_fixture_is_exposed_as_json()
    {
        var handler = StubHttpMessageHandler.Json(HttpStatusCode.OK, Fixtures.Read("report_document_excerpt.json"));
        using var http = new HttpClient(handler);
        using var client = new CertOneClient(http, new CertOneClientOptions { BaseUrl = new Uri(Base) });

        var document = await client.GetReportDocumentAsync("88b35a6b07bb456aa5159c32831f6bf4");

        Assert.Equal("fail", document.GetProperty("verdict").GetProperty("status").GetString());
        Assert.Equal(6, document.GetProperty("summary").GetProperty("total_issues").GetInt32());
        var first = document.GetProperty("issues")[0];
        Assert.Equal("iss-0001", first.GetProperty("issue_id").GetString());
        Assert.Equal("high", first.GetProperty("severity").GetString());
        Assert.Equal("EU AI Act", first.GetProperty("regulatory_references")[0].GetProperty("framework").GetString());
        Assert.Equal("/v1/reports/88b35a6b07bb456aa5159c32831f6bf4/document", Assert.Single(handler.Requests).Uri.AbsolutePath);
    }

    [Fact]
    public async Task Attestation_fixture_is_exposed_as_json()
    {
        using var http = new HttpClient(StubHttpMessageHandler.Json(HttpStatusCode.OK, Fixtures.Read("attestation.json")));
        using var client = new CertOneClient(http, new CertOneClientOptions { BaseUrl = new Uri(Base) });

        var attestation = await client.GetAttestationAsync("041376f586ae4f1d9d54f529f5f3e9ba");

        Assert.Equal("att-43d463ff6d874d1a92be85ed768b762f", attestation.GetProperty("attestation_id").GetString());
        Assert.Equal("1.0", attestation.GetProperty("input_version").GetString());
        Assert.Equal("HMAC-SHA256", attestation.GetProperty("signature_algorithm").GetString());
        Assert.True(attestation.GetProperty("conditional_validity").GetProperty("valid").GetBoolean());
    }

    [Fact]
    public async Task Systems_fixture_maps_every_system()
    {
        using var http = new HttpClient(StubHttpMessageHandler.Json(HttpStatusCode.OK, Fixtures.Read("systems.json")));
        using var client = new CertOneClient(http, new CertOneClientOptions { BaseUrl = new Uri(Base) });

        var systems = await client.ListSystemsAsync();

        Assert.Equal(3, systems.Count);
        var edge = systems[0];
        Assert.Equal("9356b603af1c419eb27e09b468463879", edge.Id);
        Assert.Equal("sdk-edge-model", edge.Slug);
        Assert.Equal("SDK Edge Model", edge.Name);
        Assert.Equal("prod", edge.Lifecycle);
        Assert.Null(edge.OwnerTeamId);
        Assert.Equal(["EU"], edge.Regions);
        Assert.Equal(["edge"], edge.Environments);
        Assert.Equal(["eu_ai_act", "gdpr", "iso_42001", "mitre_atlas", "oecd_ai"], edge.Standards);
        Assert.Equal(1, edge.Scans);
        Assert.Equal(0, edge.OpenIssues);
        Assert.Equal("pass", edge.LastVerdict);
        Assert.True(edge.Attested);
        Assert.Equal("valid", edge.AttestationStatus);
        Assert.Equal("low", edge.Risk);
        Assert.NotNull(edge.LastEvaluated);
        Assert.Equal(6, systems[1].OpenIssues);
        Assert.False(systems[1].Attested);
    }

    [Fact]
    public async Task Unknown_fields_are_preserved_and_do_not_break_deserialization()
    {
        const string body = """
            {"scan_run":{"id":"s","kind":"process","status":"queued","snapshot_ref":"git:o/r@1","created_by":null,
              "created_at":"2026-11-08T19:43:23Z","finished_at":null,"error":null,"region":"eu-west"},
             "report":null,"queued":true,"jobs":{"static":1,"dynamic":2},"health":{"ok":true},
             "energy":{"joules":1.5},"future_field":[1,2]}
            """;
        using var http = new HttpClient(StubHttpMessageHandler.Json(HttpStatusCode.Created, body));
        using var client = new CertOneClient(http, new CertOneClientOptions { BaseUrl = new Uri(Base) });

        var result = await client.SubmitProcessAsync(new MemoryStream([1]));

        Assert.True(result.Queued);
        Assert.Null(result.Report);
        Assert.False(result.ScanRun.IsTerminal);
        Assert.Equal("eu-west", result.ScanRun.AdditionalProperties!["region"].GetString());
        Assert.Equal(2, result.AdditionalProperties!["future_field"].GetArrayLength());
        Assert.Equal(2, result.Jobs!["dynamic"]);
        Assert.True(result.Health!.Value.GetProperty("ok").GetBoolean());
        Assert.Equal(1.5, result.Energy!["joules"]);
    }
}
