package ai.certkor.certone;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ai.certkor.certone.StubServer.Fixtures;
import ai.certkor.certone.StubServer.Recorded;
import ai.certkor.certone.StubServer.Response;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.http.HttpClient;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** HTTP round-trips of every operation against a local stub control plane. */
class CertOneClientTest {

  private static final String TOKEN = "ck_test_0123456789abcdef";
  private static final ObjectMapper JSON = new ObjectMapper();

  private StubServer server;
  private CertOneClient client;

  @BeforeEach
  void start() throws IOException {
    server = new StubServer();
    client = CertOneClient.create(server.baseUrl() + "/", TOKEN);
  }

  @AfterEach
  void stop() {
    server.close();
  }

  // --- requests --------------------------------------------------------------------------------

  @Test
  void sendsBearerTokenAcceptAndUserAgent() {
    server.onFixture("GET /v1/scans/64ff3a4afb5e40f5b8ae5e38071c9145", "scan.json");

    ScanRun scan = client.getScan("64ff3a4afb5e40f5b8ae5e38071c9145");

    assertEquals("64ff3a4afb5e40f5b8ae5e38071c9145", scan.id());
    Recorded request = server.onlyRequest();
    assertEquals("GET", request.method());
    assertEquals("Bearer " + TOKEN, request.header("Authorization"));
    assertEquals("application/json", request.header("Accept"));
    assertTrue(request.header("User-Agent").startsWith("certone-sdk-java/"));
  }

  @Test
  void omitsAuthorizationWithoutToken() {
    server.onFixture("GET /v1/systems", "systems.json");

    CertOneClient.create(server.baseUrl(), null).listSystems();

    assertNull(server.onlyRequest().header("Authorization"));
  }

  @Test
  void keepsBaseUrlPathPrefix() {
    server.onFixture("GET /api/v1/systems", "systems.json");

    List<AiSystem> systems = CertOneClient.create(server.baseUrl() + "/api//", TOKEN).listSystems();

    assertEquals(3, systems.size());
    assertEquals("/api/v1/systems", server.onlyRequest().path());
  }

  @Test
  void encodesPathParameters() {
    server.on("GET /v1/scans/a%2Fb%20c", Response.json(200, Fixtures.read("scan.json")));

    client.getScan("a/b c");

    assertEquals("/v1/scans/a%2Fb%20c", server.onlyRequest().path());
  }

  @Test
  void rejectsBlankIds() {
    assertThrows(IllegalArgumentException.class, () -> client.getScan(" "));
    assertThrows(NullPointerException.class, () -> client.getAttestation(null));
    assertTrue(server.requests().isEmpty());
  }

  // --- operations ------------------------------------------------------------------------------

  @Test
  void submitCheckUploadsSnapshotAsMultipart(@TempDir Path dir) throws IOException {
    Path snapshot = dir.resolve("project.tar.gz");
    byte[] content = binaryContent();
    Files.write(snapshot, content);
    server.on("POST /v1/checks", Response.json(201, Fixtures.read("check_result.json")));

    CheckResult result =
        client.submitCheck(
            snapshot,
            ScanOptions.builder()
                .asset("Java SDK test")
                .environment(Environment.CI)
                .countryCode("EU")
                .failOn(FailOn.HIGH)
                .packs("eu-ai-act-core", "iso-42001-core")
                .snapshotRef("git:acme/fraud@abc")
                .commitHash("abc")
                .build());

    assertEquals("fail", result.report().verdictStatus());
    Recorded request = server.onlyRequest();
    MultipartParser.Form form = MultipartParser.parse(request);
    assertEquals(
        List.of(
            "asset",
            "environment",
            "country_code",
            "fail_on",
            "packs",
            "snapshot_ref",
            "commit_hash",
            "snapshot"),
        form.names());
    assertEquals("Java SDK test", form.text("asset"));
    assertEquals("ci", form.text("environment"));
    assertEquals("EU", form.text("country_code"));
    assertEquals("high", form.text("fail_on"));
    assertEquals("eu-ai-act-core,iso-42001-core", form.text("packs"));
    assertEquals("git:acme/fraud@abc", form.text("snapshot_ref"));
    assertEquals("abc", form.text("commit_hash"));
    MultipartParser.Part file = form.part("snapshot");
    assertEquals("project.tar.gz", file.filename());
    assertEquals("application/gzip", file.contentType());
    assertArrayEquals(content, file.content());
    assertEquals(
        String.valueOf(request.body().length), request.header("Content-Length"),
        "the streamed body must have a known length");
  }

  @Test
  void submitCheckWithDefaultsSendsOnlyTheSnapshot() {
    server.on("POST /v1/checks", Response.json(201, Fixtures.read("check_result.json")));

    client.submitCheck(new byte[] {1, 2, 3}, null, ScanOptions.defaults());

    MultipartParser.Form form = MultipartParser.parse(server.onlyRequest());
    assertEquals(List.of("snapshot"), form.names());
    assertEquals("snapshot.tar.gz", form.part("snapshot").filename());
  }

  @Test
  void submitCheckRejectsTee() {
    ScanOptions options = ScanOptions.builder().tee("amd_sev_snp").build();

    assertThrows(
        IllegalArgumentException.class, () -> client.submitCheck(new byte[] {1}, "a", options));
    assertTrue(server.requests().isEmpty());
  }

  @Test
  void submitCheckWithMissingFileFailsWithoutRequest(@TempDir Path dir) {
    CertOneException error =
        assertThrows(
            CertOneException.class, () -> client.submitCheck(dir.resolve("missing.tar.gz")));

    assertEquals(0, error.statusCode());
    assertTrue(error.getMessage().contains("missing.tar.gz"));
    assertTrue(server.requests().isEmpty());
  }

  @Test
  void submitProcessSendsTeeAndHandlesQueuedResult() {
    server.on(
        "POST /v1/process",
        Response.json(
            201,
            "{\"scan_run\":{\"id\":\"q1\",\"kind\":\"process\",\"status\":\"queued\","
                + "\"snapshot_ref\":null,\"created_by\":\"apikey:k\","
                + "\"created_at\":\"2026-11-08T19:43:23.105333\",\"finished_at\":null,"
                + "\"error\":null},\"report\":null,\"jobs\":{},\"health\":{},\"energy\":{},"
                + "\"queued\":true}"));

    CheckResult result =
        client.submitProcess(
            new byte[] {9}, "model.tar.gz", ScanOptions.builder().tee("intel_tdx").build());

    assertTrue(result.queued());
    assertFalse(result.hasReport());
    assertEquals("q1", result.scanRun().id());
    MultipartParser.Form form = MultipartParser.parse(server.onlyRequest());
    assertEquals(List.of("tee", "snapshot"), form.names());
    assertEquals("intel_tdx", form.text("tee"));
  }

  @Test
  void ingestReportPostsJsonWithOnlySetFields() throws IOException {
    server.on("POST /v1/checks/report", Response.json(201, Fixtures.read("ingest_result.json")));
    ObjectNode report = JSON.createObjectNode().put("report_id", "rat-1");
    report.putObject("verdict").put("status", "pass");

    CheckResult result =
        client.ingestReport(
            report,
            IngestOptions.builder()
                .environment(Environment.EDGE)
                .countryCode("EU")
                .inputDigest(Digests.sha256(new byte[] {1, 2, 3}))
                .build());

    assertEquals("pass", result.report().verdictStatus());
    Recorded request = server.onlyRequest();
    assertEquals("application/json", request.header("Content-Type"));
    JsonNode body = JSON.readTree(request.body());
    assertEquals(report, body.get("report"));
    assertEquals("edge", body.get("environment").asText());
    assertEquals("EU", body.get("country_code").asText());
    assertEquals(
        "sha256:039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81",
        body.get("input_digest").asText());
    assertFalse(body.has("asset"));
    assertFalse(body.has("repo"));
    assertEquals(4, body.size());
  }

  @Test
  void ingestReportFromFile(@TempDir Path dir) throws IOException {
    Path file = dir.resolve("report.json");
    Files.writeString(file, "{\"report_id\":\"rat-1\",\"issues\":[]}");
    server.on("POST /v1/checks/report", Response.json(201, Fixtures.read("ingest_result.json")));

    client.ingestReport(file, IngestOptions.defaults());

    JsonNode body = JSON.readTree(server.onlyRequest().body());
    assertEquals("rat-1", body.path("report").path("report_id").asText());
    assertEquals(1, body.size());
  }

  @Test
  void ingestReportRejectsNonObjects(@TempDir Path dir) throws IOException {
    assertThrows(
        IllegalArgumentException.class,
        () -> client.ingestReport(JSON.createArrayNode(), IngestOptions.defaults()));
    Path file = dir.resolve("broken.json");
    Files.writeString(file, "{not json");
    assertThrows(
        IllegalArgumentException.class, () -> client.ingestReport(file, IngestOptions.defaults()));
    assertTrue(server.requests().isEmpty());
  }

  @Test
  void getReportDocumentAndAttestation() {
    server
        .onFixture("GET /v1/reports/r1/document", "report_document_excerpt.json")
        .onFixture("GET /v1/reports/r1/attestation", "attestation.json");

    JsonNode document = client.getReportDocument("r1");
    JsonNode attestation = client.getAttestation("r1");

    assertEquals("fail", document.path("verdict").path("status").asText());
    assertEquals(
        "eu_ai_act/privacy/data_governance_10.aipac",
        document.path("issues").path(0).path("rule_path").asText());
    assertEquals("att-43d463ff6d874d1a92be85ed768b762f", attestation.path("attestation_id").asText());
    assertEquals("1.0", attestation.path("input_version").asText());
  }

  @Test
  void listSystemsReturnsUnmodifiableList() {
    server.onFixture("GET /v1/systems", "systems.json");

    List<AiSystem> systems = client.listSystems();

    assertEquals(3, systems.size());
    assertThrows(UnsupportedOperationException.class, () -> systems.remove(0));
  }

  // --- errors ----------------------------------------------------------------------------------

  @Test
  void notFoundCarriesStatusAndDetail() {
    server.on("GET /v1/scans/nope", Response.json(404, "{\"detail\":\"scan not found\"}"));

    CertOneException error = assertThrows(CertOneException.class, () -> client.getScan("nope"));

    assertEquals(404, error.statusCode());
    assertTrue(error.isHttpError());
    assertEquals("scan not found", error.detail());
    assertEquals("HTTP 404: scan not found (GET /v1/scans/nope)", error.getMessage());
  }

  @Test
  void attestationOfFailedVerdictIs404() {
    server.on(
        "GET /v1/reports/r1/attestation",
        Response.json(
            404, "{\"detail\":\"no attestation (the input did not pass, so none was issued)\"}"));

    CertOneException error =
        assertThrows(CertOneException.class, () -> client.getAttestation("r1"));

    assertEquals(404, error.statusCode());
    assertTrue(error.detail().startsWith("no attestation"));
  }

  @Test
  void validationErrorDetailIsRendered() {
    server.on(
        "POST /v1/checks/report",
        Response.json(
            422,
            "{\"detail\":[{\"type\":\"missing\",\"loc\":[\"body\",\"report\"],"
                + "\"msg\":\"Field required\",\"input\":{}},"
                + "{\"type\":\"string_type\",\"loc\":[\"body\",\"asset\",0],"
                + "\"msg\":\"Input should be a valid string\"}]}"));

    CertOneException error =
        assertThrows(
            CertOneException.class,
            () -> client.ingestReport(JSON.createObjectNode(), IngestOptions.defaults()));

    assertEquals(422, error.statusCode());
    assertEquals(
        "body.report: Field required; body.asset.0: Input should be a valid string",
        error.detail());
  }

  @Test
  void nonJsonErrorBodyIsKeptAsText() {
    server.on("GET /v1/systems", Response.text(502, "text/html", "<html>Bad Gateway</html>"));

    CertOneException error = assertThrows(CertOneException.class, client::listSystems);

    assertEquals(502, error.statusCode());
    assertEquals("<html>Bad Gateway</html>", error.detail());
  }

  @Test
  void errorWithoutBodyHasEmptyDetail() {
    server.on("GET /v1/systems", new Response(401, "application/json", new byte[0], 0));

    CertOneException error = assertThrows(CertOneException.class, client::listSystems);

    assertEquals(401, error.statusCode());
    assertEquals("", error.detail());
    assertEquals("HTTP 401 (GET /v1/systems)", error.getMessage());
  }

  @Test
  void errorMessagesNeverContainTheToken() {
    server.on("GET /v1/systems", Response.json(403, "{\"detail\":\"forbidden\"}"));

    CertOneException error = assertThrows(CertOneException.class, client::listSystems);

    assertFalse(error.getMessage().contains(TOKEN));
    assertFalse(client.toString().contains(TOKEN));
  }

  @Test
  void undecodableSuccessBodyIsAnError() {
    server.on("GET /v1/systems", Response.text(200, "application/json", "{\"truncated"));

    CertOneException error = assertThrows(CertOneException.class, client::listSystems);

    assertEquals(0, error.statusCode());
    assertInstanceOf(IOException.class, error.getCause());
  }

  @Test
  void connectionRefusedIsAnError() throws IOException {
    int port;
    try (ServerSocket socket = new ServerSocket(0)) {
      port = socket.getLocalPort();
    }
    CertOneClient unreachable = CertOneClient.create("http://127.0.0.1:" + port, TOKEN);

    CertOneException error = assertThrows(CertOneException.class, unreachable::listSystems);

    assertEquals(0, error.statusCode());
    assertFalse(error.isHttpError());
    assertInstanceOf(IOException.class, error.getCause());
  }

  @Test
  void requestTimeoutIsAnError() {
    server.on(
        "GET /v1/systems", Response.json(200, Fixtures.read("systems.json")).delayed(2_000));
    CertOneClient impatient =
        CertOneClient.builder(server.baseUrl())
            .token(TOKEN)
            .requestTimeout(Duration.ofMillis(200))
            .build();

    CertOneException error = assertThrows(CertOneException.class, impatient::listSystems);

    assertEquals(0, error.statusCode());
    assertInstanceOf(HttpTimeoutException.class, error.getCause());
    assertTrue(error.getMessage().contains("timed out"));
  }

  // --- waitForReport ---------------------------------------------------------------------------

  @Test
  void waitForReportPollsUntilSucceeded() {
    AtomicInteger polls = new AtomicInteger();
    server
        .on(
            "GET /v1/scans/s1",
            request -> {
              String status =
                  switch (polls.incrementAndGet()) {
                    case 1 -> "queued";
                    case 2 -> "running";
                    default -> "succeeded";
                  };
              return Response.json(200, scanJson("s1", status, null));
            })
        .onFixture("GET /v1/scans/s1/report", "report.json");

    Report report = client.waitForReport("s1", Duration.ofSeconds(10), Duration.ofMillis(10));

    assertEquals("88b35a6b07bb456aa5159c32831f6bf4", report.id());
    assertEquals(3, polls.get());
    assertEquals("/v1/scans/s1/report", server.requests().get(3).path());
  }

  @Test
  void waitForReportRetriesTransientErrors() {
    AtomicInteger polls = new AtomicInteger();
    server
        .on(
            "GET /v1/scans/s1",
            request ->
                polls.incrementAndGet() == 1
                    ? Response.json(503, "{\"detail\":\"draining\"}")
                    : Response.json(200, scanJson("s1", "succeeded", null)))
        .onFixture("GET /v1/scans/s1/report", "report.json");

    Report report = client.waitForReport("s1", Duration.ofSeconds(10), Duration.ofMillis(10));

    assertEquals("fail", report.verdictStatus());
    assertEquals(2, polls.get());
  }

  @Test
  void waitForReportStopsOnNonTransientErrors() {
    server.on("GET /v1/scans/s1", Response.json(404, "{\"detail\":\"scan not found\"}"));

    CertOneException error =
        assertThrows(
            CertOneException.class,
            () -> client.waitForReport("s1", Duration.ofSeconds(10), Duration.ofMillis(10)));

    assertEquals(404, error.statusCode());
    assertEquals(1, server.requests().size());
  }

  @Test
  void waitForReportRaisesScanError() {
    server.on(
        "GET /v1/scans/s1", Response.json(200, scanJson("s1", "failed", "snapshot is not a tar")));

    ScanFailedException error =
        assertThrows(
            ScanFailedException.class,
            () -> client.waitForReport("s1", Duration.ofSeconds(10), Duration.ofMillis(10)));

    assertEquals("s1", error.scanId());
    assertEquals("snapshot is not a tar", error.detail());
    assertEquals("scan s1 failed: snapshot is not a tar", error.getMessage());
  }

  @Test
  void waitForReportTimesOut() {
    server.on("GET /v1/scans/s1", Response.json(200, scanJson("s1", "running", null)));

    CertOneException error =
        assertThrows(
            CertOneException.class,
            () -> client.waitForReport("s1", Duration.ofMillis(150), Duration.ofMillis(20)));

    assertInstanceOf(TimeoutException.class, error.getCause());
    assertTrue(error.getMessage().contains("last status: running"), error.getMessage());
    assertTrue(server.requests().size() >= 2);
  }

  @Test
  void waitForReportWithZeroTimeoutPollsOnce() {
    server.on("GET /v1/scans/s1", Response.json(200, scanJson("s1", "queued", null)));

    assertThrows(
        CertOneException.class,
        () -> client.waitForReport("s1", Duration.ZERO, Duration.ofSeconds(1)));
    assertEquals(1, server.requests().size());
  }

  @Test
  void waitForReportHonoursInterruption() {
    server.on("GET /v1/scans/s1", Response.json(200, scanJson("s1", "running", null)));
    Thread.currentThread().interrupt();
    try {
      CertOneException error =
          assertThrows(
              CertOneException.class,
              () -> client.waitForReport("s1", Duration.ofSeconds(30), Duration.ofSeconds(5)));
      assertInstanceOf(InterruptedException.class, error.getCause());
      assertTrue(Thread.currentThread().isInterrupted());
    } finally {
      Thread.interrupted();
    }
  }

  @Test
  void waitForReportValidatesArguments() {
    assertThrows(
        IllegalArgumentException.class,
        () -> client.waitForReport("s1", Duration.ofSeconds(-1), Duration.ofSeconds(1)));
    assertThrows(
        IllegalArgumentException.class,
        () -> client.waitForReport("s1", Duration.ofSeconds(1), Duration.ZERO));
  }

  // --- client --------------------------------------------------------------------------------

  @Test
  void clientIsSafeForConcurrentUse() throws Exception {
    server.onFixture("GET /v1/scans/64ff3a4afb5e40f5b8ae5e38071c9145", "scan.json");
    ExecutorService pool = Executors.newFixedThreadPool(8);
    try {
      List<Callable<String>> calls = new ArrayList<>();
      for (int i = 0; i < 64; i++) {
        calls.add(() -> client.getScan("64ff3a4afb5e40f5b8ae5e38071c9145").id());
      }
      for (Future<String> result : pool.invokeAll(calls)) {
        assertEquals("64ff3a4afb5e40f5b8ae5e38071c9145", result.get());
      }
    } finally {
      pool.shutdownNow();
    }
    assertEquals(64, server.requests().size());
  }

  @Test
  void builderValidatesConfiguration() {
    assertThrows(IllegalArgumentException.class, () -> CertOneClient.builder("ftp://host"));
    assertThrows(IllegalArgumentException.class, () -> CertOneClient.builder("api.example.com"));
    assertThrows(
        IllegalArgumentException.class, () -> CertOneClient.builder("https://u:p@host.example"));
    assertThrows(
        IllegalArgumentException.class, () -> CertOneClient.builder("https://host.example/?a=b"));
    assertThrows(
        IllegalArgumentException.class, () -> CertOneClient.create("https://host.example", ""));
    assertThrows(
        IllegalArgumentException.class,
        () -> CertOneClient.create("https://host.example", "ck_x\r\nX-Injected: 1"));
    assertThrows(
        IllegalArgumentException.class,
        () -> CertOneClient.builder("https://host.example").requestTimeout(Duration.ZERO));
    assertThrows(
        IllegalStateException.class,
        () ->
            CertOneClient.builder("https://host.example")
                .connectTimeout(Duration.ofSeconds(1))
                .httpClient(HttpClient.newHttpClient())
                .build());
  }

  @Test
  void builderDefaults() {
    CertOneClient defaults = CertOneClient.create("https://api.example.com/", TOKEN);

    assertEquals("https://api.example.com", defaults.baseUrl());
    assertEquals(Duration.ofSeconds(30), defaults.requestTimeout());
    assertEquals(Duration.ofSeconds(5), CertOneClient.DEFAULT_CONNECT_TIMEOUT);
    assertEquals(Duration.ofSeconds(900), CertOneClient.DEFAULT_WAIT_TIMEOUT);
    assertEquals(Duration.ofSeconds(2), CertOneClient.DEFAULT_POLL_INTERVAL);
    assertEquals(
        "CertOneClient[baseUrl=https://api.example.com, authorization=Bearer <redacted>, "
            + "requestTimeout=PT30S]",
        defaults.toString());
    assertFalse(CertOneClient.VERSION.isBlank());
  }

  @Test
  void customHttpClientIsUsed() {
    server.onFixture("GET /v1/systems", "systems.json");
    CertOneClient custom =
        CertOneClient.builder(server.baseUrl())
            .token(TOKEN)
            .httpClient(HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build())
            .build();

    assertEquals(3, custom.listSystems().size());
  }

  private static String scanJson(String id, String status, String error) {
    return "{\"id\":\""
        + id
        + "\",\"kind\":\"check\",\"status\":\""
        + status
        + "\",\"snapshot_ref\":null,\"created_by\":\"apikey:k\","
        + "\"created_at\":\"2026-11-08T19:43:23.105333\",\"finished_at\":null,\"error\":"
        + (error == null ? "null" : "\"" + error + "\"")
        + "}";
  }

  /** Bytes covering every octet value, including CR, LF and '-' runs that resemble boundaries. */
  private static byte[] binaryContent() {
    byte[] content = new byte[4096 + 256];
    for (int i = 0; i < content.length; i++) {
      content[i] = (byte) i;
    }
    byte[] tricky = "\r\n--certone-\r\n\r\n".getBytes(StandardCharsets.US_ASCII);
    System.arraycopy(tricky, 0, content, 100, tricky.length);
    return content;
  }
}
