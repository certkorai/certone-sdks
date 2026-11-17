package ai.certkor.certone;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ai.certkor.certone.StubServer.Fixtures;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Every response fixture captured from a real control plane deserializes into the SDK types, with
 * a plain (strict) {@link ObjectMapper}: the records carry their own mapping annotations.
 */
class FixturesTest {

  private final ObjectMapper strict = new ObjectMapper();

  @Test
  void checkResultFixture() throws IOException {
    CheckResult result = strict.readValue(Fixtures.read("check_result.json"), CheckResult.class);

    assertFalse(result.queued());
    assertTrue(result.hasReport());
    ScanRun scan = result.scanRun();
    assertEquals("64ff3a4afb5e40f5b8ae5e38071c9145", scan.id());
    assertEquals("check", scan.kind());
    assertTrue(scan.isSucceeded());
    assertTrue(scan.isTerminal());
    assertNull(scan.snapshotRef());
    assertNull(scan.error());
    assertEquals("apikey:3a58fad90b314f52a37068c0c3d80e32", scan.createdBy());
    assertEquals(Instant.parse("2026-11-08T19:43:23.105333Z"), scan.createdAt());
    assertEquals(Instant.parse("2026-11-08T19:43:23.167688Z"), scan.finishedAt());

    Report report = result.report();
    assertEquals("88b35a6b07bb456aa5159c32831f6bf4", report.id());
    assertEquals(scan.id(), report.scanRunId());
    assertEquals("report-bce1fa3cd2cd", report.reportId());
    assertEquals(Report.VERDICT_FAIL, report.verdictStatus());
    assertFalse(report.isPass());
    assertEquals("high", report.failOn());
    assertEquals(6, report.totalIssues());
    assertEquals(Map.of("low", 0, "medium", 3, "high", 3), report.bySeverity());
    assertEquals(List.of("low", "medium", "high"), List.copyOf(report.bySeverity().keySet()));
    assertEquals(3, report.issuesAt("high"));
    assertEquals(0, report.issuesAt("critical"));
    assertEquals("ZZ", report.countryCode());
  }

  @Test
  void ingestResultFixture() throws IOException {
    CheckResult result = strict.readValue(Fixtures.read("ingest_result.json"), CheckResult.class);

    assertTrue(result.report().isPass());
    assertEquals("rat-sdk-0001", result.report().reportId());
    assertEquals(0, result.report().totalIssues());
    assertTrue(result.report().bySeverity().isEmpty());
    assertEquals("EU", result.report().countryCode());
  }

  @Test
  void reportFixtureWithTimestampWithoutOffsetIsUtc() throws IOException {
    Report report = strict.readValue(Fixtures.read("report.json"), Report.class);

    assertEquals("88b35a6b07bb456aa5159c32831f6bf4", report.id());
    assertEquals(Instant.parse("2026-11-08T19:43:23.168877Z"), report.createdAt());
    assertThrows(
        UnsupportedOperationException.class, () -> report.bySeverity().put("critical", 1));
  }

  @Test
  void scanFixture() throws IOException {
    ScanRun scan = strict.readValue(Fixtures.read("scan.json"), ScanRun.class);

    assertEquals("64ff3a4afb5e40f5b8ae5e38071c9145", scan.id());
    assertEquals(ScanRun.STATUS_SUCCEEDED, scan.status());
    assertEquals(Instant.parse("2026-11-08T19:43:23.105333Z"), scan.createdAt());
  }

  @Test
  void systemsFixture() throws IOException {
    List<AiSystem> systems =
        strict.readValue(Fixtures.read("systems.json"), new TypeReference<List<AiSystem>>() {});

    assertEquals(3, systems.size());
    AiSystem edge = systems.get(0);
    assertEquals("sdk-edge-model", edge.slug());
    assertEquals("SDK Edge Model", edge.name());
    assertEquals("prod", edge.lifecycle());
    assertNull(edge.ownerTeamId());
    assertEquals(List.of("EU"), edge.regions());
    assertEquals(List.of("edge"), edge.environments());
    assertEquals(5, edge.standards().size());
    assertEquals(1, edge.scans());
    assertEquals(0, edge.openIssues());
    assertEquals("pass", edge.lastVerdict());
    assertTrue(edge.attested());
    assertEquals("valid", edge.attestationStatus());
    assertEquals("low", edge.risk());
    assertEquals(Instant.parse("2026-11-08T19:43:23.231273Z"), edge.lastEvaluated());
    assertFalse(systems.get(1).attested());
    assertEquals(6, systems.get(1).openIssues());
    assertThrows(UnsupportedOperationException.class, () -> edge.regions().add("US"));
  }

  @Test
  void attestationAndReportDocumentFixturesAreJson() throws IOException {
    JsonNode attestation = strict.readTree(Fixtures.read("attestation.json"));
    assertEquals("att-43d463ff6d874d1a92be85ed768b762f", attestation.path("attestation_id").asText());
    assertEquals("HMAC-SHA256", attestation.path("signature_algorithm").asText());

    JsonNode document = strict.readTree(Fixtures.read("report_document_excerpt.json"));
    assertEquals("fail", document.path("verdict").path("status").asText());
    assertEquals("high", document.path("issues").path(0).path("severity").asText());
  }

  @Test
  void unknownFieldsAreIgnored() throws IOException {
    String json =
        "{\"scan_run\":{\"id\":\"s1\",\"kind\":\"process\",\"status\":\"queued\","
            + "\"created_at\":\"2026-11-08T19:43:23Z\",\"pool\":\"amd_sev_snp\"},"
            + "\"report\":null,\"queued\":true,\"jobs\":{\"static\":1},\"health\":{},"
            + "\"energy\":{\"kwh\":0.1}}";

    CheckResult result = strict.readValue(json, CheckResult.class);

    assertTrue(result.queued());
    assertFalse(result.hasReport());
    assertEquals(ScanRun.STATUS_QUEUED, result.scanRun().status());
    assertFalse(result.scanRun().isTerminal());
    assertNull(result.scanRun().finishedAt());
  }

  @Test
  void recordsRoundTripThroughJackson() throws IOException {
    Report report = strict.readValue(Fixtures.read("report.json"), Report.class);
    String json = strict.writeValueAsString(report);

    assertFalse(json.contains("\"pass\""), "helper accessors must not be serialized: " + json);
    assertEquals(report, strict.readValue(json, Report.class));

    ScanRun scan = strict.readValue(Fixtures.read("scan.json"), ScanRun.class);
    JsonNode tree = strict.readTree(strict.writeValueAsString(scan));
    assertFalse(tree.has("succeeded"));
    assertFalse(tree.has("terminal"));
    assertEquals(scan, strict.readValue(tree.toString(), ScanRun.class));
  }

  @Test
  void invalidTimestampIsRejected() {
    String json = "{\"id\":\"s1\",\"status\":\"running\",\"created_at\":\"yesterday\"}";

    IOException error =
        assertThrows(IOException.class, () -> strict.readValue(json, ScanRun.class));
    assertNotNull(error.getMessage());
  }

  @Test
  void timestampsWithOffsetsAreNormalized() {
    assertEquals(
        Instant.parse("2026-11-08T17:43:23Z"), Timestamps.parse("2026-11-08T19:43:23+02:00"));
    assertEquals(Instant.parse("2026-11-08T19:43:23Z"), Timestamps.parse("2026-11-08T19:43:23"));
  }
}
