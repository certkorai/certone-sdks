import ai.certkor.certone.AiSystem;
import ai.certkor.certone.CertOneClient;
import ai.certkor.certone.CertOneException;
import ai.certkor.certone.CheckResult;
import ai.certkor.certone.Digests;
import ai.certkor.certone.Environment;
import ai.certkor.certone.FailOn;
import ai.certkor.certone.IngestOptions;
import ai.certkor.certone.Report;
import ai.certkor.certone.ScanOptions;
import com.fasterxml.jackson.databind.JsonNode;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * The CertOne SDK conformance quickstart (SPEC.md, "Conformance"), against a real control
 * plane.
 *
 * <p>Environment: {@code CERTONE_API_URL}, {@code CERTONE_API_KEY}, {@code CERTONE_SNAPSHOT} (a
 * project {@code .tar.gz}) and {@code CERTONE_REPORT_JSON} (an engine report computed at the
 * source). Exits 0 on success, 1 with the error otherwise.
 */
public final class Quickstart {

  private Quickstart() {}

  /**
   * Runs the quickstart.
   *
   * @param args ignored
   */
  public static void main(String[] args) {
    try {
      run();
    } catch (CertOneException e) {
      System.err.println("quickstart failed: " + e.getMessage());
      System.exit(1);
    } catch (RuntimeException e) {
      System.err.println("quickstart failed: " + e);
      System.exit(1);
    }
  }

  private static void run() {
    // 1. Configuration from the environment.
    String apiUrl = requireEnv("CERTONE_API_URL");
    String apiKey = requireEnv("CERTONE_API_KEY");
    Path snapshot = Path.of(requireEnv("CERTONE_SNAPSHOT")).toAbsolutePath();
    Path reportJson = Path.of(requireEnv("CERTONE_REPORT_JSON")).toAbsolutePath();
    if (!Files.isRegularFile(snapshot) || !Files.isRegularFile(reportJson)) {
      throw new IllegalStateException("missing input: " + snapshot + " or " + reportJson);
    }
    CertOneClient client = CertOneClient.create(apiUrl, apiKey);
    System.out.println("CertOne Java SDK " + CertOneClient.VERSION + " quickstart -> " + apiUrl);

    // 2. Submit the sample project for a compliance check.
    CheckResult check =
        client.submitCheck(
            snapshot,
            ScanOptions.builder().asset("Java SDK quickstart").failOn(FailOn.HIGH).build());
    String scanId = check.scanRun().id();
    System.out.println("[check]  scan id: " + scanId);
    if (check.hasReport()) {
      Report summary = check.report();
      System.out.println("[check]  verdict: " + summary.verdictStatus()
          + " (fail_on=" + summary.failOn() + ")");
      System.out.println("[check]  findings by severity: " + summary.bySeverity()
          + " (total " + summary.totalIssues() + ")");
    } else {
      System.out.println("[check]  queued for the confidential worker pool");
    }

    // 3. Wait for the report, then fetch the full engine report document.
    Report report = client.waitForReport(scanId);
    System.out.println("[report] report " + report.id() + " (engine " + report.reportId()
        + "): verdict " + report.verdictStatus());
    JsonNode document = client.getReportDocument(report.id());
    JsonNode issues = document.path("issues");
    if (issues.isArray() && !issues.isEmpty()) {
      JsonNode first = issues.get(0);
      System.out.println("[report] first finding: [" + first.path("severity").asText() + "] "
          + first.path("compliance_topic").asText() + "/" + first.path("component").asText()
          + " " + first.path("rule_path").asText());
      System.out.println("[report]   " + first.path("description").asText());
    } else {
      System.out.println("[report] no findings");
    }

    // 4. Run-at-source: submit a report computed where the model lives, bound to the snapshot.
    CheckResult ingested =
        client.ingestReport(
            reportJson,
            IngestOptions.builder()
                .environment(Environment.EDGE)
                .countryCode("EU")
                .inputDigest(Digests.sha256(snapshot))
                .build());
    System.out.println("[ingest] scan id: " + ingested.scanRun().id());
    System.out.println("[ingest] verdict: " + ingested.report().verdictStatus());

    // 5. The attestation issued for the passing run-at-source report.
    JsonNode attestation = client.getAttestation(ingested.report().id());
    System.out.println("[attest] attestation_id: " + attestation.path("attestation_id").asText());
    System.out.println("[attest] input_version: " + attestation.path("input_version").asText());
    System.out.println("[attest] signature_algorithm: "
        + attestation.path("signature_algorithm").asText());

    // 6. The tenant's AI-system inventory.
    List<AiSystem> systems = client.listSystems();
    System.out.println("[systems] the tenant has " + systems.size() + " AI systems");

    // 7. Done.
    System.out.println("quickstart OK");
  }

  private static String requireEnv(String name) {
    String value = System.getenv(name);
    if (value == null || value.isBlank()) {
      throw new IllegalStateException(name + " is not set");
    }
    return value.strip();
  }
}
