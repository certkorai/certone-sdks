package ai.certkor.certone;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.ser.std.ToStringSerializer;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A report record: the verdict summary of one scan ({@code GET /v1/scans/{id}/report}). Fetch the
 * full engine report with {@link CertOneClient#getReportDocument(String)} using {@link #id()}.
 * Unknown fields sent by newer control planes are ignored.
 *
 * @param id report record id; the {@code report_id} path parameter of {@code /v1/reports/...}
 * @param scanRunId id of the scan run that produced this report
 * @param reportId the engine's own report identifier (not usable in {@code /v1/reports/...} paths)
 * @param verdictStatus {@code pass} or {@code fail}
 * @param failOn severity threshold the verdict was computed against
 * @param totalIssues number of findings
 * @param bySeverity number of findings per severity (unmodifiable, never {@code null})
 * @param countryCode origin region of the scan, or {@code null}
 * @param createdAt when the report was recorded
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record Report(
    @JsonProperty("id") String id,
    @JsonProperty("scan_run_id") String scanRunId,
    @JsonProperty("report_id") String reportId,
    @JsonProperty("verdict_status") String verdictStatus,
    @JsonProperty("fail_on") String failOn,
    @JsonProperty("total_issues") int totalIssues,
    @JsonProperty("by_severity") Map<String, Integer> bySeverity,
    @JsonProperty("country_code") String countryCode,
    @JsonProperty("created_at")
        @JsonDeserialize(using = Timestamps.Deserializer.class)
        @JsonSerialize(using = ToStringSerializer.class)
        Instant createdAt) {

  /** Verdict of a report with no finding at or above the {@code fail_on} threshold. */
  public static final String VERDICT_PASS = "pass";

  /** Verdict of a report with at least one finding at or above the {@code fail_on} threshold. */
  public static final String VERDICT_FAIL = "fail";

  /**
   * Canonical constructor; copies {@code bySeverity} into an unmodifiable, order-preserving map.
   *
   * @param id report record id
   * @param scanRunId scan run id
   * @param reportId engine report identifier
   * @param verdictStatus verdict
   * @param failOn severity threshold
   * @param totalIssues number of findings
   * @param bySeverity findings per severity; {@code null} is treated as empty
   * @param countryCode origin region
   * @param createdAt creation time
   */
  public Report {
    bySeverity =
        bySeverity == null
            ? Map.of()
            : Collections.unmodifiableMap(new LinkedHashMap<>(bySeverity));
  }

  /**
   * Whether the verdict passed.
   *
   * @return {@code true} when {@link #verdictStatus()} is {@code pass}
   */
  @JsonIgnore
  public boolean isPass() {
    return VERDICT_PASS.equals(verdictStatus);
  }

  /**
   * Number of findings at a severity.
   *
   * @param severity {@code low}, {@code medium}, {@code high}, ...
   * @return the count, {@code 0} when the severity is absent
   */
  public int issuesAt(String severity) {
    Integer count = bySeverity.get(severity);
    return count == null ? 0 : count;
  }
}
