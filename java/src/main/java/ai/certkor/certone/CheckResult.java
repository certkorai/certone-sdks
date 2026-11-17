package ai.certkor.certone;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Result of {@link CertOneClient#submitCheck}, {@link CertOneClient#submitProcess} and {@link
 * CertOneClient#ingestReport}. Unknown fields (for example the processing-unit {@code jobs}, {@code
 * health} and {@code energy} of {@code POST /v1/process}) are ignored.
 *
 * @param scanRun the scan run that was created
 * @param report the verdict summary, or {@code null} when the submission was queued for the
 *     confidential worker pool ({@code queued == true}); then call {@link
 *     CertOneClient#waitForReport(String)} with {@code scanRun().id()}
 * @param queued whether the scan was enqueued for asynchronous evaluation
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record CheckResult(
    @JsonProperty("scan_run") ScanRun scanRun,
    @JsonProperty("report") Report report,
    @JsonProperty("queued") boolean queued) {

  /**
   * Whether the verdict summary is already available.
   *
   * @return {@code true} when {@link #report()} is not {@code null}
   */
  @JsonIgnore
  public boolean hasReport() {
    return report != null;
  }
}
