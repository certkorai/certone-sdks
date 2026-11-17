package ai.certkor.certone;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.ser.std.ToStringSerializer;
import java.time.Instant;

/**
 * A scan run ({@code GET /v1/scans/{id}}). Unknown fields sent by newer control planes are ignored.
 *
 * @param id scan run id
 * @param kind {@code check} or {@code process}
 * @param status {@code queued}, {@code running}, {@code succeeded} or {@code failed}
 * @param snapshotRef stable source reference supplied at submission, or {@code null}
 * @param createdBy principal that submitted the scan (for an API key: {@code apikey:<id>})
 * @param createdAt when the scan was created
 * @param finishedAt when the scan finished, or {@code null} while it is still in progress
 * @param error failure reason when {@code status} is {@code failed}, otherwise {@code null}
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ScanRun(
    @JsonProperty("id") String id,
    @JsonProperty("kind") String kind,
    @JsonProperty("status") String status,
    @JsonProperty("snapshot_ref") String snapshotRef,
    @JsonProperty("created_by") String createdBy,
    @JsonProperty("created_at")
        @JsonDeserialize(using = Timestamps.Deserializer.class)
        @JsonSerialize(using = ToStringSerializer.class)
        Instant createdAt,
    @JsonProperty("finished_at")
        @JsonDeserialize(using = Timestamps.Deserializer.class)
        @JsonSerialize(using = ToStringSerializer.class)
        Instant finishedAt,
    @JsonProperty("error") String error) {

  /** Status of a scan waiting for a worker. */
  public static final String STATUS_QUEUED = "queued";

  /** Status of a scan being evaluated. */
  public static final String STATUS_RUNNING = "running";

  /** Terminal status of a scan that produced a report. */
  public static final String STATUS_SUCCEEDED = "succeeded";

  /** Terminal status of a scan that could not be evaluated; see {@link #error()}. */
  public static final String STATUS_FAILED = "failed";

  /**
   * Whether the scan produced a report.
   *
   * @return {@code true} when {@link #status()} is {@code succeeded}
   */
  @JsonIgnore
  public boolean isSucceeded() {
    return STATUS_SUCCEEDED.equals(status);
  }

  /**
   * Whether the scan failed.
   *
   * @return {@code true} when {@link #status()} is {@code failed}
   */
  @JsonIgnore
  public boolean isFailed() {
    return STATUS_FAILED.equals(status);
  }

  /**
   * Whether the scan reached a final state.
   *
   * @return {@code true} when the scan succeeded or failed
   */
  @JsonIgnore
  public boolean isTerminal() {
    return isSucceeded() || isFailed();
  }
}
