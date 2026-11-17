package ai.certkor.certone;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.ser.std.ToStringSerializer;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * An AI system of the tenant's inventory ({@code GET /v1/systems}). Systems are auto-registered by
 * the {@code asset} of the first scan. Unknown fields sent by newer control planes are ignored.
 *
 * @param id system id
 * @param slug stable slug derived from the name
 * @param name display name
 * @param lifecycle lifecycle stage, for example {@code prod}
 * @param ownerTeamId owning team id, or {@code null}
 * @param description description, or {@code null}
 * @param createdAt when the system was registered
 * @param regions origin regions it was evaluated in (unmodifiable)
 * @param environments submission environments it was evaluated from (unmodifiable)
 * @param standards frameworks it was evaluated against (unmodifiable)
 * @param scans number of scans
 * @param openIssues open findings of the latest evaluation
 * @param lastVerdict latest verdict ({@code pass}/{@code fail}), or {@code null}
 * @param attested whether a valid attestation covers the latest evaluation
 * @param attestationStatus attestation status, for example {@code valid} or {@code none}
 * @param risk risk tier, for example {@code low} or {@code high}
 * @param lastEvaluated when the system was last evaluated, or {@code null}
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record AiSystem(
    @JsonProperty("id") String id,
    @JsonProperty("slug") String slug,
    @JsonProperty("name") String name,
    @JsonProperty("lifecycle") String lifecycle,
    @JsonProperty("owner_team_id") String ownerTeamId,
    @JsonProperty("description") String description,
    @JsonProperty("created_at")
        @JsonDeserialize(using = Timestamps.Deserializer.class)
        @JsonSerialize(using = ToStringSerializer.class)
        Instant createdAt,
    @JsonProperty("regions") List<String> regions,
    @JsonProperty("environments") List<String> environments,
    @JsonProperty("standards") List<String> standards,
    @JsonProperty("scans") int scans,
    @JsonProperty("open_issues") int openIssues,
    @JsonProperty("last_verdict") String lastVerdict,
    @JsonProperty("attested") boolean attested,
    @JsonProperty("attestation_status") String attestationStatus,
    @JsonProperty("risk") String risk,
    @JsonProperty("last_evaluated")
        @JsonDeserialize(using = Timestamps.Deserializer.class)
        @JsonSerialize(using = ToStringSerializer.class)
        Instant lastEvaluated) {

  /**
   * Canonical constructor; copies the lists into unmodifiable lists ({@code null} becomes empty).
   *
   * @param id system id
   * @param slug slug
   * @param name display name
   * @param lifecycle lifecycle stage
   * @param ownerTeamId owning team id
   * @param description description
   * @param createdAt registration time
   * @param regions origin regions
   * @param environments submission environments
   * @param standards evaluated frameworks
   * @param scans number of scans
   * @param openIssues open findings
   * @param lastVerdict latest verdict
   * @param attested whether attested
   * @param attestationStatus attestation status
   * @param risk risk tier
   * @param lastEvaluated last evaluation time
   */
  public AiSystem {
    regions = copy(regions);
    environments = copy(environments);
    standards = copy(standards);
  }

  private static List<String> copy(List<String> values) {
    return values == null ? List.of() : Collections.unmodifiableList(new ArrayList<>(values));
  }
}
