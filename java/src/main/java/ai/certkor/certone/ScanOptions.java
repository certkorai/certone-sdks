package ai.certkor.certone;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Options of {@link CertOneClient#submitCheck} and {@link CertOneClient#submitProcess}, sent as
 * multipart form fields. Every option is optional: an unset option is not sent and the control
 * plane applies its default. Instances are immutable and thread-safe.
 *
 * <pre>{@code
 * ScanOptions options = ScanOptions.builder()
 *     .asset("Fraud Scorer")
 *     .environment(Environment.CI)
 *     .countryCode("EU")
 *     .failOn(FailOn.HIGH)
 *     .snapshotRef("git:acme/fraud@" + sha)
 *     .build();
 * }</pre>
 */
public final class ScanOptions {

  private static final ScanOptions DEFAULTS = new Builder().build();

  private final String asset;
  private final Environment environment;
  private final String countryCode;
  private final FailOn failOn;
  private final List<String> packs;
  private final String snapshotRef;
  private final String commitHash;
  private final String tee;

  private ScanOptions(Builder builder) {
    this.asset = builder.asset;
    this.environment = builder.environment;
    this.countryCode = builder.countryCode;
    this.failOn = builder.failOn;
    this.packs = List.copyOf(builder.packs);
    this.snapshotRef = builder.snapshotRef;
    this.commitHash = builder.commitHash;
    this.tee = builder.tee;
  }

  /**
   * Options with nothing set (every field takes the control plane's default).
   *
   * @return the empty options
   */
  public static ScanOptions defaults() {
    return DEFAULTS;
  }

  /**
   * A new builder with nothing set.
   *
   * @return the builder
   */
  public static Builder builder() {
    return new Builder();
  }

  /**
   * A builder initialised from these options.
   *
   * @return the builder
   */
  public Builder toBuilder() {
    Builder builder = new Builder();
    builder.asset = asset;
    builder.environment = environment;
    builder.countryCode = countryCode;
    builder.failOn = failOn;
    builder.packs.addAll(packs);
    builder.snapshotRef = snapshotRef;
    builder.commitHash = commitHash;
    builder.tee = tee;
    return builder;
  }

  /**
   * AI system name (auto-registered on first scan). Default: derived by the control plane.
   *
   * @return the asset name, if set
   */
  public Optional<String> asset() {
    return Optional.ofNullable(asset);
  }

  /**
   * Submission surface. Default: {@link Environment#API}.
   *
   * @return the environment, if set
   */
  public Optional<Environment> environment() {
    return Optional.ofNullable(environment);
  }

  /**
   * Origin region, for example {@code EU} or {@code US}. Default: {@code ZZ}.
   *
   * @return the region code, if set
   */
  public Optional<String> countryCode() {
    return Optional.ofNullable(countryCode);
  }

  /**
   * Verdict severity threshold. Default: {@link FailOn#HIGH}.
   *
   * @return the threshold, if set
   */
  public Optional<FailOn> failOn() {
    return Optional.ofNullable(failOn);
  }

  /**
   * Policy packs to evaluate. Default (empty): auto-matched from the AI BOM.
   *
   * @return the pack names, never {@code null}
   */
  public List<String> packs() {
    return packs;
  }

  /**
   * Stable source reference, for example {@code git:org/repo@sha}.
   *
   * @return the reference, if set
   */
  public Optional<String> snapshotRef() {
    return Optional.ofNullable(snapshotRef);
  }

  /**
   * Commit the scan is about.
   *
   * @return the commit hash, if set
   */
  public Optional<String> commitHash() {
    return Optional.ofNullable(commitHash);
  }

  /**
   * Confidential-compute backend for {@link CertOneClient#submitProcess} (for example {@code
   * amd_sev_snp}, the default). Not accepted by {@link CertOneClient#submitCheck}.
   *
   * @return the backend id, if set
   */
  public Optional<String> tee() {
    return Optional.ofNullable(tee);
  }

  /**
   * The multipart form fields, in a stable order; unset options are omitted.
   *
   * @param includeTee whether to include {@code tee} (only {@code POST /v1/process} accepts it)
   * @return field name to value
   */
  Map<String, String> formFields(boolean includeTee) {
    Map<String, String> fields = new LinkedHashMap<>();
    putIfSet(fields, "asset", asset);
    putIfSet(fields, "environment", environment == null ? null : environment.wireValue());
    putIfSet(fields, "country_code", countryCode);
    putIfSet(fields, "fail_on", failOn == null ? null : failOn.wireValue());
    if (!packs.isEmpty()) {
      fields.put("packs", String.join(",", packs));
    }
    putIfSet(fields, "snapshot_ref", snapshotRef);
    putIfSet(fields, "commit_hash", commitHash);
    if (includeTee) {
      putIfSet(fields, "tee", tee);
    }
    return fields;
  }

  private static void putIfSet(Map<String, String> fields, String name, String value) {
    if (value != null) {
      fields.put(name, value);
    }
  }

  /**
   * Validates an optional text option: {@code null} clears it; otherwise it is stripped and must
   * not be blank.
   */
  static String optionalText(String name, String value) {
    if (value == null) {
      return null;
    }
    String stripped = value.strip();
    if (stripped.isEmpty()) {
      throw new IllegalArgumentException(name + " must not be blank (pass null to unset it)");
    }
    return stripped;
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) {
      return true;
    }
    if (!(other instanceof ScanOptions that)) {
      return false;
    }
    return Objects.equals(asset, that.asset)
        && environment == that.environment
        && Objects.equals(countryCode, that.countryCode)
        && failOn == that.failOn
        && packs.equals(that.packs)
        && Objects.equals(snapshotRef, that.snapshotRef)
        && Objects.equals(commitHash, that.commitHash)
        && Objects.equals(tee, that.tee);
  }

  @Override
  public int hashCode() {
    return Objects.hash(
        asset, environment, countryCode, failOn, packs, snapshotRef, commitHash, tee);
  }

  @Override
  public String toString() {
    Map<String, String> fields = formFields(true);
    return "ScanOptions" + fields;
  }

  /** Mutable builder of {@link ScanOptions}; not thread-safe. Passing {@code null} unsets. */
  public static final class Builder {
    private String asset;
    private Environment environment;
    private String countryCode;
    private FailOn failOn;
    private final List<String> packs = new ArrayList<>();
    private String snapshotRef;
    private String commitHash;
    private String tee;

    private Builder() {}

    /**
     * Sets the AI system name.
     *
     * @param asset name of the AI system, for example {@code "Fraud Scorer"}
     * @return this builder
     */
    public Builder asset(String asset) {
      this.asset = optionalText("asset", asset);
      return this;
    }

    /**
     * Sets the submission surface.
     *
     * @param environment the environment
     * @return this builder
     */
    public Builder environment(Environment environment) {
      this.environment = environment;
      return this;
    }

    /**
     * Sets the origin region.
     *
     * @param countryCode region code, for example {@code "EU"}
     * @return this builder
     */
    public Builder countryCode(String countryCode) {
      this.countryCode = optionalText("countryCode", countryCode);
      return this;
    }

    /**
     * Sets the verdict severity threshold.
     *
     * @param failOn the threshold
     * @return this builder
     */
    public Builder failOn(FailOn failOn) {
      this.failOn = failOn;
      return this;
    }

    /**
     * Replaces the policy packs to evaluate.
     *
     * @param packs pack names; {@code null} or empty restores auto-matching
     * @return this builder
     * @throws IllegalArgumentException when a name is blank or contains a comma
     */
    public Builder packs(Collection<String> packs) {
      List<String> validated = new ArrayList<>();
      if (packs != null) {
        for (String pack : packs) {
          String name = optionalText("pack name", Objects.requireNonNull(pack, "pack name"));
          if (name.indexOf(',') >= 0) {
            throw new IllegalArgumentException("pack name must not contain ',': " + name);
          }
          validated.add(name);
        }
      }
      this.packs.clear();
      this.packs.addAll(validated);
      return this;
    }

    /**
     * Replaces the policy packs to evaluate.
     *
     * @param packs pack names, for example {@code "eu-ai-act-core", "iso-42001-core"}
     * @return this builder
     * @throws IllegalArgumentException when a name is blank or contains a comma
     */
    public Builder packs(String... packs) {
      return packs(packs == null ? null : List.of(packs));
    }

    /**
     * Sets the stable source reference.
     *
     * @param snapshotRef reference, for example {@code "git:org/repo@sha"}
     * @return this builder
     */
    public Builder snapshotRef(String snapshotRef) {
      this.snapshotRef = optionalText("snapshotRef", snapshotRef);
      return this;
    }

    /**
     * Sets the commit the scan is about.
     *
     * @param commitHash commit hash
     * @return this builder
     */
    public Builder commitHash(String commitHash) {
      this.commitHash = optionalText("commitHash", commitHash);
      return this;
    }

    /**
     * Sets the confidential-compute backend ({@link CertOneClient#submitProcess} only).
     *
     * @param tee backend id from {@code GET /v1/capabilities/tee}, for example {@code
     *     "amd_sev_snp"}
     * @return this builder
     */
    public Builder tee(String tee) {
      this.tee = optionalText("tee", tee);
      return this;
    }

    /**
     * Builds the immutable options.
     *
     * @return the options
     */
    public ScanOptions build() {
      return new ScanOptions(this);
    }
  }
}
