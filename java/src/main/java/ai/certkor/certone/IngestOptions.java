package ai.certkor.certone;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Options of {@link CertOneClient#ingestReport} (run-at-source submission). Every option is
 * optional: an unset option is not sent and the control plane applies its default. Instances are
 * immutable and thread-safe.
 *
 * <pre>{@code
 * IngestOptions options = IngestOptions.builder()
 *     .asset("Fraud Scorer")
 *     .environment(Environment.EDGE)
 *     .countryCode("EU")
 *     .inputDigest(Digests.sha256(snapshotPath))
 *     .build();
 * }</pre>
 */
public final class IngestOptions {

  private static final IngestOptions DEFAULTS = new Builder().build();

  private final String asset;
  private final Environment environment;
  private final String countryCode;
  private final String snapshotRef;
  private final String inputDigest;
  private final String repo;
  private final String commitHash;

  private IngestOptions(Builder builder) {
    this.asset = builder.asset;
    this.environment = builder.environment;
    this.countryCode = builder.countryCode;
    this.snapshotRef = builder.snapshotRef;
    this.inputDigest = builder.inputDigest;
    this.repo = builder.repo;
    this.commitHash = builder.commitHash;
  }

  /**
   * Options with nothing set (every field takes the control plane's default).
   *
   * @return the empty options
   */
  public static IngestOptions defaults() {
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
    builder.snapshotRef = snapshotRef;
    builder.inputDigest = inputDigest;
    builder.repo = repo;
    builder.commitHash = commitHash;
    return builder;
  }

  /**
   * AI system name (auto-registered on first submission).
   *
   * @return the asset name, if set
   */
  public Optional<String> asset() {
    return Optional.ofNullable(asset);
  }

  /**
   * Where the report was computed. Default: {@link Environment#API}.
   *
   * @return the environment, if set
   */
  public Optional<Environment> environment() {
    return Optional.ofNullable(environment);
  }

  /**
   * Origin region. Default: {@code ZZ}.
   *
   * @return the region code, if set
   */
  public Optional<String> countryCode() {
    return Optional.ofNullable(countryCode);
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
   * Digest of the artifact the report covers ({@code sha256:<hex>}); binds the attestation to it.
   *
   * @return the digest, if set
   */
  public Optional<String> inputDigest() {
    return Optional.ofNullable(inputDigest);
  }

  /**
   * Source repository, for example {@code org/repo}.
   *
   * @return the repository, if set
   */
  public Optional<String> repo() {
    return Optional.ofNullable(repo);
  }

  /**
   * Commit the report is about.
   *
   * @return the commit hash, if set
   */
  public Optional<String> commitHash() {
    return Optional.ofNullable(commitHash);
  }

  /**
   * The JSON body fields besides {@code report}, in a stable order; unset options are omitted.
   *
   * @return field name to value
   */
  Map<String, String> bodyFields() {
    Map<String, String> fields = new LinkedHashMap<>();
    putIfSet(fields, "asset", asset);
    putIfSet(fields, "environment", environment == null ? null : environment.wireValue());
    putIfSet(fields, "country_code", countryCode);
    putIfSet(fields, "snapshot_ref", snapshotRef);
    putIfSet(fields, "input_digest", inputDigest);
    putIfSet(fields, "repo", repo);
    putIfSet(fields, "commit_hash", commitHash);
    return fields;
  }

  private static void putIfSet(Map<String, String> fields, String name, String value) {
    if (value != null) {
      fields.put(name, value);
    }
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) {
      return true;
    }
    if (!(other instanceof IngestOptions that)) {
      return false;
    }
    return bodyFields().equals(that.bodyFields());
  }

  @Override
  public int hashCode() {
    return bodyFields().hashCode();
  }

  @Override
  public String toString() {
    return "IngestOptions" + bodyFields();
  }

  /** Mutable builder of {@link IngestOptions}; not thread-safe. Passing {@code null} unsets. */
  public static final class Builder {
    private String asset;
    private Environment environment;
    private String countryCode;
    private String snapshotRef;
    private String inputDigest;
    private String repo;
    private String commitHash;

    private Builder() {}

    /**
     * Sets the AI system name.
     *
     * @param asset name of the AI system
     * @return this builder
     */
    public Builder asset(String asset) {
      this.asset = ScanOptions.optionalText("asset", asset);
      return this;
    }

    /**
     * Sets where the report was computed.
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
      this.countryCode = ScanOptions.optionalText("countryCode", countryCode);
      return this;
    }

    /**
     * Sets the stable source reference.
     *
     * @param snapshotRef reference, for example {@code "git:org/repo@sha"}
     * @return this builder
     */
    public Builder snapshotRef(String snapshotRef) {
      this.snapshotRef = ScanOptions.optionalText("snapshotRef", snapshotRef);
      return this;
    }

    /**
     * Sets the digest of the artifact the report covers.
     *
     * @param inputDigest {@code sha256:<hex>}, see {@link Digests#sha256(java.nio.file.Path)}
     * @return this builder
     */
    public Builder inputDigest(String inputDigest) {
      this.inputDigest = ScanOptions.optionalText("inputDigest", inputDigest);
      return this;
    }

    /**
     * Sets the source repository.
     *
     * @param repo repository, for example {@code "org/repo"}
     * @return this builder
     */
    public Builder repo(String repo) {
      this.repo = ScanOptions.optionalText("repo", repo);
      return this;
    }

    /**
     * Sets the commit the report is about.
     *
     * @param commitHash commit hash
     * @return this builder
     */
    public Builder commitHash(String commitHash) {
      this.commitHash = ScanOptions.optionalText("commitHash", commitHash);
      return this;
    }

    /**
     * Builds the immutable options.
     *
     * @return the options
     */
    public IngestOptions build() {
      return new IngestOptions(this);
    }
  }
}
