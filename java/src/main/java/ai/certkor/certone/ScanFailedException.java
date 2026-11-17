package ai.certkor.certone;

/**
 * A scan reached the {@code failed} state while {@link CertOneClient#waitForReport} was waiting for
 * it. {@link #detail()} is the scan's {@code error}.
 */
public final class ScanFailedException extends CertOneException {

  private static final long serialVersionUID = 1L;

  /** Id of the failed scan run. */
  private final String scanId;

  /**
   * Creates the exception for a failed scan.
   *
   * @param scanId id of the failed scan run
   * @param error the scan's {@code error} as reported by the control plane; may be {@code null}
   */
  public ScanFailedException(String scanId, String error) {
    super(
        "scan " + scanId + " failed" + (error == null || error.isBlank() ? "" : ": " + error),
        0,
        error,
        null);
    this.scanId = scanId;
  }

  /**
   * The failed scan run's id.
   *
   * @return the scan id
   */
  public String scanId() {
    return scanId;
  }
}
