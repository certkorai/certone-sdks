package ai.certkor.certone;

/**
 * A CertOne API call failed.
 *
 * <p>This single unchecked type covers every failure mode of the SDK:
 *
 * <ul>
 *   <li>the control plane answered with an HTTP status {@code >= 400}: {@link #statusCode()} is that
 *       status and {@link #detail()} is the API's {@code detail} message (for a request-validation
 *       error, the field errors rendered as {@code "location: message; ..."});
 *   <li>the request never got an HTTP answer (connection refused, TLS failure, timeout): {@link
 *       #statusCode()} is {@code 0} and the cause is the underlying {@link java.io.IOException}
 *       ({@link java.net.http.HttpTimeoutException} for a timeout);
 *   <li>the response could not be decoded, the calling thread was interrupted, or {@link
 *       CertOneClient#waitForReport} ran out of time ({@link java.util.concurrent.TimeoutException}
 *       cause): {@link #statusCode()} is {@code 0};
 *   <li>a scan finished in the {@code failed} state: the subclass {@link ScanFailedException}.
 * </ul>
 *
 * <p>Messages never contain the bearer token.
 */
public class CertOneException extends RuntimeException {

  private static final long serialVersionUID = 1L;

  /** HTTP status, or {@code 0} when there was no HTTP error response. */
  private final int statusCode;

  /** The API's {@code detail} message (or a description of the local failure). */
  private final String detail;

  /**
   * Creates an exception.
   *
   * @param message human-readable message
   * @param statusCode HTTP status code, or {@code 0} when no HTTP error response was received
   * @param detail the API's {@code detail} message or a description of the failure; may be {@code
   *     null}
   * @param cause underlying cause; may be {@code null}
   */
  public CertOneException(String message, int statusCode, String detail, Throwable cause) {
    super(message, cause);
    this.statusCode = statusCode;
    this.detail = detail == null ? "" : detail;
  }

  /**
   * The HTTP status code of the failed call.
   *
   * @return the HTTP status ({@code >= 400}), or {@code 0} when the failure was not an HTTP error
   *     response (network error, timeout, undecodable response, interrupted wait, failed scan)
   */
  public int statusCode() {
    return statusCode;
  }

  /**
   * The API's {@code detail} message, for example {@code "scan not found"}.
   *
   * @return the detail message, never {@code null} (empty when the API sent none)
   */
  public String detail() {
    return detail;
  }

  /**
   * Whether the control plane answered with an HTTP error status.
   *
   * @return {@code true} when {@link #statusCode()} is an HTTP status code
   */
  public boolean isHttpError() {
    return statusCode > 0;
  }
}
