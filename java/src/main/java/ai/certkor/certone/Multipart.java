package ai.certkor.certone;

import java.io.FileNotFoundException;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublisher;
import java.net.http.HttpRequest.BodyPublishers;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

/**
 * A {@code multipart/form-data} request body (RFC 7578). File parts backed by a {@link Path} are
 * streamed from disk, so large snapshots are never held in memory. Single use; not thread-safe.
 */
final class Multipart {

  private static final SecureRandom RANDOM = new SecureRandom();
  private static final String CRLF = "\r\n";

  private final String boundary;
  private final List<BodyPublisher> parts = new ArrayList<>();

  Multipart() {
    byte[] nonce = new byte[16];
    RANDOM.nextBytes(nonce);
    this.boundary = "certone-" + HexFormat.of().formatHex(nonce);
  }

  /** The boundary delimiting the parts. */
  String boundary() {
    return boundary;
  }

  /** The {@code Content-Type} header value of the body. */
  String contentType() {
    return "multipart/form-data; boundary=" + boundary;
  }

  /** Adds text fields in iteration order. */
  Multipart fields(Map<String, String> fields) {
    fields.forEach(this::field);
    return this;
  }

  /** Adds a text field (UTF-8). */
  Multipart field(String name, String value) {
    text(
        "--" + boundary + CRLF
            + "Content-Disposition: form-data; name=\"" + quote(name) + "\"" + CRLF
            + CRLF
            + value + CRLF);
    return this;
  }

  /**
   * Adds a file part streamed from disk.
   *
   * @throws FileNotFoundException when the file does not exist or is not readable
   */
  Multipart file(String name, String filename, String contentType, Path file)
      throws FileNotFoundException {
    BodyPublisher content = BodyPublishers.ofFile(file);
    fileHeader(name, filename, contentType);
    parts.add(content);
    text(CRLF);
    return this;
  }

  /** Adds a file part from memory. */
  Multipart file(String name, String filename, String contentType, byte[] content) {
    fileHeader(name, filename, contentType);
    parts.add(BodyPublishers.ofByteArray(content));
    text(CRLF);
    return this;
  }

  /** Closes the body and returns its publisher; the content length is known up front. */
  HttpRequest.BodyPublisher build() {
    text("--" + boundary + "--" + CRLF);
    return BodyPublishers.concat(parts.toArray(BodyPublisher[]::new));
  }

  private void fileHeader(String name, String filename, String contentType) {
    text(
        "--" + boundary + CRLF
            + "Content-Disposition: form-data; name=\"" + quote(name) + "\"; filename=\""
            + quote(filename) + "\"" + CRLF
            + "Content-Type: " + contentType + CRLF
            + CRLF);
  }

  private void text(String text) {
    parts.add(BodyPublishers.ofByteArray(text.getBytes(StandardCharsets.UTF_8)));
  }

  /**
   * Escapes a name or filename for a quoted {@code Content-Disposition} parameter, as browsers do
   * (WHATWG HTML form submission): {@code "} becomes {@code %22}, CR {@code %0D}, LF {@code %0A}.
   */
  static String quote(String value) {
    return value.replace("\"", "%22").replace("\r", "%0D").replace("\n", "%0A");
  }
}
