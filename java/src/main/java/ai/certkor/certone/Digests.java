package ai.certkor.certone;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Objects;

/**
 * Content digests in the form the API expects for {@code input_digest}: {@code sha256:<lower-case
 * hex>}. Compute it over the exact snapshot bytes the report covers so the attestation is bound to
 * that input.
 */
public final class Digests {

  /** Prefix of every digest produced by this class. */
  public static final String SHA256_PREFIX = "sha256:";

  private static final int BUFFER_SIZE = 64 * 1024;

  private Digests() {}

  /**
   * SHA-256 of a byte array.
   *
   * @param data the bytes
   * @return {@code sha256:<hex>}
   */
  public static String sha256(byte[] data) {
    Objects.requireNonNull(data, "data");
    MessageDigest digest = newSha256();
    digest.update(data);
    return SHA256_PREFIX + HexFormat.of().formatHex(digest.digest());
  }

  /**
   * SHA-256 of a file's content, streamed (the file is not loaded into memory).
   *
   * @param file the file
   * @return {@code sha256:<hex>}
   * @throws UncheckedIOException when the file cannot be read
   */
  public static String sha256(Path file) {
    Objects.requireNonNull(file, "file");
    try (InputStream in = Files.newInputStream(file)) {
      return sha256(in);
    } catch (IOException e) {
      throw new UncheckedIOException("cannot read " + file, e);
    }
  }

  /**
   * SHA-256 of everything remaining in a stream. The stream is read to its end but not closed.
   *
   * @param in the stream
   * @return {@code sha256:<hex>}
   * @throws IOException when the stream cannot be read
   */
  public static String sha256(InputStream in) throws IOException {
    Objects.requireNonNull(in, "in");
    MessageDigest digest = newSha256();
    byte[] buffer = new byte[BUFFER_SIZE];
    int read;
    while ((read = in.read(buffer)) != -1) {
      digest.update(buffer, 0, read);
    }
    return SHA256_PREFIX + HexFormat.of().formatHex(digest.digest());
  }

  private static MessageDigest newSha256() {
    try {
      return MessageDigest.getInstance("SHA-256");
    } catch (NoSuchAlgorithmException e) {
      // Every Java SE implementation is required to provide SHA-256.
      throw new IllegalStateException("SHA-256 is not available", e);
    }
  }
}
