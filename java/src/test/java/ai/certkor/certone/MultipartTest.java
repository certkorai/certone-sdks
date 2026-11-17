package ai.certkor.certone;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.http.HttpRequest.BodyPublisher;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Encoding of the multipart body, independent of any HTTP transport. */
class MultipartTest {

  @Test
  void encodesFieldsAndFileExactly() throws Exception {
    Multipart multipart = new Multipart();
    Map<String, String> fields = new LinkedHashMap<>();
    fields.put("asset", "Fraud Scorer");
    fields.put("country_code", "EU");
    multipart.fields(fields).file("snapshot", "p.tar.gz", "application/gzip", new byte[] {0, 1});
    String boundary = multipart.boundary();

    byte[] body = drain(multipart.build());

    String expected =
        "--" + boundary + "\r\n"
            + "Content-Disposition: form-data; name=\"asset\"\r\n\r\n"
            + "Fraud Scorer\r\n"
            + "--" + boundary + "\r\n"
            + "Content-Disposition: form-data; name=\"country_code\"\r\n\r\n"
            + "EU\r\n"
            + "--" + boundary + "\r\n"
            + "Content-Disposition: form-data; name=\"snapshot\"; filename=\"p.tar.gz\"\r\n"
            + "Content-Type: application/gzip\r\n\r\n"
            + "\u0000\u0001\r\n"
            + "--" + boundary + "--\r\n";
    assertArrayEquals(expected.getBytes(StandardCharsets.ISO_8859_1), body);
    assertEquals("multipart/form-data; boundary=" + boundary, multipart.contentType());
  }

  @Test
  void streamsFilesWithKnownLength(@TempDir Path dir) throws Exception {
    Path file = dir.resolve("big.tar.gz");
    byte[] content = new byte[3 * 1024 * 1024 + 17];
    for (int i = 0; i < content.length; i++) {
      content[i] = (byte) (i * 31);
    }
    Files.write(file, content);
    Multipart multipart = new Multipart().field("fail_on", "high");
    multipart.file("snapshot", "big.tar.gz", "application/gzip", file);

    BodyPublisher publisher = multipart.build();
    byte[] body = drain(publisher);

    assertEquals(body.length, publisher.contentLength());
    MultipartParser.Form form = MultipartParser.parse(body, multipart.boundary());
    assertEquals(List.of("fail_on", "snapshot"), form.names());
    assertArrayEquals(content, form.part("snapshot").content());
  }

  @Test
  void missingFileIsReported(@TempDir Path dir) {
    assertThrows(
        FileNotFoundException.class,
        () -> new Multipart().file("snapshot", "x", "application/gzip", dir.resolve("absent")));
  }

  @Test
  void utf8FieldValuesArePreserved() throws Exception {
    Multipart multipart = new Multipart().field("asset", "Modèle de crédit — 中文");

    MultipartParser.Form form = MultipartParser.parse(drain(multipart.build()), multipart.boundary());

    assertEquals("Modèle de crédit — 中文", form.text("asset"));
  }

  @Test
  void quotedParametersAreEscaped() {
    assertEquals("a%22b%0D%0Ac.tar.gz", Multipart.quote("a\"b\r\nc.tar.gz"));
  }

  @Test
  void boundariesAreRandom() {
    String first = new Multipart().boundary();
    assertNotEquals(first, new Multipart().boundary());
    assertTrue(first.matches("certone-[0-9a-f]{32}"));
  }

  /** Subscribes to a body publisher and collects everything it emits. */
  static byte[] drain(BodyPublisher publisher) throws Exception {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    CompletableFuture<byte[]> done = new CompletableFuture<>();
    publisher.subscribe(
        new Flow.Subscriber<ByteBuffer>() {
          @Override
          public void onSubscribe(Flow.Subscription subscription) {
            subscription.request(Long.MAX_VALUE);
          }

          @Override
          public void onNext(ByteBuffer item) {
            byte[] chunk = new byte[item.remaining()];
            item.get(chunk);
            out.write(chunk, 0, chunk.length);
          }

          @Override
          public void onError(Throwable throwable) {
            done.completeExceptionally(throwable);
          }

          @Override
          public void onComplete() {
            done.complete(out.toByteArray());
          }
        });
    try {
      return done.get(30, TimeUnit.SECONDS);
    } catch (java.util.concurrent.ExecutionException e) {
      throw new IOException(e.getCause());
    }
  }
}
