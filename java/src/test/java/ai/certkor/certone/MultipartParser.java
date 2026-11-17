package ai.certkor.certone;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** A strict RFC 7578 parser used to verify what the SDK puts on the wire. */
final class MultipartParser {

  private static final Pattern NAME = Pattern.compile("(?:^|;)\\s*name=\"([^\"]*)\"");
  private static final Pattern FILENAME = Pattern.compile(";\\s*filename=\"([^\"]*)\"");

  private MultipartParser() {}

  /** One part of a form. */
  record Part(String name, String filename, String contentType, byte[] content) {
    String text() {
      return new String(content, StandardCharsets.UTF_8);
    }
  }

  /** A parsed form, parts in wire order. */
  record Form(List<Part> parts) {
    List<String> names() {
      return parts.stream().map(Part::name).toList();
    }

    Part part(String name) {
      return parts.stream()
          .filter(p -> p.name().equals(name))
          .findFirst()
          .orElseThrow(() -> new AssertionError("no part " + name + " in " + names()));
    }

    String text(String name) {
      return part(name).text();
    }
  }

  static Form parse(StubServer.Recorded request) {
    String contentType = request.header("Content-Type");
    if (contentType == null || !contentType.startsWith("multipart/form-data; boundary=")) {
      throw new AssertionError("not multipart/form-data: " + contentType);
    }
    String boundary = contentType.substring("multipart/form-data; boundary=".length());
    return parse(request.body(), boundary);
  }

  static Form parse(byte[] body, String boundary) {
    byte[] delimiter = ("--" + boundary).getBytes(StandardCharsets.US_ASCII);
    byte[] next = ("\r\n--" + boundary).getBytes(StandardCharsets.US_ASCII);
    if (indexOf(body, delimiter, 0) != 0) {
      throw new AssertionError("body does not start with the boundary");
    }
    byte[] closing = ("--" + boundary + "--\r\n").getBytes(StandardCharsets.US_ASCII);
    if (!Arrays.equals(
        Arrays.copyOfRange(body, body.length - closing.length, body.length), closing)) {
      throw new AssertionError("body does not end with the closing boundary");
    }
    List<Part> parts = new ArrayList<>();
    int position = delimiter.length;
    while (true) {
      if (body[position] == '-' && body[position + 1] == '-') {
        return new Form(parts);
      }
      expect(body, position, "\r\n");
      int headersStart = position + 2;
      int headersEnd = indexOf(body, "\r\n\r\n".getBytes(StandardCharsets.US_ASCII), headersStart);
      Map<String, String> headers = new LinkedHashMap<>();
      String rawHeaders =
          new String(body, headersStart, headersEnd - headersStart, StandardCharsets.UTF_8);
      for (String line : rawHeaders.split("\r\n")) {
        int colon = line.indexOf(':');
        headers.put(line.substring(0, colon).strip().toLowerCase(Locale.ROOT),
            line.substring(colon + 1).strip());
      }
      int contentStart = headersEnd + 4;
      int contentEnd = indexOf(body, next, contentStart);
      if (contentEnd < 0) {
        throw new AssertionError("unterminated part");
      }
      String disposition = headers.get("content-disposition");
      if (disposition == null || !disposition.startsWith("form-data")) {
        throw new AssertionError("bad Content-Disposition: " + disposition);
      }
      Matcher name = NAME.matcher(disposition);
      if (!name.find()) {
        throw new AssertionError("no name in " + disposition);
      }
      Matcher filename = FILENAME.matcher(disposition);
      parts.add(
          new Part(
              name.group(1),
              filename.find() ? filename.group(1) : null,
              headers.get("content-type"),
              Arrays.copyOfRange(body, contentStart, contentEnd)));
      position = contentEnd + next.length;
    }
  }

  private static void expect(byte[] body, int at, String text) {
    byte[] expected = text.getBytes(StandardCharsets.US_ASCII);
    if (!Arrays.equals(Arrays.copyOfRange(body, at, at + expected.length), expected)) {
      throw new AssertionError("expected " + text.replace("\r\n", "CRLF") + " at " + at);
    }
  }

  private static int indexOf(byte[] haystack, byte[] needle, int from) {
    outer:
    for (int i = from; i <= haystack.length - needle.length; i++) {
      for (int j = 0; j < needle.length; j++) {
        if (haystack[i + j] != needle[j]) {
          continue outer;
        }
      }
      return i;
    }
    return -1;
  }
}
