package ai.certkor.certone;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdScalarDeserializer;
import java.io.IOException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.temporal.TemporalAccessor;

/**
 * Control-plane timestamp parsing. The API emits ISO-8601 date-times both with an offset ({@code
 * 2026-11-08T19:43:23.105333Z}) and without one ({@code 2026-11-08T19:43:23.105333}); the latter
 * are UTC.
 */
final class Timestamps {

  private Timestamps() {}

  /**
   * Parses an API timestamp; a timestamp without an offset is interpreted as UTC.
   *
   * @param text ISO-8601 date-time
   * @return the instant
   * @throws DateTimeParseException when {@code text} is not an ISO-8601 date-time
   */
  static Instant parse(String text) {
    TemporalAccessor parsed =
        DateTimeFormatter.ISO_DATE_TIME.parseBest(
            text.strip(), OffsetDateTime::from, LocalDateTime::from);
    if (parsed instanceof OffsetDateTime offset) {
      return offset.toInstant();
    }
    return ((LocalDateTime) parsed).toInstant(ZoneOffset.UTC);
  }

  /** Jackson deserializer for API timestamps (no {@code jackson-datatype-jsr310} needed). */
  static final class Deserializer extends StdScalarDeserializer<Instant> {

    private static final long serialVersionUID = 1L;

    Deserializer() {
      super(Instant.class);
    }

    @Override
    public Instant deserialize(JsonParser parser, DeserializationContext context)
        throws IOException {
      if (parser.currentToken() != JsonToken.VALUE_STRING) {
        return (Instant) context.handleUnexpectedToken(Instant.class, parser);
      }
      String text = parser.getText();
      if (text.isBlank()) {
        return null;
      }
      try {
        return parse(text);
      } catch (DateTimeParseException e) {
        return (Instant)
            context.handleWeirdStringValue(Instant.class, text, "not an ISO-8601 date-time");
      }
    }
  }
}
