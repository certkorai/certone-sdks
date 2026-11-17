package ai.certkor.certone;

import java.util.Locale;

/** Severity threshold at or above which a finding fails the verdict (the {@code fail_on} field). */
public enum FailOn {
  /** Fail on any finding of severity {@code low} or higher. */
  LOW("low"),
  /** Fail on findings of severity {@code medium} or higher. */
  MEDIUM("medium"),
  /** Fail on findings of severity {@code high} (the control plane's default). */
  HIGH("high"),
  /** Never fail the verdict; findings are still reported. */
  NONE("none");

  private final String wireValue;

  FailOn(String wireValue) {
    this.wireValue = wireValue;
  }

  /**
   * The value sent to the API.
   *
   * @return the lower-case wire value, for example {@code high}
   */
  public String wireValue() {
    return wireValue;
  }

  /**
   * Resolves a wire value.
   *
   * @param value wire value, case-insensitive, for example {@code "high"}
   * @return the threshold
   * @throws IllegalArgumentException when {@code value} is not a known threshold
   */
  public static FailOn fromWireValue(String value) {
    if (value != null) {
      String normalized = value.strip().toLowerCase(Locale.ROOT);
      for (FailOn failOn : values()) {
        if (failOn.wireValue.equals(normalized)) {
          return failOn;
        }
      }
    }
    throw new IllegalArgumentException(
        "unknown fail_on '" + value + "' (expected low|medium|high|none)");
  }

  @Override
  public String toString() {
    return wireValue;
  }
}
