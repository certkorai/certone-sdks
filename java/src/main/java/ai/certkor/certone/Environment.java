package ai.certkor.certone;

import java.util.Locale;

/** The surface a scan was submitted from (the {@code environment} field). */
public enum Environment {
  /** A CI pipeline. */
  CI("ci"),
  /** A Jupyter notebook. */
  JUPYTER("jupyter"),
  /** The VS Code extension. */
  VSCODE("vscode"),
  /** An edge or embedded deployment. */
  EDGE("edge"),
  /** A direct API integration (the control plane's default). */
  API("api"),
  /** A cloud workload. */
  CLOUD("cloud"),
  /** The command line. */
  CLI("cli");

  private final String wireValue;

  Environment(String wireValue) {
    this.wireValue = wireValue;
  }

  /**
   * The value sent to the API.
   *
   * @return the lower-case wire value, for example {@code edge}
   */
  public String wireValue() {
    return wireValue;
  }

  /**
   * Resolves a wire value.
   *
   * @param value wire value, case-insensitive, for example {@code "edge"}
   * @return the environment
   * @throws IllegalArgumentException when {@code value} is not a known environment
   */
  public static Environment fromWireValue(String value) {
    if (value != null) {
      String normalized = value.strip().toLowerCase(Locale.ROOT);
      for (Environment environment : values()) {
        if (environment.wireValue.equals(normalized)) {
          return environment;
        }
      }
    }
    throw new IllegalArgumentException(
        "unknown environment '" + value + "' (expected ci|jupyter|vscode|edge|api|cloud|cli)");
  }

  @Override
  public String toString() {
    return wireValue;
  }
}
