package ai.certkor.certone;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectReader;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublisher;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.concurrent.TimeoutException;

/**
 * Client of the CertOne control-plane REST API.
 *
 * <p>Instances are immutable and thread-safe; create one per control plane and share it. Every
 * request carries {@code Authorization: Bearer <token>} (a tenant API key {@code ck_...} or an OIDC
 * ID token); the token is never logged or included in exception messages. Every failure surfaces as
 * an unchecked {@link CertOneException}.
 *
 * <pre>{@code
 * CertOneClient client = CertOneClient.builder("https://api.example.com")
 *     .token(System.getenv("CERTONE_API_KEY"))
 *     .build();
 * CheckResult result = client.submitCheck(Path.of("project.tar.gz"),
 *     ScanOptions.builder().asset("Fraud Scorer").failOn(FailOn.HIGH).build());
 * Report report = client.waitForReport(result.scanRun().id());
 * }</pre>
 */
public final class CertOneClient {

  /** Default TCP connect timeout: 5 seconds. */
  public static final Duration DEFAULT_CONNECT_TIMEOUT = Duration.ofSeconds(5);

  /** Default per-request timeout (until the response headers arrive): 30 seconds. */
  public static final Duration DEFAULT_REQUEST_TIMEOUT = Duration.ofSeconds(30);

  /** Default overall timeout of {@link #waitForReport(String)}: 900 seconds. */
  public static final Duration DEFAULT_WAIT_TIMEOUT = Duration.ofSeconds(900);

  /** Default polling interval of {@link #waitForReport(String)}: 2 seconds. */
  public static final Duration DEFAULT_POLL_INTERVAL = Duration.ofSeconds(2);

  /** Version of this SDK. */
  public static final String VERSION = loadVersion();

  private static final String SNAPSHOT_CONTENT_TYPE = "application/gzip";
  private static final String DEFAULT_SNAPSHOT_FILENAME = "snapshot.tar.gz";
  private static final int MAX_ERROR_BODY_CHARS = 2000;

  private static final JsonMapper MAPPER =
      JsonMapper.builder().disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES).build();
  private static final ObjectReader TREE = MAPPER.readerFor(JsonNode.class);
  private static final ObjectReader CHECK_RESULT = MAPPER.readerFor(CheckResult.class);
  private static final ObjectReader SCAN_RUN = MAPPER.readerFor(ScanRun.class);
  private static final ObjectReader REPORT = MAPPER.readerFor(Report.class);
  private static final ObjectReader SYSTEMS =
      MAPPER.readerFor(MAPPER.getTypeFactory().constructCollectionType(List.class, AiSystem.class));

  private final String baseUrl;
  private final String authorization;
  private final HttpClient http;
  private final Duration requestTimeout;
  private final String userAgent;

  private CertOneClient(Builder builder) {
    this.baseUrl = builder.baseUrl;
    this.authorization = builder.token == null ? null : "Bearer " + builder.token;
    this.requestTimeout = builder.requestTimeout;
    this.http =
        builder.httpClient != null
            ? builder.httpClient
            : HttpClient.newBuilder()
                .connectTimeout(builder.connectTimeout)
                .version(HttpClient.Version.HTTP_1_1)
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    this.userAgent =
        "certone-sdk-java/" + VERSION + " (Java " + Runtime.version().feature() + ")";
  }

  /**
   * A builder for a client of the control plane at {@code baseUrl}.
   *
   * @param baseUrl control-plane base URL, for example {@code https://api.example.com}; a path
   *     prefix is kept, a trailing slash is ignored
   * @return the builder
   * @throws IllegalArgumentException when {@code baseUrl} is not an absolute http(s) URL
   */
  public static Builder builder(String baseUrl) {
    return new Builder(baseUrl);
  }

  /**
   * A client with default timeouts.
   *
   * @param baseUrl control-plane base URL
   * @param token API key or OIDC ID token; {@code null} sends no {@code Authorization} header
   * @return the client
   * @throws IllegalArgumentException when {@code baseUrl} or {@code token} is malformed
   */
  public static CertOneClient create(String baseUrl, String token) {
    return builder(baseUrl).token(token).build();
  }

  /**
   * The control-plane base URL, without a trailing slash.
   *
   * @return the base URL
   */
  public String baseUrl() {
    return baseUrl;
  }

  /**
   * The per-request timeout.
   *
   * @return the timeout
   */
  public Duration requestTimeout() {
    return requestTimeout;
  }

  // ---------------------------------------------------------------------------------------------
  // Submissions
  // ---------------------------------------------------------------------------------------------

  /**
   * Submits a project snapshot for a compliance check ({@code POST /v1/checks}). The file is
   * streamed from disk.
   *
   * @param snapshot the project snapshot ({@code .tar.gz})
   * @param options scan options; {@code tee} must not be set (it applies to {@link #submitProcess}
   *     only)
   * @return the scan run and, unless queued, its verdict summary
   * @throws IllegalArgumentException when {@code options} sets {@code tee}
   * @throws CertOneException when the snapshot cannot be read or the call fails
   */
  public CheckResult submitCheck(Path snapshot, ScanOptions options) {
    return submitSnapshot("/v1/checks", fileSnapshot(snapshot), checkFields(options));
  }

  /**
   * Submits a project snapshot for a compliance check with default options.
   *
   * @param snapshot the project snapshot ({@code .tar.gz})
   * @return the scan run and, unless queued, its verdict summary
   * @throws CertOneException when the snapshot cannot be read or the call fails
   */
  public CheckResult submitCheck(Path snapshot) {
    return submitCheck(snapshot, ScanOptions.defaults());
  }

  /**
   * Submits an in-memory project snapshot for a compliance check ({@code POST /v1/checks}).
   *
   * @param snapshot the {@code .tar.gz} bytes
   * @param filename file name reported for the upload, for example {@code project.tar.gz}
   * @param options scan options; {@code tee} must not be set
   * @return the scan run and, unless queued, its verdict summary
   * @throws IllegalArgumentException when {@code options} sets {@code tee}
   * @throws CertOneException when the call fails
   */
  public CheckResult submitCheck(byte[] snapshot, String filename, ScanOptions options) {
    return submitSnapshot("/v1/checks", bytesSnapshot(snapshot, filename), checkFields(options));
  }

  /**
   * Submits a project snapshot to the processing unit ({@code POST /v1/process}): static and
   * dynamic evaluation, on the attested confidential worker pool when the control plane is
   * configured with one (then the result is {@code queued} with no report yet; use {@link
   * #waitForReport(String)}). The file is streamed from disk.
   *
   * @param snapshot the project snapshot ({@code .tar.gz})
   * @param options scan options, including the optional {@code tee} backend
   * @return the scan run and, unless queued, its verdict summary
   * @throws CertOneException when the snapshot cannot be read or the call fails
   */
  public CheckResult submitProcess(Path snapshot, ScanOptions options) {
    return submitSnapshot(
        "/v1/process", fileSnapshot(snapshot), requireOptions(options).formFields(true));
  }

  /**
   * Submits an in-memory project snapshot to the processing unit ({@code POST /v1/process}).
   *
   * @param snapshot the {@code .tar.gz} bytes
   * @param filename file name reported for the upload
   * @param options scan options, including the optional {@code tee} backend
   * @return the scan run and, unless queued, its verdict summary
   * @throws CertOneException when the call fails
   */
  public CheckResult submitProcess(byte[] snapshot, String filename, ScanOptions options) {
    return submitSnapshot(
        "/v1/process", bytesSnapshot(snapshot, filename), requireOptions(options).formFields(true));
  }

  /**
   * Submits an engine report computed where the model lives ({@code POST /v1/checks/report}). The
   * model and code never leave the caller's environment; set {@link
   * IngestOptions.Builder#inputDigest(String)} to bind the attestation to the exact input.
   *
   * @param report the engine report (a JSON object)
   * @param options submission options
   * @return the scan run and its verdict summary
   * @throws IllegalArgumentException when {@code report} is not a JSON object
   * @throws CertOneException when the call fails
   */
  public CheckResult ingestReport(JsonNode report, IngestOptions options) {
    Objects.requireNonNull(report, "report");
    Objects.requireNonNull(options, "options");
    if (!report.isObject()) {
      throw new IllegalArgumentException("report must be a JSON object, got " + report.getNodeType());
    }
    ObjectNode body = MAPPER.createObjectNode();
    body.set("report", report);
    options.bodyFields().forEach(body::put);
    byte[] json;
    try {
      json = MAPPER.writeValueAsBytes(body);
    } catch (JsonProcessingException e) {
      throw new IllegalArgumentException("report cannot be serialized as JSON", e);
    }
    HttpRequest.Builder request =
        HttpRequest.newBuilder()
            .header("Content-Type", "application/json")
            .POST(BodyPublishers.ofByteArray(json));
    return send("POST", "/v1/checks/report", request, CHECK_RESULT);
  }

  /**
   * Reads an engine report from a JSON file and submits it ({@code POST /v1/checks/report}).
   *
   * @param reportJson path of the engine report JSON file
   * @param options submission options
   * @return the scan run and its verdict summary
   * @throws IllegalArgumentException when the file does not contain a JSON object
   * @throws CertOneException when the file cannot be read or the call fails
   */
  public CheckResult ingestReport(Path reportJson, IngestOptions options) {
    Objects.requireNonNull(reportJson, "reportJson");
    JsonNode report;
    try (InputStream in = Files.newInputStream(reportJson)) {
      report = TREE.readValue(in);
    } catch (JsonProcessingException e) {
      throw new IllegalArgumentException(reportJson + " is not valid JSON", e);
    } catch (IOException e) {
      throw new CertOneException(
          "cannot read report " + reportJson + ": " + e, 0, String.valueOf(e.getMessage()), e);
    }
    if (report == null) {
      throw new IllegalArgumentException(reportJson + " is empty");
    }
    return ingestReport(report, options);
  }

  // ---------------------------------------------------------------------------------------------
  // Reads
  // ---------------------------------------------------------------------------------------------

  /**
   * Fetches a scan run ({@code GET /v1/scans/{id}}).
   *
   * @param scanId scan run id
   * @return the scan run
   * @throws CertOneException when the call fails (404 when the scan does not exist)
   */
  public ScanRun getScan(String scanId) {
    return get("/v1/scans/" + segment("scanId", scanId), SCAN_RUN);
  }

  /**
   * Fetches the verdict summary of a finished scan ({@code GET /v1/scans/{id}/report}).
   *
   * @param scanId scan run id
   * @return the report record
   * @throws CertOneException when the call fails (404 when the scan has no report yet)
   */
  public Report getScanReport(String scanId) {
    return get("/v1/scans/" + segment("scanId", scanId) + "/report", REPORT);
  }

  /**
   * Waits for a scan with the default timeout (900 s) and polling interval (2 s), then returns its
   * report.
   *
   * @param scanId scan run id
   * @return the report record
   * @throws ScanFailedException when the scan failed
   * @throws CertOneException when the wait timed out or a call failed
   * @see #waitForReport(String, Duration, Duration)
   */
  public Report waitForReport(String scanId) {
    return waitForReport(scanId, DEFAULT_WAIT_TIMEOUT, DEFAULT_POLL_INTERVAL);
  }

  /**
   * Polls {@code GET /v1/scans/{id}} until the scan is {@code succeeded} or {@code failed}, then
   * fetches its report ({@code GET /v1/scans/{id}/report}).
   *
   * <p>Transient failures while polling (network errors, timeouts, HTTP 429/502/503/504) are
   * retried until the deadline; any other error is thrown immediately. The calling thread sleeps
   * between polls; interrupting it aborts the wait with a {@link CertOneException} and keeps the
   * thread's interrupt status set.
   *
   * @param scanId scan run id
   * @param timeout overall deadline (zero polls once)
   * @param interval delay between polls (positive)
   * @return the report record
   * @throws ScanFailedException when the scan failed; {@link ScanFailedException#detail()} is the
   *     scan's {@code error}
   * @throws CertOneException when the deadline passed (cause: {@link TimeoutException}), the
   *     thread was interrupted, or a call failed
   * @throws IllegalArgumentException when {@code timeout} is negative or {@code interval} is not
   *     positive
   */
  public Report waitForReport(String scanId, Duration timeout, Duration interval) {
    String id = segment("scanId", scanId);
    Objects.requireNonNull(timeout, "timeout");
    Objects.requireNonNull(interval, "interval");
    if (timeout.isNegative()) {
      throw new IllegalArgumentException("timeout must not be negative: " + timeout);
    }
    if (interval.isNegative() || interval.isZero()) {
      throw new IllegalArgumentException("interval must be positive: " + interval);
    }
    long deadline = System.nanoTime() + saturatedNanos(timeout);
    String lastStatus = "unknown";
    while (true) {
      try {
        ScanRun scan = get("/v1/scans/" + id, SCAN_RUN);
        lastStatus = scan.status();
        if (scan.isFailed()) {
          throw new ScanFailedException(scan.id(), scan.error());
        }
        if (scan.isSucceeded()) {
          return get("/v1/scans/" + id + "/report", REPORT);
        }
      } catch (ScanFailedException e) {
        throw e;
      } catch (CertOneException e) {
        if (!isTransient(e) || System.nanoTime() - deadline >= 0) {
          throw e;
        }
        lastStatus = "unreachable (" + e.getMessage() + ")";
      }
      long remaining = deadline - System.nanoTime();
      if (remaining <= 0) {
        String message =
            "scan " + scanId + " did not finish within " + timeout + " (last status: "
                + lastStatus + ")";
        throw new CertOneException(message, 0, message, new TimeoutException(message));
      }
      sleep(Math.min(saturatedNanos(interval), remaining), scanId);
    }
  }

  /**
   * Fetches the full engine report ({@code GET /v1/reports/{id}/document}): {@code verdict},
   * {@code summary}, {@code issues[]}, ...
   *
   * @param reportId the report record's {@link Report#id()} (not the engine's {@code report_id})
   * @return the report document
   * @throws CertOneException when the call fails
   */
  public JsonNode getReportDocument(String reportId) {
    return get("/v1/reports/" + segment("reportId", reportId) + "/document", TREE);
  }

  /**
   * Fetches the conditional compliance attestation of a passing report ({@code GET
   * /v1/reports/{id}/attestation}).
   *
   * @param reportId the report record's {@link Report#id()}
   * @return the attestation ({@code attestation_id}, {@code input_version}, {@code signature},
   *     {@code signature_algorithm}, ...)
   * @throws CertOneException when the call fails; status 404 when the verdict did not pass (no
   *     attestation was issued)
   */
  public JsonNode getAttestation(String reportId) {
    return get("/v1/reports/" + segment("reportId", reportId) + "/attestation", TREE);
  }

  /**
   * Lists the tenant's AI systems ({@code GET /v1/systems}).
   *
   * @return the AI systems (unmodifiable)
   * @throws CertOneException when the call fails
   */
  public List<AiSystem> listSystems() {
    List<AiSystem> systems = get("/v1/systems", SYSTEMS);
    return systems == null ? List.of() : List.copyOf(systems);
  }

  @Override
  public String toString() {
    return "CertOneClient[baseUrl="
        + baseUrl
        + ", authorization="
        + (authorization == null ? "none" : "Bearer <redacted>")
        + ", requestTimeout="
        + requestTimeout
        + "]";
  }

  // ---------------------------------------------------------------------------------------------
  // Transport
  // ---------------------------------------------------------------------------------------------

  private record Snapshot(String filename, Path file, byte[] bytes) {}

  private static Snapshot fileSnapshot(Path snapshot) {
    Objects.requireNonNull(snapshot, "snapshot");
    Path name = snapshot.getFileName();
    return new Snapshot(
        name == null ? DEFAULT_SNAPSHOT_FILENAME : name.toString(), snapshot, null);
  }

  private static Snapshot bytesSnapshot(byte[] snapshot, String filename) {
    Objects.requireNonNull(snapshot, "snapshot");
    String name =
        filename == null || filename.isBlank() ? DEFAULT_SNAPSHOT_FILENAME : filename.strip();
    return new Snapshot(name, null, snapshot);
  }

  private static ScanOptions requireOptions(ScanOptions options) {
    return Objects.requireNonNull(options, "options");
  }

  private static Map<String, String> checkFields(ScanOptions options) {
    if (requireOptions(options).tee().isPresent()) {
      throw new IllegalArgumentException(
          "tee applies to submitProcess only; remove it from the submitCheck options");
    }
    return options.formFields(false);
  }

  private CheckResult submitSnapshot(String path, Snapshot snapshot, Map<String, String> fields) {
    Multipart multipart = new Multipart().fields(fields);
    if (snapshot.file() != null) {
      if (!Files.isRegularFile(snapshot.file())) {
        String message = "snapshot is not a readable file: " + snapshot.file();
        throw new CertOneException(message, 0, message, null);
      }
      try {
        multipart.file("snapshot", snapshot.filename(), SNAPSHOT_CONTENT_TYPE, snapshot.file());
      } catch (FileNotFoundException e) {
        String message = "cannot read snapshot " + snapshot.file() + ": " + e.getMessage();
        throw new CertOneException(message, 0, message, e);
      }
    } else {
      multipart.file("snapshot", snapshot.filename(), SNAPSHOT_CONTENT_TYPE, snapshot.bytes());
    }
    HttpRequest.Builder request =
        HttpRequest.newBuilder()
            .header("Content-Type", multipart.contentType())
            .POST(multipart.build());
    return send("POST", path, request, CHECK_RESULT);
  }

  private <T> T get(String path, ObjectReader reader) {
    return send("GET", path, HttpRequest.newBuilder().GET(), reader);
  }

  private <T> T send(String method, String path, HttpRequest.Builder builder, ObjectReader reader) {
    builder
        .uri(URI.create(baseUrl + path))
        .timeout(requestTimeout)
        .header("Accept", "application/json")
        .header("User-Agent", userAgent);
    if (authorization != null) {
      builder.header("Authorization", authorization);
    }
    String call = method + " " + path;
    HttpResponse<byte[]> response;
    try {
      response = http.send(builder.build(), BodyHandlers.ofByteArray());
    } catch (HttpTimeoutException e) {
      String message = call + " timed out: " + e.getMessage();
      throw new CertOneException(message, 0, e.getMessage(), e);
    } catch (IOException e) {
      String reason = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
      throw new CertOneException(call + " failed: " + reason, 0, reason, e);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new CertOneException(call + " interrupted", 0, "interrupted", e);
    }
    int status = response.statusCode();
    byte[] body = response.body() == null ? new byte[0] : response.body();
    if (status < 200 || status >= 300) {
      String detail = errorDetail(body);
      if (detail.isEmpty() && status >= 300 && status < 400) {
        detail =
            "unexpected redirect"
                + response.headers().firstValue("Location").map(l -> " to " + l).orElse("");
      }
      String message = "HTTP " + status + (detail.isEmpty() ? "" : ": " + detail) + " (" + call + ")";
      throw new CertOneException(message, status, detail, null);
    }
    try {
      T value = reader.readValue(body);
      if (value == null) {
        throw new CertOneException(call + " returned an empty body", 0, "empty response", null);
      }
      return value;
    } catch (JsonProcessingException e) {
      String message = call + " returned an undecodable response: " + e.getOriginalMessage();
      throw new CertOneException(message, 0, message, e);
    } catch (IOException e) {
      String message = call + " returned an unreadable response: " + e.getMessage();
      throw new CertOneException(message, 0, message, e);
    }
  }

  /**
   * Extracts the API's {@code detail} from an error body. FastAPI sends {@code {"detail": "..."}};
   * request-validation errors (422) send {@code {"detail": [{"loc": [...], "msg": "..."}]}}, which
   * is rendered as {@code "body.report: Field required; ..."}. A non-JSON body is returned as text.
   */
  static String errorDetail(byte[] body) {
    if (body.length == 0) {
      return "";
    }
    try {
      JsonNode root = TREE.readValue(body);
      if (root != null && root.isObject() && root.has("detail")) {
        JsonNode detail = root.get("detail");
        if (detail.isTextual()) {
          return detail.asText();
        }
        if (detail.isArray()) {
          return validationErrors(detail);
        }
        return detail.isNull() ? "" : detail.toString();
      }
    } catch (IOException e) {
      // Not JSON (for example an HTML error page from a proxy): fall through to the raw text.
    }
    String text = new String(body, StandardCharsets.UTF_8).strip();
    return text.length() <= MAX_ERROR_BODY_CHARS
        ? text
        : text.substring(0, MAX_ERROR_BODY_CHARS) + "...";
  }

  private static String validationErrors(JsonNode errors) {
    List<String> rendered = new ArrayList<>();
    for (JsonNode error : errors) {
      if (error.isObject() && error.hasNonNull("msg")) {
        List<String> location = new ArrayList<>();
        for (JsonNode part : error.path("loc")) {
          location.add(part.asText());
        }
        String msg = error.get("msg").asText();
        rendered.add(location.isEmpty() ? msg : String.join(".", location) + ": " + msg);
      } else {
        rendered.add(error.isTextual() ? error.asText() : error.toString());
      }
    }
    return String.join("; ", rendered);
  }

  private static boolean isTransient(CertOneException e) {
    int status = e.statusCode();
    if (status == 0) {
      return e.getCause() instanceof IOException;
    }
    return status == 429 || status == 502 || status == 503 || status == 504;
  }

  private static void sleep(long nanos, String scanId) {
    try {
      Thread.sleep(nanos / 1_000_000L, (int) (nanos % 1_000_000L));
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      String message = "interrupted while waiting for scan " + scanId;
      throw new CertOneException(message, 0, "interrupted", e);
    }
  }

  private static long saturatedNanos(Duration duration) {
    try {
      return duration.toNanos();
    } catch (ArithmeticException e) {
      return Long.MAX_VALUE / 2;
    }
  }

  private static String segment(String name, String value) {
    Objects.requireNonNull(value, name);
    if (value.isBlank()) {
      throw new IllegalArgumentException(name + " must not be blank");
    }
    return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
  }

  private static String loadVersion() {
    Properties properties = new Properties();
    try (InputStream in = CertOneClient.class.getResourceAsStream("certone-sdk.properties")) {
      if (in != null) {
        properties.load(in);
      }
    } catch (IOException e) {
      return "unknown";
    }
    String version = properties.getProperty("version", "unknown");
    return version.startsWith("${") ? "unknown" : version;
  }

  // ---------------------------------------------------------------------------------------------
  // Builder
  // ---------------------------------------------------------------------------------------------

  /** Builder of {@link CertOneClient}; not thread-safe. */
  public static final class Builder {
    private final String baseUrl;
    private String token;
    private Duration connectTimeout = DEFAULT_CONNECT_TIMEOUT;
    private boolean connectTimeoutSet;
    private Duration requestTimeout = DEFAULT_REQUEST_TIMEOUT;
    private HttpClient httpClient;

    private Builder(String baseUrl) {
      this.baseUrl = normalizeBaseUrl(baseUrl);
    }

    /**
     * Sets the bearer token: a tenant API key ({@code ck_...}) or an OIDC ID token.
     *
     * @param token the token; {@code null} sends no {@code Authorization} header
     * @return this builder
     * @throws IllegalArgumentException when the token is blank or contains whitespace or control
     *     characters
     */
    public Builder token(String token) {
      if (token != null) {
        if (token.isEmpty()) {
          throw new IllegalArgumentException("token must not be empty (pass null for no auth)");
        }
        for (int i = 0; i < token.length(); i++) {
          char c = token.charAt(i);
          if (c <= 0x20 || c >= 0x7f) {
            throw new IllegalArgumentException(
                "token contains whitespace or non-printable characters");
          }
        }
      }
      this.token = token;
      return this;
    }

    /**
     * Sets the TCP connect timeout (default 5 s). Not applicable with {@link
     * #httpClient(HttpClient)}, whose own connect timeout applies.
     *
     * @param connectTimeout positive timeout
     * @return this builder
     * @throws IllegalArgumentException when the timeout is not positive
     */
    public Builder connectTimeout(Duration connectTimeout) {
      this.connectTimeout = positive("connectTimeout", connectTimeout);
      this.connectTimeoutSet = true;
      return this;
    }

    /**
     * Sets the per-request timeout (default 30 s): the maximum time to wait for the response
     * headers of each call.
     *
     * @param requestTimeout positive timeout
     * @return this builder
     * @throws IllegalArgumentException when the timeout is not positive
     */
    public Builder requestTimeout(Duration requestTimeout) {
      this.requestTimeout = positive("requestTimeout", requestTimeout);
      return this;
    }

    /**
     * Uses a caller-configured {@link HttpClient}, for example with a corporate proxy, a custom
     * {@link javax.net.ssl.SSLContext} (private CA, mutual TLS) or an executor. The client should
     * not follow redirects, so the bearer token is never replayed to another host.
     *
     * @param httpClient the HTTP client
     * @return this builder
     */
    public Builder httpClient(HttpClient httpClient) {
      this.httpClient = Objects.requireNonNull(httpClient, "httpClient");
      return this;
    }

    /**
     * Builds the client.
     *
     * @return the client
     * @throws IllegalStateException when both {@link #connectTimeout(Duration)} and {@link
     *     #httpClient(HttpClient)} were set
     */
    public CertOneClient build() {
      if (httpClient != null && connectTimeoutSet) {
        throw new IllegalStateException(
            "connectTimeout cannot be combined with httpClient; configure it on the HttpClient");
      }
      return new CertOneClient(this);
    }

    private static Duration positive(String name, Duration value) {
      Objects.requireNonNull(value, name);
      if (value.isNegative() || value.isZero()) {
        throw new IllegalArgumentException(name + " must be positive: " + value);
      }
      return value;
    }

    private static String normalizeBaseUrl(String baseUrl) {
      Objects.requireNonNull(baseUrl, "baseUrl");
      String trimmed = baseUrl.strip();
      while (trimmed.endsWith("/")) {
        trimmed = trimmed.substring(0, trimmed.length() - 1);
      }
      URI uri;
      try {
        uri = new URI(trimmed);
      } catch (URISyntaxException e) {
        throw new IllegalArgumentException("baseUrl is not a valid URI", e);
      }
      String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
      if (!scheme.equals("http") && !scheme.equals("https")) {
        throw new IllegalArgumentException("baseUrl must be an absolute http(s) URL");
      }
      if (uri.getHost() == null) {
        throw new IllegalArgumentException("baseUrl has no host");
      }
      if (uri.getRawUserInfo() != null || uri.getRawQuery() != null || uri.getRawFragment() != null) {
        throw new IllegalArgumentException(
            "baseUrl must not contain credentials, a query or a fragment");
      }
      return trimmed;
    }
  }
}
