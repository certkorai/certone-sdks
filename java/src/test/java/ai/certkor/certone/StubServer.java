package ai.certkor.certone;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Function;

/** A local HTTP server standing in for the control plane: scripted responses, recorded requests. */
final class StubServer implements AutoCloseable {

  /** A request as received by the stub. */
  record Recorded(String method, String path, Headers headers, byte[] body) {
    String header(String name) {
      return headers.getFirst(name);
    }

    String bodyText() {
      return new String(body, StandardCharsets.UTF_8);
    }
  }

  /** A scripted response. */
  record Response(int status, String contentType, byte[] body, long delayMillis) {
    static Response json(int status, String json) {
      return new Response(status, "application/json", json.getBytes(StandardCharsets.UTF_8), 0);
    }

    static Response text(int status, String contentType, String text) {
      return new Response(status, contentType, text.getBytes(StandardCharsets.UTF_8), 0);
    }

    Response delayed(long millis) {
      return new Response(status, contentType, body, millis);
    }
  }

  private final HttpServer server;
  private final ExecutorService executor = Executors.newCachedThreadPool();
  private final List<Recorded> requests = new CopyOnWriteArrayList<>();
  private final Map<String, Function<Recorded, Response>> routes = new ConcurrentHashMap<>();

  StubServer() throws IOException {
    server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
    server.setExecutor(executor);
    server.createContext("/", this::handle);
    server.start();
  }

  String baseUrl() {
    return "http://127.0.0.1:" + server.getAddress().getPort();
  }

  /** Routes {@code "METHOD /path"} (raw, still-encoded path) to a responder. */
  StubServer on(String methodAndPath, Function<Recorded, Response> responder) {
    routes.put(methodAndPath, responder);
    return this;
  }

  StubServer on(String methodAndPath, Response response) {
    return on(methodAndPath, request -> response);
  }

  /** Serves a fixture file of {@code conformance/fixtures} with status 200. */
  StubServer onFixture(String methodAndPath, String fixture) {
    return on(methodAndPath, Response.json(200, Fixtures.read(fixture)));
  }

  List<Recorded> requests() {
    return Collections.unmodifiableList(new ArrayList<>(requests));
  }

  Recorded onlyRequest() {
    if (requests.size() != 1) {
      throw new AssertionError("expected exactly one request, got " + requests.size());
    }
    return requests.get(0);
  }

  private void handle(HttpExchange exchange) throws IOException {
    try {
      byte[] body;
      try (InputStream in = exchange.getRequestBody()) {
        body = in.readAllBytes();
      }
      String path = exchange.getRequestURI().getRawPath();
      Recorded recorded =
          new Recorded(exchange.getRequestMethod(), path, exchange.getRequestHeaders(), body);
      requests.add(recorded);
      Function<Recorded, Response> responder = routes.get(recorded.method() + " " + path);
      Response response =
          responder == null
              ? Response.json(404, "{\"detail\":\"Not Found\"}")
              : responder.apply(recorded);
      if (response.delayMillis() > 0) {
        try {
          Thread.sleep(response.delayMillis());
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
          return;
        }
      }
      exchange.getResponseHeaders().set("Content-Type", response.contentType());
      exchange.sendResponseHeaders(
          response.status(), response.body().length == 0 ? -1 : response.body().length);
      if (response.body().length > 0) {
        try (OutputStream out = exchange.getResponseBody()) {
          out.write(response.body());
        }
      }
    } catch (IOException e) {
      // The client gave up (for example a timeout test); nothing to answer.
    } finally {
      exchange.close();
    }
  }

  @Override
  public void close() {
    server.stop(0);
    executor.shutdownNow();
  }

  /** Access to the shared conformance fixtures. */
  static final class Fixtures {
    private Fixtures() {}

    static Path dir() {
      return Path.of(System.getProperty("certone.fixtures.dir", "../conformance/fixtures"));
    }

    static String read(String name) {
      try {
        return Files.readString(dir().resolve(name), StandardCharsets.UTF_8);
      } catch (IOException e) {
        throw new AssertionError("missing fixture " + name + " in " + dir().toAbsolutePath(), e);
      }
    }
  }
}
