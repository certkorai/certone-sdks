import { describe, expect, it } from "vitest";

import { CertOneClient, CertOneError, type CertOneErrorKind, type FetchLike } from "../src/index.node.js";
import { fakeFetch, fixture, hang, json, stalledBody, text } from "./support/fake-fetch.js";

const BASE = "https://api.certone.test";

function client(fetch: FetchLike, timeoutMs?: number): CertOneClient {
  return new CertOneClient({ baseUrl: BASE, token: "ck_secret", fetch, timeoutMs });
}

async function failure(promise: Promise<unknown>, kind: CertOneErrorKind): Promise<CertOneError> {
  const err = await promise.then(
    () => {
      throw new Error("expected the call to reject");
    },
    (e: unknown) => e,
  );
  expect(err).toBeInstanceOf(CertOneError);
  expect(err).toBeInstanceOf(Error);
  const e = err as CertOneError;
  expect(e.name).toBe("CertOneError");
  expect(e.kind).toBe(kind);
  return e;
}

describe("HTTP error mapping (status >= 400)", () => {
  it("maps a FastAPI string detail", async () => {
    const { fetch } = fakeFetch(() => json({ detail: "scan not found" }, 404));
    const e = await failure(client(fetch).getScan("missing"), "http");
    expect(e.status).toBe(404);
    expect(e.detail).toBe("scan not found");
    expect(e.message).toBe("HTTP 404: scan not found");
    expect(e.method).toBe("GET");
    expect(e.url).toBe(`${BASE}/v1/scans/missing`);
    expect(e.responseBody).toEqual({ detail: "scan not found" });
  });

  it("maps the 404 for a report without an attestation", async () => {
    const detail = "no attestation (the input did not pass, so none was issued)";
    const { fetch } = fakeFetch(() => json({ detail }, 404));
    const e = await failure(client(fetch).getAttestation("88b35a6b07bb456aa5159c32831f6bf4"), "http");
    expect(e.status).toBe(404);
    expect(e.detail).toBe(detail);
  });

  it("flattens FastAPI validation errors (422)", async () => {
    const body = {
      detail: [
        { type: "missing", loc: ["body", "snapshot"], msg: "Field required", input: null },
        { type: "string_type", loc: ["body", "asset"], msg: "Input should be a valid string" },
      ],
    };
    const { fetch } = fakeFetch(() => json(body, 422));
    const e = await failure(client(fetch).submitCheck(new Uint8Array([1])), "http");
    expect(e.status).toBe(422);
    expect(e.detail).toBe("body.snapshot: Field required; body.asset: Input should be a valid string");
  });

  it("maps a 400 business-rule error", async () => {
    const { fetch } = fakeFetch(() => json({ detail: "fail_on must be low|medium|high|none" }, 400));
    // @ts-expect-error -- a JavaScript caller passing an unsupported value; the server decides
    const e = await failure(client(fetch).submitCheck(new Uint8Array([1]), { failOn: "critical" }), "http");
    expect(e.detail).toBe("fail_on must be low|medium|high|none");
  });

  it("serialises a structured (non-string) detail", async () => {
    const { fetch } = fakeFetch(() => json({ detail: { code: "quota", limit: 10 } }, 429));
    const e = await failure(client(fetch).listSystems(), "http");
    expect(e.detail).toBe('{"code":"quota","limit":10}');
  });

  it("uses the raw text of a non-JSON error body (proxy / load balancer)", async () => {
    const { fetch } = fakeFetch(() => text("<html><body>502 Bad Gateway</body></html>", 502, "text/html"));
    const e = await failure(client(fetch).listSystems(), "http");
    expect(e.status).toBe(502);
    expect(e.detail).toBe("<html><body>502 Bad Gateway</body></html>");
    expect(e.responseBody).toBe("<html><body>502 Bad Gateway</body></html>");
  });

  it("handles an empty error body", async () => {
    const { fetch } = fakeFetch(() => new Response(null, { status: 503 }));
    const e = await failure(client(fetch).listSystems(), "http");
    expect(e.status).toBe(503);
    expect(e.detail).toBe("");
    expect(e.message).toBe("HTTP 503");
  });

  it("truncates a huge error body", async () => {
    const { fetch } = fakeFetch(() => text("x".repeat(10_000), 500));
    const e = await failure(client(fetch).listSystems(), "http");
    expect(e.detail.length).toBeLessThanOrEqual(2001);
  });
});

describe("invalid 2xx responses", () => {
  it("rejects a body that is not JSON", async () => {
    const { fetch } = fakeFetch(() => text("<html>login page</html>", 200, "text/html"));
    const e = await failure(client(fetch).listSystems(), "invalid_response");
    expect(e.status).toBe(200);
    expect(e.responseBody).toBe("<html>login page</html>");
  });

  it("rejects JSON of the wrong shape with the request context", async () => {
    const { fetch } = fakeFetch(() => json({ ...(fixture("scan") as object), status: 3 }));
    const e = await failure(client(fetch).getScan("s1"), "invalid_response");
    expect(e.detail).toBe("body.status must be a string");
    expect(e.status).toBe(200);
    expect(e.url).toBe(`${BASE}/v1/scans/s1`);
    expect(e.method).toBe("GET");
  });
});

describe("network failures", () => {
  it("wraps a connection error with its system error code", async () => {
    const cause = Object.assign(new Error("connect ECONNREFUSED 127.0.0.1:8088"), { code: "ECONNREFUSED" });
    const fetch: FetchLike = () => Promise.reject(new TypeError("fetch failed", { cause }));
    const e = await failure(client(fetch).listSystems(), "network");
    expect(e.status).toBeNull();
    expect(e.message).toBe(`GET ${BASE}/v1/systems failed: fetch failed (ECONNREFUSED: connect ECONNREFUSED 127.0.0.1:8088)`);
    expect(e.cause).toBeInstanceOf(TypeError);
  });

  it("is recognisable across package copies via CertOneError.is", async () => {
    const fetch: FetchLike = () => Promise.reject(new TypeError("Failed to fetch"));
    const e = await failure(client(fetch).listSystems(), "network");
    expect(CertOneError.is(e)).toBe(true);
    const foreign = Object.assign(new Error("x"), { [Symbol.for("@certkor/certone.CertOneError")]: true });
    expect(CertOneError.is(foreign)).toBe(true);
    expect(CertOneError.is(new Error("x"))).toBe(false);
    expect(CertOneError.is(null)).toBe(false);
  });
});

describe("timeouts", () => {
  it("aborts a request that gets no response within the client timeout", async () => {
    const { fetch, calls } = fakeFetch(hang);
    const started = Date.now();
    const e = await failure(client(fetch, 50).listSystems(), "timeout");
    expect(Date.now() - started).toBeGreaterThanOrEqual(45);
    expect(e.message).toBe(`GET ${BASE}/v1/systems timed out after 50 ms`);
    expect(calls[0]?.signal?.aborted).toBe(true);
  });

  it("applies a per-call timeout override", async () => {
    const { fetch } = fakeFetch(hang);
    const e = await failure(client(fetch, 60_000).getScan("s1", { timeoutMs: 30 }), "timeout");
    expect(e.message).toContain("timed out after 30 ms");
  });

  it("covers a response body that stalls after the headers", async () => {
    const { fetch } = fakeFetch(stalledBody);
    await failure(client(fetch, 50).listSystems(), "timeout");
  });

  it("applies to uploads", async () => {
    const { fetch } = fakeFetch(hang);
    const e = await failure(client(fetch).submitCheck(new Uint8Array([1]), { timeoutMs: 20 }), "timeout");
    expect(e.method).toBe("POST");
  });

  it("validates timeout values", async () => {
    const { fetch } = fakeFetch(() => json(fixture("systems")));
    await expect(client(fetch).listSystems({ timeoutMs: -1 })).rejects.toThrow(RangeError);
  });
});

describe("caller aborts", () => {
  it("does not send a request whose signal is already aborted", async () => {
    const { fetch, calls } = fakeFetch(() => json(fixture("systems")));
    const controller = new AbortController();
    controller.abort(new Error("shutting down"));
    const e = await failure(client(fetch).listSystems({ signal: controller.signal }), "aborted");
    expect(calls).toHaveLength(0);
    expect((e.cause as Error).message).toBe("shutting down");
  });

  it("cancels an in-flight request", async () => {
    const { fetch, calls } = fakeFetch(hang);
    const controller = new AbortController();
    const pending = client(fetch).getScan("s1", { signal: controller.signal });
    setTimeout(() => controller.abort(), 10);
    const e = await failure(pending, "aborted");
    expect(e.message).toBe(`GET ${BASE}/v1/scans/s1 was aborted by the caller`);
    expect(calls[0]?.signal?.aborted).toBe(true);
  });

  it("detaches its abort listener after the request completes", async () => {
    const { fetch } = fakeFetch(() => json(fixture("systems")));
    const controller = new AbortController();
    let added = 0;
    let removed = 0;
    const signal = controller.signal;
    const add = signal.addEventListener.bind(signal);
    const remove = signal.removeEventListener.bind(signal);
    signal.addEventListener = ((...args: Parameters<AbortSignal["addEventListener"]>) => {
      added += 1;
      add(...args);
    }) as AbortSignal["addEventListener"];
    signal.removeEventListener = ((...args: Parameters<AbortSignal["removeEventListener"]>) => {
      removed += 1;
      remove(...args);
    }) as AbortSignal["removeEventListener"];
    await client(fetch).listSystems({ signal });
    expect(added).toBe(1);
    expect(removed).toBe(1);
  });
});
