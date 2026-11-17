import { inspect } from "node:util";

import { describe, expect, it } from "vitest";

import { CertOneClient, CertOneError, DEFAULT_TIMEOUT_MS, type FetchLike } from "../src/index.node.js";
import { fakeFetch, fixture, json, type RecordedCall } from "./support/fake-fetch.js";

const BASE = "https://api.certone.test";
const TOKEN = "ck_test_0123456789abcdef";
const SNAPSHOT = new Uint8Array([0x1f, 0x8b, 0x08, 0x00, 0xde, 0xad, 0xbe, 0xef]);

function client(fetch: FetchLike, extra: Partial<ConstructorParameters<typeof CertOneClient>[0]> = {}): CertOneClient {
  return new CertOneClient({ baseUrl: BASE, token: TOKEN, fetch, ...extra });
}

function formOf(call: RecordedCall): FormData {
  expect(call.body).toBeInstanceOf(FormData);
  return call.body as FormData;
}

function fields(form: FormData): Record<string, string> {
  const out: Record<string, string> = {};
  form.forEach((value, key) => {
    if (typeof value === "string") out[key] = value;
  });
  return out;
}

async function snapshotPart(form: FormData): Promise<{ name: string; bytes: number[] }> {
  const part = form.get("snapshot");
  expect(part).toBeInstanceOf(Blob);
  const blob = part as File;
  return { name: blob.name, bytes: [...new Uint8Array(await blob.arrayBuffer())] };
}

describe("CertOneClient construction", () => {
  it("normalises the base URL and exposes the default timeout", () => {
    const c = new CertOneClient({ baseUrl: "https://api.certone.test/prefix///" });
    expect(c.baseUrl).toBe("https://api.certone.test/prefix");
    expect(c.timeoutMs).toBe(DEFAULT_TIMEOUT_MS);
    expect(DEFAULT_TIMEOUT_MS).toBe(30_000);
  });

  it("rejects invalid configuration", () => {
    expect(() => new CertOneClient({ baseUrl: "not a url" })).toThrow(TypeError);
    expect(() => new CertOneClient({ baseUrl: "ftp://api.certone.test" })).toThrow(/http\(s\)/);
    expect(() => new CertOneClient({ baseUrl: "https://user:pw@api.certone.test" })).toThrow(/credentials/);
    expect(() => new CertOneClient({ baseUrl: "https://api.certone.test/?x=1" })).toThrow(/query/);
    expect(() => new CertOneClient({ baseUrl: BASE, token: "" })).toThrow(/empty/);
    expect(() => new CertOneClient({ baseUrl: BASE, timeoutMs: 0 })).toThrow(RangeError);
    expect(() => new CertOneClient({ baseUrl: BASE, timeoutMs: Number.NaN })).toThrow(RangeError);
    expect(() => new CertOneClient({ baseUrl: BASE, headers: { Authorization: "Bearer x" } })).toThrow(/token/);
    // @ts-expect-error -- runtime guard for JavaScript callers
    expect(() => new CertOneClient(undefined)).toThrow(/baseUrl/);
  });

  it("never exposes the token through JSON, inspection or enumeration", () => {
    const c = new CertOneClient({ baseUrl: BASE, token: TOKEN });
    expect(JSON.stringify(c)).not.toContain(TOKEN);
    expect(inspect(c, { depth: 5, showHidden: true })).not.toContain(TOKEN);
    expect(Object.values(c).join(" ")).not.toContain(TOKEN);
  });
});

describe("submitCheck", () => {
  it("posts a multipart snapshot with the mapped scan options", async () => {
    const { fetch, calls } = fakeFetch(() => json(fixture("check_result"), 201));
    const result = await client(fetch).submitCheck(SNAPSHOT, {
      asset: "JavaScript SDK quickstart",
      environment: "ci",
      countryCode: "EU",
      failOn: "medium",
      packs: ["eu-ai-act-core", "iso-42001-core"],
      snapshotRef: "git:acme/fraud@abc123",
      commitHash: "abc123",
      filename: "project.tar.gz",
    });

    expect(result.report?.verdict_status).toBe("fail");
    expect(calls).toHaveLength(1);
    const [call] = calls as [RecordedCall];
    expect(call.method).toBe("POST");
    expect(call.url).toBe(`${BASE}/v1/checks`);
    expect(call.headers["authorization"]).toBe(`Bearer ${TOKEN}`);
    expect(call.headers["accept"]).toBe("application/json");
    // fetch must derive the multipart content-type (with boundary) itself
    expect(call.headers["content-type"]).toBeUndefined();

    const form = formOf(call);
    expect(fields(form)).toEqual({
      asset: "JavaScript SDK quickstart",
      environment: "ci",
      country_code: "EU",
      fail_on: "medium",
      packs: "eu-ai-act-core,iso-42001-core",
      snapshot_ref: "git:acme/fraud@abc123",
      commit_hash: "abc123",
    });
    expect(form.has("tee")).toBe(false);
    expect(await snapshotPart(form)).toEqual({ name: "project.tar.gz", bytes: [...SNAPSHOT] });
  });

  it("omits unset options so the server defaults apply", async () => {
    const { fetch, calls } = fakeFetch(() => json(fixture("check_result"), 201));
    await client(fetch).submitCheck(SNAPSHOT);
    const form = formOf(calls[0] as RecordedCall);
    expect(fields(form)).toEqual({});
    expect((await snapshotPart(form)).name).toBe("snapshot.tar.gz");
  });

  it("passes a comma-separated packs string through unchanged", async () => {
    const { fetch, calls } = fakeFetch(() => json(fixture("check_result"), 201));
    await client(fetch).submitCheck(SNAPSHOT, { packs: "eu-ai-act-core" });
    expect(fields(formOf(calls[0] as RecordedCall))["packs"]).toBe("eu-ai-act-core");
  });

  it.each([
    ["Uint8Array", () => SNAPSHOT],
    ["ArrayBuffer", () => SNAPSHOT.slice().buffer],
    ["Buffer", () => Buffer.from(SNAPSHOT)],
    ["Blob", () => new Blob([SNAPSHOT])],
    ["offset view", () => new Uint8Array([9, 9, ...SNAPSHOT, 9]).subarray(2, 2 + SNAPSHOT.length)],
    ["DataView", () => new DataView(SNAPSHOT.slice().buffer)],
  ] as const)("accepts a %s snapshot", async (_label, make) => {
    const { fetch, calls } = fakeFetch(() => json(fixture("check_result"), 201));
    await client(fetch).submitCheck(make());
    expect((await snapshotPart(formOf(calls[0] as RecordedCall))).bytes).toEqual([...SNAPSHOT]);
  });

  it("rejects a snapshot that is not binary", async () => {
    const { fetch, calls } = fakeFetch(() => json(fixture("check_result"), 201));
    // @ts-expect-error -- runtime guard for JavaScript callers
    await expect(client(fetch).submitCheck("not bytes")).rejects.toThrow(TypeError);
    expect(calls).toHaveLength(0);
  });
});

describe("submitProcess", () => {
  it("posts to /v1/process with the tee field and returns job telemetry", async () => {
    const body = { ...(fixture("check_result") as object), jobs: { static: 1, dynamic: 1 }, health: { ok: true } };
    const { fetch, calls } = fakeFetch(() => json(body, 201));
    const result = await client(fetch).submitProcess(SNAPSHOT, { tee: "intel_tdx", asset: "Fraud Scorer" });
    const call = calls[0] as RecordedCall;
    expect(call.url).toBe(`${BASE}/v1/process`);
    expect(fields(formOf(call))).toEqual({ asset: "Fraud Scorer", tee: "intel_tdx" });
    expect(result.jobs).toEqual({ static: 1, dynamic: 1 });
  });

  it("surfaces a queued submission (confidential worker pool)", async () => {
    const queued = { scan_run: { ...(fixture("scan") as object), status: "queued", finished_at: null }, report: null, queued: true };
    const { fetch } = fakeFetch(() => json(queued, 201));
    const result = await client(fetch).submitProcess(SNAPSHOT);
    expect(result.queued).toBe(true);
    expect(result.report).toBeNull();
    expect(result.scan_run.status).toBe("queued");
  });
});

describe("reads", () => {
  it("getScan encodes the id into the path", async () => {
    const { fetch, calls } = fakeFetch(() => json(fixture("scan")));
    const scan = await client(fetch).getScan("a/b c");
    expect(calls[0]?.url).toBe(`${BASE}/v1/scans/a%2Fb%20c`);
    expect(calls[0]?.method).toBe("GET");
    expect(calls[0]?.body).toBeNull();
    expect(scan.status).toBe("succeeded");
  });

  it("getReportDocument and getAttestation use the report record id", async () => {
    const { fetch, calls } = fakeFetch(
      () => json(fixture("report_document_excerpt")),
      () => json(fixture("attestation")),
    );
    const c = client(fetch);
    const doc = await c.getReportDocument("88b35a6b07bb456aa5159c32831f6bf4");
    const att = await c.getAttestation("041376f586ae4f1d9d54f529f5f3e9ba");
    expect(calls.map((x) => x.url)).toEqual([
      `${BASE}/v1/reports/88b35a6b07bb456aa5159c32831f6bf4/document`,
      `${BASE}/v1/reports/041376f586ae4f1d9d54f529f5f3e9ba/attestation`,
    ]);
    expect(doc.issues[0]?.severity).toBe("high");
    expect(att.signature_algorithm).toBe("HMAC-SHA256");
  });

  it("listSystems returns the inventory", async () => {
    const { fetch, calls } = fakeFetch(() => json(fixture("systems")));
    const systems = await client(fetch).listSystems();
    expect(calls[0]?.url).toBe(`${BASE}/v1/systems`);
    expect(systems.map((s) => s.slug)).toEqual(["sdk-edge-model", "sdk-sample", "default"]);
  });

  it("rejects empty ids before sending anything", async () => {
    const { fetch, calls } = fakeFetch(() => json(fixture("scan")));
    await expect(client(fetch).getScan("")).rejects.toThrow(TypeError);
    await expect(client(fetch).getAttestation("  ")).rejects.toThrow(TypeError);
    expect(calls).toHaveLength(0);
  });
});

describe("ingestReport", () => {
  const report = { report_id: "rat-sdk-0001", verdict: { status: "pass", fail_on: "high" }, issues: [] };

  it("posts the run-at-source body as snake_case JSON", async () => {
    const { fetch, calls } = fakeFetch(() => json(fixture("ingest_result"), 201));
    const result = await client(fetch).ingestReport(report, {
      asset: "Fraud Scorer",
      environment: "edge",
      countryCode: "EU",
      snapshotRef: "git:org/repo@sha",
      inputDigest: `sha256:${"a".repeat(64)}`,
      repo: "org/repo",
      commitHash: "sha",
    });
    const call = calls[0] as RecordedCall;
    expect(call.method).toBe("POST");
    expect(call.url).toBe(`${BASE}/v1/checks/report`);
    expect(call.headers["content-type"]).toBe("application/json");
    expect(JSON.parse(call.body as string)).toEqual({
      report,
      asset: "Fraud Scorer",
      environment: "edge",
      country_code: "EU",
      snapshot_ref: "git:org/repo@sha",
      input_digest: `sha256:${"a".repeat(64)}`,
      repo: "org/repo",
      commit_hash: "sha",
    });
    expect(result.report?.verdict_status).toBe("pass");
  });

  it("leaves unset fields out of the body", async () => {
    const { fetch, calls } = fakeFetch(() => json(fixture("ingest_result"), 201));
    await client(fetch).ingestReport(report);
    expect(JSON.parse(calls[0]?.body as string)).toEqual({ report });
  });

  it("rejects a report that is not a JSON object", async () => {
    const { fetch, calls } = fakeFetch(() => json(fixture("ingest_result"), 201));
    // @ts-expect-error -- runtime guard for JavaScript callers
    await expect(client(fetch).ingestReport([])).rejects.toThrow(TypeError);
    // @ts-expect-error -- runtime guard for JavaScript callers
    await expect(client(fetch).ingestReport(null)).rejects.toThrow(TypeError);
    expect(calls).toHaveLength(0);
  });
});

describe("authentication and headers", () => {
  it("sends no authorization header without a token", async () => {
    const { fetch, calls } = fakeFetch(() => json(fixture("systems")));
    await new CertOneClient({ baseUrl: BASE, fetch }).listSystems();
    expect(calls[0]?.headers["authorization"]).toBeUndefined();
  });

  it("calls a token provider on every request (refreshable OIDC tokens)", async () => {
    let n = 0;
    const { fetch, calls } = fakeFetch(() => json(fixture("systems")));
    const c = new CertOneClient({ baseUrl: BASE, fetch, token: async () => `oidc-${++n}` });
    await c.listSystems();
    await c.listSystems();
    expect(calls.map((x) => x.headers["authorization"])).toEqual(["Bearer oidc-1", "Bearer oidc-2"]);
  });

  it("rejects tokens with whitespace or control characters without echoing them", async () => {
    const leaked = (fn: () => unknown): string => {
      try {
        fn();
      } catch (err) {
        expect(err).toBeInstanceOf(TypeError);
        return (err as Error).message;
      }
      throw new Error("expected a TypeError");
    };
    for (const bad of [`${TOKEN}\r`, `${TOKEN}\n`, ` ${TOKEN}`, "ck_a b", "ck_é"]) {
      expect(leaked(() => new CertOneClient({ baseUrl: BASE, token: bad }))).not.toContain(TOKEN);
    }
    const { fetch, calls } = fakeFetch(() => json(fixture("systems")));
    const c = new CertOneClient({ baseUrl: BASE, fetch, token: () => `${TOKEN}\r\n` });
    const err = (await c.listSystems().catch((e: unknown) => e)) as Error;
    expect(err).toBeInstanceOf(TypeError);
    expect(err.message).toMatch(/carriage return/);
    expect(err.message).not.toContain(TOKEN);
    expect(calls).toHaveLength(0);
    expect(() => new CertOneClient({ baseUrl: BASE, headers: { "x-trace": "a\r\nb" } })).toThrow(/line break/);
  });

  it("rejects an empty token from the provider without sending the request", async () => {
    const { fetch, calls } = fakeFetch(() => json(fixture("systems")));
    const c = new CertOneClient({ baseUrl: BASE, fetch, token: () => "" });
    await expect(c.listSystems()).rejects.toThrow(/non-empty/);
    expect(calls).toHaveLength(0);
  });

  it("adds configured extra headers", async () => {
    const { fetch, calls } = fakeFetch(() => json(fixture("systems")));
    await client(fetch, { headers: { "X-Request-Id": "req-1" } }).listSystems();
    expect(calls[0]?.headers["x-request-id"]).toBe("req-1");
    expect(calls[0]?.headers["authorization"]).toBe(`Bearer ${TOKEN}`);
  });

  it("uses the global fetch when none is injected", async () => {
    const original = globalThis.fetch;
    const { fetch, calls } = fakeFetch(() => json(fixture("systems")));
    globalThis.fetch = ((input: string, init: RequestInit) => fetch(input, init)) as typeof globalThis.fetch;
    try {
      await new CertOneClient({ baseUrl: BASE }).listSystems();
    } finally {
      globalThis.fetch = original;
    }
    expect(calls).toHaveLength(1);
  });
});

describe("errors never leak the token", () => {
  it("keeps the token out of every error field", async () => {
    const { fetch } = fakeFetch(() => json({ detail: "invalid credentials" }, 401));
    const err = (await client(fetch).listSystems().catch((e: unknown) => e)) as CertOneError;
    expect(err.status).toBe(401);
    const everything = [err.message, err.detail, err.url, String(err.stack), JSON.stringify(err.responseBody)].join("\n");
    expect(everything).not.toContain(TOKEN);
  });
});

