import { describe, expect, it } from "vitest";

import {
  CertOneClient,
  CertOneError,
  DEFAULT_POLL_INTERVAL_MS,
  DEFAULT_WAIT_TIMEOUT_MS,
  type FetchLike,
} from "../src/index.node.js";
import { fakeFetch, fixture, hang, json, type RecordedCall } from "./support/fake-fetch.js";

const BASE = "https://api.certone.test";
const SCAN_ID = "64ff3a4afb5e40f5b8ae5e38071c9145";
const scanWith = (status: string, error: string | null = null): unknown => ({
  ...(fixture("scan") as object),
  status,
  error,
  finished_at: status === "succeeded" || status === "failed" ? "2026-11-08T19:43:23.167688" : null,
});

function client(fetch: FetchLike): CertOneClient {
  return new CertOneClient({ baseUrl: BASE, token: "ck_secret", fetch });
}

describe("waitForReport", () => {
  it("uses the SPEC defaults (2 s interval, 900 s deadline)", () => {
    expect(DEFAULT_POLL_INTERVAL_MS).toBe(2_000);
    expect(DEFAULT_WAIT_TIMEOUT_MS).toBe(900_000);
  });

  it("returns at once for a scan that already succeeded", async () => {
    const { fetch, calls } = fakeFetch(
      () => json(scanWith("succeeded")),
      () => json(fixture("report")),
    );
    const report = await client(fetch).waitForReport(SCAN_ID);
    expect(report.id).toBe("88b35a6b07bb456aa5159c32831f6bf4");
    expect(calls.map((c) => c.url)).toEqual([`${BASE}/v1/scans/${SCAN_ID}`, `${BASE}/v1/scans/${SCAN_ID}/report`]);
  });

  it("polls through queued and running until the scan succeeds", async () => {
    const { fetch, calls } = fakeFetch(
      () => json(scanWith("queued")),
      () => json(scanWith("running")),
      () => json(scanWith("running")),
      () => json(scanWith("succeeded")),
      () => json(fixture("report")),
    );
    const started = Date.now();
    const report = await client(fetch).waitForReport(SCAN_ID, { intervalMs: 15 });
    expect(Date.now() - started).toBeGreaterThanOrEqual(40); // three sleeps of 15 ms
    expect(report.verdict_status).toBe("fail");
    expect(calls).toHaveLength(5);
    expect(calls.at(-1)?.url).toBe(`${BASE}/v1/scans/${SCAN_ID}/report`);
  });

  it("raises scan_failed carrying the scan's error", async () => {
    const { fetch, calls } = fakeFetch(
      () => json(scanWith("running")),
      () => json(scanWith("failed", "worker lost: CVM attestation failed")),
    );
    const err = (await client(fetch)
      .waitForReport(SCAN_ID, { intervalMs: 1 })
      .catch((e: unknown) => e)) as CertOneError;
    expect(err).toBeInstanceOf(CertOneError);
    expect(err.kind).toBe("scan_failed");
    expect(err.detail).toBe("worker lost: CVM attestation failed");
    expect(err.scanId).toBe(SCAN_ID);
    expect(err.message).toBe(`scan ${SCAN_ID} failed: worker lost: CVM attestation failed`);
    expect(calls).toHaveLength(2); // never asks for a report of a failed scan
  });

  it("raises scan_failed for a failed scan without an error message", async () => {
    const { fetch } = fakeFetch(() => json(scanWith("failed")));
    const err = (await client(fetch).waitForReport(SCAN_ID).catch((e: unknown) => e)) as CertOneError;
    expect(err.kind).toBe("scan_failed");
    expect(err.detail).toBe("the scan failed without an error message");
  });

  it("times out when the scan never finishes", async () => {
    const { fetch, calls } = fakeFetch(() => json(scanWith("running")));
    const err = (await client(fetch)
      .waitForReport(SCAN_ID, { timeoutMs: 60, intervalMs: 10 })
      .catch((e: unknown) => e)) as CertOneError;
    expect(err.kind).toBe("timeout");
    expect(err.scanId).toBe(SCAN_ID);
    expect(err.detail).toBe("last status: running");
    expect(calls.length).toBeGreaterThanOrEqual(3);
  });

  it("bounds each poll by the overall deadline", async () => {
    const { fetch } = fakeFetch(hang);
    const started = Date.now();
    const err = (await client(fetch)
      .waitForReport(SCAN_ID, { timeoutMs: 40, requestTimeoutMs: 60_000 })
      .catch((e: unknown) => e)) as CertOneError;
    expect(err.kind).toBe("timeout");
    expect(Date.now() - started).toBeLessThan(5_000);
  });

  it("can be cancelled while sleeping between polls", async () => {
    const { fetch, calls } = fakeFetch(() => json(scanWith("running")));
    const controller = new AbortController();
    const pending = client(fetch).waitForReport(SCAN_ID, { intervalMs: 60_000, signal: controller.signal });
    setTimeout(() => controller.abort(), 20);
    const err = (await pending.catch((e: unknown) => e)) as CertOneError;
    expect(err.kind).toBe("aborted");
    expect(calls).toHaveLength(1);
  });

  it("can be cancelled during a poll request", async () => {
    const { fetch, calls } = fakeFetch(hang);
    const controller = new AbortController();
    const pending = client(fetch).waitForReport(SCAN_ID, { signal: controller.signal });
    setTimeout(() => controller.abort(), 10);
    const err = (await pending.catch((e: unknown) => e)) as CertOneError;
    expect(err.kind).toBe("aborted");
    expect((calls[0] as RecordedCall).signal?.aborted).toBe(true);
  });

  it("propagates HTTP errors from polling", async () => {
    const { fetch } = fakeFetch(() => json({ detail: "scan not found" }, 404));
    const err = (await client(fetch).waitForReport("nope").catch((e: unknown) => e)) as CertOneError;
    expect(err.kind).toBe("http");
    expect(err.status).toBe(404);
  });

  it("validates its options", async () => {
    const { fetch, calls } = fakeFetch(() => json(scanWith("running")));
    const c = client(fetch);
    await expect(c.waitForReport(SCAN_ID, { timeoutMs: 0 })).rejects.toThrow(RangeError);
    await expect(c.waitForReport(SCAN_ID, { intervalMs: -5 })).rejects.toThrow(RangeError);
    await expect(c.waitForReport("")).rejects.toThrow(TypeError);
    expect(calls).toHaveLength(0);
  });
});
