import { toBlob } from "./binary.js";
import { CertOneError, extractDetail } from "./errors.js";
import type {
  AISystem,
  Attestation,
  BinaryInput,
  CertOneClientOptions,
  CheckResult,
  FetchLike,
  IngestOptions,
  ProcessOptions,
  ProcessResult,
  Report,
  ReportDocument,
  RequestOptions,
  ScanOptions,
  ScanRun,
  TokenProvider,
  WaitOptions,
} from "./types.js";
import {
  parseAttestation,
  parseCheckResult,
  parseProcessResult,
  parseReport,
  parseReportDocument,
  parseScanRun,
  parseSystems,
} from "./validate.js";

/** Default per-request timeout (SPEC: 30 s). */
export const DEFAULT_TIMEOUT_MS = 30_000;
/** Default `waitForReport` deadline (SPEC: 900 s). */
export const DEFAULT_WAIT_TIMEOUT_MS = 900_000;
/** Default `waitForReport` poll interval (SPEC: 2 s). */
export const DEFAULT_POLL_INTERVAL_MS = 2_000;

// setTimeout stores delays as a signed 32-bit integer; longer delays fire immediately.
const MAX_TIMER_MS = 2_147_483_647;

interface Call {
  readonly method: "GET" | "POST";
  readonly path: string;
  readonly json?: unknown;
  readonly form?: FormData;
  readonly signal?: AbortSignal | undefined;
  readonly timeoutMs?: number | undefined;
}

interface RawResponse {
  readonly status: number;
  readonly value: unknown;
  readonly method: string;
  readonly url: string;
}

/**
 * Client for the CertOne control-plane REST API (`SPEC.md`).
 *
 * ```ts
 * const certone = new CertOneClient({ baseUrl: "https://api.yourco.com", token: process.env.CERTONE_API_KEY });
 * const { scan_run, report } = await certone.submitCheck(snapshotBytes, { asset: "Fraud Scorer" });
 * ```
 *
 * Every method rejects with {@link CertOneError} on HTTP errors (status >= 400), network
 * failures, timeouts, aborts and malformed responses. The token is held in a private field and is
 * never included in errors, logs or `JSON.stringify(client)`.
 */
export class CertOneClient {
  /** Normalised base URL (no trailing slash). */
  readonly baseUrl: string;
  /** Per-request timeout in milliseconds. */
  readonly timeoutMs: number;

  readonly #token: string | TokenProvider | undefined;
  readonly #fetch: FetchLike;
  readonly #headers: Readonly<Record<string, string>>;

  constructor(options: CertOneClientOptions) {
    if (typeof options !== "object" || options === null || typeof options.baseUrl !== "string") {
      throw new TypeError("CertOneClient: options.baseUrl is required");
    }
    this.baseUrl = normaliseBaseUrl(options.baseUrl);
    this.timeoutMs = positiveMs(options.timeoutMs, "timeoutMs", DEFAULT_TIMEOUT_MS);

    const token = options.token;
    if (token !== undefined && typeof token !== "string" && typeof token !== "function") {
      throw new TypeError("CertOneClient: token must be a string or a function returning one");
    }
    if (token === "") throw new TypeError("CertOneClient: token must not be empty");
    if (typeof token === "string") checkTokenChars(token);
    this.#token = token;

    if (options.fetch !== undefined && typeof options.fetch !== "function") {
      throw new TypeError("CertOneClient: fetch must be a function");
    }
    // Resolve the global lazily (and call it unbound-safe) so polyfills installed later still apply.
    this.#fetch = options.fetch ?? ((input, init) => globalThis.fetch(input, init));

    const headers: Record<string, string> = {};
    for (const [name, value] of Object.entries(options.headers ?? {})) {
      const key = name.toLowerCase();
      if (key === "authorization") {
        throw new TypeError("CertOneClient: pass credentials with options.token, not options.headers");
      }
      const text = String(value);
      if (/[\r\n\0]/.test(text)) {
        throw new TypeError(`CertOneClient: header ${JSON.stringify(name)} contains a line break or NUL`);
      }
      headers[key] = text;
    }
    this.#headers = Object.freeze(headers);
  }

  /** `POST /v1/checks`: static compliance check of a project snapshot (`.tar.gz`). */
  async submitCheck(snapshot: BinaryInput, options: ScanOptions = {}): Promise<CheckResult> {
    const form = scanForm(snapshot, options);
    return this.#call(
      { method: "POST", path: "/v1/checks", form, signal: options.signal, timeoutMs: options.timeoutMs },
      parseCheckResult,
    );
  }

  /**
   * `POST /v1/process`: full processing (static + dynamic) on the confidential worker pool. On the
   * asynchronous pool the result has `queued: true` and `report: null`; use {@link waitForReport}.
   */
  async submitProcess(snapshot: BinaryInput, options: ProcessOptions = {}): Promise<ProcessResult> {
    const form = scanForm(snapshot, options);
    if (options.tee !== undefined) form.append("tee", options.tee);
    return this.#call(
      { method: "POST", path: "/v1/process", form, signal: options.signal, timeoutMs: options.timeoutMs },
      parseProcessResult,
    );
  }

  /** `GET /v1/scans/{id}`. */
  async getScan(scanId: string, options: RequestOptions = {}): Promise<ScanRun> {
    return this.#call(
      { method: "GET", path: `/v1/scans/${pathId(scanId, "scanId")}`, ...options },
      parseScanRun,
    );
  }

  /**
   * Polls `GET /v1/scans/{id}` until the scan is `succeeded` or `failed`, then returns its report
   * (`GET /v1/scans/{id}/report`). A `failed` scan rejects with kind `scan_failed` carrying the
   * scan's `error`; exceeding `timeoutMs` rejects with kind `timeout`.
   */
  async waitForReport(scanId: string, options: WaitOptions = {}): Promise<Report> {
    const id = pathId(scanId, "scanId");
    const timeoutMs = positiveMs(options.timeoutMs, "timeoutMs", DEFAULT_WAIT_TIMEOUT_MS);
    const intervalMs = nonNegativeMs(options.intervalMs, "intervalMs", DEFAULT_POLL_INTERVAL_MS);
    const requestTimeoutMs = positiveMs(options.requestTimeoutMs, "requestTimeoutMs", this.timeoutMs);
    const { signal } = options;
    const deadline = Date.now() + timeoutMs;
    // Each request is bounded by the overall deadline as well as its own timeout.
    const budget = (): number => Math.max(1, Math.min(requestTimeoutMs, deadline - Date.now()));

    for (;;) {
      const scan = await this.getScan(scanId, { signal, timeoutMs: budget() });
      if (scan.status === "failed") {
        const detail = scan.error ?? "the scan failed without an error message";
        throw new CertOneError(`scan ${scanId} failed: ${detail}`, { kind: "scan_failed", detail, scanId });
      }
      if (scan.status === "succeeded") {
        return this.#call(
          { method: "GET", path: `/v1/scans/${id}/report`, signal, timeoutMs: budget() },
          parseReport,
        );
      }
      const remaining = deadline - Date.now();
      if (remaining <= 0) {
        throw new CertOneError(
          `scan ${scanId} did not finish within ${timeoutMs} ms (last status: ${scan.status})`,
          { kind: "timeout", detail: `last status: ${scan.status}`, scanId },
        );
      }
      await sleep(Math.min(intervalMs, remaining), signal);
    }
  }

  /**
   * `GET /v1/reports/{id}/document`: the full engine report (`verdict`, `summary`, `issues`).
   * `reportId` is the report record's `id` (for example `report.id`), not the engine `report_id`.
   */
  async getReportDocument(reportId: string, options: RequestOptions = {}): Promise<ReportDocument> {
    return this.#call(
      { method: "GET", path: `/v1/reports/${pathId(reportId, "reportId")}/document`, ...options },
      parseReportDocument,
    );
  }

  /**
   * `GET /v1/reports/{id}/attestation`: the conditional compliance attestation. Rejects with an
   * `http` error of status 404 when the verdict did not pass (no attestation was issued).
   */
  async getAttestation(reportId: string, options: RequestOptions = {}): Promise<Attestation> {
    return this.#call(
      { method: "GET", path: `/v1/reports/${pathId(reportId, "reportId")}/attestation`, ...options },
      parseAttestation,
    );
  }

  /**
   * `POST /v1/checks/report`: submit an engine report computed where the model lives
   * (run-at-source). The model and code never leave the caller's environment; pass
   * `inputDigest: await inputDigest(snapshotBytes)` to bind the attestation to the exact input.
   */
  async ingestReport(report: Readonly<Record<string, unknown>>, options: IngestOptions = {}): Promise<CheckResult> {
    if (typeof report !== "object" || report === null || Array.isArray(report)) {
      throw new TypeError("ingestReport: report must be a JSON object (an engine report)");
    }
    const body = {
      report,
      asset: options.asset,
      environment: options.environment,
      country_code: options.countryCode,
      snapshot_ref: options.snapshotRef,
      input_digest: options.inputDigest,
      repo: options.repo,
      commit_hash: options.commitHash,
    };
    return this.#call(
      {
        method: "POST",
        path: "/v1/checks/report",
        json: body,
        signal: options.signal,
        timeoutMs: options.timeoutMs,
      },
      parseCheckResult,
    );
  }

  /** `GET /v1/systems`: the tenant's AI-system inventory with each system's posture. */
  async listSystems(options: RequestOptions = {}): Promise<AISystem[]> {
    return this.#call({ method: "GET", path: "/v1/systems", ...options }, parseSystems);
  }

  /** Never expose the token through `JSON.stringify(client)`. */
  toJSON(): { baseUrl: string; timeoutMs: number } {
    return { baseUrl: this.baseUrl, timeoutMs: this.timeoutMs };
  }

  async #call<T>(call: Call, parse: (value: unknown) => T): Promise<T> {
    const raw = await this.#send(call);
    try {
      return parse(raw.value);
    } catch (err) {
      if (CertOneError.is(err) && err.kind === "invalid_response") {
        throw new CertOneError(err.message, {
          kind: "invalid_response",
          status: raw.status,
          detail: err.detail,
          method: raw.method,
          url: raw.url,
          responseBody: raw.value,
        });
      }
      throw err;
    }
  }

  async #send(call: Call): Promise<RawResponse> {
    const { method } = call;
    const url = `${this.baseUrl}${call.path}`;
    const timeoutMs = positiveMs(call.timeoutMs, "timeoutMs", this.timeoutMs);
    const external = call.signal;
    if (external?.aborted) throw abortedError(external, method, url);

    const headers: Record<string, string> = { ...this.#headers, accept: "application/json" };
    const token = await this.#resolveToken();
    if (token) headers["authorization"] = `Bearer ${token}`;
    let body: BodyInit | null = null;
    if (call.json !== undefined) {
      headers["content-type"] = "application/json";
      body = JSON.stringify(call.json);
    } else if (call.form !== undefined) {
      body = call.form; // fetch sets the multipart content-type with its boundary
    }

    const controller = new AbortController();
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, Math.min(timeoutMs, MAX_TIMER_MS));
    const onAbort = (): void => controller.abort();
    external?.addEventListener("abort", onAbort, { once: true });

    let status: number;
    let text: string;
    try {
      const response = await this.#fetch(url, { method, headers, body, signal: controller.signal });
      status = response.status;
      // Reading the body stays under the same timeout: a stalled body must not hang the caller.
      text = await response.text();
    } catch (err) {
      if (timedOut) {
        throw new CertOneError(`${method} ${url} timed out after ${timeoutMs} ms`, {
          kind: "timeout",
          method,
          url,
          cause: err,
        });
      }
      if (external?.aborted) throw abortedError(external, method, url);
      if (CertOneError.is(err)) throw err;
      throw new CertOneError(`${method} ${url} failed: ${describe(err)}`, {
        kind: "network",
        method,
        url,
        cause: err,
      });
    } finally {
      clearTimeout(timer);
      external?.removeEventListener("abort", onAbort);
    }

    const parsed = parseJson(text);
    if (status >= 400) {
      const detail = extractDetail(parsed.ok ? parsed.value : undefined, text);
      throw new CertOneError(detail ? `HTTP ${status}: ${detail}` : `HTTP ${status}`, {
        kind: "http",
        status,
        detail,
        method,
        url,
        responseBody: parsed.ok ? parsed.value : text,
      });
    }
    if (status < 200 || status >= 300 || !parsed.ok) {
      const why = parsed.ok ? "unexpected status" : "the response body is not JSON";
      throw new CertOneError(`HTTP ${status} from ${method} ${url}: ${why}`, {
        kind: "invalid_response",
        status,
        detail: why,
        method,
        url,
        responseBody: text,
      });
    }
    return { status, value: parsed.value, method, url };
  }

  async #resolveToken(): Promise<string | undefined> {
    const token = this.#token;
    if (typeof token !== "function") return token;
    const value = await token();
    if (typeof value !== "string" || value === "") {
      throw new TypeError("CertOneClient: the token provider must return a non-empty string");
    }
    checkTokenChars(value);
    return value;
  }
}

/**
 * Bearer tokens (API keys, JWTs) are visible ASCII. Reject anything else up front: a stray CR/LF
 * or space (typically from a CRLF env file) would otherwise make `fetch` throw an "invalid header
 * value" error whose message embeds the token. The token itself is never echoed.
 */
function checkTokenChars(token: string): void {
  if (!/^[\x21-\x7e]+$/.test(token)) {
    throw new TypeError(
      "CertOneClient: the token contains whitespace or non-printable characters " +
        "(check for a trailing newline or carriage return)",
    );
  }
}

function scanForm(snapshot: BinaryInput, options: ScanOptions): FormData {
  const form = new FormData();
  form.append("snapshot", toBlob(snapshot), options.filename ?? "snapshot.tar.gz");
  const packs = typeof options.packs === "string" ? options.packs : options.packs?.join(",");
  const fields: ReadonlyArray<readonly [string, string | undefined]> = [
    ["asset", options.asset],
    ["environment", options.environment],
    ["country_code", options.countryCode],
    ["fail_on", options.failOn],
    ["packs", packs],
    ["snapshot_ref", options.snapshotRef],
    ["commit_hash", options.commitHash],
  ];
  for (const [name, value] of fields) {
    if (value !== undefined) form.append(name, value);
  }
  return form;
}

function normaliseBaseUrl(raw: string): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new TypeError(`CertOneClient: baseUrl is not a valid URL: ${JSON.stringify(raw)}`);
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new TypeError("CertOneClient: baseUrl must be an http(s) URL");
  }
  if (url.username || url.password) {
    throw new TypeError("CertOneClient: baseUrl must not embed credentials; use options.token");
  }
  if (url.search || url.hash) {
    throw new TypeError("CertOneClient: baseUrl must not have a query string or fragment");
  }
  return `${url.origin}${url.pathname.replace(/\/+$/, "")}`;
}

function pathId(value: string, name: string): string {
  if (typeof value !== "string" || value.trim() === "") {
    throw new TypeError(`${name} must be a non-empty string`);
  }
  return encodeURIComponent(value);
}

function positiveMs(value: number | undefined, name: string, fallback: number): number {
  if (value === undefined) return fallback;
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
    throw new RangeError(`${name} must be a positive number of milliseconds`);
  }
  return value;
}

function nonNegativeMs(value: number | undefined, name: string, fallback: number): number {
  if (value === undefined) return fallback;
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    throw new RangeError(`${name} must be a non-negative number of milliseconds`);
  }
  return value;
}

function parseJson(text: string): { ok: true; value: unknown } | { ok: false } {
  if (text.trim() === "") return { ok: false };
  try {
    return { ok: true, value: JSON.parse(text) as unknown };
  } catch {
    return { ok: false };
  }
}

function abortedError(signal: AbortSignal, method?: string, url?: string): CertOneError {
  const message = method && url ? `${method} ${url} was aborted by the caller` : "Aborted by the caller";
  return new CertOneError(message, {
    kind: "aborted",
    ...(method === undefined ? {} : { method }),
    ...(url === undefined ? {} : { url }),
    cause: signal.reason,
  });
}

/** A short reason for a network failure (undici nests the system error in `cause`). */
function describe(err: unknown): string {
  if (!(err instanceof Error)) return String(err);
  const cause = err.cause;
  if (cause instanceof Error) {
    const code = (cause as { code?: unknown }).code;
    return `${err.message} (${typeof code === "string" ? `${code}: ` : ""}${cause.message})`;
  }
  return err.message;
}

function sleep(ms: number, signal: AbortSignal | undefined): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(abortedError(signal));
      return;
    }
    const onAbort = (): void => {
      clearTimeout(timer);
      reject(abortedError(signal as AbortSignal));
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, Math.min(ms, MAX_TIMER_MS));
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}
