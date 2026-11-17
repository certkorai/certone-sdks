/**
 * The single error type every CertOne SDK operation rejects with.
 *
 * `kind` tells the failure modes apart without string matching:
 *
 * - `http`             the API answered with a status >= 400 (`status` and `detail` are set);
 * - `network`          the request never got a response (DNS, TLS, connection reset, CORS, ...);
 * - `timeout`          the per-request timeout or the `waitForReport` deadline elapsed;
 * - `aborted`          the caller's `AbortSignal` fired;
 * - `scan_failed`      `waitForReport` saw the scan end in `failed` (`detail` is the scan's error);
 * - `invalid_response` a 2xx response whose body is not the documented JSON shape.
 */
export type CertOneErrorKind =
  | "http"
  | "network"
  | "timeout"
  | "aborted"
  | "scan_failed"
  | "invalid_response";

export interface CertOneErrorInit {
  kind: CertOneErrorKind;
  status?: number | null;
  detail?: string;
  method?: string;
  url?: string;
  scanId?: string;
  responseBody?: unknown;
  cause?: unknown;
}

const BRAND = Symbol.for("@certkor/certone.CertOneError");

export class CertOneError extends Error {
  override readonly name = "CertOneError";
  readonly kind: CertOneErrorKind;
  /** HTTP status code for `kind === "http"` (and `invalid_response`); otherwise `null`. */
  readonly status: number | null;
  /** The API's `detail` message (or the scan's `error` for `scan_failed`). */
  readonly detail: string;
  /** HTTP method of the failed request, when the failure is tied to one request. */
  readonly method: string | undefined;
  /** Absolute URL of the failed request (never contains credentials). */
  readonly url: string | undefined;
  /** The scan the failure concerns (`scan_failed`, and `waitForReport` timeouts). */
  readonly scanId: string | undefined;
  /** The parsed (or raw text) error body returned by the API, when there was one. */
  readonly responseBody: unknown;

  constructor(message: string, init: CertOneErrorInit) {
    super(message, init.cause === undefined ? undefined : { cause: init.cause });
    this.kind = init.kind;
    this.status = init.status ?? null;
    this.detail = init.detail ?? "";
    this.method = init.method;
    this.url = init.url;
    this.scanId = init.scanId;
    this.responseBody = init.responseBody;
    Object.defineProperty(this, BRAND, { value: true });
  }

  /**
   * `true` for any CertOneError, including one thrown by another copy of this package (for
   * example the CommonJS build loaded next to the ESM build), where `instanceof` would fail.
   */
  static is(value: unknown): value is CertOneError {
    return (
      value instanceof CertOneError ||
      (typeof value === "object" && value !== null && (value as Record<symbol, unknown>)[BRAND] === true)
    );
  }
}

const MAX_DETAIL_CHARS = 2000;

/**
 * Extract a human-readable message from an API error body.
 *
 * FastAPI sends `{"detail": "..."}` for application errors and `{"detail": [{loc, msg}, ...]}`
 * for request validation errors (422); proxies and load balancers may send HTML or plain text.
 */
export function extractDetail(body: unknown, rawText: string): string {
  if (typeof body === "object" && body !== null && "detail" in body) {
    const detail = (body as { detail: unknown }).detail;
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail)) {
      const parts = detail.map((entry: unknown) => {
        if (typeof entry === "object" && entry !== null) {
          const { loc, msg } = entry as { loc?: unknown; msg?: unknown };
          const where = Array.isArray(loc) ? loc.map(String).join(".") : "";
          const text = typeof msg === "string" ? msg : JSON.stringify(entry);
          return where ? `${where}: ${text}` : text;
        }
        return String(entry);
      });
      return truncate(parts.join("; "));
    }
    if (detail !== null && detail !== undefined) return truncate(JSON.stringify(detail));
  }
  return truncate(rawText.trim());
}

function truncate(text: string): string {
  return text.length > MAX_DETAIL_CHARS ? `${text.slice(0, MAX_DETAIL_CHARS)}…` : text;
}
