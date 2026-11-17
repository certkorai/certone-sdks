/**
 * Runtime checks for API responses.
 *
 * A 2xx body that does not have the documented shape (a misrouted proxy, an incompatible control
 * plane version) is rejected with `CertOneError(kind: "invalid_response")` at the SDK boundary
 * instead of surfacing later as an `undefined` deep inside the caller's code. Only the documented,
 * stable fields are checked; additional fields are kept as-is so newer servers stay compatible.
 */

import { CertOneError } from "./errors.js";
import type {
  AISystem,
  Attestation,
  CheckResult,
  ProcessResult,
  Report,
  ReportDocument,
  ScanRun,
} from "./types.js";

type Json = Record<string, unknown>;

class Checker {
  constructor(private readonly what: string) {}

  fail(path: string, expected: string, value: unknown): never {
    const got = value === null ? "null" : Array.isArray(value) ? "array" : typeof value;
    throw new CertOneError(
      `invalid ${this.what} from the CertOne API: ${path} must be ${expected} (got ${got})`,
      { kind: "invalid_response", detail: `${path} must be ${expected}` },
    );
  }

  object(value: unknown, path: string): Json {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      this.fail(path, "an object", value);
    }
    return value as Json;
  }

  array(value: unknown, path: string): unknown[] {
    if (!Array.isArray(value)) this.fail(path, "an array", value);
    return value;
  }

  string(o: Json, key: string, path: string): void {
    if (typeof o[key] !== "string") this.fail(`${path}.${key}`, "a string", o[key]);
  }

  nullableString(o: Json, key: string, path: string): void {
    const v = o[key];
    if (v !== null && typeof v !== "string") this.fail(`${path}.${key}`, "a string or null", v);
  }

  optionalString(o: Json, key: string, path: string): void {
    const v = o[key];
    if (v !== undefined && typeof v !== "string") this.fail(`${path}.${key}`, "a string", v);
  }

  number(o: Json, key: string, path: string): void {
    const v = o[key];
    if (typeof v !== "number" || !Number.isFinite(v)) this.fail(`${path}.${key}`, "a number", v);
  }

  boolean(o: Json, key: string, path: string): void {
    if (typeof o[key] !== "boolean") this.fail(`${path}.${key}`, "a boolean", o[key]);
  }

  counts(o: Json, key: string, path: string): void {
    const counts = this.object(o[key], `${path}.${key}`);
    for (const [k, v] of Object.entries(counts)) {
      if (typeof v !== "number") this.fail(`${path}.${key}.${k}`, "a number", v);
    }
  }

  stringArray(o: Json, key: string, path: string): void {
    this.array(o[key], `${path}.${key}`).forEach((v, i) => {
      if (typeof v !== "string") this.fail(`${path}.${key}[${i}]`, "a string", v);
    });
  }
}

function checkScanRun(c: Checker, value: unknown, path: string): ScanRun {
  const o = c.object(value, path);
  c.string(o, "id", path);
  c.string(o, "kind", path);
  c.string(o, "status", path);
  c.nullableString(o, "snapshot_ref", path);
  c.nullableString(o, "created_by", path);
  c.string(o, "created_at", path);
  c.nullableString(o, "finished_at", path);
  c.nullableString(o, "error", path);
  return o as unknown as ScanRun;
}

function checkReport(c: Checker, value: unknown, path: string): Report {
  const o = c.object(value, path);
  c.string(o, "id", path);
  c.string(o, "scan_run_id", path);
  c.string(o, "report_id", path);
  c.string(o, "verdict_status", path);
  c.string(o, "fail_on", path);
  c.number(o, "total_issues", path);
  c.counts(o, "by_severity", path);
  if (o["country_code"] !== undefined) c.nullableString(o, "country_code", path);
  c.string(o, "created_at", path);
  return o as unknown as Report;
}

function checkCheckResult(c: Checker, value: unknown): Json {
  const o = c.object(value, "body");
  checkScanRun(c, o["scan_run"], "body.scan_run");
  if (o["report"] !== null && o["report"] !== undefined) checkReport(c, o["report"], "body.report");
  if (o["queued"] !== undefined) c.boolean(o, "queued", "body");
  // Normalise the two fields a pydantic default may omit, without dropping anything else.
  return { ...o, report: o["report"] ?? null, queued: o["queued"] ?? false };
}

/** Validate a `GET /v1/scans/{id}` body. */
export function parseScanRun(value: unknown): ScanRun {
  return checkScanRun(new Checker("ScanRun"), value, "body");
}

/** Validate a report record (`GET /v1/scans/{id}/report`, `GET /v1/reports/{id}`). */
export function parseReport(value: unknown): Report {
  return checkReport(new Checker("Report"), value, "body");
}

/** Validate a `POST /v1/checks` or `POST /v1/checks/report` body. */
export function parseCheckResult(value: unknown): CheckResult {
  return checkCheckResult(new Checker("CheckResult"), value) as unknown as CheckResult;
}

/** Validate a `POST /v1/process` body. */
export function parseProcessResult(value: unknown): ProcessResult {
  return checkCheckResult(new Checker("ProcessResult"), value) as unknown as ProcessResult;
}

/** Validate the core of a full engine report document (`GET /v1/reports/{id}/document`). */
export function parseReportDocument(value: unknown): ReportDocument {
  const c = new Checker("ReportDocument");
  const o = c.object(value, "body");
  c.string(o, "report_id", "body");
  const verdict = c.object(o["verdict"], "body.verdict");
  c.string(verdict, "status", "body.verdict");
  c.string(verdict, "fail_on", "body.verdict");
  c.optionalString(verdict, "reason", "body.verdict");
  const summary = c.object(o["summary"], "body.summary");
  c.number(summary, "total_issues", "body.summary");
  c.counts(summary, "by_severity", "body.summary");
  c.array(o["issues"], "body.issues").forEach((item, i) => {
    const path = `body.issues[${i}]`;
    const issue = c.object(item, path);
    c.string(issue, "issue_id", path);
    c.string(issue, "description", path);
    c.string(issue, "severity", path);
    c.string(issue, "detected_by", path);
    c.optionalString(issue, "compliance_topic", path);
    c.optionalString(issue, "component", path);
    c.optionalString(issue, "suggested_fix", path);
    c.optionalString(issue, "rule_path", path);
    c.array(issue["regulatory_references"], `${path}.regulatory_references`);
    c.object(issue["location"], `${path}.location`);
  });
  return o as unknown as ReportDocument;
}

/** Validate a `GET /v1/reports/{id}/attestation` body. */
export function parseAttestation(value: unknown): Attestation {
  const c = new Checker("Attestation");
  const o = c.object(value, "body");
  c.string(o, "attestation_id", "body");
  c.string(o, "input_version", "body");
  c.string(o, "issued_at", "body");
  c.string(o, "signature", "body");
  c.string(o, "signature_algorithm", "body");
  if (o["conditional_validity"] !== undefined) {
    const cv = c.object(o["conditional_validity"], "body.conditional_validity");
    c.boolean(cv, "valid", "body.conditional_validity");
  }
  if (o["fingerprint"] !== undefined) {
    const fp = c.object(o["fingerprint"], "body.fingerprint");
    c.string(fp, "algorithm", "body.fingerprint");
    c.string(fp, "value", "body.fingerprint");
  }
  return o as unknown as Attestation;
}

/** Validate a `GET /v1/systems` body. */
export function parseSystems(value: unknown): AISystem[] {
  const c = new Checker("AISystem list");
  return c.array(value, "body").map((item, i) => {
    const path = `body[${i}]`;
    const o = c.object(item, path);
    c.string(o, "id", path);
    c.string(o, "slug", path);
    c.string(o, "name", path);
    c.string(o, "lifecycle", path);
    c.nullableString(o, "owner_team_id", path);
    c.nullableString(o, "description", path);
    c.string(o, "created_at", path);
    c.stringArray(o, "regions", path);
    c.stringArray(o, "environments", path);
    c.stringArray(o, "standards", path);
    c.number(o, "scans", path);
    c.number(o, "open_issues", path);
    c.nullableString(o, "last_verdict", path);
    c.boolean(o, "attested", path);
    c.string(o, "attestation_status", path);
    c.string(o, "risk", path);
    c.nullableString(o, "last_evaluated", path);
    return o as unknown as AISystem;
  });
}
