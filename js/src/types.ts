/**
 * Wire types for the CertOne control-plane API.
 *
 * Response objects keep the API's snake_case field names, exactly as documented in
 * `SPEC.md` and the conformance fixtures, so they can be logged, stored and compared with the
 * REST payloads one-to-one. Timestamps are ISO-8601 strings as sent by the API. Unions that the
 * server may extend (for example scan statuses) accept any string while still offering the known
 * values to editors.
 */

/** A string union that still accepts values a newer control plane may introduce. */
export type OpenUnion<T extends string> = T | (string & Record<never, never>);

/** Lifecycle of a scan run. `succeeded` and `failed` are terminal. */
export type ScanStatus = OpenUnion<"queued" | "running" | "succeeded" | "failed">;

export type ScanKind = OpenUnion<"check" | "process" | "correct">;

/** Engine verdict for a report. */
export type VerdictStatus = OpenUnion<"pass" | "fail">;

export type Severity = OpenUnion<"low" | "medium" | "high">;

/** Lowest severity that makes the verdict fail; `none` never fails. */
export type FailOn = "low" | "medium" | "high" | "none";

/** The surface a submission came from (the server maps unknown values to `api`). */
export type Environment = "ci" | "jupyter" | "vscode" | "edge" | "api" | "cloud" | "cli";

/** `GET /v1/scans/{id}` (fixture `scan.json`). */
export interface ScanRun {
  readonly id: string;
  readonly kind: ScanKind;
  readonly status: ScanStatus;
  readonly snapshot_ref: string | null;
  readonly created_by: string | null;
  readonly created_at: string;
  readonly finished_at: string | null;
  /** Why the scan failed, when `status === "failed"`. */
  readonly error: string | null;
}

/**
 * A report record (fixture `report.json`). `id` is the record id used by `getReportDocument` and
 * `getAttestation`; `report_id` is the engine's own report identifier.
 */
export interface Report {
  readonly id: string;
  readonly scan_run_id: string;
  readonly report_id: string;
  readonly verdict_status: VerdictStatus;
  readonly fail_on: FailOn;
  readonly total_issues: number;
  readonly by_severity: Readonly<Record<string, number>>;
  readonly country_code: string | null;
  readonly created_at: string;
}

/** `POST /v1/checks` and `POST /v1/checks/report` (fixtures `check_result.json`, `ingest_result.json`). */
export interface CheckResult {
  readonly scan_run: ScanRun;
  /** `null` when the submission was queued for the worker pool: use `waitForReport(scan_run.id)`. */
  readonly report: Report | null;
  readonly queued: boolean;
}

/** `POST /v1/process`: a `CheckResult` plus the processing unit's job telemetry when it ran inline. */
export interface ProcessResult extends CheckResult {
  readonly jobs?: Readonly<Record<string, number>>;
  readonly health?: Readonly<Record<string, unknown>>;
  readonly energy?: Readonly<Record<string, number>>;
}

/** One regulatory citation attached to an issue. */
export interface RegulatoryReference {
  readonly framework: string;
  readonly article?: string;
  readonly [key: string]: unknown;
}

/** One finding in the engine report document (`compliance-issue.schema.json`). */
export interface ReportIssue {
  readonly issue_id: string;
  readonly description: string;
  readonly severity: Severity;
  readonly detected_by: string;
  readonly compliance_topic?: string;
  /** The AI-system component the issue concerns (input | model | output | pipeline | config). */
  readonly component?: string;
  readonly regulatory_references: readonly RegulatoryReference[];
  readonly location: Readonly<Record<string, unknown>>;
  readonly suggested_fix?: string;
  readonly rule_path?: string;
  readonly [key: string]: unknown;
}

export interface ReportVerdict {
  readonly status: VerdictStatus;
  readonly fail_on: FailOn;
  readonly reason?: string;
  readonly [key: string]: unknown;
}

export interface ReportSummary {
  readonly total_issues: number;
  readonly by_severity: Readonly<Record<string, number>>;
  readonly by_topic?: Readonly<Record<string, number>>;
  readonly by_component?: Readonly<Record<string, number>>;
  readonly rules_evaluated?: number;
  readonly rules_triggered?: number;
  readonly [key: string]: unknown;
}

/**
 * The full engine report (`GET /v1/reports/{id}/document`, fixture `report_document_excerpt.json`).
 * Only the stable core is typed; every other section is available as `unknown`.
 */
export interface ReportDocument {
  readonly report_id: string;
  readonly verdict: ReportVerdict;
  readonly summary: ReportSummary;
  readonly issues: readonly ReportIssue[];
  readonly [key: string]: unknown;
}

/**
 * The conditional compliance attestation for a passing report
 * (`GET /v1/reports/{id}/attestation`, fixture `attestation.json`).
 */
export interface Attestation {
  readonly attestation_id: string;
  readonly input_version: string;
  readonly issued_at: string;
  readonly signature: string;
  readonly signature_algorithm: string;
  readonly test_status?: Readonly<Record<string, unknown>>;
  readonly issuance?: Readonly<Record<string, unknown>>;
  readonly conditional_validity?: {
    readonly valid: boolean;
    readonly covers?: readonly string[];
    readonly [key: string]: unknown;
  };
  readonly fingerprint?: {
    readonly algorithm: string;
    readonly value: string;
    readonly [key: string]: unknown;
  };
  readonly log?: readonly unknown[];
  readonly [key: string]: unknown;
}

/** An AI system and its rolled-up posture (`GET /v1/systems`, fixture `systems.json`). */
export interface AISystem {
  readonly id: string;
  readonly slug: string;
  readonly name: string;
  readonly lifecycle: string;
  readonly owner_team_id: string | null;
  readonly description: string | null;
  readonly created_at: string;
  readonly regions: readonly string[];
  readonly environments: readonly string[];
  readonly standards: readonly string[];
  readonly scans: number;
  readonly open_issues: number;
  readonly last_verdict: VerdictStatus | null;
  readonly attested: boolean;
  readonly attestation_status: OpenUnion<"valid" | "revoked" | "none">;
  readonly risk: OpenUnion<"low" | "medium" | "high" | "unknown">;
  readonly last_evaluated: string | null;
}

/**
 * A snapshot or any other binary input: a `Blob` (or `File`), an `ArrayBuffer`, or a typed-array
 * view such as `Uint8Array` (a Node.js `Buffer` is one).
 */
export type BinaryInput = Blob | ArrayBuffer | ArrayBufferView;

/** Per-call transport options accepted by every operation. */
export interface RequestOptions {
  /** Cancels the call; the promise rejects with a `CertOneError` of kind `aborted`. */
  readonly signal?: AbortSignal | undefined;
  /** Overrides the client's per-request timeout (milliseconds) for this call. */
  readonly timeoutMs?: number | undefined;
}

/** Multipart form fields for `submitCheck` (all optional; the server applies the defaults shown). */
export interface ScanOptions extends RequestOptions {
  /** AI system name (auto-registered on first scan). Default: derived by the server. */
  readonly asset?: string | undefined;
  /** Default `api`. */
  readonly environment?: Environment | undefined;
  /** Origin region, for example `EU` or `US`. Default `ZZ`. */
  readonly countryCode?: string | undefined;
  /** Default `high`. */
  readonly failOn?: FailOn | undefined;
  /** Policy packs (array or comma-separated). Default: auto-matched from the AI BOM. */
  readonly packs?: string | readonly string[] | undefined;
  /** Stable source reference, for example `git:org/repo@sha`. */
  readonly snapshotRef?: string | undefined;
  /** Commit the scan is about. */
  readonly commitHash?: string | undefined;
  /** File name sent for the `snapshot` part. Default `snapshot.tar.gz`. */
  readonly filename?: string | undefined;
}

/** `submitProcess` options: the scan options plus the confidential-compute backend. */
export interface ProcessOptions extends ScanOptions {
  /** Confidential-compute backend id (`GET /v1/capabilities/tee`). Default `amd_sev_snp`. */
  readonly tee?: OpenUnion<"amd_sev_snp" | "intel_tdx"> | undefined;
}

/** Fields sent with a run-at-source report (`POST /v1/checks/report`). */
export interface IngestOptions extends RequestOptions {
  readonly asset?: string | undefined;
  /** Default `api`. */
  readonly environment?: Environment | undefined;
  /** Default `ZZ`. */
  readonly countryCode?: string | undefined;
  readonly snapshotRef?: string | undefined;
  /**
   * `sha256:<hex>` of the exact artifact the report covers; binds the attestation to that input.
   * Compute it with `inputDigest(snapshotBytes)`.
   */
  readonly inputDigest?: string | undefined;
  /** Repository full name (`owner/name`) the report is about. */
  readonly repo?: string | undefined;
  readonly commitHash?: string | undefined;
}

/** `waitForReport` options. */
export interface WaitOptions {
  /** Overall deadline in milliseconds. Default 900 000 (15 min). */
  readonly timeoutMs?: number | undefined;
  /** Delay between polls in milliseconds. Default 2 000. */
  readonly intervalMs?: number | undefined;
  /** Cancels the wait; rejects with a `CertOneError` of kind `aborted`. */
  readonly signal?: AbortSignal | undefined;
  /** Per-poll request timeout; defaults to the client's request timeout. */
  readonly requestTimeoutMs?: number | undefined;
}

/** A `fetch`-compatible function (inject one for tests, proxies, retries or custom TLS agents). */
export type FetchLike = (input: string, init: RequestInit) => Promise<Response>;

/** Supplies the bearer token per request, so short-lived OIDC tokens can be refreshed. */
export type TokenProvider = () => string | Promise<string>;

export interface CertOneClientOptions {
  /** Control-plane base URL, for example `https://api.yourco.com`. */
  readonly baseUrl: string;
  /** Tenant API key (`ck_...`) or OIDC ID token, or a function returning one. Never logged. */
  readonly token?: string | TokenProvider | undefined;
  /** Per-request timeout in milliseconds. Default 30 000. */
  readonly timeoutMs?: number | undefined;
  /** `fetch` implementation. Default: the global `fetch` (Node >= 18, browsers). */
  readonly fetch?: FetchLike | undefined;
  /** Extra headers sent with every request (for example tracing or proxy headers). */
  readonly headers?: Readonly<Record<string, string>> | undefined;
}
