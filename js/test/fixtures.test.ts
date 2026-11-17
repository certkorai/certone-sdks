import { readdirSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import {
  CertOneError,
  parseAttestation,
  parseCheckResult,
  parseProcessResult,
  parseReport,
  parseReportDocument,
  parseScanRun,
  parseSystems,
  type AISystem,
  type Attestation,
  type CheckResult,
  type Report,
  type ReportDocument,
  type ScanRun,
} from "../src/index.node.js";
import { CONFORMANCE_DIR, fixture } from "./support/fake-fetch.js";

function expectInvalid(fn: () => unknown, path: string): void {
  try {
    fn();
  } catch (err) {
    expect(CertOneError.is(err)).toBe(true);
    const e = err as CertOneError;
    expect(e.kind).toBe("invalid_response");
    expect(e.detail).toContain(path);
    return;
  }
  throw new Error(`expected an invalid_response error for ${path}`);
}

const clone = <T>(value: T): T => JSON.parse(JSON.stringify(value)) as T;

describe("conformance fixtures parse through the SDK types", () => {
  it("covers every fixture shipped in conformance/fixtures", () => {
    const names = readdirSync(join(CONFORMANCE_DIR, "fixtures")).sort();
    expect(names).toEqual([
      "attestation.json",
      "check_result.json",
      "ingest_result.json",
      "report.json",
      "report_document_excerpt.json",
      "scan.json",
      "systems.json",
    ]);
  });

  it("scan.json -> ScanRun", () => {
    const scan: ScanRun = parseScanRun(fixture("scan"));
    expect(scan.id).toBe("64ff3a4afb5e40f5b8ae5e38071c9145");
    expect(scan.kind).toBe("check");
    expect(scan.status).toBe("succeeded");
    expect(scan.snapshot_ref).toBeNull();
    expect(scan.error).toBeNull();
    expect(scan.finished_at).toBe("2026-11-08T19:43:23.167688");
  });

  it("report.json -> Report", () => {
    const report: Report = parseReport(fixture("report"));
    expect(report.id).toBe("88b35a6b07bb456aa5159c32831f6bf4");
    expect(report.report_id).toBe("report-bce1fa3cd2cd");
    expect(report.verdict_status).toBe("fail");
    expect(report.fail_on).toBe("high");
    expect(report.total_issues).toBe(6);
    expect(report.by_severity).toEqual({ low: 0, medium: 3, high: 3 });
    expect(report.country_code).toBe("ZZ");
  });

  it("check_result.json -> CheckResult (failing verdict)", () => {
    const result: CheckResult = parseCheckResult(fixture("check_result"));
    expect(result.queued).toBe(false);
    expect(result.scan_run.id).toBe("64ff3a4afb5e40f5b8ae5e38071c9145");
    expect(result.report?.verdict_status).toBe("fail");
    expect(result.report?.scan_run_id).toBe(result.scan_run.id);
    expect(result.report?.by_severity["high"]).toBe(3);
  });

  it("ingest_result.json -> CheckResult (passing run-at-source verdict)", () => {
    const result: CheckResult = parseCheckResult(fixture("ingest_result"));
    expect(result.report?.verdict_status).toBe("pass");
    expect(result.report?.report_id).toBe("rat-sdk-0001");
    expect(result.report?.country_code).toBe("EU");
    expect(result.report?.by_severity).toEqual({});
  });

  it("report_document_excerpt.json -> ReportDocument", () => {
    const doc: ReportDocument = parseReportDocument(fixture("report_document_excerpt"));
    expect(doc.report_id).toBe("report-bce1fa3cd2cd");
    expect(doc.verdict.status).toBe("fail");
    expect(doc.verdict.reason).toBe("3 issue(s) at or above 'high' (worst: high)");
    expect(doc.summary.total_issues).toBe(6);
    expect(doc.summary.by_component).toEqual({ input: 2, model: 4 });
    expect(doc.summary.rules_evaluated).toBe(7);
    const [first] = doc.issues;
    expect(first?.issue_id).toBe("iss-0001");
    expect(first?.severity).toBe("high");
    expect(first?.compliance_topic).toBe("privacy");
    expect(first?.regulatory_references[0]).toEqual({ framework: "EU AI Act", article: "Article 10" });
    expect(first?.location["artifact"]).toBe("sample-project/data/train.csv");
    expect(first?.rule_path).toBe("eu_ai_act/privacy/data_governance_10.aipac");
  });

  it("attestation.json -> Attestation", () => {
    const att: Attestation = parseAttestation(fixture("attestation"));
    expect(att.attestation_id).toBe("att-43d463ff6d874d1a92be85ed768b762f");
    expect(att.input_version).toBe("1.0");
    expect(att.signature_algorithm).toBe("HMAC-SHA256");
    expect(att.signature).toMatch(/^[0-9a-f]{64}$/);
    expect(att.conditional_validity?.valid).toBe(true);
    expect(att.conditional_validity?.covers).toEqual(["binary", "configuration", "dependency_graph"]);
    expect(att.fingerprint?.algorithm).toBe("HMAC-SHA256");
    expect(att.test_status?.["status"]).toBe("Passed");
  });

  it("systems.json -> AISystem[]", () => {
    const systems: AISystem[] = parseSystems(fixture("systems"));
    expect(systems).toHaveLength(3);
    const edge = systems.find((s) => s.slug === "sdk-edge-model");
    expect(edge?.environments).toEqual(["edge"]);
    expect(edge?.regions).toEqual(["EU"]);
    expect(edge?.attested).toBe(true);
    expect(edge?.attestation_status).toBe("valid");
    expect(edge?.last_verdict).toBe("pass");
    expect(systems.filter((s) => s.risk === "high")).toHaveLength(2);
  });

  it("keeps fields the SDK does not model (forward compatibility)", () => {
    const body = { ...clone(fixture("check_result") as Record<string, unknown>), region: "eu-west-1" };
    const result = parseCheckResult(body);
    expect((result as unknown as Record<string, unknown>)["region"]).toBe("eu-west-1");
  });
});

describe("response shape validation", () => {
  it("normalises an omitted report/queued on CheckResult", () => {
    const body = clone(fixture("check_result")) as Record<string, unknown>;
    delete body["report"];
    delete body["queued"];
    const result = parseCheckResult(body);
    expect(result.report).toBeNull();
    expect(result.queued).toBe(false);
  });

  it("accepts a queued process result with a null report and telemetry", () => {
    const body = { ...(clone(fixture("check_result")) as Record<string, unknown>), report: null, queued: true };
    const result = parseProcessResult({ ...body, jobs: { static: 1 }, energy: { joules: 2.5 } });
    expect(result.queued).toBe(true);
    expect(result.report).toBeNull();
    expect(result.jobs).toEqual({ static: 1 });
  });

  it("rejects malformed bodies with a precise path", () => {
    expectInvalid(() => parseScanRun(null), "body");
    expectInvalid(() => parseScanRun([]), "body");
    expectInvalid(() => parseScanRun({ ...(fixture("scan") as object), id: 7 }), "body.id");
    expectInvalid(() => parseScanRun({ ...(fixture("scan") as object), error: 1 }), "body.error");

    const check = clone(fixture("check_result")) as { report: Record<string, unknown> };
    check.report["total_issues"] = "6";
    expectInvalid(() => parseCheckResult(check), "body.report.total_issues");

    const counts = clone(fixture("report")) as Record<string, unknown>;
    counts["by_severity"] = { high: "3" };
    expectInvalid(() => parseReport(counts), "body.by_severity.high");

    const doc = clone(fixture("report_document_excerpt")) as { issues: Array<Record<string, unknown>> };
    delete doc.issues[0]?.["severity"];
    expectInvalid(() => parseReportDocument(doc), "body.issues[0].severity");
    expectInvalid(() => parseReportDocument({ ...doc, issues: {} }), "body.issues");

    const att = clone(fixture("attestation")) as Record<string, unknown>;
    delete att["signature"];
    expectInvalid(() => parseAttestation(att), "body.signature");

    const systems = clone(fixture("systems")) as Array<Record<string, unknown>>;
    systems[1] = { ...systems[1], regions: ["EU", 3] };
    expectInvalid(() => parseSystems(systems), "body[1].regions[1]");
    expectInvalid(() => parseSystems({}), "body");
  });
});
