// CertOne TypeScript SDK quickstart: the same 7-step conformance flow as quickstart.mjs, typed.
//
//   npx tsc -p examples/tsconfig.json --noEmit false --outDir .examples-build
//   node .examples-build/quickstart.js
import { readFile } from "node:fs/promises";
import { basename } from "node:path";

import {
  CertOneClient,
  CertOneError,
  inputDigest,
  type Attestation,
  type CheckResult,
  type Report,
  type ReportDocument,
} from "@certkor/certone";

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not set`);
  return value;
}

function formatCounts(counts: Readonly<Record<string, number>>): string {
  const entries = Object.entries(counts);
  return entries.length ? entries.map(([k, v]) => `${k}=${v}`).join(" ") : "none";
}

async function main(): Promise<void> {
  // 1. Configuration from the environment.
  const snapshotPath = requireEnv("CERTONE_SNAPSHOT");
  const certone = new CertOneClient({
    baseUrl: requireEnv("CERTONE_API_URL"),
    token: requireEnv("CERTONE_API_KEY"),
  });
  const snapshot = await readFile(snapshotPath);
  const atSourceReport = JSON.parse(await readFile(requireEnv("CERTONE_REPORT_JSON"), "utf8")) as Record<string, unknown>;
  console.log(`CertOne TypeScript SDK quickstart -> ${certone.baseUrl}`);

  // 2. Static compliance check of the sample project.
  const check: CheckResult = await certone.submitCheck(snapshot, {
    asset: "TypeScript SDK quickstart",
    failOn: "high",
    filename: basename(snapshotPath),
  });
  console.log(`[2] check: scan ${check.scan_run.id} (${check.queued ? "queued" : check.scan_run.status})`);

  // 3. Wait for the report, fetch the full document and show the first finding.
  const report: Report = await certone.waitForReport(check.scan_run.id);
  console.log(`    verdict: ${report.verdict_status} (fail_on ${report.fail_on})`);
  console.log(`    findings by severity: ${formatCounts(report.by_severity)}`);
  const document: ReportDocument = await certone.getReportDocument(report.id);
  console.log(`[3] report ${report.id} (${document.report_id}): ${document.summary.total_issues} issue(s)`);
  const [first] = document.issues;
  if (first) {
    console.log(`    first finding: [${first.severity}] ${first.compliance_topic ?? "general"} ${first.issue_id}`);
    console.log(`      ${first.description}`);
  } else {
    console.log("    no findings");
  }

  // 4. Run-at-source: submit a report computed where the model lives, bound to the snapshot bytes.
  const digest = await inputDigest(snapshot);
  const ingested = await certone.ingestReport(atSourceReport, {
    environment: "edge",
    countryCode: "EU",
    inputDigest: digest,
  });
  if (!ingested.report) throw new Error("the control plane returned no report for the ingested result");
  console.log(`[4] ingest: scan ${ingested.scan_run.id}, report ${ingested.report.id}`);
  console.log(`    verdict: ${ingested.report.verdict_status} (input_digest ${digest})`);

  // 5. The attestation issued for the passing, ingested report.
  const attestation: Attestation = await certone.getAttestation(ingested.report.id);
  console.log(`[5] attestation_id: ${attestation.attestation_id}`);
  console.log(`    input_version: ${attestation.input_version}`);
  console.log(`    signature_algorithm: ${attestation.signature_algorithm}`);

  // 6. The tenant's AI-system inventory.
  const systems = await certone.listSystems();
  console.log(`[6] systems: ${systems.length} AI system(s) in the tenant`);

  // 7. Success.
  console.log("[7] quickstart complete");
}

main().catch((err: unknown) => {
  if (CertOneError.is(err)) {
    const status = err.status === null ? "" : ` status=${err.status}`;
    console.error(`quickstart failed: [${err.kind}${status}] ${err.message}`);
  } else {
    console.error(`quickstart failed: ${err instanceof Error ? err.message : String(err)}`);
  }
  process.exitCode = 1;
});
