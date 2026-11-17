#!/usr/bin/env node
// CertOne JavaScript SDK quickstart: the 7-step conformance flow from SPEC.md.
//
//   CERTONE_API_URL=https://api.yourco.com CERTONE_API_KEY=ck_... \
//   CERTONE_SNAPSHOT=project.tar.gz CERTONE_REPORT_JSON=report.json node examples/quickstart.mjs
//
// Exits 0 on success, 1 with the error on any failure. The API key is never printed.
import { readFile } from "node:fs/promises";
import { basename } from "node:path";

import { CertOneClient, CertOneError, inputDigest } from "@certkor/certone";

function requireEnv(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not set`);
  return value;
}

function formatCounts(counts) {
  const entries = Object.entries(counts);
  return entries.length ? entries.map(([k, v]) => `${k}=${v}`).join(" ") : "none";
}

async function main() {
  // 1. Configuration from the environment.
  const apiUrl = requireEnv("CERTONE_API_URL");
  const snapshotPath = requireEnv("CERTONE_SNAPSHOT");
  const reportPath = requireEnv("CERTONE_REPORT_JSON");
  const certone = new CertOneClient({ baseUrl: apiUrl, token: requireEnv("CERTONE_API_KEY") });
  const snapshot = await readFile(snapshotPath);
  const atSourceReport = JSON.parse(await readFile(reportPath, "utf8"));
  console.log(`CertOne JavaScript SDK quickstart -> ${certone.baseUrl}`);

  // 2. Static compliance check of the sample project.
  const check = await certone.submitCheck(snapshot, {
    asset: "JavaScript SDK quickstart",
    failOn: "high",
    filename: basename(snapshotPath),
  });
  console.log(`[2] check: scan ${check.scan_run.id} (${check.queued ? "queued" : check.scan_run.status})`);
  if (check.report) {
    console.log(`    verdict: ${check.report.verdict_status} (fail_on ${check.report.fail_on})`);
    console.log(`    findings by severity: ${formatCounts(check.report.by_severity)}`);
  }

  // 3. Wait for the report, fetch the full document and show the first finding.
  const report = await certone.waitForReport(check.scan_run.id);
  if (!check.report) {
    console.log(`    verdict: ${report.verdict_status} (fail_on ${report.fail_on})`);
    console.log(`    findings by severity: ${formatCounts(report.by_severity)}`);
  }
  const document = await certone.getReportDocument(report.id);
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
  const attestation = await certone.getAttestation(ingested.report.id);
  console.log(`[5] attestation_id: ${attestation.attestation_id}`);
  console.log(`    input_version: ${attestation.input_version}`);
  console.log(`    signature_algorithm: ${attestation.signature_algorithm}`);

  // 6. The tenant's AI-system inventory.
  const systems = await certone.listSystems();
  console.log(`[6] systems: ${systems.length} AI system(s) in the tenant`);

  // 7. Success.
  console.log("[7] quickstart complete");
}

main().catch((err) => {
  if (CertOneError.is(err)) {
    const status = err.status === null ? "" : ` status=${err.status}`;
    console.error(`quickstart failed: [${err.kind}${status}] ${err.message}`);
  } else {
    console.error(`quickstart failed: ${err instanceof Error ? err.message : String(err)}`);
  }
  process.exitCode = 1;
});
