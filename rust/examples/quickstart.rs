//! CertOne Rust SDK quickstart: the 7-step conformance flow from `SPEC.md`.
//!
//! ```bash
//! CERTONE_API_URL=http://localhost:8088 CERTONE_API_KEY=ck_... \
//! CERTONE_SNAPSHOT=conformance/sample-project.tar.gz \
//! CERTONE_REPORT_JSON=conformance/run-at-source-report.json \
//!   cargo run --example quickstart
//! ```

use std::process::ExitCode;

use certone::{
    Client, Environment, FailOn, IngestOptions, ScanOptions, Snapshot, DEFAULT_POLL_INTERVAL,
    DEFAULT_WAIT_TIMEOUT,
};
use serde_json::Value;

type BoxError = Box<dyn std::error::Error>;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("quickstart failed: {e}");
            ExitCode::FAILURE
        }
    }
}

fn env(name: &str) -> Result<String, BoxError> {
    match std::env::var(name) {
        Ok(v) if !v.trim().is_empty() => Ok(v.trim().to_string()),
        _ => Err(format!("environment variable {name} is not set").into()),
    }
}

fn run() -> Result<(), BoxError> {
    // 1. Configuration from the environment (the API key is never printed).
    let api_url = env("CERTONE_API_URL")?;
    let api_key = env("CERTONE_API_KEY")?;
    let snapshot_path = env("CERTONE_SNAPSHOT")?;
    let report_path = env("CERTONE_REPORT_JSON")?;
    let client = Client::new(api_url, api_key)?;
    println!("CertOne Rust SDK quickstart against {}", client.base_url());

    // 2. Compliance check of the sample project.
    let snapshot = Snapshot::from_path(&snapshot_path)
        .map_err(|e| format!("reading snapshot {snapshot_path}: {e}"))?;
    let options = ScanOptions::new()
        .asset("Rust SDK quickstart")
        .fail_on(FailOn::High);
    let check = client.submit_check(&snapshot, &options)?;
    println!("[2] scan {} submitted", check.scan_run.id);
    if let Some(report) = &check.report {
        println!("[2] verdict: {}", report.verdict_status);
        let by_severity: Vec<String> = report
            .by_severity
            .iter()
            .map(|(severity, count)| format!("{severity}={count}"))
            .collect();
        println!(
            "[2] findings: {} ({})",
            report.total_issues,
            by_severity.join(", ")
        );
    } else {
        println!("[2] queued for the worker pool; waiting for the verdict");
    }

    // 3. Wait for the report, then read the full engine report.
    let report = client.wait_for_report(
        &check.scan_run.id,
        DEFAULT_WAIT_TIMEOUT,
        DEFAULT_POLL_INTERVAL,
    )?;
    println!(
        "[3] report {} ready: verdict {}",
        report.id, report.verdict_status
    );
    let document = client.get_report_document(&report.id)?;
    match document["issues"]
        .as_array()
        .and_then(|issues| issues.first())
    {
        Some(issue) => println!(
            "[3] first finding: {} [{}] {}: {}",
            text(&issue["issue_id"]),
            text(&issue["severity"]),
            text(&issue["compliance_topic"]),
            text(&issue["description"])
        ),
        None => println!("[3] the report has no findings"),
    }

    // 4. Run-at-source ingest, bound to the snapshot bytes by input_digest.
    let report_json = std::fs::read_to_string(&report_path)
        .map_err(|e| format!("reading report {report_path}: {e}"))?;
    let local_report: Value = serde_json::from_str(&report_json)
        .map_err(|e| format!("parsing report {report_path}: {e}"))?;
    let ingest_options = IngestOptions::new()
        .asset("Rust SDK quickstart")
        .environment(Environment::Edge)
        .country_code("EU")
        .input_digest(snapshot.input_digest());
    let ingest = client.ingest_report(&local_report, &ingest_options)?;
    let ingested = ingest.require_report()?;
    println!(
        "[4] ingested scan {}: verdict {}",
        ingest.scan_run.id, ingested.verdict_status
    );

    // 5. Attestation for the ingested report.
    let attestation = client.get_attestation(&ingested.id)?;
    println!(
        "[5] attestation_id={} input_version={} signature_algorithm={}",
        text(&attestation["attestation_id"]),
        text(&attestation["input_version"]),
        text(&attestation["signature_algorithm"])
    );

    // 6. AI systems inventory.
    let systems = client.list_systems()?;
    println!("[6] tenant has {} AI systems", systems.len());

    // 7. Success.
    println!("[7] quickstart OK");
    Ok(())
}

/// A JSON value as display text (strings unquoted, missing values as `-`).
fn text(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Null => "-".to_string(),
        other => other.to_string(),
    }
}
