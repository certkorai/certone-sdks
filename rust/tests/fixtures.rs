//! Every conformance fixture (real control-plane responses) deserializes into the SDK's types.

use certone::{AiSystem, CheckResult, Error, Report, ScanRun};
use serde_json::Value;

const CHECK_RESULT: &str = include_str!("../../conformance/fixtures/check_result.json");
const INGEST_RESULT: &str = include_str!("../../conformance/fixtures/ingest_result.json");
const SCAN: &str = include_str!("../../conformance/fixtures/scan.json");
const REPORT: &str = include_str!("../../conformance/fixtures/report.json");
const REPORT_DOCUMENT: &str =
    include_str!("../../conformance/fixtures/report_document_excerpt.json");
const ATTESTATION: &str = include_str!("../../conformance/fixtures/attestation.json");
const SYSTEMS: &str = include_str!("../../conformance/fixtures/systems.json");

fn parse<T: serde::de::DeserializeOwned>(name: &str, text: &str) -> T {
    match serde_json::from_str(text) {
        Ok(v) => v,
        Err(e) => panic!("{name}: {e}"),
    }
}

#[test]
fn check_result_fixture() {
    let result: CheckResult = parse("check_result", CHECK_RESULT);
    assert_eq!(result.scan_run.id, "64ff3a4afb5e40f5b8ae5e38071c9145");
    assert_eq!(result.scan_run.kind, "check");
    assert!(result.scan_run.is_succeeded());
    assert!(result.scan_run.is_terminal());
    assert_eq!(result.scan_run.snapshot_ref, None);
    assert_eq!(result.scan_run.error, None);
    assert!(!result.queued);
    let report = result.require_report().cloned();
    let report = match report {
        Ok(r) => r,
        Err(e) => panic!("{e}"),
    };
    assert_eq!(report.id, "88b35a6b07bb456aa5159c32831f6bf4");
    assert_eq!(report.verdict_status, "fail");
    assert!(!report.passed());
    assert_eq!(report.fail_on, "high");
    assert_eq!(report.total_issues, 6);
    assert_eq!(report.by_severity.get("high"), Some(&3));
    assert_eq!(report.by_severity.get("medium"), Some(&3));
    assert_eq!(report.by_severity.get("low"), Some(&0));
    assert_eq!(report.country_code.as_deref(), Some("ZZ"));
    assert!(result.extra.is_empty());
}

#[test]
fn ingest_result_fixture() {
    let result: CheckResult = parse("ingest_result", INGEST_RESULT);
    let report = match result.report {
        Some(r) => r,
        None => panic!("ingest result has a report"),
    };
    assert_eq!(report.verdict_status, "pass");
    assert!(report.passed());
    assert_eq!(report.report_id, "rat-sdk-0001");
    assert_eq!(report.total_issues, 0);
    assert!(report.by_severity.is_empty());
    assert_eq!(report.country_code.as_deref(), Some("EU"));
}

#[test]
fn scan_fixture() {
    let scan: ScanRun = parse("scan", SCAN);
    assert_eq!(scan.id, "64ff3a4afb5e40f5b8ae5e38071c9145");
    assert_eq!(scan.status, ScanRun::SUCCEEDED);
    assert_eq!(
        scan.created_by.as_deref(),
        Some("apikey:3a58fad90b314f52a37068c0c3d80e32")
    );
    assert_eq!(
        scan.finished_at.as_deref(),
        Some("2026-11-08T19:43:23.167688")
    );
}

#[test]
fn report_fixture() {
    let report: Report = parse("report", REPORT);
    assert_eq!(report.scan_run_id, "64ff3a4afb5e40f5b8ae5e38071c9145");
    assert_eq!(report.report_id, "report-bce1fa3cd2cd");
    assert_eq!(report.created_at, "2026-11-08T19:43:23.168877");
}

#[test]
fn report_document_fixture_is_raw_json() {
    let doc: Value = parse("report_document_excerpt", REPORT_DOCUMENT);
    assert_eq!(doc["verdict"]["status"], "fail");
    assert_eq!(doc["summary"]["total_issues"], 6);
    let issues = doc["issues"].as_array().map(Vec::len);
    assert_eq!(issues, Some(1));
    assert_eq!(doc["issues"][0]["issue_id"], "iss-0001");
    assert_eq!(doc["issues"][0]["severity"], "high");
}

#[test]
fn attestation_fixture_is_raw_json() {
    let att: Value = parse("attestation", ATTESTATION);
    assert_eq!(
        att["attestation_id"],
        "att-43d463ff6d874d1a92be85ed768b762f"
    );
    assert_eq!(att["input_version"], "1.0");
    assert_eq!(att["signature_algorithm"], "HMAC-SHA256");
    assert_eq!(att["test_status"]["status"], "Passed");
}

#[test]
fn systems_fixture() {
    let systems: Vec<AiSystem> = parse("systems", SYSTEMS);
    assert_eq!(systems.len(), 3);
    let edge = &systems[0];
    assert_eq!(edge.slug, "sdk-edge-model");
    assert_eq!(edge.name, "SDK Edge Model");
    assert_eq!(edge.regions, vec!["EU"]);
    assert_eq!(edge.environments, vec!["edge"]);
    assert_eq!(edge.standards.len(), 5);
    assert!(edge.attested);
    assert_eq!(edge.attestation_status.as_deref(), Some("valid"));
    assert_eq!(edge.last_verdict.as_deref(), Some("pass"));
    assert_eq!(systems[1].open_issues, 6);
    assert_eq!(systems[1].risk.as_deref(), Some("high"));
    assert!(systems.iter().all(|s| s.extra.is_empty()));
}

#[test]
fn unknown_fields_are_tolerated_and_kept() {
    let mut value: Value = parse("check_result", CHECK_RESULT);
    value["jobs"] = serde_json::json!({"analysis": 1});
    value["scan_run"]["region"] = Value::from("eu-west-1");
    let result: CheckResult = parse("extended", &value.to_string());
    assert_eq!(
        result.extra.get("jobs"),
        Some(&serde_json::json!({"analysis": 1}))
    );
    assert_eq!(
        result.scan_run.extra.get("region"),
        Some(&Value::from("eu-west-1"))
    );
}

#[test]
fn queued_result_has_no_report() {
    let mut value: Value = parse("check_result", CHECK_RESULT);
    value["report"] = Value::Null;
    value["queued"] = Value::Bool(true);
    value["scan_run"]["status"] = Value::from("queued");
    let result: CheckResult = parse("queued", &value.to_string());
    assert!(result.queued);
    assert!(!result.scan_run.is_terminal());
    match result.require_report() {
        Err(Error::Queued { scan_id }) => assert_eq!(scan_id, result.scan_run.id),
        other => panic!("expected Queued, got {other:?}"),
    }
}
