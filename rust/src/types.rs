//! Typed control-plane responses.
//!
//! Every struct tolerates fields it does not model: they are kept in `extra` so a newer control
//! plane never breaks an older SDK, and callers can still read them.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::error::{Error, Result};

/// A scan run (`GET /v1/scans/{id}`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanRun {
    /// Scan run id; pass it to `get_scan` / `wait_for_report`.
    pub id: String,
    /// `check` or `process`.
    pub kind: String,
    /// `queued`, `running`, `succeeded` or `failed`.
    pub status: String,
    /// Stable source reference supplied at submission, for example `git:org/repo@sha`.
    #[serde(default)]
    pub snapshot_ref: Option<String>,
    /// Principal that submitted the scan, for example `apikey:<id>`.
    #[serde(default)]
    pub created_by: Option<String>,
    /// ISO-8601 creation timestamp.
    pub created_at: String,
    /// ISO-8601 completion timestamp, once finished.
    #[serde(default)]
    pub finished_at: Option<String>,
    /// Failure message when `status` is `failed`.
    #[serde(default)]
    pub error: Option<String>,
    /// Fields this SDK version does not model.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl ScanRun {
    /// Status of a scan that completed with a report.
    pub const SUCCEEDED: &'static str = "succeeded";
    /// Status of a scan that failed; see [`ScanRun::error`].
    pub const FAILED: &'static str = "failed";

    /// `true` once the scan is `succeeded` or `failed`.
    pub fn is_terminal(&self) -> bool {
        self.is_succeeded() || self.is_failed()
    }

    /// `true` when the scan completed with a report.
    pub fn is_succeeded(&self) -> bool {
        self.status == Self::SUCCEEDED
    }

    /// `true` when the scan failed.
    pub fn is_failed(&self) -> bool {
        self.status == Self::FAILED
    }
}

/// A report record (`GET /v1/scans/{id}/report`): the verdict summary of one scan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Report {
    /// Report record id; use it for `get_report_document` and `get_attestation`.
    pub id: String,
    /// The scan run that produced this report.
    pub scan_run_id: String,
    /// The engine's own report id string (not usable in API paths).
    pub report_id: String,
    /// `pass` or `fail`.
    pub verdict_status: String,
    /// Severity threshold the verdict was computed with.
    pub fail_on: String,
    /// Number of findings.
    pub total_issues: u64,
    /// Findings by severity (`low`, `medium`, `high`).
    #[serde(default)]
    pub by_severity: BTreeMap<String, u64>,
    /// Origin region of the scan.
    #[serde(default)]
    pub country_code: Option<String>,
    /// ISO-8601 creation timestamp.
    pub created_at: String,
    /// Fields this SDK version does not model.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Report {
    /// `true` when the verdict is `pass`.
    pub fn passed(&self) -> bool {
        self.verdict_status == "pass"
    }
}

/// Result of `submit_check`, `submit_process` and `ingest_report`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CheckResult {
    /// The scan run created by the submission.
    pub scan_run: ScanRun,
    /// The report, or `None` when the submission was queued to a worker pool.
    #[serde(default)]
    pub report: Option<Report>,
    /// `true` when the work was queued; poll `wait_for_report(scan_run.id)`.
    #[serde(default)]
    pub queued: bool,
    /// Fields this SDK version does not model (for `submit_process`: `jobs`, `health`, `energy`).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl CheckResult {
    /// The report, or [`Error::Queued`] when the submission was queued to a worker pool.
    pub fn require_report(&self) -> Result<&Report> {
        self.report.as_ref().ok_or_else(|| Error::Queued {
            scan_id: self.scan_run.id.clone(),
        })
    }
}

/// An AI system registered for the tenant (`GET /v1/systems`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AiSystem {
    /// System id.
    pub id: String,
    /// URL-safe identifier.
    pub slug: String,
    /// Display name (the `asset` given at submission).
    pub name: String,
    /// Lifecycle stage, for example `prod`.
    #[serde(default)]
    pub lifecycle: Option<String>,
    /// Owning team, if assigned.
    #[serde(default)]
    pub owner_team_id: Option<String>,
    /// Free-text description.
    #[serde(default)]
    pub description: Option<String>,
    /// ISO-8601 registration timestamp.
    #[serde(default)]
    pub created_at: Option<String>,
    /// Regions the system has been evaluated in.
    #[serde(default)]
    pub regions: Vec<String>,
    /// Environments the system has been evaluated in.
    #[serde(default)]
    pub environments: Vec<String>,
    /// Standards the system has been evaluated against.
    #[serde(default)]
    pub standards: Vec<String>,
    /// Number of scans.
    #[serde(default)]
    pub scans: u64,
    /// Open findings from the latest evaluation.
    #[serde(default)]
    pub open_issues: u64,
    /// Latest verdict (`pass` / `fail`).
    #[serde(default)]
    pub last_verdict: Option<String>,
    /// Whether a valid attestation exists.
    #[serde(default)]
    pub attested: bool,
    /// Attestation status, for example `valid` or `none`.
    #[serde(default)]
    pub attestation_status: Option<String>,
    /// Risk level, for example `low` or `high`.
    #[serde(default)]
    pub risk: Option<String>,
    /// ISO-8601 timestamp of the latest evaluation.
    #[serde(default)]
    pub last_evaluated: Option<String>,
    /// Fields this SDK version does not model.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}
