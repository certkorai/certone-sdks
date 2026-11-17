//! Rust client for the CertOne control-plane API.
//!
//! Submit AI compliance checks over a project snapshot, poll for the verdict, read the full engine
//! report, ingest reports computed at the source (the model never leaves your environment) and
//! fetch the conditional compliance attestation. The contract is `SPEC.md`, shared by every
//! CertOne SDK.
//!
//! ```no_run
//! use certone::{Client, FailOn, ScanOptions, Snapshot};
//!
//! let client = Client::new("https://api.yourco.com", std::env::var("CERTONE_API_KEY").unwrap_or_default())?;
//! let snapshot = Snapshot::from_path("project.tar.gz")?;
//! let result = client.submit_check(&snapshot, &ScanOptions::new().asset("Fraud Scorer").fail_on(FailOn::High))?;
//! let report = client.wait_for_report(
//!     &result.scan_run.id,
//!     certone::DEFAULT_WAIT_TIMEOUT,
//!     certone::DEFAULT_POLL_INTERVAL,
//! )?;
//! println!("verdict: {} ({} findings)", report.verdict_status, report.total_issues);
//! # Ok::<(), certone::Error>(())
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod client;
mod error;
mod options;
mod types;

pub use client::{
    Client, ClientBuilder, DEFAULT_CONNECT_TIMEOUT, DEFAULT_POLL_INTERVAL, DEFAULT_REQUEST_TIMEOUT,
    DEFAULT_WAIT_TIMEOUT,
};
pub use error::{Error, Result};
pub use options::{sha256_digest, Environment, FailOn, IngestOptions, ScanOptions, Snapshot};
pub use types::{AiSystem, CheckResult, Report, ScanRun};
