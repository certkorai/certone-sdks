//! Submission inputs: the snapshot, scan options and run-at-source ingest options.

use std::fmt;
use std::path::Path;
use std::sync::Arc;

use serde::Serialize;
use sha2::{Digest, Sha256};

/// Where a scan ran or was submitted from (`environment` form field).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Environment {
    /// Continuous integration.
    Ci,
    /// Jupyter notebook.
    Jupyter,
    /// VS Code extension.
    Vscode,
    /// Edge / embedded device.
    Edge,
    /// Direct API call (the server default).
    Api,
    /// Cloud runtime.
    Cloud,
    /// Command line.
    Cli,
}

impl Environment {
    /// The wire value.
    pub fn as_str(self) -> &'static str {
        match self {
            Environment::Ci => "ci",
            Environment::Jupyter => "jupyter",
            Environment::Vscode => "vscode",
            Environment::Edge => "edge",
            Environment::Api => "api",
            Environment::Cloud => "cloud",
            Environment::Cli => "cli",
        }
    }
}

impl fmt::Display for Environment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for Environment {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// Lowest finding severity that fails the verdict (`fail_on` form field).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FailOn {
    /// Fail on any finding.
    Low,
    /// Fail on medium or high findings.
    Medium,
    /// Fail on high findings (the server default).
    High,
    /// Never fail the verdict (report only).
    None,
}

impl FailOn {
    /// The wire value.
    pub fn as_str(self) -> &'static str {
        match self {
            FailOn::Low => "low",
            FailOn::Medium => "medium",
            FailOn::High => "high",
            FailOn::None => "none",
        }
    }
}

impl fmt::Display for FailOn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Optional form fields for `submit_check` / `submit_process`. Unset fields use server defaults.
///
/// ```
/// use certone::{Environment, FailOn, ScanOptions};
///
/// let options = ScanOptions::new()
///     .asset("Fraud Scorer")
///     .environment(Environment::Ci)
///     .country_code("EU")
///     .fail_on(FailOn::High)
///     .snapshot_ref("git:acme/fraud@4f2a9c1");
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanOptions {
    asset: Option<String>,
    environment: Option<Environment>,
    country_code: Option<String>,
    fail_on: Option<FailOn>,
    packs: Vec<String>,
    snapshot_ref: Option<String>,
    commit_hash: Option<String>,
    tee: Option<String>,
}

impl ScanOptions {
    /// Empty options: every field takes its server default.
    pub fn new() -> Self {
        Self::default()
    }

    /// AI system name (auto-registered on first scan).
    pub fn asset(mut self, asset: impl Into<String>) -> Self {
        self.asset = Some(asset.into());
        self
    }

    /// Environment the scan is submitted from (default `api`).
    pub fn environment(mut self, environment: Environment) -> Self {
        self.environment = Some(environment);
        self
    }

    /// Origin region, for example `EU` or `US` (default `ZZ`).
    pub fn country_code(mut self, country_code: impl Into<String>) -> Self {
        self.country_code = Some(country_code.into());
        self
    }

    /// Severity threshold that fails the verdict (default `high`).
    pub fn fail_on(mut self, fail_on: FailOn) -> Self {
        self.fail_on = Some(fail_on);
        self
    }

    /// Add one policy pack (default: auto-matched from the AI BOM).
    pub fn pack(mut self, pack: impl Into<String>) -> Self {
        self.packs.push(pack.into());
        self
    }

    /// Add several policy packs.
    pub fn packs<I, S>(mut self, packs: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.packs.extend(packs.into_iter().map(Into::into));
        self
    }

    /// Stable source reference, for example `git:org/repo@sha`.
    pub fn snapshot_ref(mut self, snapshot_ref: impl Into<String>) -> Self {
        self.snapshot_ref = Some(snapshot_ref.into());
        self
    }

    /// Commit the scan is about.
    pub fn commit_hash(mut self, commit_hash: impl Into<String>) -> Self {
        self.commit_hash = Some(commit_hash.into());
        self
    }

    /// Confidential-compute backend (default `amd_sev_snp`). Sent by `submit_process` only.
    pub fn tee(mut self, tee: impl Into<String>) -> Self {
        self.tee = Some(tee.into());
        self
    }

    /// The multipart form fields for these options, in a stable order.
    pub(crate) fn form_fields(&self, include_tee: bool) -> Vec<(&'static str, String)> {
        let mut fields = Vec::new();
        if let Some(v) = &self.asset {
            fields.push(("asset", v.clone()));
        }
        if let Some(v) = self.environment {
            fields.push(("environment", v.as_str().to_string()));
        }
        if let Some(v) = &self.country_code {
            fields.push(("country_code", v.clone()));
        }
        if let Some(v) = self.fail_on {
            fields.push(("fail_on", v.as_str().to_string()));
        }
        let packs: Vec<&str> = self
            .packs
            .iter()
            .map(|p| p.trim())
            .filter(|p| !p.is_empty())
            .collect();
        if !packs.is_empty() {
            fields.push(("packs", packs.join(",")));
        }
        if let Some(v) = &self.snapshot_ref {
            fields.push(("snapshot_ref", v.clone()));
        }
        if let Some(v) = &self.commit_hash {
            fields.push(("commit_hash", v.clone()));
        }
        if include_tee {
            if let Some(v) = &self.tee {
                fields.push(("tee", v.clone()));
            }
        }
        fields
    }
}

/// Optional fields for `ingest_report` (`POST /v1/checks/report`). Unset fields use server
/// defaults (`environment=api`, `country_code=ZZ`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct IngestOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    asset: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    environment: Option<Environment>,
    #[serde(skip_serializing_if = "Option::is_none")]
    country_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    snapshot_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    input_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    repo: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    commit_hash: Option<String>,
}

impl IngestOptions {
    /// Empty options: every field takes its server default.
    pub fn new() -> Self {
        Self::default()
    }

    /// AI system name (auto-registered on first submission).
    pub fn asset(mut self, asset: impl Into<String>) -> Self {
        self.asset = Some(asset.into());
        self
    }

    /// Environment the report was computed in.
    pub fn environment(mut self, environment: Environment) -> Self {
        self.environment = Some(environment);
        self
    }

    /// Origin region, for example `EU`.
    pub fn country_code(mut self, country_code: impl Into<String>) -> Self {
        self.country_code = Some(country_code.into());
        self
    }

    /// Stable source reference, for example `git:org/repo@sha`.
    pub fn snapshot_ref(mut self, snapshot_ref: impl Into<String>) -> Self {
        self.snapshot_ref = Some(snapshot_ref.into());
        self
    }

    /// Pre-computed digest in the form `sha256:<hex>`. Prefer [`IngestOptions::input_digest_of`].
    pub fn input_digest(mut self, input_digest: impl Into<String>) -> Self {
        self.input_digest = Some(input_digest.into());
        self
    }

    /// Bind the attestation to `bytes` (the artifact the report covers) via its SHA-256 digest.
    pub fn input_digest_of(self, bytes: &[u8]) -> Self {
        self.input_digest(sha256_digest(bytes))
    }

    /// GitHub repository full name, for example `org/repo`.
    pub fn repo(mut self, repo: impl Into<String>) -> Self {
        self.repo = Some(repo.into());
        self
    }

    /// Commit the report is about.
    pub fn commit_hash(mut self, commit_hash: impl Into<String>) -> Self {
        self.commit_hash = Some(commit_hash.into());
        self
    }
}

/// The `input_digest` of `bytes`: `sha256:` followed by the lowercase hex SHA-256.
pub fn sha256_digest(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let hash = Sha256::digest(bytes);
    let mut out = String::with_capacity(7 + hash.len() * 2);
    out.push_str("sha256:");
    for byte in hash {
        // Writing into a String cannot fail.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// A project snapshot (`.tar.gz`) to upload. Cheap to clone: the bytes are shared.
#[derive(Clone)]
pub struct Snapshot {
    file_name: String,
    data: Arc<[u8]>,
}

impl Snapshot {
    /// Read a snapshot from disk; the upload keeps the file's name.
    pub fn from_path(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref();
        let data = std::fs::read(path)?;
        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "snapshot.tar.gz".to_string());
        Ok(Self::from_bytes(file_name, data))
    }

    /// Wrap in-memory snapshot bytes under the given upload file name.
    pub fn from_bytes(file_name: impl Into<String>, data: impl Into<Arc<[u8]>>) -> Self {
        Self {
            file_name: file_name.into(),
            data: data.into(),
        }
    }

    /// Upload file name.
    pub fn file_name(&self) -> &str {
        &self.file_name
    }

    /// Snapshot bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.data
    }

    /// The snapshot's `input_digest` (`sha256:<hex>`), for binding a run-at-source attestation.
    pub fn input_digest(&self) -> String {
        sha256_digest(&self.data)
    }

    pub(crate) fn shared_bytes(&self) -> Arc<[u8]> {
        Arc::clone(&self.data)
    }
}

impl fmt::Debug for Snapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Snapshot")
            .field("file_name", &self.file_name)
            .field("len", &self.data.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_options_send_no_fields() {
        assert!(ScanOptions::new().form_fields(true).is_empty());
    }

    #[test]
    fn options_map_to_form_fields_in_order() {
        let options = ScanOptions::new()
            .asset("Fraud Scorer")
            .environment(Environment::Edge)
            .country_code("EU")
            .fail_on(FailOn::Medium)
            .packs(["eu-ai-act-core", " "])
            .pack("gdpr-core")
            .snapshot_ref("git:acme/fraud@abc")
            .commit_hash("abc")
            .tee("intel_tdx");
        let fields = options.form_fields(true);
        let expected: Vec<(&str, String)> = vec![
            ("asset", "Fraud Scorer".into()),
            ("environment", "edge".into()),
            ("country_code", "EU".into()),
            ("fail_on", "medium".into()),
            ("packs", "eu-ai-act-core,gdpr-core".into()),
            ("snapshot_ref", "git:acme/fraud@abc".into()),
            ("commit_hash", "abc".into()),
            ("tee", "intel_tdx".into()),
        ];
        assert_eq!(fields, expected);
    }

    #[test]
    fn tee_is_only_sent_when_requested() {
        let options = ScanOptions::new().tee("amd_sev_snp");
        assert!(options.form_fields(false).is_empty());
        assert_eq!(
            options.form_fields(true),
            vec![("tee", "amd_sev_snp".to_string())]
        );
    }

    #[test]
    fn enum_wire_values() {
        let envs = [
            (Environment::Ci, "ci"),
            (Environment::Jupyter, "jupyter"),
            (Environment::Vscode, "vscode"),
            (Environment::Edge, "edge"),
            (Environment::Api, "api"),
            (Environment::Cloud, "cloud"),
            (Environment::Cli, "cli"),
        ];
        for (env, wire) in envs {
            assert_eq!(env.as_str(), wire);
            assert_eq!(env.to_string(), wire);
        }
        let fails = [
            (FailOn::Low, "low"),
            (FailOn::Medium, "medium"),
            (FailOn::High, "high"),
            (FailOn::None, "none"),
        ];
        for (fail_on, wire) in fails {
            assert_eq!(fail_on.as_str(), wire);
        }
    }

    #[test]
    fn ingest_options_skip_unset_fields() {
        let json = serde_json::to_value(IngestOptions::new()).unwrap_or_default();
        assert_eq!(json, serde_json::json!({}));
        let json = serde_json::to_value(
            IngestOptions::new()
                .asset("Edge Model")
                .environment(Environment::Edge)
                .country_code("EU")
                .input_digest("sha256:00")
                .repo("org/repo")
                .commit_hash("abc")
                .snapshot_ref("git:org/repo@abc"),
        )
        .unwrap_or_default();
        assert_eq!(
            json,
            serde_json::json!({
                "asset": "Edge Model",
                "environment": "edge",
                "country_code": "EU",
                "snapshot_ref": "git:org/repo@abc",
                "input_digest": "sha256:00",
                "repo": "org/repo",
                "commit_hash": "abc"
            })
        );
    }

    #[test]
    fn sha256_digest_matches_known_vectors() {
        assert_eq!(
            sha256_digest(b""),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_digest(b"abc"),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let snapshot = Snapshot::from_bytes("s.tar.gz", b"abc".to_vec());
        assert_eq!(snapshot.input_digest(), sha256_digest(b"abc"));
        assert_eq!(
            IngestOptions::new().input_digest_of(b"abc"),
            IngestOptions::new().input_digest(sha256_digest(b"abc"))
        );
    }

    #[test]
    fn snapshot_debug_hides_bytes() {
        let snapshot = Snapshot::from_bytes("s.tar.gz", vec![1u8, 2, 3]);
        assert_eq!(
            format!("{snapshot:?}"),
            r#"Snapshot { file_name: "s.tar.gz", len: 3 }"#
        );
    }
}
