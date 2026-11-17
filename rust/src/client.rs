//! The blocking control-plane client.

use std::fmt;
use std::io::Cursor;
use std::thread;
use std::time::{Duration, Instant};

use reqwest::blocking::multipart::{Form, Part};
use reqwest::blocking::{RequestBuilder, Response};
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION};
use reqwest::Url;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;

use crate::error::{Error, Result};
use crate::options::{IngestOptions, ScanOptions, Snapshot};
use crate::types::{AiSystem, CheckResult, Report, ScanRun};

/// Default TCP connect timeout.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Default whole-request timeout.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Default `wait_for_report` deadline.
pub const DEFAULT_WAIT_TIMEOUT: Duration = Duration::from_secs(900);
/// Default `wait_for_report` polling interval.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Shortest polling interval `wait_for_report` will use, so a zero interval cannot spin.
const MIN_POLL_INTERVAL: Duration = Duration::from_millis(100);

const USER_AGENT: &str = concat!("certone-rust/", env!("CARGO_PKG_VERSION"));

/// Configures and builds a [`Client`].
///
/// ```no_run
/// use std::time::Duration;
///
/// let client = certone::Client::builder("https://api.yourco.com", "ck_...")
///     .connect_timeout(Duration::from_secs(5))
///     .request_timeout(Duration::from_secs(60))
///     .build()?;
/// # Ok::<(), certone::Error>(())
/// ```
pub struct ClientBuilder {
    base_url: String,
    token: String,
    connect_timeout: Duration,
    request_timeout: Duration,
    user_agent: Option<String>,
}

impl ClientBuilder {
    /// TCP connect timeout (default 5 s).
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Whole-request timeout, including upload and response body (default 30 s).
    pub fn request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Prefix prepended to the SDK's `User-Agent`, for example `"acme-ci/2.3"`.
    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    /// Validate the configuration and build the client.
    pub fn build(self) -> Result<Client> {
        let base_url = parse_base_url(&self.base_url)?;
        let token = self.token.trim();
        if token.is_empty() {
            return Err(Error::Config("API token is empty".into()));
        }
        let mut auth = HeaderValue::from_str(&format!("Bearer {token}")).map_err(|_| {
            Error::Config("API token contains characters not allowed in an HTTP header".into())
        })?;
        auth.set_sensitive(true);
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, auth);
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        let user_agent = match self.user_agent {
            Some(prefix) => format!("{prefix} {USER_AGENT}"),
            None => USER_AGENT.to_string(),
        };
        let http = reqwest::blocking::Client::builder()
            .default_headers(headers)
            .user_agent(user_agent)
            .connect_timeout(self.connect_timeout)
            .timeout(self.request_timeout)
            .build()
            .map_err(|e| Error::Config(format!("could not build HTTP client: {e}")))?;
        Ok(Client {
            base_url,
            http,
            request_timeout: self.request_timeout,
        })
    }
}

impl fmt::Debug for ClientBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientBuilder")
            .field("base_url", &self.base_url)
            .field("token", &"<redacted>")
            .field("connect_timeout", &self.connect_timeout)
            .field("request_timeout", &self.request_timeout)
            .field("user_agent", &self.user_agent)
            .finish()
    }
}

/// Blocking client for the CertOne control-plane REST API.
///
/// Every request sends `Authorization: Bearer <token>`; the token is never logged or included in
/// `Debug` output. The client is cheap to clone and safe to share across threads.
#[derive(Clone)]
pub struct Client {
    base_url: Url,
    http: reqwest::blocking::Client,
    request_timeout: Duration,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client")
            .field("base_url", &self.base_url.as_str())
            .field("token", &"<redacted>")
            .field("request_timeout", &self.request_timeout)
            .finish()
    }
}

impl Client {
    /// A client with default timeouts (connect 5 s, request 30 s).
    ///
    /// `token` is a tenant API key (`ck_...`) or an OIDC ID token.
    pub fn new(base_url: impl Into<String>, token: impl Into<String>) -> Result<Self> {
        Self::builder(base_url, token).build()
    }

    /// Start configuring a client.
    pub fn builder(base_url: impl Into<String>, token: impl Into<String>) -> ClientBuilder {
        ClientBuilder {
            base_url: base_url.into(),
            token: token.into(),
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            user_agent: None,
        }
    }

    /// The control-plane base URL this client talks to.
    pub fn base_url(&self) -> &str {
        self.base_url.as_str()
    }

    /// Upload a snapshot and run a compliance check (`POST /v1/checks`).
    ///
    /// The `tee` option is not sent; use [`Client::submit_process`] for confidential processing.
    pub fn submit_check(&self, snapshot: &Snapshot, options: &ScanOptions) -> Result<CheckResult> {
        self.submit_multipart(&["v1", "checks"], snapshot, options.form_fields(false))
    }

    /// Upload a snapshot for confidential processing (`POST /v1/process`).
    ///
    /// On the confidential worker pool the result is `queued` with no report: poll it with
    /// [`Client::wait_for_report`].
    pub fn submit_process(
        &self,
        snapshot: &Snapshot,
        options: &ScanOptions,
    ) -> Result<CheckResult> {
        self.submit_multipart(&["v1", "process"], snapshot, options.form_fields(true))
    }

    /// Fetch a scan run (`GET /v1/scans/{id}`).
    pub fn get_scan(&self, scan_id: &str) -> Result<ScanRun> {
        self.get_json(&["v1", "scans", scan_id])
    }

    /// Poll a scan until it `succeeded` or `failed`, then return its report
    /// (`GET /v1/scans/{id}/report`).
    ///
    /// A `failed` scan returns [`Error::ScanFailed`] with the scan's `error`; exceeding `timeout`
    /// returns [`Error::WaitTimeout`]. Spec defaults: [`DEFAULT_WAIT_TIMEOUT`] and
    /// [`DEFAULT_POLL_INTERVAL`].
    pub fn wait_for_report(
        &self,
        scan_id: &str,
        timeout: Duration,
        interval: Duration,
    ) -> Result<Report> {
        let interval = interval.max(MIN_POLL_INTERVAL);
        let started = Instant::now();
        loop {
            let scan = self.get_scan(scan_id)?;
            if scan.is_succeeded() {
                return self.get_json(&["v1", "scans", scan_id, "report"]);
            }
            if scan.is_failed() {
                return Err(Error::ScanFailed {
                    scan_id: scan_id.to_string(),
                    message: scan
                        .error
                        .filter(|e| !e.trim().is_empty())
                        .unwrap_or_else(|| "the scan failed without an error message".into()),
                });
            }
            let elapsed = started.elapsed();
            if elapsed >= timeout {
                return Err(Error::WaitTimeout {
                    scan_id: scan_id.to_string(),
                    waited: elapsed,
                    last_status: scan.status,
                });
            }
            thread::sleep(interval.min(timeout - elapsed));
        }
    }

    /// The full engine report: `verdict`, `summary`, `issues[]` (`GET /v1/reports/{id}/document`).
    ///
    /// `report_id` is the report record's [`Report::id`], not the engine's `report_id` string.
    pub fn get_report_document(&self, report_id: &str) -> Result<Value> {
        self.get_json(&["v1", "reports", report_id, "document"])
    }

    /// The conditional compliance attestation (`GET /v1/reports/{id}/attestation`).
    ///
    /// Returns HTTP 404 ([`Error::is_not_found`]) when the verdict did not pass.
    pub fn get_attestation(&self, report_id: &str) -> Result<Value> {
        self.get_json(&["v1", "reports", report_id, "attestation"])
    }

    /// Run-at-source: submit an engine report computed where the model lives
    /// (`POST /v1/checks/report`). The model and code never leave the caller's environment.
    pub fn ingest_report(&self, report: &Value, options: &IngestOptions) -> Result<CheckResult> {
        #[derive(Serialize)]
        struct Body<'a> {
            report: &'a Value,
            #[serde(flatten)]
            options: &'a IngestOptions,
        }
        if !report.is_object() {
            return Err(Error::Config("the report must be a JSON object".into()));
        }
        let url = self.url(&["v1", "checks", "report"])?;
        let request = self.http.post(url).json(&Body { report, options });
        self.execute(request)
    }

    /// The tenant's AI systems (`GET /v1/systems`).
    pub fn list_systems(&self) -> Result<Vec<AiSystem>> {
        self.get_json(&["v1", "systems"])
    }

    fn submit_multipart(
        &self,
        path: &[&str],
        snapshot: &Snapshot,
        fields: Vec<(&'static str, String)>,
    ) -> Result<CheckResult> {
        let data = snapshot.shared_bytes();
        let len = data.len() as u64;
        let part = Part::reader_with_length(Cursor::new(data), len)
            .file_name(snapshot.file_name().to_string())
            .mime_str("application/gzip")
            .map_err(|e| Error::Config(format!("invalid snapshot content type: {e}")))?;
        let form = fields
            .into_iter()
            .fold(Form::new(), |form, (name, value)| form.text(name, value))
            .part("snapshot", part);
        let url = self.url(path)?;
        self.execute(self.http.post(url).multipart(form))
    }

    fn get_json<T: DeserializeOwned>(&self, path: &[&str]) -> Result<T> {
        let url = self.url(path)?;
        self.execute(self.http.get(url))
    }

    fn execute<T: DeserializeOwned>(&self, request: RequestBuilder) -> Result<T> {
        let response = request.send().map_err(Error::transport)?;
        decode(response)
    }

    /// Join path segments onto the base URL, percent-encoding each segment so ids cannot alter
    /// the request path.
    fn url(&self, segments: &[&str]) -> Result<Url> {
        if let Some(bad) = segments
            .iter()
            .find(|s| s.is_empty() || **s == "." || **s == "..")
        {
            return Err(Error::Config(format!(
                "invalid id in request path: {bad:?}"
            )));
        }
        let mut url = self.base_url.clone();
        url.path_segments_mut()
            .map_err(|()| Error::Config("base URL cannot carry a path".into()))?
            .pop_if_empty()
            .extend(segments);
        Ok(url)
    }
}

fn decode<T: DeserializeOwned>(response: Response) -> Result<T> {
    let status = response.status().as_u16();
    let body = response.bytes().map_err(Error::transport)?;
    if status >= 400 {
        return Err(Error::api(status, &body));
    }
    serde_json::from_slice(&body).map_err(|e| Error::Decode {
        status,
        message: e.to_string(),
    })
}

fn parse_base_url(raw: &str) -> Result<Url> {
    let raw = raw.trim();
    let url = Url::parse(raw).map_err(|e| Error::Config(format!("invalid base URL: {e}")))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(Error::Config(format!(
            "base URL must use http or https, not {:?}",
            url.scheme()
        )));
    }
    if url.cannot_be_a_base() || url.host_str().is_none() {
        return Err(Error::Config("base URL must include a host".into()));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(Error::Config(
            "base URL must not include a query or fragment".into(),
        ));
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(base: &str) -> Client {
        match Client::new(base, "ck_test_secret") {
            Ok(c) => c,
            Err(e) => panic!("client: {e}"),
        }
    }

    #[test]
    fn urls_join_and_encode_segments() {
        let c = client("http://localhost:8088");
        let url = c.url(&["v1", "scans", "abc"]).map(|u| u.to_string());
        assert_eq!(
            url.ok().as_deref(),
            Some("http://localhost:8088/v1/scans/abc")
        );

        let c = client("https://api.example.com/certone/");
        let url = c
            .url(&["v1", "scans", "../admin?x=1"])
            .map(|u| u.to_string());
        assert_eq!(
            url.ok().as_deref(),
            Some("https://api.example.com/certone/v1/scans/..%2Fadmin%3Fx=1")
        );
    }

    #[test]
    fn empty_ids_are_rejected() {
        let c = client("http://localhost:8088");
        for id in ["", ".", ".."] {
            assert!(matches!(c.get_scan(id), Err(Error::Config(_))), "{id:?}");
        }
    }

    #[test]
    fn invalid_configuration_is_rejected() {
        for base in [
            "",
            "localhost:8088",
            "ftp://x",
            "http://x?a=b",
            "mailto:a@b",
        ] {
            assert!(
                matches!(Client::new(base, "t"), Err(Error::Config(_))),
                "{base}"
            );
        }
        assert!(matches!(
            Client::new("http://x", "  "),
            Err(Error::Config(_))
        ));
        assert!(matches!(
            Client::new("http://x", "bad\ntoken"),
            Err(Error::Config(_))
        ));
    }

    #[test]
    fn debug_output_never_contains_the_token() {
        let c = client("http://localhost:8088");
        let builder = Client::builder("http://localhost:8088", "ck_test_secret");
        for text in [format!("{c:?}"), format!("{builder:?}")] {
            assert!(!text.contains("ck_test_secret"), "{text}");
            assert!(text.contains("<redacted>"));
        }
    }

    #[test]
    fn non_object_report_is_rejected_before_sending() {
        let c = client("http://127.0.0.1:9");
        let result = c.ingest_report(&Value::Null, &IngestOptions::new());
        assert!(matches!(result, Err(Error::Config(_))));
    }
}
