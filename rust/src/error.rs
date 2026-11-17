//! The single error type every CertOne operation returns.

use std::time::Duration;

/// Longest API error body kept verbatim in [`Error::Api`] when the response is not JSON.
const MAX_DETAIL_CHARS: usize = 2048;

/// Result alias used throughout the crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// A CertOne API call failed.
///
/// HTTP failures (status >= 400) carry the status code and the API's `detail` message; network
/// failures and timeouts surface as [`Error::Transport`]. Use [`Error::status`] and
/// [`Error::detail`] to inspect an error without matching on every variant.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The control plane answered with an HTTP status >= 400.
    #[error("HTTP {status}: {detail}")]
    Api {
        /// HTTP status code, for example 401, 404 or 422.
        status: u16,
        /// The API's `detail` message (validation errors are rendered as compact JSON).
        detail: String,
    },

    /// The request never produced an HTTP response: DNS, connect, TLS, I/O or timeout failure.
    #[error("transport error: {message}")]
    Transport {
        /// Human-readable description of the failure.
        message: String,
        /// `true` when the connect or request timeout elapsed.
        timeout: bool,
        /// The underlying error.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },

    /// A 2xx response body was not the JSON shape this SDK expects.
    #[error("invalid response body (HTTP {status}): {message}")]
    Decode {
        /// HTTP status of the response that could not be decoded.
        status: u16,
        /// What went wrong while decoding.
        message: String,
    },

    /// `wait_for_report` saw the scan finish with status `failed`.
    #[error("scan {scan_id} failed: {message}")]
    ScanFailed {
        /// The scan run id.
        scan_id: String,
        /// The scan's `error` field.
        message: String,
    },

    /// `wait_for_report` gave up before the scan reached a terminal status.
    #[error("scan {scan_id} did not finish within {waited:?} (last status: {last_status})")]
    WaitTimeout {
        /// The scan run id.
        scan_id: String,
        /// How long the SDK waited.
        waited: Duration,
        /// The last status the control plane reported.
        last_status: String,
    },

    /// The control plane accepted the submission but queued it, so no report is available yet.
    #[error("submission {scan_id} was queued; poll it with wait_for_report")]
    Queued {
        /// The scan run id to poll.
        scan_id: String,
    },

    /// Reading a local input (for example the snapshot file) failed.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The client was configured with an invalid base URL, token or option.
    #[error("invalid configuration: {0}")]
    Config(String),
}

impl Error {
    /// HTTP status code, when the control plane answered.
    pub fn status(&self) -> Option<u16> {
        match self {
            Error::Api { status, .. } | Error::Decode { status, .. } => Some(*status),
            _ => None,
        }
    }

    /// The API's `detail` message, for [`Error::Api`].
    pub fn detail(&self) -> Option<&str> {
        match self {
            Error::Api { detail, .. } => Some(detail),
            _ => None,
        }
    }

    /// `true` for HTTP 404 (unknown id, or no attestation because the verdict did not pass).
    pub fn is_not_found(&self) -> bool {
        self.status() == Some(404)
    }

    /// `true` for HTTP 401 / 403.
    pub fn is_auth(&self) -> bool {
        matches!(self.status(), Some(401) | Some(403))
    }

    /// `true` when a network timeout or the `wait_for_report` deadline elapsed.
    pub fn is_timeout(&self) -> bool {
        matches!(
            self,
            Error::Transport { timeout: true, .. } | Error::WaitTimeout { .. }
        )
    }

    pub(crate) fn transport(err: reqwest::Error) -> Self {
        let timeout = err.is_timeout();
        let message = if timeout {
            format!("timed out: {err}")
        } else if err.is_connect() {
            format!("could not connect: {err}")
        } else {
            err.to_string()
        };
        Error::Transport {
            message,
            timeout,
            source: Box::new(err),
        }
    }

    pub(crate) fn api(status: u16, body: &[u8]) -> Self {
        Error::Api {
            status,
            detail: extract_detail(status, body),
        }
    }
}

/// Pull the API's `detail` out of an error body.
///
/// FastAPI answers `{"detail": "..."}` for application errors and `{"detail": [...]}` for request
/// validation errors; anything else (a proxy's HTML page, an empty body) is kept as bounded text.
pub(crate) fn extract_detail(status: u16, body: &[u8]) -> String {
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) {
        match value.get("detail") {
            Some(serde_json::Value::String(s)) => return s.clone(),
            Some(serde_json::Value::Null) | None => {}
            Some(other) => return other.to_string(),
        }
    }
    let text = String::from_utf8_lossy(body);
    let text = text.trim();
    if text.is_empty() {
        return reqwest::StatusCode::from_u16(status)
            .ok()
            .and_then(|s| s.canonical_reason())
            .unwrap_or("request failed")
            .to_string();
    }
    if text.chars().count() > MAX_DETAIL_CHARS {
        let truncated: String = text.chars().take(MAX_DETAIL_CHARS).collect();
        format!("{truncated}...")
    } else {
        text.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_detail_is_extracted() {
        let e = Error::api(404, br#"{"detail":"scan not found"}"#);
        assert_eq!(e.status(), Some(404));
        assert_eq!(e.detail(), Some("scan not found"));
        assert!(e.is_not_found());
        assert_eq!(e.to_string(), "HTTP 404: scan not found");
    }

    #[test]
    fn validation_detail_is_rendered_as_json() {
        let body =
            br#"{"detail":[{"type":"missing","loc":["body","report"],"msg":"Field required"}]}"#;
        let e = Error::api(422, body);
        let detail = e.detail().unwrap_or_default();
        assert!(detail.starts_with('['), "{detail}");
        assert!(detail.contains("Field required"));
    }

    #[test]
    fn non_json_body_is_kept_as_text() {
        let e = Error::api(502, b"  <html>Bad Gateway</html>\n");
        assert_eq!(e.detail(), Some("<html>Bad Gateway</html>"));
    }

    #[test]
    fn empty_body_falls_back_to_reason_phrase() {
        assert_eq!(extract_detail(503, b""), "Service Unavailable");
        assert_eq!(extract_detail(599, b""), "request failed");
    }

    #[test]
    fn json_without_detail_is_kept_as_text() {
        assert_eq!(extract_detail(500, br#"{"error":"x"}"#), r#"{"error":"x"}"#);
    }

    #[test]
    fn long_text_body_is_truncated() {
        let body = "x".repeat(MAX_DETAIL_CHARS + 50);
        let detail = extract_detail(500, body.as_bytes());
        assert_eq!(detail.chars().count(), MAX_DETAIL_CHARS + 3);
        assert!(detail.ends_with("..."));
    }

    #[test]
    fn auth_and_timeout_helpers() {
        assert!(Error::api(401, b"").is_auth());
        assert!(Error::api(403, b"").is_auth());
        assert!(!Error::api(500, b"").is_auth());
        let wait = Error::WaitTimeout {
            scan_id: "s".into(),
            waited: Duration::from_secs(1),
            last_status: "running".into(),
        };
        assert!(wait.is_timeout());
        assert_eq!(wait.status(), None);
    }
}
