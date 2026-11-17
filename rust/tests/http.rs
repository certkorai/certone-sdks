//! Offline HTTP behaviour against a loopback server: request shape (auth, multipart fields, JSON
//! body, paths), error mapping, polling and timeouts. No control plane needed.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use certone::{
    Client, Environment, Error, FailOn, IngestOptions, ScanOptions, Snapshot, DEFAULT_WAIT_TIMEOUT,
};
use serde_json::{json, Value};

const TOKEN: &str = "ck_test_offline_token";
const CHECK_RESULT: &str = include_str!("../../conformance/fixtures/check_result.json");
const INGEST_RESULT: &str = include_str!("../../conformance/fixtures/ingest_result.json");
const REPORT: &str = include_str!("../../conformance/fixtures/report.json");

#[derive(Debug, Clone)]
struct Recorded {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Recorded {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// A one-request-per-connection HTTP/1.1 server answering from a script. The last scripted
/// response repeats once the script is exhausted.
struct MockServer {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    requests: Arc<Mutex<Vec<Recorded>>>,
    handle: Option<JoinHandle<()>>,
}

impl MockServer {
    fn start(script: Vec<(u16, String)>) -> Self {
        assert!(!script.is_empty());
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let (stop_t, requests_t) = (Arc::clone(&stop), Arc::clone(&requests));
        let handle = thread::spawn(move || {
            let mut served = 0usize;
            for stream in listener.incoming() {
                if stop_t.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(mut stream) = stream else { continue };
                let Some(request) = read_request(&mut stream) else {
                    continue;
                };
                requests_t.lock().expect("lock").push(request);
                let (status, body) = &script[served.min(script.len() - 1)];
                served += 1;
                let response = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });
        Self {
            addr,
            stop,
            requests,
            handle: Some(handle),
        }
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn client(&self) -> Client {
        Client::new(self.url(), TOKEN).expect("client")
    }

    fn finish(mut self) -> Vec<Recorded> {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
        if let Some(handle) = self.handle.take() {
            handle.join().expect("server thread");
        }
        let requests = self.requests.lock().expect("lock").clone();
        requests
    }
}

fn read_request(stream: &mut TcpStream) -> Option<Recorded> {
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();
    let mut headers = Vec::new();
    loop {
        let mut h = String::new();
        reader.read_line(&mut h).ok()?;
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        let (k, v) = h.split_once(':')?;
        headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
    }
    let header = |name: &str| {
        headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    };
    let mut body = Vec::new();
    if let Some(len) = header("content-length").and_then(|v| v.parse::<usize>().ok()) {
        body.resize(len, 0);
        reader.read_exact(&mut body).ok()?;
    } else if header("transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked")) {
        loop {
            let mut size = String::new();
            reader.read_line(&mut size).ok()?;
            let size = usize::from_str_radix(size.trim(), 16).ok()?;
            let mut chunk = vec![0u8; size + 2];
            reader.read_exact(&mut chunk).ok()?;
            if size == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..size]);
        }
    }
    Some(Recorded {
        method,
        path,
        headers,
        body,
    })
}

fn scan_json(status: &str, error: Option<&str>) -> String {
    json!({
        "id": "scan-1",
        "kind": "check",
        "status": status,
        "snapshot_ref": null,
        "created_by": "apikey:x",
        "created_at": "2026-11-08T19:43:23.105333",
        "finished_at": null,
        "error": error,
    })
    .to_string()
}

fn snapshot() -> Snapshot {
    Snapshot::from_bytes(
        "sample-project.tar.gz",
        b"\x1f\x8bfake-tarball-bytes".to_vec(),
    )
}

#[test]
fn submit_check_sends_auth_multipart_and_options() {
    let server = MockServer::start(vec![(201, CHECK_RESULT.to_string())]);
    let options = ScanOptions::new()
        .asset("Rust SDK quickstart")
        .environment(Environment::Ci)
        .country_code("EU")
        .fail_on(FailOn::High)
        .packs(["iso-42001-core", "eu-ai-act-core"])
        .snapshot_ref("git:org/repo@abc")
        .commit_hash("abc")
        .tee("intel_tdx");
    let result = server
        .client()
        .submit_check(&snapshot(), &options)
        .expect("check");
    assert_eq!(result.scan_run.id, "64ff3a4afb5e40f5b8ae5e38071c9145");

    let requests = server.finish();
    assert_eq!(requests.len(), 1);
    let r = &requests[0];
    assert_eq!(r.method, "POST");
    assert_eq!(r.path, "/v1/checks");
    assert_eq!(r.header("authorization"), Some(&*format!("Bearer {TOKEN}")));
    assert_eq!(r.header("accept"), Some("application/json"));
    assert!(r
        .header("user-agent")
        .is_some_and(|ua| ua.starts_with("certone-rust/")));
    assert!(r
        .header("content-type")
        .is_some_and(|ct| ct.starts_with("multipart/form-data; boundary=")));
    let body = r.body_text();
    for (name, value) in [
        ("asset", "Rust SDK quickstart"),
        ("environment", "ci"),
        ("country_code", "EU"),
        ("fail_on", "high"),
        ("packs", "iso-42001-core,eu-ai-act-core"),
        ("snapshot_ref", "git:org/repo@abc"),
        ("commit_hash", "abc"),
    ] {
        let field = format!("name=\"{name}\"\r\n\r\n{value}\r\n");
        assert!(body.contains(&field), "missing {name}: {body}");
    }
    assert!(!body.contains("name=\"tee\""), "check must not send tee");
    assert!(body.contains("name=\"snapshot\"; filename=\"sample-project.tar.gz\""));
    assert!(body.contains("Content-Type: application/gzip"));
    assert!(r
        .body
        .windows(b"fake-tarball-bytes".len())
        .any(|w| w == b"fake-tarball-bytes"));
}

#[test]
fn submit_process_sends_tee_and_handles_queued() {
    let mut queued: Value = serde_json::from_str(CHECK_RESULT).expect("fixture");
    queued["report"] = Value::Null;
    queued["queued"] = Value::Bool(true);
    queued["jobs"] = json!({});
    let server = MockServer::start(vec![(201, queued.to_string())]);
    let result = server
        .client()
        .submit_process(&snapshot(), &ScanOptions::new().tee("amd_sev_snp"))
        .expect("process");
    assert!(result.queued);
    assert!(result.report.is_none());
    assert!(matches!(result.require_report(), Err(Error::Queued { .. })));
    assert!(result.extra.contains_key("jobs"));

    let requests = server.finish();
    assert_eq!(requests[0].path, "/v1/process");
    assert!(requests[0]
        .body_text()
        .contains("name=\"tee\"\r\n\r\namd_sev_snp\r\n"));
}

#[test]
fn submit_check_without_options_sends_only_the_snapshot() {
    let server = MockServer::start(vec![(201, CHECK_RESULT.to_string())]);
    server
        .client()
        .submit_check(&snapshot(), &ScanOptions::new())
        .expect("check");
    let body = server.finish()[0].body_text();
    assert_eq!(body.matches("Content-Disposition: form-data").count(), 1);
}

#[test]
fn ingest_report_posts_json_body() {
    let server = MockServer::start(vec![(201, INGEST_RESULT.to_string())]);
    let report = json!({"report_id": "rat-1", "verdict": {"status": "pass"}, "issues": []});
    let options = IngestOptions::new()
        .asset("Edge Model")
        .environment(Environment::Edge)
        .country_code("EU")
        .input_digest_of(b"abc");
    let result = server
        .client()
        .ingest_report(&report, &options)
        .expect("ingest");
    assert_eq!(
        result
            .require_report()
            .map(|r| r.verdict_status.clone())
            .ok(),
        Some("pass".to_string())
    );

    let requests = server.finish();
    let r = &requests[0];
    assert_eq!(
        (r.method.as_str(), r.path.as_str()),
        ("POST", "/v1/checks/report")
    );
    assert_eq!(r.header("content-type"), Some("application/json"));
    let body: Value = serde_json::from_slice(&r.body).expect("json body");
    assert_eq!(
        body,
        json!({
            "report": report,
            "asset": "Edge Model",
            "environment": "edge",
            "country_code": "EU",
            "input_digest": "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        })
    );
}

#[test]
fn reads_hit_the_spec_paths() {
    let server = MockServer::start(vec![
        (200, scan_json("running", None)),
        (
            200,
            json!({"verdict": {"status": "fail"}, "issues": []}).to_string(),
        ),
        (200, json!({"attestation_id": "att-1"}).to_string()),
        (200, "[]".to_string()),
    ]);
    let client = server.client();
    assert_eq!(client.get_scan("scan-1").expect("scan").status, "running");
    assert_eq!(
        client.get_report_document("rep-1").expect("doc")["verdict"]["status"],
        "fail"
    );
    assert_eq!(
        client.get_attestation("rep-1").expect("att")["attestation_id"],
        "att-1"
    );
    assert!(client.list_systems().expect("systems").is_empty());
    let paths: Vec<String> = server.finish().into_iter().map(|r| r.path).collect();
    assert_eq!(
        paths,
        [
            "/v1/scans/scan-1",
            "/v1/reports/rep-1/document",
            "/v1/reports/rep-1/attestation",
            "/v1/systems",
        ]
    );
}

#[test]
fn ids_are_percent_encoded_in_paths() {
    let server = MockServer::start(vec![(200, scan_json("running", None))]);
    server.client().get_scan("a/b?c#d").expect("scan");
    assert_eq!(server.finish()[0].path, "/v1/scans/a%2Fb%3Fc%23d");
}

#[test]
fn http_errors_carry_status_and_detail() {
    let server = MockServer::start(vec![
        (404, r#"{"detail":"scan not found"}"#.to_string()),
        (
            404,
            r#"{"detail":"no attestation (the input did not pass, so none was issued)"}"#
                .to_string(),
        ),
        (
            422,
            r#"{"detail":[{"type":"missing","loc":["body","report"],"msg":"Field required"}]}"#
                .to_string(),
        ),
        (401, r#"{"detail":"missing bearer credential"}"#.to_string()),
        (500, "Internal Server Error".to_string()),
    ]);
    let client = server.client();

    let e = client.get_scan("nope").expect_err("404");
    assert_eq!(
        (e.status(), e.detail()),
        (Some(404), Some("scan not found"))
    );
    assert_eq!(e.to_string(), "HTTP 404: scan not found");

    let e = client.get_attestation("rep").expect_err("404");
    assert!(e.is_not_found());
    assert!(e.detail().is_some_and(|d| d.contains("did not pass")));

    let e = client
        .ingest_report(&json!({}), &IngestOptions::new())
        .expect_err("422");
    assert_eq!(e.status(), Some(422));
    assert!(e.detail().is_some_and(|d| d.contains("Field required")));

    let e = client.list_systems().expect_err("401");
    assert!(e.is_auth());

    let e = client.get_scan("x").expect_err("500");
    assert_eq!(
        (e.status(), e.detail()),
        (Some(500), Some("Internal Server Error"))
    );
    server.finish();
}

#[test]
fn malformed_success_body_is_a_decode_error() {
    let server = MockServer::start(vec![(200, "{\"not\": \"a scan\"}".to_string())]);
    let e = server.client().get_scan("x").expect_err("decode");
    assert!(matches!(e, Error::Decode { status: 200, .. }), "{e:?}");
    server.finish();
}

#[test]
fn wait_for_report_polls_until_succeeded() {
    let server = MockServer::start(vec![
        (200, scan_json("queued", None)),
        (200, scan_json("running", None)),
        (200, scan_json("succeeded", None)),
        (200, REPORT.to_string()),
    ]);
    let report = server
        .client()
        .wait_for_report("scan-1", DEFAULT_WAIT_TIMEOUT, Duration::ZERO)
        .expect("report");
    assert_eq!(report.verdict_status, "fail");
    let paths: Vec<String> = server.finish().into_iter().map(|r| r.path).collect();
    assert_eq!(
        paths,
        [
            "/v1/scans/scan-1",
            "/v1/scans/scan-1",
            "/v1/scans/scan-1",
            "/v1/scans/scan-1/report",
        ]
    );
}

#[test]
fn wait_for_report_surfaces_scan_failure() {
    let server = MockServer::start(vec![(
        200,
        scan_json("failed", Some("snapshot is not a tar.gz")),
    )]);
    let e = server
        .client()
        .wait_for_report("scan-1", DEFAULT_WAIT_TIMEOUT, Duration::from_millis(10))
        .expect_err("failed");
    match e {
        Error::ScanFailed { scan_id, message } => {
            assert_eq!(scan_id, "scan-1");
            assert_eq!(message, "snapshot is not a tar.gz");
        }
        other => panic!("expected ScanFailed, got {other:?}"),
    }
    server.finish();
}

#[test]
fn wait_for_report_times_out() {
    let server = MockServer::start(vec![(200, scan_json("running", None))]);
    let e = server
        .client()
        .wait_for_report(
            "scan-1",
            Duration::from_millis(250),
            Duration::from_millis(100),
        )
        .expect_err("timeout");
    assert!(e.is_timeout());
    match e {
        Error::WaitTimeout {
            scan_id,
            waited,
            last_status,
        } => {
            assert_eq!(scan_id, "scan-1");
            assert_eq!(last_status, "running");
            assert!(waited >= Duration::from_millis(250));
        }
        other => panic!("expected WaitTimeout, got {other:?}"),
    }
    assert!(server.finish().len() >= 2);
}

#[test]
fn connection_refused_is_a_transport_error() {
    let port = TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .expect("free port")
        .port();
    let client = Client::new(format!("http://127.0.0.1:{port}"), TOKEN).expect("client");
    let e = client.get_scan("x").expect_err("refused");
    assert!(
        matches!(e, Error::Transport { timeout: false, .. }),
        "{e:?}"
    );
    assert_eq!(e.status(), None);
    assert!(!e.to_string().contains(TOKEN));
}

#[test]
fn request_timeout_is_a_transport_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let silent = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let _ = read_request(&mut stream);
            thread::sleep(Duration::from_millis(1500));
        }
    });
    let client = Client::builder(format!("http://{addr}"), TOKEN)
        .request_timeout(Duration::from_millis(300))
        .build()
        .expect("client");
    let e = client.get_scan("x").expect_err("timeout");
    assert!(matches!(e, Error::Transport { timeout: true, .. }), "{e:?}");
    assert!(e.is_timeout());
    silent.join().expect("silent server");
}
