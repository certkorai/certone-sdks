// CertOne C++ SDK: an idiomatic C++17 wrapper over the CertOne C SDK (c, SPEC.md).
//
//   certone::Client client("https://api.example.com", api_key);
//   certone::Json result = client.submit_check(certone::Snapshot::file("project.tar.gz"));
//   std::cout << result.get_string("report.verdict_status") << "\n";
//
// Every failure throws certone::Error, which carries the C status code, the HTTP status (for
// HTTP errors) and the message (for HTTP errors: "HTTP <status>: <API detail>").
// A Client is movable, not copyable, and not thread-safe: use one per thread.
#ifndef CERTONE_HPP
#define CERTONE_HPP

#include <certone.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace certone {

/// Any failed SDK call: transport, timeout, HTTP status >= 300, failed scan, malformed JSON,
/// missing JSON path or wrong JSON type.
class Error : public std::runtime_error {
public:
    Error(certone_status status, long http_status, const std::string &message);

    /// The C SDK status code (CERTONE_E_HTTP, CERTONE_E_TIMEOUT, CERTONE_E_NOT_FOUND, ...).
    certone_status status() const noexcept { return status_; }
    /// The HTTP status of the failed response, or 0 when no response was received.
    long http_status() const noexcept { return http_status_; }

private:
    certone_status status_;
    long http_status_;
};

/// An immutable, validated JSON document (an API response) with path-based accessors.
/// Paths: "report.verdict_status", "issues[0].severity", "[1].name"; "" is the whole document.
class Json {
public:
    enum class Type { Null, Bool, Number, String, Array, Object };

    /// Validates text (throws Error with CERTONE_E_JSON if it is not a single JSON value).
    explicit Json(std::string text);

    /// The raw JSON text.
    const std::string &dump() const noexcept { return text_; }

    /// True if a value (including null) exists at path.
    bool has(const std::string &path) const;
    /// Type of the value at path (throws CERTONE_E_NOT_FOUND if absent).
    Type type(const std::string &path = "") const;

    // Required values: throw Error (CERTONE_E_NOT_FOUND / CERTONE_E_TYPE / CERTONE_E_RANGE).
    std::string get_string(const std::string &path) const;
    std::int64_t get_int(const std::string &path) const;
    double get_double(const std::string &path) const;
    bool get_bool(const std::string &path) const;

    // Optional values: std::nullopt when the path is absent or the value is null; throw Error
    // when the value exists with another type.
    std::optional<std::string> find_string(const std::string &path) const;
    std::optional<std::int64_t> find_int(const std::string &path) const;
    std::optional<double> find_double(const std::string &path) const;
    std::optional<bool> find_bool(const std::string &path) const;

    /// Number of elements of an array, or members of an object.
    std::size_t size(const std::string &path = "") const;
    /// Member names of the object at path, in document order.
    std::vector<std::string> keys(const std::string &path = "") const;
    /// The value at path as its own document.
    Json at(const std::string &path) const;

    /// Escape a single object key for use in a path ("a.b" -> "a\\.b").
    static std::string escape_key(std::string_view key);

private:
    std::string text_;
};

/// A project snapshot (.tar.gz) to upload.
struct Snapshot {
    std::string path;                    ///< file to stream from (when non-empty)
    std::string_view data;               ///< in-memory bytes, not copied (when path is empty)
    std::optional<std::string> filename; ///< multipart filename (default: basename or snapshot.tar.gz)

    static Snapshot file(std::string path);
    /// bytes must stay alive until the submit call returns.
    static Snapshot memory(std::string_view bytes, std::string filename = "snapshot.tar.gz");
};

/// Multipart form fields of submit_check / submit_process; unset fields use the server default.
struct ScanOptions {
    std::optional<std::string> asset;        ///< AI system name (auto-registered)
    std::optional<std::string> environment;  ///< ci|jupyter|vscode|edge|api|cloud|cli
    std::optional<std::string> country_code; ///< e.g. "EU" (default ZZ)
    std::optional<std::string> fail_on;      ///< low|medium|high|none (default high)
    std::optional<std::string> packs;        ///< comma-separated policy packs
    std::optional<std::string> snapshot_ref; ///< e.g. "git:org/repo@sha"
    std::optional<std::string> commit_hash;
    std::optional<std::string> tee; ///< submit_process only: confidential-compute backend
};

/// Run-at-source ingest fields; unset fields use the server default.
struct IngestOptions {
    std::optional<std::string> asset;
    std::optional<std::string> environment;  ///< default api
    std::optional<std::string> country_code; ///< default ZZ
    std::optional<std::string> snapshot_ref;
    std::optional<std::string> input_digest; ///< "sha256:<hex>", see input_digest_file()
    std::optional<std::string> repo;
    std::optional<std::string> commit_hash;
};

struct Config {
    std::string base_url;                ///< e.g. "https://api.example.com"
    std::optional<std::string> token;    ///< API key (ck_...) or OIDC ID token
    std::chrono::milliseconds connect_timeout{5000};
    std::chrono::milliseconds timeout{30000}; ///< whole request, including upload
    std::size_t max_response_bytes = 0;       ///< 0 = 64 MiB
    std::optional<std::string> ca_bundle_path;
    std::optional<std::string> user_agent;
};

class Client {
public:
    explicit Client(const Config &config);
    Client(std::string base_url, std::string token);
    ~Client();
    Client(Client &&other) noexcept;
    Client &operator=(Client &&other) noexcept;
    Client(const Client &) = delete;
    Client &operator=(const Client &) = delete;

    /// POST /v1/checks -> CheckResult {scan_run, report, queued}.
    Json submit_check(const Snapshot &snapshot, const ScanOptions &options = {});
    /// POST /v1/process -> CheckResult (queued=true and report=null on the confidential pool).
    Json submit_process(const Snapshot &snapshot, const ScanOptions &options = {});
    /// GET /v1/scans/{id} -> ScanRun.
    Json get_scan(const std::string &scan_id);
    /// Poll the scan until it succeeded (-> Report) or failed (throws CERTONE_E_SCAN_FAILED
    /// with the scan's error); throws CERTONE_E_TIMEOUT after timeout.
    Json wait_for_report(const std::string &scan_id,
                         std::chrono::milliseconds timeout = std::chrono::minutes(15),
                         std::chrono::milliseconds interval = std::chrono::seconds(2));
    /// GET /v1/reports/{id}/document -> full engine report (id = the report record's "id").
    Json get_report_document(const std::string &report_id);
    /// GET /v1/reports/{id}/attestation (HTTP 404 when the verdict did not pass).
    Json get_attestation(const std::string &report_id);
    /// POST /v1/checks/report with a run-at-source engine report (must be a JSON object).
    Json ingest_report(const Json &report, const IngestOptions &options = {});
    /// GET /v1/systems -> array of AI systems.
    Json list_systems();

private:
    struct Deleter {
        void operator()(certone_client *c) const noexcept { certone_client_free(c); }
    };
    std::unique_ptr<certone_client, Deleter> client_;

    [[noreturn]] void raise(certone_status status) const;
    certone_client *handle() const;
};

/// "sha256:<hex>" over a buffer: the input_digest that binds an attestation to its input.
std::string input_digest(std::string_view bytes);
/// "sha256:<hex>" over a file's bytes (streamed); throws CERTONE_E_IO if unreadable.
std::string input_digest_file(const std::string &path);
/// Raw 32-byte SHA-256 digest.
std::vector<std::uint8_t> sha256(std::string_view bytes);
/// SDK version, e.g. "0.1.0".
std::string version();

} // namespace certone

#endif // CERTONE_HPP
