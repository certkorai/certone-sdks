// CertOne C++ SDK implementation: RAII + exceptions over the C core.
#include "certone/certone.hpp"

#include <cstdlib>
#include <utility>

namespace certone {

namespace {

// Owns a buffer returned by the C SDK.
struct CFree {
    void operator()(char *p) const noexcept { certone_free(p); }
};
using CString = std::unique_ptr<char, CFree>;

std::string take(char *p)
{
    CString owned(p);
    return owned ? std::string(owned.get()) : std::string();
}

// Strings handed to the C core are NUL-terminated: reject embedded NULs instead of truncating.
const char *c_arg(const std::string &s, const char *what)
{
    if (s.find('\0') != std::string::npos) {
        throw Error(CERTONE_E_INVALID_ARG, 0, std::string(what) + " contains a NUL character");
    }
    return s.c_str();
}

const char *c_opt(const std::optional<std::string> &s, const char *what)
{
    return s ? c_arg(*s, what) : nullptr;
}

[[noreturn]] void json_error(certone_status status, const std::string &path)
{
    throw Error(status, 0, std::string(certone_status_str(status)) + " (path \"" + path + "\")");
}

void check_json(certone_status status, const std::string &path)
{
    if (status != CERTONE_OK) {
        json_error(status, path);
    }
}

long to_ms(std::chrono::milliseconds d, const char *what)
{
    if (d.count() < 0 || d.count() > 0x7FFFFFFF) {
        throw Error(CERTONE_E_INVALID_ARG, 0, std::string(what) + " out of range");
    }
    return static_cast<long>(d.count());
}

// libcurl global state: initialised on first use, released at process exit.
void ensure_global_init()
{
    struct Global {
        Global()
        {
            if (certone_global_init() != CERTONE_OK) {
                throw Error(CERTONE_E_NETWORK, 0, "libcurl global initialisation failed");
            }
        }
        ~Global() { certone_global_cleanup(); }
        Global(const Global &) = delete;
        Global &operator=(const Global &) = delete;
    };
    static Global global;
    (void)global;
}

} // namespace

// ---- Error ---------------------------------------------------------------------------------

Error::Error(certone_status status, long http_status, const std::string &message)
    : std::runtime_error(message.empty() ? std::string(certone_status_str(status)) : message),
      status_(status), http_status_(http_status)
{
}

// ---- Json ----------------------------------------------------------------------------------

Json::Json(std::string text) : text_(std::move(text))
{
    if (text_.find('\0') != std::string::npos || certone_json_validate(text_.c_str()) != CERTONE_OK) {
        throw Error(CERTONE_E_JSON, 0, "not a valid JSON document");
    }
}

bool Json::has(const std::string &path) const
{
    certone_json_type t;
    certone_status st = certone_json_type_at(text_.c_str(), c_arg(path, "path"), &t);
    if (st == CERTONE_E_NOT_FOUND) {
        return false;
    }
    check_json(st, path);
    return true;
}

Json::Type Json::type(const std::string &path) const
{
    certone_json_type t;
    check_json(certone_json_type_at(text_.c_str(), c_arg(path, "path"), &t), path);
    switch (t) {
    case CERTONE_JSON_NULL: return Type::Null;
    case CERTONE_JSON_BOOL: return Type::Bool;
    case CERTONE_JSON_NUMBER: return Type::Number;
    case CERTONE_JSON_STRING: return Type::String;
    case CERTONE_JSON_ARRAY: return Type::Array;
    case CERTONE_JSON_OBJECT: return Type::Object;
    }
    json_error(CERTONE_E_TYPE, path);
}

std::string Json::get_string(const std::string &path) const
{
    char *out = nullptr;
    check_json(certone_json_get_string(text_.c_str(), c_arg(path, "path"), &out), path);
    return take(out);
}

std::int64_t Json::get_int(const std::string &path) const
{
    std::int64_t v = 0;
    check_json(certone_json_get_int(text_.c_str(), c_arg(path, "path"), &v), path);
    return v;
}

double Json::get_double(const std::string &path) const
{
    double v = 0;
    check_json(certone_json_get_double(text_.c_str(), c_arg(path, "path"), &v), path);
    return v;
}

bool Json::get_bool(const std::string &path) const
{
    int v = 0;
    check_json(certone_json_get_bool(text_.c_str(), c_arg(path, "path"), &v), path);
    return v != 0;
}

std::optional<std::string> Json::find_string(const std::string &path) const
{
    if (!has(path) || type(path) == Type::Null) {
        return std::nullopt;
    }
    return get_string(path);
}

std::optional<std::int64_t> Json::find_int(const std::string &path) const
{
    if (!has(path) || type(path) == Type::Null) {
        return std::nullopt;
    }
    return get_int(path);
}

std::optional<double> Json::find_double(const std::string &path) const
{
    if (!has(path) || type(path) == Type::Null) {
        return std::nullopt;
    }
    return get_double(path);
}

std::optional<bool> Json::find_bool(const std::string &path) const
{
    if (!has(path) || type(path) == Type::Null) {
        return std::nullopt;
    }
    return get_bool(path);
}

std::size_t Json::size(const std::string &path) const
{
    std::size_t n = 0;
    check_json(certone_json_get_size(text_.c_str(), c_arg(path, "path"), &n), path);
    return n;
}

std::vector<std::string> Json::keys(const std::string &path) const
{
    if (type(path) != Type::Object) {
        json_error(CERTONE_E_TYPE, path);
    }
    std::size_t n = size(path);
    std::vector<std::string> out;
    out.reserve(n);
    for (std::size_t i = 0; i < n; ++i) {
        char *key = nullptr;
        check_json(certone_json_get_key(text_.c_str(), path.c_str(), i, &key), path);
        out.push_back(take(key));
    }
    return out;
}

Json Json::at(const std::string &path) const
{
    char *out = nullptr;
    check_json(certone_json_get_raw(text_.c_str(), c_arg(path, "path"), &out), path);
    return Json(take(out));
}

std::string Json::escape_key(std::string_view key)
{
    std::string out;
    out.reserve(key.size());
    for (char ch : key) {
        if (ch == '.' || ch == '[' || ch == '\\') {
            out.push_back('\\');
        }
        out.push_back(ch);
    }
    return out;
}

// ---- Snapshot ------------------------------------------------------------------------------

Snapshot Snapshot::file(std::string path)
{
    Snapshot s;
    s.path = std::move(path);
    return s;
}

Snapshot Snapshot::memory(std::string_view bytes, std::string filename)
{
    Snapshot s;
    s.data = bytes;
    s.filename = std::move(filename);
    return s;
}

// ---- Client --------------------------------------------------------------------------------

Client::Client(const Config &config)
{
    ensure_global_init();
    certone_config cfg{};
    cfg.base_url = c_arg(config.base_url, "base_url");
    cfg.token = c_opt(config.token, "token");
    cfg.connect_timeout_ms = to_ms(config.connect_timeout, "connect_timeout");
    cfg.timeout_ms = to_ms(config.timeout, "timeout");
    cfg.max_response_bytes = config.max_response_bytes;
    cfg.ca_bundle_path = c_opt(config.ca_bundle_path, "ca_bundle_path");
    cfg.user_agent = c_opt(config.user_agent, "user_agent");
    certone_client *raw = nullptr;
    certone_status st = certone_client_new(&cfg, &raw);
    if (st != CERTONE_OK) {
        throw Error(st, 0,
                    st == CERTONE_E_INVALID_ARG
                        ? "invalid client configuration: base_url must be http(s)://host; token and "
                          "user agent must be non-empty, without control characters"
                        : certone_status_str(st));
    }
    client_.reset(raw);
}

Client::Client(std::string base_url, std::string token)
    : Client([&] {
          Config c;
          c.base_url = std::move(base_url);
          c.token = std::move(token);
          return c;
      }())
{
}

Client::~Client() = default;
Client::Client(Client &&other) noexcept = default;
Client &Client::operator=(Client &&other) noexcept = default;

certone_client *Client::handle() const
{
    if (!client_) {
        throw Error(CERTONE_E_INVALID_ARG, 0, "use of a moved-from certone::Client");
    }
    return client_.get();
}

void Client::raise(certone_status status) const
{
    const char *msg = certone_last_error(client_.get());
    throw Error(status, certone_last_http_status(client_.get()),
                msg != nullptr && msg[0] != '\0' ? std::string(msg)
                                                 : std::string(certone_status_str(status)));
}

namespace {

certone_scan_options scan_options(const ScanOptions &o)
{
    certone_scan_options c{};
    c.asset = c_opt(o.asset, "asset");
    c.environment = c_opt(o.environment, "environment");
    c.country_code = c_opt(o.country_code, "country_code");
    c.fail_on = c_opt(o.fail_on, "fail_on");
    c.packs = c_opt(o.packs, "packs");
    c.snapshot_ref = c_opt(o.snapshot_ref, "snapshot_ref");
    c.commit_hash = c_opt(o.commit_hash, "commit_hash");
    c.tee = c_opt(o.tee, "tee");
    return c;
}

certone_snapshot c_snapshot(const Snapshot &s)
{
    certone_snapshot c{};
    if (!s.path.empty()) {
        c.path = c_arg(s.path, "snapshot path");
    } else {
        c.data = s.data.data();
        c.size = s.data.size();
    }
    c.filename = c_opt(s.filename, "snapshot filename");
    return c;
}

} // namespace

Json Client::submit_check(const Snapshot &snapshot, const ScanOptions &options)
{
    certone_snapshot snap = c_snapshot(snapshot);
    certone_scan_options opts = scan_options(options);
    char *out = nullptr;
    certone_status st = certone_submit_check(handle(), &snap, &opts, &out);
    if (st != CERTONE_OK) {
        raise(st);
    }
    return Json(take(out));
}

Json Client::submit_process(const Snapshot &snapshot, const ScanOptions &options)
{
    certone_snapshot snap = c_snapshot(snapshot);
    certone_scan_options opts = scan_options(options);
    char *out = nullptr;
    certone_status st = certone_submit_process(handle(), &snap, &opts, &out);
    if (st != CERTONE_OK) {
        raise(st);
    }
    return Json(take(out));
}

Json Client::get_scan(const std::string &scan_id)
{
    char *out = nullptr;
    certone_status st = certone_get_scan(handle(), c_arg(scan_id, "scan_id"), &out);
    if (st != CERTONE_OK) {
        raise(st);
    }
    return Json(take(out));
}

Json Client::wait_for_report(const std::string &scan_id, std::chrono::milliseconds timeout,
                             std::chrono::milliseconds interval)
{
    if (timeout.count() <= 0 || interval.count() <= 0) {
        throw Error(CERTONE_E_INVALID_ARG, 0, "timeout and interval must be positive");
    }
    char *out = nullptr;
    certone_status st =
        certone_wait_for_report(handle(), c_arg(scan_id, "scan_id"), to_ms(timeout, "timeout"),
                                to_ms(interval, "interval"), &out);
    if (st != CERTONE_OK) {
        raise(st);
    }
    return Json(take(out));
}

Json Client::get_report_document(const std::string &report_id)
{
    char *out = nullptr;
    certone_status st =
        certone_get_report_document(handle(), c_arg(report_id, "report_id"), &out);
    if (st != CERTONE_OK) {
        raise(st);
    }
    return Json(take(out));
}

Json Client::get_attestation(const std::string &report_id)
{
    char *out = nullptr;
    certone_status st = certone_get_attestation(handle(), c_arg(report_id, "report_id"), &out);
    if (st != CERTONE_OK) {
        raise(st);
    }
    return Json(take(out));
}

Json Client::ingest_report(const Json &report, const IngestOptions &options)
{
    certone_ingest_options c{};
    c.asset = c_opt(options.asset, "asset");
    c.environment = c_opt(options.environment, "environment");
    c.country_code = c_opt(options.country_code, "country_code");
    c.snapshot_ref = c_opt(options.snapshot_ref, "snapshot_ref");
    c.input_digest = c_opt(options.input_digest, "input_digest");
    c.repo = c_opt(options.repo, "repo");
    c.commit_hash = c_opt(options.commit_hash, "commit_hash");
    char *out = nullptr;
    certone_status st = certone_ingest_report(handle(), report.dump().c_str(), &c, &out);
    if (st != CERTONE_OK) {
        raise(st);
    }
    return Json(take(out));
}

Json Client::list_systems()
{
    char *out = nullptr;
    certone_status st = certone_list_systems(handle(), &out);
    if (st != CERTONE_OK) {
        raise(st);
    }
    return Json(take(out));
}

// ---- free functions ------------------------------------------------------------------------

std::string input_digest(std::string_view bytes)
{
    char out[CERTONE_INPUT_DIGEST_SIZE];
    certone_input_digest(bytes.data(), bytes.size(), out);
    return std::string(out);
}

std::string input_digest_file(const std::string &path)
{
    char out[CERTONE_INPUT_DIGEST_SIZE];
    certone_status st = certone_input_digest_file(c_arg(path, "path"), out);
    if (st != CERTONE_OK) {
        throw Error(st, 0, "cannot read " + path);
    }
    return std::string(out);
}

std::vector<std::uint8_t> sha256(std::string_view bytes)
{
    std::vector<std::uint8_t> out(CERTONE_SHA256_DIGEST_SIZE);
    certone_sha256(bytes.data(), bytes.size(), out.data());
    return out;
}

std::string version()
{
    return certone_version();
}

} // namespace certone
