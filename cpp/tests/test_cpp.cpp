// Offline tests for the CertOne C++ SDK: Json accessors, SHA-256/input_digest, Error, Client
// RAII/validation, and request/exception behaviour against an in-process loopback HTTP server.
#include "certone/certone.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cstdio>
#include <fstream>
#include <functional>
#include <iostream>
#include <iterator>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <type_traits>
#include <vector>

namespace {

int g_checks = 0;
int g_failures = 0;
int g_tests = 0;
std::string g_fixtures = ".";

#define CHECK(cond)                                                                            \
    do {                                                                                       \
        ++g_checks;                                                                            \
        if (!(cond)) {                                                                         \
            ++g_failures;                                                                      \
            std::cerr << __FILE__ << ":" << __LINE__ << ": CHECK failed: " #cond "\n";         \
        }                                                                                      \
    } while (0)

#define CHECK_EQ(actual, expected)                                                             \
    do {                                                                                       \
        ++g_checks;                                                                            \
        auto a_ = (actual);                                                                    \
        auto e_ = (expected);                                                                  \
        if (!(a_ == e_)) {                                                                     \
            ++g_failures;                                                                      \
            std::cerr << __FILE__ << ":" << __LINE__ << ": " #actual " == [" << a_             \
                      << "], expected [" << e_ << "]\n";                                       \
        }                                                                                      \
    } while (0)

// Expect `expr` to throw certone::Error with the given status.
#define CHECK_THROWS(expr, expected_status)                                                    \
    do {                                                                                       \
        ++g_checks;                                                                            \
        try {                                                                                  \
            (void)(expr);                                                                      \
            ++g_failures;                                                                      \
            std::cerr << __FILE__ << ":" << __LINE__ << ": " #expr " did not throw\n";         \
        } catch (const certone::Error &err_) {                                                 \
            if (err_.status() != (expected_status)) {                                          \
                ++g_failures;                                                                  \
                std::cerr << __FILE__ << ":" << __LINE__ << ": " #expr " threw status "        \
                          << err_.status() << " (" << err_.what() << ")\n";                    \
            }                                                                                  \
        }                                                                                      \
    } while (0)

void run(const char *name, const std::function<void()> &test)
{
    int before = g_failures;
    ++g_tests;
    try {
        test();
    } catch (const std::exception &e) {
        ++g_failures;
        std::cerr << name << ": unexpected exception: " << e.what() << "\n";
    }
    std::printf("  %-48s %s\n", name, g_failures == before ? "ok" : "FAILED");
}

std::string read_fixture(const std::string &name)
{
    std::ifstream in(g_fixtures + "/" + name, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

// ---- loopback HTTP server --------------------------------------------------------------

struct Canned {
    int status;
    std::string body;
};

class LoopbackServer {
public:
    explicit LoopbackServer(std::vector<Canned> responses) : responses_(std::move(responses))
    {
        fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        socklen_t len = sizeof addr;
        if (fd_ < 0 || ::bind(fd_, reinterpret_cast<sockaddr *>(&addr), sizeof addr) != 0 ||
            ::listen(fd_, 8) != 0 ||
            ::getsockname(fd_, reinterpret_cast<sockaddr *>(&addr), &len) != 0) {
            throw std::runtime_error("loopback server: cannot listen");
        }
        port_ = ntohs(addr.sin_port);
        thread_ = std::thread([this] { serve(); });
    }
    ~LoopbackServer()
    {
        stop_ = true;
        thread_.join();
        ::close(fd_);
    }
    LoopbackServer(const LoopbackServer &) = delete;
    LoopbackServer &operator=(const LoopbackServer &) = delete;

    std::string url() const { return "http://127.0.0.1:" + std::to_string(port_); }
    std::vector<std::string> requests()
    {
        std::lock_guard<std::mutex> lock(mu_);
        return requests_;
    }

private:
    void serve()
    {
        std::size_t served = 0;
        while (!stop_ && served < responses_.size()) {
            pollfd p{fd_, POLLIN, 0};
            if (::poll(&p, 1, 50) <= 0) {
                continue;
            }
            int c = ::accept(fd_, nullptr, nullptr);
            if (c < 0) {
                continue;
            }
            std::string req = read_request(c);
            {
                std::lock_guard<std::mutex> lock(mu_);
                requests_.push_back(req);
            }
            const Canned &r = responses_[served++];
            std::string out = "HTTP/1.1 " + std::to_string(r.status) +
                              " X\r\nContent-Type: application/json\r\nContent-Length: " +
                              std::to_string(r.body.size()) + "\r\nConnection: close\r\n\r\n" +
                              r.body;
            std::size_t off = 0;
            while (off < out.size()) {
                ssize_t n = ::send(c, out.data() + off, out.size() - off, 0);
                if (n <= 0) {
                    break;
                }
                off += static_cast<std::size_t>(n);
            }
            ::close(c);
        }
    }

    static std::string read_request(int c)
    {
        std::string buf;
        std::size_t need = 0;
        char chunk[4096];
        for (;;) {
            pollfd p{c, POLLIN, 0};
            if (::poll(&p, 1, 5000) <= 0) {
                break;
            }
            ssize_t n = ::recv(c, chunk, sizeof chunk, 0);
            if (n <= 0) {
                break;
            }
            buf.append(chunk, static_cast<std::size_t>(n));
            std::size_t end = buf.find("\r\n\r\n");
            if (need == 0 && end != std::string::npos) {
                std::size_t cl = 0;
                std::size_t pos = buf.find("Content-Length: ");
                if (pos != std::string::npos && pos < end) {
                    cl = std::stoul(buf.substr(pos + 16));
                }
                need = end + 4 + cl;
            }
            if (need != 0 && buf.size() >= need) {
                break;
            }
        }
        return buf;
    }

    std::vector<Canned> responses_;
    std::vector<std::string> requests_;
    std::mutex mu_;
    std::atomic<bool> stop_{false};
    std::thread thread_;
    int fd_ = -1;
    int port_ = 0;
};

// ---- tests -----------------------------------------------------------------------------

void test_json_accessors()
{
    certone::Json doc(read_fixture("check_result.json"));
    CHECK_EQ(doc.get_string("scan_run.id"), std::string("64ff3a4afb5e40f5b8ae5e38071c9145"));
    CHECK_EQ(doc.get_string("report.verdict_status"), std::string("fail"));
    CHECK_EQ(doc.get_int("report.total_issues"), 6);
    CHECK_EQ(doc.get_bool("queued"), false);
    CHECK(doc.type("report") == certone::Json::Type::Object);
    CHECK(doc.type("scan_run.error") == certone::Json::Type::Null);
    CHECK(doc.has("scan_run.error"));
    CHECK(!doc.has("scan_run.nope"));
    CHECK_EQ(doc.size("report.by_severity"), std::size_t{3});
    std::vector<std::string> keys = doc.keys("report.by_severity");
    CHECK(keys == (std::vector<std::string>{"low", "medium", "high"}));
    CHECK_EQ(doc.get_int("report.by_severity." + certone::Json::escape_key(keys[2])), 3);
    certone::Json report = doc.at("report");
    CHECK_EQ(report.get_string("report_id"), std::string("report-bce1fa3cd2cd"));
    certone::Json by_severity = doc.at("report.by_severity");
    CHECK(by_severity.dump().front() == '{' && by_severity.dump().back() == '}');
    CHECK_EQ(by_severity.get_int("medium"), 3);

    CHECK_THROWS(doc.get_string("report.missing"), CERTONE_E_NOT_FOUND);
    CHECK_THROWS(doc.get_string("report.total_issues"), CERTONE_E_TYPE);
    CHECK_THROWS(doc.get_int("report.verdict_status"), CERTONE_E_TYPE);
    CHECK_THROWS(doc.keys("report.total_issues"), CERTONE_E_TYPE);
    CHECK_THROWS(doc.get_string("a..b"), CERTONE_E_INVALID_ARG);
    CHECK_THROWS(doc.get_string(std::string("report\0x", 8)), CERTONE_E_INVALID_ARG);
}

void test_json_optional()
{
    certone::Json doc("{\"s\":\"x\",\"n\":null,\"i\":7,\"d\":2.5,\"b\":true}");
    CHECK(doc.find_string("s") == std::optional<std::string>("x"));
    CHECK(!doc.find_string("n").has_value());
    CHECK(!doc.find_string("missing").has_value());
    CHECK(doc.find_int("i") == std::optional<std::int64_t>(7));
    CHECK(!doc.find_int("n").has_value());
    CHECK(doc.find_double("d") == std::optional<double>(2.5));
    CHECK(doc.find_bool("b") == std::optional<bool>(true));
    CHECK_THROWS(doc.find_string("i"), CERTONE_E_TYPE);
    CHECK_THROWS(doc.find_int("d"), CERTONE_E_TYPE);
    CHECK_THROWS(doc.find_bool("s"), CERTONE_E_TYPE);

    certone::Json systems(read_fixture("systems.json"));
    CHECK_EQ(systems.size(), std::size_t{3});
    CHECK_EQ(systems.get_string("[0].regions[0]"), std::string("EU"));
    CHECK(!systems.find_string("[0].owner_team_id").has_value());
}

void test_json_rejects_invalid_text()
{
    CHECK_THROWS(certone::Json("{\"a\":"), CERTONE_E_JSON);
    CHECK_THROWS(certone::Json(""), CERTONE_E_JSON);
    CHECK_THROWS(certone::Json(std::string("{}\0", 3)), CERTONE_E_JSON);
    CHECK_EQ(certone::Json::escape_key("a.b[c]\\"), std::string("a\\.b\\[c]\\\\"));
}

void test_sha256_and_digest()
{
    std::vector<std::uint8_t> d = certone::sha256("abc");
    CHECK_EQ(d.size(), std::size_t{32});
    CHECK(d.size() == 32 && d[0] == 0xba && d[31] == 0xad);
    CHECK_EQ(certone::input_digest(""),
             std::string("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    {
        std::ofstream out("certone_cpp_digest.bin", std::ios::binary);
        out << "abc";
    }
    CHECK_EQ(certone::input_digest_file("certone_cpp_digest.bin"),
             std::string("sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    std::remove("certone_cpp_digest.bin");
    CHECK_THROWS(certone::input_digest_file("/nonexistent/certone.tar.gz"), CERTONE_E_IO);
    CHECK_EQ(certone::version(), std::string(CERTONE_VERSION_STRING));
}

void test_client_construction()
{
    static_assert(!std::is_copy_constructible<certone::Client>::value, "Client is move-only");
    static_assert(std::is_nothrow_move_constructible<certone::Client>::value, "noexcept move");
    CHECK_THROWS(certone::Client("ftp://example.com", "ck_x"), CERTONE_E_INVALID_ARG);
    CHECK_THROWS(certone::Client("https://example.com", "ck_x\r\nX: y"), CERTONE_E_INVALID_ARG);
    CHECK_THROWS(certone::Client("https://example.com", std::string("ck\0x", 4)),
                 CERTONE_E_INVALID_ARG);
    certone::Config cfg;
    cfg.base_url = "https://example.com";
    cfg.timeout = std::chrono::milliseconds(-1);
    CHECK_THROWS(certone::Client(cfg), CERTONE_E_INVALID_ARG);

    certone::Client a("https://example.com", "ck_x");
    certone::Client b(std::move(a));
    CHECK_THROWS(a.list_systems(), CERTONE_E_INVALID_ARG); // NOLINT(bugprone-use-after-move)
    CHECK_THROWS(b.get_scan(""), CERTONE_E_INVALID_ARG);
    CHECK_THROWS(b.submit_check(certone::Snapshot::file("/nonexistent/snap.tar.gz")),
                 CERTONE_E_IO);
    CHECK_THROWS(b.submit_check(certone::Snapshot::memory("")), CERTONE_E_INVALID_ARG);
    CHECK_THROWS(b.ingest_report(certone::Json("[1]")), CERTONE_E_TYPE);
    CHECK_THROWS(b.wait_for_report("s", std::chrono::milliseconds(0)), CERTONE_E_INVALID_ARG);
}

void test_requests_and_results()
{
    LoopbackServer server({
        {201, "{\"scan_run\":{\"id\":\"s1\"},\"report\":{\"id\":\"r1\",\"verdict_status\":\"fail\"}}"},
        {201, "{\"scan_run\":{\"id\":\"s2\"},\"report\":{\"id\":\"r2\",\"verdict_status\":\"pass\"}}"},
        {200, "[{\"name\":\"a\"},{\"name\":\"b\"}]"},
    });
    certone::Client client(server.url(), "ck_cpp_test");
    certone::ScanOptions opts;
    opts.asset = "C++ SDK quickstart";
    opts.fail_on = "high";
    const std::string bytes = "TARBYTES";
    certone::Json check = client.submit_check(certone::Snapshot::memory(bytes, "p.tar.gz"), opts);
    CHECK_EQ(check.get_string("report.verdict_status"), std::string("fail"));

    certone::IngestOptions io;
    io.environment = "edge";
    io.country_code = "EU";
    io.input_digest = certone::input_digest(bytes);
    certone::Json ingest = client.ingest_report(certone::Json("{\"report_id\":\"x\"}"), io);
    CHECK_EQ(ingest.get_string("report.verdict_status"), std::string("pass"));
    CHECK_EQ(client.list_systems().size(), std::size_t{2});

    std::vector<std::string> reqs = server.requests();
    CHECK_EQ(reqs.size(), std::size_t{3});
    if (reqs.size() == 3) {
        CHECK(reqs[0].rfind("POST /v1/checks HTTP/1.1\r\n", 0) == 0);
        CHECK(reqs[0].find("Authorization: Bearer ck_cpp_test\r\n") != std::string::npos);
        CHECK(reqs[0].find("name=\"asset\"\r\n\r\nC++ SDK quickstart\r\n") != std::string::npos);
        CHECK(reqs[0].find("filename=\"p.tar.gz\"") != std::string::npos);
        CHECK(reqs[0].find("\r\n\r\nTARBYTES\r\n") != std::string::npos);
        CHECK(reqs[1].rfind("POST /v1/checks/report HTTP/1.1\r\n", 0) == 0);
        CHECK(reqs[1].find("{\"report\":{\"report_id\":\"x\"},\"environment\":\"edge\","
                           "\"country_code\":\"EU\",\"input_digest\":\"sha256:") !=
              std::string::npos);
        CHECK(reqs[2].rfind("GET /v1/systems HTTP/1.1\r\n", 0) == 0);
    }
}

void test_http_error_becomes_exception()
{
    LoopbackServer server({
        {404, "{\"detail\":\"no attestation (the input did not pass, so none was issued)\"}"},
        {200, "{\"id\":\"s1\",\"status\":\"failed\",\"error\":\"worker crashed\"}"},
    });
    certone::Client client(server.url(), "ck_cpp_test");
    try {
        client.get_attestation("r1");
        CHECK(!"get_attestation should throw");
    } catch (const certone::Error &e) {
        CHECK_EQ(e.status(), CERTONE_E_HTTP);
        CHECK_EQ(e.http_status(), 404L);
        CHECK_EQ(std::string(e.what()),
                 std::string("HTTP 404: no attestation (the input did not pass, so none was issued)"));
        CHECK(std::string(e.what()).find("ck_cpp_test") == std::string::npos);
    }
    try {
        client.wait_for_report("s1", std::chrono::seconds(5), std::chrono::milliseconds(10));
        CHECK(!"wait_for_report should throw");
    } catch (const certone::Error &e) {
        CHECK_EQ(e.status(), CERTONE_E_SCAN_FAILED);
        CHECK_EQ(std::string(e.what()), std::string("scan s1 failed: worker crashed"));
    }
}

} // namespace

int main(int argc, char **argv)
{
    if (argc > 1) {
        g_fixtures = argv[1];
    }
    run("test_json_accessors", test_json_accessors);
    run("test_json_optional", test_json_optional);
    run("test_json_rejects_invalid_text", test_json_rejects_invalid_text);
    run("test_sha256_and_digest", test_sha256_and_digest);
    run("test_client_construction", test_client_construction);
    run("test_requests_and_results", test_requests_and_results);
    run("test_http_error_becomes_exception", test_http_error_becomes_exception);
    std::printf("test_cpp: %d tests, %d checks, %d failed\n", g_tests, g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
