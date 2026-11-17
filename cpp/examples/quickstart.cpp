// CertOne C++ SDK quickstart: the 7-step conformance flow from SPEC.md.
//
//   export CERTONE_API_URL=https://api.example.com CERTONE_API_KEY=ck_...
//   export CERTONE_SNAPSHOT=sample-project.tar.gz CERTONE_REPORT_JSON=run-at-source-report.json
//   ./quickstart_cpp
//
// Exits 0 on success, or 1 with the error on stderr.
#include "certone/certone.hpp"

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

namespace {

std::string require_env(const char *name)
{
    const char *v = std::getenv(name);
    if (v == nullptr || *v == '\0') {
        throw std::runtime_error(std::string("environment variable ") + name + " is not set");
    }
    return v;
}

std::string read_file(const std::string &path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("cannot read " + path);
    }
    return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

} // namespace

int main()
{
    try {
        // 1. Configuration from the environment (the key is never printed).
        const std::string api_url = require_env("CERTONE_API_URL");
        const std::string snapshot = require_env("CERTONE_SNAPSHOT");
        const std::string report_path = require_env("CERTONE_REPORT_JSON");
        certone::Client client(api_url, require_env("CERTONE_API_KEY"));
        std::cout << "[1] CertOne C++ SDK " << certone::version() << ", API " << api_url << "\n";

        // 2. submit_check of the sample project.
        certone::ScanOptions scan;
        scan.asset = "C++ SDK quickstart";
        scan.fail_on = "high";
        certone::Json check = client.submit_check(certone::Snapshot::file(snapshot), scan);
        const std::string scan_id = check.get_string("scan_run.id");
        std::cout << "[2] submit_check: scan " << scan_id << "\n";
        if (auto verdict = check.find_string("report.verdict_status")) {
            std::cout << "    verdict: " << *verdict << "\n    findings by severity:";
            const std::vector<std::string> severities = check.keys("report.by_severity");
            for (const std::string &sev : severities) {
                std::cout << " " << sev << "="
                          << check.get_int("report.by_severity." + certone::Json::escape_key(sev));
            }
            std::cout << (severities.empty() ? " none\n" : "\n");
        } else {
            std::cout << "    queued: the report is produced asynchronously\n";
        }

        // 3. wait_for_report, then the full engine document and its first finding.
        certone::Json report = client.wait_for_report(scan_id);
        const std::string report_id = report.get_string("id");
        certone::Json document = client.get_report_document(report_id);
        const std::size_t issues = document.size("issues");
        std::cout << "[3] wait_for_report: report " << report_id << ", document has " << issues
                  << " issue(s)\n";
        if (issues > 0) {
            std::cout << "    first finding: [" << document.get_string("issues[0].severity")
                      << "] " << document.get_string("issues[0].compliance_topic") << ": "
                      << document.get_string("issues[0].description") << "\n";
        }

        // 4. ingest_report (run-at-source) bound to the snapshot's SHA-256.
        certone::IngestOptions ingest_opts;
        ingest_opts.asset = "C++ SDK quickstart";
        ingest_opts.environment = "edge";
        ingest_opts.country_code = "EU";
        ingest_opts.input_digest = certone::input_digest_file(snapshot);
        certone::Json ingest =
            client.ingest_report(certone::Json(read_file(report_path)), ingest_opts);
        std::cout << "[4] ingest_report: verdict " << ingest.get_string("report.verdict_status")
                  << " (input_digest " << *ingest_opts.input_digest << ")\n";

        // 5. get_attestation for the ingested report.
        certone::Json att = client.get_attestation(ingest.get_string("report.id"));
        std::cout << "[5] get_attestation: attestation_id " << att.get_string("attestation_id")
                  << ", input_version " << att.get_string("input_version")
                  << ", signature_algorithm " << att.get_string("signature_algorithm") << "\n";

        // 6. list_systems.
        std::cout << "[6] list_systems: " << client.list_systems().size()
                  << " AI system(s) in the tenant\n";

        // 7. Done.
        std::cout << "[7] quickstart OK\n";
        return 0;
    } catch (const certone::Error &e) {
        std::cerr << "error: " << certone_status_str(e.status()) << ": " << e.what() << "\n";
    } catch (const std::exception &e) {
        std::cerr << "error: " << e.what() << "\n";
    }
    return 1;
}
