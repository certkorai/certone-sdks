# CertOne SDKs

Official client libraries for [CertOne](https://certkor.ai), the zero-trust AI sandbox by Certkor AI.
Submit an AI system's project for a confidential scan, wait for the verdict, and read the findings,
the full report and the signed compliance attestation, from any language.

Every SDK implements the same contract steps over the CertOne REST API (submit a compliance check, wait for the verdict, read the full report, ingest a report computed at the source, and fetch the attestation), and is tested against the same fixtures in [conformance/fixtures](conformance/fixtures).

| Language | Install | Requires |
|---|---|---|
| Python | `pip install certone-sdk` ([PyPI](https://pypi.org/project/certone-sdk/)) | Python 3.10+ |
| JavaScript and TypeScript | `npm install @certkor/certone` ([npm](https://www.npmjs.com/package/@certkor/certone)) | Node.js 18+ or a browser |
| Rust | `cargo add certone` ([crates.io](https://crates.io/crates/certone)) | stable Rust |
| C | [release archive](https://github.com/certkorai/certone-sdks/releases/tag/c-v0.1.0), built with CMake | C11 and libcurl |
| C++ | [release archive](https://github.com/certkorai/certone-sdks/releases/tag/cpp-v0.1.0), built with CMake (includes the C SDK) | C++17 and libcurl |
| Java | build from [java](java) | Java 17+ |
| C# and .NET | build from [csharp](csharp) | .NET 8 |

Java (Maven Central) and C# (NuGet) packages are coming; until then, build them from their folders.

## Get an API key

In the CertOne console, open **Developer Hub**, then **API keys**, and create a key with the
`member` role. Keys start with `ck_`, are shown once and expire within a year. Pass the key through
an environment variable such as `CERTONE_API_KEY`; never commit it.

## Documentation

- Guides for every integration: https://certkor.ai/docs/
- SDK and CLI guide: https://certkor.ai/docs/sdk-cli/
- API reference shared by all SDKs: [API reference](SPEC.md)

## Tests

Each folder has a `ci/run.sh` script. `ci/run.sh --offline` builds the SDK and runs its unit tests
against the shared fixtures, with no account needed. The live conformance run needs a CertOne test
environment, which Certkor AI provides to partners on request.

## Security

Please report security issues privately through https://certkor.ai/contact/ (topic: Customer
support) rather than in a public issue.

## License

Licensed under the [Apache License, Version 2.0](LICENSE). The CertOne platform itself is
proprietary software of Certkor AI Inc. CertOne is a registered trademark of Certkor AI Inc., and
the CertOne technology is patent pending.
