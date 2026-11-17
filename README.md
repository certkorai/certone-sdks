# CertOne SDKs

Official client libraries for [CertOne](https://certkor.ai), the zero-trust AI sandbox by Certkor AI.
Submit an AI system's project for a confidential scan, wait for the verdict, and read the findings,
the full report and the signed compliance attestation, from any language.

Every SDK implements the same small client over the CertOne REST API, described in
[SPEC.md](SPEC.md), and is tested against the same fixtures in [conformance/fixtures](conformance/fixtures).

| Language | Folder | Package | Requires |
|---|---|---|---|
| Python | [certone-sdk-python](https://pypi.org/project/certone-sdk/) | `certone-sdk` on PyPI | Python 3.10+ |
| JavaScript and TypeScript | [js](js) | `@certkor/certone` | Node.js 18+ or a browser |
| Java | [java](java) | `ai.certkor:certone-sdk` | Java 17+ |
| C# and .NET | [csharp](csharp) | `Certkor.CertOne` | .NET 8 |
| Rust | [rust](rust) | `certone` | stable Rust |
| C | [c](c) | `libcertone` | C11 and libcurl |
| C++ | [cpp](cpp) | `libcertone++` | C++17 |

The Python SDK is published on PyPI. The other packages are being published to their registries;
until then, build them from this repository by following each folder's README.

## Get an API key

In the CertOne console, open **Developer Hub**, then **API keys**, and create a key with the
`member` role. Keys start with `ck_`, are shown once and expire within a year. Pass the key through
an environment variable such as `CERTONE_API_KEY`; never commit it.

## Documentation

- Guides for every integration: https://certkor.ai/docs/
- SDK and CLI guide: https://certkor.ai/docs/sdk-cli/
- API contract shared by all SDKs: [SPEC.md](SPEC.md)

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
