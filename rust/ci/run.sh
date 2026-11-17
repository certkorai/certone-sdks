#!/usr/bin/env bash
# Build, lint, test and run the quickstart of the CertOne Rust SDK inside the official Rust image,
# against the local conformance control plane (the CertOne test environment (see README)).
#
#   bash rust/ci/run.sh                 # full pipeline: fmt, clippy, test, quickstart
#   SKIP_QUICKSTART=1 bash rust/ci/run.sh   # offline: fmt, clippy, test only
#
# Env: RUST_IMAGE (default rust:1-bookworm), CERTONE_SDK_NETWORK (default certone-sdk),
#      CERTONE_CP_URL (default http://certone-cp:8000, as seen from the network).
# The API key is read from conformance/conformance.env inside the container; it is never
# passed on a command line or printed.
set -euo pipefail

if [[ "${1:-}" == "--in-container" ]]; then
  cd /rust
  export CARGO_TERM_COLOR=never
  echo "== toolchain"
  rustup component add rustfmt clippy >/dev/null 2>&1 || rustup component add rustfmt clippy
  rustc --version
  cargo --version
  echo "== cargo fmt --check"
  cargo fmt --all -- --check
  echo "== cargo clippy -D warnings"
  cargo clippy --locked --all-targets -- -D warnings
  echo "== library hygiene: no unwrap/expect/panic/indexing in library code"
  cargo clippy --locked --lib -- -D warnings -D clippy::unwrap_used -D clippy::expect_used \
    -D clippy::panic -D clippy::indexing_slicing
  echo "== rustdoc -D warnings"
  RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps --quiet
  echo "== cargo test"
  cargo test --locked
  if [[ "${SKIP_QUICKSTART:-0}" == "1" ]]; then
    echo "== quickstart skipped (SKIP_QUICKSTART=1)"
    exit 0
  fi
  echo "== quickstart"
  conf=/conformance
  env_file="$conf/conformance.env"
  [[ -f "$env_file" ]] || { echo "missing $env_file; run the CertOne test environment (see README)" >&2; exit 1; }
  get() { grep -E "^$1=" "$env_file" | tail -n1 | cut -d= -f2- | tr -d '\r'; }
  abs() { case "$1" in /*) echo "$1" ;; *) echo "$conf/$1" ;; esac; }
  CERTONE_API_KEY="$(get CERTONE_API_KEY)"
  [[ -n "$CERTONE_API_KEY" ]] || { echo "CERTONE_API_KEY missing in $env_file" >&2; exit 1; }
  export CERTONE_API_KEY
  export CERTONE_API_URL="${CERTONE_CP_URL:-$(get CERTONE_API_URL_DOCKER)}"
  export CERTONE_API_URL="${CERTONE_API_URL:-http://certone-cp:8000}"
  export CERTONE_SNAPSHOT="$(abs "$(get CERTONE_SNAPSHOT)")"
  export CERTONE_REPORT_JSON="$(abs "$(get CERTONE_REPORT_JSON)")"
  out="$(mktemp)"
  cargo run --locked --quiet --example quickstart | tee "$out"
  # Conformance expectations for the seeded tenant: the sample project fails, the run-at-source
  # report passes and is attested.
  grep -q '^\[2\] verdict: fail$' "$out" || { echo "expected check verdict fail" >&2; exit 1; }
  grep -q '^\[4\] ingested scan .*: verdict pass$' "$out" || { echo "expected ingest verdict pass" >&2; exit 1; }
  grep -q '^\[5\] attestation_id=att-' "$out" || { echo "expected an attestation id" >&2; exit 1; }
  echo "== conformance OK"
  exit 0
fi

export MSYS_NO_PATHCONV=1  # Git Bash on Windows: keep container paths as-is
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
sdk_dir="$(cd "$here/../.." && pwd)"
host_sdk_dir="$sdk_dir"
if command -v cygpath >/dev/null 2>&1; then
  host_sdk_dir="$(cygpath -w "$sdk_dir")"
fi
image="${RUST_IMAGE:-rust:1-bookworm}"
network="${CERTONE_SDK_NETWORK:-certone-sdk}"

net_args=()
if [[ "${SKIP_QUICKSTART:-0}" != "1" ]]; then
  if ! docker network inspect "$network" >/dev/null 2>&1; then
    echo "docker network $network not found; start the control plane first:" >&2
    echo "  the CertOne test environment (see README)" >&2
    exit 1
  fi
  net_args=(--network "$network")
fi

# Named volumes keep the cargo registry and build artefacts between runs (and off the bind mount).
docker run --rm "${net_args[@]}" \
  -v "$host_sdk_dir:/sdk" \
  -v certone-rust-cargo-registry:/usr/local/cargo/registry \
  -v certone-rust-target:/target \
  -e CARGO_TARGET_DIR=/target \
  -e SKIP_QUICKSTART="${SKIP_QUICKSTART:-0}" \
  -e CERTONE_CP_URL="${CERTONE_CP_URL:-}" \
  "$image" bash /rust/ci/run.sh --in-container
