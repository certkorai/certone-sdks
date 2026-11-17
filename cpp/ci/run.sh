#!/usr/bin/env bash
# Reproducible CI for the CertOne C++ SDK: builds the toolchain image, then runs
# cpp/ci/ci.sh in it on the `certone-sdk` docker network so the quickstart reaches the
# conformance control plane.
#
#   bash cpp/ci/run.sh                         # needs: the CertOne test environment (see README)
#   CERTONE_SKIP_QUICKSTART=1 bash cpp/ci/run.sh   # offline: build + unit tests only
#
# Reads the API key from conformance/conformance.env and never prints it.
set -euo pipefail
export MSYS_NO_PATHCONV=1 # Git Bash on Windows: keep container paths as-is

HERE="$(cd "$(dirname "$0")" && pwd)"
SDK="$(cd "$HERE/../.." && pwd)"
IMAGE="${CERTONE_SDK_CPP_IMAGE:-certone-sdk-cpp-ci}"
NETWORK="${CERTONE_SDK_NETWORK:-certone-sdk}"
ENV_FILE="$SDK/conformance/conformance.env"
SKIP_QS="${CERTONE_SKIP_QUICKSTART:-0}"

host_path() { if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else echo "$1"; fi; }

docker build -q -t "$IMAGE" "$(host_path "$HERE")" >/dev/null

args=(--rm -v "$(host_path "$SDK"):/sdk:ro" -e CERTONE_SKIP_QUICKSTART="$SKIP_QS")
if [ "$SKIP_QS" != 1 ]; then
  [ -f "$ENV_FILE" ] || { echo "missing $ENV_FILE: run the CertOne test environment (see README)" >&2; exit 1; }
  api_docker="$(sed -n 's/^CERTONE_API_URL_DOCKER=//p' "$ENV_FILE" | tr -d '\r')"
  args+=(--network "$NETWORK" --env-file "$(host_path "$ENV_FILE")"
         -e CERTONE_API_URL="${api_docker:-http://certone-cp:8000}"
         -e CERTONE_SNAPSHOT=/conformance/sample-project.tar.gz
         -e CERTONE_REPORT_JSON=/conformance/run-at-source-report.json)
fi
docker run "${args[@]}" "$IMAGE" bash /cpp/ci/ci.sh
