#!/usr/bin/env bash
# Build, test, pack and run the conformance quickstart of the CertOne C# SDK in the .NET 8 SDK container.
#
#   bash csharp/ci/run.sh                       # build + tests + pack + quickstart
#   SKIP_QUICKSTART=1 bash csharp/ci/run.sh     # build + tests + pack only (no control plane needed)
#
# The quickstart needs the conformance control plane (from the repo root):
#   the CertOne test environment (see README)
# It runs on the `certone-sdk` docker network against http://certone-cp:8000.
#
# The repo is mounted read-only and copied inside the container, so no bin/obj output lands on the host.
# Environment overrides: DOTNET_SDK_IMAGE, CERTONE_SDK_NETWORK, CERTONE_API_URL_DOCKER.
set -euo pipefail
export MSYS_NO_PATHCONV=1 # Git Bash on Windows: keep container paths as-is

CSHARP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_DIR="$(cd "$CSHARP_DIR/../.." && pwd)"
CONFORMANCE_DIR="$REPO_DIR/conformance"
IMAGE="${DOTNET_SDK_IMAGE:-mcr.microsoft.com/dotnet/sdk:8.0}"
NETWORK="${CERTONE_SDK_NETWORK:-certone-sdk}"
API_URL="${CERTONE_API_URL_DOCKER:-http://certone-cp:8000}"
QUICKSTART=1
[[ "${SKIP_QUICKSTART:-0}" == "1" ]] && QUICKSTART=0

# Docker Desktop on Windows needs a Windows path for the bind mount source.
host_path() {
  if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s' "$1"; fi
}

# Reads one KEY=value from conformance.env without echoing it.
env_value() {
  grep -E "^$1=" "$CONFORMANCE_DIR/conformance.env" | head -n 1 | cut -d= -f2- | tr -d '\r'
}

# Conformance inputs are relative to conformance unless absolute.
container_input() {
  case "$1" in
    /*) printf '%s' "$1" ;;
    *) printf '/work/conformance/%s' "$1" ;;
  esac
}

docker_args=(
  run --rm
  --mount "type=bind,source=$(host_path "$REPO_DIR"),target=/repo,readonly"
  --mount "type=volume,source=certone-sdk-nuget,target=/root/.nuget/packages"
  -e DOTNET_CLI_TELEMETRY_OPTOUT=1
  -e DOTNET_NOLOGO=1
  -e DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
  -e QUICKSTART="$QUICKSTART"
)

if [[ "$QUICKSTART" == "1" ]]; then
  if [[ ! -f "$CONFORMANCE_DIR/conformance.env" ]]; then
    echo "missing $CONFORMANCE_DIR/conformance.env: run the CertOne test environment (see README) and the CertOne test environment (see README) first" >&2
    exit 1
  fi
  if ! docker network inspect "$NETWORK" >/dev/null 2>&1; then
    echo "docker network '$NETWORK' not found: run the CertOne test environment (see README) first" >&2
    exit 1
  fi
  CERTONE_API_KEY="$(env_value CERTONE_API_KEY)"
  if [[ -z "$CERTONE_API_KEY" ]]; then
    echo "CERTONE_API_KEY missing from conformance.env: run the CertOne test environment (see README)" >&2
    exit 1
  fi
  export CERTONE_API_KEY # passed by name below so the key never appears on a command line
  docker_args+=(
    --network "$NETWORK"
    -e CERTONE_API_KEY
    -e CERTONE_API_URL="$API_URL"
    -e CERTONE_SNAPSHOT="$(container_input "$(env_value CERTONE_SNAPSHOT)")"
    -e CERTONE_REPORT_JSON="$(container_input "$(env_value CERTONE_REPORT_JSON)")"
  )
fi

docker "${docker_args[@]}" "$IMAGE" bash -euo pipefail -c '
mkdir -p /work/sdk
cp -r /repo/csharp /work/csharp
cp -r /repo/conformance /work/conformance
cp /repo/LICENSE /work/LICENSE
find /work/csharp -type d \( -name bin -o -name obj \) -prune -exec rm -rf {} +
cd /work/csharp

echo "== dotnet $(dotnet --version)"
echo "== restore"
dotnet restore Certkor.CertOne.sln
echo "== build (warnings as errors)"
dotnet build Certkor.CertOne.sln -c Release --no-restore -warnaserror
echo "== test"
dotnet test Certkor.CertOne.sln -c Release --no-build --logger "console;verbosity=normal"
echo "== pack"
dotnet pack src/Certkor.CertOne/Certkor.CertOne.csproj -c Release --no-build -o /work/artifacts
ls -l /work/artifacts

if [[ "$QUICKSTART" == "1" ]]; then
  echo "== quickstart against $CERTONE_API_URL"
  dotnet run --project examples/Quickstart/Quickstart.csproj -c Release --no-build | tee /tmp/quickstart.out
  grep -qx "\[check\] verdict: fail" /tmp/quickstart.out || { echo "expected check verdict fail" >&2; exit 1; }
  grep -qx "\[ingest\] verdict: pass" /tmp/quickstart.out || { echo "expected ingest verdict pass" >&2; exit 1; }
  grep -q "^\[attestation\] attestation_id: att-" /tmp/quickstart.out || { echo "expected an attestation id" >&2; exit 1; }
fi
echo "== C# SDK: all checks passed"
'
