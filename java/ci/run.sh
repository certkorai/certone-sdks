#!/usr/bin/env bash
# Build, unit-test and run the conformance quickstart of the CertOne Java SDK, all in Docker.
#
#   bash java/ci/run.sh
#
# Needs the local conformance control plane (container `certone-cp` on docker network
# `certone-sdk`) and its seeded inputs in conformance/:
#
#   the CertOne test environment (see README) certone-controlplane:local && the CertOne test environment (see README)
#
# Runs `mvn -B -Pquickstart clean verify` in maven:3-eclipse-temurin-17 on that network: compile (lint
# warnings fail the build), unit tests, javadoc, packaging, then examples/Quickstart.java against
# http://certone-cp:8000. Finally checks the conformance expectations in the quickstart output.
# The API key is passed to the container through the environment and is never printed.
set -euo pipefail
export MSYS_NO_PATHCONV=1  # Git Bash on Windows: keep container paths as-is

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
CONFORMANCE="$REPO/conformance"
IMAGE="${MAVEN_IMAGE:-maven:3-eclipse-temurin-17}"
NETWORK="${CERTONE_SDK_NETWORK:-certone-sdk}"
CP_CONTAINER="${CERTONE_CP_CONTAINER:-certone-cp}"
M2_VOLUME="${CERTONE_M2_VOLUME:-certone-sdk-m2}"

fail() { echo "ci/run.sh: $*" >&2; exit 1; }

# Docker Desktop on Windows wants a Windows path for bind mounts; elsewhere use the POSIX path.
if REPO_MOUNT="$(cd "$REPO" && pwd -W 2>/dev/null)"; then :; else REPO_MOUNT="$REPO"; fi

[[ -f "$CONFORMANCE/conformance.env" ]] \
  || fail "missing $CONFORMANCE/conformance.env (run the CertOne test environment (see README))"
API_URL="" SNAPSHOT="" REPORT_JSON="" CERTONE_API_KEY=""
while IFS='=' read -r key value || [[ -n "$key" ]]; do
  value="${value%$'\r'}"
  case "$key" in
    CERTONE_API_URL_DOCKER) API_URL="$value" ;;
    CERTONE_API_KEY) CERTONE_API_KEY="$value" ;;
    CERTONE_SNAPSHOT) SNAPSHOT="$value" ;;
    CERTONE_REPORT_JSON) REPORT_JSON="$value" ;;
  esac
done < "$CONFORMANCE/conformance.env"
[[ -n "$CERTONE_API_KEY" ]] || fail "CERTONE_API_KEY missing from conformance.env"
[[ -f "$CONFORMANCE/$SNAPSHOT" && -f "$CONFORMANCE/$REPORT_JSON" ]] \
  || fail "conformance inputs missing in $CONFORMANCE (run the CertOne test environment (see README))"
export CERTONE_API_KEY

docker network inspect "$NETWORK" >/dev/null 2>&1 \
  || fail "docker network $NETWORK not found (run the CertOne test environment (see README))"
[[ "$(docker inspect -f '{{.State.Running}}' "$CP_CONTAINER" 2>/dev/null)" == "true" ]] \
  || fail "control plane container $CP_CONTAINER is not running (run the CertOne test environment (see README))"

# On Linux hosts hand the build output back to the invoking user (the container runs as root).
OWNER=""
if [[ "$(uname -s)" == "Linux" ]]; then OWNER="$(id -u):$(id -g)"; fi

LOG="$(mktemp)"
trap 'rm -f "$LOG"' EXIT

docker volume create "$M2_VOLUME" >/dev/null
docker run --rm --network "$NETWORK" \
  -v "$REPO_MOUNT":/work -v "$M2_VOLUME":/root/.m2 -w /work/java \
  -e CERTONE_API_URL="${API_URL:-http://certone-cp:8000}" \
  -e CERTONE_API_KEY \
  -e CERTONE_SNAPSHOT="/work/conformance/$SNAPSHOT" \
  -e CERTONE_REPORT_JSON="/work/conformance/$REPORT_JSON" \
  -e OWNER="$OWNER" \
  "$IMAGE" sh -c 'rc=0; mvn -B -ntp -Pquickstart clean verify || rc=$?;
                  if [ -n "$OWNER" ]; then chown -R "$OWNER" target; fi; exit $rc' \
  | tee "$LOG"

# Conformance expectations (SPEC.md): check fails with findings, ingest passes, attested.
grep -q '^\[check\]  verdict: fail' "$LOG" || fail "expected the check verdict to be fail"
grep -q '^\[report\] first finding: ' "$LOG" || fail "expected a first finding"
grep -q '^\[ingest\] verdict: pass' "$LOG" || fail "expected the ingest verdict to be pass"
grep -q '^\[attest\] attestation_id: att-' "$LOG" || fail "expected an attestation id"
grep -q '^quickstart OK' "$LOG" || fail "quickstart did not complete"
echo "ci/run.sh: Java SDK build, unit tests and conformance quickstart passed"
