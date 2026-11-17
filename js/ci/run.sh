#!/usr/bin/env bash
# Build, test, package-check and run the quickstart of the CertOne JavaScript/TypeScript SDK in
# Docker, on every supported Node.js line. Nothing is written to the host checkout: each job copies
# js + conformance into the container and works there.
#
#   js/ci/run.sh              # full run: needs the conformance control plane (see below)
#   js/ci/run.sh --offline    # build + unit tests + package checks only
#
# The live quickstart runs against the local control plane started by
#   the CertOne test environment (see README)
# and reaches it on the docker network `certone-sdk` at http://certone-cp:8000.
#
# Environment: NODE_IMAGES, the space-separated images to run on (default: Node 20, 18, 22, 24 on
# bookworm). The first image also runs the package lint (arethetypeswrong) and `npm pack --dry-run`.
set -euo pipefail
export MSYS_NO_PATHCONV=1 # Git Bash on Windows: keep container paths as-is

LIVE=1
case "${1:-}" in
  --offline) LIVE=0 ;;
  "") ;;
  *) echo "usage: $0 [--offline]" >&2; exit 2 ;;
esac

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SDK_DIR="$(cd "$HERE/../.." && pwd)"
# Docker Desktop on Windows needs a Windows path for bind mounts.
if SDK_MOUNT="$(cd "$SDK_DIR" && pwd -W 2>/dev/null)"; then :; else SDK_MOUNT="$SDK_DIR"; fi
NODE_IMAGES="${NODE_IMAGES:-node:20-bookworm node:18-bookworm node:22-bookworm node:24-bookworm}"
NETWORK="certone-sdk"

network_args=()
if [ "$LIVE" = 1 ]; then
  if ! docker network inspect "$NETWORK" >/dev/null 2>&1; then
    echo "docker network $NETWORK not found: start the control plane first" >&2
    echo "  the CertOne test environment (see README)   (or pass --offline)" >&2
    exit 1
  fi
  if [ ! -f "$SDK_DIR/conformance/conformance.env" ]; then
    echo "conformance/conformance.env missing: run the CertOne test environment (see README)" >&2
    exit 1
  fi
  network_args=(--network "$NETWORK")
fi

primary=1
for image in $NODE_IMAGES; do
  echo "================ $image ================"
  docker run --rm "${network_args[@]}" \
    -v "$SDK_MOUNT:/src/sdk:ro" \
    -e LIVE="$LIVE" -e PRIMARY="$primary" \
    "$image" bash /src/js/ci/in-container.sh
  primary=0
done
echo "all jobs passed: $NODE_IMAGES"
