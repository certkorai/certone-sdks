#!/usr/bin/env bash
# One CI job inside a node:<version> container (invoked by ci/run.sh). /src/sdk is the read-only
# repo `sdk/` directory. LIVE=1 runs the quickstarts against http://certone-cp:8000; PRIMARY=1 also
# runs the package lint and `npm pack --dry-run`.
set -euo pipefail

echo "node $(node --version), npm $(npm --version)"
mkdir -p /work/sdk
# Copy the sources (never host build output or host node_modules) and the shared conformance assets.
tar -C /src/sdk -cf - \
  --exclude=js/node_modules --exclude=js/dist --exclude=js/.examples-build --exclude='js/*.tgz' \
  js conformance | tar -C /work/sdk -xf -
cd /work/js

step() { echo; echo "---- $* ----"; }

step "npm ci"
npm ci --no-audit --no-fund --loglevel=error

step "typecheck (strict; browser entry without Node types)"
npm run --silent typecheck

step "build (ESM + CJS + .d.ts)"
npm run --silent build

step "typecheck examples against the built package"
npm run --silent typecheck:examples

step "unit tests"
npx vitest run

step "browser entry graph has no Node-only imports"
browser_files="index common client errors types validate version binary sha256"
for f in $browser_files; do
  for dir in dist/esm dist/cjs; do
    if grep -nE "(from |require\()[\"']node:" "$dir/$f.js"; then
      echo "Node-only import in browser entry file $dir/$f.js" >&2
      exit 1
    fi
  done
done
echo "ok: $browser_files"

if [ "${PRIMARY:-0}" = 1 ]; then
  step "package types resolution (arethetypeswrong)"
  npm run --silent lint:package

  step "npm pack --dry-run"
  npm pack --dry-run 2>&1 | grep -v "^npm notice$" | sed -n '/Tarball Contents/,$p'
fi

step "install the packed tarball into a fresh consumer project"
tarball="$(npm pack --silent | tail -1)"
consumer="$(mktemp -d)"
(
  cd "$consumer"
  npm init -y >/dev/null
  npm install --no-audit --no-fund --loglevel=error "/work/js/$tarball"
  test -z "$(ls node_modules | grep -v '^@certkor$' || true)" || { echo "unexpected runtime dependencies" >&2; ls node_modules; exit 1; }
  node -e '
    const m = require("@certkor/certone");
    for (const k of ["CertOneClient", "CertOneError", "sha256Hex", "inputDigest", "parseCheckResult"]) {
      if (typeof m[k] !== "function") throw new Error("CJS export missing: " + k);
    }
    m.sha256Hex(Buffer.from("abc")).then((h) => {
      if (h !== "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") throw new Error("bad digest");
      console.log("require(): ok, VERSION " + m.VERSION);
    });'
  node --input-type=module -e '
    import { CertOneClient, CertOneError, VERSION } from "@certkor/certone";
    const c = new CertOneClient({ baseUrl: "https://api.example.com", token: "ck_x" });
    if (!(c instanceof CertOneClient) || typeof CertOneError.is !== "function") throw new Error("bad ESM exports");
    console.log("import: ok, VERSION " + VERSION);'
)
rm -rf "$consumer" "$tarball"

if [ "${LIVE:-0}" != 1 ]; then
  echo; echo "offline job passed"
  exit 0
fi

step "quickstart against the live control plane"
# conformance.env may have CRLF line endings (written on Windows); never echo its contents.
tr -d '\r' < /work/conformance/conformance.env > /tmp/conformance.env
set -a
# shellcheck disable=SC1091
. /tmp/conformance.env
set +a
rm -f /tmp/conformance.env
export CERTONE_API_URL="${CERTONE_API_URL_DOCKER:-http://certone-cp:8000}"
export CERTONE_SNAPSHOT="/work/conformance/${CERTONE_SNAPSHOT##*/}"
export CERTONE_REPORT_JSON="/work/conformance/${CERTONE_REPORT_JSON##*/}"
curl -fsS "$CERTONE_API_URL/healthz" >/dev/null || { echo "control plane unreachable at $CERTONE_API_URL" >&2; exit 1; }

check_output() {
  local out="$1"
  grep -q "^    verdict: fail " "$out" || { echo "expected the check verdict to be fail" >&2; exit 1; }
  grep -q "^    verdict: pass " "$out" || { echo "expected the ingest verdict to be pass" >&2; exit 1; }
  grep -qE "^\[5\] attestation_id: att-[0-9a-f]+$" "$out" || { echo "expected an attestation id" >&2; exit 1; }
  if grep -qF "$CERTONE_API_KEY" "$out"; then echo "the API key appeared in the output" >&2; exit 1; fi
}

echo "+ node examples/quickstart.mjs"
node examples/quickstart.mjs | tee /tmp/quickstart-mjs.out
check_output /tmp/quickstart-mjs.out

echo; echo "+ tsc examples/quickstart.ts && node .examples-build/quickstart.js"
npx tsc -p examples/tsconfig.json --noEmit false --outDir .examples-build
node .examples-build/quickstart.js | tee /tmp/quickstart-ts.out
check_output /tmp/quickstart-ts.out

echo; echo "live job passed"
