#!/usr/bin/env bash
# CertOne C SDK CI, run inside the toolchain image (c/ci/Dockerfile) with the sdk/ directory
# mounted read-only at /sdk. Builds out of tree under $WORK. Steps:
#   1. CMake build (static + shared, -Werror) + offline unit tests (ctest)
#   2. plain Makefile build with -std=c11 -Wall -Wextra -Werror + unit tests
#   3. ASan + UBSan build: unit tests + quickstart
#   4. valgrind memcheck: unit tests + quickstart
#   5. cross-compile for aarch64 and riscv64 against the target libcurl; run the unit tests and
#      the quickstart under qemu-user
#   6. native quickstart (the conformance run)
# The quickstart steps need CERTONE_API_URL/CERTONE_API_KEY/CERTONE_SNAPSHOT/CERTONE_REPORT_JSON
# and are skipped when CERTONE_SKIP_QUICKSTART=1.
set -euo pipefail

SRC="${CERTONE_C_SRC:-/c}"
FIXTURES="${CERTONE_FIXTURES:-/conformance/fixtures}"
WORK="${WORK:-/tmp/certone-c}"
SKIP_QS="${CERTONE_SKIP_QUICKSTART:-0}"
JOBS="$(nproc)"

step() { printf '\n==== %s\n' "$*"; }

run_tests() { # <dir with test_* binaries> [runner...]
  local dir="$1"; shift
  local t
  for t in json sha256 request client; do
    (cd "$dir" && "$@" ./"test_$t" "$FIXTURES")
  done
}

rm -rf "$WORK" && mkdir -p "$WORK"
echo "gcc: $(gcc --version | head -1)"
echo "cmake: $(cmake --version | head -1)"
echo "libcurl: $(pkg-config --modversion libcurl)"

step "1. CMake build (static + shared, -Wall -Wextra -Wpedantic -Wconversion -Werror) + ctest"
cmake -S "$SRC" -B "$WORK/native" -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCERTONE_WERROR=ON \
  -DCERTONE_FIXTURES_DIR="$FIXTURES" >/dev/null
cmake --build "$WORK/native" -j "$JOBS"
ctest --test-dir "$WORK/native" --output-on-failure
ls -l "$WORK/native"/libcertone.*
cmake --install "$WORK/native" --prefix "$WORK/install" >/dev/null
echo "installed: $(cd "$WORK/install" && find . -type f -o -type l | sort | tr '\n' ' ')"
# The shared library must export exactly the public certone_* API (internals are hidden).
exported="$(nm -D --defined-only "$WORK/native/libcertone.so" | awk '{print $3}' | sort)"
unexpected="$(echo "$exported" | grep -v '^certone_[a-z0-9]' || true)"
if [ -n "$unexpected" ]; then
  echo "unexpected exported symbols: $unexpected" >&2
  exit 1
fi
echo "libcertone.so exports $(echo "$exported" | wc -l) symbols, all public certone_* API"

step "2. plain Makefile: -std=c11 -Wall -Wextra -Werror"
make -C "$SRC" BUILD="$WORK/make" CFLAGS="-O2 -g -Werror" -j "$JOBS" all
make -C "$SRC" BUILD="$WORK/make" FIXTURES="$FIXTURES" check

step "3. ASan + UBSan: unit tests + quickstart"
SAN="-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all"
cmake -S "$SRC" -B "$WORK/asan" -DCMAKE_BUILD_TYPE=Debug -DCERTONE_WERROR=ON \
  -DCERTONE_BUILD_SHARED=OFF -DCMAKE_C_FLAGS="$SAN" -DCMAKE_EXE_LINKER_FLAGS="$SAN" >/dev/null
cmake --build "$WORK/asan" -j "$JOBS"
export ASAN_OPTIONS=detect_leaks=1:abort_on_error=1:strict_string_checks=1
export UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1
run_tests "$WORK/asan"
if [ "$SKIP_QS" != 1 ]; then
  "$WORK/asan/quickstart"
  echo "ASan/UBSan quickstart: exit 0, no errors, no leaks"
fi
unset ASAN_OPTIONS UBSAN_OPTIONS

step "4. valgrind memcheck: unit tests + quickstart"
VG=(valgrind --quiet --leak-check=full --show-leak-kinds=definite,indirect,possible
    --errors-for-leak-kinds=definite,indirect,possible --error-exitcode=97)
for t in json sha256 request client; do
  (cd "$WORK/native" && "${VG[@]}" ./"test_$t" "$FIXTURES" | tail -1)
done
if [ "$SKIP_QS" != 1 ]; then
  "${VG[@]}" "$WORK/native/quickstart" >/dev/null
  echo "valgrind quickstart: exit 0 (0 errors, 0 definite/indirect/possible leaks)"
fi

for arch in aarch64 riscv64; do
  step "5. cross-compile for $arch (${arch}-linux-gnu-gcc, target libcurl) + run under qemu-$arch"
  case "$arch" in
    aarch64) multiarch=aarch64-linux-gnu ;;
    riscv64) multiarch=riscv64-linux-gnu ;;
  esac
  PKG_CONFIG_LIBDIR="/usr/lib/$multiarch/pkgconfig:/usr/share/pkgconfig" \
    make -C "$SRC" BUILD="$WORK/$arch" CC="$multiarch-gcc" AR="$multiarch-ar" \
    CFLAGS="-O2 -g -Werror" -j "$JOBS" all
  file "$WORK/$arch/libcertone.so" "$WORK/$arch/quickstart" | sed "s|$WORK/||"
  run_tests "$WORK/$arch" "qemu-$arch"
  if [ "$SKIP_QS" != 1 ]; then
    "qemu-$arch" "$WORK/$arch/quickstart"
  fi
done

if [ "$SKIP_QS" != 1 ]; then
  step "6. quickstart (native) against $CERTONE_API_URL"
  "$WORK/native/quickstart" | tee "$WORK/quickstart.out"
  # Cross-check the SDK's SHA-256 input_digest against coreutils.
  expected="sha256:$(sha256sum "$CERTONE_SNAPSHOT" | cut -d' ' -f1)"
  grep -q "input_digest $expected" "$WORK/quickstart.out"
  echo "input_digest matches sha256sum: $expected"
fi

step "C SDK CI passed"
