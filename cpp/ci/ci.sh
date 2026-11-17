#!/usr/bin/env bash
# CertOne C++ SDK CI, run inside the toolchain image (cpp/ci/Dockerfile) with the sdk/
# directory mounted read-only at /sdk. Builds out of tree under $WORK. Steps:
#   1. CMake build with the C core from ../c (-Werror, C++17) + offline unit tests (ctest)
#   2. CMake build against an *installed* C SDK (find_package(certone)) + unit tests
#   3. ASan + UBSan build: unit tests + quickstart
#   4. valgrind memcheck: quickstart
#   5. cross-compile for aarch64 and riscv64; run the unit tests and quickstart under qemu-user
#   6. native quickstart (the conformance run)
# The quickstart steps need CERTONE_API_URL/CERTONE_API_KEY/CERTONE_SNAPSHOT/CERTONE_REPORT_JSON
# and are skipped when CERTONE_SKIP_QUICKSTART=1.
set -euo pipefail

SRC="${CERTONE_CPP_SRC:-/cpp}"
FIXTURES="${CERTONE_FIXTURES:-/conformance/fixtures}"
WORK="${WORK:-/tmp/certone-cpp}"
SKIP_QS="${CERTONE_SKIP_QUICKSTART:-0}"
JOBS="$(nproc)"

step() { printf '\n==== %s\n' "$*"; }

rm -rf "$WORK" && mkdir -p "$WORK"
echo "g++: $(g++ --version | head -1)"
echo "cmake: $(cmake --version | head -1)"
echo "libcurl: $(pkg-config --modversion libcurl)"

step "1. CMake build (C core from ../c; -Wall -Wextra -Wpedantic -Wconversion -Wold-style-cast -Werror) + ctest"
cmake -S "$SRC" -B "$WORK/native" -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCERTONE_CPP_WERROR=ON \
  -DCERTONE_FIXTURES_DIR="$FIXTURES" >/dev/null
cmake --build "$WORK/native" -j "$JOBS"
ctest --test-dir "$WORK/native" --output-on-failure
(cd "$WORK/native" && ./test_cpp "$FIXTURES" | tail -1)

step "2. build against an installed C SDK (find_package(certone)) + unit tests"
cmake -S "$SRC/../c" -B "$WORK/c" -DCMAKE_BUILD_TYPE=Release -DCERTONE_BUILD_TESTS=OFF \
  -DCERTONE_BUILD_EXAMPLES=OFF -DCERTONE_WERROR=ON >/dev/null
cmake --build "$WORK/c" -j "$JOBS" >/dev/null
cmake --install "$WORK/c" --prefix "$WORK/prefix" >/dev/null
cmake -S "$SRC" -B "$WORK/installed" -DCERTONE_CPP_USE_INSTALLED_C=ON -DCERTONE_CPP_WERROR=ON \
  -DCMAKE_PREFIX_PATH="$WORK/prefix" -DCERTONE_FIXTURES_DIR="$FIXTURES" >/dev/null
cmake --build "$WORK/installed" -j "$JOBS"
(cd "$WORK/installed" && ./test_cpp "$FIXTURES" | tail -1)

step "3. ASan + UBSan: unit tests + quickstart"
SAN="-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all"
cmake -S "$SRC" -B "$WORK/asan" -DCMAKE_BUILD_TYPE=Debug -DCERTONE_CPP_WERROR=ON \
  -DCMAKE_C_FLAGS="$SAN" -DCMAKE_CXX_FLAGS="$SAN" -DCMAKE_EXE_LINKER_FLAGS="$SAN" >/dev/null
cmake --build "$WORK/asan" -j "$JOBS"
export ASAN_OPTIONS=detect_leaks=1:abort_on_error=1:strict_string_checks=1
export UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1
(cd "$WORK/asan" && ./test_cpp "$FIXTURES" | tail -1)
if [ "$SKIP_QS" != 1 ]; then
  "$WORK/asan/quickstart_cpp"
  echo "ASan/UBSan quickstart_cpp: exit 0, no errors, no leaks"
fi
unset ASAN_OPTIONS UBSAN_OPTIONS

if [ "$SKIP_QS" != 1 ]; then
  step "4. valgrind memcheck: quickstart_cpp"
  valgrind --quiet --leak-check=full --show-leak-kinds=definite,indirect,possible \
    --errors-for-leak-kinds=definite,indirect,possible --error-exitcode=97 \
    "$WORK/native/quickstart_cpp" >/dev/null
  echo "valgrind quickstart_cpp: exit 0 (0 errors, 0 definite/indirect/possible leaks)"
fi

for triple in aarch64-linux-gnu riscv64-linux-gnu; do
  arch="${triple%%-*}"
  step "5. cross-compile for $arch ($triple-g++, target libcurl) + run under qemu-$arch"
  CERTONE_CROSS_TRIPLE="$triple" cmake -S "$SRC" -B "$WORK/$arch" \
    -DCMAKE_TOOLCHAIN_FILE="$SRC/ci/cross-toolchain.cmake" -DCMAKE_BUILD_TYPE=Release \
    -DCERTONE_CPP_WERROR=ON -DCERTONE_FIXTURES_DIR="$FIXTURES" >/dev/null
  CERTONE_CROSS_TRIPLE="$triple" cmake --build "$WORK/$arch" -j "$JOBS"
  file "$WORK/$arch/quickstart_cpp" | sed "s|$WORK/||"
  (cd "$WORK/$arch" && "qemu-$arch" ./test_cpp "$FIXTURES" | tail -1)
  if [ "$SKIP_QS" != 1 ]; then
    "qemu-$arch" "$WORK/$arch/quickstart_cpp"
  fi
done

if [ "$SKIP_QS" != 1 ]; then
  step "6. quickstart_cpp (native) against $CERTONE_API_URL"
  "$WORK/native/quickstart_cpp"
fi

step "C++ SDK CI passed"
