# Toolchain image for the CertOne C and C++ SDKs: native gcc/g++ + CMake + libcurl, valgrind,
# and cross toolchains with libcurl for aarch64 and riscv64 (Debian multiarch), plus qemu-user
# to run the cross-compiled unit tests and quickstart.
#
#   docker build -t certone-sdk-cpp-ci sdk/cpp/ci
FROM debian:trixie

ENV DEBIAN_FRONTEND=noninteractive
# Skip man pages and docs: co-installed multiarch -dev packages ship differing compressed man
# pages, which dpkg refuses to overwrite.
RUN echo 'path-exclude=/usr/share/man/*' > /etc/dpkg/dpkg.cfg.d/01-nodoc \
 && echo 'path-exclude=/usr/share/doc/*' >> /etc/dpkg/dpkg.cfg.d/01-nodoc \
 && echo 'path-include=/usr/share/doc/*/copyright' >> /etc/dpkg/dpkg.cfg.d/01-nodoc \
 && dpkg --add-architecture arm64 \
 && dpkg --add-architecture riscv64 \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential cmake make pkg-config ca-certificates valgrind file \
      libcurl4-openssl-dev \
      gcc-aarch64-linux-gnu g++-aarch64-linux-gnu libc6-dev-arm64-cross \
      libcurl4-openssl-dev:arm64 \
      gcc-riscv64-linux-gnu g++-riscv64-linux-gnu libc6-dev-riscv64-cross \
      libcurl4-openssl-dev:riscv64 \
      qemu-user \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /work
