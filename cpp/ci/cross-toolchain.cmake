# CMake toolchain for cross-compiling the CertOne SDKs with a Debian cross toolchain and the
# target's multiarch libcurl (libcurl4-openssl-dev:<arch>). Select the target with the
# CERTONE_CROSS_TRIPLE environment variable, e.g. aarch64-linux-gnu or riscv64-linux-gnu.
if(NOT DEFINED ENV{CERTONE_CROSS_TRIPLE})
  message(FATAL_ERROR "set CERTONE_CROSS_TRIPLE (e.g. aarch64-linux-gnu)")
endif()
set(_triple "$ENV{CERTONE_CROSS_TRIPLE}")
string(REGEX MATCH "^[^-]+" _arch "${_triple}")

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR ${_arch})
set(CMAKE_C_COMPILER ${_triple}-gcc)
set(CMAKE_CXX_COMPILER ${_triple}-g++)
set(CMAKE_LIBRARY_ARCHITECTURE ${_triple})
set(CMAKE_FIND_ROOT_PATH /usr/${_triple})
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_CROSSCOMPILING_EMULATOR qemu-${_arch})
# libcurl comes from the target's multiarch directory, not the host's pkg-config.
set(ENV{PKG_CONFIG_LIBDIR} "/usr/lib/${_triple}/pkgconfig:/usr/share/pkgconfig")
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY BOTH)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE BOTH)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE BOTH)
