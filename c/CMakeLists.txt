cmake_minimum_required(VERSION 3.13)
project(certone VERSION 0.1.0 LANGUAGES C)

option(CERTONE_BUILD_SHARED "Build libcertone as a shared library" ON)
option(CERTONE_BUILD_STATIC "Build libcertone as a static library" ON)
option(CERTONE_BUILD_TESTS "Build the offline unit tests" ON)
option(CERTONE_BUILD_EXAMPLES "Build examples/quickstart" ON)
option(CERTONE_WERROR "Treat compiler warnings as errors" OFF)

if(NOT CERTONE_BUILD_SHARED AND NOT CERTONE_BUILD_STATIC)
  message(FATAL_ERROR "enable CERTONE_BUILD_SHARED and/or CERTONE_BUILD_STATIC")
endif()

find_package(CURL 7.56 REQUIRED)
include(GNUInstallDirs)

set(CERTONE_SOURCES src/certone.c src/json.c src/sha256.c)
set(CERTONE_WARNINGS -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes -Wconversion
    -Wno-sign-conversion)
if(CERTONE_WERROR)
  list(APPEND CERTONE_WARNINGS -Werror)
endif()

function(certone_configure target)
  target_include_directories(${target}
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
           $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
  target_link_libraries(${target} PUBLIC CURL::libcurl)
  set_target_properties(${target} PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON
    C_EXTENSIONS OFF OUTPUT_NAME certone)
  if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(${target} PRIVATE ${CERTONE_WARNINGS})
  endif()
endfunction()

set(CERTONE_TARGETS)
if(CERTONE_BUILD_STATIC)
  add_library(certone_static STATIC ${CERTONE_SOURCES})
  certone_configure(certone_static)
  set_target_properties(certone_static PROPERTIES POSITION_INDEPENDENT_CODE ON)
  list(APPEND CERTONE_TARGETS certone_static)
endif()
if(CERTONE_BUILD_SHARED)
  add_library(certone_shared SHARED ${CERTONE_SOURCES})
  certone_configure(certone_shared)
  target_compile_definitions(certone_shared PUBLIC CERTONE_SHARED)
  set_target_properties(certone_shared PROPERTIES VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR} C_VISIBILITY_PRESET hidden)
  list(APPEND CERTONE_TARGETS certone_shared)
endif()

# `certone::certone` is what consumers (and the tests/examples) link: static when available.
if(CERTONE_BUILD_STATIC)
  add_library(certone::certone ALIAS certone_static)
else()
  add_library(certone::certone ALIAS certone_shared)
endif()

if(CERTONE_BUILD_TESTS)
  enable_testing()
  find_package(Threads REQUIRED)
  set(CERTONE_FIXTURES_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../conformance/fixtures"
      CACHE PATH "Directory with the SDK conformance JSON fixtures")
  foreach(t json sha256 request client)
    add_executable(test_${t} tests/test_${t}.c)
    target_link_libraries(test_${t} PRIVATE certone_static Threads::Threads)
    target_include_directories(test_${t} PRIVATE src tests)
    set_target_properties(test_${t} PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON
      C_EXTENSIONS OFF)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
      target_compile_options(test_${t} PRIVATE ${CERTONE_WARNINGS})
    endif()
    add_test(NAME ${t} COMMAND test_${t} "${CERTONE_FIXTURES_DIR}")
  endforeach()
  if(NOT CERTONE_BUILD_STATIC)
    message(FATAL_ERROR "the unit tests link the static library: enable CERTONE_BUILD_STATIC")
  endif()
endif()

if(CERTONE_BUILD_EXAMPLES)
  add_executable(quickstart examples/quickstart.c)
  target_link_libraries(quickstart PRIVATE certone::certone)
  set_target_properties(quickstart PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON
    C_EXTENSIONS OFF)
  if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(quickstart PRIVATE ${CERTONE_WARNINGS})
  endif()
endif()

install(TARGETS ${CERTONE_TARGETS} EXPORT certoneTargets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES include/certone.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT certoneTargets NAMESPACE certone:: DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/certone)
include(CMakePackageConfigHelpers)
configure_package_config_file(cmake/certoneConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/certoneConfig.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/certone)
write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/certoneConfigVersion.cmake
  COMPATIBILITY SameMinorVersion)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/certoneConfig.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/certoneConfigVersion.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/certone)
configure_file(cmake/certone.pc.in ${CMAKE_CURRENT_BINARY_DIR}/certone.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/certone.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
