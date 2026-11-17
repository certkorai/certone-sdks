cmake_minimum_required(VERSION 3.13)
project(certone_cpp VERSION 0.1.0 LANGUAGES C CXX)

# The C++ SDK wraps the C SDK. By default the C sources in ../c are built alongside (static);
# set CERTONE_CPP_USE_INSTALLED_C=ON to use an installed C SDK via find_package(certone).
option(CERTONE_CPP_USE_INSTALLED_C "Link an installed C SDK (find_package) instead of ../c" OFF)
option(CERTONE_CPP_BUILD_TESTS "Build the offline unit tests" ON)
option(CERTONE_CPP_BUILD_EXAMPLES "Build examples/quickstart" ON)
option(CERTONE_CPP_WERROR "Treat compiler warnings as errors" OFF)
set(CERTONE_C_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../c" CACHE PATH "CertOne C SDK source directory")

if(CERTONE_CPP_USE_INSTALLED_C)
  find_package(certone 0.1 REQUIRED)
else()
  set(CERTONE_BUILD_SHARED OFF CACHE BOOL "" FORCE)
  set(CERTONE_BUILD_STATIC ON CACHE BOOL "" FORCE)
  set(CERTONE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
  set(CERTONE_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
  set(CERTONE_WERROR ${CERTONE_CPP_WERROR} CACHE BOOL "" FORCE)
  add_subdirectory("${CERTONE_C_DIR}" certone-c)
endif()

include(GNUInstallDirs)
set(CERTONE_CPP_WARNINGS -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion
    -Wold-style-cast -Wnon-virtual-dtor -Woverloaded-virtual)
if(CERTONE_CPP_WERROR)
  list(APPEND CERTONE_CPP_WARNINGS -Werror)
endif()

function(certone_cpp_configure target)
  set_target_properties(${target} PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF)
  if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(${target} PRIVATE ${CERTONE_CPP_WARNINGS})
  endif()
endfunction()

add_library(certone_cpp src/certone.cpp)
add_library(certone::cpp ALIAS certone_cpp)
target_include_directories(certone_cpp PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_link_libraries(certone_cpp PUBLIC certone::certone)
set_target_properties(certone_cpp PROPERTIES OUTPUT_NAME certone++ VERSION ${PROJECT_VERSION}
  SOVERSION ${PROJECT_VERSION_MAJOR} POSITION_INDEPENDENT_CODE ON)
certone_cpp_configure(certone_cpp)

if(CERTONE_CPP_BUILD_TESTS)
  enable_testing()
  find_package(Threads REQUIRED)
  set(CERTONE_FIXTURES_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../conformance/fixtures"
      CACHE PATH "Directory with the SDK conformance JSON fixtures")
  add_executable(test_cpp tests/test_cpp.cpp)
  target_link_libraries(test_cpp PRIVATE certone_cpp Threads::Threads)
  certone_cpp_configure(test_cpp)
  add_test(NAME cpp COMMAND test_cpp "${CERTONE_FIXTURES_DIR}")
endif()

if(CERTONE_CPP_BUILD_EXAMPLES)
  add_executable(quickstart_cpp examples/quickstart.cpp)
  target_link_libraries(quickstart_cpp PRIVATE certone_cpp)
  certone_cpp_configure(quickstart_cpp)
endif()

install(TARGETS certone_cpp
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES include/certone/certone.hpp DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/certone)
