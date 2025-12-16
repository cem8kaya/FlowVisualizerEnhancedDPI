cmake_minimum_required(VERSION 3.14)

project(CallflowVisualizer
    VERSION 0.1.0
    DESCRIPTION "Telecom Callflow Visualizer with nDPI"
    LANGUAGES CXX C
)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Export compile commands for IDE support
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Compiler flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -O0 -fsanitize=address -fsanitize=undefined")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3 -DNDEBUG")

# Options
option(BUILD_TESTS "Build unit tests" ON)
option(BUILD_API_SERVER "Build REST API server" ON)
option(BUILD_BENCHMARKS "Build performance benchmarks" ON)
option(ENABLE_COVERAGE "Enable code coverage" OFF)
option(ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)
option(ENABLE_TLS "Enable TLS/HTTPS support" ON)

# Include paths
include_directories(${PROJECT_SOURCE_DIR}/include)

# Find dependencies
find_package(Threads REQUIRED)

# Find libpcap
find_path(PCAP_INCLUDE_DIR pcap.h)
find_library(PCAP_LIBRARY pcap)
if(NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARY)
    message(FATAL_ERROR "libpcap not found. Install with: apt-get install libpcap-dev")
endif()
message(STATUS "Found libpcap: ${PCAP_LIBRARY}")

# Find SQLite3
find_package(SQLite3)
if(NOT SQLite3_FOUND)
    message(WARNING "SQLite3 not found. Database persistence will be disabled.")
    message(STATUS "To install SQLite3:")
    message(STATUS "  sudo apt-get install libsqlite3-dev")
else()
    message(STATUS "Found SQLite3: ${SQLite3_LIBRARIES}")
endif()

# Find nDPI (check common locations)
find_path(NDPI_INCLUDE_DIR
    NAMES ndpi_api.h
    PATHS /usr/include /usr/local/include
    PATH_SUFFIXES ndpi
)
find_library(NDPI_LIBRARY
    NAMES ndpi libndpi
    PATHS /usr/lib /usr/local/lib
)
if(NOT NDPI_INCLUDE_DIR OR NOT NDPI_LIBRARY)
    message(WARNING "nDPI not found in system. Will need to build from source.")
    message(STATUS "To install nDPI:")
    message(STATUS "  git clone https://github.com/ntop/nDPI.git")
    message(STATUS "  cd nDPI && ./autogen.sh && ./configure && make && sudo make install")
    set(NEED_NDPI_BUILD TRUE)
else()
    message(STATUS "Found nDPI: ${NDPI_LIBRARY}")
    message(STATUS "nDPI headers: ${NDPI_INCLUDE_DIR}")
endif()

# FetchContent for external dependencies
include(FetchContent)

# JSON library (nlohmann/json - header only)
set(JSON_BuildTests OFF CACHE INTERNAL "")
set(JSON_Install OFF CACHE INTERNAL "")

FetchContent_Declare(
    json
    URL https://github.com/nlohmann/json/releases/download/v3.11.2/json.tar.xz
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(json)
message(STATUS "nlohmann/json fetched successfully")

# fmt library for logging
FetchContent_Declare(
    fmt
    URL https://github.com/fmtlib/fmt/releases/download/10.1.1/fmt-10.1.1.zip
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(fmt)
message(STATUS "fmt fetched for logging")

# cpp-httplib (header only HTTP server/client library)
if(BUILD_API_SERVER)
    FetchContent_Declare(
        httplib
        URL https://github.com/yhirose/cpp-httplib/archive/refs/tags/v0.14.3.tar.gz
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )
    FetchContent_MakeAvailable(httplib)
    message(STATUS "cpp-httplib fetched for API server")

    # OpenSSL for HTTPS/TLS support and JWT signing
    if(ENABLE_TLS)
        find_package(OpenSSL REQUIRED)
        if(OpenSSL_FOUND)
            message(STATUS "Found OpenSSL: ${OPENSSL_VERSION}")
            message(STATUS "  Include: ${OPENSSL_INCLUDE_DIR}")
            message(STATUS "  Libraries: ${OPENSSL_LIBRARIES}")
        endif()
    endif()

    # jwt-cpp for JWT token handling
    set(JWT_BUILD_EXAMPLES OFF CACHE INTERNAL "")
    set(JWT_BUILD_TESTS OFF CACHE INTERNAL "")
    set(JWT_DISABLE_PICOJSON ON CACHE INTERNAL "")
    
    FetchContent_Declare(
        jwt-cpp
        GIT_REPOSITORY https://github.com/Thalhammer/jwt-cpp.git
        GIT_TAG v0.7.0
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )
    
    # Make nlohmann_json available to jwt-cpp
    set(nlohmann_json_DIR "${json_BINARY_DIR}")
    
    FetchContent_MakeAvailable(jwt-cpp)
    message(STATUS "jwt-cpp fetched for authentication")
endif()

# Google Test for unit testing
if(BUILD_TESTS)
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG v1.14.0
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )
    # Prevent GoogleTest from overriding compiler/linker options
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
    message(STATUS "GoogleTest fetched for unit testing")
endif()

# Google Benchmark for performance testing
if(BUILD_BENCHMARKS)
    FetchContent_Declare(
        benchmark
        GIT_REPOSITORY https://github.com/google/benchmark.git
        GIT_TAG v1.8.3
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )
    set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "" FORCE)
    set(BENCHMARK_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(benchmark)
    message(STATUS "Google Benchmark fetched for performance testing")
endif()

# Add subdirectories
add_subdirectory(src)

if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(BUILD_BENCHMARKS)
    if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/bench)
        add_subdirectory(bench)
    else()
        message(WARNING "Benchmarks enabled but bench/ directory not found. Skipping benchmarks.")
    endif()
endif()

# Installation
install(TARGETS callflowd DESTINATION bin)
install(DIRECTORY ui/static DESTINATION share/callflow-visualizer/ui)

# Sanitizers
if(ENABLE_ASAN)
    message(STATUS "AddressSanitizer enabled")
    add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address)
endif()

if(ENABLE_UBSAN)
    message(STATUS "UndefinedBehaviorSanitizer enabled")
    add_compile_options(-fsanitize=undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=undefined)
endif()

if(ENABLE_COVERAGE)
    message(STATUS "Code coverage enabled")
    add_compile_options(--coverage -O0 -g)
    add_link_options(--coverage)
endif()

# Print configuration summary
message(STATUS "")
message(STATUS "Configuration Summary:")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  C++ standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  Build tests: ${BUILD_TESTS}")
message(STATUS "  Build benchmarks: ${BUILD_BENCHMARKS}")
message(STATUS "  Build API server: ${BUILD_API_SERVER}")
message(STATUS "  Enable TLS/HTTPS: ${ENABLE_TLS}")
message(STATUS "  Enable sanitizers: ASAN=${ENABLE_ASAN} UBSAN=${ENABLE_UBSAN}")
message(STATUS "  Enable coverage: ${ENABLE_COVERAGE}")
message(STATUS "  Install prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "")
