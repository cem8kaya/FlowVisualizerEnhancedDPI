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
option(ENABLE_COVERAGE "Enable code coverage" OFF)

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
FetchContent_Declare(
    json
    URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
)
FetchContent_MakeAvailable(json)

# cpp-httplib (header only HTTP server/client library)
if(BUILD_API_SERVER)
    FetchContent_Declare(
        httplib
        URL https://github.com/yhirose/cpp-httplib/archive/refs/tags/v0.14.3.tar.gz
    )
    FetchContent_MakeAvailable(httplib)
    message(STATUS "cpp-httplib fetched for API server")
endif()

# Add subdirectories
add_subdirectory(src)

if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Installation
install(TARGETS callflowd DESTINATION bin)
install(DIRECTORY ui/static DESTINATION share/callflow-visualizer/ui)

# Print configuration summary
message(STATUS "")
message(STATUS "Configuration Summary:")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  C++ standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  Build tests: ${BUILD_TESTS}")
message(STATUS "  Build API server: ${BUILD_API_SERVER}")
message(STATUS "  Install prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "")
