# Tests CMakeLists.txt

message(STATUS "Configuring unit tests")

# PCAPNG Reader Tests
add_executable(test_pcapng_reader
    unit/test_pcapng_reader.cpp
)

target_link_libraries(test_pcapng_reader PRIVATE
    callflow_common
    pcap_ingest
    GTest::gtest
    GTest::gtest_main
)

# Register tests with CTest
add_test(NAME test_pcapng_reader COMMAND test_pcapng_reader)

# Set test properties
set_tests_properties(test_pcapng_reader PROPERTIES
    TIMEOUT 30
    LABELS "unit"
)

message(STATUS "Unit tests configured successfully")
