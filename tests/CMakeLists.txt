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

# GTPv1 Parser Tests
add_executable(test_gtpv1_parser
    unit/test_gtpv1_parser.cpp
)

target_link_libraries(test_gtpv1_parser PRIVATE
    callflow_common
    protocol_parsers
    transport
    GTest::gtest
    GTest::gtest_main
)

add_test(NAME test_gtpv1_parser COMMAND test_gtpv1_parser)

set_tests_properties(test_gtpv1_parser PROPERTIES
    TIMEOUT 30
    LABELS "unit"
)

# SCTP Parser Tests
add_executable(test_sctp_parser
    unit/test_sctp_parser.cpp
)

target_link_libraries(test_sctp_parser PRIVATE
    callflow_common
    transport
    GTest::gtest
    GTest::gtest_main
)

add_test(NAME test_sctp_parser COMMAND test_sctp_parser)

set_tests_properties(test_sctp_parser PROPERTIES
    TIMEOUT 30
    LABELS "unit"
)

# S1AP Parser Tests
add_executable(test_s1ap_parser
    unit/test_s1ap_parser.cpp
)

target_link_libraries(test_s1ap_parser PRIVATE
    callflow_common
    protocol_parsers
    asn1_wrapper
    GTest::gtest
    GTest::gtest_main
)

add_test(NAME test_s1ap_parser COMMAND test_s1ap_parser)

set_tests_properties(test_s1ap_parser PROPERTIES
    TIMEOUT 30
    LABELS "unit"
)

# NAS Parser Tests
add_executable(test_nas_parser
    unit/test_nas_parser.cpp
)

target_link_libraries(test_nas_parser PRIVATE
    callflow_common
    protocol_parsers
    GTest::gtest
    GTest::gtest_main
)

add_test(NAME test_nas_parser COMMAND test_nas_parser)

set_tests_properties(test_nas_parser PROPERTIES
    TIMEOUT 30
    LABELS "unit"
)

# Diameter Base Protocol Tests
add_executable(test_diameter_base
    unit/test_diameter_base.cpp
)

target_link_libraries(test_diameter_base PRIVATE
    callflow_common
    protocol_parsers
    GTest::gtest
    GTest::gtest_main
)

add_test(NAME test_diameter_base COMMAND test_diameter_base)

set_tests_properties(test_diameter_base PROPERTIES
    TIMEOUT 30
    LABELS "unit"
)

# Diameter Gx Parser Tests
add_executable(test_diameter_gx
    unit/test_diameter_gx.cpp
)

target_link_libraries(test_diameter_gx PRIVATE
    callflow_common
    protocol_parsers
    GTest::gtest
    GTest::gtest_main
)

add_test(NAME test_diameter_gx COMMAND test_diameter_gx)

set_tests_properties(test_diameter_gx PROPERTIES
    TIMEOUT 30
    LABELS "unit"
)

# Diameter Rx Parser Tests
add_executable(test_diameter_rx
    unit/test_diameter_rx.cpp
)

target_link_libraries(test_diameter_rx PRIVATE
    callflow_common
    protocol_parsers
    GTest::gtest
    GTest::gtest_main
)

add_test(NAME test_diameter_rx COMMAND test_diameter_rx)

set_tests_properties(test_diameter_rx PROPERTIES
    TIMEOUT 30
    LABELS "unit"
)

# Diameter Gy Parser Tests
add_executable(test_diameter_gy
    unit/test_diameter_gy.cpp
)

target_link_libraries(test_diameter_gy PRIVATE
    callflow_common
    protocol_parsers
    GTest::gtest
    GTest::gtest_main
)

add_test(NAME test_diameter_gy COMMAND test_diameter_gy)

set_tests_properties(test_diameter_gy PROPERTIES
    TIMEOUT 30
    LABELS "unit"
)

message(STATUS "Unit tests configured successfully")
