#include <gtest/gtest.h>
#include "protocol_parsers/gtp/gtpv2_ie_parser.h"
#include <vector>
#include <cstring>
#include <arpa/inet.h>

using namespace callflow::gtp;

// ============================================================================
// IMSI BCD Decoding Tests
// ============================================================================

TEST(GtpV2IEParser, IMSI_BCD_Decoding) {
    // Test IMSI: 001010123456789 (15 digits)
    // BCD encoding: 00 10 01 21 43 65 87 F9
    std::vector<uint8_t> imsi_data = {0x00, 0x10, 0x01, 0x21, 0x43, 0x65, 0x87, 0xF9};

    auto result = GtpV2IEParser::decodeBCD(imsi_data.data(), imsi_data.size());
    EXPECT_EQ(result, "001010123456789");
}

TEST(GtpV2IEParser, IMSI_BCD_Decoding_14Digits) {
    // Test IMSI: 00101012345678 (14 digits, filler in high nibble of last byte)
    // BCD encoding: 00 10 01 21 43 65 87 0F
    std::vector<uint8_t> imsi_data = {0x00, 0x10, 0x01, 0x21, 0x43, 0x65, 0x87, 0x0F};

    auto result = GtpV2IEParser::decodeBCD(imsi_data.data(), imsi_data.size());
    EXPECT_EQ(result, "00101012345678");
}

TEST(GtpV2IEParser, IMSI_Parse_Valid) {
    // Create a complete IMSI IE
    std::vector<uint8_t> ie_data = {0x00, 0x10, 0x01, 0x21, 0x43, 0x65, 0x87, 0xF9};

    GtpV2IE ie;
    ie.header.type = GtpV2IEType::IMSI;
    ie.header.length = ie_data.size();
    ie.header.instance = 0;
    ie.header.cr_flag = false;
    ie.value = ie_data;

    auto imsi_opt = GtpV2IEParser::parseIMSI(ie);
    ASSERT_TRUE(imsi_opt.has_value());
    EXPECT_EQ(imsi_opt.value().imsi, "001010123456789");
}

TEST(GtpV2IMSI, Parse_InvalidLength) {
    // Too short
    std::vector<uint8_t> short_data = {};
    auto result = GtpV2IMSI::parse(short_data);
    EXPECT_FALSE(result.has_value());

    // Too long
    std::vector<uint8_t> long_data(10, 0x00);
    result = GtpV2IMSI::parse(long_data);
    EXPECT_FALSE(result.has_value());
}

// ============================================================================
// F-TEID Parsing Tests
// ============================================================================

TEST(GtpV2FTEID, Parse_IPv4_Only) {
    // F-TEID with IPv4 only
    // Flags: V4=1, V6=0, Interface=S1-U SGW GTP-U (1)
    // TEID: 0x12345678
    // IPv4: 192.168.1.1
    std::vector<uint8_t> fteid_data = {
        0x81,  // Flags: V4=1, Interface=1 (S1-U SGW GTP-U)
        0x12, 0x34, 0x56, 0x78,  // TEID
        192, 168, 1, 1  // IPv4 address
    };

    auto fteid_opt = GtpV2FTEID::parse(fteid_data);
    ASSERT_TRUE(fteid_opt.has_value());

    const auto& fteid = fteid_opt.value();
    EXPECT_EQ(fteid.interface_type, FTEIDInterfaceType::S1_U_SGW_GTP_U);
    EXPECT_EQ(fteid.teid, 0x12345678);
    ASSERT_TRUE(fteid.ipv4_address.has_value());
    EXPECT_EQ(fteid.ipv4_address.value(), "192.168.1.1");
    EXPECT_FALSE(fteid.ipv6_address.has_value());
}

TEST(GtpV2FTEID, Parse_IPv6_Only) {
    // F-TEID with IPv6 only
    // Flags: V4=0, V6=1, Interface=S5/S8 PGW GTP-U (5)
    // TEID: 0xABCDEF00
    // IPv6: 2001:db8::1
    std::vector<uint8_t> fteid_data = {
        0x45,  // Flags: V6=1, Interface=5 (S5/S8 PGW GTP-U)
        0xAB, 0xCD, 0xEF, 0x00,  // TEID
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01  // IPv6 address
    };

    auto fteid_opt = GtpV2FTEID::parse(fteid_data);
    ASSERT_TRUE(fteid_opt.has_value());

    const auto& fteid = fteid_opt.value();
    EXPECT_EQ(fteid.interface_type, FTEIDInterfaceType::S5_S8_PGW_GTP_U);
    EXPECT_EQ(fteid.teid, 0xABCDEF00);
    EXPECT_FALSE(fteid.ipv4_address.has_value());
    ASSERT_TRUE(fteid.ipv6_address.has_value());
    EXPECT_EQ(fteid.ipv6_address.value(), "2001:db8::1");
}

TEST(GtpV2FTEID, Parse_IPv4_And_IPv6) {
    // F-TEID with both IPv4 and IPv6
    // Flags: V4=1, V6=1, Interface=S11 MME GTP-C (10)
    // TEID: 0x11223344
    // IPv4: 10.0.0.1
    // IPv6: fe80::1
    std::vector<uint8_t> fteid_data = {
        0xCA,  // Flags: V4=1, V6=1, Interface=10 (S11 MME GTP-C)
        0x11, 0x22, 0x33, 0x44,  // TEID
        10, 0, 0, 1,  // IPv4
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01  // IPv6
    };

    auto fteid_opt = GtpV2FTEID::parse(fteid_data);
    ASSERT_TRUE(fteid_opt.has_value());

    const auto& fteid = fteid_opt.value();
    EXPECT_EQ(fteid.interface_type, FTEIDInterfaceType::S11_MME_GTP_C);
    EXPECT_EQ(fteid.teid, 0x11223344);
    ASSERT_TRUE(fteid.ipv4_address.has_value());
    EXPECT_EQ(fteid.ipv4_address.value(), "10.0.0.1");
    ASSERT_TRUE(fteid.ipv6_address.has_value());
    EXPECT_EQ(fteid.ipv6_address.value(), "fe80::1");
}

TEST(GtpV2FTEID, Parse_TooShort) {
    std::vector<uint8_t> fteid_data = {0x81, 0x12, 0x34};  // Only 3 bytes
    auto fteid_opt = GtpV2FTEID::parse(fteid_data);
    EXPECT_FALSE(fteid_opt.has_value());
}

TEST(GtpV2FTEID, InterfaceTypeNames) {
    GtpV2FTEID fteid;
    fteid.interface_type = FTEIDInterfaceType::S1_U_ENODEB_GTP_U;
    EXPECT_EQ(fteid.getInterfaceTypeName(), "S1-U eNodeB GTP-U");

    fteid.interface_type = FTEIDInterfaceType::S1_U_SGW_GTP_U;
    EXPECT_EQ(fteid.getInterfaceTypeName(), "S1-U SGW GTP-U");

    fteid.interface_type = FTEIDInterfaceType::S5_S8_SGW_GTP_U;
    EXPECT_EQ(fteid.getInterfaceTypeName(), "S5/S8 SGW GTP-U");

    fteid.interface_type = FTEIDInterfaceType::S5_S8_PGW_GTP_U;
    EXPECT_EQ(fteid.getInterfaceTypeName(), "S5/S8 PGW GTP-U");

    fteid.interface_type = FTEIDInterfaceType::S11_MME_GTP_C;
    EXPECT_EQ(fteid.getInterfaceTypeName(), "S11 MME GTP-C");
}

// ============================================================================
// Bearer QoS Parsing Tests
// ============================================================================

TEST(GtpV2BearerQoS, Parse_Valid) {
    // Create Bearer QoS IE data (22 bytes minimum)
    std::vector<uint8_t> qos_data(22);

    // Byte 0: PCI=1, PL=5, PVI=0
    qos_data[0] = (1 << 6) | (5 << 2) | (0 << 1);

    // Byte 1: QCI=9 (best effort)
    qos_data[1] = 9;

    // Bytes 2-6: Max Bit Rate Uplink = 1000000 bps
    uint64_t mbr_ul = 1000000;
    for (int i = 4; i >= 0; --i) {
        qos_data[2 + i] = mbr_ul & 0xFF;
        mbr_ul >>= 8;
    }

    // Bytes 7-11: Max Bit Rate Downlink = 10000000 bps
    uint64_t mbr_dl = 10000000;
    for (int i = 4; i >= 0; --i) {
        qos_data[7 + i] = mbr_dl & 0xFF;
        mbr_dl >>= 8;
    }

    // Bytes 12-16: Guaranteed Bit Rate Uplink = 500000 bps
    uint64_t gbr_ul = 500000;
    for (int i = 4; i >= 0; --i) {
        qos_data[12 + i] = gbr_ul & 0xFF;
        gbr_ul >>= 8;
    }

    // Bytes 17-21: Guaranteed Bit Rate Downlink = 5000000 bps
    uint64_t gbr_dl = 5000000;
    for (int i = 4; i >= 0; --i) {
        qos_data[17 + i] = gbr_dl & 0xFF;
        gbr_dl >>= 8;
    }

    auto qos_opt = GtpV2BearerQoS::parse(qos_data);
    ASSERT_TRUE(qos_opt.has_value());

    const auto& qos = qos_opt.value();
    EXPECT_EQ(qos.pci, 1);
    EXPECT_EQ(qos.pl, 5);
    EXPECT_EQ(qos.pvi, 0);
    EXPECT_EQ(qos.qci, 9);
    EXPECT_EQ(qos.max_bitrate_uplink, 1000000);
    EXPECT_EQ(qos.max_bitrate_downlink, 10000000);
    EXPECT_EQ(qos.guaranteed_bitrate_uplink, 500000);
    EXPECT_EQ(qos.guaranteed_bitrate_downlink, 5000000);
}

TEST(GtpV2BearerQoS, QCI_Names) {
    GtpV2BearerQoS qos;
    qos.qci = 1;
    EXPECT_EQ(qos.getQCIName(), "Conversational Voice");

    qos.qci = 5;
    EXPECT_EQ(qos.getQCIName(), "IMS Signalling");

    qos.qci = 9;
    EXPECT_TRUE(qos.getQCIName().find("Buffered Streaming") != std::string::npos);

    qos.qci = 128;
    EXPECT_TRUE(qos.getQCIName().find("Operator-specific") != std::string::npos);
}

// ============================================================================
// PDN Address Allocation Parsing Tests
// ============================================================================

TEST(GtpV2PAA, Parse_IPv4) {
    // PDN Type: IPv4 (1)
    // IPv4 Address: 192.168.100.1
    std::vector<uint8_t> paa_data = {
        0x01,  // PDN Type: IPv4
        192, 168, 100, 1  // IPv4 address
    };

    auto paa_opt = GtpV2PDNAddressAllocation::parse(paa_data);
    ASSERT_TRUE(paa_opt.has_value());

    const auto& paa = paa_opt.value();
    EXPECT_EQ(paa.pdn_type, PDNType::IPv4);
    ASSERT_TRUE(paa.ipv4_address.has_value());
    EXPECT_EQ(paa.ipv4_address.value(), "192.168.100.1");
    EXPECT_FALSE(paa.ipv6_address.has_value());
}

TEST(GtpV2PAA, Parse_IPv6) {
    // PDN Type: IPv6 (2)
    // IPv6 Prefix Length: 64
    // IPv6 Address: 2001:db8:1::1
    std::vector<uint8_t> paa_data = {
        0x02,  // PDN Type: IPv6
        64,    // Prefix length
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01  // IPv6 address
    };

    auto paa_opt = GtpV2PDNAddressAllocation::parse(paa_data);
    ASSERT_TRUE(paa_opt.has_value());

    const auto& paa = paa_opt.value();
    EXPECT_EQ(paa.pdn_type, PDNType::IPv6);
    EXPECT_FALSE(paa.ipv4_address.has_value());
    ASSERT_TRUE(paa.ipv6_address.has_value());
    EXPECT_EQ(paa.ipv6_address.value(), "2001:db8:1::1");
    ASSERT_TRUE(paa.ipv6_prefix_length.has_value());
    EXPECT_EQ(paa.ipv6_prefix_length.value(), 64);
}

TEST(GtpV2PAA, Parse_IPv4v6) {
    // PDN Type: IPv4v6 (3)
    // IPv4: 10.0.0.1
    // IPv6 Prefix Length: 64
    // IPv6: fe80::1
    std::vector<uint8_t> paa_data = {
        0x03,  // PDN Type: IPv4v6
        10, 0, 0, 1,  // IPv4
        64,  // IPv6 prefix length
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01  // IPv6
    };

    auto paa_opt = GtpV2PDNAddressAllocation::parse(paa_data);
    ASSERT_TRUE(paa_opt.has_value());

    const auto& paa = paa_opt.value();
    EXPECT_EQ(paa.pdn_type, PDNType::IPv4v6);
    ASSERT_TRUE(paa.ipv4_address.has_value());
    EXPECT_EQ(paa.ipv4_address.value(), "10.0.0.1");
    ASSERT_TRUE(paa.ipv6_address.has_value());
    EXPECT_EQ(paa.ipv6_address.value(), "fe80::1");
    ASSERT_TRUE(paa.ipv6_prefix_length.has_value());
    EXPECT_EQ(paa.ipv6_prefix_length.value(), 64);
}

// ============================================================================
// APN Parsing Tests
// ============================================================================

TEST(GtpV2IEParser, APN_Decoding) {
    // APN: "internet.mnc001.mcc001.gprs"
    // Encoded: 8-byte label "internet", 6-byte label "mnc001", 6-byte label "mcc001", 4-byte label "gprs"
    std::vector<uint8_t> apn_data = {
        8, 'i', 'n', 't', 'e', 'r', 'n', 'e', 't',
        6, 'm', 'n', 'c', '0', '0', '1',
        6, 'm', 'c', 'c', '0', '0', '1',
        4, 'g', 'p', 'r', 's',
        0  // Terminator
    };

    auto result = GtpV2IEParser::decodeAPN(apn_data);
    EXPECT_EQ(result, "internet.mnc001.mcc001.gprs");
}

TEST(GtpV2IEParser, APN_Simple) {
    // APN: "internet"
    std::vector<uint8_t> apn_data = {
        8, 'i', 'n', 't', 'e', 'r', 'n', 'e', 't', 0
    };

    auto result = GtpV2IEParser::decodeAPN(apn_data);
    EXPECT_EQ(result, "internet");
}

// ============================================================================
// Cause Parsing Tests
// ============================================================================

TEST(GtpV2Cause, Parse_Simple) {
    // Cause: REQUEST_ACCEPTED (16)
    // Flags: PCE=0, BCE=0, CS=0
    std::vector<uint8_t> cause_data = {
        16,  // Cause value
        0    // Flags
    };

    auto cause_opt = GtpV2Cause::parse(cause_data);
    ASSERT_TRUE(cause_opt.has_value());

    const auto& cause = cause_opt.value();
    EXPECT_EQ(cause.cause_value, CauseValue::REQUEST_ACCEPTED);
    EXPECT_FALSE(cause.pce);
    EXPECT_FALSE(cause.bce);
    EXPECT_FALSE(cause.cs);
    EXPECT_FALSE(cause.offending_ie_type.has_value());
}

TEST(GtpV2Cause, Parse_WithOffendingIE) {
    // Cause: MANDATORY_IE_MISSING (70)
    // Flags: PCE=1, BCE=1, CS=1
    // Offending IE: IMSI (1), Length: 8, Instance: 0
    std::vector<uint8_t> cause_data = {
        70,  // Cause value
        0x07,  // Flags: PCE=1, BCE=1, CS=1
        1,     // Offending IE type: IMSI
        0, 8,  // IE Length: 8 (network byte order)
        0x00   // Instance: 0 (upper nibble)
    };

    auto cause_opt = GtpV2Cause::parse(cause_data);
    ASSERT_TRUE(cause_opt.has_value());

    const auto& cause = cause_opt.value();
    EXPECT_EQ(cause.cause_value, CauseValue::MANDATORY_IE_MISSING);
    EXPECT_TRUE(cause.pce);
    EXPECT_TRUE(cause.bce);
    EXPECT_TRUE(cause.cs);
    ASSERT_TRUE(cause.offending_ie_type.has_value());
    EXPECT_EQ(cause.offending_ie_type.value(), GtpV2IEType::IMSI);
    ASSERT_TRUE(cause.offending_ie_length.has_value());
    EXPECT_EQ(cause.offending_ie_length.value(), 8);
    ASSERT_TRUE(cause.offending_ie_instance.has_value());
    EXPECT_EQ(cause.offending_ie_instance.value(), 0);
}

// ============================================================================
// IE Header Parsing Tests
// ============================================================================

TEST(GtpV2IEParser, ParseIE_Header) {
    // Create IE data: IMSI IE with instance 0
    std::vector<uint8_t> data = {
        1,      // Type: IMSI
        0, 8,   // Length: 8 (network byte order)
        0x00,   // Instance: 0 (upper nibble), CR flag: 0
        // IE value (8 bytes IMSI)
        0x00, 0x10, 0x01, 0x21, 0x43, 0x65, 0x87, 0xF9
    };

    size_t offset = 0;
    auto ie_opt = GtpV2IEParser::parseIE(data.data(), data.size(), offset);

    ASSERT_TRUE(ie_opt.has_value());
    const auto& ie = ie_opt.value();

    EXPECT_EQ(ie.header.type, GtpV2IEType::IMSI);
    EXPECT_EQ(ie.header.length, 8);
    EXPECT_EQ(ie.header.instance, 0);
    EXPECT_FALSE(ie.header.cr_flag);
    EXPECT_EQ(ie.value.size(), 8);
    EXPECT_EQ(offset, 12);  // 4 bytes header + 8 bytes value
}

TEST(GtpV2IEParser, ParseIEs_Multiple) {
    // Create multiple IEs: IMSI + APN
    std::vector<uint8_t> data;

    // IE 1: IMSI
    data.push_back(1);  // Type
    data.push_back(0);  // Length high byte
    data.push_back(8);  // Length low byte
    data.push_back(0);  // Instance + flags
    // IMSI value
    for (int i = 0; i < 8; ++i) {
        data.push_back(0x00);
    }

    // IE 2: Recovery (3)
    data.push_back(3);  // Type
    data.push_back(0);  // Length high byte
    data.push_back(1);  // Length low byte
    data.push_back(0);  // Instance + flags
    data.push_back(42); // Recovery value

    auto ies = GtpV2IEParser::parseIEs(data.data(), data.size());
    EXPECT_EQ(ies.size(), 2);

    EXPECT_EQ(ies[0].header.type, GtpV2IEType::IMSI);
    EXPECT_EQ(ies[0].header.length, 8);

    EXPECT_EQ(ies[1].header.type, GtpV2IEType::RECOVERY);
    EXPECT_EQ(ies[1].header.length, 1);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
