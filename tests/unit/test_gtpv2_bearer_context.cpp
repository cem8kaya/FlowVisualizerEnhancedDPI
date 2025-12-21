#include <gtest/gtest.h>
#include "protocol_parsers/gtp/gtpv2_ie_parser.h"
#include <vector>
#include <cstring>
#include <arpa/inet.h>

using namespace callflow::gtp;

// ============================================================================
// Bearer Context Grouped IE Parsing Tests
// ============================================================================

TEST(GtpV2BearerContext, Parse_WithEPSBearerID) {
    // Create Bearer Context with EPS Bearer ID only
    std::vector<uint8_t> bearer_ctx_data;

    // Nested IE: EPS Bearer ID (73)
    bearer_ctx_data.push_back(73);  // Type: EPS Bearer ID
    bearer_ctx_data.push_back(0);   // Length high byte
    bearer_ctx_data.push_back(1);   // Length low byte
    bearer_ctx_data.push_back(0);   // Instance + flags
    bearer_ctx_data.push_back(5);   // EPS Bearer ID value: 5

    auto bearer_ctx_opt = GtpV2BearerContext::parse(bearer_ctx_data);
    ASSERT_TRUE(bearer_ctx_opt.has_value());

    const auto& bearer_ctx = bearer_ctx_opt.value();
    ASSERT_TRUE(bearer_ctx.eps_bearer_id.has_value());
    EXPECT_EQ(bearer_ctx.eps_bearer_id.value(), 5);
    EXPECT_FALSE(bearer_ctx.qos.has_value());
    EXPECT_TRUE(bearer_ctx.fteids.empty());
}

TEST(GtpV2BearerContext, Parse_WithSingleFTEID) {
    // Create Bearer Context with one F-TEID
    std::vector<uint8_t> bearer_ctx_data;

    // Nested IE: EPS Bearer ID
    bearer_ctx_data.push_back(73);  // Type
    bearer_ctx_data.push_back(0);   // Length high
    bearer_ctx_data.push_back(1);   // Length low
    bearer_ctx_data.push_back(0);   // Instance
    bearer_ctx_data.push_back(5);   // Value: Bearer ID 5

    // Nested IE: F-TEID (S1-U eNodeB GTP-U)
    bearer_ctx_data.push_back(87);  // Type: F-TEID
    bearer_ctx_data.push_back(0);   // Length high
    bearer_ctx_data.push_back(9);   // Length low (1 + 4 + 4 = 9)
    bearer_ctx_data.push_back(0);   // Instance
    // F-TEID value
    bearer_ctx_data.push_back(0x80);  // Flags: V4=1, Interface=0 (S1-U eNodeB)
    // TEID: 0xABCD1234
    bearer_ctx_data.push_back(0xAB);
    bearer_ctx_data.push_back(0xCD);
    bearer_ctx_data.push_back(0x12);
    bearer_ctx_data.push_back(0x34);
    // IPv4: 10.20.30.40
    bearer_ctx_data.push_back(10);
    bearer_ctx_data.push_back(20);
    bearer_ctx_data.push_back(30);
    bearer_ctx_data.push_back(40);

    auto bearer_ctx_opt = GtpV2BearerContext::parse(bearer_ctx_data);
    ASSERT_TRUE(bearer_ctx_opt.has_value());

    const auto& bearer_ctx = bearer_ctx_opt.value();
    ASSERT_TRUE(bearer_ctx.eps_bearer_id.has_value());
    EXPECT_EQ(bearer_ctx.eps_bearer_id.value(), 5);

    ASSERT_EQ(bearer_ctx.fteids.size(), 1);
    const auto& fteid = bearer_ctx.fteids[0];
    EXPECT_EQ(fteid.interface_type, FTEIDInterfaceType::S1_U_ENODEB_GTP_U);
    EXPECT_EQ(fteid.teid, 0xABCD1234);
    ASSERT_TRUE(fteid.ipv4_address.has_value());
    EXPECT_EQ(fteid.ipv4_address.value(), "10.20.30.40");
}

TEST(GtpV2BearerContext, Parse_WithMultipleFTEIDs) {
    // Create Bearer Context with multiple F-TEIDs
    // This simulates a Create Session Response with both uplink and downlink TEIDs
    std::vector<uint8_t> bearer_ctx_data;

    // Nested IE: EPS Bearer ID
    bearer_ctx_data.push_back(73);
    bearer_ctx_data.push_back(0);
    bearer_ctx_data.push_back(1);
    bearer_ctx_data.push_back(0);
    bearer_ctx_data.push_back(5);  // Bearer ID 5

    // Nested IE: F-TEID #1 (S1-U eNodeB GTP-U)
    bearer_ctx_data.push_back(87);  // Type
    bearer_ctx_data.push_back(0);
    bearer_ctx_data.push_back(9);   // Length
    bearer_ctx_data.push_back(0);   // Instance 0
    bearer_ctx_data.push_back(0x80);  // Flags: V4=1, Interface=0
    // TEID: 0x11111111
    bearer_ctx_data.push_back(0x11);
    bearer_ctx_data.push_back(0x11);
    bearer_ctx_data.push_back(0x11);
    bearer_ctx_data.push_back(0x11);
    // IPv4: 192.168.1.1
    bearer_ctx_data.push_back(192);
    bearer_ctx_data.push_back(168);
    bearer_ctx_data.push_back(1);
    bearer_ctx_data.push_back(1);

    // Nested IE: F-TEID #2 (S1-U SGW GTP-U)
    bearer_ctx_data.push_back(87);  // Type
    bearer_ctx_data.push_back(0);
    bearer_ctx_data.push_back(9);   // Length
    bearer_ctx_data.push_back(1);   // Instance 1
    bearer_ctx_data.push_back(0x81);  // Flags: V4=1, Interface=1 (S1-U SGW)
    // TEID: 0x22222222
    bearer_ctx_data.push_back(0x22);
    bearer_ctx_data.push_back(0x22);
    bearer_ctx_data.push_back(0x22);
    bearer_ctx_data.push_back(0x22);
    // IPv4: 192.168.2.1
    bearer_ctx_data.push_back(192);
    bearer_ctx_data.push_back(168);
    bearer_ctx_data.push_back(2);
    bearer_ctx_data.push_back(1);

    auto bearer_ctx_opt = GtpV2BearerContext::parse(bearer_ctx_data);
    ASSERT_TRUE(bearer_ctx_opt.has_value());

    const auto& bearer_ctx = bearer_ctx_opt.value();
    ASSERT_EQ(bearer_ctx.fteids.size(), 2);

    // Check first F-TEID (eNodeB)
    const auto& fteid1 = bearer_ctx.fteids[0];
    EXPECT_EQ(fteid1.interface_type, FTEIDInterfaceType::S1_U_ENODEB_GTP_U);
    EXPECT_EQ(fteid1.teid, 0x11111111);
    EXPECT_EQ(fteid1.ipv4_address.value(), "192.168.1.1");

    // Check second F-TEID (SGW)
    const auto& fteid2 = bearer_ctx.fteids[1];
    EXPECT_EQ(fteid2.interface_type, FTEIDInterfaceType::S1_U_SGW_GTP_U);
    EXPECT_EQ(fteid2.teid, 0x22222222);
    EXPECT_EQ(fteid2.ipv4_address.value(), "192.168.2.1");
}

TEST(GtpV2BearerContext, Parse_Complete) {
    // Create complete Bearer Context with EPS Bearer ID, QoS, F-TEIDs, Charging ID
    std::vector<uint8_t> bearer_ctx_data;

    // 1. EPS Bearer ID
    bearer_ctx_data.push_back(73);
    bearer_ctx_data.push_back(0);
    bearer_ctx_data.push_back(1);
    bearer_ctx_data.push_back(0);
    bearer_ctx_data.push_back(5);

    // 2. Bearer QoS (22 bytes value + 4 bytes header)
    bearer_ctx_data.push_back(80);  // Type: Bearer QoS
    bearer_ctx_data.push_back(0);
    bearer_ctx_data.push_back(22);  // Length
    bearer_ctx_data.push_back(0);
    // QoS value: PCI=1, PL=5, PVI=0, QCI=9
    bearer_ctx_data.push_back((1 << 6) | (5 << 2));  // Byte 0
    bearer_ctx_data.push_back(9);  // QCI
    // MBR UL (5 bytes)
    for (int i = 0; i < 5; ++i) bearer_ctx_data.push_back(0);
    // MBR DL (5 bytes)
    for (int i = 0; i < 5; ++i) bearer_ctx_data.push_back(0);
    // GBR UL (5 bytes)
    for (int i = 0; i < 5; ++i) bearer_ctx_data.push_back(0);
    // GBR DL (5 bytes)
    for (int i = 0; i < 5; ++i) bearer_ctx_data.push_back(0);

    // 3. F-TEID (S1-U SGW GTP-U)
    bearer_ctx_data.push_back(87);
    bearer_ctx_data.push_back(0);
    bearer_ctx_data.push_back(9);
    bearer_ctx_data.push_back(0);
    bearer_ctx_data.push_back(0x81);  // V4=1, Interface=1
    bearer_ctx_data.push_back(0x33);
    bearer_ctx_data.push_back(0x33);
    bearer_ctx_data.push_back(0x33);
    bearer_ctx_data.push_back(0x33);
    bearer_ctx_data.push_back(10);
    bearer_ctx_data.push_back(0);
    bearer_ctx_data.push_back(0);
    bearer_ctx_data.push_back(1);

    // 4. Charging ID
    bearer_ctx_data.push_back(94);  // Type: Charging ID
    bearer_ctx_data.push_back(0);
    bearer_ctx_data.push_back(4);   // Length
    bearer_ctx_data.push_back(0);
    // Charging ID: 0x12345678
    bearer_ctx_data.push_back(0x12);
    bearer_ctx_data.push_back(0x34);
    bearer_ctx_data.push_back(0x56);
    bearer_ctx_data.push_back(0x78);

    auto bearer_ctx_opt = GtpV2BearerContext::parse(bearer_ctx_data);
    ASSERT_TRUE(bearer_ctx_opt.has_value());

    const auto& bearer_ctx = bearer_ctx_opt.value();

    // Verify EPS Bearer ID
    ASSERT_TRUE(bearer_ctx.eps_bearer_id.has_value());
    EXPECT_EQ(bearer_ctx.eps_bearer_id.value(), 5);

    // Verify QoS
    ASSERT_TRUE(bearer_ctx.qos.has_value());
    EXPECT_EQ(bearer_ctx.qos.value().qci, 9);
    EXPECT_EQ(bearer_ctx.qos.value().pl, 5);

    // Verify F-TEID
    ASSERT_EQ(bearer_ctx.fteids.size(), 1);
    EXPECT_EQ(bearer_ctx.fteids[0].teid, 0x33333333);
    EXPECT_EQ(bearer_ctx.fteids[0].interface_type, FTEIDInterfaceType::S1_U_SGW_GTP_U);

    // Verify Charging ID
    ASSERT_TRUE(bearer_ctx.charging_id.has_value());
    EXPECT_EQ(bearer_ctx.charging_id.value(), 0x12345678);
}

TEST(GtpV2BearerContext, Parse_WithCause) {
    // Create Bearer Context with Cause (typically in response messages)
    std::vector<uint8_t> bearer_ctx_data;

    // EPS Bearer ID
    bearer_ctx_data.push_back(73);
    bearer_ctx_data.push_back(0);
    bearer_ctx_data.push_back(1);
    bearer_ctx_data.push_back(0);
    bearer_ctx_data.push_back(5);

    // Cause: REQUEST_ACCEPTED (16)
    bearer_ctx_data.push_back(2);  // Type: Cause
    bearer_ctx_data.push_back(0);
    bearer_ctx_data.push_back(2);  // Length
    bearer_ctx_data.push_back(0);
    bearer_ctx_data.push_back(16); // Cause value: REQUEST_ACCEPTED
    bearer_ctx_data.push_back(0);  // Flags

    auto bearer_ctx_opt = GtpV2BearerContext::parse(bearer_ctx_data);
    ASSERT_TRUE(bearer_ctx_opt.has_value());

    const auto& bearer_ctx = bearer_ctx_opt.value();
    ASSERT_TRUE(bearer_ctx.cause.has_value());
    EXPECT_EQ(bearer_ctx.cause.value(), CauseValue::REQUEST_ACCEPTED);
}

TEST(GtpV2BearerContext, Parse_S5S8_Interfaces) {
    // Create Bearer Context with S5/S8 interface F-TEIDs
    std::vector<uint8_t> bearer_ctx_data;

    // EPS Bearer ID
    bearer_ctx_data.push_back(73);
    bearer_ctx_data.push_back(0);
    bearer_ctx_data.push_back(1);
    bearer_ctx_data.push_back(0);
    bearer_ctx_data.push_back(5);

    // F-TEID: S5/S8 SGW GTP-U (interface type 4)
    bearer_ctx_data.push_back(87);
    bearer_ctx_data.push_back(0);
    bearer_ctx_data.push_back(9);
    bearer_ctx_data.push_back(0);
    bearer_ctx_data.push_back(0x84);  // V4=1, Interface=4 (S5/S8 SGW GTP-U)
    bearer_ctx_data.push_back(0x44);
    bearer_ctx_data.push_back(0x44);
    bearer_ctx_data.push_back(0x44);
    bearer_ctx_data.push_back(0x44);
    bearer_ctx_data.push_back(172);
    bearer_ctx_data.push_back(16);
    bearer_ctx_data.push_back(0);
    bearer_ctx_data.push_back(1);

    // F-TEID: S5/S8 PGW GTP-U (interface type 5)
    bearer_ctx_data.push_back(87);
    bearer_ctx_data.push_back(0);
    bearer_ctx_data.push_back(9);
    bearer_ctx_data.push_back(1);  // Instance 1
    bearer_ctx_data.push_back(0x85);  // V4=1, Interface=5 (S5/S8 PGW GTP-U)
    bearer_ctx_data.push_back(0x55);
    bearer_ctx_data.push_back(0x55);
    bearer_ctx_data.push_back(0x55);
    bearer_ctx_data.push_back(0x55);
    bearer_ctx_data.push_back(172);
    bearer_ctx_data.push_back(16);
    bearer_ctx_data.push_back(1);
    bearer_ctx_data.push_back(1);

    auto bearer_ctx_opt = GtpV2BearerContext::parse(bearer_ctx_data);
    ASSERT_TRUE(bearer_ctx_opt.has_value());

    const auto& bearer_ctx = bearer_ctx_opt.value();
    ASSERT_EQ(bearer_ctx.fteids.size(), 2);

    // Verify S5/S8 SGW F-TEID
    const auto& fteid_sgw = bearer_ctx.fteids[0];
    EXPECT_EQ(fteid_sgw.interface_type, FTEIDInterfaceType::S5_S8_SGW_GTP_U);
    EXPECT_EQ(fteid_sgw.teid, 0x44444444);

    // Verify S5/S8 PGW F-TEID
    const auto& fteid_pgw = bearer_ctx.fteids[1];
    EXPECT_EQ(fteid_pgw.interface_type, FTEIDInterfaceType::S5_S8_PGW_GTP_U);
    EXPECT_EQ(fteid_pgw.teid, 0x55555555);
}

TEST(GtpV2BearerContext, Parse_Empty) {
    std::vector<uint8_t> bearer_ctx_data;
    auto bearer_ctx_opt = GtpV2BearerContext::parse(bearer_ctx_data);
    ASSERT_TRUE(bearer_ctx_opt.has_value());

    const auto& bearer_ctx = bearer_ctx_opt.value();
    EXPECT_FALSE(bearer_ctx.eps_bearer_id.has_value());
    EXPECT_FALSE(bearer_ctx.qos.has_value());
    EXPECT_TRUE(bearer_ctx.fteids.empty());
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
