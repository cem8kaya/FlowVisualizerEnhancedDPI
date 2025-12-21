#include <gtest/gtest.h>
#include "protocol_parsers/gtp/gtp_teid_manager.h"

using namespace callflow::gtp;

// ============================================================================
// GTP TEID Manager Tests
// ============================================================================

TEST(GtpTEIDManager, RegisterTunnel_Basic) {
    GtpTEIDManager manager;

    GtpTunnel tunnel;
    tunnel.teid_uplink = 0x12345678;
    tunnel.teid_downlink = 0x87654321;
    tunnel.teid_s5_sgw = 0;
    tunnel.teid_s5_pgw = 0;
    tunnel.imsi = "001010123456789";
    tunnel.ue_ip = "192.168.100.1";
    tunnel.apn = "internet";
    tunnel.session_id = "session-001";
    tunnel.eps_bearer_id = 5;
    tunnel.qci = 9;

    manager.registerTunnel(tunnel);

    EXPECT_EQ(manager.getTunnelCount(), 2);  // uplink and downlink TEIDs
}

TEST(GtpTEIDManager, FindByTEID) {
    GtpTEIDManager manager;

    GtpTunnel tunnel;
    tunnel.teid_uplink = 0x11111111;
    tunnel.teid_downlink = 0x22222222;
    tunnel.teid_s5_sgw = 0;
    tunnel.teid_s5_pgw = 0;
    tunnel.imsi = "001010123456789";
    tunnel.ue_ip = "10.0.0.1";
    tunnel.apn = "internet.mnc001.mcc001.gprs";
    tunnel.session_id = "test-session";
    tunnel.eps_bearer_id = 5;
    tunnel.qci = 9;

    manager.registerTunnel(tunnel);

    // Find by uplink TEID
    auto result = manager.findByTEID(0x11111111);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().imsi, "001010123456789");
    EXPECT_EQ(result.value().ue_ip, "10.0.0.1");
    EXPECT_EQ(result.value().teid_uplink, 0x11111111);

    // Find by downlink TEID
    result = manager.findByTEID(0x22222222);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().imsi, "001010123456789");

    // Find non-existent TEID
    result = manager.findByTEID(0x99999999);
    EXPECT_FALSE(result.has_value());
}

TEST(GtpTEIDManager, FindByIMSI) {
    GtpTEIDManager manager;

    GtpTunnel tunnel;
    tunnel.teid_uplink = 0xAAAAAAAA;
    tunnel.teid_downlink = 0xBBBBBBBB;
    tunnel.teid_s5_sgw = 0;
    tunnel.teid_s5_pgw = 0;
    tunnel.imsi = "310410123456789";
    tunnel.ue_ip = "172.16.0.1";
    tunnel.apn = "ims";
    tunnel.session_id = "ims-session";
    tunnel.eps_bearer_id = 5;
    tunnel.qci = 5;

    manager.registerTunnel(tunnel);

    auto result = manager.findByIMSI("310410123456789");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().teid_uplink, 0xAAAAAAAA);
    EXPECT_EQ(result.value().ue_ip, "172.16.0.1");
    EXPECT_EQ(result.value().apn, "ims");

    // Find non-existent IMSI
    result = manager.findByIMSI("999999999999999");
    EXPECT_FALSE(result.has_value());
}

TEST(GtpTEIDManager, FindByUEIP) {
    GtpTEIDManager manager;

    GtpTunnel tunnel;
    tunnel.teid_uplink = 0xCCCCCCCC;
    tunnel.teid_downlink = 0xDDDDDDDD;
    tunnel.teid_s5_sgw = 0;
    tunnel.teid_s5_pgw = 0;
    tunnel.imsi = "001010987654321";
    tunnel.ue_ip = "192.168.200.50";
    tunnel.apn = "internet";
    tunnel.session_id = "ue-session";
    tunnel.eps_bearer_id = 5;
    tunnel.qci = 9;

    manager.registerTunnel(tunnel);

    auto result = manager.findByUEIP("192.168.200.50");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().imsi, "001010987654321");
    EXPECT_EQ(result.value().teid_uplink, 0xCCCCCCCC);

    // Find non-existent UE IP
    result = manager.findByUEIP("10.10.10.10");
    EXPECT_FALSE(result.has_value());
}

TEST(GtpTEIDManager, FindBySessionID) {
    GtpTEIDManager manager;

    GtpTunnel tunnel;
    tunnel.teid_uplink = 0xEEEEEEEE;
    tunnel.teid_downlink = 0xFFFFFFFF;
    tunnel.teid_s5_sgw = 0;
    tunnel.teid_s5_pgw = 0;
    tunnel.imsi = "001010111111111";
    tunnel.ue_ip = "10.20.30.40";
    tunnel.apn = "internet";
    tunnel.session_id = "unique-session-id-12345";
    tunnel.eps_bearer_id = 5;
    tunnel.qci = 9;

    manager.registerTunnel(tunnel);

    auto result = manager.findBySessionID("unique-session-id-12345");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().imsi, "001010111111111");
    EXPECT_EQ(result.value().ue_ip, "10.20.30.40");

    // Find non-existent session ID
    result = manager.findBySessionID("non-existent-session");
    EXPECT_FALSE(result.has_value());
}

TEST(GtpTEIDManager, RegisterTunnel_WithS5S8) {
    GtpTEIDManager manager;

    GtpTunnel tunnel;
    tunnel.teid_uplink = 0x11111111;
    tunnel.teid_downlink = 0x22222222;
    tunnel.teid_s5_sgw = 0x33333333;
    tunnel.teid_s5_pgw = 0x44444444;
    tunnel.imsi = "001010123456789";
    tunnel.ue_ip = "192.168.1.1";
    tunnel.apn = "internet";
    tunnel.session_id = "s5s8-session";
    tunnel.eps_bearer_id = 5;
    tunnel.qci = 9;

    manager.registerTunnel(tunnel);

    // Should be able to find by any of the 4 TEIDs
    EXPECT_TRUE(manager.findByTEID(0x11111111).has_value());
    EXPECT_TRUE(manager.findByTEID(0x22222222).has_value());
    EXPECT_TRUE(manager.findByTEID(0x33333333).has_value());
    EXPECT_TRUE(manager.findByTEID(0x44444444).has_value());

    // All lookups should return the same tunnel
    auto result1 = manager.findByTEID(0x11111111);
    auto result2 = manager.findByTEID(0x33333333);
    EXPECT_EQ(result1.value().imsi, result2.value().imsi);
}

TEST(GtpTEIDManager, UpdateTunnel) {
    GtpTEIDManager manager;

    GtpTunnel tunnel;
    tunnel.teid_uplink = 0xAAAAAAAA;
    tunnel.teid_downlink = 0xBBBBBBBB;
    tunnel.teid_s5_sgw = 0;
    tunnel.teid_s5_pgw = 0;
    tunnel.imsi = "001010123456789";
    tunnel.ue_ip = "192.168.1.1";
    tunnel.apn = "internet";
    tunnel.session_id = "session-001";
    tunnel.eps_bearer_id = 5;
    tunnel.qci = 9;

    manager.registerTunnel(tunnel);

    // Update tunnel with new UE IP
    tunnel.ue_ip = "192.168.1.100";
    tunnel.qci = 7;  // Changed QCI
    manager.updateTunnel(0xAAAAAAAA, tunnel);

    auto result = manager.findByTEID(0xAAAAAAAA);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().ue_ip, "192.168.1.100");
    EXPECT_EQ(result.value().qci, 7);
}

TEST(GtpTEIDManager, DeleteTunnel) {
    GtpTEIDManager manager;

    GtpTunnel tunnel;
    tunnel.teid_uplink = 0x12121212;
    tunnel.teid_downlink = 0x34343434;
    tunnel.teid_s5_sgw = 0;
    tunnel.teid_s5_pgw = 0;
    tunnel.imsi = "001010123456789";
    tunnel.ue_ip = "192.168.1.1";
    tunnel.apn = "internet";
    tunnel.session_id = "delete-test";
    tunnel.eps_bearer_id = 5;
    tunnel.qci = 9;

    manager.registerTunnel(tunnel);
    EXPECT_EQ(manager.getTunnelCount(), 2);

    // Delete tunnel
    manager.deleteTunnel(0x12121212);

    // Should not be found by any method
    EXPECT_FALSE(manager.findByTEID(0x12121212).has_value());
    EXPECT_FALSE(manager.findByTEID(0x34343434).has_value());
    EXPECT_FALSE(manager.findByIMSI("001010123456789").has_value());
    EXPECT_FALSE(manager.findByUEIP("192.168.1.1").has_value());
    EXPECT_FALSE(manager.findBySessionID("delete-test").has_value());

    EXPECT_EQ(manager.getTunnelCount(), 0);
}

TEST(GtpTEIDManager, MultipleTunnels) {
    GtpTEIDManager manager;

    // Register multiple tunnels
    for (int i = 0; i < 10; ++i) {
        GtpTunnel tunnel;
        tunnel.teid_uplink = 0x1000 + i;
        tunnel.teid_downlink = 0x2000 + i;
        tunnel.teid_s5_sgw = 0;
        tunnel.teid_s5_pgw = 0;
        tunnel.imsi = "00101012345678" + std::to_string(i);
        tunnel.ue_ip = "192.168.1." + std::to_string(i + 1);
        tunnel.apn = "internet";
        tunnel.session_id = "session-" + std::to_string(i);
        tunnel.eps_bearer_id = 5;
        tunnel.qci = 9;

        manager.registerTunnel(tunnel);
    }

    EXPECT_EQ(manager.getTunnelCount(), 20);  // 10 tunnels * 2 TEIDs each

    // Verify each tunnel can be found
    for (int i = 0; i < 10; ++i) {
        auto result = manager.findByTEID(0x1000 + i);
        ASSERT_TRUE(result.has_value());
        EXPECT_EQ(result.value().imsi, "00101012345678" + std::to_string(i));
    }
}

TEST(GtpTEIDManager, Clear) {
    GtpTEIDManager manager;

    // Add some tunnels
    for (int i = 0; i < 5; ++i) {
        GtpTunnel tunnel;
        tunnel.teid_uplink = 0x1000 + i;
        tunnel.teid_downlink = 0x2000 + i;
        tunnel.teid_s5_sgw = 0;
        tunnel.teid_s5_pgw = 0;
        tunnel.imsi = "00101012345678" + std::to_string(i);
        tunnel.ue_ip = "192.168.1." + std::to_string(i + 1);
        tunnel.apn = "internet";
        tunnel.session_id = "session-" + std::to_string(i);
        tunnel.eps_bearer_id = 5;
        tunnel.qci = 9;

        manager.registerTunnel(tunnel);
    }

    EXPECT_GT(manager.getTunnelCount(), 0);

    manager.clear();

    EXPECT_EQ(manager.getTunnelCount(), 0);
    EXPECT_FALSE(manager.findByTEID(0x1000).has_value());
}

TEST(GtpTEIDManager, Statistics) {
    GtpTEIDManager manager;

    // Register tunnel
    GtpTunnel tunnel;
    tunnel.teid_uplink = 0xAAAAAAAA;
    tunnel.teid_downlink = 0xBBBBBBBB;
    tunnel.teid_s5_sgw = 0;
    tunnel.teid_s5_pgw = 0;
    tunnel.imsi = "001010123456789";
    tunnel.ue_ip = "192.168.1.1";
    tunnel.apn = "internet";
    tunnel.session_id = "stats-test";
    tunnel.eps_bearer_id = 5;
    tunnel.qci = 9;

    manager.registerTunnel(tunnel);

    // Perform lookups
    manager.findByTEID(0xAAAAAAAA);  // Hit
    manager.findByTEID(0x12345678);  // Miss
    manager.findByIMSI("001010123456789");  // Hit
    manager.findByIMSI("999999999999999");  // Miss

    auto stats = manager.getStatistics();

    EXPECT_EQ(stats["active_tunnels"], 2);
    EXPECT_EQ(stats["total_tunnels_created"], 1);
    EXPECT_EQ(stats["total_lookups"], 4);
    EXPECT_EQ(stats["total_lookup_hits"], 2);
    EXPECT_DOUBLE_EQ(stats["lookup_hit_rate"], 0.5);
}

TEST(GtpTEIDManager, GetAllTunnels) {
    GtpTEIDManager manager;

    // Register 3 tunnels
    for (int i = 0; i < 3; ++i) {
        GtpTunnel tunnel;
        tunnel.teid_uplink = 0x1000 + i;
        tunnel.teid_downlink = 0x2000 + i;
        tunnel.teid_s5_sgw = 0;
        tunnel.teid_s5_pgw = 0;
        tunnel.imsi = "00101012345678" + std::to_string(i);
        tunnel.ue_ip = "192.168.1." + std::to_string(i + 1);
        tunnel.apn = "internet";
        tunnel.session_id = "session-" + std::to_string(i);
        tunnel.eps_bearer_id = 5;
        tunnel.qci = 9;

        manager.registerTunnel(tunnel);
    }

    auto tunnels = manager.getAllTunnels();
    EXPECT_EQ(tunnels.size(), 6);  // 3 tunnels * 2 TEID entries each
}

TEST(GtpTEIDManager, ZeroTEID_Handling) {
    GtpTEIDManager manager;

    // Try to register tunnel with zero uplink TEID (should use downlink)
    GtpTunnel tunnel;
    tunnel.teid_uplink = 0;
    tunnel.teid_downlink = 0x12345678;
    tunnel.teid_s5_sgw = 0;
    tunnel.teid_s5_pgw = 0;
    tunnel.imsi = "001010123456789";
    tunnel.ue_ip = "192.168.1.1";
    tunnel.apn = "internet";
    tunnel.session_id = "zero-test";
    tunnel.eps_bearer_id = 5;
    tunnel.qci = 9;

    manager.registerTunnel(tunnel);

    // Should be able to find by downlink TEID
    auto result = manager.findByTEID(0x12345678);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().imsi, "001010123456789");
}

TEST(GtpTEIDManager, ZeroTEID_Both_Reject) {
    GtpTEIDManager manager;

    // Try to register tunnel with both TEIDs zero (should be rejected)
    GtpTunnel tunnel;
    tunnel.teid_uplink = 0;
    tunnel.teid_downlink = 0;
    tunnel.teid_s5_sgw = 0;
    tunnel.teid_s5_pgw = 0;
    tunnel.imsi = "001010123456789";
    tunnel.ue_ip = "192.168.1.1";
    tunnel.apn = "internet";
    tunnel.session_id = "invalid-test";
    tunnel.eps_bearer_id = 5;
    tunnel.qci = 9;

    manager.registerTunnel(tunnel);

    // Should not be registered
    EXPECT_EQ(manager.getTunnelCount(), 0);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
