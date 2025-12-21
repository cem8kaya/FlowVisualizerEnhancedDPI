#include <gtest/gtest.h>
#include "correlation/tunnel_manager.h"
#include "session/session_types.h"
#include "common/types.h"
#include <chrono>
#include <thread>

using namespace callflow;

class TunnelLifecycleTest : public ::testing::Test {
protected:
    void SetUp() override {
        manager = std::make_unique<TunnelManager>();
        msg_counter = 0;
    }

    void TearDown() override {
        manager.reset();
    }

    SessionMessageRef createMessage(MessageType msg_type, uint32_t teid = 0) {
        SessionMessageRef msg;
        msg.message_id = "msg_" + std::to_string(msg_counter++);
        msg.timestamp = std::chrono::system_clock::now();
        msg.message_type = msg_type;
        msg.protocol = ProtocolType::GTP_C;
        msg.interface = InterfaceType::S11;

        // Set correlation key
        if (teid != 0) {
            msg.correlation_key.teid_s1u = teid;
        }
        msg.correlation_key.imsi = "001010123456789";
        msg.correlation_key.apn = "internet";

        // Set parsed data
        if (teid != 0) {
            msg.parsed_data["teid"] = teid;
        }

        return msg;
    }

    SessionMessageRef createCreateSessionRequest(uint32_t teid) {
        auto msg = createMessage(MessageType::GTP_CREATE_SESSION_REQ, teid);

        msg.parsed_data["imsi"] = "001010123456789";
        msg.parsed_data["apn"] = "internet";
        msg.parsed_data["bearer_contexts"] = nlohmann::json::array();
        msg.parsed_data["bearer_contexts"].push_back({
            {"eps_bearer_id", 5},
            {"qci", 9}
        });

        return msg;
    }

    SessionMessageRef createCreateSessionResponse(uint32_t teid_uplink,
                                                    uint32_t teid_downlink) {
        auto msg = createMessage(MessageType::GTP_CREATE_SESSION_RESP, teid_uplink);

        msg.correlation_key.ue_ipv4 = "10.0.0.100";
        msg.parsed_data["ue_ipv4"] = "10.0.0.100";

        msg.parsed_data["bearer_contexts"] = nlohmann::json::array();
        msg.parsed_data["bearer_contexts"].push_back({
            {"s1u_enb_fteid", {
                {"teid", teid_uplink},
                {"ipv4", "192.168.1.10"}
            }},
            {"s1u_sgw_fteid", {
                {"teid", teid_downlink},
                {"ipv4", "192.168.2.10"}
            }}
        });

        return msg;
    }

    SessionMessageRef createDeleteSessionRequest(uint32_t teid) {
        return createMessage(MessageType::GTP_DELETE_SESSION_REQ, teid);
    }

    SessionMessageRef createDeleteSessionResponse(uint32_t teid) {
        return createMessage(MessageType::GTP_DELETE_SESSION_RESP, teid);
    }

    std::unique_ptr<TunnelManager> manager;
    int msg_counter;
};

TEST_F(TunnelLifecycleTest, CreateTunnelBasic) {
    uint32_t teid = 0x12345678;

    auto req = createCreateSessionRequest(teid);
    manager->processMessage(req);

    auto tunnel_opt = manager->getTunnel(teid);
    ASSERT_TRUE(tunnel_opt.has_value());

    const auto& tunnel = *tunnel_opt;
    EXPECT_EQ(tunnel.teid_uplink, teid);
    EXPECT_EQ(tunnel.state, TunnelState::CREATING);
    EXPECT_EQ(tunnel.imsi, "001010123456789");
    EXPECT_EQ(tunnel.apn, "internet");
    EXPECT_EQ(tunnel.eps_bearer_id, 5);
    EXPECT_EQ(tunnel.qci, 9);
}

TEST_F(TunnelLifecycleTest, ActivateTunnel) {
    uint32_t teid_uplink = 0x12345678;
    uint32_t teid_downlink = 0x87654321;

    auto req = createCreateSessionRequest(teid_uplink);
    manager->processMessage(req);

    auto resp = createCreateSessionResponse(teid_uplink, teid_downlink);
    manager->processMessage(resp);

    auto tunnel_opt = manager->getTunnel(teid_uplink);
    ASSERT_TRUE(tunnel_opt.has_value());

    const auto& tunnel = *tunnel_opt;
    EXPECT_EQ(tunnel.state, TunnelState::ACTIVE);
    EXPECT_EQ(tunnel.teid_downlink, teid_downlink);
    EXPECT_EQ(tunnel.ue_ip_v4, "10.0.0.100");
}

TEST_F(TunnelLifecycleTest, DeleteTunnel) {
    uint32_t teid_uplink = 0x12345678;
    uint32_t teid_downlink = 0x87654321;

    // Create and activate
    auto req = createCreateSessionRequest(teid_uplink);
    manager->processMessage(req);

    auto resp = createCreateSessionResponse(teid_uplink, teid_downlink);
    manager->processMessage(resp);

    // Delete
    auto del_req = createDeleteSessionRequest(teid_uplink);
    manager->processMessage(del_req);

    auto tunnel_opt = manager->getTunnel(teid_uplink);
    ASSERT_TRUE(tunnel_opt.has_value());
    EXPECT_EQ(tunnel_opt->state, TunnelState::DELETING);

    auto del_resp = createDeleteSessionResponse(teid_uplink);
    manager->processMessage(del_resp);

    tunnel_opt = manager->getTunnel(teid_uplink);
    ASSERT_TRUE(tunnel_opt.has_value());
    EXPECT_EQ(tunnel_opt->state, TunnelState::DELETED);
    EXPECT_TRUE(tunnel_opt->deleted.has_value());
}

TEST_F(TunnelLifecycleTest, GetTunnelsByImsi) {
    uint32_t teid1 = 0x11111111;
    uint32_t teid2 = 0x22222222;

    auto req1 = createCreateSessionRequest(teid1);
    manager->processMessage(req1);

    auto req2 = createCreateSessionRequest(teid2);
    manager->processMessage(req2);

    auto tunnels = manager->getTunnelsByImsi("001010123456789");
    EXPECT_EQ(tunnels.size(), 2);
}

TEST_F(TunnelLifecycleTest, GetTunnelsByUeIp) {
    uint32_t teid_uplink = 0x12345678;
    uint32_t teid_downlink = 0x87654321;

    auto req = createCreateSessionRequest(teid_uplink);
    manager->processMessage(req);

    auto resp = createCreateSessionResponse(teid_uplink, teid_downlink);
    manager->processMessage(resp);

    auto tunnels = manager->getTunnelsByUeIp("10.0.0.100");
    EXPECT_EQ(tunnels.size(), 1);
    EXPECT_EQ(tunnels[0].teid_uplink, teid_uplink);
}

TEST_F(TunnelLifecycleTest, GetActiveTunnels) {
    uint32_t teid1 = 0x11111111;
    uint32_t teid2 = 0x22222222;

    // Create tunnel 1 and activate
    auto req1 = createCreateSessionRequest(teid1);
    manager->processMessage(req1);

    auto resp1 = createCreateSessionResponse(teid1, 0x11111112);
    manager->processMessage(resp1);

    // Create tunnel 2 but don't activate
    auto req2 = createCreateSessionRequest(teid2);
    manager->processMessage(req2);

    auto active_tunnels = manager->getActiveTunnels();
    EXPECT_EQ(active_tunnels.size(), 1);
    EXPECT_EQ(active_tunnels[0].teid_uplink, teid1);

    auto all_tunnels = manager->getAllTunnels();
    EXPECT_EQ(all_tunnels.size(), 2);
}

TEST_F(TunnelLifecycleTest, TunnelDuration) {
    uint32_t teid_uplink = 0x12345678;
    uint32_t teid_downlink = 0x87654321;

    auto req = createCreateSessionRequest(teid_uplink);
    manager->processMessage(req);

    auto resp = createCreateSessionResponse(teid_uplink, teid_downlink);
    manager->processMessage(resp);

    // Wait a bit
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    auto del_resp = createDeleteSessionResponse(teid_uplink);
    manager->processMessage(del_resp);

    auto tunnel_opt = manager->getTunnel(teid_uplink);
    ASSERT_TRUE(tunnel_opt.has_value());

    double duration_hours = tunnel_opt->getDurationHours();
    EXPECT_GT(duration_hours, 0.0);
    EXPECT_LT(duration_hours, 1.0);  // Should be a tiny fraction of an hour
}

TEST_F(TunnelLifecycleTest, TunnelVisualizationJson) {
    uint32_t teid_uplink = 0x12345678;
    uint32_t teid_downlink = 0x87654321;

    auto req = createCreateSessionRequest(teid_uplink);
    manager->processMessage(req);

    auto resp = createCreateSessionResponse(teid_uplink, teid_downlink);
    manager->processMessage(resp);

    auto viz_json = manager->getTunnelVisualization(teid_uplink);

    EXPECT_TRUE(viz_json.is_object());
    EXPECT_EQ(viz_json["teid_uplink"], teid_uplink);
    EXPECT_EQ(viz_json["teid_downlink"], teid_downlink);
    EXPECT_EQ(viz_json["imsi"], "001010123456789");
    EXPECT_EQ(viz_json["apn"], "internet");
    EXPECT_EQ(viz_json["state"], "ACTIVE");
    EXPECT_TRUE(viz_json.contains("events"));
    EXPECT_TRUE(viz_json["events"].is_array());
}

TEST_F(TunnelLifecycleTest, ImsiVisualizationJson) {
    uint32_t teid1 = 0x11111111;
    uint32_t teid2 = 0x22222222;

    auto req1 = createCreateSessionRequest(teid1);
    manager->processMessage(req1);

    auto resp1 = createCreateSessionResponse(teid1, 0x11111112);
    manager->processMessage(resp1);

    auto req2 = createCreateSessionRequest(teid2);
    manager->processMessage(req2);

    auto resp2 = createCreateSessionResponse(teid2, 0x22222223);
    manager->processMessage(resp2);

    auto viz_json = manager->getImsiVisualization("001010123456789");

    EXPECT_TRUE(viz_json.is_array());
    EXPECT_EQ(viz_json.size(), 2);

    for (const auto& tunnel : viz_json) {
        EXPECT_TRUE(tunnel.contains("events"));
        EXPECT_EQ(tunnel["imsi"], "001010123456789");
    }
}

TEST_F(TunnelLifecycleTest, Statistics) {
    uint32_t teid1 = 0x11111111;
    uint32_t teid2 = 0x22222222;

    // Create and activate tunnel 1
    auto req1 = createCreateSessionRequest(teid1);
    manager->processMessage(req1);

    auto resp1 = createCreateSessionResponse(teid1, 0x11111112);
    manager->processMessage(resp1);

    // Create and activate tunnel 2
    auto req2 = createCreateSessionRequest(teid2);
    manager->processMessage(req2);

    auto resp2 = createCreateSessionResponse(teid2, 0x22222223);
    manager->processMessage(resp2);

    // Delete tunnel 1
    auto del1 = createDeleteSessionResponse(teid1);
    manager->processMessage(del1);

    auto stats = manager->getStatistics();
    EXPECT_EQ(stats.total_tunnels, 2);
    EXPECT_EQ(stats.active_tunnels, 1);
    EXPECT_EQ(stats.deleted_tunnels, 1);
}

TEST_F(TunnelLifecycleTest, UserDataTracking) {
    uint32_t teid = 0x12345678;

    auto req = createCreateSessionRequest(teid);
    manager->processMessage(req);

    auto resp = createCreateSessionResponse(teid, 0x87654321);
    manager->processMessage(resp);

    // Simulate user data packets
    auto now = std::chrono::system_clock::now();
    manager->handleUserData(teid, true, 1500, now);   // Uplink
    manager->handleUserData(teid, false, 3000, now);  // Downlink
    manager->handleUserData(teid, true, 500, now);    // Uplink
    manager->handleUserData(teid, false, 1000, now);  // Downlink

    auto tunnel_opt = manager->getTunnel(teid);
    ASSERT_TRUE(tunnel_opt.has_value());

    const auto& tunnel = *tunnel_opt;
    EXPECT_EQ(tunnel.uplink_packets, 2);
    EXPECT_EQ(tunnel.downlink_packets, 2);
    EXPECT_EQ(tunnel.uplink_bytes, 2000);
    EXPECT_EQ(tunnel.downlink_bytes, 4000);
}

TEST_F(TunnelLifecycleTest, TimeoutDetection) {
    TunnelManager::Config config;
    config.activity_timeout = std::chrono::seconds(1);  // Short timeout for testing
    auto timeout_manager = std::make_unique<TunnelManager>(config);

    uint32_t teid = 0x12345678;

    auto req = createCreateSessionRequest(teid);
    timeout_manager->processMessage(req);

    auto resp = createCreateSessionResponse(teid, 0x87654321);
    timeout_manager->processMessage(resp);

    // Tunnel should be active
    auto tunnel_opt = timeout_manager->getTunnel(teid);
    ASSERT_TRUE(tunnel_opt.has_value());
    EXPECT_EQ(tunnel_opt->state, TunnelState::ACTIVE);

    // Wait for timeout
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));

    // Check timeouts
    timeout_manager->checkTimeouts();

    // Tunnel should now be inactive
    tunnel_opt = timeout_manager->getTunnel(teid);
    ASSERT_TRUE(tunnel_opt.has_value());
    EXPECT_EQ(tunnel_opt->state, TunnelState::INACTIVE);
}

TEST_F(TunnelLifecycleTest, MaxTunnelsLimit) {
    TunnelManager::Config config;
    config.max_tunnels = 10;
    auto limited_manager = std::make_unique<TunnelManager>(config);

    // Create 10 tunnels (should succeed)
    for (uint32_t i = 1; i <= 10; ++i) {
        auto req = createCreateSessionRequest(0x10000000 + i);
        limited_manager->processMessage(req);
    }

    EXPECT_EQ(limited_manager->getAllTunnels().size(), 10);

    // Try to create 11th tunnel (should fail)
    auto req = createCreateSessionRequest(0x20000000);
    limited_manager->processMessage(req);

    // Should still be 10 tunnels
    EXPECT_EQ(limited_manager->getAllTunnels().size(), 10);
}

TEST_F(TunnelLifecycleTest, ClearAllTunnels) {
    uint32_t teid1 = 0x11111111;
    uint32_t teid2 = 0x22222222;

    auto req1 = createCreateSessionRequest(teid1);
    manager->processMessage(req1);

    auto req2 = createCreateSessionRequest(teid2);
    manager->processMessage(req2);

    EXPECT_EQ(manager->getAllTunnels().size(), 2);

    manager->clear();

    EXPECT_EQ(manager->getAllTunnels().size(), 0);
}
