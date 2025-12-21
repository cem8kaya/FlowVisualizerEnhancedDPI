#include <gtest/gtest.h>
#include "correlation/tunnel_manager.h"
#include "session/session_types.h"
#include "common/types.h"
#include <chrono>
#include <thread>

using namespace callflow;

class HandoverDetectionTest : public ::testing::Test {
protected:
    void SetUp() override {
        manager = std::make_unique<TunnelManager>();
        msg_counter = 0;
        imsi = "001010123456789";
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

        if (teid != 0) {
            msg.correlation_key.teid_s1u = teid;
        }
        msg.correlation_key.imsi = imsi;
        msg.correlation_key.apn = "internet";

        if (teid != 0) {
            msg.parsed_data["teid"] = teid;
        }
        msg.parsed_data["imsi"] = imsi;

        return msg;
    }

    SessionMessageRef createCreateSessionRequest(uint32_t teid) {
        auto msg = createMessage(MessageType::GTP_CREATE_SESSION_REQ, teid);
        msg.parsed_data["apn"] = "internet";
        msg.parsed_data["bearer_contexts"] = nlohmann::json::array();
        msg.parsed_data["bearer_contexts"].push_back({
            {"eps_bearer_id", 5},
            {"qci", 9}
        });
        return msg;
    }

    SessionMessageRef createCreateSessionResponse(uint32_t teid_uplink,
                                                    uint32_t teid_downlink,
                                                    const std::string& enb_ip) {
        auto msg = createMessage(MessageType::GTP_CREATE_SESSION_RESP, teid_uplink);

        msg.correlation_key.ue_ipv4 = "10.0.0.100";
        msg.parsed_data["ue_ipv4"] = "10.0.0.100";

        msg.parsed_data["bearer_contexts"] = nlohmann::json::array();
        msg.parsed_data["bearer_contexts"].push_back({
            {"s1u_enb_fteid", {
                {"teid", teid_uplink},
                {"ipv4", enb_ip}
            }},
            {"s1u_sgw_fteid", {
                {"teid", teid_downlink},
                {"ipv4", "192.168.2.10"}
            }}
        });

        return msg;
    }

    SessionMessageRef createModifyBearerResponse(uint32_t new_teid_uplink,
                                                   const std::string& new_enb_ip) {
        auto msg = createMessage(MessageType::GTP_MODIFY_BEARER_RESP, new_teid_uplink);

        msg.parsed_data["bearer_contexts"] = nlohmann::json::array();
        msg.parsed_data["bearer_contexts"].push_back({
            {"s1u_enb_fteid", {
                {"teid", new_teid_uplink},
                {"ipv4", new_enb_ip}
            }},
            {"s1u_sgw_fteid", {
                {"teid", 0x87654321},
                {"ipv4", "192.168.2.10"}
            }}
        });

        msg.parsed_data["cause"] = 16;  // Success

        return msg;
    }

    std::unique_ptr<TunnelManager> manager;
    int msg_counter;
    std::string imsi;
};

TEST_F(HandoverDetectionTest, DetectBasicHandover) {
    uint32_t old_teid = 0x12345678;
    uint32_t new_teid = 0x87654321;

    // Create initial tunnel
    auto create_req = createCreateSessionRequest(old_teid);
    manager->processMessage(create_req);

    auto create_resp = createCreateSessionResponse(old_teid, 0x11111111, "192.168.1.10");
    manager->processMessage(create_resp);

    // Verify tunnel created
    auto tunnel_opt = manager->getTunnel(old_teid);
    ASSERT_TRUE(tunnel_opt.has_value());
    EXPECT_EQ(tunnel_opt->state, TunnelState::ACTIVE);

    // Wait a bit to simulate activity
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // Modify bearer with new TEID (handover)
    auto modify_resp = createModifyBearerResponse(new_teid, "192.168.1.20");
    manager->processMessage(modify_resp);

    // Check old tunnel for handover event
    tunnel_opt = manager->getTunnel(old_teid);
    ASSERT_TRUE(tunnel_opt.has_value());

    const auto& old_tunnel = *tunnel_opt;
    EXPECT_EQ(old_tunnel.handovers.size(), 1);

    const auto& handover = old_tunnel.handovers[0];
    EXPECT_EQ(handover.old_teid_uplink, old_teid);
    EXPECT_EQ(handover.new_teid_uplink, new_teid);
    EXPECT_EQ(handover.handover_type, "X2");

    // New tunnel should be created
    auto new_tunnel_opt = manager->getTunnel(new_teid);
    ASSERT_TRUE(new_tunnel_opt.has_value());

    const auto& new_tunnel = *new_tunnel_opt;
    EXPECT_EQ(new_tunnel.imsi, imsi);
    EXPECT_EQ(new_tunnel.state, TunnelState::ACTIVE);
}

TEST_F(HandoverDetectionTest, HandoverSameImsiDifferentTeid) {
    uint32_t teid1 = 0x11111111;
    uint32_t teid2 = 0x22222222;

    // Create first tunnel
    auto req1 = createCreateSessionRequest(teid1);
    manager->processMessage(req1);

    auto resp1 = createCreateSessionResponse(teid1, 0x11111112, "192.168.1.10");
    manager->processMessage(resp1);

    // Handover to new TEID
    auto modify = createModifyBearerResponse(teid2, "192.168.1.20");
    manager->processMessage(modify);

    // Both tunnels should exist
    auto tunnels = manager->getTunnelsByImsi(imsi);
    EXPECT_EQ(tunnels.size(), 2);

    // Old tunnel should have handover event
    auto old_tunnel_opt = manager->getTunnel(teid1);
    ASSERT_TRUE(old_tunnel_opt.has_value());
    EXPECT_EQ(old_tunnel_opt->handovers.size(), 1);

    // New tunnel should be active
    auto new_tunnel_opt = manager->getTunnel(teid2);
    ASSERT_TRUE(new_tunnel_opt.has_value());
    EXPECT_EQ(new_tunnel_opt->state, TunnelState::ACTIVE);
}

TEST_F(HandoverDetectionTest, MultipleHandovers) {
    std::vector<uint32_t> teids = {
        0x11111111,
        0x22222222,
        0x33333333,
        0x44444444
    };

    // Create initial tunnel
    auto req = createCreateSessionRequest(teids[0]);
    manager->processMessage(req);

    auto resp = createCreateSessionResponse(teids[0], 0x11111112, "192.168.1.10");
    manager->processMessage(resp);

    // Perform 3 handovers
    for (size_t i = 1; i < teids.size(); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        std::string enb_ip = "192.168.1." + std::to_string(10 + i);
        auto modify = createModifyBearerResponse(teids[i], enb_ip);
        manager->processMessage(modify);
    }

    // Check handover count
    auto stats = manager->getStatistics();
    EXPECT_EQ(stats.handovers_detected, 3);

    // All tunnels should exist for same IMSI
    auto tunnels = manager->getTunnelsByImsi(imsi);
    EXPECT_EQ(tunnels.size(), 4);

    // First tunnel should have 1 handover (to second)
    auto tunnel1 = manager->getTunnel(teids[0]);
    ASSERT_TRUE(tunnel1.has_value());
    EXPECT_EQ(tunnel1->handovers.size(), 1);

    // Second tunnel should have 1 handover (to third)
    auto tunnel2 = manager->getTunnel(teids[1]);
    ASSERT_TRUE(tunnel2.has_value());
    EXPECT_EQ(tunnel2->handovers.size(), 1);

    // Third tunnel should have 1 handover (to fourth)
    auto tunnel3 = manager->getTunnel(teids[2]);
    ASSERT_TRUE(tunnel3.has_value());
    EXPECT_EQ(tunnel3->handovers.size(), 1);

    // Fourth tunnel should have no handovers (current)
    auto tunnel4 = manager->getTunnel(teids[3]);
    ASSERT_TRUE(tunnel4.has_value());
    EXPECT_EQ(tunnel4->handovers.size(), 0);
}

TEST_F(HandoverDetectionTest, HandoverInterruptionTime) {
    uint32_t old_teid = 0x12345678;
    uint32_t new_teid = 0x87654321;

    // Create initial tunnel
    auto create_req = createCreateSessionRequest(old_teid);
    manager->processMessage(create_req);

    auto create_resp = createCreateSessionResponse(old_teid, 0x11111111, "192.168.1.10");
    manager->processMessage(create_resp);

    // Simulate some activity
    auto activity_time = std::chrono::system_clock::now();
    manager->handleUserData(old_teid, true, 1500, activity_time);

    // Wait to simulate interruption
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Perform handover
    auto modify_resp = createModifyBearerResponse(new_teid, "192.168.1.20");
    manager->processMessage(modify_resp);

    // Check handover interruption time
    auto old_tunnel = manager->getTunnel(old_teid);
    ASSERT_TRUE(old_tunnel.has_value());
    ASSERT_EQ(old_tunnel->handovers.size(), 1);

    const auto& handover = old_tunnel->handovers[0];
    EXPECT_GT(handover.interruption_time.count(), 0);
    EXPECT_LT(handover.interruption_time.count(), 1000);  // Should be < 1 second
}

TEST_F(HandoverDetectionTest, HandoverCallback) {
    uint32_t old_teid = 0x12345678;
    uint32_t new_teid = 0x87654321;

    // Set up callback
    bool callback_invoked = false;
    HandoverEvent captured_event;
    GtpTunnel captured_tunnel;

    manager->setHandoverCallback([&](const HandoverEvent& event, const GtpTunnel& tunnel) {
        callback_invoked = true;
        captured_event = event;
        captured_tunnel = tunnel;
    });

    // Create initial tunnel
    auto create_req = createCreateSessionRequest(old_teid);
    manager->processMessage(create_req);

    auto create_resp = createCreateSessionResponse(old_teid, 0x11111111, "192.168.1.10");
    manager->processMessage(create_resp);

    // Perform handover
    auto modify_resp = createModifyBearerResponse(new_teid, "192.168.1.20");
    manager->processMessage(modify_resp);

    // Verify callback was invoked
    EXPECT_TRUE(callback_invoked);
    EXPECT_EQ(captured_event.old_teid_uplink, old_teid);
    EXPECT_EQ(captured_event.new_teid_uplink, new_teid);
    EXPECT_EQ(captured_tunnel.teid_uplink, old_teid);
}

TEST_F(HandoverDetectionTest, HandoverJsonSerialization) {
    uint32_t old_teid = 0x12345678;
    uint32_t new_teid = 0x87654321;

    // Create initial tunnel
    auto create_req = createCreateSessionRequest(old_teid);
    manager->processMessage(create_req);

    auto create_resp = createCreateSessionResponse(old_teid, 0x11111111, "192.168.1.10");
    manager->processMessage(create_resp);

    // Perform handover
    auto modify_resp = createModifyBearerResponse(new_teid, "192.168.1.20");
    manager->processMessage(modify_resp);

    // Get visualization JSON
    auto viz_json = manager->getTunnelVisualization(old_teid);

    EXPECT_TRUE(viz_json.contains("handovers"));
    EXPECT_TRUE(viz_json["handovers"].is_array());
    EXPECT_EQ(viz_json["handovers"].size(), 1);

    const auto& ho_json = viz_json["handovers"][0];
    EXPECT_TRUE(ho_json.contains("old_teid"));
    EXPECT_TRUE(ho_json.contains("new_teid"));
    EXPECT_TRUE(ho_json.contains("handover_type"));
    EXPECT_TRUE(ho_json.contains("interruption_ms"));

    EXPECT_EQ(ho_json["old_teid"], old_teid);
    EXPECT_EQ(ho_json["new_teid"], new_teid);
    EXPECT_EQ(ho_json["handover_type"], "X2");

    // Check events timeline
    EXPECT_TRUE(viz_json.contains("events"));
    bool found_handover_event = false;
    for (const auto& event : viz_json["events"]) {
        if (event["type"] == "HANDOVER") {
            found_handover_event = true;
            EXPECT_TRUE(event.contains("details"));
        }
    }
    EXPECT_TRUE(found_handover_event);
}

TEST_F(HandoverDetectionTest, ModifyWithoutTeidChangeNotHandover) {
    uint32_t teid = 0x12345678;

    // Create initial tunnel
    auto create_req = createCreateSessionRequest(teid);
    manager->processMessage(create_req);

    auto create_resp = createCreateSessionResponse(teid, 0x11111111, "192.168.1.10");
    manager->processMessage(create_resp);

    // Modify bearer with SAME TEID (QoS change, not handover)
    auto modify_resp = createModifyBearerResponse(teid, "192.168.1.10");
    manager->processMessage(modify_resp);

    // Should not have any handover events
    auto tunnel = manager->getTunnel(teid);
    ASSERT_TRUE(tunnel.has_value());
    EXPECT_EQ(tunnel->handovers.size(), 0);

    // Should only have one tunnel
    auto tunnels = manager->getTunnelsByImsi(imsi);
    EXPECT_EQ(tunnels.size(), 1);
}

TEST_F(HandoverDetectionTest, HandoverPreservesUserData) {
    uint32_t old_teid = 0x12345678;
    uint32_t new_teid = 0x87654321;

    // Create initial tunnel
    auto create_req = createCreateSessionRequest(old_teid);
    manager->processMessage(create_req);

    auto create_resp = createCreateSessionResponse(old_teid, 0x11111111, "192.168.1.10");
    manager->processMessage(create_resp);

    // Track some user data
    auto now = std::chrono::system_clock::now();
    manager->handleUserData(old_teid, true, 1000, now);
    manager->handleUserData(old_teid, false, 5000, now);

    auto old_tunnel = manager->getTunnel(old_teid);
    ASSERT_TRUE(old_tunnel.has_value());
    EXPECT_EQ(old_tunnel->uplink_bytes, 1000);
    EXPECT_EQ(old_tunnel->downlink_bytes, 5000);

    // Perform handover
    auto modify_resp = createModifyBearerResponse(new_teid, "192.168.1.20");
    manager->processMessage(modify_resp);

    // New tunnel should inherit subscriber info but start fresh on data metrics
    auto new_tunnel = manager->getTunnel(new_teid);
    ASSERT_TRUE(new_tunnel.has_value());
    EXPECT_EQ(new_tunnel->imsi, imsi);
    EXPECT_EQ(new_tunnel->ue_ip_v4, "10.0.0.100");
    EXPECT_EQ(new_tunnel->apn, "internet");
    EXPECT_EQ(new_tunnel->uplink_bytes, 0);    // New tunnel starts fresh
    EXPECT_EQ(new_tunnel->downlink_bytes, 0);
}

TEST_F(HandoverDetectionTest, ImsiVisualizationWithHandovers) {
    uint32_t teid1 = 0x11111111;
    uint32_t teid2 = 0x22222222;
    uint32_t teid3 = 0x33333333;

    // Create initial tunnel
    auto req1 = createCreateSessionRequest(teid1);
    manager->processMessage(req1);

    auto resp1 = createCreateSessionResponse(teid1, 0x11111112, "192.168.1.10");
    manager->processMessage(resp1);

    // First handover
    auto modify1 = createModifyBearerResponse(teid2, "192.168.1.20");
    manager->processMessage(modify1);

    // Second handover
    auto modify2 = createModifyBearerResponse(teid3, "192.168.1.30");
    manager->processMessage(modify2);

    // Get IMSI visualization
    auto imsi_viz = manager->getImsiVisualization(imsi);

    EXPECT_TRUE(imsi_viz.is_array());
    EXPECT_EQ(imsi_viz.size(), 3);

    // Count total handover events
    int total_handovers = 0;
    for (const auto& tunnel_json : imsi_viz) {
        if (tunnel_json.contains("handovers")) {
            total_handovers += tunnel_json["handovers"].size();
        }
    }

    EXPECT_EQ(total_handovers, 2);
}
