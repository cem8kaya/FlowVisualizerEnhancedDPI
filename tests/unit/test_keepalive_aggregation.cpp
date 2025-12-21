#include <gtest/gtest.h>
#include "correlation/keepalive_aggregator.h"
#include "correlation/tunnel_manager.h"
#include "session/session_types.h"
#include "common/types.h"
#include <chrono>
#include <thread>

using namespace callflow;

class KeepAliveAggregationTest : public ::testing::Test {
protected:
    void SetUp() override {
        aggregator = std::make_unique<KeepAliveAggregator>();
        teid = 0x12345678;
    }

    void TearDown() override {
        aggregator.reset();
    }

    std::chrono::system_clock::time_point getTimePoint(int seconds_offset = 0) {
        static auto base_time = std::chrono::system_clock::now();
        return base_time + std::chrono::seconds(seconds_offset);
    }

    std::unique_ptr<KeepAliveAggregator> aggregator;
    uint32_t teid;
};

TEST_F(KeepAliveAggregationTest, AddSingleEchoRequest) {
    auto ts = getTimePoint(0);
    aggregator->addEchoRequest(teid, ts);

    auto stats = aggregator->getEchoStats(teid);
    EXPECT_EQ(stats.request_count, 1);
    EXPECT_EQ(stats.response_count, 0);
    EXPECT_EQ(stats.timeout_count, 0);
}

TEST_F(KeepAliveAggregationTest, AddEchoRequestResponse) {
    auto req_ts = getTimePoint(0);
    auto resp_ts = getTimePoint(1);

    aggregator->addEchoRequest(teid, req_ts);
    aggregator->addEchoResponse(teid, resp_ts);

    auto stats = aggregator->getEchoStats(teid);
    EXPECT_EQ(stats.request_count, 1);
    EXPECT_EQ(stats.response_count, 1);
    EXPECT_EQ(stats.timeout_count, 0);
}

TEST_F(KeepAliveAggregationTest, MultipleEchoPairs) {
    int interval_sec = 300;  // 5 minutes

    for (int i = 0; i < 10; ++i) {
        auto req_ts = getTimePoint(i * interval_sec);
        auto resp_ts = getTimePoint(i * interval_sec + 1);

        aggregator->addEchoRequest(teid, req_ts);
        aggregator->addEchoResponse(teid, resp_ts);
    }

    auto stats = aggregator->getEchoStats(teid);
    EXPECT_EQ(stats.request_count, 10);
    EXPECT_EQ(stats.response_count, 10);
    EXPECT_EQ(stats.avg_interval.count(), interval_sec);
}

TEST_F(KeepAliveAggregationTest, AggregateHundredEchoes) {
    int interval_sec = 300;  // 5 minutes

    // Add 100 echo request/response pairs
    for (int i = 0; i < 100; ++i) {
        auto req_ts = getTimePoint(i * interval_sec);
        auto resp_ts = getTimePoint(i * interval_sec + 1);

        aggregator->addEchoRequest(teid, req_ts);
        aggregator->addEchoResponse(teid, resp_ts);
    }

    auto stats = aggregator->getEchoStats(teid);
    EXPECT_EQ(stats.request_count, 100);
    EXPECT_EQ(stats.response_count, 100);

    // Finalize to generate aggregations
    aggregator->finalizeTunnel(teid);

    auto aggregations = aggregator->getAggregatedKeepalives(teid);

    // Should aggregate most echoes (first and last shown individually)
    EXPECT_GT(aggregations.size(), 0);

    // Verify total echo count across aggregations
    uint32_t total_echoes = 0;
    for (const auto& agg : aggregations) {
        total_echoes += agg.echo_count;
    }

    // Should aggregate middle echoes (not first and last)
    EXPECT_GT(total_echoes, 0);
    EXPECT_LE(total_echoes, 100);
}

TEST_F(KeepAliveAggregationTest, IntervalChangeDetection) {
    int initial_interval = 300;  // 5 minutes
    int new_interval = 600;      // 10 minutes

    // Add echoes with initial interval
    for (int i = 0; i < 10; ++i) {
        auto req_ts = getTimePoint(i * initial_interval);
        auto resp_ts = getTimePoint(i * initial_interval + 1);

        aggregator->addEchoRequest(teid, req_ts);
        aggregator->addEchoResponse(teid, resp_ts);
    }

    // Change interval (> 20% change should trigger new aggregation)
    int time_offset = 10 * initial_interval;
    for (int i = 0; i < 10; ++i) {
        auto req_ts = getTimePoint(time_offset + i * new_interval);
        auto resp_ts = getTimePoint(time_offset + i * new_interval + 1);

        aggregator->addEchoRequest(teid, req_ts);
        aggregator->addEchoResponse(teid, resp_ts);
    }

    aggregator->finalizeTunnel(teid);

    auto aggregations = aggregator->getAggregatedKeepalives(teid);

    // Should have multiple aggregations due to interval change
    EXPECT_GT(aggregations.size(), 1);
}

TEST_F(KeepAliveAggregationTest, EchoTimeout) {
    int interval_sec = 300;  // 5 minutes

    // Add successful echoes
    for (int i = 0; i < 5; ++i) {
        auto req_ts = getTimePoint(i * interval_sec);
        auto resp_ts = getTimePoint(i * interval_sec + 1);

        aggregator->addEchoRequest(teid, req_ts);
        aggregator->addEchoResponse(teid, resp_ts);
    }

    // Add echo request without response (timeout)
    auto timeout_req = getTimePoint(5 * interval_sec);
    aggregator->addEchoRequest(teid, timeout_req);

    // Continue with more echoes after timeout
    for (int i = 6; i < 10; ++i) {
        auto req_ts = getTimePoint(i * interval_sec);
        auto resp_ts = getTimePoint(i * interval_sec + 1);

        aggregator->addEchoRequest(teid, req_ts);
        aggregator->addEchoResponse(teid, resp_ts);
    }

    aggregator->finalizeTunnel(teid);

    auto stats = aggregator->getEchoStats(teid);
    EXPECT_EQ(stats.request_count, 10);
    EXPECT_EQ(stats.response_count, 9);  // One timeout

    // Timeout should be marked for individual visualization
    auto should_show = aggregator->shouldShowEcho(teid, timeout_req);
    EXPECT_TRUE(should_show);
}

TEST_F(KeepAliveAggregationTest, TwentyFourHourTunnel) {
    int interval_sec = 300;  // 5 minutes
    int duration_hours = 24;
    int expected_echoes = (duration_hours * 3600) / interval_sec;  // 288 echoes

    // Add echoes for 24 hours
    for (int i = 0; i < expected_echoes; ++i) {
        auto req_ts = getTimePoint(i * interval_sec);
        auto resp_ts = getTimePoint(i * interval_sec + 1);

        aggregator->addEchoRequest(teid, req_ts);
        aggregator->addEchoResponse(teid, resp_ts);
    }

    auto stats = aggregator->getEchoStats(teid);
    EXPECT_EQ(stats.request_count, expected_echoes);
    EXPECT_EQ(stats.response_count, expected_echoes);

    aggregator->finalizeTunnel(teid);

    auto aggregations = aggregator->getAggregatedKeepalives(teid);

    // Verify aggregation
    EXPECT_GT(aggregations.size(), 0);

    // Should significantly reduce the number of events
    // Instead of 288 individual echoes, should have much fewer aggregations
    EXPECT_LT(aggregations.size(), 10);
}

TEST_F(KeepAliveAggregationTest, AggregatedKeepaliveJson) {
    int interval_sec = 300;  // 5 minutes

    // Add 20 echoes
    for (int i = 0; i < 20; ++i) {
        auto req_ts = getTimePoint(i * interval_sec);
        auto resp_ts = getTimePoint(i * interval_sec + 1);

        aggregator->addEchoRequest(teid, req_ts);
        aggregator->addEchoResponse(teid, resp_ts);
    }

    aggregator->finalizeTunnel(teid);

    auto aggregations = aggregator->getAggregatedKeepalives(teid);
    EXPECT_GT(aggregations.size(), 0);

    // Test JSON serialization
    for (const auto& agg : aggregations) {
        auto json = agg.toJson();

        EXPECT_TRUE(json.contains("type"));
        EXPECT_EQ(json["type"], "KEEPALIVE_AGGREGATED");
        EXPECT_TRUE(json.contains("echo_count"));
        EXPECT_TRUE(json.contains("interval_sec"));
        EXPECT_TRUE(json.contains("all_successful"));
        EXPECT_TRUE(json.contains("message"));
    }
}

TEST_F(KeepAliveAggregationTest, ClearTunnel) {
    auto req_ts = getTimePoint(0);
    aggregator->addEchoRequest(teid, req_ts);

    auto stats = aggregator->getEchoStats(teid);
    EXPECT_EQ(stats.request_count, 1);

    aggregator->clearTunnel(teid);

    stats = aggregator->getEchoStats(teid);
    EXPECT_EQ(stats.request_count, 0);
}

TEST_F(KeepAliveAggregationTest, ClearAll) {
    uint32_t teid1 = 0x11111111;
    uint32_t teid2 = 0x22222222;

    aggregator->addEchoRequest(teid1, getTimePoint(0));
    aggregator->addEchoRequest(teid2, getTimePoint(0));

    aggregator->clear();

    auto stats1 = aggregator->getEchoStats(teid1);
    auto stats2 = aggregator->getEchoStats(teid2);

    EXPECT_EQ(stats1.request_count, 0);
    EXPECT_EQ(stats2.request_count, 0);
}

TEST_F(KeepAliveAggregationTest, IntegrationWithTunnelManager) {
    auto manager = std::make_unique<TunnelManager>();

    // Helper to create GTP echo messages
    auto createEchoRequest = [](uint32_t teid, auto ts) {
        SessionMessageRef msg;
        msg.message_id = "echo_req";
        msg.timestamp = ts;
        msg.message_type = MessageType::GTP_ECHO_REQ;
        msg.protocol = ProtocolType::GTP_C;
        msg.correlation_key.teid_s1u = teid;
        msg.parsed_data["teid"] = teid;
        return msg;
    };

    auto createEchoResponse = [](uint32_t teid, auto ts) {
        SessionMessageRef msg;
        msg.message_id = "echo_resp";
        msg.timestamp = ts;
        msg.message_type = MessageType::GTP_ECHO_RESP;
        msg.protocol = ProtocolType::GTP_C;
        msg.correlation_key.teid_s1u = teid;
        msg.parsed_data["teid"] = teid;
        return msg;
    };

    // Create tunnel
    SessionMessageRef create_req;
    create_req.message_id = "create_req";
    create_req.timestamp = getTimePoint(0);
    create_req.message_type = MessageType::GTP_CREATE_SESSION_REQ;
    create_req.protocol = ProtocolType::GTP_C;
    create_req.correlation_key.teid_s1u = teid;
    create_req.correlation_key.imsi = "001010123456789";
    create_req.parsed_data["teid"] = teid;
    create_req.parsed_data["imsi"] = "001010123456789";
    create_req.parsed_data["apn"] = "internet";

    manager->processMessage(create_req);

    // Activate tunnel
    SessionMessageRef create_resp;
    create_resp.message_id = "create_resp";
    create_resp.timestamp = getTimePoint(1);
    create_resp.message_type = MessageType::GTP_CREATE_SESSION_RESP;
    create_resp.protocol = ProtocolType::GTP_C;
    create_resp.correlation_key.teid_s1u = teid;
    create_resp.parsed_data["bearer_contexts"] = nlohmann::json::array();
    create_resp.parsed_data["bearer_contexts"].push_back({
        {"s1u_enb_fteid", {{"teid", teid}, {"ipv4", "192.168.1.10"}}},
        {"s1u_sgw_fteid", {{"teid", 0x87654321}, {"ipv4", "192.168.2.10"}}}
    });

    manager->processMessage(create_resp);

    // Send 50 echo request/response pairs
    int interval_sec = 300;
    for (int i = 0; i < 50; ++i) {
        auto req_ts = getTimePoint(100 + i * interval_sec);
        auto resp_ts = getTimePoint(100 + i * interval_sec + 1);

        auto echo_req = createEchoRequest(teid, req_ts);
        auto echo_resp = createEchoResponse(teid, resp_ts);

        manager->processMessage(echo_req);
        manager->processMessage(echo_resp);
    }

    // Get tunnel and check echo counts
    auto tunnel_opt = manager->getTunnel(teid);
    ASSERT_TRUE(tunnel_opt.has_value());

    const auto& tunnel = *tunnel_opt;
    EXPECT_EQ(tunnel.echo_request_count, 50);
    EXPECT_EQ(tunnel.echo_response_count, 50);
    EXPECT_EQ(tunnel.echo_interval.count(), interval_sec);

    // Get visualization JSON
    auto viz_json = manager->getTunnelVisualization(teid);
    EXPECT_TRUE(viz_json.contains("events"));
    EXPECT_TRUE(viz_json["events"].is_array());

    // Events should include create, aggregated keep-alives
    // Much fewer than 50 individual echoes
    EXPECT_LT(viz_json["events"].size(), 20);
}
