#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "correlation/volte_call.h"
#include <nlohmann/json.hpp>

using namespace callflow::correlation;
using namespace std::chrono_literals;

class VolteCallTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create a basic call for testing
        call = std::make_shared<VolteCall>();
        call->call_id = "test-call-id@192.168.1.1";
        call->icid = "test-icid-12345";
        call->imsi = "001010123456789";
        call->msisdn = "+1234567890";
        call->calling_number = "sip:+1234567890@ims.example.com";
        call->called_number = "sip:+9876543210@ims.example.com";
        call->start_time = std::chrono::system_clock::now();
        call->state = VolteCall::State::INITIATING;
    }

    std::shared_ptr<VolteCall> call;
};

// ============================================================================
// Basic State Tests
// ============================================================================

TEST_F(VolteCallTest, InitialState) {
    EXPECT_EQ(call->state, VolteCall::State::INITIATING);
    EXPECT_FALSE(call->isComplete());
    EXPECT_FALSE(call->isFailed());
    EXPECT_FALSE(call->hasMedia());
}

TEST_F(VolteCallTest, StateTransitions) {
    // INITIATING → TRYING
    call->state = VolteCall::State::TRYING;
    EXPECT_FALSE(call->isComplete());
    EXPECT_FALSE(call->isFailed());

    // TRYING → RINGING
    call->state = VolteCall::State::RINGING;
    EXPECT_FALSE(call->isComplete());
    EXPECT_FALSE(call->isFailed());

    // RINGING → ANSWERED
    call->state = VolteCall::State::ANSWERED;
    EXPECT_FALSE(call->isComplete());
    EXPECT_FALSE(call->isFailed());

    // ANSWERED → CONFIRMED
    call->state = VolteCall::State::CONFIRMED;
    EXPECT_FALSE(call->isComplete());
    EXPECT_FALSE(call->isFailed());

    // CONFIRMED → MEDIA_ACTIVE
    call->state = VolteCall::State::MEDIA_ACTIVE;
    EXPECT_FALSE(call->isComplete());
    EXPECT_FALSE(call->isFailed());

    // MEDIA_ACTIVE → TERMINATING → COMPLETED
    call->state = VolteCall::State::TERMINATING;
    EXPECT_FALSE(call->isComplete());

    call->state = VolteCall::State::COMPLETED;
    EXPECT_TRUE(call->isComplete());
    EXPECT_FALSE(call->isFailed());
}

TEST_F(VolteCallTest, FailedState) {
    call->state = VolteCall::State::FAILED;
    call->state_reason = "486 Busy Here";

    EXPECT_TRUE(call->isComplete());
    EXPECT_TRUE(call->isFailed());
    EXPECT_EQ(call->state_reason, "486 Busy Here");
}

TEST_F(VolteCallTest, CancelledState) {
    call->state = VolteCall::State::CANCELLED;

    EXPECT_TRUE(call->isComplete());
    EXPECT_TRUE(call->isFailed());
}

// ============================================================================
// SIP Leg Tests
// ============================================================================

TEST_F(VolteCallTest, SipLegTimestamps) {
    auto now = std::chrono::system_clock::now();

    call->sip_leg.call_id = call->call_id;
    call->sip_leg.invite_time = now;
    call->sip_leg.trying_time = now + 10ms;
    call->sip_leg.ringing_time = now + 500ms;
    call->sip_leg.answer_time = now + 2000ms;
    call->sip_leg.ack_time = now + 2050ms;
    call->sip_leg.bye_time = now + 30000ms;

    EXPECT_EQ(call->sip_leg.call_id, call->call_id);
    EXPECT_TRUE(call->sip_leg.trying_time.has_value());
    EXPECT_TRUE(call->sip_leg.ringing_time.has_value());
    EXPECT_TRUE(call->sip_leg.answer_time.has_value());
    EXPECT_TRUE(call->sip_leg.ack_time.has_value());
    EXPECT_TRUE(call->sip_leg.bye_time.has_value());
}

TEST_F(VolteCallTest, SipLegMediaParameters) {
    call->sip_leg.audio_codec = "AMR-WB";
    call->sip_leg.rtp_port_local = 50000;
    call->sip_leg.rtp_port_remote = 60000;
    call->sip_leg.remote_ip = "10.20.30.40";

    EXPECT_EQ(call->sip_leg.audio_codec, "AMR-WB");
    EXPECT_EQ(call->sip_leg.rtp_port_local, 50000);
    EXPECT_EQ(call->sip_leg.rtp_port_remote, 60000);
    EXPECT_EQ(call->sip_leg.remote_ip, "10.20.30.40");
}

TEST_F(VolteCallTest, SipLegToJson) {
    call->sip_leg.call_id = call->call_id;
    call->sip_leg.from_uri = "sip:alice@example.com";
    call->sip_leg.to_uri = "sip:bob@example.com";
    call->sip_leg.p_cscf_ip = "192.168.1.100";
    call->sip_leg.invite_time = std::chrono::system_clock::now();
    call->sip_leg.audio_codec = "AMR";
    call->sip_leg.rtp_port_local = 50000;

    auto json = call->sip_leg.toJson();

    EXPECT_EQ(json["call_id"], call->call_id);
    EXPECT_EQ(json["from_uri"], "sip:alice@example.com");
    EXPECT_EQ(json["to_uri"], "sip:bob@example.com");
    EXPECT_EQ(json["p_cscf_ip"], "192.168.1.100");
    EXPECT_EQ(json["audio_codec"], "AMR");
    EXPECT_EQ(json["rtp_port_local"], 50000);
    EXPECT_TRUE(json.contains("invite_time"));
}

// ============================================================================
// DIAMETER Rx Leg Tests
// ============================================================================

TEST_F(VolteCallTest, RxLegCreation) {
    call->rx_leg = VolteCall::RxLeg();
    call->rx_leg->session_id = "pcscf.example.com;1234567890";
    call->rx_leg->af_app_id = "IMS Services";
    call->rx_leg->framed_ip = "10.10.10.10";
    call->rx_leg->aar_time = std::chrono::system_clock::now();
    call->rx_leg->aaa_time = call->rx_leg->aar_time + 50ms;
    call->rx_leg->result_code = 2001;  // DIAMETER_SUCCESS

    EXPECT_TRUE(call->rx_leg.has_value());
    EXPECT_EQ(call->rx_leg->result_code, 2001);
    EXPECT_TRUE(call->rx_leg->aaa_time.has_value());
}

TEST_F(VolteCallTest, RxLegMediaComponents) {
    call->rx_leg = VolteCall::RxLeg();

    VolteCall::RxLeg::MediaComponent audio_component;
    audio_component.flow_number = 1;
    audio_component.media_type = "audio";
    audio_component.max_bandwidth_ul = 128000;
    audio_component.max_bandwidth_dl = 128000;
    audio_component.flow_description = "permit in ip from 10.20.30.40 to any";

    call->rx_leg->media_components.push_back(audio_component);

    EXPECT_EQ(call->rx_leg->media_components.size(), 1);
    EXPECT_EQ(call->rx_leg->media_components[0].media_type, "audio");
    EXPECT_EQ(call->rx_leg->media_components[0].max_bandwidth_ul, 128000);
}

TEST_F(VolteCallTest, RxLegToJson) {
    call->rx_leg = VolteCall::RxLeg();
    call->rx_leg->session_id = "test-session";
    call->rx_leg->framed_ip = "10.10.10.10";
    call->rx_leg->aar_time = std::chrono::system_clock::now();
    call->rx_leg->result_code = 2001;

    auto json = call->rx_leg->toJson();

    EXPECT_EQ(json["session_id"], "test-session");
    EXPECT_EQ(json["framed_ip"], "10.10.10.10");
    EXPECT_EQ(json["result_code"], 2001);
    EXPECT_TRUE(json.contains("aar_time"));
}

// ============================================================================
// DIAMETER Gx Leg Tests
// ============================================================================

TEST_F(VolteCallTest, GxLegCreation) {
    call->gx_leg = VolteCall::GxLeg();
    call->gx_leg->session_id = "pgw.example.com;9876543210";
    call->gx_leg->framed_ip = "10.10.10.10";
    call->gx_leg->rar_time = std::chrono::system_clock::now();
    call->gx_leg->raa_time = call->gx_leg->rar_time + 30ms;

    EXPECT_TRUE(call->gx_leg.has_value());
    EXPECT_TRUE(call->gx_leg->raa_time.has_value());
}

TEST_F(VolteCallTest, GxLegChargingRules) {
    call->gx_leg = VolteCall::GxLeg();

    VolteCall::GxLeg::ChargingRule voice_rule;
    voice_rule.rule_name = "voice_qci1";
    voice_rule.qci = 1;
    voice_rule.guaranteed_bandwidth_ul = 128000;
    voice_rule.guaranteed_bandwidth_dl = 128000;

    call->gx_leg->charging_rules.push_back(voice_rule);

    EXPECT_EQ(call->gx_leg->charging_rules.size(), 1);
    EXPECT_EQ(call->gx_leg->charging_rules[0].qci, 1);
    EXPECT_EQ(call->gx_leg->charging_rules[0].rule_name, "voice_qci1");
}

TEST_F(VolteCallTest, GxLegToJson) {
    call->gx_leg = VolteCall::GxLeg();
    call->gx_leg->session_id = "gx-session";
    call->gx_leg->framed_ip = "10.10.10.10";
    call->gx_leg->rar_time = std::chrono::system_clock::now();

    auto json = call->gx_leg->toJson();

    EXPECT_EQ(json["session_id"], "gx-session");
    EXPECT_EQ(json["framed_ip"], "10.10.10.10");
    EXPECT_TRUE(json.contains("rar_time"));
}

// ============================================================================
// GTP Bearer Leg Tests
// ============================================================================

TEST_F(VolteCallTest, BearerLegCreation) {
    call->bearer_leg = VolteCall::BearerLeg();
    call->bearer_leg->teid_uplink = 0x12345678;
    call->bearer_leg->teid_downlink = 0x87654321;
    call->bearer_leg->eps_bearer_id = 5;
    call->bearer_leg->qci = 1;
    call->bearer_leg->gbr_ul = 128000;
    call->bearer_leg->gbr_dl = 128000;
    call->bearer_leg->request_time = std::chrono::system_clock::now();
    call->bearer_leg->response_time = call->bearer_leg->request_time + 100ms;
    call->bearer_leg->cause = 16;  // Request accepted

    EXPECT_TRUE(call->bearer_leg.has_value());
    EXPECT_EQ(call->bearer_leg->qci, 1);
    EXPECT_EQ(call->bearer_leg->eps_bearer_id, 5);
    EXPECT_EQ(call->bearer_leg->cause, 16);
    EXPECT_TRUE(call->bearer_leg->response_time.has_value());
}

TEST_F(VolteCallTest, BearerLegToJson) {
    call->bearer_leg = VolteCall::BearerLeg();
    call->bearer_leg->teid_uplink = 0x12345678;
    call->bearer_leg->eps_bearer_id = 5;
    call->bearer_leg->qci = 1;
    call->bearer_leg->request_time = std::chrono::system_clock::now();

    auto json = call->bearer_leg->toJson();

    EXPECT_EQ(json["teid_uplink"], 0x12345678);
    EXPECT_EQ(json["eps_bearer_id"], 5);
    EXPECT_EQ(json["qci"], 1);
    EXPECT_TRUE(json.contains("request_time"));
}

// ============================================================================
// RTP Leg Tests
// ============================================================================

TEST_F(VolteCallTest, RtpLegCreation) {
    call->rtp_leg = VolteCall::RtpLeg();
    call->rtp_leg->ssrc = 0xDEADBEEF;
    call->rtp_leg->local_ip = "10.10.10.10";
    call->rtp_leg->local_port = 50000;
    call->rtp_leg->remote_ip = "10.20.30.40";
    call->rtp_leg->remote_port = 60000;

    EXPECT_TRUE(call->rtp_leg.has_value());
    EXPECT_EQ(call->rtp_leg->ssrc, 0xDEADBEEF);
}

TEST_F(VolteCallTest, RtpLegStatistics) {
    call->rtp_leg = VolteCall::RtpLeg();

    // Uplink stats
    call->rtp_leg->uplink.packets = 1500;
    call->rtp_leg->uplink.bytes = 240000;
    call->rtp_leg->uplink.packet_loss_rate = 0.5;
    call->rtp_leg->uplink.jitter_ms = 15.2;
    call->rtp_leg->uplink.mos_estimate = 4.2;

    // Downlink stats
    call->rtp_leg->downlink.packets = 1480;
    call->rtp_leg->downlink.bytes = 236800;
    call->rtp_leg->downlink.packet_loss_rate = 0.8;
    call->rtp_leg->downlink.jitter_ms = 18.5;
    call->rtp_leg->downlink.mos_estimate = 4.0;

    EXPECT_EQ(call->rtp_leg->uplink.packets, 1500);
    EXPECT_DOUBLE_EQ(call->rtp_leg->uplink.mos_estimate, 4.2);
    EXPECT_EQ(call->rtp_leg->downlink.packets, 1480);
    EXPECT_DOUBLE_EQ(call->rtp_leg->downlink.mos_estimate, 4.0);

    // Call should have media
    EXPECT_TRUE(call->hasMedia());
}

TEST_F(VolteCallTest, HasMediaCheck) {
    // No RTP leg
    EXPECT_FALSE(call->hasMedia());

    // RTP leg exists but no packets
    call->rtp_leg = VolteCall::RtpLeg();
    EXPECT_FALSE(call->hasMedia());

    // RTP leg with uplink packets
    call->rtp_leg->uplink.packets = 100;
    EXPECT_TRUE(call->hasMedia());

    // RTP leg with downlink packets only
    call->rtp_leg = VolteCall::RtpLeg();
    call->rtp_leg->downlink.packets = 100;
    EXPECT_TRUE(call->hasMedia());
}

TEST_F(VolteCallTest, RtpLegToJson) {
    call->rtp_leg = VolteCall::RtpLeg();
    call->rtp_leg->ssrc = 0x12345678;
    call->rtp_leg->local_ip = "10.10.10.10";
    call->rtp_leg->local_port = 50000;
    call->rtp_leg->uplink.packets = 1000;
    call->rtp_leg->uplink.bytes = 160000;
    call->rtp_leg->uplink.mos_estimate = 4.1;

    auto json = call->rtp_leg->toJson();

    EXPECT_EQ(json["ssrc"], 0x12345678);
    EXPECT_EQ(json["local_ip"], "10.10.10.10");
    EXPECT_EQ(json["local_port"], 50000);
    EXPECT_EQ(json["uplink"]["packets"], 1000);
    EXPECT_EQ(json["uplink"]["bytes"], 160000);
    EXPECT_DOUBLE_EQ(json["uplink"]["mos_estimate"], 4.1);
}

// ============================================================================
// Metrics Tests
// ============================================================================

TEST_F(VolteCallTest, MetricsCalculation) {
    auto now = std::chrono::system_clock::now();

    // Set up timing
    call->sip_leg.invite_time = now;
    call->sip_leg.ringing_time = now + 500ms;
    call->sip_leg.answer_time = now + 2000ms;

    // Calculate metrics manually
    call->metrics.setup_time = 2000ms;
    call->metrics.post_dial_delay = 500ms;
    call->metrics.answer_delay = 1500ms;
    call->metrics.bearer_setup_time = 100ms;
    call->metrics.rx_authorization_time = 50ms;
    call->metrics.total_call_duration = 30000ms;
    call->metrics.media_duration = 29000ms;
    call->metrics.avg_mos = 4.15;
    call->metrics.packet_loss_rate = 0.65;
    call->metrics.jitter_ms = 16.85;

    EXPECT_EQ(call->metrics.setup_time.count(), 2000);
    EXPECT_EQ(call->metrics.post_dial_delay.count(), 500);
    EXPECT_EQ(call->metrics.answer_delay.count(), 1500);
    EXPECT_DOUBLE_EQ(call->metrics.avg_mos, 4.15);
    EXPECT_DOUBLE_EQ(call->metrics.packet_loss_rate, 0.65);
}

TEST_F(VolteCallTest, MetricsToJson) {
    call->metrics.setup_time = 2000ms;
    call->metrics.post_dial_delay = 500ms;
    call->metrics.avg_mos = 4.2;
    call->metrics.packet_loss_rate = 0.5;
    call->metrics.jitter_ms = 15.0;

    auto json = call->metrics.toJson();

    EXPECT_EQ(json["setup_time_ms"], 2000);
    EXPECT_EQ(json["post_dial_delay_ms"], 500);
    EXPECT_DOUBLE_EQ(json["avg_mos"], 4.2);
    EXPECT_DOUBLE_EQ(json["packet_loss_rate"], 0.5);
    EXPECT_DOUBLE_EQ(json["jitter_ms"], 15.0);
}

// ============================================================================
// Complete Call JSON Tests
// ============================================================================

TEST_F(VolteCallTest, CompleteCallToJson) {
    // Set up a complete call
    call->state = VolteCall::State::COMPLETED;
    call->sip_leg.invite_time = std::chrono::system_clock::now();
    call->sip_leg.from_uri = "sip:alice@example.com";
    call->sip_leg.to_uri = "sip:bob@example.com";

    call->rx_leg = VolteCall::RxLeg();
    call->rx_leg->result_code = 2001;

    call->bearer_leg = VolteCall::BearerLeg();
    call->bearer_leg->qci = 1;

    call->rtp_leg = VolteCall::RtpLeg();
    call->rtp_leg->uplink.packets = 1000;

    auto json = call->toJson();

    EXPECT_EQ(json["call_id"], call->call_id);
    EXPECT_EQ(json["imsi"], call->imsi);
    EXPECT_EQ(json["state_name"], "COMPLETED");
    EXPECT_TRUE(json.contains("sip_leg"));
    EXPECT_TRUE(json.contains("rx_leg"));
    EXPECT_TRUE(json.contains("bearer_leg"));
    EXPECT_TRUE(json.contains("rtp_leg"));
    EXPECT_TRUE(json.contains("metrics"));
}

// ============================================================================
// Ladder Diagram Tests
// ============================================================================

TEST_F(VolteCallTest, LadderDiagramGeneration) {
    call->sip_leg.invite_time = std::chrono::system_clock::now();
    call->sip_leg.trying_time = call->sip_leg.invite_time + 10ms;
    call->sip_leg.ringing_time = call->sip_leg.invite_time + 500ms;
    call->sip_leg.answer_time = call->sip_leg.invite_time + 2000ms;

    auto diagram = call->toLadderDiagramJson();

    EXPECT_EQ(diagram["call_id"], call->call_id);
    EXPECT_EQ(diagram["type"], "volte_call");
    EXPECT_TRUE(diagram.contains("participants"));
    EXPECT_TRUE(diagram.contains("messages"));
    EXPECT_TRUE(diagram.contains("metrics"));

    // Check participants
    auto participants = diagram["participants"];
    EXPECT_GE(participants.size(), 5);

    // Check messages
    auto messages = diagram["messages"];
    EXPECT_GE(messages.size(), 3);  // At least INVITE, 100 Trying, 180 Ringing
}

TEST_F(VolteCallTest, LadderDiagramMessageOrdering) {
    auto now = std::chrono::system_clock::now();

    call->sip_leg.invite_time = now;
    call->sip_leg.trying_time = now + 10ms;
    call->sip_leg.ringing_time = now + 500ms;
    call->sip_leg.answer_time = now + 2000ms;

    call->rx_leg = VolteCall::RxLeg();
    call->rx_leg->aar_time = now + 20ms;
    call->rx_leg->aaa_time = now + 70ms;

    auto diagram = call->toLadderDiagramJson();
    auto messages = diagram["messages"];

    // Verify messages are in chronological order
    for (size_t i = 1; i < messages.size(); i++) {
        EXPECT_LE(messages[i-1]["timestamp"], messages[i]["timestamp"]);
    }
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
