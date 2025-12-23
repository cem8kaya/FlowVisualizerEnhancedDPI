#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "correlation/volte_call.h"
#include "correlation/subscriber_context.h"
#include "protocol_parsers/sip_parser.h"
#include "protocol_parsers/diameter_parser.h"
#include "protocol_parsers/gtp_parser.h"
#include "protocol_parsers/rtp_parser.h"

using namespace callflow::correlation;
using namespace callflow::protocol;
using namespace callflow::session;
using namespace std::chrono_literals;

class VolteCallCorrelatorTest : public ::testing::Test {
protected:
    void SetUp() override {
        context_mgr = std::make_shared<SubscriberContextManager>();
        correlator = std::make_unique<VolteCallCorrelator>(context_mgr);

        // Create a test subscriber context
        auto ctx = context_mgr->getOrCreate("001010123456789");
        ctx->msisdn = "+1234567890";
        ctx->ue_ipv4_addresses.insert("10.10.10.10");
    }

    SessionMessageRef createMessage(const std::string& msg_id,
                                    const std::string& src_ip,
                                    const std::string& dst_ip,
                                    uint16_t src_port = 5060,
                                    uint16_t dst_port = 5060) {
        SessionMessageRef msg;
        msg.message_id = msg_id;
        msg.timestamp = std::chrono::system_clock::now();
        msg.src_ip = src_ip;
        msg.dst_ip = dst_ip;
        msg.src_port = src_port;
        msg.dst_port = dst_port;
        return msg;
    }

    std::shared_ptr<SubscriberContextManager> context_mgr;
    std::unique_ptr<VolteCallCorrelator> correlator;
};

// ============================================================================
// SIP Processing Tests
// ============================================================================

TEST_F(VolteCallCorrelatorTest, ProcessSipInviteCreatesCall) {
    SipMessage sip;
    sip.is_request = true;
    sip.method = "INVITE";
    sip.call_id = "test-call-1@10.10.10.10";
    sip.from = "sip:+1234567890@ims.example.com";
    sip.to = "sip:+9876543210@ims.example.com";
    sip.request_uri = "sip:+9876543210@ims.example.com";

    // Add P-Charging-Vector
    sip.p_charging_vector = SipPChargingVector();
    sip.p_charging_vector->icid = "icid-test-12345";

    // Add P-Asserted-Identity
    sip.p_asserted_identity = std::vector<SipPAssertedIdentity>();
    SipPAssertedIdentity pai;
    pai.uri = "sip:+1234567890@ims.example.com";
    sip.p_asserted_identity->push_back(pai);

    auto msg = createMessage("msg-1", "10.10.10.10", "192.168.1.100");

    correlator->processSipMessage(msg, sip);

    // Verify call was created
    auto call = correlator->findByCallId(sip.call_id);
    ASSERT_NE(call, nullptr);
    EXPECT_EQ(call->call_id, sip.call_id);
    EXPECT_EQ(call->icid, "icid-test-12345");
    EXPECT_EQ(call->state, VolteCall::State::INITIATING);
    EXPECT_EQ(call->calling_number, pai.uri);
    EXPECT_EQ(call->called_number, sip.request_uri);
}

TEST_F(VolteCallCorrelatorTest, ProcessSipInviteWithSdp) {
    SipMessage sip;
    sip.is_request = true;
    sip.method = "INVITE";
    sip.call_id = "test-call-2@10.10.10.10";
    sip.from = "sip:alice@example.com";
    sip.to = "sip:bob@example.com";
    sip.request_uri = "sip:bob@example.com";

    // Add SDP
    sip.sdp = SdpInfo();
    SdpMediaDescription audio_media;
    audio_media.media_type = "audio";
    audio_media.port = 50000;
    SdpRtpMap rtpmap;
    rtpmap.payload_type = 97;
    rtpmap.encoding_name = "AMR-WB";
    audio_media.rtpmap.push_back(rtpmap);
    sip.sdp->media_descriptions.push_back(audio_media);

    auto msg = createMessage("msg-2", "10.10.10.10", "192.168.1.100");

    correlator->processSipMessage(msg, sip);

    auto call = correlator->findByCallId(sip.call_id);
    ASSERT_NE(call, nullptr);
    EXPECT_EQ(call->sip_leg.rtp_port_local, 50000);
    EXPECT_EQ(call->sip_leg.audio_codec, "AMR-WB");
}

TEST_F(VolteCallCorrelatorTest, ProcessSip100Trying) {
    // First create call with INVITE
    SipMessage invite;
    invite.is_request = true;
    invite.method = "INVITE";
    invite.call_id = "test-call-3@10.10.10.10";
    invite.from = "sip:alice@example.com";
    invite.to = "sip:bob@example.com";
    invite.request_uri = "sip:bob@example.com";

    auto msg1 = createMessage("msg-1", "10.10.10.10", "192.168.1.100");
    correlator->processSipMessage(msg1, invite);

    // Now send 100 Trying
    SipMessage trying_msg;
    trying_msg.is_request = false;
    trying_msg.call_id = invite.call_id;
    trying_msg.status_code = 100;
    trying_msg.reason_phrase = "Trying";

    auto msg2 = createMessage("msg-2", "192.168.1.100", "10.10.10.10");
    msg2.timestamp = msg1.timestamp + 10ms;
    correlator->processSipMessage(msg2, trying_msg);

    auto call = correlator->findByCallId(invite.call_id);
    ASSERT_NE(call, nullptr);
    EXPECT_EQ(call->state, VolteCall::State::TRYING);
    EXPECT_TRUE(call->sip_leg.trying_time.has_value());
}

TEST_F(VolteCallCorrelatorTest, ProcessSip180Ringing) {
    // Create call
    SipMessage invite;
    invite.is_request = true;
    invite.method = "INVITE";
    invite.call_id = "test-call-4@10.10.10.10";
    invite.from = "sip:alice@example.com";
    invite.to = "sip:bob@example.com";
    invite.request_uri = "sip:bob@example.com";

    auto msg1 = createMessage("msg-1", "10.10.10.10", "192.168.1.100");
    correlator->processSipMessage(msg1, invite);

    // Send 180 Ringing
    SipMessage ringing;
    ringing.is_request = false;
    ringing.call_id = invite.call_id;
    ringing.status_code = 180;
    ringing.reason_phrase = "Ringing";

    auto msg2 = createMessage("msg-2", "192.168.1.100", "10.10.10.10");
    msg2.timestamp = msg1.timestamp + 500ms;
    correlator->processSipMessage(msg2, ringing);

    auto call = correlator->findByCallId(invite.call_id);
    ASSERT_NE(call, nullptr);
    EXPECT_EQ(call->state, VolteCall::State::RINGING);
    EXPECT_TRUE(call->sip_leg.ringing_time.has_value());
}

TEST_F(VolteCallCorrelatorTest, ProcessSip200OK) {
    // Create call
    SipMessage invite;
    invite.is_request = true;
    invite.method = "INVITE";
    invite.call_id = "test-call-5@10.10.10.10";
    invite.from = "sip:alice@example.com";
    invite.to = "sip:bob@example.com";
    invite.request_uri = "sip:bob@example.com";

    auto msg1 = createMessage("msg-1", "10.10.10.10", "192.168.1.100");
    correlator->processSipMessage(msg1, invite);

    // Send 200 OK with SDP
    SipMessage ok;
    ok.is_request = false;
    ok.call_id = invite.call_id;
    ok.status_code = 200;
    ok.reason_phrase = "OK";

    ok.sdp = SdpInfo();
    ok.sdp->connection_address = "10.20.30.40";
    SdpMediaDescription audio;
    audio.media_type = "audio";
    audio.port = 60000;
    ok.sdp->media_descriptions.push_back(audio);

    auto msg2 = createMessage("msg-2", "192.168.1.100", "10.10.10.10");
    msg2.timestamp = msg1.timestamp + 2000ms;
    correlator->processSipMessage(msg2, ok);

    auto call = correlator->findByCallId(invite.call_id);
    ASSERT_NE(call, nullptr);
    EXPECT_EQ(call->state, VolteCall::State::ANSWERED);
    EXPECT_TRUE(call->sip_leg.answer_time.has_value());
    EXPECT_EQ(call->sip_leg.remote_ip, "10.20.30.40");
    EXPECT_EQ(call->sip_leg.rtp_port_remote, 60000);
}

TEST_F(VolteCallCorrelatorTest, ProcessSipAck) {
    // Create and answer call
    SipMessage invite;
    invite.is_request = true;
    invite.method = "INVITE";
    invite.call_id = "test-call-6@10.10.10.10";
    invite.from = "sip:alice@example.com";
    invite.to = "sip:bob@example.com";
    invite.request_uri = "sip:bob@example.com";

    auto msg1 = createMessage("msg-1", "10.10.10.10", "192.168.1.100");
    correlator->processSipMessage(msg1, invite);

    SipMessage ok;
    ok.is_request = false;
    ok.call_id = invite.call_id;
    ok.status_code = 200;
    ok.reason_phrase = "OK";

    auto msg2 = createMessage("msg-2", "192.168.1.100", "10.10.10.10");
    msg2.timestamp = msg1.timestamp + 2000ms;
    correlator->processSipMessage(msg2, ok);

    // Send ACK
    SipMessage ack;
    ack.is_request = true;
    ack.method = "ACK";
    ack.call_id = invite.call_id;

    auto msg3 = createMessage("msg-3", "10.10.10.10", "192.168.1.100");
    msg3.timestamp = msg2.timestamp + 50ms;
    correlator->processSipMessage(msg3, ack);

    auto call = correlator->findByCallId(invite.call_id);
    ASSERT_NE(call, nullptr);
    EXPECT_EQ(call->state, VolteCall::State::CONFIRMED);
    EXPECT_TRUE(call->sip_leg.ack_time.has_value());
}

TEST_F(VolteCallCorrelatorTest, ProcessSipBye) {
    // Create confirmed call
    SipMessage invite;
    invite.is_request = true;
    invite.method = "INVITE";
    invite.call_id = "test-call-7@10.10.10.10";
    invite.from = "sip:alice@example.com";
    invite.to = "sip:bob@example.com";
    invite.request_uri = "sip:bob@example.com";

    auto msg1 = createMessage("msg-1", "10.10.10.10", "192.168.1.100");
    correlator->processSipMessage(msg1, invite);

    // Send BYE
    SipMessage bye;
    bye.is_request = true;
    bye.method = "BYE";
    bye.call_id = invite.call_id;

    auto msg2 = createMessage("msg-2", "10.10.10.10", "192.168.1.100");
    msg2.timestamp = msg1.timestamp + 30000ms;
    correlator->processSipMessage(msg2, bye);

    auto call = correlator->findByCallId(invite.call_id);
    ASSERT_NE(call, nullptr);
    EXPECT_EQ(call->state, VolteCall::State::COMPLETED);
    EXPECT_TRUE(call->sip_leg.bye_time.has_value());
    EXPECT_TRUE(call->isComplete());
}

TEST_F(VolteCallCorrelatorTest, ProcessSipFailure) {
    // Create call
    SipMessage invite;
    invite.is_request = true;
    invite.method = "INVITE";
    invite.call_id = "test-call-8@10.10.10.10";
    invite.from = "sip:alice@example.com";
    invite.to = "sip:bob@example.com";
    invite.request_uri = "sip:bob@example.com";

    auto msg1 = createMessage("msg-1", "10.10.10.10", "192.168.1.100");
    correlator->processSipMessage(msg1, invite);

    // Send 486 Busy Here
    SipMessage busy;
    busy.is_request = false;
    busy.call_id = invite.call_id;
    busy.status_code = 486;
    busy.reason_phrase = "Busy Here";

    auto msg2 = createMessage("msg-2", "192.168.1.100", "10.10.10.10");
    correlator->processSipMessage(msg2, busy);

    auto call = correlator->findByCallId(invite.call_id);
    ASSERT_NE(call, nullptr);
    EXPECT_EQ(call->state, VolteCall::State::FAILED);
    EXPECT_TRUE(call->isFailed());
    EXPECT_EQ(call->state_reason, "486 Busy Here");
}

TEST_F(VolteCallCorrelatorTest, ProcessSipCancel) {
    // Create call
    SipMessage invite;
    invite.is_request = true;
    invite.method = "INVITE";
    invite.call_id = "test-call-9@10.10.10.10";
    invite.from = "sip:alice@example.com";
    invite.to = "sip:bob@example.com";
    invite.request_uri = "sip:bob@example.com";

    auto msg1 = createMessage("msg-1", "10.10.10.10", "192.168.1.100");
    correlator->processSipMessage(msg1, invite);

    // Send CANCEL
    SipMessage cancel;
    cancel.is_request = true;
    cancel.method = "CANCEL";
    cancel.call_id = invite.call_id;

    auto msg2 = createMessage("msg-2", "10.10.10.10", "192.168.1.100");
    correlator->processSipMessage(msg2, cancel);

    auto call = correlator->findByCallId(invite.call_id);
    ASSERT_NE(call, nullptr);
    EXPECT_EQ(call->state, VolteCall::State::CANCELLED);
    EXPECT_TRUE(call->isFailed());
}

// ============================================================================
// DIAMETER Rx Processing Tests
// ============================================================================

TEST_F(VolteCallCorrelatorTest, ProcessDiameterRxAAR) {
    // First create a call
    SipMessage invite;
    invite.is_request = true;
    invite.method = "INVITE";
    invite.call_id = "test-call-10@10.10.10.10";
    invite.from = "sip:alice@example.com";
    invite.to = "sip:bob@example.com";
    invite.request_uri = "sip:bob@example.com";
    invite.p_charging_vector = SipPChargingVector();
    invite.p_charging_vector->icid = "icid-rx-test";

    auto msg1 = createMessage("msg-1", "10.10.10.10", "192.168.1.100");
    correlator->processSipMessage(msg1, invite);

    // Now send DIAMETER Rx AAR
    DiameterMessage dia;
    dia.session_id = "pcscf.example.com;123456";

    auto msg2 = createMessage("msg-2", "192.168.1.100", "192.168.2.100");
    msg2.correlation_key.icid = "icid-rx-test";
    msg2.correlation_key.ue_ipv4 = "10.10.10.10";

    correlator->processDiameterRx(msg2, dia);

    auto call = correlator->findByCallId(invite.call_id);
    ASSERT_NE(call, nullptr);
    EXPECT_TRUE(call->rx_leg.has_value());
    EXPECT_EQ(call->rx_leg->session_id, dia.session_id.value());
}

TEST_F(VolteCallCorrelatorTest, ProcessDiameterRxAAA) {
    // Create call with AAR
    SipMessage invite;
    invite.is_request = true;
    invite.method = "INVITE";
    invite.call_id = "test-call-11@10.10.10.10";
    invite.from = "sip:alice@example.com";
    invite.to = "sip:bob@example.com";
    invite.request_uri = "sip:bob@example.com";
    invite.p_charging_vector = SipPChargingVector();
    invite.p_charging_vector->icid = "icid-rx-test-2";

    auto msg1 = createMessage("msg-1", "10.10.10.10", "192.168.1.100");
    correlator->processSipMessage(msg1, invite);

    // Send AAA
    DiameterMessage dia;
    dia.session_id = "pcscf.example.com;123456";
    dia.result_code = 2001;  // DIAMETER_SUCCESS

    auto msg2 = createMessage("msg-2", "192.168.2.100", "192.168.1.100");
    msg2.correlation_key.icid = "icid-rx-test-2";
    msg2.correlation_key.ue_ipv4 = "10.10.10.10";

    correlator->processDiameterRx(msg2, dia);

    auto call = correlator->findByCallId(invite.call_id);
    ASSERT_NE(call, nullptr);
    EXPECT_TRUE(call->rx_leg.has_value());
    EXPECT_EQ(call->rx_leg->result_code, 2001);
    EXPECT_TRUE(call->rx_leg->aaa_time.has_value());
}

// ============================================================================
// DIAMETER Gx Processing Tests
// ============================================================================

TEST_F(VolteCallCorrelatorTest, ProcessDiameterGxRAR) {
    // Create call
    SipMessage invite;
    invite.is_request = true;
    invite.method = "INVITE";
    invite.call_id = "test-call-12@10.10.10.10";
    invite.from = "sip:alice@example.com";
    invite.to = "sip:bob@example.com";
    invite.request_uri = "sip:bob@example.com";

    auto msg1 = createMessage("msg-1", "10.10.10.10", "192.168.1.100");
    correlator->processSipMessage(msg1, invite);

    // Send Gx RAR
    DiameterMessage dia;
    dia.session_id = "pgw.example.com;789012";

    auto msg2 = createMessage("msg-2", "192.168.2.100", "192.168.3.100");
    msg2.correlation_key.ue_ipv4 = "10.10.10.10";
    msg2.correlation_key.imsi = "001010123456789";

    correlator->processDiameterGx(msg2, dia);

    auto call = correlator->findByCallId(invite.call_id);
    ASSERT_NE(call, nullptr);
    EXPECT_TRUE(call->gx_leg.has_value());
    EXPECT_EQ(call->gx_leg->session_id, dia.session_id.value());
}

// ============================================================================
// GTP Bearer Processing Tests
// ============================================================================

TEST_F(VolteCallCorrelatorTest, ProcessGtpCreateBearerRequest) {
    // Create call
    SipMessage invite;
    invite.is_request = true;
    invite.method = "INVITE";
    invite.call_id = "test-call-13@10.10.10.10";
    invite.from = "sip:alice@example.com";
    invite.to = "sip:bob@example.com";
    invite.request_uri = "sip:bob@example.com";

    auto msg1 = createMessage("msg-1", "10.10.10.10", "192.168.1.100");
    correlator->processSipMessage(msg1, invite);

    // Send GTP Create Bearer Request
    GtpMessage gtp;
    gtp.imsi = "001010123456789";

    auto msg2 = createMessage("msg-2", "192.168.3.100", "192.168.4.100", 2123, 2123);
    msg2.correlation_key.imsi = "001010123456789";
    msg2.correlation_key.teid_s1u = 0x12345678;
    msg2.correlation_key.eps_bearer_id = 5;

    correlator->processGtpBearer(msg2, gtp);

    auto call = correlator->findByCallId(invite.call_id);
    ASSERT_NE(call, nullptr);
    EXPECT_TRUE(call->bearer_leg.has_value());
    EXPECT_EQ(call->bearer_leg->teid_uplink, 0x12345678);
    EXPECT_EQ(call->bearer_leg->eps_bearer_id, 5);
    EXPECT_EQ(call->bearer_leg->qci, 1);
}

// ============================================================================
// RTP Processing Tests
// ============================================================================

TEST_F(VolteCallCorrelatorTest, ProcessRtpPacket) {
    // Create call with SDP
    SipMessage invite;
    invite.is_request = true;
    invite.method = "INVITE";
    invite.call_id = "test-call-14@10.10.10.10";
    invite.from = "sip:alice@example.com";
    invite.to = "sip:bob@example.com";
    invite.request_uri = "sip:bob@example.com";

    invite.sdp = SdpInfo();
    SdpMediaDescription audio;
    audio.media_type = "audio";
    audio.port = 50000;
    invite.sdp->media_descriptions.push_back(audio);

    auto msg1 = createMessage("msg-1", "10.10.10.10", "192.168.1.100");
    correlator->processSipMessage(msg1, invite);

    // Mark call as CONFIRMED
    auto call = correlator->findByCallId(invite.call_id);
    ASSERT_NE(call, nullptr);
    call->state = VolteCall::State::CONFIRMED;

    // Send RTP packet
    RtpHeader rtp;
    rtp.version = 2;
    rtp.ssrc = 0xDEADBEEF;
    rtp.sequence_number = 1;

    auto msg2 = createMessage("msg-2", "10.10.10.10", "10.20.30.40", 50000, 60000);
    msg2.payload_length = 160;
    correlator->processRtpPacket(msg2, rtp);

    call = correlator->findByCallId(invite.call_id);
    EXPECT_TRUE(call->rtp_leg.has_value());
    EXPECT_EQ(call->rtp_leg->ssrc, 0xDEADBEEF);
    EXPECT_EQ(call->rtp_leg->uplink.packets, 1);
    EXPECT_EQ(call->rtp_leg->uplink.bytes, 160);
    EXPECT_EQ(call->state, VolteCall::State::MEDIA_ACTIVE);
}

// ============================================================================
// Lookup Tests
// ============================================================================

TEST_F(VolteCallCorrelatorTest, FindByCallId) {
    SipMessage invite;
    invite.is_request = true;
    invite.method = "INVITE";
    invite.call_id = "test-call-15@10.10.10.10";
    invite.from = "sip:alice@example.com";
    invite.to = "sip:bob@example.com";
    invite.request_uri = "sip:bob@example.com";

    auto msg = createMessage("msg-1", "10.10.10.10", "192.168.1.100");
    correlator->processSipMessage(msg, invite);

    auto call = correlator->findByCallId(invite.call_id);
    ASSERT_NE(call, nullptr);
    EXPECT_EQ(call->call_id, invite.call_id);
}

TEST_F(VolteCallCorrelatorTest, FindByIcid) {
    SipMessage invite;
    invite.is_request = true;
    invite.method = "INVITE";
    invite.call_id = "test-call-16@10.10.10.10";
    invite.from = "sip:alice@example.com";
    invite.to = "sip:bob@example.com";
    invite.request_uri = "sip:bob@example.com";
    invite.p_charging_vector = SipPChargingVector();
    invite.p_charging_vector->icid = "icid-lookup-test";

    auto msg = createMessage("msg-1", "10.10.10.10", "192.168.1.100");
    correlator->processSipMessage(msg, invite);

    auto call = correlator->findByIcid("icid-lookup-test");
    ASSERT_NE(call, nullptr);
    EXPECT_EQ(call->icid, "icid-lookup-test");
}

TEST_F(VolteCallCorrelatorTest, FindByImsi) {
    // Create multiple calls for the same IMSI
    for (int i = 0; i < 3; i++) {
        SipMessage invite;
        invite.is_request = true;
        invite.method = "INVITE";
        invite.call_id = "test-call-" + std::to_string(i) + "@10.10.10.10";
        invite.from = "sip:alice@example.com";
        invite.to = "sip:bob@example.com";
        invite.request_uri = "sip:bob@example.com";

        auto msg = createMessage("msg-" + std::to_string(i), "10.10.10.10", "192.168.1.100");
        correlator->processSipMessage(msg, invite);
    }

    auto calls = correlator->findByImsi("001010123456789");
    EXPECT_EQ(calls.size(), 3);
}

// ============================================================================
// Statistics Tests
// ============================================================================

TEST_F(VolteCallCorrelatorTest, GetStats) {
    // Create successful call
    SipMessage invite1;
    invite1.is_request = true;
    invite1.method = "INVITE";
    invite1.call_id = "test-call-success@10.10.10.10";
    invite1.from = "sip:alice@example.com";
    invite1.to = "sip:bob@example.com";
    invite1.request_uri = "sip:bob@example.com";

    auto msg1 = createMessage("msg-1", "10.10.10.10", "192.168.1.100");
    correlator->processSipMessage(msg1, invite1);

    auto call1 = correlator->findByCallId(invite1.call_id);
    call1->state = VolteCall::State::COMPLETED;

    // Create failed call
    SipMessage invite2;
    invite2.is_request = true;
    invite2.method = "INVITE";
    invite2.call_id = "test-call-failed@10.10.10.10";
    invite2.from = "sip:alice@example.com";
    invite2.to = "sip:bob@example.com";
    invite2.request_uri = "sip:bob@example.com";

    auto msg2 = createMessage("msg-2", "10.10.10.10", "192.168.1.100");
    correlator->processSipMessage(msg2, invite2);

    auto call2 = correlator->findByCallId(invite2.call_id);
    call2->state = VolteCall::State::FAILED;

    // Create active call
    SipMessage invite3;
    invite3.is_request = true;
    invite3.method = "INVITE";
    invite3.call_id = "test-call-active@10.10.10.10";
    invite3.from = "sip:alice@example.com";
    invite3.to = "sip:bob@example.com";
    invite3.request_uri = "sip:bob@example.com";

    auto msg3 = createMessage("msg-3", "10.10.10.10", "192.168.1.100");
    correlator->processSipMessage(msg3, invite3);

    auto stats = correlator->getStats();
    EXPECT_EQ(stats.total_calls, 3);
    EXPECT_EQ(stats.successful_calls, 1);
    EXPECT_EQ(stats.failed_calls, 1);
    EXPECT_EQ(stats.active_calls, 1);
}

// ============================================================================
// Cleanup Tests
// ============================================================================

TEST_F(VolteCallCorrelatorTest, CleanupCompletedCalls) {
    // Create completed call
    SipMessage invite;
    invite.is_request = true;
    invite.method = "INVITE";
    invite.call_id = "test-call-cleanup@10.10.10.10";
    invite.from = "sip:alice@example.com";
    invite.to = "sip:bob@example.com";
    invite.request_uri = "sip:bob@example.com";

    auto msg = createMessage("msg-1", "10.10.10.10", "192.168.1.100");
    correlator->processSipMessage(msg, invite);

    auto call = correlator->findByCallId(invite.call_id);
    call->state = VolteCall::State::COMPLETED;
    call->end_time = std::chrono::system_clock::now() - std::chrono::hours(2);

    // Clean up calls older than 1 hour
    size_t removed = correlator->cleanupCompletedCalls(std::chrono::hours(1));
    EXPECT_EQ(removed, 1);

    // Call should no longer be found
    call = correlator->findByCallId(invite.call_id);
    EXPECT_EQ(call, nullptr);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
