#include <gtest/gtest.h>
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

/**
 * Integration test for complete VoLTE call flow
 *
 * Tests the full lifecycle of a VoLTE call:
 * 1. SIP INVITE → 100 Trying → 180 Ringing → 200 OK → ACK
 * 2. DIAMETER Rx AAR → AAA
 * 3. DIAMETER Gx RAR → RAA
 * 4. GTP Create Bearer Request → Response
 * 5. RTP media packets
 * 6. SIP BYE
 */
class VolteFullCallTest : public ::testing::Test {
protected:
    void SetUp() override {
        context_mgr = std::make_shared<SubscriberContextManager>();
        correlator = std::make_unique<VolteCallCorrelator>(context_mgr);

        // Create subscriber context
        auto ctx = context_mgr->getOrCreate("001010123456789");
        ctx->msisdn = "+1234567890";
        ctx->ue_ipv4_addresses.insert("10.10.10.10");

        // Initialize test parameters
        call_id = "test-full-call@10.10.10.10";
        icid = "icid-full-test-12345";
        imsi = "001010123456789";
        ue_ip = "10.10.10.10";
        pcscf_ip = "192.168.1.100";
        pcrf_ip = "192.168.2.100";
        pgw_ip = "192.168.3.100";
        remote_media_ip = "10.20.30.40";

        msg_counter = 0;
        base_time = std::chrono::system_clock::now();
    }

    SessionMessageRef createMessage(const std::string& src_ip, const std::string& dst_ip,
                                    uint16_t src_port = 5060, uint16_t dst_port = 5060,
                                    std::chrono::milliseconds offset = 0ms) {
        SessionMessageRef msg;
        msg.message_id = "msg-" + std::to_string(++msg_counter);
        msg.timestamp = base_time + offset;
        msg.src_ip = src_ip;
        msg.dst_ip = dst_ip;
        msg.src_port = src_port;
        msg.dst_port = dst_port;
        return msg;
    }

    std::shared_ptr<SubscriberContextManager> context_mgr;
    std::unique_ptr<VolteCallCorrelator> correlator;

    std::string call_id;
    std::string icid;
    std::string imsi;
    std::string ue_ip;
    std::string pcscf_ip;
    std::string pcrf_ip;
    std::string pgw_ip;
    std::string remote_media_ip;

    int msg_counter;
    std::chrono::system_clock::time_point base_time;
};

TEST_F(VolteFullCallTest, CompleteSuccessfulCall) {
    // =========================================================================
    // 1. SIP INVITE
    // =========================================================================
    SipMessage invite;
    invite.is_request = true;
    invite.method = "INVITE";
    invite.call_id = call_id;
    invite.from = "sip:+1234567890@ims.example.com";
    invite.to = "sip:+9876543210@ims.example.com";
    invite.request_uri = "sip:+9876543210@ims.example.com";

    // P-Charging-Vector with ICID
    invite.p_charging_vector = SipPChargingVector();
    invite.p_charging_vector->icid = icid;

    // P-Asserted-Identity
    invite.p_asserted_identity = std::vector<SipPAssertedIdentity>();
    SipPAssertedIdentity pai;
    pai.uri = "sip:+1234567890@ims.example.com";
    invite.p_asserted_identity->push_back(pai);

    // SDP
    invite.sdp = SdpInfo();
    SdpMediaDescription audio;
    audio.media_type = "audio";
    audio.port = 50000;
    SdpRtpMap rtpmap;
    rtpmap.payload_type = 97;
    rtpmap.encoding_name = "AMR-WB";
    audio.rtpmap.push_back(rtpmap);
    invite.sdp->media_descriptions.push_back(audio);

    auto msg_invite = createMessage(ue_ip, pcscf_ip, 5060, 5060, 0ms);
    correlator->processSipMessage(msg_invite, invite);

    auto call = correlator->findByCallId(call_id);
    ASSERT_NE(call, nullptr);
    EXPECT_EQ(call->state, VolteCall::State::INITIATING);

    // =========================================================================
    // 2. SIP 100 Trying
    // =========================================================================
    SipMessage trying;
    trying.is_request = false;
    trying.call_id = call_id;
    trying.status_code = 100;
    trying.reason_phrase = "Trying";

    auto msg_trying = createMessage(pcscf_ip, ue_ip, 5060, 5060, 10ms);
    correlator->processSipMessage(msg_trying, trying);

    call = correlator->findByCallId(call_id);
    EXPECT_EQ(call->state, VolteCall::State::TRYING);

    // =========================================================================
    // 3. DIAMETER Rx AAR (Media authorization request)
    // =========================================================================
    DiameterMessage aar;
    aar.session_id = "pcscf.example.com;1234567890";

    auto msg_aar = createMessage(pcscf_ip, pcrf_ip, 3868, 3868, 20ms);
    msg_aar.correlation_key.icid = icid;
    msg_aar.correlation_key.ue_ipv4 = ue_ip;
    msg_aar.correlation_key.imsi = imsi;

    correlator->processDiameterRx(msg_aar, aar);

    call = correlator->findByCallId(call_id);
    EXPECT_TRUE(call->rx_leg.has_value());

    // =========================================================================
    // 4. DIAMETER Rx AAA (Media authorization answer)
    // =========================================================================
    DiameterMessage aaa;
    aaa.session_id = "pcscf.example.com;1234567890";
    aaa.result_code = 2001;  // DIAMETER_SUCCESS

    auto msg_aaa = createMessage(pcrf_ip, pcscf_ip, 3868, 3868, 70ms);
    msg_aaa.correlation_key.icid = icid;
    msg_aaa.correlation_key.ue_ipv4 = ue_ip;

    correlator->processDiameterRx(msg_aaa, aaa);

    call = correlator->findByCallId(call_id);
    EXPECT_TRUE(call->rx_leg->aaa_time.has_value());
    EXPECT_EQ(call->rx_leg->result_code, 2001);

    // =========================================================================
    // 5. DIAMETER Gx RAR (Policy installation)
    // =========================================================================
    DiameterMessage rar;
    rar.session_id = "pgw.example.com;9876543210";

    auto msg_rar = createMessage(pcrf_ip, pgw_ip, 3868, 3868, 80ms);
    msg_rar.correlation_key.ue_ipv4 = ue_ip;
    msg_rar.correlation_key.imsi = imsi;

    correlator->processDiameterGx(msg_rar, rar);

    call = correlator->findByCallId(call_id);
    EXPECT_TRUE(call->gx_leg.has_value());

    // =========================================================================
    // 6. DIAMETER Gx RAA (Policy installation acknowledgment)
    // =========================================================================
    DiameterMessage raa;
    raa.session_id = "pgw.example.com;9876543210";

    auto msg_raa = createMessage(pgw_ip, pcrf_ip, 3868, 3868, 110ms);
    msg_raa.correlation_key.ue_ipv4 = ue_ip;
    msg_raa.correlation_key.imsi = imsi;

    correlator->processDiameterGx(msg_raa, raa);

    call = correlator->findByCallId(call_id);
    EXPECT_TRUE(call->gx_leg->raa_time.has_value());

    // =========================================================================
    // 7. GTP Create Bearer Request (Dedicated bearer for voice)
    // =========================================================================
    GtpMessage create_bearer_req;
    create_bearer_req.imsi = imsi;

    auto msg_bearer_req = createMessage(pgw_ip, "192.168.4.100", 2123, 2123, 120ms);
    msg_bearer_req.correlation_key.imsi = imsi;
    msg_bearer_req.correlation_key.teid_s1u = 0x12345678;
    msg_bearer_req.correlation_key.teid_s5u = 0x87654321;
    msg_bearer_req.correlation_key.eps_bearer_id = 5;

    correlator->processGtpBearer(msg_bearer_req, create_bearer_req);

    call = correlator->findByCallId(call_id);
    EXPECT_TRUE(call->bearer_leg.has_value());
    EXPECT_EQ(call->bearer_leg->eps_bearer_id, 5);
    EXPECT_EQ(call->bearer_leg->qci, 1);

    // =========================================================================
    // 8. GTP Create Bearer Response
    // =========================================================================
    GtpMessage create_bearer_resp;
    create_bearer_resp.imsi = imsi;
    create_bearer_resp.cause = 16;  // Request accepted

    auto msg_bearer_resp = createMessage("192.168.4.100", pgw_ip, 2123, 2123, 220ms);
    msg_bearer_resp.correlation_key.imsi = imsi;

    correlator->processGtpBearer(msg_bearer_resp, create_bearer_resp);

    call = correlator->findByCallId(call_id);
    EXPECT_TRUE(call->bearer_leg->response_time.has_value());
    EXPECT_EQ(call->bearer_leg->cause, 16);

    // =========================================================================
    // 9. SIP 180 Ringing
    // =========================================================================
    SipMessage ringing;
    ringing.is_request = false;
    ringing.call_id = call_id;
    ringing.status_code = 180;
    ringing.reason_phrase = "Ringing";

    auto msg_ringing = createMessage(pcscf_ip, ue_ip, 5060, 5060, 500ms);
    correlator->processSipMessage(msg_ringing, ringing);

    call = correlator->findByCallId(call_id);
    EXPECT_EQ(call->state, VolteCall::State::RINGING);

    // =========================================================================
    // 10. SIP 200 OK
    // =========================================================================
    SipMessage ok;
    ok.is_request = false;
    ok.call_id = call_id;
    ok.status_code = 200;
    ok.reason_phrase = "OK";

    ok.sdp = SdpInfo();
    ok.sdp->connection_address = remote_media_ip;
    SdpMediaDescription remote_audio;
    remote_audio.media_type = "audio";
    remote_audio.port = 60000;
    ok.sdp->media_descriptions.push_back(remote_audio);

    auto msg_ok = createMessage(pcscf_ip, ue_ip, 5060, 5060, 2000ms);
    correlator->processSipMessage(msg_ok, ok);

    call = correlator->findByCallId(call_id);
    EXPECT_EQ(call->state, VolteCall::State::ANSWERED);
    EXPECT_EQ(call->sip_leg.remote_ip, remote_media_ip);
    EXPECT_EQ(call->sip_leg.rtp_port_remote, 60000);

    // =========================================================================
    // 11. SIP ACK
    // =========================================================================
    SipMessage ack;
    ack.is_request = true;
    ack.method = "ACK";
    ack.call_id = call_id;

    auto msg_ack = createMessage(ue_ip, pcscf_ip, 5060, 5060, 2050ms);
    correlator->processSipMessage(msg_ack, ack);

    call = correlator->findByCallId(call_id);
    EXPECT_EQ(call->state, VolteCall::State::CONFIRMED);

    // =========================================================================
    // 12. RTP media packets (simulate voice call)
    // =========================================================================
    uint32_t ssrc = 0xDEADBEEF;

    // Uplink packets (UE → Network)
    for (int i = 0; i < 1500; i++) {
        RtpHeader rtp;
        rtp.version = 2;
        rtp.ssrc = ssrc;
        rtp.sequence_number = i + 1;
        rtp.timestamp = 160 * (i + 1);
        rtp.payload_type = 97;

        auto msg_rtp = createMessage(ue_ip, remote_media_ip, 50000, 60000,
                                    2100ms + std::chrono::milliseconds(i * 20));
        msg_rtp.payload_length = 160;
        correlator->processRtpPacket(msg_rtp, rtp);
    }

    call = correlator->findByCallId(call_id);
    EXPECT_TRUE(call->rtp_leg.has_value());
    EXPECT_EQ(call->rtp_leg->ssrc, ssrc);
    EXPECT_EQ(call->rtp_leg->uplink.packets, 1500);
    EXPECT_EQ(call->rtp_leg->uplink.bytes, 1500 * 160);
    EXPECT_EQ(call->state, VolteCall::State::MEDIA_ACTIVE);

    // =========================================================================
    // 13. SIP BYE
    // =========================================================================
    SipMessage bye;
    bye.is_request = true;
    bye.method = "BYE";
    bye.call_id = call_id;

    auto msg_bye = createMessage(ue_ip, pcscf_ip, 5060, 5060, 32100ms);
    correlator->processSipMessage(msg_bye, bye);

    call = correlator->findByCallId(call_id);
    EXPECT_EQ(call->state, VolteCall::State::COMPLETED);
    EXPECT_TRUE(call->isComplete());
    EXPECT_FALSE(call->isFailed());

    // =========================================================================
    // Verify complete call structure
    // =========================================================================
    EXPECT_EQ(call->call_id, call_id);
    EXPECT_EQ(call->icid, icid);
    EXPECT_EQ(call->imsi, imsi);

    // SIP leg
    EXPECT_TRUE(call->sip_leg.trying_time.has_value());
    EXPECT_TRUE(call->sip_leg.ringing_time.has_value());
    EXPECT_TRUE(call->sip_leg.answer_time.has_value());
    EXPECT_TRUE(call->sip_leg.ack_time.has_value());
    EXPECT_TRUE(call->sip_leg.bye_time.has_value());

    // Rx leg
    EXPECT_TRUE(call->rx_leg.has_value());
    EXPECT_TRUE(call->rx_leg->aaa_time.has_value());

    // Gx leg
    EXPECT_TRUE(call->gx_leg.has_value());
    EXPECT_TRUE(call->gx_leg->raa_time.has_value());

    // Bearer leg
    EXPECT_TRUE(call->bearer_leg.has_value());
    EXPECT_TRUE(call->bearer_leg->response_time.has_value());

    // RTP leg
    EXPECT_TRUE(call->rtp_leg.has_value());
    EXPECT_GT(call->rtp_leg->uplink.packets, 0);

    // Verify metrics were calculated
    EXPECT_GT(call->metrics.setup_time.count(), 0);
    EXPECT_GT(call->metrics.post_dial_delay.count(), 0);

    // =========================================================================
    // Test JSON serialization
    // =========================================================================
    auto json = call->toJson();
    EXPECT_TRUE(json.contains("call_id"));
    EXPECT_TRUE(json.contains("sip_leg"));
    EXPECT_TRUE(json.contains("rx_leg"));
    EXPECT_TRUE(json.contains("gx_leg"));
    EXPECT_TRUE(json.contains("bearer_leg"));
    EXPECT_TRUE(json.contains("rtp_leg"));
    EXPECT_TRUE(json.contains("metrics"));

    // =========================================================================
    // Test ladder diagram generation
    // =========================================================================
    auto ladder = call->toLadderDiagramJson();
    EXPECT_TRUE(ladder.contains("participants"));
    EXPECT_TRUE(ladder.contains("messages"));
    EXPECT_GT(ladder["messages"].size(), 10);  // Should have many messages

    // Verify message ordering
    auto messages = ladder["messages"];
    for (size_t i = 1; i < messages.size(); i++) {
        EXPECT_LE(messages[i-1]["timestamp"], messages[i]["timestamp"]);
    }
}

TEST_F(VolteFullCallTest, CallFailure_BusyHere) {
    // =========================================================================
    // 1. SIP INVITE
    // =========================================================================
    SipMessage invite;
    invite.is_request = true;
    invite.method = "INVITE";
    invite.call_id = call_id;
    invite.from = "sip:+1234567890@ims.example.com";
    invite.to = "sip:+9876543210@ims.example.com";
    invite.request_uri = "sip:+9876543210@ims.example.com";

    auto msg_invite = createMessage(ue_ip, pcscf_ip, 5060, 5060, 0ms);
    correlator->processSipMessage(msg_invite, invite);

    auto call = correlator->findByCallId(call_id);
    ASSERT_NE(call, nullptr);

    // =========================================================================
    // 2. SIP 100 Trying
    // =========================================================================
    SipMessage trying;
    trying.is_request = false;
    trying.call_id = call_id;
    trying.status_code = 100;
    trying.reason_phrase = "Trying";

    auto msg_trying = createMessage(pcscf_ip, ue_ip, 5060, 5060, 10ms);
    correlator->processSipMessage(msg_trying, trying);

    // =========================================================================
    // 3. SIP 486 Busy Here (call failed)
    // =========================================================================
    SipMessage busy;
    busy.is_request = false;
    busy.call_id = call_id;
    busy.status_code = 486;
    busy.reason_phrase = "Busy Here";

    auto msg_busy = createMessage(pcscf_ip, ue_ip, 5060, 5060, 1000ms);
    correlator->processSipMessage(msg_busy, busy);

    call = correlator->findByCallId(call_id);
    EXPECT_EQ(call->state, VolteCall::State::FAILED);
    EXPECT_TRUE(call->isFailed());
    EXPECT_TRUE(call->isComplete());
    EXPECT_EQ(call->state_reason, "486 Busy Here");

    // No media legs should be present
    EXPECT_FALSE(call->rtp_leg.has_value() && call->rtp_leg->uplink.packets > 0);
}

TEST_F(VolteFullCallTest, CallCancelled) {
    // =========================================================================
    // 1. SIP INVITE
    // =========================================================================
    SipMessage invite;
    invite.is_request = true;
    invite.method = "INVITE";
    invite.call_id = call_id;
    invite.from = "sip:+1234567890@ims.example.com";
    invite.to = "sip:+9876543210@ims.example.com";
    invite.request_uri = "sip:+9876543210@ims.example.com";

    auto msg_invite = createMessage(ue_ip, pcscf_ip, 5060, 5060, 0ms);
    correlator->processSipMessage(msg_invite, invite);

    auto call = correlator->findByCallId(call_id);
    ASSERT_NE(call, nullptr);

    // =========================================================================
    // 2. SIP 100 Trying
    // =========================================================================
    SipMessage trying;
    trying.is_request = false;
    trying.call_id = call_id;
    trying.status_code = 100;
    trying.reason_phrase = "Trying";

    auto msg_trying = createMessage(pcscf_ip, ue_ip, 5060, 5060, 10ms);
    correlator->processSipMessage(msg_trying, trying);

    // =========================================================================
    // 3. SIP 180 Ringing
    // =========================================================================
    SipMessage ringing;
    ringing.is_request = false;
    ringing.call_id = call_id;
    ringing.status_code = 180;
    ringing.reason_phrase = "Ringing";

    auto msg_ringing = createMessage(pcscf_ip, ue_ip, 5060, 5060, 500ms);
    correlator->processSipMessage(msg_ringing, ringing);

    // =========================================================================
    // 4. SIP CANCEL (user cancels before answer)
    // =========================================================================
    SipMessage cancel;
    cancel.is_request = true;
    cancel.method = "CANCEL";
    cancel.call_id = call_id;

    auto msg_cancel = createMessage(ue_ip, pcscf_ip, 5060, 5060, 2000ms);
    correlator->processSipMessage(msg_cancel, cancel);

    call = correlator->findByCallId(call_id);
    EXPECT_EQ(call->state, VolteCall::State::CANCELLED);
    EXPECT_TRUE(call->isFailed());
    EXPECT_TRUE(call->isComplete());

    // Should have ringing but no answer
    EXPECT_TRUE(call->sip_leg.ringing_time.has_value());
    EXPECT_FALSE(call->sip_leg.answer_time.has_value());
}

TEST_F(VolteFullCallTest, MultipleCallsSameSubscriber) {
    // Create 3 calls for the same subscriber
    std::vector<std::string> call_ids;

    for (int i = 0; i < 3; i++) {
        std::string cid = "call-" + std::to_string(i) + "@10.10.10.10";
        call_ids.push_back(cid);

        SipMessage invite;
        invite.is_request = true;
        invite.method = "INVITE";
        invite.call_id = cid;
        invite.from = "sip:+1234567890@ims.example.com";
        invite.to = "sip:+9876543210@ims.example.com";
        invite.request_uri = "sip:+9876543210@ims.example.com";

        auto msg = createMessage(ue_ip, pcscf_ip, 5060, 5060,
                                std::chrono::milliseconds(i * 35000));
        correlator->processSipMessage(msg, invite);
    }

    // Verify all calls were created
    for (const auto& cid : call_ids) {
        auto call = correlator->findByCallId(cid);
        ASSERT_NE(call, nullptr);
    }

    // Find all calls for this IMSI
    auto calls = correlator->findByImsi(imsi);
    EXPECT_EQ(calls.size(), 3);

    // Verify stats
    auto stats = correlator->getStats();
    EXPECT_EQ(stats.total_calls, 3);
}

TEST_F(VolteFullCallTest, CorrelationByIcid) {
    // Create call with ICID
    SipMessage invite;
    invite.is_request = true;
    invite.method = "INVITE";
    invite.call_id = call_id;
    invite.from = "sip:+1234567890@ims.example.com";
    invite.to = "sip:+9876543210@ims.example.com";
    invite.request_uri = "sip:+9876543210@ims.example.com";
    invite.p_charging_vector = SipPChargingVector();
    invite.p_charging_vector->icid = icid;

    auto msg_invite = createMessage(ue_ip, pcscf_ip, 5060, 5060, 0ms);
    correlator->processSipMessage(msg_invite, invite);

    // Find call by ICID
    auto call = correlator->findByIcid(icid);
    ASSERT_NE(call, nullptr);
    EXPECT_EQ(call->call_id, call_id);
    EXPECT_EQ(call->icid, icid);
}

TEST_F(VolteFullCallTest, CorrelationByTeid) {
    // Create call
    SipMessage invite;
    invite.is_request = true;
    invite.method = "INVITE";
    invite.call_id = call_id;
    invite.from = "sip:+1234567890@ims.example.com";
    invite.to = "sip:+9876543210@ims.example.com";
    invite.request_uri = "sip:+9876543210@ims.example.com";

    auto msg_invite = createMessage(ue_ip, pcscf_ip, 5060, 5060, 0ms);
    correlator->processSipMessage(msg_invite, invite);

    // Add GTP bearer with TEID
    GtpMessage create_bearer_req;
    create_bearer_req.imsi = imsi;

    uint32_t test_teid = 0xABCDEF01;
    auto msg_bearer = createMessage(pgw_ip, "192.168.4.100", 2123, 2123, 100ms);
    msg_bearer.correlation_key.imsi = imsi;
    msg_bearer.correlation_key.teid_s1u = test_teid;

    correlator->processGtpBearer(msg_bearer, create_bearer_req);

    // Find call by TEID
    auto call = correlator->findByTeid(test_teid);
    ASSERT_NE(call, nullptr);
    EXPECT_EQ(call->call_id, call_id);
    EXPECT_TRUE(call->bearer_leg.has_value());
    EXPECT_EQ(call->bearer_leg->teid_uplink, test_teid);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
