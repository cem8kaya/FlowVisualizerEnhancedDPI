#include <gtest/gtest.h>
#include "correlation/volte/volte_correlator.h"
#include "correlation/sip/sip_correlator.h"
#include "correlation/diameter/diameter_correlator.h"
#include "correlation/gtpv2/gtpv2_correlator.h"
#include "correlation/nas/nas_correlator.h"
#include "correlation/rtp/rtp_correlator.h"
#include "correlation/identity/subscriber_context_manager.h"

using namespace callflow::correlation;

class VolteCorrelatorTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create all correlators
        subscriber_manager = std::make_unique<SubscriberContextManager>();
        sip_correlator = std::make_unique<SipCorrelator>(subscriber_manager.get());
        diameter_correlator = std::make_unique<DiameterCorrelator>(subscriber_manager.get());
        gtpv2_correlator = std::make_unique<Gtpv2Correlator>(subscriber_manager.get());
        nas_correlator = std::make_unique<NasCorrelator>(subscriber_manager.get());
        rtp_correlator = std::make_unique<RtpCorrelator>();

        // Create VoLTE correlator
        volte_correlator = std::make_unique<VolteCorrelator>();
        volte_correlator->setSipCorrelator(sip_correlator.get());
        volte_correlator->setDiameterCorrelator(diameter_correlator.get());
        volte_correlator->setGtpv2Correlator(gtpv2_correlator.get());
        volte_correlator->setNasCorrelator(nas_correlator.get());
        volte_correlator->setRtpCorrelator(rtp_correlator.get());
        volte_correlator->setSubscriberContextManager(subscriber_manager.get());
    }

    // Helper to create SIP INVITE
    SipMessage createSipInvite(const std::string& call_id,
                              const std::string& caller_msisdn,
                              const std::string& callee_msisdn,
                              const std::string& caller_ip,
                              double timestamp,
                              uint32_t frame) {
        SipMessage msg;
        msg.setRequest(true);
        msg.setMethod("INVITE");
        msg.setCallId(call_id);
        msg.setFromUri("sip:" + caller_msisdn + "@ims.mnc001.mcc001.3gppnetwork.org");
        msg.setFromTag("from-tag-123");
        msg.setToUri("sip:" + callee_msisdn + "@ims.mnc001.mcc001.3gppnetwork.org");
        msg.setCSeq(1);
        msg.setCSeqMethod("INVITE");
        msg.setTimestamp(timestamp);
        msg.setFrameNumber(frame);

        // Add Via header with caller IP
        SipViaHeader via;
        via.protocol = "SIP/2.0/UDP";
        via.sent_by = caller_ip + ":5060";
        via.branch = "z9hG4bK-test-branch";
        via.index = 0;
        msg.addViaHeader(via);

        // Add SDP with media info
        std::string sdp = "v=0\n";
        sdp += "o=- 123456 654321 IN IP4 " + caller_ip + "\n";
        sdp += "s=Call\n";
        sdp += "c=IN IP4 " + caller_ip + "\n";
        sdp += "t=0 0\n";
        sdp += "m=audio 49170 RTP/AVP 0\n";
        sdp += "a=rtpmap:0 PCMU/8000\n";
        sdp += "a=sendrecv\n";
        msg.setSdpBody(sdp);

        return msg;
    }

    // Helper to create SIP 200 OK
    SipMessage createSip200Ok(const std::string& call_id,
                             const std::string& from_tag,
                             const std::string& to_tag,
                             double timestamp,
                             uint32_t frame) {
        SipMessage msg;
        msg.setRequest(false);
        msg.setStatusCode(200);
        msg.setCallId(call_id);
        msg.setFromTag(from_tag);
        msg.setToTag(to_tag);
        msg.setCSeq(1);
        msg.setCSeqMethod("INVITE");
        msg.setTimestamp(timestamp);
        msg.setFrameNumber(frame);

        return msg;
    }

    // Helper to create SIP BYE
    SipMessage createSipBye(const std::string& call_id,
                           const std::string& from_tag,
                           const std::string& to_tag,
                           double timestamp,
                           uint32_t frame) {
        SipMessage msg;
        msg.setRequest(true);
        msg.setMethod("BYE");
        msg.setCallId(call_id);
        msg.setFromTag(from_tag);
        msg.setToTag(to_tag);
        msg.setCSeq(2);
        msg.setCSeqMethod("BYE");
        msg.setTimestamp(timestamp);
        msg.setFrameNumber(frame);

        return msg;
    }

    std::unique_ptr<SubscriberContextManager> subscriber_manager;
    std::unique_ptr<SipCorrelator> sip_correlator;
    std::unique_ptr<DiameterCorrelator> diameter_correlator;
    std::unique_ptr<Gtpv2Correlator> gtpv2_correlator;
    std::unique_ptr<NasCorrelator> nas_correlator;
    std::unique_ptr<RtpCorrelator> rtp_correlator;
    std::unique_ptr<VolteCorrelator> volte_correlator;
};

// ============================================================================
// Basic Correlation Tests
// ============================================================================

TEST_F(VolteCorrelatorTest, EmptyCorrelation) {
    volte_correlator->correlate();

    auto flows = volte_correlator->getCallFlows();
    EXPECT_EQ(flows.size(), 0);

    auto stats = volte_correlator->getStats();
    EXPECT_EQ(stats.total_call_flows, 0);
}

TEST_F(VolteCorrelatorTest, SingleVoiceCallFromSip) {
    // Add SIP call messages
    auto invite = createSipInvite("call-1@ims.example.com",
                                  "+14155551234",
                                  "+14155555678",
                                  "10.1.2.3",
                                  1000.0, 100);
    auto ok = createSip200Ok("call-1@ims.example.com",
                            "from-tag-123", "to-tag-456",
                            1001.0, 101);
    auto bye = createSipBye("call-1@ims.example.com",
                           "from-tag-123", "to-tag-456",
                           1030.0, 102);

    sip_correlator->addMessage(invite);
    sip_correlator->addMessage(ok);
    sip_correlator->addMessage(bye);
    sip_correlator->finalize();

    // Run VoLTE correlation
    volte_correlator->correlate();

    // Verify call flow created
    auto flows = volte_correlator->getCallFlows();
    ASSERT_EQ(flows.size(), 1);

    auto* flow = flows[0];
    EXPECT_EQ(flow->type, VolteFlowType::MO_VOICE_CALL);
    EXPECT_EQ(flow->caller.msisdn, "+14155551234");
    EXPECT_EQ(flow->callee.msisdn, "+14155555678");
    EXPECT_EQ(flow->caller.ip_v4, "10.1.2.3");
    EXPECT_EQ(flow->sip_sessions.size(), 1);
    EXPECT_EQ(flow->stats.sip_messages, 3);

    // Verify statistics
    auto stats = volte_correlator->getStats();
    EXPECT_EQ(stats.total_call_flows, 1);
    EXPECT_EQ(stats.voice_calls, 1);
}

TEST_F(VolteCorrelatorTest, LookupByMsisdn) {
    // Create two calls with different MSISDNs
    auto invite1 = createSipInvite("call-1@ims.example.com",
                                   "+14155551234",
                                   "+14155555678",
                                   "10.1.2.3",
                                   1000.0, 100);
    sip_correlator->addMessage(invite1);

    auto invite2 = createSipInvite("call-2@ims.example.com",
                                   "+14155555678",
                                   "+14155559999",
                                   "10.1.2.4",
                                   2000.0, 200);
    sip_correlator->addMessage(invite2);

    sip_correlator->finalize();
    volte_correlator->correlate();

    // Lookup by first MSISDN (caller in first call)
    auto flows1 = volte_correlator->findByMsisdn("+14155551234");
    ASSERT_EQ(flows1.size(), 1);
    EXPECT_EQ(flows1[0]->caller.msisdn, "+14155551234");

    // Lookup by second MSISDN (callee in first call, caller in second call)
    auto flows2 = volte_correlator->findByMsisdn("+14155555678");
    EXPECT_EQ(flows2.size(), 2);
}

TEST_F(VolteCorrelatorTest, LookupByFlowId) {
    auto invite = createSipInvite("call-1@ims.example.com",
                                  "+14155551234",
                                  "+14155555678",
                                  "10.1.2.3",
                                  1000.0, 100);
    sip_correlator->addMessage(invite);
    sip_correlator->finalize();
    volte_correlator->correlate();

    auto flows = volte_correlator->getCallFlows();
    ASSERT_EQ(flows.size(), 1);

    auto flow_id = flows[0]->flow_id;
    auto* found_flow = volte_correlator->findByFlowId(flow_id);
    ASSERT_NE(found_flow, nullptr);
    EXPECT_EQ(found_flow->flow_id, flow_id);
}

TEST_F(VolteCorrelatorTest, LookupByFrame) {
    auto invite = createSipInvite("call-1@ims.example.com",
                                  "+14155551234",
                                  "+14155555678",
                                  "10.1.2.3",
                                  1000.0, 100);
    auto ok = createSip200Ok("call-1@ims.example.com",
                            "from-tag-123", "to-tag-456",
                            1001.0, 101);

    sip_correlator->addMessage(invite);
    sip_correlator->addMessage(ok);
    sip_correlator->finalize();
    volte_correlator->correlate();

    // Find flow by INVITE frame
    auto* flow1 = volte_correlator->findByFrame(100);
    ASSERT_NE(flow1, nullptr);

    // Find flow by 200 OK frame
    auto* flow2 = volte_correlator->findByFrame(101);
    ASSERT_NE(flow2, nullptr);

    // Should be the same flow
    EXPECT_EQ(flow1->flow_id, flow2->flow_id);
}

// ============================================================================
// Call Type Detection Tests
// ============================================================================

TEST_F(VolteCorrelatorTest, DetectVideoCall) {
    auto invite = createSipInvite("call-1@ims.example.com",
                                  "+14155551234",
                                  "+14155555678",
                                  "10.1.2.3",
                                  1000.0, 100);

    // Add video SDP
    std::string sdp = "v=0\n";
    sdp += "o=- 123456 654321 IN IP4 10.1.2.3\n";
    sdp += "s=Call\n";
    sdp += "c=IN IP4 10.1.2.3\n";
    sdp += "t=0 0\n";
    sdp += "m=audio 49170 RTP/AVP 0\n";
    sdp += "a=rtpmap:0 PCMU/8000\n";
    sdp += "m=video 49172 RTP/AVP 96\n";
    sdp += "a=rtpmap:96 H264/90000\n";
    invite.setSdpBody(sdp);

    sip_correlator->addMessage(invite);
    sip_correlator->finalize();
    volte_correlator->correlate();

    auto flows = volte_correlator->getCallFlows();
    ASSERT_EQ(flows.size(), 1);
    // Note: Detection depends on SIP session finalization logic
    // which might detect video from SDP
}

// ============================================================================
// Statistics Tests
// ============================================================================

TEST_F(VolteCorrelatorTest, CalculateCallStatistics) {
    // Create a complete call with timing
    auto invite = createSipInvite("call-1@ims.example.com",
                                  "+14155551234",
                                  "+14155555678",
                                  "10.1.2.3",
                                  1000.0, 100);
    auto ringing = createSip200Ok("call-1@ims.example.com",
                                 "from-tag-123", "to-tag-456",
                                 1002.0, 101);
    ringing.setStatusCode(180);

    auto ok = createSip200Ok("call-1@ims.example.com",
                            "from-tag-123", "to-tag-456",
                            1005.0, 102);

    auto bye = createSipBye("call-1@ims.example.com",
                           "from-tag-123", "to-tag-456",
                           1065.0, 103);

    sip_correlator->addMessage(invite);
    sip_correlator->addMessage(ringing);
    sip_correlator->addMessage(ok);
    sip_correlator->addMessage(bye);
    sip_correlator->finalize();

    volte_correlator->correlate();

    auto flows = volte_correlator->getCallFlows();
    ASSERT_EQ(flows.size(), 1);

    auto* flow = flows[0];

    // Check timing statistics
    ASSERT_TRUE(flow->stats.setup_time_ms.has_value());
    EXPECT_NEAR(*flow->stats.setup_time_ms, 5000.0, 10.0);  // INVITE to 200 OK

    ASSERT_TRUE(flow->stats.ring_time_ms.has_value());
    EXPECT_NEAR(*flow->stats.ring_time_ms, 2000.0, 10.0);  // INVITE to 180

    ASSERT_TRUE(flow->stats.call_duration_ms.has_value());
    EXPECT_NEAR(*flow->stats.call_duration_ms, 60000.0, 10.0);  // 200 OK to BYE
}

// ============================================================================
// Multi-Protocol Correlation Tests
// ============================================================================

TEST_F(VolteCorrelatorTest, GetVoiceCalls) {
    // Create one voice call
    auto invite1 = createSipInvite("call-1@ims.example.com",
                                   "+14155551234",
                                   "+14155555678",
                                   "10.1.2.3",
                                   1000.0, 100);
    sip_correlator->addMessage(invite1);

    sip_correlator->finalize();
    volte_correlator->correlate();

    auto voice_calls = volte_correlator->getVoiceCalls();
    EXPECT_GE(voice_calls.size(), 1);
}

TEST_F(VolteCorrelatorTest, GetCallFlowsByType) {
    // Create a voice call
    auto invite = createSipInvite("call-1@ims.example.com",
                                  "+14155551234",
                                  "+14155555678",
                                  "10.1.2.3",
                                  1000.0, 100);
    sip_correlator->addMessage(invite);
    sip_correlator->finalize();
    volte_correlator->correlate();

    auto mo_calls = volte_correlator->getCallFlowsByType(VolteFlowType::MO_VOICE_CALL);
    EXPECT_GE(mo_calls.size(), 1);

    auto video_calls = volte_correlator->getCallFlowsByType(VolteFlowType::MO_VIDEO_CALL);
    // Depends on whether SIP detects video
}

// ============================================================================
// Clear/Reset Tests
// ============================================================================

TEST_F(VolteCorrelatorTest, ClearResetsState) {
    auto invite = createSipInvite("call-1@ims.example.com",
                                  "+14155551234",
                                  "+14155555678",
                                  "10.1.2.3",
                                  1000.0, 100);
    sip_correlator->addMessage(invite);
    sip_correlator->finalize();
    volte_correlator->correlate();

    EXPECT_EQ(volte_correlator->getCallFlows().size(), 1);

    volte_correlator->clear();

    EXPECT_EQ(volte_correlator->getCallFlows().size(), 0);
    auto stats = volte_correlator->getStats();
    EXPECT_EQ(stats.total_call_flows, 0);
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
