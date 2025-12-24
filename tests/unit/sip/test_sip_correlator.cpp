#include <gtest/gtest.h>
#include "correlation/sip/sip_correlator.h"
#include "correlation/sip/sip_message.h"

using namespace callflow::correlation;

class SipCorrelatorTest : public ::testing::Test {
protected:
    void SetUp() override {
        correlator = std::make_unique<SipCorrelator>();
    }

    std::unique_ptr<SipCorrelator> correlator;

    SipMessage createInvite(const std::string& call_id,
                           const std::string& from_uri,
                           const std::string& to_uri,
                           double timestamp,
                           uint32_t frame) {
        SipMessage msg;
        msg.setRequest(true);
        msg.setMethod("INVITE");
        msg.setCallId(call_id);
        msg.setFromUri(from_uri);
        msg.setFromTag("from-tag-123");
        msg.setToUri(to_uri);
        msg.setCSeq(1);
        msg.setCSeqMethod("INVITE");
        msg.setTimestamp(timestamp);
        msg.setFrameNumber(frame);

        // Add Via header
        SipViaHeader via;
        via.protocol = "SIP/2.0/UDP";
        via.sent_by = "192.168.1.100:5060";
        via.branch = "z9hG4bK-test-branch";
        via.index = 0;
        msg.addViaHeader(via);

        // Add audio SDP
        std::string sdp = R"(v=0
o=- 123456 654321 IN IP4 192.168.1.100
s=Call
c=IN IP4 192.168.1.100
t=0 0
m=audio 49170 RTP/AVP 0
a=rtpmap:0 PCMU/8000
a=sendrecv
)";
        msg.setSdpBody(sdp);

        return msg;
    }

    SipMessage createResponse(const std::string& call_id,
                             int status_code,
                             const std::string& from_tag,
                             const std::string& to_tag,
                             const std::string& cseq_method,
                             double timestamp,
                             uint32_t frame) {
        SipMessage msg;
        msg.setRequest(false);
        msg.setStatusCode(status_code);
        msg.setCallId(call_id);
        msg.setFromTag(from_tag);
        msg.setToTag(to_tag);
        msg.setCSeq(1);
        msg.setCSeqMethod(cseq_method);
        msg.setTimestamp(timestamp);
        msg.setFrameNumber(frame);

        return msg;
    }
};

TEST_F(SipCorrelatorTest, AddSingleMessage) {
    auto invite = createInvite("call-1@example.com",
                               "sip:+14155551234@ims.example.com",
                               "sip:+14155555678@ims.example.com",
                               1000.0, 100);

    correlator->addMessage(invite);

    auto session = correlator->findByCallId("call-1@example.com");
    ASSERT_NE(session, nullptr);
    EXPECT_EQ(session->getCallId(), "call-1@example.com");
    EXPECT_EQ(session->getMessageCount(), 1);
}

TEST_F(SipCorrelatorTest, GroupMessagesByCallId) {
    // Call 1
    auto invite1 = createInvite("call-1@example.com",
                                "sip:+14155551234@ims.example.com",
                                "sip:+14155555678@ims.example.com",
                                1000.0, 100);
    auto ok1 = createResponse("call-1@example.com", 200,
                              "from-tag-123", "to-tag-456",
                              "INVITE", 1001.0, 101);

    // Call 2
    auto invite2 = createInvite("call-2@example.com",
                                "sip:+14155559999@ims.example.com",
                                "sip:+14155558888@ims.example.com",
                                1002.0, 102);

    correlator->addMessage(invite1);
    correlator->addMessage(ok1);
    correlator->addMessage(invite2);

    auto sessions = correlator->getSessions();
    EXPECT_EQ(sessions.size(), 2);

    auto session1 = correlator->findByCallId("call-1@example.com");
    ASSERT_NE(session1, nullptr);
    EXPECT_EQ(session1->getMessageCount(), 2);

    auto session2 = correlator->findByCallId("call-2@example.com");
    ASSERT_NE(session2, nullptr);
    EXPECT_EQ(session2->getMessageCount(), 1);
}

TEST_F(SipCorrelatorTest, DetectVoiceCall) {
    auto invite = createInvite("call-1@example.com",
                               "sip:+14155551234@ims.example.com",
                               "sip:+14155555678@ims.example.com",
                               1000.0, 100);

    auto ok = createResponse("call-1@example.com", 200,
                            "from-tag-123", "to-tag-456",
                            "INVITE", 1001.0, 101);

    correlator->addMessage(invite);
    correlator->addMessage(ok);
    correlator->finalize();

    auto sessions = correlator->getCallSessions();
    ASSERT_EQ(sessions.size(), 1);
    EXPECT_EQ(sessions[0]->getType(), SipSessionType::VOICE_CALL);
}

TEST_F(SipCorrelatorTest, ExtractCallerCallee) {
    auto invite = createInvite("call-1@example.com",
                               "sip:+14155551234@ims.example.com",
                               "sip:+14155555678@ims.example.com",
                               1000.0, 100);

    correlator->addMessage(invite);
    correlator->finalize();

    auto session = correlator->findByCallId("call-1@example.com");
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->getCallerMsisdn(), "14155551234");
    EXPECT_EQ(session->getCalleeMsisdn(), "14155555678");
}

TEST_F(SipCorrelatorTest, FindByMsisdn) {
    auto invite1 = createInvite("call-1@example.com",
                                "sip:+14155551234@ims.example.com",
                                "sip:+14155555678@ims.example.com",
                                1000.0, 100);

    auto invite2 = createInvite("call-2@example.com",
                                "sip:+14155551234@ims.example.com",
                                "sip:+14155559999@ims.example.com",
                                1002.0, 102);

    correlator->addMessage(invite1);
    correlator->addMessage(invite2);
    correlator->finalize();

    // Find by caller MSISDN
    auto sessions = correlator->findByMsisdn("14155551234");
    EXPECT_EQ(sessions.size(), 2);

    // Find by callee MSISDN
    sessions = correlator->findByMsisdn("14155555678");
    EXPECT_EQ(sessions.size(), 1);
}

TEST_F(SipCorrelatorTest, FindByFrame) {
    auto invite = createInvite("call-1@example.com",
                               "sip:+14155551234@ims.example.com",
                               "sip:+14155555678@ims.example.com",
                               1000.0, 100);

    auto ok = createResponse("call-1@example.com", 200,
                            "from-tag-123", "to-tag-456",
                            "INVITE", 1001.0, 105);

    correlator->addMessage(invite);
    correlator->addMessage(ok);

    auto session = correlator->findByFrame(103);
    ASSERT_NE(session, nullptr);
    EXPECT_EQ(session->getCallId(), "call-1@example.com");

    // Frame outside range
    session = correlator->findByFrame(200);
    EXPECT_EQ(session, nullptr);
}

TEST_F(SipCorrelatorTest, GetStatistics) {
    // Voice call
    auto invite1 = createInvite("call-1@example.com",
                                "sip:+14155551234@ims.example.com",
                                "sip:+14155555678@ims.example.com",
                                1000.0, 100);

    // Registration
    SipMessage reg;
    reg.setRequest(true);
    reg.setMethod("REGISTER");
    reg.setCallId("reg-1@example.com");
    reg.setFromUri("sip:+14155551234@ims.example.com");
    reg.setTimestamp(1010.0);
    reg.setFrameNumber(110);

    // SMS
    SipMessage sms;
    sms.setRequest(true);
    sms.setMethod("MESSAGE");
    sms.setCallId("msg-1@example.com");
    sms.setFromUri("sip:+14155551234@ims.example.com");
    sms.setTimestamp(1020.0);
    sms.setFrameNumber(120);

    correlator->addMessage(invite1);
    correlator->addMessage(reg);
    correlator->addMessage(sms);
    correlator->finalize();

    auto stats = correlator->getStats();
    EXPECT_EQ(stats.total_sessions, 3);
    EXPECT_EQ(stats.total_messages, 3);
    EXPECT_EQ(stats.voice_call_sessions, 1);
    EXPECT_EQ(stats.registration_sessions, 1);
    EXPECT_EQ(stats.sms_sessions, 1);
}

TEST_F(SipCorrelatorTest, GetCallSessionsOnly) {
    // Voice call
    auto invite = createInvite("call-1@example.com",
                               "sip:+14155551234@ims.example.com",
                               "sip:+14155555678@ims.example.com",
                               1000.0, 100);

    // Registration
    SipMessage reg;
    reg.setRequest(true);
    reg.setMethod("REGISTER");
    reg.setCallId("reg-1@example.com");
    reg.setFromUri("sip:+14155551234@ims.example.com");
    reg.setTimestamp(1010.0);
    reg.setFrameNumber(110);

    correlator->addMessage(invite);
    correlator->addMessage(reg);
    correlator->finalize();

    auto call_sessions = correlator->getCallSessions();
    EXPECT_EQ(call_sessions.size(), 1);
    EXPECT_EQ(call_sessions[0]->getType(), SipSessionType::VOICE_CALL);
}

TEST_F(SipCorrelatorTest, ClearSessions) {
    auto invite = createInvite("call-1@example.com",
                               "sip:+14155551234@ims.example.com",
                               "sip:+14155555678@ims.example.com",
                               1000.0, 100);

    correlator->addMessage(invite);
    EXPECT_EQ(correlator->getSessions().size(), 1);

    correlator->clear();
    EXPECT_EQ(correlator->getSessions().size(), 0);

    auto stats = correlator->getStats();
    EXPECT_EQ(stats.total_sessions, 0);
    EXPECT_EQ(stats.total_messages, 0);
}
