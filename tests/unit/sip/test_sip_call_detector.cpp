#include <gtest/gtest.h>
#include "correlation/sip/sip_call_detector.h"
#include "correlation/sip/sip_message.h"

using namespace callflow::correlation;

class SipCallDetectorTest : public ::testing::Test {
protected:
    void SetUp() override {}
};

TEST_F(SipCallDetectorTest, ExtractMsisdnFromSipUri) {
    EXPECT_EQ(SipCallDetector::extractMsisdn("sip:+14155551234@ims.example.com"),
              "14155551234");
    EXPECT_EQ(SipCallDetector::extractMsisdn("sip:14155551234@example.com"),
              "14155551234");
    EXPECT_EQ(SipCallDetector::extractMsisdn("<sip:+1-415-555-1234@example.com>"),
              "14155551234");
}

TEST_F(SipCallDetectorTest, ExtractMsisdnWithDisplayName) {
    EXPECT_EQ(SipCallDetector::extractMsisdn("\"John Doe\" <sip:+14155551234@example.com>"),
              "14155551234");
    EXPECT_EQ(SipCallDetector::extractMsisdn("Alice <sip:14155555678@ims.example.com>"),
              "14155555678");
}

TEST_F(SipCallDetectorTest, ExtractUserFromUri) {
    EXPECT_EQ(SipCallDetector::extractUser("sip:user@host"), "user");
    EXPECT_EQ(SipCallDetector::extractUser("sip:+14155551234@host:5060"),
              "+14155551234");
    EXPECT_EQ(SipCallDetector::extractUser("<sip:alice@example.com>"), "alice");
}

TEST_F(SipCallDetectorTest, ExtractHostFromUri) {
    EXPECT_EQ(SipCallDetector::extractHost("sip:user@host"), "host");
    EXPECT_EQ(SipCallDetector::extractHost("sip:user@example.com:5060"),
              "example.com");
    EXPECT_EQ(SipCallDetector::extractHost("<sip:user@192.168.1.1>"),
              "192.168.1.1");
}

TEST_F(SipCallDetectorTest, DetectEmergencyUrn) {
    EXPECT_TRUE(SipCallDetector::isEmergencyUrn("urn:service:sos"));
    EXPECT_TRUE(SipCallDetector::isEmergencyUrn("urn:service:sos.police"));
    EXPECT_TRUE(SipCallDetector::isEmergencyUrn("urn:service:sos.fire"));
    EXPECT_FALSE(SipCallDetector::isEmergencyUrn("sip:911@ims.example.com"));
}

TEST_F(SipCallDetectorTest, DetectVoiceCall) {
    std::vector<SipMessage> messages;

    // INVITE
    SipMessage invite;
    invite.setRequest(true);
    invite.setMethod("INVITE");
    invite.setCallId("test-call-1@example.com");
    invite.setFromUri("sip:+14155551234@ims.example.com");
    invite.setToUri("sip:+14155555678@ims.example.com");

    // Add audio-only SDP
    std::string sdp = R"(v=0
o=- 123456 654321 IN IP4 192.168.1.100
s=Voice Call
c=IN IP4 192.168.1.100
t=0 0
m=audio 49170 RTP/AVP 0 8
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
)";
    invite.setSdpBody(sdp);

    messages.push_back(invite);

    // 200 OK
    SipMessage ok;
    ok.setRequest(false);
    ok.setStatusCode(200);
    ok.setCallId("test-call-1@example.com");
    ok.setCSeqMethod("INVITE");
    messages.push_back(ok);

    EXPECT_TRUE(SipCallDetector::isVoiceCall(messages));
    EXPECT_FALSE(SipCallDetector::isVideoCall(messages));
}

TEST_F(SipCallDetectorTest, DetectVideoCall) {
    std::vector<SipMessage> messages;

    // INVITE with video
    SipMessage invite;
    invite.setRequest(true);
    invite.setMethod("INVITE");
    invite.setCallId("test-video-1@example.com");
    invite.setFromUri("sip:+14155551234@ims.example.com");
    invite.setToUri("sip:+14155555678@ims.example.com");

    // Add audio+video SDP
    std::string sdp = R"(v=0
o=- 123456 654321 IN IP4 192.168.1.100
s=Video Call
c=IN IP4 192.168.1.100
t=0 0
m=audio 49170 RTP/AVP 0 8
a=rtpmap:0 PCMU/8000
a=sendrecv
m=video 51372 RTP/AVP 96
a=rtpmap:96 H264/90000
a=sendrecv
)";
    invite.setSdpBody(sdp);

    messages.push_back(invite);

    EXPECT_TRUE(SipCallDetector::isVideoCall(messages));
    EXPECT_FALSE(SipCallDetector::isVoiceCall(messages));
}

TEST_F(SipCallDetectorTest, DetectRegistration) {
    std::vector<SipMessage> messages;

    SipMessage reg;
    reg.setRequest(true);
    reg.setMethod("REGISTER");
    reg.setCallId("reg-1@example.com");
    reg.setFromUri("sip:+14155551234@ims.example.com");
    reg.setToUri("sip:+14155551234@ims.example.com");

    messages.push_back(reg);

    EXPECT_EQ(SipCallDetector::detectSessionType(messages),
              SipSessionType::REGISTRATION);
}

TEST_F(SipCallDetectorTest, DetectDeregistration) {
    std::vector<SipMessage> messages;

    SipMessage dereg;
    dereg.setRequest(true);
    dereg.setMethod("REGISTER");
    dereg.setCallId("dereg-1@example.com");
    dereg.setHeader("Expires", "0");

    messages.push_back(dereg);

    EXPECT_EQ(SipCallDetector::detectSessionType(messages),
              SipSessionType::DEREGISTRATION);
}

TEST_F(SipCallDetectorTest, DetectSmsMessage) {
    std::vector<SipMessage> messages;

    SipMessage msg;
    msg.setRequest(true);
    msg.setMethod("MESSAGE");
    msg.setCallId("msg-1@example.com");

    messages.push_back(msg);

    EXPECT_EQ(SipCallDetector::detectSessionType(messages),
              SipSessionType::SMS_MESSAGE);
}

TEST_F(SipCallDetectorTest, ExtractCallParties) {
    std::vector<SipMessage> messages;

    SipMessage invite;
    invite.setRequest(true);
    invite.setMethod("INVITE");
    invite.setCallId("test-call-1@example.com");
    invite.setFromUri("sip:+14155551234@ims.example.com");
    invite.setToUri("sip:+14155555678@ims.example.com");
    invite.setPAssertedIdentity("sip:+14155551234@ims.example.com");

    messages.push_back(invite);

    auto party_info = SipCallDetector::extractCallParties(messages);

    EXPECT_EQ(party_info.caller_msisdn, "14155551234");
    EXPECT_EQ(party_info.callee_msisdn, "14155555678");
}

TEST_F(SipCallDetectorTest, ExtractMediaInfo) {
    std::vector<SipMessage> messages;

    SipMessage invite;
    invite.setRequest(true);
    invite.setMethod("INVITE");

    std::string sdp = R"(v=0
o=- 123456 654321 IN IP4 192.168.1.100
s=Call
c=IN IP4 192.168.1.100
t=0 0
m=audio 49170 RTP/AVP 0 8
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=sendrecv
)";
    invite.setSdpBody(sdp);

    messages.push_back(invite);

    auto media = SipCallDetector::extractMediaInfo(messages);

    ASSERT_EQ(media.size(), 1);
    EXPECT_EQ(media[0].media_type, "audio");
    EXPECT_EQ(media[0].port, 49170);
    EXPECT_EQ(media[0].connection_ip, "192.168.1.100");
    EXPECT_EQ(media[0].direction, "sendrecv");
    ASSERT_GE(media[0].codecs.size(), 2);
}
