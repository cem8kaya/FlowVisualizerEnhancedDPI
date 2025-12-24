#include <gtest/gtest.h>
#include "correlation/gtpv2/gtpv2_correlator.h"
#include "correlation/gtpv2/gtpv2_message.h"
#include "correlation/gtpv2/gtpv2_types.h"

using namespace callflow::correlation;

class Gtpv2CorrelatorTest : public ::testing::Test {
protected:
    void SetUp() override {
        correlator = std::make_unique<Gtpv2Correlator>();
    }

    void TearDown() override {
        correlator.reset();
    }

    Gtpv2Message createCreateSessionRequest(uint32_t teid, uint32_t seq, double timestamp) {
        Gtpv2Message msg;
        msg.setMessageType(GtpV2MessageType::CREATE_SESSION_REQUEST);
        msg.setTeid(teid);
        msg.setSequence(seq);
        msg.setTimestamp(timestamp);
        msg.setFrameNumber(1);
        msg.setSourceIp("10.0.0.1");
        msg.setDestIp("10.0.0.2");
        return msg;
    }

    Gtpv2Message createCreateSessionResponse(uint32_t teid, uint32_t seq, double timestamp) {
        Gtpv2Message msg;
        msg.setMessageType(GtpV2MessageType::CREATE_SESSION_RESPONSE);
        msg.setTeid(teid);
        msg.setSequence(seq);
        msg.setTimestamp(timestamp);
        msg.setFrameNumber(2);
        msg.setSourceIp("10.0.0.2");
        msg.setDestIp("10.0.0.1");

        // Add success cause
        gtp::GtpV2Cause cause;
        cause.cause_value = CauseValue::REQUEST_ACCEPTED;
        cause.pce = false;
        cause.bce = false;
        cause.cs = false;
        msg.setCause(cause);

        return msg;
    }

    std::unique_ptr<Gtpv2Correlator> correlator;
};

TEST_F(Gtpv2CorrelatorTest, CreateSession) {
    auto req = createCreateSessionRequest(0x12345678, 1, 100.0);
    auto resp = createCreateSessionResponse(0x12345678, 1, 100.1);

    correlator->addMessage(req);
    correlator->addMessage(resp);

    auto sessions = correlator->getSessions();
    ASSERT_EQ(sessions.size(), 1);

    auto* session = sessions[0];
    EXPECT_EQ(session->getControlTeid(), 0x12345678);
    EXPECT_EQ(session->getSequence(), 1);
    EXPECT_EQ(session->getMessageCount(), 2);
}

TEST_F(Gtpv2CorrelatorTest, SessionStateTransition) {
    auto req = createCreateSessionRequest(0x12345678, 1, 100.0);
    auto resp = createCreateSessionResponse(0x12345678, 1, 100.1);

    correlator->addMessage(req);
    auto* session = correlator->findByControlTeid(0x12345678);
    ASSERT_NE(session, nullptr);
    EXPECT_EQ(session->getState(), Gtpv2Session::State::CREATING);

    correlator->addMessage(resp);
    EXPECT_EQ(session->getState(), Gtpv2Session::State::ACTIVE);
}

TEST_F(Gtpv2CorrelatorTest, FindByControlTeid) {
    auto req = createCreateSessionRequest(0x12345678, 1, 100.0);
    correlator->addMessage(req);

    auto* session = correlator->findByControlTeid(0x12345678);
    ASSERT_NE(session, nullptr);
    EXPECT_EQ(session->getControlTeid(), 0x12345678);

    auto* not_found = correlator->findByControlTeid(0x99999999);
    EXPECT_EQ(not_found, nullptr);
}

TEST_F(Gtpv2CorrelatorTest, MultipleSessions) {
    auto req1 = createCreateSessionRequest(0x11111111, 1, 100.0);
    auto req2 = createCreateSessionRequest(0x22222222, 2, 100.1);
    auto req3 = createCreateSessionRequest(0x33333333, 3, 100.2);

    correlator->addMessage(req1);
    correlator->addMessage(req2);
    correlator->addMessage(req3);

    auto sessions = correlator->getSessions();
    EXPECT_EQ(sessions.size(), 3);

    auto stats = correlator->getStats();
    EXPECT_EQ(stats.total_messages, 3);
    EXPECT_EQ(stats.total_sessions, 3);
}

TEST_F(Gtpv2CorrelatorTest, Statistics) {
    auto req = createCreateSessionRequest(0x12345678, 1, 100.0);
    auto resp = createCreateSessionResponse(0x12345678, 1, 100.1);

    correlator->addMessage(req);
    correlator->addMessage(resp);

    auto stats = correlator->getStats();
    EXPECT_EQ(stats.total_messages, 2);
    EXPECT_EQ(stats.total_sessions, 1);
}

TEST_F(Gtpv2CorrelatorTest, FinalizeSession) {
    auto req = createCreateSessionRequest(0x12345678, 1, 100.0);
    auto resp = createCreateSessionResponse(0x12345678, 1, 100.1);

    correlator->addMessage(req);
    correlator->addMessage(resp);

    correlator->finalize();

    auto sessions = correlator->getSessions();
    ASSERT_EQ(sessions.size(), 1);
    EXPECT_TRUE(sessions[0]->isFinalized());
}

TEST_F(Gtpv2CorrelatorTest, ClearSessions) {
    auto req = createCreateSessionRequest(0x12345678, 1, 100.0);
    correlator->addMessage(req);

    EXPECT_EQ(correlator->getSessionCount(), 1);

    correlator->clear();

    EXPECT_EQ(correlator->getSessionCount(), 0);
    auto stats = correlator->getStats();
    EXPECT_EQ(stats.total_messages, 0);
    EXPECT_EQ(stats.total_sessions, 0);
}

TEST_F(Gtpv2CorrelatorTest, MessageTypes) {
    EXPECT_TRUE(isRequest(GtpV2MessageType::CREATE_SESSION_REQUEST));
    EXPECT_TRUE(isResponse(GtpV2MessageType::CREATE_SESSION_RESPONSE));
    EXPECT_FALSE(isRequest(GtpV2MessageType::CREATE_SESSION_RESPONSE));
    EXPECT_FALSE(isResponse(GtpV2MessageType::CREATE_SESSION_REQUEST));
}

TEST_F(Gtpv2CorrelatorTest, SessionEstablishmentDetection) {
    EXPECT_TRUE(isSessionEstablishment(GtpV2MessageType::CREATE_SESSION_REQUEST));
    EXPECT_TRUE(isSessionEstablishment(GtpV2MessageType::CREATE_SESSION_RESPONSE));
    EXPECT_FALSE(isSessionEstablishment(GtpV2MessageType::DELETE_SESSION_REQUEST));
}

TEST_F(Gtpv2CorrelatorTest, SessionTerminationDetection) {
    EXPECT_TRUE(isSessionTermination(GtpV2MessageType::DELETE_SESSION_REQUEST));
    EXPECT_TRUE(isSessionTermination(GtpV2MessageType::DELETE_SESSION_RESPONSE));
    EXPECT_FALSE(isSessionTermination(GtpV2MessageType::CREATE_SESSION_REQUEST));
}

TEST_F(Gtpv2CorrelatorTest, BearerMessageDetection) {
    EXPECT_TRUE(isBearerCreation(GtpV2MessageType::CREATE_BEARER_REQUEST));
    EXPECT_TRUE(isBearerCreation(GtpV2MessageType::CREATE_BEARER_RESPONSE));

    EXPECT_TRUE(isBearerModification(GtpV2MessageType::MODIFY_BEARER_REQUEST));
    EXPECT_TRUE(isBearerModification(GtpV2MessageType::UPDATE_BEARER_REQUEST));

    EXPECT_TRUE(isBearerDeletion(GtpV2MessageType::DELETE_BEARER_REQUEST));
}

TEST_F(Gtpv2CorrelatorTest, CauseSuccess) {
    EXPECT_TRUE(isSuccessCause(CauseValue::REQUEST_ACCEPTED));
    EXPECT_TRUE(isSuccessCause(CauseValue::REQUEST_ACCEPTED_PARTIALLY));
    EXPECT_FALSE(isSuccessCause(CauseValue::CONTEXT_NOT_FOUND));
    EXPECT_FALSE(isSuccessCause(CauseValue::SYSTEM_FAILURE));
}

TEST_F(Gtpv2CorrelatorTest, PdnClassification) {
    EXPECT_EQ(classifyPdnFromApn("ims"), PdnClass::IMS);
    EXPECT_EQ(classifyPdnFromApn("ims.mnc001.mcc001.gprs"), PdnClass::IMS);
    EXPECT_EQ(classifyPdnFromApn("internet"), PdnClass::INTERNET);
    EXPECT_EQ(classifyPdnFromApn("internet.mnc001.mcc001.gprs"), PdnClass::INTERNET);
    EXPECT_EQ(classifyPdnFromApn("emergency"), PdnClass::EMERGENCY);
    EXPECT_EQ(classifyPdnFromApn("sos"), PdnClass::EMERGENCY);
    EXPECT_EQ(classifyPdnFromApn("mms"), PdnClass::MMS);
    EXPECT_EQ(classifyPdnFromApn("unknown.apn"), PdnClass::OTHER);
}
