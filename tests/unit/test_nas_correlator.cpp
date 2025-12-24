#include <gtest/gtest.h>
#include "correlation/nas/nas_correlator.h"
#include "correlation/nas/nas_message.h"
#include "correlation/nas/nas_ie_parser.h"
#include "correlation/identity/subscriber_context_manager.h"
#include <vector>
#include <cstring>

using namespace callflow::correlation;

/**
 * Test fixture for NAS correlator tests
 */
class NasCorrelatorTest : public ::testing::Test {
protected:
    void SetUp() override {
        ctx_manager = std::make_unique<SubscriberContextManager>();
        correlator = std::make_unique<NasCorrelator>(ctx_manager.get());
    }

    void TearDown() override {
        correlator.reset();
        ctx_manager.reset();
    }

    /**
     * Create a simple NAS Attach Request message
     */
    NasMessage createAttachRequest(uint32_t frame_num, double timestamp) {
        // Simplified message creation for testing
        std::vector<uint8_t> data = {
            0x07,  // Plain NAS, EMM
            0x41   // Attach Request
        };

        auto msg = NasMessage::parse(data.data(), data.size(), frame_num, timestamp);
        EXPECT_TRUE(msg.has_value());

        // Manually set some fields for testing
        if (msg) {
            msg->setImsi("001010123456789");
            msg->setAttachType(EpsAttachType::EPS_ATTACH);
        }

        return *msg;
    }

    /**
     * Create a PDN Connectivity Request (ESM)
     */
    NasMessage createPdnConnectivityRequest(uint32_t frame_num, double timestamp) {
        std::vector<uint8_t> data = {
            0x02,  // Plain NAS, ESM
            0x05,  // EPS Bearer Identity (5)
            0x01,  // PTI
            0xD0   // PDN Connectivity Request
        };

        auto msg = NasMessage::parse(data.data(), data.size(), frame_num, timestamp);
        EXPECT_TRUE(msg.has_value());

        if (msg) {
            msg->setApn("internet");
            msg->setPdnType(NasPdnType::IPV4);
        }

        return *msg;
    }

    std::unique_ptr<SubscriberContextManager> ctx_manager;
    std::unique_ptr<NasCorrelator> correlator;
};

TEST_F(NasCorrelatorTest, AddEmmMessage) {
    auto msg = createAttachRequest(1, 1.0);

    correlator->addMessage(msg, 100, 200);

    auto sessions = correlator->getSessions();
    EXPECT_EQ(sessions.size(), 1);

    auto* session = sessions[0];
    EXPECT_EQ(session->getType(), NasSessionType::EMM);
    EXPECT_EQ(session->getMessageCount(), 1);
}

TEST_F(NasCorrelatorTest, AddEsmMessage) {
    auto msg = createPdnConnectivityRequest(1, 1.0);

    correlator->addMessage(msg, 100, 200);

    auto sessions = correlator->getSessions();
    EXPECT_EQ(sessions.size(), 1);

    auto* session = sessions[0];
    EXPECT_EQ(session->getType(), NasSessionType::ESM);
    EXPECT_EQ(session->getMessageCount(), 1);
}

TEST_F(NasCorrelatorTest, CorrelateByS1apContext) {
    auto msg1 = createAttachRequest(1, 1.0);
    auto msg2 = createAttachRequest(2, 2.0);

    // Same S1AP context
    correlator->addMessage(msg1, 100, 200);
    correlator->addMessage(msg2, 100, 200);

    auto sessions = correlator->getSessions();
    EXPECT_EQ(sessions.size(), 1);  // Same session

    auto* session = sessions[0];
    EXPECT_EQ(session->getMessageCount(), 2);
}

TEST_F(NasCorrelatorTest, CorrelateByImsi) {
    auto msg1 = createAttachRequest(1, 1.0);
    auto msg2 = createAttachRequest(2, 2.0);

    // Both have same IMSI
    msg1.setImsi("001010123456789");
    msg2.setImsi("001010123456789");

    correlator->addMessage(msg1, std::nullopt, std::nullopt);
    correlator->addMessage(msg2, std::nullopt, std::nullopt);

    auto sessions = correlator->getSessions();
    EXPECT_EQ(sessions.size(), 1);  // Same session

    auto* session = sessions[0];
    EXPECT_EQ(session->getMessageCount(), 2);
    EXPECT_EQ(session->getImsi(), "001010123456789");
}

TEST_F(NasCorrelatorTest, FindByImsi) {
    auto msg = createAttachRequest(1, 1.0);
    msg.setImsi("001010123456789");

    correlator->addMessage(msg, 100, 200);

    auto sessions = correlator->findByImsi("001010123456789");
    EXPECT_EQ(sessions.size(), 1);

    auto* session = sessions[0];
    EXPECT_EQ(session->getImsi(), "001010123456789");
}

TEST_F(NasCorrelatorTest, FindByS1apContext) {
    auto msg = createAttachRequest(1, 1.0);

    correlator->addMessage(msg, 100, 200);

    auto* session = correlator->findByS1apContext(100, 200);
    EXPECT_NE(session, nullptr);
    EXPECT_EQ(session->getMmeUeS1apId(), 100);
    EXPECT_EQ(session->getEnbUeS1apId(), 200);
}

TEST_F(NasCorrelatorTest, GetStatistics) {
    auto msg1 = createAttachRequest(1, 1.0);
    auto msg2 = createPdnConnectivityRequest(2, 2.0);

    correlator->addMessage(msg1, 100, 200);
    correlator->addMessage(msg2, 100, 200);

    correlator->finalize();

    auto stats = correlator->getStats();
    EXPECT_EQ(stats.total_messages, 2);
    EXPECT_GE(stats.total_sessions, 1);
    EXPECT_EQ(stats.attach_procedures, 1);
}

TEST_F(NasCorrelatorTest, GetEmmSessions) {
    auto msg1 = createAttachRequest(1, 1.0);
    auto msg2 = createPdnConnectivityRequest(2, 2.0);

    correlator->addMessage(msg1, 100, 200);
    correlator->addMessage(msg2, 101, 201);

    correlator->finalize();

    auto emm_sessions = correlator->getEmmSessions();
    EXPECT_GE(emm_sessions.size(), 1);

    for (auto* session : emm_sessions) {
        EXPECT_EQ(session->getType(), NasSessionType::EMM);
    }
}

TEST_F(NasCorrelatorTest, GetEsmSessions) {
    auto msg = createPdnConnectivityRequest(1, 1.0);

    correlator->addMessage(msg, 100, 200);
    correlator->finalize();

    auto esm_sessions = correlator->getEsmSessions();
    EXPECT_GE(esm_sessions.size(), 1);

    for (auto* session : esm_sessions) {
        EXPECT_EQ(session->getType(), NasSessionType::ESM);
    }
}

TEST_F(NasCorrelatorTest, ImsDetection) {
    auto msg = createPdnConnectivityRequest(1, 1.0);
    msg.setApn("ims");  // IMS APN

    correlator->addMessage(msg, 100, 200);
    correlator->finalize();

    auto ims_sessions = correlator->getImsEsmSessions();
    EXPECT_GE(ims_sessions.size(), 1);

    for (auto* session : ims_sessions) {
        EXPECT_TRUE(session->isIms());
    }
}

// Test NAS IE Parser
TEST(NasIEParserTest, DecodeTbcdDigits) {
    uint8_t data[] = {0x12, 0x34, 0xF5};
    std::string result = NasIEParser::decodeTbcdDigits(data, 3, true);
    EXPECT_EQ(result, "214355");
}

TEST(NasIEParserTest, DecodePlmn) {
    uint8_t data[] = {0x10, 0x20, 0x30};  // MCC=001, MNC=023
    std::string mcc, mnc;

    bool success = NasIEParser::decodePlmn(data, mcc, mnc);
    EXPECT_TRUE(success);
    EXPECT_EQ(mcc, "001");
    EXPECT_EQ(mnc, "23");
}

TEST(NasIEParserTest, ParseApn) {
    // APN "internet" encoded as length + label
    uint8_t data[] = {0x08, 'i', 'n', 't', 'e', 'r', 'n', 'e', 't'};

    auto apn = NasIEParser::parseApn(data, sizeof(data));
    EXPECT_TRUE(apn.has_value());
    EXPECT_EQ(*apn, "internet");
}

TEST(NasIEParserTest, ParseApnMultiLabel) {
    // APN "mnc001.mcc001.gprs" encoded as length + label for each part
    uint8_t data[] = {
        0x06, 'm', 'n', 'c', '0', '0', '1',
        0x06, 'm', 'c', 'c', '0', '0', '1',
        0x04, 'g', 'p', 'r', 's'
    };

    auto apn = NasIEParser::parseApn(data, sizeof(data));
    EXPECT_TRUE(apn.has_value());
    EXPECT_EQ(*apn, "mnc001.mcc001.gprs");
}

TEST(NasMessageTest, ParseAttachRequest) {
    std::vector<uint8_t> data = {
        0x07,  // Plain NAS, EMM
        0x41   // Attach Request
    };

    auto msg = NasMessage::parse(data.data(), data.size(), 1, 1.0);
    EXPECT_TRUE(msg.has_value());

    if (msg) {
        EXPECT_TRUE(msg->isEmm());
        EXPECT_FALSE(msg->isEsm());
        EXPECT_EQ(msg->getEmmMessageType(), NasEmmMessageType::ATTACH_REQUEST);
        EXPECT_EQ(msg->getDirection(), NasMessage::Direction::UPLINK);
    }
}

TEST(NasMessageTest, ParsePdnConnectivityRequest) {
    std::vector<uint8_t> data = {
        0x02,  // Plain NAS, ESM
        0x05,  // EPS Bearer Identity
        0x01,  // PTI
        0xD0   // PDN Connectivity Request
    };

    auto msg = NasMessage::parse(data.data(), data.size(), 1, 1.0);
    EXPECT_TRUE(msg.has_value());

    if (msg) {
        EXPECT_TRUE(msg->isEsm());
        EXPECT_FALSE(msg->isEmm());
        EXPECT_EQ(msg->getEsmMessageType(), NasEsmMessageType::PDN_CONNECTIVITY_REQUEST);
        EXPECT_EQ(msg->getDirection(), NasMessage::Direction::UPLINK);
        EXPECT_EQ(msg->getPti(), 1);
    }
}

TEST(NasSessionTest, AddMessages) {
    NasSession session;

    auto msg1 = NasMessage();
    msg1.setEmmMessageType(NasEmmMessageType::ATTACH_REQUEST);

    auto msg2 = NasMessage();
    msg2.setEmmMessageType(NasEmmMessageType::ATTACH_ACCEPT);

    session.addMessage(msg1);
    session.addMessage(msg2);

    EXPECT_EQ(session.getMessageCount(), 2);
}

TEST(NasSessionTest, ExtractImsi) {
    NasSession session;

    auto msg = NasMessage();
    msg.setImsi("001010123456789");
    msg.setEmmMessageType(NasEmmMessageType::ATTACH_REQUEST);

    session.addMessage(msg);

    EXPECT_EQ(session.getImsi(), "001010123456789");
}

TEST(NasSessionTest, ExtractApn) {
    NasSession session;

    auto msg = NasMessage();
    msg.setApn("internet");
    msg.setEsmMessageType(NasEsmMessageType::PDN_CONNECTIVITY_REQUEST);

    session.addMessage(msg);

    EXPECT_EQ(session.getApn(), "internet");
}
