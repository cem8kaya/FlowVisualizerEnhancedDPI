#include <gtest/gtest.h>
#include "correlation/diameter/diameter_correlator.h"
#include "correlation/diameter/diameter_message.h"
#include "protocol_parsers/diameter/diameter_base.h"
#include <memory>

using namespace callflow::correlation;
using namespace callflow::diameter;

// ============================================================================
// Test Fixtures
// ============================================================================

class DiameterCorrelatorTest : public ::testing::Test {
protected:
    void SetUp() override {
        correlator_ = std::make_unique<DiameterCorrelator>();
    }

    void TearDown() override {
        correlator_.reset();
    }

    // Helper to create a basic Diameter message
    std::shared_ptr<DiameterMessage> createDiameterMessage(
        bool is_request,
        uint32_t command_code,
        uint32_t application_id,
        uint32_t hop_by_hop_id,
        const std::string& session_id) {

        auto msg = std::make_shared<DiameterMessage>();
        msg->header.request = is_request;
        msg->header.command_code = command_code;
        msg->header.application_id = application_id;
        msg->header.hop_by_hop_id = hop_by_hop_id;
        msg->header.end_to_end_id = 12345;
        msg->session_id = session_id;

        // Add Session-ID AVP
        auto session_avp = std::make_shared<DiameterAVP>();
        session_avp->code = static_cast<uint32_t>(DiameterAVPCode::SESSION_ID);
        session_avp->data.assign(session_id.begin(), session_id.end());
        session_avp->decoded_value = session_id;
        msg->avps.push_back(session_avp);

        return msg;
    }

    // Helper to create a correlation message
    DiameterMessage createCorrelationMessage(
        std::shared_ptr<DiameterMessage> proto_msg,
        uint32_t frame_number,
        double timestamp) {

        DiameterMessage corr_msg(proto_msg);
        corr_msg.setFrameNumber(frame_number);
        corr_msg.setTimestamp(timestamp);
        corr_msg.setSourceIp("192.168.1.100");
        corr_msg.setDestIp("192.168.1.200");
        corr_msg.setSourcePort(3868);
        corr_msg.setDestPort(3868);

        return corr_msg;
    }

    std::unique_ptr<DiameterCorrelator> correlator_;
};

// ============================================================================
// Basic Functionality Tests
// ============================================================================

TEST_F(DiameterCorrelatorTest, CreateEmptyCorrelator) {
    EXPECT_EQ(correlator_->getSessionCount(), 0);

    auto stats = correlator_->getStats();
    EXPECT_EQ(stats.total_messages, 0);
    EXPECT_EQ(stats.total_sessions, 0);
}

TEST_F(DiameterCorrelatorTest, AddSingleMessage) {
    auto proto_msg = createDiameterMessage(
        true,  // request
        static_cast<uint32_t>(DiameterCommandCode::CREDIT_CONTROL),
        static_cast<uint32_t>(DiameterApplicationID::TGPP_GX),
        100,
        "gx-session-1");

    auto msg = createCorrelationMessage(proto_msg, 1, 1.0);

    correlator_->addMessage(msg);

    EXPECT_EQ(correlator_->getSessionCount(), 1);

    auto stats = correlator_->getStats();
    EXPECT_EQ(stats.total_messages, 1);
    EXPECT_EQ(stats.total_sessions, 1);
    EXPECT_EQ(stats.request_count, 1);
    EXPECT_EQ(stats.answer_count, 0);
}

TEST_F(DiameterCorrelatorTest, AddRequestAnswerPair) {
    // Create request
    auto proto_req = createDiameterMessage(
        true,  // request
        static_cast<uint32_t>(DiameterCommandCode::CREDIT_CONTROL),
        static_cast<uint32_t>(DiameterApplicationID::TGPP_GX),
        100,
        "gx-session-1");

    auto req = createCorrelationMessage(proto_req, 1, 1.0);
    correlator_->addMessage(req);

    // Create answer
    auto proto_ans = createDiameterMessage(
        false,  // answer
        static_cast<uint32_t>(DiameterCommandCode::CREDIT_CONTROL),
        static_cast<uint32_t>(DiameterApplicationID::TGPP_GX),
        100,  // same hop-by-hop
        "gx-session-1");

    // Add Result-Code AVP
    auto result_avp = std::make_shared<DiameterAVP>();
    result_avp->code = static_cast<uint32_t>(DiameterAVPCode::RESULT_CODE);
    result_avp->decoded_value = uint32_t(2001);  // DIAMETER_SUCCESS
    proto_ans->result_code = 2001;
    proto_ans->avps.push_back(result_avp);

    auto ans = createCorrelationMessage(proto_ans, 2, 1.1);
    correlator_->addMessage(ans);

    EXPECT_EQ(correlator_->getSessionCount(), 1);

    auto stats = correlator_->getStats();
    EXPECT_EQ(stats.total_messages, 2);
    EXPECT_EQ(stats.request_count, 1);
    EXPECT_EQ(stats.answer_count, 1);

    // Find session and verify pairing
    auto session = correlator_->findBySessionId("gx-session-1");
    ASSERT_NE(session, nullptr);
    EXPECT_EQ(session->getMessageCount(), 2);
}

// ============================================================================
// Session Tracking Tests
// ============================================================================

TEST_F(DiameterCorrelatorTest, MultipleSessionsTracking) {
    // Create messages for 3 different sessions
    for (int i = 1; i <= 3; i++) {
        std::string session_id = "session-" + std::to_string(i);

        auto proto_msg = createDiameterMessage(
            true,
            static_cast<uint32_t>(DiameterCommandCode::CREDIT_CONTROL),
            static_cast<uint32_t>(DiameterApplicationID::TGPP_GX),
            100 + i,
            session_id);

        auto msg = createCorrelationMessage(proto_msg, i, 1.0 * i);
        correlator_->addMessage(msg);
    }

    EXPECT_EQ(correlator_->getSessionCount(), 3);

    auto sessions = correlator_->getSessions();
    EXPECT_EQ(sessions.size(), 3);
}

TEST_F(DiameterCorrelatorTest, SessionLookupBySessionId) {
    auto proto_msg = createDiameterMessage(
        true,
        static_cast<uint32_t>(DiameterCommandCode::UPDATE_LOCATION),
        static_cast<uint32_t>(DiameterApplicationID::TGPP_S6A_S6D),
        200,
        "s6a-session-1");

    auto msg = createCorrelationMessage(proto_msg, 10, 5.0);
    correlator_->addMessage(msg);

    auto session = correlator_->findBySessionId("s6a-session-1");
    ASSERT_NE(session, nullptr);
    EXPECT_EQ(session->getSessionId(), "s6a-session-1");
    EXPECT_EQ(session->getInterface(), DiameterInterface::S6A);
}

TEST_F(DiameterCorrelatorTest, SessionLookupByHopByHop) {
    auto proto_msg = createDiameterMessage(
        true,
        static_cast<uint32_t>(DiameterCommandCode::CREDIT_CONTROL),
        static_cast<uint32_t>(DiameterApplicationID::TGPP_GX),
        12345,
        "gx-session-hop");

    auto msg = createCorrelationMessage(proto_msg, 1, 1.0);
    correlator_->addMessage(msg);

    auto session = correlator_->findByHopByHopId(12345);
    ASSERT_NE(session, nullptr);
    EXPECT_EQ(session->getSessionId(), "gx-session-hop");
}

// ============================================================================
// Interface Detection Tests
// ============================================================================

TEST_F(DiameterCorrelatorTest, InterfaceDetection_Gx) {
    auto proto_msg = createDiameterMessage(
        true,
        static_cast<uint32_t>(DiameterCommandCode::CREDIT_CONTROL),
        static_cast<uint32_t>(DiameterApplicationID::TGPP_GX),
        100,
        "gx-session");

    auto msg = createCorrelationMessage(proto_msg, 1, 1.0);
    correlator_->addMessage(msg);

    auto gx_sessions = correlator_->getGxSessions();
    EXPECT_EQ(gx_sessions.size(), 1);
    EXPECT_EQ(gx_sessions[0]->getInterface(), DiameterInterface::GX);
}

TEST_F(DiameterCorrelatorTest, InterfaceDetection_S6a) {
    auto proto_msg = createDiameterMessage(
        true,
        static_cast<uint32_t>(DiameterCommandCode::UPDATE_LOCATION),
        static_cast<uint32_t>(DiameterApplicationID::TGPP_S6A_S6D),
        100,
        "s6a-session");

    auto msg = createCorrelationMessage(proto_msg, 1, 1.0);
    correlator_->addMessage(msg);

    auto s6a_sessions = correlator_->getS6aSessions();
    EXPECT_EQ(s6a_sessions.size(), 1);
    EXPECT_EQ(s6a_sessions[0]->getInterface(), DiameterInterface::S6A);
}

TEST_F(DiameterCorrelatorTest, InterfaceDetection_Rx) {
    auto proto_msg = createDiameterMessage(
        true,
        static_cast<uint32_t>(DiameterCommandCode::AA_REQUEST),
        static_cast<uint32_t>(DiameterApplicationID::TGPP_RX),
        100,
        "rx-session");

    auto msg = createCorrelationMessage(proto_msg, 1, 1.0);
    correlator_->addMessage(msg);

    auto rx_sessions = correlator_->getRxSessions();
    EXPECT_EQ(rx_sessions.size(), 1);
    EXPECT_EQ(rx_sessions[0]->getInterface(), DiameterInterface::RX);
}

TEST_F(DiameterCorrelatorTest, InterfaceDetection_Cx) {
    auto proto_msg = createDiameterMessage(
        true,
        static_cast<uint32_t>(DiameterCommandCode::USER_AUTHORIZATION),
        static_cast<uint32_t>(DiameterApplicationID::TGPP_CX),
        100,
        "cx-session");

    auto msg = createCorrelationMessage(proto_msg, 1, 1.0);
    correlator_->addMessage(msg);

    auto cx_sessions = correlator_->getCxSessions();
    EXPECT_EQ(cx_sessions.size(), 1);
    EXPECT_EQ(cx_sessions[0]->getInterface(), DiameterInterface::CX);
}

// ============================================================================
// Subscriber Identity Tests
// ============================================================================

TEST_F(DiameterCorrelatorTest, ExtractImsiFromUserName) {
    auto proto_msg = createDiameterMessage(
        true,
        static_cast<uint32_t>(DiameterCommandCode::UPDATE_LOCATION),
        static_cast<uint32_t>(DiameterApplicationID::TGPP_S6A_S6D),
        100,
        "s6a-imsi-session");

    // Add User-Name AVP with IMSI
    auto user_name_avp = std::make_shared<DiameterAVP>();
    user_name_avp->code = static_cast<uint32_t>(DiameterAVPCode::USER_NAME);
    std::string imsi = "310150123456789";  // 15 digits
    user_name_avp->data.assign(imsi.begin(), imsi.end());
    user_name_avp->decoded_value = imsi;
    proto_msg->avps.push_back(user_name_avp);

    auto msg = createCorrelationMessage(proto_msg, 1, 1.0);
    correlator_->addMessage(msg);
    correlator_->finalize();

    auto session = correlator_->findBySessionId("s6a-imsi-session");
    ASSERT_NE(session, nullptr);

    auto extracted_imsi = session->getImsi();
    ASSERT_TRUE(extracted_imsi.has_value());
    EXPECT_EQ(*extracted_imsi, "310150123456789");

    // Test lookup by IMSI
    auto sessions = correlator_->findByImsi("310150123456789");
    EXPECT_EQ(sessions.size(), 1);
    EXPECT_EQ(sessions[0]->getSessionId(), "s6a-imsi-session");
}

// ============================================================================
// Statistics Tests
// ============================================================================

TEST_F(DiameterCorrelatorTest, Statistics_RequestAnswerCounts) {
    // Add 3 requests and 2 answers
    for (int i = 0; i < 3; i++) {
        auto proto_req = createDiameterMessage(
            true,
            static_cast<uint32_t>(DiameterCommandCode::CREDIT_CONTROL),
            static_cast<uint32_t>(DiameterApplicationID::TGPP_GX),
            100 + i,
            "session-" + std::to_string(i));

        auto req = createCorrelationMessage(proto_req, i * 2, 1.0 * i);
        correlator_->addMessage(req);
    }

    for (int i = 0; i < 2; i++) {
        auto proto_ans = createDiameterMessage(
            false,
            static_cast<uint32_t>(DiameterCommandCode::CREDIT_CONTROL),
            static_cast<uint32_t>(DiameterApplicationID::TGPP_GX),
            100 + i,
            "session-" + std::to_string(i));

        proto_ans->result_code = 2001;
        auto ans = createCorrelationMessage(proto_ans, i * 2 + 1, 1.0 * i + 0.1);
        correlator_->addMessage(ans);
    }

    auto stats = correlator_->getStats();
    EXPECT_EQ(stats.total_messages, 5);
    EXPECT_EQ(stats.request_count, 3);
    EXPECT_EQ(stats.answer_count, 2);
    EXPECT_EQ(stats.total_sessions, 3);
}

TEST_F(DiameterCorrelatorTest, Statistics_ErrorTracking) {
    // Add successful answer
    auto proto_success = createDiameterMessage(
        false,
        static_cast<uint32_t>(DiameterCommandCode::CREDIT_CONTROL),
        static_cast<uint32_t>(DiameterApplicationID::TGPP_GX),
        100,
        "session-success");
    proto_success->result_code = 2001;  // SUCCESS

    auto success_msg = createCorrelationMessage(proto_success, 1, 1.0);
    correlator_->addMessage(success_msg);

    // Add error answer
    auto proto_error = createDiameterMessage(
        false,
        static_cast<uint32_t>(DiameterCommandCode::CREDIT_CONTROL),
        static_cast<uint32_t>(DiameterApplicationID::TGPP_GX),
        200,
        "session-error");
    proto_error->result_code = 5012;  // UNABLE_TO_COMPLY

    auto error_msg = createCorrelationMessage(proto_error, 2, 2.0);
    correlator_->addMessage(error_msg);

    auto stats = correlator_->getStats();
    EXPECT_EQ(stats.error_responses, 1);
}

TEST_F(DiameterCorrelatorTest, Statistics_InterfaceCounts) {
    // Add Gx session
    auto gx_msg = createDiameterMessage(
        true,
        static_cast<uint32_t>(DiameterCommandCode::CREDIT_CONTROL),
        static_cast<uint32_t>(DiameterApplicationID::TGPP_GX),
        100,
        "gx-1");
    correlator_->addMessage(createCorrelationMessage(gx_msg, 1, 1.0));

    // Add S6a session
    auto s6a_msg = createDiameterMessage(
        true,
        static_cast<uint32_t>(DiameterCommandCode::UPDATE_LOCATION),
        static_cast<uint32_t>(DiameterApplicationID::TGPP_S6A_S6D),
        200,
        "s6a-1");
    correlator_->addMessage(createCorrelationMessage(s6a_msg, 2, 2.0));

    // Add Rx session
    auto rx_msg = createDiameterMessage(
        true,
        static_cast<uint32_t>(DiameterCommandCode::AA_REQUEST),
        static_cast<uint32_t>(DiameterApplicationID::TGPP_RX),
        300,
        "rx-1");
    correlator_->addMessage(createCorrelationMessage(rx_msg, 3, 3.0));

    auto stats = correlator_->getStats();
    EXPECT_EQ(stats.sessions_by_interface[DiameterInterface::GX], 1);
    EXPECT_EQ(stats.sessions_by_interface[DiameterInterface::S6A], 1);
    EXPECT_EQ(stats.sessions_by_interface[DiameterInterface::RX], 1);
}

// ============================================================================
// Clear Tests
// ============================================================================

TEST_F(DiameterCorrelatorTest, ClearAllSessions) {
    // Add some sessions
    for (int i = 0; i < 5; i++) {
        auto proto_msg = createDiameterMessage(
            true,
            static_cast<uint32_t>(DiameterCommandCode::CREDIT_CONTROL),
            static_cast<uint32_t>(DiameterApplicationID::TGPP_GX),
            100 + i,
            "session-" + std::to_string(i));

        auto msg = createCorrelationMessage(proto_msg, i, 1.0 * i);
        correlator_->addMessage(msg);
    }

    EXPECT_EQ(correlator_->getSessionCount(), 5);

    correlator_->clear();

    EXPECT_EQ(correlator_->getSessionCount(), 0);
    auto stats = correlator_->getStats();
    EXPECT_EQ(stats.total_messages, 0);
    EXPECT_EQ(stats.total_sessions, 0);
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
