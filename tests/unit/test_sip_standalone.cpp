#include <gtest/gtest.h>
#include "correlation/sip_session_manager.h"
#include "protocol_parsers/sip_parser.h"
#include "common/types.h"

using namespace callflow;
using namespace callflow::correlation;

class SipStandaloneTest : public ::testing::Test {
protected:
    void SetUp() override {
        manager_ = std::make_unique<SipSessionManager>();
    }

    std::unique_ptr<SipSessionManager> manager_;

    // Helper to create a test INVITE message
    SipMessage createSipInvite(const std::string& call_id) {
        SipMessage msg;
        msg.is_request = true;
        msg.method = "INVITE";
        msg.call_id = call_id;
        msg.from = "sip:alice@example.com";
        msg.to = "sip:bob@example.com";
        msg.cseq = 1;
        msg.cseq_method = "INVITE";
        msg.status_code = 0;

        // Add Via header
        SipViaHeader via;
        via.protocol = "SIP/2.0/UDP";
        via.sent_by = "192.168.1.100:5060";
        via.branch = "z9hG4bK-test-branch-" + call_id;
        msg.via_headers.push_back(via);

        // Add SDP
        SdpInfo sdp;
        sdp.connection_address = "192.168.1.100";
        sdp.session_name = "Test Call";
        sdp.origin_username = "alice";
        sdp.origin_session_id = "123456";
        sdp.origin_session_version = "654321";
        sdp.origin_network_type = "IN";
        sdp.origin_address_type = "IP4";
        sdp.origin_address = "192.168.1.100";
        msg.sdp = sdp;

        return msg;
    }

    // Helper to create a test response
    SipMessage createSipResponse(const std::string& call_id, int status_code,
                                 const std::string& reason_phrase) {
        SipMessage msg;
        msg.is_request = false;
        msg.status_code = status_code;
        msg.reason_phrase = reason_phrase;
        msg.call_id = call_id;
        msg.from = "sip:alice@example.com";
        msg.to = "sip:bob@example.com";
        msg.cseq = 1;
        msg.cseq_method = "INVITE";

        // Add Via header
        SipViaHeader via;
        via.protocol = "SIP/2.0/UDP";
        via.sent_by = "192.168.1.100:5060";
        via.branch = "z9hG4bK-test-branch-" + call_id;
        msg.via_headers.push_back(via);

        return msg;
    }

    // Helper to create a BYE message
    SipMessage createSipBye(const std::string& call_id) {
        SipMessage msg;
        msg.is_request = true;
        msg.method = "BYE";
        msg.call_id = call_id;
        msg.from = "sip:alice@example.com";
        msg.to = "sip:bob@example.com";
        msg.cseq = 2;
        msg.cseq_method = "BYE";
        msg.status_code = 0;

        // Add Via header
        SipViaHeader via;
        via.protocol = "SIP/2.0/UDP";
        via.sent_by = "192.168.1.100:5060";
        via.branch = "z9hG4bK-test-bye-branch-" + call_id;
        msg.via_headers.push_back(via);

        return msg;
    }

    // Helper to create PacketMetadata
    PacketMetadata createMetadata(double timestamp, uint32_t frame_number,
                                  const std::string& src_ip, uint16_t src_port,
                                  const std::string& dst_ip, uint16_t dst_port) {
        PacketMetadata metadata;
        metadata.packet_id = frame_number;
        metadata.timestamp = std::chrono::system_clock::from_time_t(static_cast<time_t>(timestamp));
        metadata.packet_length = 512;
        metadata.five_tuple.src_ip = src_ip;
        metadata.five_tuple.src_port = src_port;
        metadata.five_tuple.dst_ip = dst_ip;
        metadata.five_tuple.dst_port = dst_port;
        metadata.five_tuple.protocol = 17; // UDP
        return metadata;
    }
};

// Test: Create Standalone SIP Session
TEST_F(SipStandaloneTest, CreateStandaloneSipSession) {
    auto invite = createSipInvite("test-call-id@192.168.1.1");
    auto metadata = createMetadata(1000.0, 100, "192.168.1.100", 5060, "192.168.1.200", 5060);

    manager_->processSipMessage(invite, metadata);

    auto session = manager_->getSessionByCallId("test-call-id@192.168.1.1");
    ASSERT_NE(session, nullptr);
    EXPECT_EQ(session->getCallId(), "test-call-id@192.168.1.1");
    EXPECT_EQ(session->getMessageCount(), 1);
}

// Test: Multiple Messages in Same Session
TEST_F(SipStandaloneTest, MultipleMessagesInSameSession) {
    auto invite = createSipInvite("call-123@example.com");
    auto ringing = createSipResponse("call-123@example.com", 180, "Ringing");
    auto ok = createSipResponse("call-123@example.com", 200, "OK");

    auto metadata1 = createMetadata(1000.0, 100, "192.168.1.100", 5060, "192.168.1.200", 5060);
    auto metadata2 = createMetadata(1001.0, 101, "192.168.1.200", 5060, "192.168.1.100", 5060);
    auto metadata3 = createMetadata(1002.0, 102, "192.168.1.200", 5060, "192.168.1.100", 5060);

    manager_->processSipMessage(invite, metadata1);
    manager_->processSipMessage(ringing, metadata2);
    manager_->processSipMessage(ok, metadata3);

    auto session = manager_->getSessionByCallId("call-123@example.com");
    ASSERT_NE(session, nullptr);
    EXPECT_EQ(session->getMessageCount(), 3);
}

// Test: Complete Call Flow
TEST_F(SipStandaloneTest, CompleteCallFlow) {
    auto invite = createSipInvite("complete-call@example.com");
    auto trying = createSipResponse("complete-call@example.com", 100, "Trying");
    auto ringing = createSipResponse("complete-call@example.com", 180, "Ringing");
    auto ok = createSipResponse("complete-call@example.com", 200, "OK");
    auto bye = createSipBye("complete-call@example.com");
    auto bye_ok = createSipResponse("complete-call@example.com", 200, "OK");

    auto metadata1 = createMetadata(1000.0, 100, "192.168.1.100", 5060, "192.168.1.200", 5060);
    auto metadata2 = createMetadata(1000.5, 101, "192.168.1.200", 5060, "192.168.1.100", 5060);
    auto metadata3 = createMetadata(1001.0, 102, "192.168.1.200", 5060, "192.168.1.100", 5060);
    auto metadata4 = createMetadata(1002.0, 103, "192.168.1.200", 5060, "192.168.1.100", 5060);
    auto metadata5 = createMetadata(1010.0, 104, "192.168.1.100", 5060, "192.168.1.200", 5060);
    auto metadata6 = createMetadata(1010.5, 105, "192.168.1.200", 5060, "192.168.1.100", 5060);

    manager_->processSipMessage(invite, metadata1);
    manager_->processSipMessage(trying, metadata2);
    manager_->processSipMessage(ringing, metadata3);
    manager_->processSipMessage(ok, metadata4);
    manager_->processSipMessage(bye, metadata5);
    manager_->processSipMessage(bye_ok, metadata6);

    auto session = manager_->getSessionByCallId("complete-call@example.com");
    ASSERT_NE(session, nullptr);
    EXPECT_EQ(session->getMessageCount(), 6);

    // Verify time window
    EXPECT_NEAR(session->getStartTime(), 1000.0, 0.1);
    EXPECT_NEAR(session->getEndTime(), 1010.5, 0.1);
}

// Test: Multiple Independent Sessions
TEST_F(SipStandaloneTest, MultipleIndependentSessions) {
    auto invite1 = createSipInvite("call-1@example.com");
    auto invite2 = createSipInvite("call-2@example.com");
    auto invite3 = createSipInvite("call-3@example.com");

    auto metadata1 = createMetadata(1000.0, 100, "192.168.1.100", 5060, "192.168.1.200", 5060);
    auto metadata2 = createMetadata(1001.0, 101, "192.168.1.101", 5060, "192.168.1.201", 5060);
    auto metadata3 = createMetadata(1002.0, 102, "192.168.1.102", 5060, "192.168.1.202", 5060);

    manager_->processSipMessage(invite1, metadata1);
    manager_->processSipMessage(invite2, metadata2);
    manager_->processSipMessage(invite3, metadata3);

    auto sessions = manager_->getSessions();
    EXPECT_EQ(sessions.size(), 3);

    auto session1 = manager_->getSessionByCallId("call-1@example.com");
    auto session2 = manager_->getSessionByCallId("call-2@example.com");
    auto session3 = manager_->getSessionByCallId("call-3@example.com");

    ASSERT_NE(session1, nullptr);
    ASSERT_NE(session2, nullptr);
    ASSERT_NE(session3, nullptr);

    EXPECT_EQ(session1->getMessageCount(), 1);
    EXPECT_EQ(session2->getMessageCount(), 1);
    EXPECT_EQ(session3->getMessageCount(), 1);
}

// Test: Export to JSON
TEST_F(SipStandaloneTest, ExportToJson) {
    // Create a complete SIP call flow
    auto invite = createSipInvite("export-call@example.com");
    auto ok = createSipResponse("export-call@example.com", 200, "OK");
    auto bye = createSipBye("export-call@example.com");

    auto metadata1 = createMetadata(1000.0, 100, "192.168.1.100", 5060, "192.168.1.200", 5060);
    auto metadata2 = createMetadata(1002.0, 101, "192.168.1.200", 5060, "192.168.1.100", 5060);
    auto metadata3 = createMetadata(1010.0, 102, "192.168.1.100", 5060, "192.168.1.200", 5060);

    manager_->processSipMessage(invite, metadata1);
    manager_->processSipMessage(ok, metadata2);
    manager_->processSipMessage(bye, metadata3);

    auto json = manager_->exportSessions();
    ASSERT_TRUE(json.is_array());
    ASSERT_GE(json.size(), 1);

    auto session = json[0];
    EXPECT_TRUE(session.contains("session_id"));
    EXPECT_TRUE(session.contains("call_id"));
    EXPECT_EQ(session["call_id"], "export-call@example.com");
    EXPECT_TRUE(session.contains("events"));
    EXPECT_GE(session["events"].size(), 3);
}

// Test: Statistics
TEST_F(SipStandaloneTest, Statistics) {
    // Create multiple sessions
    auto invite1 = createSipInvite("call-1@example.com");
    auto invite2 = createSipInvite("call-2@example.com");
    auto ok1 = createSipResponse("call-1@example.com", 200, "OK");

    auto metadata1 = createMetadata(1000.0, 100, "192.168.1.100", 5060, "192.168.1.200", 5060);
    auto metadata2 = createMetadata(1001.0, 101, "192.168.1.101", 5060, "192.168.1.201", 5060);
    auto metadata3 = createMetadata(1002.0, 102, "192.168.1.200", 5060, "192.168.1.100", 5060);

    manager_->processSipMessage(invite1, metadata1);
    manager_->processSipMessage(invite2, metadata2);
    manager_->processSipMessage(ok1, metadata3);

    auto stats = manager_->getStats();
    EXPECT_EQ(stats.total_sessions, 2);
    EXPECT_EQ(stats.total_messages, 3);
    EXPECT_GT(stats.active_sessions, 0);
}

// Test: Empty Session Manager
TEST_F(SipStandaloneTest, EmptySessionManager) {
    auto sessions = manager_->getSessions();
    EXPECT_TRUE(sessions.empty());

    auto stats = manager_->getStats();
    EXPECT_EQ(stats.total_sessions, 0);
    EXPECT_EQ(stats.total_messages, 0);
    EXPECT_EQ(stats.active_sessions, 0);
    EXPECT_EQ(stats.completed_sessions, 0);
}

// Test: Session Not Found
TEST_F(SipStandaloneTest, SessionNotFound) {
    auto session = manager_->getSessionByCallId("nonexistent@example.com");
    EXPECT_EQ(session, nullptr);
}
