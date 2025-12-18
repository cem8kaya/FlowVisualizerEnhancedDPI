#include <gtest/gtest.h>
#include "protocol_parsers/pfcp_parser.h"
#include <cstring>

using namespace callflow;

class PfcpParserTest : public ::testing::Test {
protected:
    PfcpParser parser;
};

TEST_F(PfcpParserTest, DetectValidPfcpHeartbeat) {
    // PFCP Heartbeat Request (minimal header)
    // Version=1 (001), S=0, MP=0, Message Type=1, Length=4, Sequence=0x000001
    uint8_t pfcp_data[] = {
        0x20,  // Version=1 (001), Spare=0, MP=0, S=0
        0x01,  // Message Type: Heartbeat Request
        0x00, 0x04,  // Message Length: 4 bytes
        0x00, 0x00, 0x01  // Sequence Number: 1
    };

    EXPECT_TRUE(PfcpParser::isPfcp(pfcp_data, sizeof(pfcp_data)));
}

TEST_F(PfcpParserTest, DetectInvalidVersion) {
    // Invalid version (version 2)
    uint8_t invalid_data[] = {
        0x40,  // Version=2 (010), invalid
        0x01,  // Message Type: Heartbeat Request
        0x00, 0x04,
        0x00, 0x00, 0x01
    };

    EXPECT_FALSE(PfcpParser::isPfcp(invalid_data, sizeof(invalid_data)));
}

TEST_F(PfcpParserTest, ParseHeartbeatRequest) {
    // PFCP Heartbeat Request
    uint8_t pfcp_data[] = {
        0x20,  // Version=1, S=0, MP=0
        0x01,  // Message Type: Heartbeat Request
        0x00, 0x04,  // Message Length: 4 bytes (just the recovery time stamp IE)
        0x00, 0x00, 0x01,  // Sequence Number: 1
        // Recovery Time Stamp IE (Type=96, Length=4)
        0x00, 0x60,  // Type: 96 (Recovery Time Stamp)
        0x00, 0x04,  // Length: 4
        0x00, 0x00, 0x00, 0x01  // Timestamp: 1
    };

    auto result = parser.parse(pfcp_data, sizeof(pfcp_data));
    ASSERT_TRUE(result.has_value());

    const auto& msg = result.value();
    EXPECT_EQ(msg.header.version, 1);
    EXPECT_EQ(msg.header.message_type, 1);  // Heartbeat Request
    EXPECT_EQ(msg.header.sequence_number, 1);
    EXPECT_FALSE(msg.header.s);  // No SEID
    EXPECT_EQ(msg.ies.size(), 1);  // One IE

    // Check recovery timestamp
    EXPECT_TRUE(msg.recovery_timestamp.has_value());
    EXPECT_EQ(msg.recovery_timestamp.value(), 1);
}

TEST_F(PfcpParserTest, ParseSessionEstablishmentRequest) {
    // PFCP Session Establishment Request with SEID
    uint8_t pfcp_data[] = {
        0x21,  // Version=1, S=1 (SEID present), MP=0
        0x32,  // Message Type: Session Establishment Request (50)
        0x00, 0x14,  // Message Length: 20 bytes
        // SEID (8 bytes)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34,
        0x00, 0x00, 0x01,  // Sequence Number: 1
        // Node ID IE (Type=60, Length=5, IPv4)
        0x00, 0x3C,  // Type: 60 (Node ID)
        0x00, 0x05,  // Length: 5
        0x00,  // Type: IPv4
        0xC0, 0xA8, 0x01, 0x01  // 192.168.1.1
    };

    auto result = parser.parse(pfcp_data, sizeof(pfcp_data));
    ASSERT_TRUE(result.has_value());

    const auto& msg = result.value();
    EXPECT_EQ(msg.header.version, 1);
    EXPECT_EQ(msg.header.message_type, 50);  // Session Establishment Request
    EXPECT_TRUE(msg.header.s);  // SEID present
    EXPECT_EQ(msg.header.seid, 0x1234);
    EXPECT_EQ(msg.header.sequence_number, 1);

    // Check Node ID
    EXPECT_TRUE(msg.node_id.has_value());
    EXPECT_EQ(msg.node_id.value(), "192.168.1.1");
}

TEST_F(PfcpParserTest, ParseInvalidMessage) {
    // Too short
    uint8_t pfcp_data[] = {0x20, 0x01};

    auto result = parser.parse(pfcp_data, sizeof(pfcp_data));
    EXPECT_FALSE(result.has_value());
}

TEST_F(PfcpParserTest, GetMessageTypeName) {
    // PFCP Heartbeat Request
    uint8_t pfcp_data[] = {
        0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01
    };

    auto result = parser.parse(pfcp_data, sizeof(pfcp_data));
    ASSERT_TRUE(result.has_value());

    EXPECT_EQ(result->getMessageTypeName(), "Heartbeat Request");
    EXPECT_EQ(result->getMessageType(), MessageType::PFCP_HEARTBEAT_REQ);
}

TEST_F(PfcpParserTest, SessionDeletionRequest) {
    // PFCP Session Deletion Request
    uint8_t pfcp_data[] = {
        0x21,  // Version=1, S=1 (SEID present)
        0x36,  // Message Type: Session Deletion Request (54)
        0x00, 0x00,  // Message Length: 0 (no IEs)
        // SEID (8 bytes)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x56, 0x78,
        0x00, 0x00, 0x02  // Sequence Number: 2
    };

    auto result = parser.parse(pfcp_data, sizeof(pfcp_data));
    ASSERT_TRUE(result.has_value());

    const auto& msg = result.value();
    EXPECT_EQ(msg.header.message_type, 54);  // Session Deletion Request
    EXPECT_EQ(msg.header.seid, 0x5678);
    EXPECT_EQ(msg.getMessageTypeName(), "Session Deletion Request");
    EXPECT_EQ(msg.getMessageType(), MessageType::PFCP_SESSION_DELETION_REQ);
}

TEST_F(PfcpParserTest, JsonSerialization) {
    // PFCP Heartbeat Request with Recovery Timestamp
    uint8_t pfcp_data[] = {
        0x20, 0x01, 0x00, 0x04,  // Header
        0x00, 0x00, 0x01,  // Sequence
        // Recovery Time Stamp IE
        0x00, 0x60, 0x00, 0x04,
        0x12, 0x34, 0x56, 0x78
    };

    auto result = parser.parse(pfcp_data, sizeof(pfcp_data));
    ASSERT_TRUE(result.has_value());

    auto json = result->toJson();
    EXPECT_TRUE(json.contains("header"));
    EXPECT_TRUE(json.contains("message_type_name"));
    EXPECT_TRUE(json.contains("ies"));
    EXPECT_EQ(json["message_type_name"], "Heartbeat Request");
}
