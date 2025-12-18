#include <gtest/gtest.h>
#include "protocol_parsers/gtpv1_parser.h"
#include <vector>
#include <cstring>
#include <arpa/inet.h>

using namespace callflow;

/**
 * Test fixture for GTPv1 parser tests
 */
class GtpV1ParserTest : public ::testing::Test {
protected:
    void SetUp() override {
        parser_ = std::make_unique<GtpV1Parser>();
    }

    void TearDown() override {
        parser_.reset();
    }

    /**
     * Create a minimal GTPv1 header
     */
    std::vector<uint8_t> createMinimalGtpV1Header(uint8_t msg_type, uint32_t teid,
                                                   uint16_t msg_len = 0) {
        std::vector<uint8_t> header(8);

        // Byte 0: Version (1) + PT (1) + Flags
        header[0] = 0x30;  // Version 1, PT=1, no optional fields

        // Byte 1: Message Type
        header[1] = msg_type;

        // Bytes 2-3: Message Length
        uint16_t len = htons(msg_len);
        std::memcpy(&header[2], &len, 2);

        // Bytes 4-7: TEID
        uint32_t teid_net = htonl(teid);
        std::memcpy(&header[4], &teid_net, 4);

        return header;
    }

    /**
     * Create GTPv1 header with optional fields
     */
    std::vector<uint8_t> createExtendedGtpV1Header(uint8_t msg_type, uint32_t teid,
                                                    uint16_t seq_num, uint16_t msg_len = 0) {
        std::vector<uint8_t> header(12);

        // Byte 0: Version (1) + PT (1) + S flag set
        header[0] = 0x32;  // Version 1, PT=1, S flag set

        // Byte 1: Message Type
        header[1] = msg_type;

        // Bytes 2-3: Message Length
        uint16_t len = htons(msg_len);
        std::memcpy(&header[2], &len, 2);

        // Bytes 4-7: TEID
        uint32_t teid_net = htonl(teid);
        std::memcpy(&header[4], &teid_net, 4);

        // Bytes 8-9: Sequence Number
        uint16_t seq = htons(seq_num);
        std::memcpy(&header[8], &seq, 2);

        // Byte 10: N-PDU Number
        header[10] = 0;

        // Byte 11: Next Extension Header Type
        header[11] = 0;

        return header;
    }

    /**
     * Encode IMSI in BCD format
     */
    std::vector<uint8_t> encodeImsi(const std::string& imsi) {
        std::vector<uint8_t> encoded;

        for (size_t i = 0; i < imsi.length(); i += 2) {
            uint8_t byte = 0;

            // Lower nibble
            byte |= (imsi[i] - '0');

            // Upper nibble
            if (i + 1 < imsi.length()) {
                byte |= ((imsi[i + 1] - '0') << 4);
            } else {
                byte |= 0xF0;  // Filler
            }

            encoded.push_back(byte);
        }

        return encoded;
    }

    /**
     * Encode APN in length-prefixed label format
     */
    std::vector<uint8_t> encodeApn(const std::string& apn) {
        std::vector<uint8_t> encoded;
        size_t start = 0;

        while (start < apn.length()) {
            size_t dot = apn.find('.', start);
            if (dot == std::string::npos) {
                dot = apn.length();
            }

            size_t label_len = dot - start;
            encoded.push_back(static_cast<uint8_t>(label_len));

            for (size_t i = start; i < dot; ++i) {
                encoded.push_back(static_cast<uint8_t>(apn[i]));
            }

            start = dot + 1;
        }

        return encoded;
    }

    std::unique_ptr<GtpV1Parser> parser_;
};

// Test GTPv1 version detection
TEST_F(GtpV1ParserTest, IsGtpV1Detection) {
    auto header = createMinimalGtpV1Header(
        static_cast<uint8_t>(GtpV1MessageType::ECHO_REQUEST), 0x12345678);

    EXPECT_TRUE(GtpV1Parser::isGtpV1(header.data(), header.size()));

    // Test with invalid version
    header[0] = 0x50;  // Version 2
    EXPECT_FALSE(GtpV1Parser::isGtpV1(header.data(), header.size()));

    // Test with too short data
    EXPECT_FALSE(GtpV1Parser::isGtpV1(header.data(), 4));
}

// Test minimal header parsing
TEST_F(GtpV1ParserTest, ParseMinimalHeader) {
    uint32_t teid = 0x12345678;
    auto header = createMinimalGtpV1Header(
        static_cast<uint8_t>(GtpV1MessageType::ECHO_REQUEST), teid);

    auto result = parser_->parse(header.data(), header.size());
    ASSERT_TRUE(result.has_value());

    const auto& msg = result.value();
    EXPECT_EQ(msg.header.version, 1);
    EXPECT_EQ(msg.header.protocol_type, 1);
    EXPECT_EQ(msg.header.message_type, static_cast<uint8_t>(GtpV1MessageType::ECHO_REQUEST));
    EXPECT_EQ(msg.header.teid, teid);
    EXPECT_FALSE(msg.header.sequence_number.has_value());
}

// Test extended header parsing
TEST_F(GtpV1ParserTest, ParseExtendedHeader) {
    uint32_t teid = 0x87654321;
    uint16_t seq_num = 0x1234;
    auto header = createExtendedGtpV1Header(
        static_cast<uint8_t>(GtpV1MessageType::CREATE_PDP_CONTEXT_REQUEST), teid, seq_num);

    auto result = parser_->parse(header.data(), header.size());
    ASSERT_TRUE(result.has_value());

    const auto& msg = result.value();
    EXPECT_EQ(msg.header.version, 1);
    EXPECT_EQ(msg.header.teid, teid);
    EXPECT_TRUE(msg.header.sequence_number.has_value());
    EXPECT_EQ(msg.header.sequence_number.value(), seq_num);
}

// Test CREATE PDP CONTEXT message
TEST_F(GtpV1ParserTest, ParseCreatePdpContext) {
    uint32_t teid = 0;  // TEID is 0 for initial request
    auto header = createExtendedGtpV1Header(
        static_cast<uint8_t>(GtpV1MessageType::CREATE_PDP_CONTEXT_REQUEST), teid, 1);

    // Add IMSI IE (type 2, fixed 8 bytes)
    std::string imsi = "310150123456789";
    auto imsi_encoded = encodeImsi(imsi);
    header.push_back(static_cast<uint8_t>(GtpV1IeType::IMSI));
    header.insert(header.end(), imsi_encoded.begin(), imsi_encoded.end());

    // Update message length
    uint16_t msg_len = 4 + 1 + imsi_encoded.size();  // optional fields + IE
    uint16_t len_net = htons(msg_len);
    std::memcpy(&header[2], &len_net, 2);

    auto result = parser_->parse(header.data(), header.size());
    ASSERT_TRUE(result.has_value());

    const auto& msg = result.value();
    EXPECT_EQ(msg.header.message_type,
              static_cast<uint8_t>(GtpV1MessageType::CREATE_PDP_CONTEXT_REQUEST));
    EXPECT_EQ(msg.getMessageType(), MessageType::GTP_CREATE_SESSION_REQ);
    EXPECT_TRUE(msg.imsi.has_value());
    EXPECT_EQ(msg.imsi.value(), imsi);
}

// Test APN decoding
TEST_F(GtpV1ParserTest, DecodeApn) {
    uint32_t teid = 0x12345678;
    auto header = createExtendedGtpV1Header(
        static_cast<uint8_t>(GtpV1MessageType::CREATE_PDP_CONTEXT_REQUEST), teid, 1);

    // Add APN IE (type 131, variable TLV)
    std::string apn = "internet.mnc001.mcc310.gprs";
    auto apn_encoded = encodeApn(apn);

    header.push_back(static_cast<uint8_t>(GtpV1IeType::APN));
    // Add length field (2 bytes)
    uint16_t apn_len = htons(static_cast<uint16_t>(apn_encoded.size()));
    header.push_back((apn_len >> 8) & 0xFF);
    header.push_back(apn_len & 0xFF);
    header.insert(header.end(), apn_encoded.begin(), apn_encoded.end());

    // Update message length
    uint16_t msg_len = 4 + 1 + 2 + apn_encoded.size();  // optional + type + len + data
    uint16_t len_net = htons(msg_len);
    std::memcpy(&header[2], &len_net, 2);

    auto result = parser_->parse(header.data(), header.size());
    ASSERT_TRUE(result.has_value());

    const auto& msg = result.value();
    EXPECT_TRUE(msg.apn.has_value());
    EXPECT_EQ(msg.apn.value(), apn);
}

// Test G-PDU (user plane) message
TEST_F(GtpV1ParserTest, ParseGpdu) {
    uint32_t teid = 0x12345678;
    auto header = createExtendedGtpV1Header(
        static_cast<uint8_t>(GtpV1MessageType::G_PDU), teid, 100);

    // Add some user data
    std::vector<uint8_t> user_data = {0x45, 0x00, 0x00, 0x54};  // IP header start
    header.insert(header.end(), user_data.begin(), user_data.end());

    // Update message length
    uint16_t msg_len = 4 + user_data.size();  // optional fields + data
    uint16_t len_net = htons(msg_len);
    std::memcpy(&header[2], &len_net, 2);

    auto result = parser_->parse(header.data(), header.size());
    ASSERT_TRUE(result.has_value());

    const auto& msg = result.value();
    EXPECT_EQ(msg.header.message_type, static_cast<uint8_t>(GtpV1MessageType::G_PDU));
    EXPECT_TRUE(msg.isUserPlane());
    EXPECT_EQ(msg.getMessageTypeName(), "G-PDU");
}

// Test message type names
TEST_F(GtpV1ParserTest, MessageTypeNames) {
    auto test_msg_name = [this](GtpV1MessageType type, const std::string& expected_name) {
        auto header = createMinimalGtpV1Header(static_cast<uint8_t>(type), 0);
        auto result = parser_->parse(header.data(), header.size());
        ASSERT_TRUE(result.has_value());
        EXPECT_EQ(result.value().getMessageTypeName(), expected_name);
    };

    test_msg_name(GtpV1MessageType::ECHO_REQUEST, "Echo-Request");
    test_msg_name(GtpV1MessageType::ECHO_RESPONSE, "Echo-Response");
    test_msg_name(GtpV1MessageType::CREATE_PDP_CONTEXT_REQUEST, "Create-PDP-Context-Request");
    test_msg_name(GtpV1MessageType::CREATE_PDP_CONTEXT_RESPONSE, "Create-PDP-Context-Response");
    test_msg_name(GtpV1MessageType::UPDATE_PDP_CONTEXT_REQUEST, "Update-PDP-Context-Request");
    test_msg_name(GtpV1MessageType::DELETE_PDP_CONTEXT_REQUEST, "Delete-PDP-Context-Request");
    test_msg_name(GtpV1MessageType::G_PDU, "G-PDU");
}

// Test NSAPI parsing
TEST_F(GtpV1ParserTest, ParseNsapi) {
    uint32_t teid = 0x12345678;
    auto header = createExtendedGtpV1Header(
        static_cast<uint8_t>(GtpV1MessageType::CREATE_PDP_CONTEXT_REQUEST), teid, 1);

    // Add NSAPI IE (type 20, fixed 1 byte value)
    header.push_back(static_cast<uint8_t>(GtpV1IeType::NSAPI));
    header.push_back(0x05);  // NSAPI value 5

    // Update message length
    uint16_t msg_len = 4 + 2;  // optional fields + IE
    uint16_t len_net = htons(msg_len);
    std::memcpy(&header[2], &len_net, 2);

    auto result = parser_->parse(header.data(), header.size());
    ASSERT_TRUE(result.has_value());

    const auto& msg = result.value();
    EXPECT_TRUE(msg.nsapi.has_value());
    EXPECT_EQ(msg.nsapi.value(), 5);
}

// Test JSON serialization
TEST_F(GtpV1ParserTest, JsonSerialization) {
    uint32_t teid = 0x12345678;
    auto header = createExtendedGtpV1Header(
        static_cast<uint8_t>(GtpV1MessageType::ECHO_REQUEST), teid, 42);

    auto result = parser_->parse(header.data(), header.size());
    ASSERT_TRUE(result.has_value());

    auto json = result.value().toJson();

    EXPECT_TRUE(json.contains("header"));
    EXPECT_TRUE(json.contains("message_type_name"));
    EXPECT_EQ(json["message_type_name"], "Echo-Request");
    EXPECT_TRUE(json.contains("is_user_plane"));
    EXPECT_FALSE(json["is_user_plane"]);

    auto header_json = json["header"];
    EXPECT_EQ(header_json["version"], 1);
    EXPECT_EQ(header_json["teid"], teid);
    EXPECT_EQ(header_json["sequence_number"], 42);
}

// Test invalid packet
TEST_F(GtpV1ParserTest, InvalidPacket) {
    std::vector<uint8_t> invalid_data = {0x00, 0x01, 0x02};

    auto result = parser_->parse(invalid_data.data(), invalid_data.size());
    EXPECT_FALSE(result.has_value());
}

// Test incomplete packet
TEST_F(GtpV1ParserTest, IncompletePacket) {
    auto header = createExtendedGtpV1Header(
        static_cast<uint8_t>(GtpV1MessageType::CREATE_PDP_CONTEXT_REQUEST), 0, 1);

    // Set message length to indicate more data than actually present
    uint16_t msg_len = 100;
    uint16_t len_net = htons(msg_len);
    std::memcpy(&header[2], &len_net, 2);

    auto result = parser_->parse(header.data(), header.size());
    EXPECT_FALSE(result.has_value());
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
