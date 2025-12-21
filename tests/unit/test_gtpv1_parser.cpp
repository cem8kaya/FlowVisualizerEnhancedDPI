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

// Test G-PDU with encapsulated IPv4 packet
TEST_F(GtpV1ParserTest, ParseGpduWithEncapsulatedIPv4) {
    uint32_t teid = 0x12345678;
    auto header = createExtendedGtpV1Header(
        static_cast<uint8_t>(GtpV1MessageType::G_PDU), teid, 100);

    // Create a minimal IPv4 packet (HTTP request)
    std::vector<uint8_t> ipv4_packet;

    // IPv4 header
    ipv4_packet.push_back(0x45);  // Version 4, IHL 5 (20 bytes)
    ipv4_packet.push_back(0x00);  // TOS
    ipv4_packet.push_back(0x00);  // Total length (high)
    ipv4_packet.push_back(0x28);  // Total length (low) = 40 bytes
    ipv4_packet.push_back(0x00);  // ID (high)
    ipv4_packet.push_back(0x00);  // ID (low)
    ipv4_packet.push_back(0x00);  // Flags + Fragment offset (high)
    ipv4_packet.push_back(0x00);  // Fragment offset (low)
    ipv4_packet.push_back(0x40);  // TTL
    ipv4_packet.push_back(0x06);  // Protocol = TCP
    ipv4_packet.push_back(0x00);  // Checksum (high)
    ipv4_packet.push_back(0x00);  // Checksum (low)
    // Source IP: 10.0.0.1
    ipv4_packet.push_back(0x0A);
    ipv4_packet.push_back(0x00);
    ipv4_packet.push_back(0x00);
    ipv4_packet.push_back(0x01);
    // Dest IP: 192.168.1.100
    ipv4_packet.push_back(0xC0);
    ipv4_packet.push_back(0xA8);
    ipv4_packet.push_back(0x01);
    ipv4_packet.push_back(0x64);

    // TCP header (minimal)
    uint16_t src_port = htons(1234);
    uint16_t dst_port = htons(80);
    ipv4_packet.push_back((src_port >> 8) & 0xFF);
    ipv4_packet.push_back(src_port & 0xFF);
    ipv4_packet.push_back((dst_port >> 8) & 0xFF);
    ipv4_packet.push_back(dst_port & 0xFF);
    // Add minimal TCP fields (seq, ack, flags, etc.)
    for (int i = 0; i < 16; i++) {
        ipv4_packet.push_back(0x00);
    }

    header.insert(header.end(), ipv4_packet.begin(), ipv4_packet.end());

    // Update message length
    uint16_t msg_len = 4 + ipv4_packet.size();
    uint16_t len_net = htons(msg_len);
    std::memcpy(&header[2], &len_net, 2);

    auto result = parser_->parse(header.data(), header.size());
    ASSERT_TRUE(result.has_value());

    const auto& msg = result.value();
    EXPECT_TRUE(msg.isUserPlane());
    EXPECT_FALSE(msg.user_data.empty());
    EXPECT_EQ(msg.user_data.size(), ipv4_packet.size());

    // Check encapsulated packet parsing
    ASSERT_TRUE(msg.encapsulated.has_value());
    const auto& encap = msg.encapsulated.value();
    EXPECT_TRUE(encap.is_ipv4);
    EXPECT_EQ(encap.src_ip, "10.0.0.1");
    EXPECT_EQ(encap.dst_ip, "192.168.1.100");
    EXPECT_EQ(encap.protocol, 6);  // TCP
    EXPECT_EQ(encap.getProtocolName(), "TCP");
    ASSERT_TRUE(encap.src_port.has_value());
    EXPECT_EQ(encap.src_port.value(), 1234);
    ASSERT_TRUE(encap.dst_port.has_value());
    EXPECT_EQ(encap.dst_port.value(), 80);
}

// Test G-PDU with encapsulated IPv6 packet
TEST_F(GtpV1ParserTest, ParseGpduWithEncapsulatedIPv6) {
    uint32_t teid = 0xABCDEF12;
    auto header = createExtendedGtpV1Header(
        static_cast<uint8_t>(GtpV1MessageType::G_PDU), teid, 200);

    // Create a minimal IPv6 packet
    std::vector<uint8_t> ipv6_packet;

    // IPv6 header (40 bytes)
    ipv6_packet.push_back(0x60);  // Version 6, Traffic class (high)
    ipv6_packet.push_back(0x00);  // Traffic class (low) + Flow label (high)
    ipv6_packet.push_back(0x00);  // Flow label (mid)
    ipv6_packet.push_back(0x00);  // Flow label (low)
    ipv6_packet.push_back(0x00);  // Payload length (high)
    ipv6_packet.push_back(0x14);  // Payload length (low) = 20 bytes (UDP header)
    ipv6_packet.push_back(0x11);  // Next header = UDP
    ipv6_packet.push_back(0x40);  // Hop limit

    // Source IPv6 address: 2001:db8::1
    ipv6_packet.push_back(0x20);
    ipv6_packet.push_back(0x01);
    ipv6_packet.push_back(0x0d);
    ipv6_packet.push_back(0xb8);
    for (int i = 0; i < 10; i++) ipv6_packet.push_back(0x00);
    ipv6_packet.push_back(0x00);
    ipv6_packet.push_back(0x01);

    // Dest IPv6 address: 2001:db8::2
    ipv6_packet.push_back(0x20);
    ipv6_packet.push_back(0x01);
    ipv6_packet.push_back(0x0d);
    ipv6_packet.push_back(0xb8);
    for (int i = 0; i < 10; i++) ipv6_packet.push_back(0x00);
    ipv6_packet.push_back(0x00);
    ipv6_packet.push_back(0x02);

    // UDP header
    uint16_t src_port = htons(5060);
    uint16_t dst_port = htons(5060);
    ipv6_packet.push_back((src_port >> 8) & 0xFF);
    ipv6_packet.push_back(src_port & 0xFF);
    ipv6_packet.push_back((dst_port >> 8) & 0xFF);
    ipv6_packet.push_back(dst_port & 0xFF);
    // UDP length and checksum
    for (int i = 0; i < 4; i++) {
        ipv6_packet.push_back(0x00);
    }

    header.insert(header.end(), ipv6_packet.begin(), ipv6_packet.end());

    // Update message length
    uint16_t msg_len = 4 + ipv6_packet.size();
    uint16_t len_net = htons(msg_len);
    std::memcpy(&header[2], &len_net, 2);

    auto result = parser_->parse(header.data(), header.size());
    ASSERT_TRUE(result.has_value());

    const auto& msg = result.value();
    EXPECT_TRUE(msg.isUserPlane());

    // Check encapsulated packet parsing
    ASSERT_TRUE(msg.encapsulated.has_value());
    const auto& encap = msg.encapsulated.value();
    EXPECT_FALSE(encap.is_ipv4);
    EXPECT_EQ(encap.src_ip, "2001:db8::1");
    EXPECT_EQ(encap.dst_ip, "2001:db8::2");
    EXPECT_EQ(encap.protocol, 17);  // UDP
    EXPECT_EQ(encap.getProtocolName(), "UDP");
    ASSERT_TRUE(encap.src_port.has_value());
    EXPECT_EQ(encap.src_port.value(), 5060);
    ASSERT_TRUE(encap.dst_port.has_value());
    EXPECT_EQ(encap.dst_port.value(), 5060);
}

// Test G-PDU with extension header (PDCP PDU Number)
TEST_F(GtpV1ParserTest, ParseGpduWithExtensionHeader) {
    uint32_t teid = 0x11223344;
    std::vector<uint8_t> header(12);

    // Byte 0: Version (1) + PT (1) + E flag set
    header[0] = 0x34;  // Version 1, PT=1, E flag set

    // Byte 1: Message Type = G-PDU
    header[1] = static_cast<uint8_t>(GtpV1MessageType::G_PDU);

    // Extension header: PDCP PDU Number (0xC0)
    // Extension header format: length (1 byte in 4-byte units) + content + next_type (1 byte)
    std::vector<uint8_t> ext_header;
    ext_header.push_back(0x01);  // Length = 1 (4 bytes total)
    ext_header.push_back(0x12);  // PDCP PDU Number (high)
    ext_header.push_back(0x34);  // PDCP PDU Number (low)
    ext_header.push_back(0x00);  // Next extension header type = none

    // User data (simple IP packet indicator)
    std::vector<uint8_t> user_data = {0x45, 0x00};

    uint16_t msg_len = 4 + ext_header.size() + user_data.size();
    uint16_t len_net = htons(msg_len);
    std::memcpy(&header[2], &len_net, 2);

    // TEID
    uint32_t teid_net = htonl(teid);
    std::memcpy(&header[4], &teid_net, 4);

    // Optional fields
    header[8] = 0x00;   // Sequence number (high)
    header[9] = 0x01;   // Sequence number (low)
    header[10] = 0x00;  // N-PDU number
    header[11] = 0xC0;  // Next extension header type = PDCP PDU Number

    // Assemble complete packet
    header.insert(header.end(), ext_header.begin(), ext_header.end());
    header.insert(header.end(), user_data.begin(), user_data.end());

    auto result = parser_->parse(header.data(), header.size());
    ASSERT_TRUE(result.has_value());

    const auto& msg = result.value();
    EXPECT_TRUE(msg.isUserPlane());
    EXPECT_EQ(msg.header.teid, teid);

    // Check extension header parsing
    EXPECT_EQ(msg.extension_headers.size(), 1);
    const auto& ext = msg.extension_headers[0];
    EXPECT_EQ(static_cast<uint8_t>(ext.type), 0xC0);
    EXPECT_EQ(ext.getTypeName(), "PDCP-PDU-Number");
    EXPECT_EQ(ext.length, 1);
    EXPECT_EQ(ext.content.size(), 2);
    EXPECT_EQ(ext.content[0], 0x12);
    EXPECT_EQ(ext.content[1], 0x34);
    ASSERT_TRUE(ext.next_extension_header_type.has_value());
    EXPECT_EQ(ext.next_extension_header_type.value(), 0);
}

// Test extension header JSON serialization
TEST_F(GtpV1ParserTest, ExtensionHeaderJsonSerialization) {
    uint32_t teid = 0x99887766;
    std::vector<uint8_t> header(12);

    header[0] = 0x34;  // E flag set
    header[1] = static_cast<uint8_t>(GtpV1MessageType::G_PDU);

    // Service Class Indicator extension (0x20)
    std::vector<uint8_t> ext_header;
    ext_header.push_back(0x01);  // Length = 1
    ext_header.push_back(0x05);  // Service class value
    ext_header.push_back(0x00);  // Padding
    ext_header.push_back(0x00);  // Next = none

    uint16_t msg_len = 4 + ext_header.size();
    uint16_t len_net = htons(msg_len);
    std::memcpy(&header[2], &len_net, 2);

    uint32_t teid_net = htonl(teid);
    std::memcpy(&header[4], &teid_net, 4);

    header[8] = 0x00;
    header[9] = 0x00;
    header[10] = 0x00;
    header[11] = 0x20;  // Service Class Indicator

    header.insert(header.end(), ext_header.begin(), ext_header.end());

    auto result = parser_->parse(header.data(), header.size());
    ASSERT_TRUE(result.has_value());

    auto json = result.value().toJson();
    EXPECT_TRUE(json.contains("extension_headers"));
    EXPECT_TRUE(json.contains("extension_header_count"));
    EXPECT_EQ(json["extension_header_count"], 1);

    auto ext_json = json["extension_headers"][0];
    EXPECT_EQ(ext_json["type"], 0x20);
    EXPECT_EQ(ext_json["type_name"], "Service-Class-Indicator");
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
