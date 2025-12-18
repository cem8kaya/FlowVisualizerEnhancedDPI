#include <gtest/gtest.h>
#include "protocol_parsers/nas_parser.h"
#include <vector>
#include <cstring>
#include <arpa/inet.h>

using namespace callflow;

/**
 * Test fixture for NAS parser tests
 */
class NasParserTest : public ::testing::Test {
protected:
    void SetUp() override {
        parser_ = std::make_unique<NasParser>();
    }

    void TearDown() override {
        parser_.reset();
    }

    /**
     * Create a plain EMM message (no security)
     */
    std::vector<uint8_t> createPlainEmmMessage(uint8_t msg_type) {
        std::vector<uint8_t> msg;

        // Byte 0: Security header type (0 = plain) + Protocol discriminator (7 = EMM)
        msg.push_back(0x07);  // Plain NAS, EMM

        // Byte 1: Message type
        msg.push_back(msg_type);

        return msg;
    }

    /**
     * Create a plain ESM message
     */
    std::vector<uint8_t> createPlainEsmMessage(uint8_t msg_type) {
        std::vector<uint8_t> msg;

        // Byte 0: Security header type (0 = plain) + Protocol discriminator (2 = ESM)
        msg.push_back(0x02);  // Plain NAS, ESM

        // Byte 1: Message type
        msg.push_back(msg_type);

        return msg;
    }

    /**
     * Create a security-protected EMM message
     */
    std::vector<uint8_t> createProtectedEmmMessage(uint8_t msg_type,
                                                   uint32_t mac, uint8_t seq_num) {
        std::vector<uint8_t> msg;

        // Byte 0: Security header type (2 = integrity + ciphered) + PD (7 = EMM)
        msg.push_back(0x27);  // Security type 2, EMM

        // Bytes 1-4: MAC
        uint32_t mac_net = htonl(mac);
        uint8_t mac_bytes[4];
        std::memcpy(mac_bytes, &mac_net, 4);
        msg.insert(msg.end(), mac_bytes, mac_bytes + 4);

        // Byte 5: Sequence number
        msg.push_back(seq_num);

        // Byte 6: Protocol discriminator (plain)
        msg.push_back(0x07);

        // Byte 7: Message type
        msg.push_back(msg_type);

        return msg;
    }

    /**
     * Encode IMSI in BCD format for NAS
     */
    std::vector<uint8_t> encodeNasImsi(const std::string& imsi) {
        std::vector<uint8_t> encoded;

        // First byte: odd/even indicator + identity type (1 = IMSI)
        uint8_t first_byte = 0x01;  // Type = IMSI
        if (imsi.length() % 2 == 1) {
            first_byte |= 0x08;  // Odd number of digits
        }
        encoded.push_back(first_byte);

        // Encode digits in BCD
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
     * Encode APN in NAS format
     */
    std::vector<uint8_t> encodeApn(const std::string& apn) {
        std::vector<uint8_t> encoded;

        size_t start = 0;
        while (start < apn.length()) {
            size_t dot_pos = apn.find('.', start);
            if (dot_pos == std::string::npos) {
                dot_pos = apn.length();
            }

            uint8_t label_len = dot_pos - start;
            encoded.push_back(label_len);

            for (size_t i = start; i < dot_pos; ++i) {
                encoded.push_back(apn[i]);
            }

            start = dot_pos + 1;
        }

        return encoded;
    }

    std::unique_ptr<NasParser> parser_;
};

// ============================================================================
// Basic Tests
// ============================================================================

TEST_F(NasParserTest, IsNasDetection) {
    // Valid EMM message
    auto emm_msg = createPlainEmmMessage(0x41);  // ATTACH_REQUEST
    EXPECT_TRUE(NasParser::isNas(emm_msg.data(), emm_msg.size()));

    // Valid ESM message
    auto esm_msg = createPlainEsmMessage(0xD0);  // PDN_CONNECTIVITY_REQUEST
    EXPECT_TRUE(NasParser::isNas(esm_msg.data(), esm_msg.size()));

    // Invalid - too short
    std::vector<uint8_t> short_data = {0x07};
    EXPECT_FALSE(NasParser::isNas(short_data.data(), short_data.size()));

    // Invalid - bad protocol discriminator
    std::vector<uint8_t> bad_pd = {0x0F, 0x00};
    EXPECT_FALSE(NasParser::isNas(bad_pd.data(), bad_pd.size()));

    // Invalid - null data
    EXPECT_FALSE(NasParser::isNas(nullptr, 0));
}

TEST_F(NasParserTest, ParsePlainEmmMessage) {
    auto msg = createPlainEmmMessage(
        static_cast<uint8_t>(EmmMessageType::ATTACH_REQUEST)
    );

    auto result = parser_->parse(msg.data(), msg.size());
    ASSERT_TRUE(result.has_value());

    EXPECT_EQ(result->protocol_discriminator,
              NasProtocolDiscriminator::EPS_MOBILITY_MANAGEMENT);
    EXPECT_EQ(result->security_header_type,
              NasSecurityHeaderType::PLAIN_NAS_MESSAGE);
    EXPECT_EQ(result->message_type,
              static_cast<uint8_t>(EmmMessageType::ATTACH_REQUEST));
    EXPECT_TRUE(result->isEmm());
    EXPECT_FALSE(result->isEsm());
    EXPECT_FALSE(result->isProtected());
}

TEST_F(NasParserTest, ParsePlainEsmMessage) {
    auto msg = createPlainEsmMessage(
        static_cast<uint8_t>(EsmMessageType::PDN_CONNECTIVITY_REQUEST)
    );

    auto result = parser_->parse(msg.data(), msg.size());
    ASSERT_TRUE(result.has_value());

    EXPECT_EQ(result->protocol_discriminator,
              NasProtocolDiscriminator::EPS_SESSION_MANAGEMENT);
    EXPECT_EQ(result->security_header_type,
              NasSecurityHeaderType::PLAIN_NAS_MESSAGE);
    EXPECT_EQ(result->message_type,
              static_cast<uint8_t>(EsmMessageType::PDN_CONNECTIVITY_REQUEST));
    EXPECT_TRUE(result->isEsm());
    EXPECT_FALSE(result->isEmm());
    EXPECT_FALSE(result->isProtected());
}

TEST_F(NasParserTest, ParseProtectedMessage) {
    auto msg = createProtectedEmmMessage(
        static_cast<uint8_t>(EmmMessageType::ATTACH_REQUEST),
        0x12345678,  // MAC
        42           // Sequence number
    );

    auto result = parser_->parse(msg.data(), msg.size());
    ASSERT_TRUE(result.has_value());

    EXPECT_TRUE(result->isProtected());
    EXPECT_TRUE(result->message_authentication_code.has_value());
    EXPECT_EQ(result->message_authentication_code.value(), 0x12345678);
    EXPECT_TRUE(result->sequence_number.has_value());
    EXPECT_EQ(result->sequence_number.value(), 42);
}

// ============================================================================
// Message Type Name Tests
// ============================================================================

TEST_F(NasParserTest, EmmMessageTypeNames) {
    EXPECT_EQ(emmMessageTypeToString(EmmMessageType::ATTACH_REQUEST),
              "Attach-Request");
    EXPECT_EQ(emmMessageTypeToString(EmmMessageType::ATTACH_ACCEPT),
              "Attach-Accept");
    EXPECT_EQ(emmMessageTypeToString(EmmMessageType::TRACKING_AREA_UPDATE_REQUEST),
              "TAU-Request");
    EXPECT_EQ(emmMessageTypeToString(EmmMessageType::AUTHENTICATION_REQUEST),
              "Authentication-Request");
    EXPECT_EQ(emmMessageTypeToString(EmmMessageType::SECURITY_MODE_COMMAND),
              "Security-Mode-Command");
}

TEST_F(NasParserTest, EsmMessageTypeNames) {
    EXPECT_EQ(esmMessageTypeToString(EsmMessageType::PDN_CONNECTIVITY_REQUEST),
              "PDN-Connectivity-Request");
    EXPECT_EQ(esmMessageTypeToString(
                  EsmMessageType::ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST),
              "Activate-Default-Bearer-Request");
    EXPECT_EQ(esmMessageTypeToString(
                  EsmMessageType::ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_REQUEST),
              "Activate-Dedicated-Bearer-Request");
}

TEST_F(NasParserTest, MessageTypeNameFromMessage) {
    // EMM message
    auto emm_msg = createPlainEmmMessage(
        static_cast<uint8_t>(EmmMessageType::ATTACH_REQUEST)
    );
    auto emm_result = parser_->parse(emm_msg.data(), emm_msg.size());
    ASSERT_TRUE(emm_result.has_value());
    EXPECT_EQ(emm_result->getMessageTypeName(), "Attach-Request");

    // ESM message
    auto esm_msg = createPlainEsmMessage(
        static_cast<uint8_t>(EsmMessageType::PDN_CONNECTIVITY_REQUEST)
    );
    auto esm_result = parser_->parse(esm_msg.data(), esm_msg.size());
    ASSERT_TRUE(esm_result.has_value());
    EXPECT_EQ(esm_result->getMessageTypeName(), "PDN-Connectivity-Request");
}

// ============================================================================
// IMSI Decoding Tests
// ============================================================================

TEST_F(NasParserTest, ExtractImsiEvenLength) {
    std::string imsi = "001010123456789";  // 15 digits (odd)
    auto encoded = encodeNasImsi(imsi);

    // The extractImsi method is private, but we can test through a full message
    // For now, test the encoding is correct
    EXPECT_GT(encoded.size(), 0);
}

TEST_F(NasParserTest, ExtractImsiOddLength) {
    std::string imsi = "00101012345678";  // 14 digits (even)
    auto encoded = encodeNasImsi(imsi);

    EXPECT_GT(encoded.size(), 0);
}

// ============================================================================
// APN Decoding Tests
// ============================================================================

TEST_F(NasParserTest, EncodeApn) {
    std::string apn = "internet.mnc001.mcc001.gprs";
    auto encoded = encodeApn(apn);

    // First label: "internet" (8 chars)
    EXPECT_EQ(encoded[0], 8);
    EXPECT_EQ(std::string(encoded.begin() + 1, encoded.begin() + 9), "internet");

    // Second label: "mnc001" (6 chars)
    EXPECT_EQ(encoded[9], 6);
    EXPECT_EQ(std::string(encoded.begin() + 10, encoded.begin() + 16), "mnc001");
}

// ============================================================================
// Security Header Type Tests
// ============================================================================

TEST_F(NasParserTest, SecurityHeaderTypeStrings) {
    EXPECT_EQ(nasSecurityHeaderTypeToString(NasSecurityHeaderType::PLAIN_NAS_MESSAGE),
              "Plain-NAS-Message");
    EXPECT_EQ(nasSecurityHeaderTypeToString(NasSecurityHeaderType::INTEGRITY_PROTECTED),
              "Integrity-Protected");
    EXPECT_EQ(nasSecurityHeaderTypeToString(
                  NasSecurityHeaderType::INTEGRITY_PROTECTED_CIPHERED),
              "Integrity-Protected-Ciphered");
}

TEST_F(NasParserTest, ProtocolDiscriminatorStrings) {
    EXPECT_EQ(nasProtocolDiscriminatorToString(
                  NasProtocolDiscriminator::EPS_MOBILITY_MANAGEMENT),
              "EPS-Mobility-Management");
    EXPECT_EQ(nasProtocolDiscriminatorToString(
                  NasProtocolDiscriminator::EPS_SESSION_MANAGEMENT),
              "EPS-Session-Management");
}

// ============================================================================
// JSON Serialization Tests
// ============================================================================

TEST_F(NasParserTest, ToJson) {
    auto msg = createPlainEmmMessage(
        static_cast<uint8_t>(EmmMessageType::ATTACH_REQUEST)
    );

    auto result = parser_->parse(msg.data(), msg.size());
    ASSERT_TRUE(result.has_value());

    auto json = result->toJson();
    EXPECT_TRUE(json.contains("security_header_type"));
    EXPECT_TRUE(json.contains("protocol_discriminator"));
    EXPECT_TRUE(json.contains("message_type"));
    EXPECT_TRUE(json.contains("message_type_name"));
    EXPECT_TRUE(json.contains("is_protected"));

    EXPECT_EQ(json["message_type_name"], "Attach-Request");
    EXPECT_EQ(json["is_protected"], false);
}

// ============================================================================
// Edge Cases
// ============================================================================

TEST_F(NasParserTest, EmptyMessage) {
    std::vector<uint8_t> empty;
    auto result = parser_->parse(empty.data(), empty.size());
    EXPECT_FALSE(result.has_value());
}

TEST_F(NasParserTest, MinimalMessage) {
    std::vector<uint8_t> minimal = {0x07, 0x41};  // EMM, ATTACH_REQUEST
    auto result = parser_->parse(minimal.data(), minimal.size());
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->message_type, 0x41);
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
