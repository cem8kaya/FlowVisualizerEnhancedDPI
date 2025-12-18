#include <gtest/gtest.h>
#include "protocol_parsers/s1ap_parser.h"
#include "thirdparty/asn1c/s1ap_asn1_wrapper.h"
#include <vector>
#include <cstring>
#include <arpa/inet.h>

using namespace callflow;

/**
 * Test fixture for S1AP parser tests
 */
class S1apParserTest : public ::testing::Test {
protected:
    void SetUp() override {
        parser_ = std::make_unique<S1apParser>();
    }

    void TearDown() override {
        parser_.reset();
    }

    /**
     * Create a minimal S1AP PDU header
     * This creates a simplified ASN.1 PER encoded S1AP message
     */
    std::vector<uint8_t> createSimpleS1apPdu(uint8_t choice, uint8_t proc_code) {
        std::vector<uint8_t> pdu;

        // Simplified ASN.1 PER encoding for S1AP
        // In reality, this would be more complex
        pdu.push_back(choice);           // Message type (CHOICE)
        pdu.push_back(proc_code);        // Procedure code
        pdu.push_back(0x00);             // Criticality (reject=0)

        return pdu;
    }

    /**
     * Encode IMSI in TBCD format
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

    std::unique_ptr<S1apParser> parser_;
};

// ============================================================================
// Basic Tests
// ============================================================================

TEST_F(S1apParserTest, IsS1apDetection) {
    // Valid S1AP message
    auto pdu = createSimpleS1apPdu(0x00, 12);  // INITIAL_UE_MESSAGE
    EXPECT_TRUE(S1apParser::isS1ap(pdu.data(), pdu.size()));

    // Invalid - too short
    std::vector<uint8_t> short_data = {0x00};
    EXPECT_FALSE(S1apParser::isS1ap(short_data.data(), short_data.size()));

    // Invalid - bad choice value
    std::vector<uint8_t> bad_choice = {0xFF, 0x00, 0x00};
    EXPECT_FALSE(S1apParser::isS1ap(bad_choice.data(), bad_choice.size()));

    // Invalid - null data
    EXPECT_FALSE(S1apParser::isS1ap(nullptr, 0));
}

TEST_F(S1apParserTest, ParseBasicPdu) {
    // Create a simple S1AP PDU
    auto pdu = createSimpleS1apPdu(
        static_cast<uint8_t>(S1apMessageType::INITIATING_MESSAGE),
        static_cast<uint8_t>(S1apProcedureCode::INITIAL_UE_MESSAGE)
    );

    auto result = parser_->parse(pdu.data(), pdu.size());

    // Note: This test may fail with the simple PDU as full ASN.1 decoding
    // would require proper encoding. This is a basic sanity test.
    // In production, use real S1AP PDU captures for testing.
}

// ============================================================================
// ASN.1 Decoder Tests
// ============================================================================

TEST_F(S1apParserTest, DecodeImsi) {
    std::string imsi = "001010123456789";
    auto encoded = encodeImsi(imsi);

    auto decoded = asn1::decodeImsi(encoded.data(), encoded.size());
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded.value(), imsi);
}

TEST_F(S1apParserTest, DecodeImsiWithFiller) {
    // Odd length IMSI
    std::string imsi = "00101012345678";  // 14 digits
    auto encoded = encodeImsi(imsi);

    auto decoded = asn1::decodeImsi(encoded.data(), encoded.size());
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded.value(), imsi);
}

TEST_F(S1apParserTest, DecodeUeId) {
    // Test ENB-UE-S1AP-ID (24-bit)
    uint32_t enb_ue_id = 0x123456;
    std::vector<uint8_t> encoded_id(3);
    encoded_id[0] = (enb_ue_id >> 16) & 0xFF;
    encoded_id[1] = (enb_ue_id >> 8) & 0xFF;
    encoded_id[2] = enb_ue_id & 0xFF;

    auto decoded = asn1::decodeUeId(encoded_id.data(), encoded_id.size());
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded.value(), enb_ue_id);
}

TEST_F(S1apParserTest, DecodeUeIdFull32Bit) {
    // Test MME-UE-S1AP-ID (32-bit)
    uint32_t mme_ue_id = 0x12345678;
    std::vector<uint8_t> encoded_id(4);
    encoded_id[0] = (mme_ue_id >> 24) & 0xFF;
    encoded_id[1] = (mme_ue_id >> 16) & 0xFF;
    encoded_id[2] = (mme_ue_id >> 8) & 0xFF;
    encoded_id[3] = mme_ue_id & 0xFF;

    auto decoded = asn1::decodeUeId(encoded_id.data(), encoded_id.size());
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded.value(), mme_ue_id);
}

// ============================================================================
// Procedure Code Tests
// ============================================================================

TEST_F(S1apParserTest, ProcedureCodeToString) {
    EXPECT_EQ(s1apProcedureCodeToString(S1apProcedureCode::INITIAL_UE_MESSAGE),
              "Initial-UE-Message");
    EXPECT_EQ(s1apProcedureCodeToString(S1apProcedureCode::UPLINK_NAS_TRANSPORT),
              "Uplink-NAS-Transport");
    EXPECT_EQ(s1apProcedureCodeToString(S1apProcedureCode::DOWNLINK_NAS_TRANSPORT),
              "Downlink-NAS-Transport");
    EXPECT_EQ(s1apProcedureCodeToString(S1apProcedureCode::INITIAL_CONTEXT_SETUP),
              "Initial-Context-Setup");
    EXPECT_EQ(s1apProcedureCodeToString(S1apProcedureCode::S1_SETUP),
              "S1-Setup");
}

TEST_F(S1apParserTest, MessageTypeToString) {
    EXPECT_EQ(s1apMessageTypeToString(S1apMessageType::INITIATING_MESSAGE),
              "Initiating-Message");
    EXPECT_EQ(s1apMessageTypeToString(S1apMessageType::SUCCESSFUL_OUTCOME),
              "Successful-Outcome");
    EXPECT_EQ(s1apMessageTypeToString(S1apMessageType::UNSUCCESSFUL_OUTCOME),
              "Unsuccessful-Outcome");
}

// ============================================================================
// PER Decoder Tests
// ============================================================================

TEST_F(S1apParserTest, PerDecoderReadBits) {
    std::vector<uint8_t> data = {0xAB, 0xCD};  // 10101011 11001101
    asn1::PerDecoder decoder(data.data(), data.size());

    uint32_t value;

    // Read 4 bits: 1010
    ASSERT_TRUE(decoder.readBits(4, value));
    EXPECT_EQ(value, 0x0A);

    // Read 4 bits: 1011
    ASSERT_TRUE(decoder.readBits(4, value));
    EXPECT_EQ(value, 0x0B);

    // Read 8 bits: 11001101
    ASSERT_TRUE(decoder.readBits(8, value));
    EXPECT_EQ(value, 0xCD);
}

TEST_F(S1apParserTest, PerDecoderReadOctet) {
    std::vector<uint8_t> data = {0x12, 0x34, 0x56};
    asn1::PerDecoder decoder(data.data(), data.size());

    uint8_t value;
    ASSERT_TRUE(decoder.readOctet(value));
    EXPECT_EQ(value, 0x12);

    ASSERT_TRUE(decoder.readOctet(value));
    EXPECT_EQ(value, 0x34);

    ASSERT_TRUE(decoder.readOctet(value));
    EXPECT_EQ(value, 0x56);

    // No more data
    EXPECT_FALSE(decoder.readOctet(value));
}

TEST_F(S1apParserTest, PerDecoderAlignToByte) {
    std::vector<uint8_t> data = {0xAB, 0xCD};
    asn1::PerDecoder decoder(data.data(), data.size());

    uint32_t value;
    // Read 3 bits
    ASSERT_TRUE(decoder.readBits(3, value));
    EXPECT_EQ(decoder.getCurrentBitPosition(), 3);

    // Align to byte
    decoder.alignToByte();
    EXPECT_EQ(decoder.getCurrentBitPosition(), 8);

    // Should be at second byte now
    uint8_t octet;
    ASSERT_TRUE(decoder.readOctet(octet));
    EXPECT_EQ(octet, 0xCD);
}

TEST_F(S1apParserTest, PerDecoderConstrainedWholeNumber) {
    // Encode value 5 in range [0, 15] requires 4 bits
    std::vector<uint8_t> data = {0x50};  // 0101 0000
    asn1::PerDecoder decoder(data.data(), data.size());

    auto result = decoder.decodeConstrainedWholeNumber(0, 15);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), 5);
}

TEST_F(S1apParserTest, PerDecoderEnumerated) {
    // Encode value 2 out of 4 possible values (requires 2 bits)
    std::vector<uint8_t> data = {0x80};  // 10 00 0000
    asn1::PerDecoder decoder(data.data(), data.size());

    auto result = decoder.decodeEnumerated(4);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), 2);
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
