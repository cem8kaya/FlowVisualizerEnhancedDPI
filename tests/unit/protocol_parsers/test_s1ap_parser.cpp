#include <gtest/gtest.h>
#include "protocol_parsers/s1ap/s1ap_parser.h"
#include "protocol_parsers/s1ap/s1ap_ie_parser.h"
#include <vector>
#include <cstring>

using namespace callflow::s1ap;

class S1APParserTest : public ::testing::Test {
protected:
    S1APParser parser_;

    void SetUp() override {
        parser_.resetStatistics();
    }
};

// ============================================================================
// Basic Parser Tests
// ============================================================================

TEST_F(S1APParserTest, IsS1APDetection) {
    // S1AP uses SCTP port 36412 and PPID 18
    EXPECT_TRUE(S1APParser::isS1AP(36412, 18));
    EXPECT_FALSE(S1APParser::isS1AP(2152, 0));  // GTP-U
    EXPECT_FALSE(S1APParser::isS1AP(36412, 0)); // Wrong PPID
    EXPECT_FALSE(S1APParser::isS1AP(80, 18));   // Wrong port
}

TEST_F(S1APParserTest, ParseNullData) {
    auto result = parser_.parse(nullptr, 0);
    EXPECT_FALSE(result.has_value());

    const auto& stats = parser_.getStatistics();
    EXPECT_EQ(stats.parse_errors, 1);
}

TEST_F(S1APParserTest, ParseInsufficientData) {
    uint8_t data[3] = {0x00, 0x01, 0x02};
    auto result = parser_.parse(data, sizeof(data));
    EXPECT_FALSE(result.has_value());
}

TEST_F(S1APParserTest, ParseBasicS1APMessage) {
    // Simplified S1AP Initial UE Message structure
    std::vector<uint8_t> data = {
        0x00,  // PDU type: initiatingMessage
        0x0C,  // Procedure code: 12 (Initial UE Message)
        0x00,  // Criticality: reject
        0x00,  // IE list marker
    };

    auto result = parser_.parse(data.data(), data.size());
    ASSERT_TRUE(result.has_value());

    EXPECT_EQ(result->pdu_type, S1APPDUType::INITIATING_MESSAGE);
    EXPECT_EQ(result->procedure_code, 12);
    EXPECT_EQ(result->message_type, S1APMessageType::INITIAL_UE_MESSAGE);
    EXPECT_EQ(result->criticality, S1APCriticality::REJECT);
}

TEST_F(S1APParserTest, MessageTypeMapping) {
    std::vector<std::pair<uint8_t, S1APMessageType>> test_cases = {
        {12, S1APMessageType::INITIAL_UE_MESSAGE},
        {11, S1APMessageType::DOWNLINK_NAS_TRANSPORT},
        {13, S1APMessageType::UPLINK_NAS_TRANSPORT},
        {9, S1APMessageType::INITIAL_CONTEXT_SETUP},
        {23, S1APMessageType::UE_CONTEXT_RELEASE},
        {3, S1APMessageType::PATH_SWITCH_REQUEST},
    };

    for (const auto& [proc_code, expected_type] : test_cases) {
        std::vector<uint8_t> data = {
            0x00,       // PDU type
            proc_code,  // Procedure code
            0x00,       // Criticality
            0x00,       // IE list
        };

        auto result = parser_.parse(data.data(), data.size());
        ASSERT_TRUE(result.has_value()) << "Failed for procedure code " << (int)proc_code;
        EXPECT_EQ(result->message_type, expected_type)
            << "Wrong message type for procedure code " << (int)proc_code;
    }
}

// ============================================================================
// IE Parser Tests
// ============================================================================

TEST_F(S1APParserTest, ParseENB_UE_S1AP_ID) {
    // eNB-UE-S1AP-ID is 24-bit (0..16777215)
    // Simplified encoding: 3 bytes big-endian
    std::vector<uint8_t> data = {0x00, 0x12, 0x34};  // 0x001234 = 4660

    auto result = S1APIEParser::parseENB_UE_S1AP_ID(data.data(), data.size());
    ASSERT_TRUE(result.has_value());
    // Note: Actual parsing depends on ASN.1 PER encoding
}

TEST_F(S1APParserTest, ParseMME_UE_S1AP_ID) {
    // MME-UE-S1AP-ID is 32-bit
    std::vector<uint8_t> data = {0x00, 0x00, 0x56, 0x78};

    auto result = S1APIEParser::parseMME_UE_S1AP_ID(data.data(), data.size());
    ASSERT_TRUE(result.has_value());
}

TEST_F(S1APParserTest, ParseNAS_PDU) {
    // NAS-PDU is an octet string containing embedded NAS message
    std::vector<uint8_t> nas_data = {
        0x07, 0x41, 0x71, 0x08, 0x09,  // Example NAS Attach Request
        0x10, 0x20, 0x30, 0x40, 0x50
    };

    auto result = S1APIEParser::parseNAS_PDU(nas_data.data(), nas_data.size());
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), nas_data.size());
    EXPECT_EQ(*result, nas_data);
}

TEST_F(S1APParserTest, ParseTAI) {
    // TAI: PLMN (3 bytes) + TAC (2 bytes)
    std::vector<uint8_t> data = {
        0x10, 0x00, 0x10,  // PLMN: MCC=001, MNC=01
        0x00, 0x01         // TAC = 1
    };

    auto result = S1APIEParser::parseTAI(data.data(), data.size());
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->plmn_identity.length(), 5);  // "00101" for 2-digit MNC
    EXPECT_EQ(result->tac, 1);
}

TEST_F(S1APParserTest, ParseEUTRAN_CGI) {
    // E-UTRAN CGI: PLMN (3 bytes) + Cell Identity (28 bits = 4 bytes)
    std::vector<uint8_t> data = {
        0x10, 0x00, 0x10,        // PLMN: MCC=001, MNC=01
        0x00, 0x12, 0x34, 0x50   // Cell Identity (28-bit)
    };

    auto result = S1APIEParser::parseEUTRAN_CGI(data.data(), data.size());
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->plmn_identity.length(), 5);
    // Cell identity is 28-bit value
    EXPECT_GT(result->cell_identity, 0);
}

TEST_F(S1APParserTest, ParseUESecurityCapabilities) {
    std::vector<uint8_t> data = {
        0xC0, 0x00,  // Encryption algorithms bitmap
        0x80, 0x00   // Integrity algorithms bitmap
    };

    auto result = S1APIEParser::parseUESecurityCapabilities(data.data(), data.size());
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->encryption_algorithms, 0xC000);
    EXPECT_EQ(result->integrity_algorithms, 0x8000);
}

TEST_F(S1APParserTest, ParseCause) {
    std::vector<uint8_t> data = {
        0x00,  // Cause type: Radio Network
        0x05   // Cause value: 5
    };

    auto result = S1APIEParser::parseCause(data.data(), data.size());
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->first, S1APCauseType::RADIO_NETWORK);
    EXPECT_EQ(result->second, 5);
}

TEST_F(S1APParserTest, ParseRRCEstablishmentCause) {
    std::vector<uint8_t> data = {0x00};  // mo-Signalling

    auto result = S1APIEParser::parseRRCEstablishmentCause(data.data(), data.size());
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), 0);
}

// ============================================================================
// PLMN Decoding Tests
// ============================================================================

class PLMNDecodingTest : public ::testing::Test {
protected:
    std::string decodePLMN(const uint8_t* data) {
        // Access private function via public IE parser
        auto tai = S1APIEParser::parseTAI(data, 5);
        return tai.has_value() ? tai->plmn_identity : "";
    }
};

TEST_F(PLMNDecodingTest, DecodePLMN_2DigitMNC) {
    // MCC=001, MNC=01
    std::vector<uint8_t> data = {
        0x10, 0xF0, 0x10,  // PLMN with 2-digit MNC
        0x00, 0x01         // TAC
    };

    auto tai = S1APIEParser::parseTAI(data.data(), data.size());
    ASSERT_TRUE(tai.has_value());
    // PLMN should be "00101" (MCC=001, MNC=01)
    EXPECT_EQ(tai->plmn_identity.length(), 5);
}

TEST_F(PLMNDecodingTest, DecodePLMN_3DigitMNC) {
    // MCC=001, MNC=001
    std::vector<uint8_t> data = {
        0x10, 0x00, 0x11,  // PLMN with 3-digit MNC
        0x00, 0x01         // TAC
    };

    auto tai = S1APIEParser::parseTAI(data.data(), data.size());
    ASSERT_TRUE(tai.has_value());
    // PLMN should be "001001" (MCC=001, MNC=001)
    EXPECT_EQ(tai->plmn_identity.length(), 6);
}

// ============================================================================
// E-RAB Tests
// ============================================================================

TEST_F(S1APParserTest, ParseE_RAB_LevelQoSParameters) {
    std::vector<uint8_t> data = {
        0x09,  // QCI = 9 (best effort)
        0x05,  // Priority level = 5
        0x00,  // Pre-emption flags
    };

    auto result = S1APIEParser::parseE_RAB_LevelQoSParameters(data.data(), data.size());
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->qci, 9);
    EXPECT_EQ(result->arp.priority_level, 5);
}

TEST_F(S1APParserTest, ParseGTP_TEID) {
    std::vector<uint8_t> data = {0x12, 0x34, 0x56, 0x78};

    auto result = S1APIEParser::parseGTP_TEID(data.data(), data.size());
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), 0x12345678);
}

// ============================================================================
// JSON Serialization Tests
// ============================================================================

TEST_F(S1APParserTest, JSONSerialization_BasicMessage) {
    S1APMessage msg;
    msg.pdu_type = S1APPDUType::INITIATING_MESSAGE;
    msg.procedure_code = 12;
    msg.message_type = S1APMessageType::INITIAL_UE_MESSAGE;
    msg.criticality = S1APCriticality::REJECT;
    msg.enb_ue_s1ap_id = 12345;
    msg.mme_ue_s1ap_id = 67890;

    nlohmann::json j = msg.toJson();

    EXPECT_EQ(j["pdu_type"], 0);
    EXPECT_EQ(j["procedure_code"], 12);
    EXPECT_EQ(j["enb_ue_s1ap_id"], 12345);
    EXPECT_EQ(j["mme_ue_s1ap_id"], 67890);
}

TEST_F(S1APParserTest, JSONSerialization_WithNASPDU) {
    S1APMessage msg;
    msg.message_type = S1APMessageType::INITIAL_UE_MESSAGE;
    msg.nas_pdu = std::vector<uint8_t>{0x07, 0x41, 0x71, 0x08, 0x09};

    nlohmann::json j = msg.toJson();

    EXPECT_TRUE(j["nas_pdu_present"].get<bool>());
    EXPECT_EQ(j["nas_pdu_length"], 5);
}

TEST_F(S1APParserTest, JSONSerialization_WithTAI) {
    S1APMessage msg;
    msg.message_type = S1APMessageType::INITIAL_UE_MESSAGE;

    TrackingAreaIdentity tai;
    tai.plmn_identity = "00101";
    tai.tac = 1;
    msg.tai = tai;

    nlohmann::json j = msg.toJson();

    EXPECT_TRUE(j.contains("tai"));
    EXPECT_EQ(j["tai"]["plmn_identity"], "00101");
    EXPECT_EQ(j["tai"]["tac"], 1);
}

TEST_F(S1APParserTest, JSONSerialization_WithERABList) {
    S1APMessage msg;
    msg.message_type = S1APMessageType::INITIAL_CONTEXT_SETUP;

    E_RAB_ToBeSetupItem erab;
    erab.e_rab_id = 5;
    erab.qos_parameters.qci = 9;
    erab.qos_parameters.arp.priority_level = 1;
    erab.qos_parameters.arp.pre_emption_capability = true;
    erab.qos_parameters.arp.pre_emption_vulnerability = false;
    erab.transport_layer_address = {192, 168, 1, 100};
    erab.gtp_teid = 0x12345678;

    msg.e_rab_to_be_setup_list.push_back(erab);

    nlohmann::json j = msg.toJson();

    EXPECT_TRUE(j.contains("e_rab_to_be_setup_list"));
    EXPECT_EQ(j["e_rab_to_be_setup_list"].size(), 1);
    EXPECT_EQ(j["e_rab_to_be_setup_list"][0]["e_rab_id"], 5);
    EXPECT_EQ(j["e_rab_to_be_setup_list"][0]["gtp_teid"], 0x12345678);
    EXPECT_EQ(j["e_rab_to_be_setup_list"][0]["transport_layer_address"], "192.168.1.100");
}

// ============================================================================
// Message Type Name Tests
// ============================================================================

TEST_F(S1APParserTest, GetMessageTypeName) {
    S1APMessage msg;

    msg.message_type = S1APMessageType::INITIAL_UE_MESSAGE;
    EXPECT_EQ(msg.getMessageTypeName(), "Initial UE Message");

    msg.message_type = S1APMessageType::INITIAL_CONTEXT_SETUP;
    EXPECT_EQ(msg.getMessageTypeName(), "Initial Context Setup");

    msg.message_type = S1APMessageType::PATH_SWITCH_REQUEST;
    EXPECT_EQ(msg.getMessageTypeName(), "Path Switch Request");

    msg.message_type = S1APMessageType::UE_CONTEXT_RELEASE;
    EXPECT_EQ(msg.getMessageTypeName(), "UE Context Release");
}

// ============================================================================
// Statistics Tests
// ============================================================================

TEST_F(S1APParserTest, Statistics) {
    // Parse a valid message
    std::vector<uint8_t> data = {
        0x00,  // PDU type
        0x0C,  // Procedure code: Initial UE Message
        0x00,  // Criticality
        0x00,  // IE list
    };

    auto result = parser_.parse(data.data(), data.size());
    ASSERT_TRUE(result.has_value());

    const auto& stats = parser_.getStatistics();
    EXPECT_EQ(stats.messages_parsed, 1);
    EXPECT_EQ(stats.initial_ue_messages, 1);
    EXPECT_EQ(stats.parse_errors, 0);

    // Parse an invalid message
    parser_.parse(nullptr, 0);

    const auto& stats2 = parser_.getStatistics();
    EXPECT_EQ(stats2.parse_errors, 1);

    // Reset statistics
    parser_.resetStatistics();
    const auto& stats3 = parser_.getStatistics();
    EXPECT_EQ(stats3.messages_parsed, 0);
    EXPECT_EQ(stats3.parse_errors, 0);
}

// ============================================================================
// Integration Tests
// ============================================================================

TEST_F(S1APParserTest, ParseInitialUEMessageWithMultipleIEs) {
    // Construct a more realistic S1AP Initial UE Message with multiple IEs
    std::vector<uint8_t> data = {
        0x00,  // PDU type: initiatingMessage
        0x0C,  // Procedure code: 12 (Initial UE Message)
        0x00,  // Criticality: reject
        0x00,  // Start of IE list

        // IE 1: eNB-UE-S1AP-ID (IE 8)
        0x00, 0x08,  // IE ID = 8
        0x00,        // Criticality
        0x03,        // Length = 3
        0x00, 0x12, 0x34,  // Value = 0x001234

        // IE 2: NAS-PDU (IE 26)
        0x00, 0x1A,  // IE ID = 26
        0x00,        // Criticality
        0x05,        // Length = 5
        0x07, 0x41, 0x71, 0x08, 0x09,  // NAS Attach Request (simplified)

        // IE 3: TAI (IE 67)
        0x00, 0x43,  // IE ID = 67
        0x00,        // Criticality
        0x05,        // Length = 5
        0x10, 0xF0, 0x10,  // PLMN
        0x00, 0x01,        // TAC = 1
    };

    auto result = parser_.parse(data.data(), data.size());
    ASSERT_TRUE(result.has_value());

    EXPECT_EQ(result->message_type, S1APMessageType::INITIAL_UE_MESSAGE);
    EXPECT_TRUE(result->enb_ue_s1ap_id.has_value());
    EXPECT_TRUE(result->nas_pdu.has_value());
    EXPECT_TRUE(result->tai.has_value());

    if (result->nas_pdu.has_value()) {
        EXPECT_EQ(result->nas_pdu->size(), 5);
    }

    if (result->tai.has_value()) {
        EXPECT_EQ(result->tai->tac, 1);
    }
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
