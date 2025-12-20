#include <gtest/gtest.h>
#include "protocol_parsers/diameter/diameter_sh.h"
#include "protocol_parsers/diameter/diameter_avp_parser.h"
#include <arpa/inet.h>

using namespace callflow::diameter;

class DiameterShParserTest : public ::testing::Test {
protected:
    DiameterShParser parser;

    // Helper to create a basic Diameter Sh message
    DiameterMessage createBasicShMessage(uint32_t command_code, bool is_request) {
        DiameterMessage msg;
        msg.header.version = 1;
        msg.header.command_code = command_code;
        msg.header.application_id = DIAMETER_SH_APPLICATION_ID;
        msg.header.request = is_request;
        msg.auth_application_id = DIAMETER_SH_APPLICATION_ID;
        return msg;
    }

    // Helper to create a uint32 AVP
    std::shared_ptr<DiameterAVP> createUint32AVP(uint32_t code, uint32_t value, bool vendor_specific = false) {
        auto avp = std::make_shared<DiameterAVP>();
        avp->code = code;
        avp->vendor_specific = vendor_specific;
        if (vendor_specific) {
            avp->vendor_id = DIAMETER_VENDOR_3GPP;
        }

        // Encode uint32 in network byte order
        uint32_t network_value = htonl(value);
        avp->data.resize(4);
        std::memcpy(avp->data.data(), &network_value, 4);
        avp->decoded_value = value;

        return avp;
    }

    // Helper to create a string AVP
    std::shared_ptr<DiameterAVP> createStringAVP(uint32_t code, const std::string& value, bool vendor_specific = false) {
        auto avp = std::make_shared<DiameterAVP>();
        avp->code = code;
        avp->vendor_specific = vendor_specific;
        if (vendor_specific) {
            avp->vendor_id = DIAMETER_VENDOR_3GPP;
        }
        avp->data.assign(value.begin(), value.end());
        avp->decoded_value = value;
        return avp;
    }

    // Helper to create a grouped AVP
    std::shared_ptr<DiameterAVP> createGroupedAVP(uint32_t code,
                                                   std::vector<std::shared_ptr<DiameterAVP>> children,
                                                   bool vendor_specific = false) {
        auto avp = std::make_shared<DiameterAVP>();
        avp->code = code;
        avp->vendor_specific = vendor_specific;
        if (vendor_specific) {
            avp->vendor_id = DIAMETER_VENDOR_3GPP;
        }
        avp->decoded_value = children;
        return avp;
    }

    // Helper to create Experimental-Result AVP
    std::shared_ptr<DiameterAVP> createExperimentalResultAVP(uint32_t result_code) {
        std::vector<std::shared_ptr<DiameterAVP>> exp_result_avps;
        exp_result_avps.push_back(createUint32AVP(
            static_cast<uint32_t>(DiameterAVPCode::VENDOR_ID), DIAMETER_VENDOR_3GPP));
        exp_result_avps.push_back(createUint32AVP(
            static_cast<uint32_t>(DiameterAVPCode::EXPERIMENTAL_RESULT_CODE), result_code));
        return createGroupedAVP(
            static_cast<uint32_t>(DiameterAVPCode::EXPERIMENTAL_RESULT),
            exp_result_avps);
    }

    // Helper to create User-Identity AVP
    std::shared_ptr<DiameterAVP> createUserIdentityAVP(const std::string& public_id,
                                                        const std::string& msisdn = "") {
        std::vector<std::shared_ptr<DiameterAVP>> identity_avps;

        if (!public_id.empty()) {
            identity_avps.push_back(createStringAVP(
                static_cast<uint32_t>(ShAVPCode::PUBLIC_IDENTITY), public_id, true));
        }

        if (!msisdn.empty()) {
            identity_avps.push_back(createStringAVP(
                static_cast<uint32_t>(ShAVPCode::MSISDN), msisdn, true));
        }

        return createGroupedAVP(
            static_cast<uint32_t>(ShAVPCode::USER_IDENTITY), identity_avps, true);
    }
};

// ============================================================================
// Basic Message Parsing Tests
// ============================================================================

TEST_F(DiameterShParserTest, IsShMessage) {
    DiameterMessage msg = createBasicShMessage(
        static_cast<uint32_t>(ShCommandCode::USER_DATA), true);
    EXPECT_TRUE(DiameterShParser::isShMessage(msg));
}

TEST_F(DiameterShParserTest, IsNotShMessage) {
    DiameterMessage msg;
    msg.header.application_id = 0;  // Not Sh
    EXPECT_FALSE(DiameterShParser::isShMessage(msg));
}

// ============================================================================
// UDR/UDA Tests (User Data Request/Answer)
// ============================================================================

TEST_F(DiameterShParserTest, ParseUDR_Basic) {
    DiameterMessage msg = createBasicShMessage(
        static_cast<uint32_t>(ShCommandCode::USER_DATA), true);

    // Add User-Identity
    msg.avps.push_back(createUserIdentityAVP("sip:user@example.com", "1234567890"));

    // Add Data-Reference
    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(ShAVPCode::DATA_REFERENCE),
        static_cast<uint32_t>(DataReference::IMS_PUBLIC_IDENTITY), true));

    // Add Service-Indication
    msg.avps.push_back(createStringAVP(
        static_cast<uint32_t>(ShAVPCode::SERVICE_INDICATION),
        "service1", true));

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->udr.has_value());

    const auto& udr = result->udr.value();
    ASSERT_EQ(udr.user_identities.size(), 1);
    EXPECT_TRUE(udr.user_identities[0].public_identity.has_value());
    EXPECT_EQ(udr.user_identities[0].public_identity.value(), "sip:user@example.com");
    EXPECT_TRUE(udr.user_identities[0].msisdn.has_value());
    EXPECT_EQ(udr.user_identities[0].msisdn.value(), "1234567890");

    ASSERT_EQ(udr.data_references.size(), 1);
    EXPECT_EQ(udr.data_references[0], DataReference::IMS_PUBLIC_IDENTITY);

    EXPECT_TRUE(udr.service_indication.has_value());
    EXPECT_EQ(udr.service_indication.value(), "service1");
}

TEST_F(DiameterShParserTest, ParseUDA_WithUserData) {
    DiameterMessage msg = createBasicShMessage(
        static_cast<uint32_t>(ShCommandCode::USER_DATA), false);

    // Add Experimental-Result
    msg.avps.push_back(createExperimentalResultAVP(2001));  // Success

    // Add User-Data (XML)
    std::string user_data_xml = "<?xml version=\"1.0\"?><ShData></ShData>";
    msg.avps.push_back(createStringAVP(
        static_cast<uint32_t>(ShAVPCode::USER_DATA),
        user_data_xml, true));

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->uda.has_value());

    const auto& uda = result->uda.value();
    EXPECT_TRUE(uda.experimental_result_code.has_value());
    EXPECT_EQ(uda.experimental_result_code.value(), 2001);

    ASSERT_TRUE(uda.user_data.has_value());
    EXPECT_EQ(uda.user_data->raw_xml, user_data_xml);
}

TEST_F(DiameterShParserTest, ParseUDR_MultipleDataReferences) {
    DiameterMessage msg = createBasicShMessage(
        static_cast<uint32_t>(ShCommandCode::USER_DATA), true);

    // Add User-Identity
    msg.avps.push_back(createUserIdentityAVP("sip:user@example.com"));

    // Add multiple Data-References
    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(ShAVPCode::DATA_REFERENCE),
        static_cast<uint32_t>(DataReference::IMS_PUBLIC_IDENTITY), true));
    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(ShAVPCode::DATA_REFERENCE),
        static_cast<uint32_t>(DataReference::IMS_USER_STATE), true));
    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(ShAVPCode::DATA_REFERENCE),
        static_cast<uint32_t>(DataReference::S_CSCF_NAME), true));

    // Add Identity-Set
    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(ShAVPCode::IDENTITY_SET),
        static_cast<uint32_t>(IdentitySet::ALL_IDENTITIES), true));

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->udr.has_value());

    const auto& udr = result->udr.value();
    ASSERT_EQ(udr.data_references.size(), 3);
    EXPECT_EQ(udr.data_references[0], DataReference::IMS_PUBLIC_IDENTITY);
    EXPECT_EQ(udr.data_references[1], DataReference::IMS_USER_STATE);
    EXPECT_EQ(udr.data_references[2], DataReference::S_CSCF_NAME);

    ASSERT_EQ(udr.identity_sets.size(), 1);
    EXPECT_EQ(udr.identity_sets[0], IdentitySet::ALL_IDENTITIES);
}

// ============================================================================
// PUR/PUA Tests (Profile Update Request/Answer)
// ============================================================================

TEST_F(DiameterShParserTest, ParsePUR_WithRepositoryData) {
    DiameterMessage msg = createBasicShMessage(
        static_cast<uint32_t>(ShCommandCode::PROFILE_UPDATE), true);

    // Add User-Identity
    msg.avps.push_back(createUserIdentityAVP("sip:user@example.com"));

    // Add User-Data
    std::string user_data_xml = "<?xml version=\"1.0\"?><RepositoryData></RepositoryData>";
    msg.avps.push_back(createStringAVP(
        static_cast<uint32_t>(ShAVPCode::USER_DATA),
        user_data_xml, true));

    // Add Data-Reference
    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(ShAVPCode::DATA_REFERENCE),
        static_cast<uint32_t>(DataReference::REPOSITORY_DATA), true));

    // Add Repository-Data-ID
    std::vector<std::shared_ptr<DiameterAVP>> repo_id_avps;
    repo_id_avps.push_back(createStringAVP(
        static_cast<uint32_t>(ShAVPCode::SERVICE_INDICATION), "service1", true));
    repo_id_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(ShAVPCode::SEQUENCE_NUMBER), 1, true));

    msg.avps.push_back(createGroupedAVP(
        static_cast<uint32_t>(ShAVPCode::REPOSITORY_DATA_ID), repo_id_avps, true));

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->pur.has_value());

    const auto& pur = result->pur.value();
    ASSERT_EQ(pur.user_identities.size(), 1);
    EXPECT_TRUE(pur.user_identities[0].public_identity.has_value());

    ASSERT_TRUE(pur.user_data.has_value());
    EXPECT_EQ(pur.user_data->raw_xml, user_data_xml);

    ASSERT_TRUE(pur.data_reference.has_value());
    EXPECT_EQ(pur.data_reference.value(), DataReference::REPOSITORY_DATA);

    ASSERT_TRUE(pur.repository_data_id.has_value());
    EXPECT_TRUE(pur.repository_data_id->service_indication.has_value());
    EXPECT_EQ(pur.repository_data_id->service_indication.value(), "service1");
    EXPECT_EQ(pur.repository_data_id->sequence_number, 1);
}

TEST_F(DiameterShParserTest, ParsePUA_Success) {
    DiameterMessage msg = createBasicShMessage(
        static_cast<uint32_t>(ShCommandCode::PROFILE_UPDATE), false);

    // Add Experimental-Result
    msg.avps.push_back(createExperimentalResultAVP(2001));  // Success

    // Add Repository-Data-ID
    std::vector<std::shared_ptr<DiameterAVP>> repo_id_avps;
    repo_id_avps.push_back(createStringAVP(
        static_cast<uint32_t>(ShAVPCode::SERVICE_INDICATION), "service1", true));
    repo_id_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(ShAVPCode::SEQUENCE_NUMBER), 1, true));

    msg.avps.push_back(createGroupedAVP(
        static_cast<uint32_t>(ShAVPCode::REPOSITORY_DATA_ID), repo_id_avps, true));

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->pua.has_value());

    const auto& pua = result->pua.value();
    EXPECT_TRUE(pua.experimental_result_code.has_value());
    EXPECT_EQ(pua.experimental_result_code.value(), 2001);

    ASSERT_TRUE(pua.repository_data_id.has_value());
    EXPECT_EQ(pua.repository_data_id->sequence_number, 1);
}

// ============================================================================
// SNR/SNA Tests (Subscribe Notifications Request/Answer)
// ============================================================================

TEST_F(DiameterShParserTest, ParseSNR_Subscribe) {
    DiameterMessage msg = createBasicShMessage(
        static_cast<uint32_t>(ShCommandCode::SUBSCRIBE_NOTIFICATIONS), true);

    // Add User-Identity
    msg.avps.push_back(createUserIdentityAVP("sip:user@example.com"));

    // Add Subs-Req-Type
    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(ShAVPCode::SUBS_REQ_TYPE),
        static_cast<uint32_t>(SubscriptionRequestType::SUBSCRIBE), true));

    // Add Data-References
    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(ShAVPCode::DATA_REFERENCE),
        static_cast<uint32_t>(DataReference::IMS_USER_STATE), true));
    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(ShAVPCode::DATA_REFERENCE),
        static_cast<uint32_t>(DataReference::S_CSCF_NAME), true));

    // Add Service-Indication
    msg.avps.push_back(createStringAVP(
        static_cast<uint32_t>(ShAVPCode::SERVICE_INDICATION),
        "service1", true));

    // Add Send-Data-Indication
    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(ShAVPCode::SEND_DATA_INDICATION),
        static_cast<uint32_t>(SendDataIndication::USER_DATA_REQUESTED), true));

    // Add Server-Name
    msg.avps.push_back(createStringAVP(
        static_cast<uint32_t>(ShAVPCode::SERVER_NAME),
        "as1.example.com", true));

    // Add DSAI-Tags
    msg.avps.push_back(createStringAVP(
        static_cast<uint32_t>(ShAVPCode::DSAI_TAG), "tag1", true));
    msg.avps.push_back(createStringAVP(
        static_cast<uint32_t>(ShAVPCode::DSAI_TAG), "tag2", true));

    // Add Expiry-Time
    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(ShAVPCode::EXPIRY_TIME), 3600, true));

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->snr.has_value());

    const auto& snr = result->snr.value();
    ASSERT_EQ(snr.user_identities.size(), 1);

    ASSERT_TRUE(snr.subs_req_type.has_value());
    EXPECT_EQ(snr.subs_req_type.value(), SubscriptionRequestType::SUBSCRIBE);

    ASSERT_EQ(snr.data_references.size(), 2);
    EXPECT_EQ(snr.data_references[0], DataReference::IMS_USER_STATE);
    EXPECT_EQ(snr.data_references[1], DataReference::S_CSCF_NAME);

    EXPECT_TRUE(snr.service_indication.has_value());
    EXPECT_EQ(snr.service_indication.value(), "service1");

    ASSERT_TRUE(snr.send_data_indication.has_value());
    EXPECT_EQ(snr.send_data_indication.value(), SendDataIndication::USER_DATA_REQUESTED);

    EXPECT_TRUE(snr.server_name.has_value());
    EXPECT_EQ(snr.server_name.value(), "as1.example.com");

    ASSERT_TRUE(snr.dsai_tags.has_value());
    ASSERT_EQ(snr.dsai_tags->size(), 2);
    EXPECT_EQ((*snr.dsai_tags)[0], "tag1");
    EXPECT_EQ((*snr.dsai_tags)[1], "tag2");

    EXPECT_TRUE(snr.expiry_time.has_value());
    EXPECT_EQ(snr.expiry_time.value(), 3600);
}

TEST_F(DiameterShParserTest, ParseSNA_Success) {
    DiameterMessage msg = createBasicShMessage(
        static_cast<uint32_t>(ShCommandCode::SUBSCRIBE_NOTIFICATIONS), false);

    // Add Experimental-Result
    msg.avps.push_back(createExperimentalResultAVP(2001));  // Success

    // Add User-Data
    std::string user_data_xml = "<?xml version=\"1.0\"?><ShData></ShData>";
    msg.avps.push_back(createStringAVP(
        static_cast<uint32_t>(ShAVPCode::USER_DATA),
        user_data_xml, true));

    // Add Expiry-Time
    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(ShAVPCode::EXPIRY_TIME), 3600, true));

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->sna.has_value());

    const auto& sna = result->sna.value();
    EXPECT_TRUE(sna.experimental_result_code.has_value());
    EXPECT_EQ(sna.experimental_result_code.value(), 2001);

    ASSERT_TRUE(sna.user_data.has_value());
    EXPECT_EQ(sna.user_data->raw_xml, user_data_xml);

    EXPECT_TRUE(sna.expiry_time.has_value());
    EXPECT_EQ(sna.expiry_time.value(), 3600);
}

// ============================================================================
// PNR/PNA Tests (Push Notification Request/Answer)
// ============================================================================

TEST_F(DiameterShParserTest, ParsePNR_DataChange) {
    DiameterMessage msg = createBasicShMessage(
        static_cast<uint32_t>(ShCommandCode::PUSH_NOTIFICATION), true);

    // Add User-Identity
    msg.avps.push_back(createUserIdentityAVP("sip:user@example.com"));

    // Add User-Data
    std::string user_data_xml = "<?xml version=\"1.0\"?><ShData><ChangedData/></ShData>";
    msg.avps.push_back(createStringAVP(
        static_cast<uint32_t>(ShAVPCode::USER_DATA),
        user_data_xml, true));

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->pnr.has_value());

    const auto& pnr = result->pnr.value();
    ASSERT_EQ(pnr.user_identities.size(), 1);
    EXPECT_TRUE(pnr.user_identities[0].public_identity.has_value());
    EXPECT_EQ(pnr.user_identities[0].public_identity.value(), "sip:user@example.com");

    ASSERT_TRUE(pnr.user_data.has_value());
    EXPECT_EQ(pnr.user_data->raw_xml, user_data_xml);
}

TEST_F(DiameterShParserTest, ParsePNA_Success) {
    DiameterMessage msg = createBasicShMessage(
        static_cast<uint32_t>(ShCommandCode::PUSH_NOTIFICATION), false);

    // Add Experimental-Result
    msg.avps.push_back(createExperimentalResultAVP(2001));  // Success

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->pna.has_value());

    const auto& pna = result->pna.value();
    EXPECT_TRUE(pna.experimental_result_code.has_value());
    EXPECT_EQ(pna.experimental_result_code.value(), 2001);
}

// ============================================================================
// User Identity Tests
// ============================================================================

TEST_F(DiameterShParserTest, ParseUserIdentity_PublicOnly) {
    DiameterMessage msg = createBasicShMessage(
        static_cast<uint32_t>(ShCommandCode::USER_DATA), true);

    msg.avps.push_back(createUserIdentityAVP("sip:user@example.com"));
    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(ShAVPCode::DATA_REFERENCE),
        static_cast<uint32_t>(DataReference::IMS_PUBLIC_IDENTITY), true));

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->udr.has_value());

    const auto& udr = result->udr.value();
    ASSERT_EQ(udr.user_identities.size(), 1);
    EXPECT_TRUE(udr.user_identities[0].public_identity.has_value());
    EXPECT_EQ(udr.user_identities[0].public_identity.value(), "sip:user@example.com");
    EXPECT_FALSE(udr.user_identities[0].msisdn.has_value());
}

TEST_F(DiameterShParserTest, ParseUserIdentity_WithMSISDN) {
    DiameterMessage msg = createBasicShMessage(
        static_cast<uint32_t>(ShCommandCode::USER_DATA), true);

    msg.avps.push_back(createUserIdentityAVP("sip:user@example.com", "1234567890"));
    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(ShAVPCode::DATA_REFERENCE),
        static_cast<uint32_t>(DataReference::MSISDN), true));

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->udr.has_value());

    const auto& udr = result->udr.value();
    ASSERT_EQ(udr.user_identities.size(), 1);
    EXPECT_TRUE(udr.user_identities[0].public_identity.has_value());
    EXPECT_TRUE(udr.user_identities[0].msisdn.has_value());
    EXPECT_EQ(udr.user_identities[0].msisdn.value(), "1234567890");
}

// ============================================================================
// JSON Serialization Tests
// ============================================================================

TEST_F(DiameterShParserTest, UDR_ToJson) {
    DiameterMessage msg = createBasicShMessage(
        static_cast<uint32_t>(ShCommandCode::USER_DATA), true);

    msg.avps.push_back(createUserIdentityAVP("sip:user@example.com"));
    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(ShAVPCode::DATA_REFERENCE),
        static_cast<uint32_t>(DataReference::IMS_PUBLIC_IDENTITY), true));

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());

    auto json = result->toJson();
    EXPECT_EQ(json["interface"], "Sh");
    ASSERT_TRUE(json.contains("udr"));
    ASSERT_TRUE(json["udr"].contains("user_identities"));
    EXPECT_EQ(json["udr"]["user_identities"].size(), 1);
}

TEST_F(DiameterShParserTest, SNR_ToJson) {
    DiameterMessage msg = createBasicShMessage(
        static_cast<uint32_t>(ShCommandCode::SUBSCRIBE_NOTIFICATIONS), true);

    msg.avps.push_back(createUserIdentityAVP("sip:user@example.com"));
    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(ShAVPCode::SUBS_REQ_TYPE),
        static_cast<uint32_t>(SubscriptionRequestType::SUBSCRIBE), true));
    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(ShAVPCode::DATA_REFERENCE),
        static_cast<uint32_t>(DataReference::IMS_USER_STATE), true));

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());

    auto json = result->toJson();
    EXPECT_EQ(json["interface"], "Sh");
    ASSERT_TRUE(json.contains("snr"));
    EXPECT_EQ(json["snr"]["subs_req_type"], "SUBSCRIBE");
}
