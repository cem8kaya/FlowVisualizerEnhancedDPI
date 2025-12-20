#include <gtest/gtest.h>
#include "protocol_parsers/diameter/diameter_cx.h"
#include "protocol_parsers/diameter/diameter_avp_parser.h"
#include <arpa/inet.h>

using namespace callflow::diameter;

class DiameterCxParserTest : public ::testing::Test {
protected:
    DiameterCxParser parser;

    // Helper to create a basic Diameter Cx message
    DiameterMessage createBasicCxMessage(uint32_t command_code, bool is_request) {
        DiameterMessage msg;
        msg.header.version = 1;
        msg.header.command_code = command_code;
        msg.header.application_id = DIAMETER_CX_APPLICATION_ID;
        msg.header.request = is_request;
        msg.auth_application_id = DIAMETER_CX_APPLICATION_ID;
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
};

// ============================================================================
// Basic Message Parsing Tests
// ============================================================================

TEST_F(DiameterCxParserTest, IsCxMessage) {
    DiameterMessage msg = createBasicCxMessage(
        static_cast<uint32_t>(CxDxCommandCode::USER_AUTHORIZATION), true);
    EXPECT_TRUE(DiameterCxParser::isCxMessage(msg));
}

TEST_F(DiameterCxParserTest, IsNotCxMessage) {
    DiameterMessage msg;
    msg.header.application_id = 0;  // Not Cx
    EXPECT_FALSE(DiameterCxParser::isCxMessage(msg));
}

// ============================================================================
// UAR/UAA Tests (User Authorization)
// ============================================================================

TEST_F(DiameterCxParserTest, ParseUAR_Basic) {
    DiameterMessage msg = createBasicCxMessage(
        static_cast<uint32_t>(CxDxCommandCode::USER_AUTHORIZATION), true);

    // Add Public-Identity
    msg.avps.push_back(createStringAVP(
        static_cast<uint32_t>(CxDxAVPCode::PUBLIC_IDENTITY),
        "sip:user@example.com", true));

    // Add Visited-Network-Identifier
    msg.avps.push_back(createStringAVP(
        static_cast<uint32_t>(CxDxAVPCode::VISITED_NETWORK_IDENTIFIER),
        "visited.network.com", true));

    // Add User-Authorization-Type
    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(CxDxAVPCode::USER_AUTHORIZATION_TYPE),
        static_cast<uint32_t>(UserAuthorizationType::REGISTRATION), true));

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->uar.has_value());

    const auto& uar = result->uar.value();
    EXPECT_EQ(uar.public_identity, "sip:user@example.com");
    EXPECT_TRUE(uar.visited_network_identifier.has_value());
    EXPECT_EQ(uar.visited_network_identifier.value(), "visited.network.com");
    EXPECT_TRUE(uar.user_authorization_type.has_value());
    EXPECT_EQ(uar.user_authorization_type.value(), UserAuthorizationType::REGISTRATION);
}

TEST_F(DiameterCxParserTest, ParseUAA_WithServerCapabilities) {
    DiameterMessage msg = createBasicCxMessage(
        static_cast<uint32_t>(CxDxCommandCode::USER_AUTHORIZATION), false);

    // Add Experimental-Result
    msg.avps.push_back(createExperimentalResultAVP(
        static_cast<uint32_t>(CxDxExperimentalResultCode::DIAMETER_FIRST_REGISTRATION)));

    // Create Server-Capabilities
    std::vector<std::shared_ptr<DiameterAVP>> cap_avps;
    cap_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(CxDxAVPCode::MANDATORY_CAPABILITY), 1, true));
    cap_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(CxDxAVPCode::OPTIONAL_CAPABILITY), 2, true));
    cap_avps.push_back(createStringAVP(
        static_cast<uint32_t>(CxDxAVPCode::SERVER_NAME), "scscf1.ims.com", true));

    msg.avps.push_back(createGroupedAVP(
        static_cast<uint32_t>(CxDxAVPCode::SERVER_CAPABILITIES), cap_avps, true));

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->uaa.has_value());

    const auto& uaa = result->uaa.value();
    EXPECT_TRUE(uaa.experimental_result_code.has_value());
    EXPECT_EQ(uaa.experimental_result_code.value(),
              static_cast<uint32_t>(CxDxExperimentalResultCode::DIAMETER_FIRST_REGISTRATION));

    ASSERT_TRUE(uaa.server_capabilities.has_value());
    const auto& caps = uaa.server_capabilities.value();
    EXPECT_EQ(caps.mandatory_capabilities.size(), 1);
    EXPECT_EQ(caps.mandatory_capabilities[0], 1);
    EXPECT_EQ(caps.optional_capabilities.size(), 1);
    EXPECT_EQ(caps.optional_capabilities[0], 2);
    EXPECT_EQ(caps.server_names.size(), 1);
    EXPECT_EQ(caps.server_names[0], "scscf1.ims.com");
}

// ============================================================================
// SAR/SAA Tests (Server Assignment)
// ============================================================================

TEST_F(DiameterCxParserTest, ParseSAR_Registration) {
    DiameterMessage msg = createBasicCxMessage(
        static_cast<uint32_t>(CxDxCommandCode::SERVER_ASSIGNMENT), true);

    // Add Public-Identity
    msg.avps.push_back(createStringAVP(
        static_cast<uint32_t>(CxDxAVPCode::PUBLIC_IDENTITY),
        "sip:user@example.com", true));

    // Add Server-Name
    msg.avps.push_back(createStringAVP(
        static_cast<uint32_t>(CxDxAVPCode::SERVER_NAME),
        "scscf1.ims.com", true));

    // Add User-Name (Private Identity)
    msg.avps.push_back(createStringAVP(
        static_cast<uint32_t>(DiameterAVPCode::USER_NAME),
        "user@example.com"));

    // Add Server-Assignment-Type
    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(CxDxAVPCode::SERVER_ASSIGNMENT_TYPE),
        static_cast<uint32_t>(ServerAssignmentType::REGISTRATION), true));

    // Add User-Data-Already-Available
    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(CxDxAVPCode::USER_DATA_ALREADY_AVAILABLE),
        static_cast<uint32_t>(UserDataAlreadyAvailable::USER_DATA_NOT_AVAILABLE), true));

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->sar.has_value());

    const auto& sar = result->sar.value();
    EXPECT_EQ(sar.public_identity, "sip:user@example.com");
    EXPECT_EQ(sar.server_name, "scscf1.ims.com");
    EXPECT_TRUE(sar.user_name.has_value());
    EXPECT_EQ(sar.user_name.value(), "user@example.com");
    EXPECT_TRUE(sar.server_assignment_type.has_value());
    EXPECT_EQ(sar.server_assignment_type.value(), ServerAssignmentType::REGISTRATION);
    EXPECT_TRUE(sar.user_data_already_available.has_value());
    EXPECT_EQ(sar.user_data_already_available.value(),
              UserDataAlreadyAvailable::USER_DATA_NOT_AVAILABLE);
}

TEST_F(DiameterCxParserTest, ParseSAA_WithUserData) {
    DiameterMessage msg = createBasicCxMessage(
        static_cast<uint32_t>(CxDxCommandCode::SERVER_ASSIGNMENT), false);

    // Add Experimental-Result
    msg.avps.push_back(createExperimentalResultAVP(
        static_cast<uint32_t>(CxDxExperimentalResultCode::DIAMETER_FIRST_REGISTRATION)));

    // Add User-Data (XML)
    std::string user_data_xml = "<?xml version=\"1.0\"?><IMSSubscription></IMSSubscription>";
    msg.avps.push_back(createStringAVP(
        static_cast<uint32_t>(CxDxAVPCode::USER_DATA),
        user_data_xml, true));

    // Add Charging-Information
    std::vector<std::shared_ptr<DiameterAVP>> charging_avps;
    charging_avps.push_back(createStringAVP(
        static_cast<uint32_t>(CxDxAVPCode::PRIMARY_EVENT_CHARGING_FUNCTION_NAME),
        "ecf1.ims.com", true));
    charging_avps.push_back(createStringAVP(
        static_cast<uint32_t>(CxDxAVPCode::SECONDARY_EVENT_CHARGING_FUNCTION_NAME),
        "ecf2.ims.com", true));

    msg.avps.push_back(createGroupedAVP(
        static_cast<uint32_t>(CxDxAVPCode::CHARGING_INFORMATION), charging_avps, true));

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->saa.has_value());

    const auto& saa = result->saa.value();
    EXPECT_TRUE(saa.experimental_result_code.has_value());

    ASSERT_TRUE(saa.user_data.has_value());
    EXPECT_EQ(saa.user_data->raw_xml, user_data_xml);

    ASSERT_TRUE(saa.charging_information.has_value());
    const auto& charging = saa.charging_information.value();
    EXPECT_TRUE(charging.primary_event_charging_function_name.has_value());
    EXPECT_EQ(charging.primary_event_charging_function_name.value(), "ecf1.ims.com");
    EXPECT_TRUE(charging.secondary_event_charging_function_name.has_value());
    EXPECT_EQ(charging.secondary_event_charging_function_name.value(), "ecf2.ims.com");
}

// ============================================================================
// LIR/LIA Tests (Location Info)
// ============================================================================

TEST_F(DiameterCxParserTest, ParseLIR_Basic) {
    DiameterMessage msg = createBasicCxMessage(
        static_cast<uint32_t>(CxDxCommandCode::LOCATION_INFO), true);

    // Add Public-Identity
    msg.avps.push_back(createStringAVP(
        static_cast<uint32_t>(CxDxAVPCode::PUBLIC_IDENTITY),
        "sip:user@example.com", true));

    // Add Originating-Request
    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(CxDxAVPCode::ORIGINATING_REQUEST), 0, true));

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->lir.has_value());

    const auto& lir = result->lir.value();
    EXPECT_EQ(lir.public_identity, "sip:user@example.com");
    EXPECT_TRUE(lir.originating_request.has_value());
    EXPECT_EQ(lir.originating_request.value(), 0);
}

TEST_F(DiameterCxParserTest, ParseLIA_WithServerName) {
    DiameterMessage msg = createBasicCxMessage(
        static_cast<uint32_t>(CxDxCommandCode::LOCATION_INFO), false);

    // Add Experimental-Result
    msg.avps.push_back(createExperimentalResultAVP(
        static_cast<uint32_t>(CxDxExperimentalResultCode::DIAMETER_SUCCESS_SERVER_NAME_NOT_STORED)));

    // Add Server-Name
    msg.avps.push_back(createStringAVP(
        static_cast<uint32_t>(CxDxAVPCode::SERVER_NAME),
        "scscf1.ims.com", true));

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->lia.has_value());

    const auto& lia = result->lia.value();
    EXPECT_TRUE(lia.experimental_result_code.has_value());
    EXPECT_TRUE(lia.server_name.has_value());
    EXPECT_EQ(lia.server_name.value(), "scscf1.ims.com");
}

// ============================================================================
// MAR/MAA Tests (Multimedia Auth)
// ============================================================================

TEST_F(DiameterCxParserTest, ParseMAR_Basic) {
    DiameterMessage msg = createBasicCxMessage(
        static_cast<uint32_t>(CxDxCommandCode::MULTIMEDIA_AUTH), true);

    // Add Public-Identity
    msg.avps.push_back(createStringAVP(
        static_cast<uint32_t>(CxDxAVPCode::PUBLIC_IDENTITY),
        "sip:user@example.com", true));

    // Add User-Name
    msg.avps.push_back(createStringAVP(
        static_cast<uint32_t>(DiameterAVPCode::USER_NAME),
        "user@example.com"));

    // Add Server-Name
    msg.avps.push_back(createStringAVP(
        static_cast<uint32_t>(CxDxAVPCode::SERVER_NAME),
        "scscf1.ims.com", true));

    // Add SIP-Number-Auth-Items
    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(CxDxAVPCode::SIP_NUMBER_AUTH_ITEMS), 1, true));

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->mar.has_value());

    const auto& mar = result->mar.value();
    EXPECT_EQ(mar.public_identity, "sip:user@example.com");
    EXPECT_EQ(mar.user_name, "user@example.com");
    EXPECT_TRUE(mar.server_name.has_value());
    EXPECT_EQ(mar.server_name.value(), "scscf1.ims.com");
    EXPECT_TRUE(mar.sip_number_auth_items.has_value());
    EXPECT_EQ(mar.sip_number_auth_items.value(), 1);
}

TEST_F(DiameterCxParserTest, ParseMAA_WithAuthVectors) {
    DiameterMessage msg = createBasicCxMessage(
        static_cast<uint32_t>(CxDxCommandCode::MULTIMEDIA_AUTH), false);

    // Add Experimental-Result
    msg.avps.push_back(createExperimentalResultAVP(
        static_cast<uint32_t>(CxDxExperimentalResultCode::DIAMETER_FIRST_REGISTRATION)));

    // Add User-Name
    msg.avps.push_back(createStringAVP(
        static_cast<uint32_t>(DiameterAVPCode::USER_NAME),
        "user@example.com"));

    // Create SIP-Auth-Data-Item
    std::vector<std::shared_ptr<DiameterAVP>> auth_item_avps;
    auth_item_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(CxDxAVPCode::SIP_ITEM_NUMBER), 1, true));
    auth_item_avps.push_back(createStringAVP(
        static_cast<uint32_t>(CxDxAVPCode::SIP_AUTHENTICATION_SCHEME),
        "Digest-AKAv1-MD5", true));
    auth_item_avps.push_back(createStringAVP(
        static_cast<uint32_t>(CxDxAVPCode::SIP_AUTHENTICATE),
        "challenge_data", true));
    auth_item_avps.push_back(createStringAVP(
        static_cast<uint32_t>(CxDxAVPCode::CONFIDENTIALITY_KEY),
        "0123456789ABCDEF", true));
    auth_item_avps.push_back(createStringAVP(
        static_cast<uint32_t>(CxDxAVPCode::INTEGRITY_KEY),
        "FEDCBA9876543210", true));

    auto auth_item = createGroupedAVP(
        static_cast<uint32_t>(CxDxAVPCode::SIP_AUTH_DATA_ITEM), auth_item_avps, true);

    // Create SIP-Number-Auth-Items
    std::vector<std::shared_ptr<DiameterAVP>> num_auth_avps;
    num_auth_avps.push_back(auth_item);

    msg.avps.push_back(createGroupedAVP(
        static_cast<uint32_t>(CxDxAVPCode::SIP_NUMBER_AUTH_ITEMS), num_auth_avps, true));

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->maa.has_value());

    const auto& maa = result->maa.value();
    EXPECT_TRUE(maa.user_name.has_value());
    EXPECT_EQ(maa.user_name.value(), "user@example.com");

    ASSERT_TRUE(maa.sip_number_auth_items.has_value());
    const auto& auth_items = maa.sip_number_auth_items.value();
    ASSERT_EQ(auth_items.auth_data_items.size(), 1);

    const auto& item = auth_items.auth_data_items[0];
    EXPECT_EQ(item.sip_item_number, 1);
    EXPECT_TRUE(item.sip_authentication_scheme.has_value());
    EXPECT_EQ(item.sip_authentication_scheme.value(), "Digest-AKAv1-MD5");
    EXPECT_TRUE(item.confidentiality_key.has_value());
    EXPECT_EQ(item.confidentiality_key.value(), "0123456789ABCDEF");
    EXPECT_TRUE(item.integrity_key.has_value());
    EXPECT_EQ(item.integrity_key.value(), "FEDCBA9876543210");
}

// ============================================================================
// RTR/RTA Tests (Registration Termination)
// ============================================================================

TEST_F(DiameterCxParserTest, ParseRTR_WithDeregistrationReason) {
    DiameterMessage msg = createBasicCxMessage(
        static_cast<uint32_t>(CxDxCommandCode::REGISTRATION_TERMINATION), true);

    // Create Deregistration-Reason
    std::vector<std::shared_ptr<DiameterAVP>> dereg_avps;
    dereg_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(CxDxAVPCode::REASON_CODE),
        static_cast<uint32_t>(ReasonCode::PERMANENT_TERMINATION), true));
    dereg_avps.push_back(createStringAVP(
        static_cast<uint32_t>(CxDxAVPCode::REASON_INFO),
        "User deregistered", true));

    msg.avps.push_back(createGroupedAVP(
        static_cast<uint32_t>(CxDxAVPCode::DEREGISTRATION_REASON), dereg_avps, true));

    // Add User-Name
    msg.avps.push_back(createStringAVP(
        static_cast<uint32_t>(DiameterAVPCode::USER_NAME),
        "user@example.com"));

    // Add Public-Identities
    msg.avps.push_back(createStringAVP(
        static_cast<uint32_t>(CxDxAVPCode::PUBLIC_IDENTITY),
        "sip:user@example.com", true));

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->rtr.has_value());

    const auto& rtr = result->rtr.value();
    ASSERT_TRUE(rtr.deregistration_reason.has_value());
    const auto& reason = rtr.deregistration_reason.value();
    EXPECT_EQ(reason.reason_code, static_cast<uint32_t>(ReasonCode::PERMANENT_TERMINATION));
    EXPECT_TRUE(reason.reason_info.has_value());
    EXPECT_EQ(reason.reason_info.value(), "User deregistered");
    EXPECT_TRUE(rtr.user_name.has_value());
    EXPECT_EQ(rtr.public_identities.size(), 1);
}

TEST_F(DiameterCxParserTest, ParseRTA_Success) {
    DiameterMessage msg = createBasicCxMessage(
        static_cast<uint32_t>(CxDxCommandCode::REGISTRATION_TERMINATION), false);

    // Add Experimental-Result
    msg.avps.push_back(createExperimentalResultAVP(
        static_cast<uint32_t>(CxDxExperimentalResultCode::DIAMETER_FIRST_REGISTRATION)));

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->rta.has_value());

    const auto& rta = result->rta.value();
    EXPECT_TRUE(rta.experimental_result_code.has_value());
}

// ============================================================================
// PPR/PPA Tests (Push Profile)
// ============================================================================

TEST_F(DiameterCxParserTest, ParsePPR_WithUserData) {
    DiameterMessage msg = createBasicCxMessage(
        static_cast<uint32_t>(CxDxCommandCode::PUSH_PROFILE), true);

    // Add User-Name
    msg.avps.push_back(createStringAVP(
        static_cast<uint32_t>(DiameterAVPCode::USER_NAME),
        "user@example.com"));

    // Add User-Data
    std::string user_data_xml = "<?xml version=\"1.0\"?><IMSSubscription></IMSSubscription>";
    msg.avps.push_back(createStringAVP(
        static_cast<uint32_t>(CxDxAVPCode::USER_DATA),
        user_data_xml, true));

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->ppr.has_value());

    const auto& ppr = result->ppr.value();
    EXPECT_TRUE(ppr.user_name.has_value());
    EXPECT_EQ(ppr.user_name.value(), "user@example.com");
    ASSERT_TRUE(ppr.user_data.has_value());
    EXPECT_EQ(ppr.user_data->raw_xml, user_data_xml);
}

TEST_F(DiameterCxParserTest, ParsePPA_Success) {
    DiameterMessage msg = createBasicCxMessage(
        static_cast<uint32_t>(CxDxCommandCode::PUSH_PROFILE), false);

    // Add Experimental-Result
    msg.avps.push_back(createExperimentalResultAVP(
        static_cast<uint32_t>(CxDxExperimentalResultCode::DIAMETER_FIRST_REGISTRATION)));

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->ppa.has_value());

    const auto& ppa = result->ppa.value();
    EXPECT_TRUE(ppa.experimental_result_code.has_value());
}

// ============================================================================
// JSON Serialization Tests
// ============================================================================

TEST_F(DiameterCxParserTest, UAR_ToJson) {
    DiameterMessage msg = createBasicCxMessage(
        static_cast<uint32_t>(CxDxCommandCode::USER_AUTHORIZATION), true);

    msg.avps.push_back(createStringAVP(
        static_cast<uint32_t>(CxDxAVPCode::PUBLIC_IDENTITY),
        "sip:user@example.com", true));

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());

    auto json = result->toJson();
    EXPECT_EQ(json["interface"], "Cx/Dx");
    ASSERT_TRUE(json.contains("uar"));
    EXPECT_EQ(json["uar"]["public_identity"], "sip:user@example.com");
}
