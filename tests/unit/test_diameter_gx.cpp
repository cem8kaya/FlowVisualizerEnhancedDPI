#include <gtest/gtest.h>
#include "protocol_parsers/diameter/diameter_gx.h"
#include "protocol_parsers/diameter/diameter_avp_parser.h"
#include <arpa/inet.h>

using namespace callflow::diameter;

class DiameterGxParserTest : public ::testing::Test {
protected:
    DiameterGxParser parser;

    // Helper to create a basic Diameter message
    DiameterMessage createBasicGxMessage(bool is_request) {
        DiameterMessage msg;
        msg.header.version = 1;
        msg.header.command_code = static_cast<uint32_t>(DiameterCommandCode::CREDIT_CONTROL);
        msg.header.application_id = DIAMETER_GX_APPLICATION_ID;
        msg.header.request = is_request;
        msg.auth_application_id = DIAMETER_GX_APPLICATION_ID;
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
    std::shared_ptr<DiameterAVP> createStringAVP(uint32_t code, const std::string& value) {
        auto avp = std::make_shared<DiameterAVP>();
        avp->code = code;
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
};

// ============================================================================
// Basic Message Parsing Tests
// ============================================================================

TEST_F(DiameterGxParserTest, IsGxMessage) {
    DiameterMessage msg = createBasicGxMessage(true);
    EXPECT_TRUE(DiameterGxParser::isGxMessage(msg));
}

TEST_F(DiameterGxParserTest, IsNotGxMessage) {
    DiameterMessage msg;
    msg.header.application_id = 0;  // Not Gx
    EXPECT_FALSE(DiameterGxParser::isGxMessage(msg));
}

TEST_F(DiameterGxParserTest, ParseCCR_Initial) {
    DiameterMessage msg = createBasicGxMessage(true);

    // Add CC-Request-Type (INITIAL_REQUEST = 1)
    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(DiameterAVPCode::CC_REQUEST_TYPE), 1));

    // Add CC-Request-Number
    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(DiameterAVPCode::CC_REQUEST_NUMBER), 0));

    // Add Framed-IP-Address (192.168.1.100)
    auto framed_ip_avp = std::make_shared<DiameterAVP>();
    framed_ip_avp->code = static_cast<uint32_t>(GxAVPCode::FRAMED_IP_ADDRESS);
    // IPv4 format: 2 bytes AF (0x0001) + 4 bytes IP
    framed_ip_avp->data = {0x00, 0x01, 192, 168, 1, 100};
    msg.avps.push_back(framed_ip_avp);

    // Add Called-Station-ID (APN)
    msg.avps.push_back(createStringAVP(
        static_cast<uint32_t>(GxAVPCode::CALLED_STATION_ID), "internet.apn"));

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->ccr.has_value());

    const auto& ccr = result->ccr.value();
    EXPECT_EQ(ccr.cc_request_type, CCRequestType::INITIAL_REQUEST);
    EXPECT_EQ(ccr.cc_request_number, 0);
    EXPECT_TRUE(ccr.framed_ip_address.has_value());
    EXPECT_EQ(ccr.framed_ip_address.value(), "192.168.1.100");
    EXPECT_TRUE(ccr.called_station_id.has_value());
    EXPECT_EQ(ccr.called_station_id.value(), "internet.apn");
}

TEST_F(DiameterGxParserTest, ParseCCA_Success) {
    DiameterMessage msg = createBasicGxMessage(false);
    msg.result_code = static_cast<uint32_t>(DiameterResultCode::DIAMETER_SUCCESS);

    // Add CC-Request-Type
    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(DiameterAVPCode::CC_REQUEST_TYPE), 1));

    // Add CC-Request-Number
    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(DiameterAVPCode::CC_REQUEST_NUMBER), 0));

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->cca.has_value());

    const auto& cca = result->cca.value();
    EXPECT_EQ(cca.result_code, static_cast<uint32_t>(DiameterResultCode::DIAMETER_SUCCESS));
    EXPECT_EQ(cca.cc_request_type, CCRequestType::INITIAL_REQUEST);
    EXPECT_EQ(cca.cc_request_number, 0);
}

// ============================================================================
// Charging Rule Tests
// ============================================================================

TEST_F(DiameterGxParserTest, ParseChargingRuleInstall) {
    DiameterMessage msg = createBasicGxMessage(false);
    msg.result_code = static_cast<uint32_t>(DiameterResultCode::DIAMETER_SUCCESS);

    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(DiameterAVPCode::CC_REQUEST_TYPE), 1));
    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(DiameterAVPCode::CC_REQUEST_NUMBER), 0));

    // Create a charging rule definition
    std::vector<std::shared_ptr<DiameterAVP>> rule_def_avps;
    rule_def_avps.push_back(createStringAVP(
        static_cast<uint32_t>(GxAVPCode::CHARGING_RULE_NAME), "rule1"));
    rule_def_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GxAVPCode::RATING_GROUP), 100));
    rule_def_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GxAVPCode::SERVICE_IDENTIFIER), 200));
    rule_def_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GxAVPCode::PRECEDENCE), 10));

    auto rule_def = createGroupedAVP(
        static_cast<uint32_t>(GxAVPCode::CHARGING_RULE_DEFINITION),
        rule_def_avps, true);

    // Create charging rule install
    std::vector<std::shared_ptr<DiameterAVP>> install_avps;
    install_avps.push_back(rule_def);

    auto rule_install = createGroupedAVP(
        static_cast<uint32_t>(GxAVPCode::CHARGING_RULE_INSTALL),
        install_avps, true);

    msg.avps.push_back(rule_install);

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->cca.has_value());

    const auto& cca = result->cca.value();
    ASSERT_FALSE(cca.charging_rule_install.empty());

    const auto& install = cca.charging_rule_install[0];
    ASSERT_FALSE(install.charging_rule_definition.empty());

    const auto& rule = install.charging_rule_definition[0];
    EXPECT_EQ(rule.charging_rule_name, "rule1");
    EXPECT_TRUE(rule.rating_group.has_value());
    EXPECT_EQ(rule.rating_group.value(), 100);
    EXPECT_TRUE(rule.service_identifier.has_value());
    EXPECT_EQ(rule.service_identifier.value(), 200);
    EXPECT_TRUE(rule.precedence.has_value());
    EXPECT_EQ(rule.precedence.value(), 10);
}

TEST_F(DiameterGxParserTest, ParseChargingRuleRemove) {
    DiameterMessage msg = createBasicGxMessage(false);
    msg.result_code = static_cast<uint32_t>(DiameterResultCode::DIAMETER_SUCCESS);

    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(DiameterAVPCode::CC_REQUEST_TYPE), 2));
    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(DiameterAVPCode::CC_REQUEST_NUMBER), 1));

    // Create charging rule remove
    std::vector<std::shared_ptr<DiameterAVP>> remove_avps;
    remove_avps.push_back(createStringAVP(
        static_cast<uint32_t>(GxAVPCode::CHARGING_RULE_NAME), "rule1"));
    remove_avps.push_back(createStringAVP(
        static_cast<uint32_t>(GxAVPCode::CHARGING_RULE_NAME), "rule2"));

    auto rule_remove = createGroupedAVP(
        static_cast<uint32_t>(GxAVPCode::CHARGING_RULE_REMOVE),
        remove_avps, true);

    msg.avps.push_back(rule_remove);

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->cca.has_value());

    const auto& cca = result->cca.value();
    ASSERT_FALSE(cca.charging_rule_remove.empty());

    const auto& remove = cca.charging_rule_remove[0];
    EXPECT_EQ(remove.charging_rule_name.size(), 2);
    EXPECT_EQ(remove.charging_rule_name[0], "rule1");
    EXPECT_EQ(remove.charging_rule_name[1], "rule2");
}

// ============================================================================
// QoS Tests
// ============================================================================

TEST_F(DiameterGxParserTest, ParseQoSInformation) {
    DiameterMessage msg = createBasicGxMessage(false);
    msg.result_code = static_cast<uint32_t>(DiameterResultCode::DIAMETER_SUCCESS);

    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(DiameterAVPCode::CC_REQUEST_TYPE), 1));
    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(DiameterAVPCode::CC_REQUEST_NUMBER), 0));

    // Create QoS Information
    std::vector<std::shared_ptr<DiameterAVP>> qos_avps;
    qos_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GxAVPCode::QOS_CLASS_IDENTIFIER), 9));
    qos_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GxAVPCode::MAX_REQUESTED_BANDWIDTH_UL), 1000000));
    qos_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GxAVPCode::MAX_REQUESTED_BANDWIDTH_DL), 5000000));

    auto qos_info = createGroupedAVP(
        static_cast<uint32_t>(GxAVPCode::QOS_INFORMATION),
        qos_avps, true);

    msg.avps.push_back(qos_info);

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->cca.has_value());

    const auto& cca = result->cca.value();
    ASSERT_TRUE(cca.qos_information.has_value());

    const auto& qos = cca.qos_information.value();
    EXPECT_TRUE(qos.qos_class_identifier.has_value());
    EXPECT_EQ(qos.qos_class_identifier.value(), 9);
    EXPECT_TRUE(qos.max_requested_bandwidth_ul.has_value());
    EXPECT_EQ(qos.max_requested_bandwidth_ul.value(), 1000000);
    EXPECT_TRUE(qos.max_requested_bandwidth_dl.has_value());
    EXPECT_EQ(qos.max_requested_bandwidth_dl.value(), 5000000);
}

TEST_F(DiameterGxParserTest, ParseDefaultEPSBearerQoS) {
    DiameterMessage msg = createBasicGxMessage(false);
    msg.result_code = static_cast<uint32_t>(DiameterResultCode::DIAMETER_SUCCESS);

    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(DiameterAVPCode::CC_REQUEST_TYPE), 1));
    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(DiameterAVPCode::CC_REQUEST_NUMBER), 0));

    // Create ARP
    std::vector<std::shared_ptr<DiameterAVP>> arp_avps;
    arp_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GxAVPCode::PRIORITY_LEVEL), 5));
    arp_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GxAVPCode::PRE_EMPTION_CAPABILITY), 0));
    arp_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GxAVPCode::PRE_EMPTION_VULNERABILITY), 1));

    auto arp = createGroupedAVP(
        static_cast<uint32_t>(GxAVPCode::ALLOCATION_RETENTION_PRIORITY),
        arp_avps, true);

    // Create Default EPS Bearer QoS
    std::vector<std::shared_ptr<DiameterAVP>> qos_avps;
    qos_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GxAVPCode::QOS_CLASS_IDENTIFIER), 9));
    qos_avps.push_back(arp);

    auto default_qos = createGroupedAVP(
        static_cast<uint32_t>(GxAVPCode::DEFAULT_EPS_BEARER_QOS),
        qos_avps, true);

    msg.avps.push_back(default_qos);

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->cca.has_value());

    const auto& cca = result->cca.value();
    ASSERT_TRUE(cca.default_eps_bearer_qos.has_value());

    const auto& qos = cca.default_eps_bearer_qos.value();
    EXPECT_EQ(qos.qos_class_identifier, 9);
    EXPECT_EQ(qos.allocation_retention_priority.priority_level, 5);
    EXPECT_EQ(qos.allocation_retention_priority.pre_emption_capability,
              PreemptionCapability::PRE_EMPTION_CAPABILITY_ENABLED);
    EXPECT_EQ(qos.allocation_retention_priority.pre_emption_vulnerability,
              PreemptionVulnerability::PRE_EMPTION_VULNERABILITY_DISABLED);
}

// ============================================================================
// Event Trigger Tests
// ============================================================================

TEST_F(DiameterGxParserTest, ParseEventTriggers) {
    DiameterMessage msg = createBasicGxMessage(true);

    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(DiameterAVPCode::CC_REQUEST_TYPE), 2));
    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(DiameterAVPCode::CC_REQUEST_NUMBER), 1));

    // Add multiple event triggers
    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GxAVPCode::EVENT_TRIGGER),
        static_cast<uint32_t>(EventTrigger::QOS_CHANGE), true));
    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GxAVPCode::EVENT_TRIGGER),
        static_cast<uint32_t>(EventTrigger::RAT_CHANGE), true));
    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GxAVPCode::EVENT_TRIGGER),
        static_cast<uint32_t>(EventTrigger::USAGE_REPORT), true));

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->ccr.has_value());

    const auto& ccr = result->ccr.value();
    EXPECT_EQ(ccr.event_triggers.size(), 3);
    EXPECT_EQ(ccr.event_triggers[0], EventTrigger::QOS_CHANGE);
    EXPECT_EQ(ccr.event_triggers[1], EventTrigger::RAT_CHANGE);
    EXPECT_EQ(ccr.event_triggers[2], EventTrigger::USAGE_REPORT);
}

// ============================================================================
// JSON Serialization Tests
// ============================================================================

TEST_F(DiameterGxParserTest, ToJson) {
    DiameterMessage msg = createBasicGxMessage(true);

    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(DiameterAVPCode::CC_REQUEST_TYPE), 1));
    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(DiameterAVPCode::CC_REQUEST_NUMBER), 0));
    msg.avps.push_back(createStringAVP(
        static_cast<uint32_t>(GxAVPCode::CALLED_STATION_ID), "internet.apn"));

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());

    auto json = result->toJson();
    EXPECT_TRUE(json.contains("interface"));
    EXPECT_EQ(json["interface"], "Gx");
    EXPECT_TRUE(json.contains("ccr"));
}

// ============================================================================
// RAR/RAA Tests
// ============================================================================

TEST_F(DiameterGxParserTest, ParseRAR_VoLTEBearerInstallation) {
    DiameterMessage msg;
    msg.header.version = 1;
    msg.header.command_code = static_cast<uint32_t>(DiameterCommandCode::RE_AUTH);
    msg.header.application_id = DIAMETER_GX_APPLICATION_ID;
    msg.header.request = true;
    msg.auth_application_id = DIAMETER_GX_APPLICATION_ID;

    // Add Re-Auth-Request-Type (AUTHORIZE_ONLY = 0)
    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(DiameterAVPCode::RE_AUTH_REQUEST_TYPE), 0));

    // Create QoS Information for VoLTE (QCI-1)
    std::vector<std::shared_ptr<DiameterAVP>> qos_avps;
    qos_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GxAVPCode::QOS_CLASS_IDENTIFIER), 1));  // QCI-1 for VoLTE
    qos_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GxAVPCode::MAX_REQUESTED_BANDWIDTH_UL), 128000));  // 128 kbps
    qos_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GxAVPCode::MAX_REQUESTED_BANDWIDTH_DL), 128000));
    qos_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GxAVPCode::GUARANTEED_BITRATE_UL), 88000));  // 88 kbps GBR
    qos_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GxAVPCode::GUARANTEED_BITRATE_DL), 88000));

    auto qos_info = createGroupedAVP(
        static_cast<uint32_t>(GxAVPCode::QOS_INFORMATION),
        qos_avps, true);

    // Create charging rule definition for VoLTE
    std::vector<std::shared_ptr<DiameterAVP>> rule_def_avps;
    rule_def_avps.push_back(createStringAVP(
        static_cast<uint32_t>(GxAVPCode::CHARGING_RULE_NAME), "volte_voice"));
    rule_def_avps.push_back(qos_info);
    rule_def_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GxAVPCode::PRECEDENCE), 100));

    auto rule_def = createGroupedAVP(
        static_cast<uint32_t>(GxAVPCode::CHARGING_RULE_DEFINITION),
        rule_def_avps, true);

    // Create charging rule install
    std::vector<std::shared_ptr<DiameterAVP>> install_avps;
    install_avps.push_back(rule_def);
    install_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GxAVPCode::BEARER_IDENTIFIER), 5));
    install_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GxAVPCode::BEARER_OPERATION), 1));  // ESTABLISHMENT

    auto rule_install = createGroupedAVP(
        static_cast<uint32_t>(GxAVPCode::CHARGING_RULE_INSTALL),
        install_avps, true);

    msg.avps.push_back(rule_install);

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->rar.has_value());

    const auto& rar = result->rar.value();
    EXPECT_EQ(rar.re_auth_request_type, 0);
    ASSERT_FALSE(rar.charging_rule_install.empty());

    const auto& install = rar.charging_rule_install[0];
    EXPECT_TRUE(install.bearer_identifier.has_value());
    EXPECT_EQ(install.bearer_identifier.value(), 5);
    EXPECT_TRUE(install.bearer_operation.has_value());
    EXPECT_EQ(install.bearer_operation.value(), BearerOperation::ESTABLISHMENT);

    ASSERT_FALSE(install.charging_rule_definition.empty());
    const auto& rule = install.charging_rule_definition[0];
    EXPECT_EQ(rule.charging_rule_name, "volte_voice");
    EXPECT_TRUE(rule.qos_information.has_value());
    EXPECT_EQ(rule.qos_information->qos_class_identifier.value(), 1);
    EXPECT_EQ(rule.qos_information->guaranteed_bitrate_ul.value(), 88000);
}

TEST_F(DiameterGxParserTest, ParseRAA_WithRuleReports) {
    DiameterMessage msg;
    msg.header.version = 1;
    msg.header.command_code = static_cast<uint32_t>(DiameterCommandCode::RE_AUTH);
    msg.header.application_id = DIAMETER_GX_APPLICATION_ID;
    msg.header.request = false;
    msg.auth_application_id = DIAMETER_GX_APPLICATION_ID;
    msg.result_code = static_cast<uint32_t>(DiameterResultCode::DIAMETER_SUCCESS);

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->raa.has_value());

    const auto& raa = result->raa.value();
    EXPECT_EQ(raa.result_code, static_cast<uint32_t>(DiameterResultCode::DIAMETER_SUCCESS));
}

// ============================================================================
// Subscription ID Tests
// ============================================================================

TEST_F(DiameterGxParserTest, ParseSubscriptionId_IMSI) {
    DiameterMessage msg = createBasicGxMessage(true);

    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(DiameterAVPCode::CC_REQUEST_TYPE), 1));
    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(DiameterAVPCode::CC_REQUEST_NUMBER), 0));

    // Create Subscription-Id grouped AVP with IMSI
    std::vector<std::shared_ptr<DiameterAVP>> sub_id_avps;
    sub_id_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(DiameterAVPCode::SUBSCRIPTION_ID_TYPE), 1));  // END_USER_IMSI
    sub_id_avps.push_back(createStringAVP(
        static_cast<uint32_t>(DiameterAVPCode::SUBSCRIPTION_ID_DATA), "001010123456789"));

    auto sub_id = createGroupedAVP(
        static_cast<uint32_t>(DiameterAVPCode::SUBSCRIPTION_ID), sub_id_avps);

    msg.avps.push_back(sub_id);

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->ccr.has_value());

    const auto& ccr = result->ccr.value();
    EXPECT_TRUE(ccr.subscription_id.has_value());
    EXPECT_EQ(ccr.subscription_id->subscription_id_type, SubscriptionIdType::END_USER_IMSI);
    EXPECT_EQ(ccr.subscription_id->subscription_id_data, "001010123456789");
}

// ============================================================================
// Flow Information Tests
// ============================================================================

TEST_F(DiameterGxParserTest, ParseFlowInformation) {
    DiameterMessage msg = createBasicGxMessage(false);
    msg.result_code = static_cast<uint32_t>(DiameterResultCode::DIAMETER_SUCCESS);

    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(DiameterAVPCode::CC_REQUEST_TYPE), 1));
    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(DiameterAVPCode::CC_REQUEST_NUMBER), 0));

    // Create Flow Information
    std::vector<std::shared_ptr<DiameterAVP>> flow_avps;
    flow_avps.push_back(createStringAVP(
        static_cast<uint32_t>(GxAVPCode::FLOW_DESCRIPTION),
        "permit out ip from 10.0.0.1 to 192.168.1.100"));
    flow_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GxAVPCode::TOS_TRAFFIC_CLASS), 0xb8));  // EF (Expedited Forwarding)

    auto flow_info = createGroupedAVP(
        static_cast<uint32_t>(GxAVPCode::FLOW_INFORMATION),
        flow_avps, true);

    // Create charging rule definition with flow
    std::vector<std::shared_ptr<DiameterAVP>> rule_def_avps;
    rule_def_avps.push_back(createStringAVP(
        static_cast<uint32_t>(GxAVPCode::CHARGING_RULE_NAME), "rule_with_flow"));
    rule_def_avps.push_back(flow_info);

    auto rule_def = createGroupedAVP(
        static_cast<uint32_t>(GxAVPCode::CHARGING_RULE_DEFINITION),
        rule_def_avps, true);

    // Create charging rule install
    std::vector<std::shared_ptr<DiameterAVP>> install_avps;
    install_avps.push_back(rule_def);

    auto rule_install = createGroupedAVP(
        static_cast<uint32_t>(GxAVPCode::CHARGING_RULE_INSTALL),
        install_avps, true);

    msg.avps.push_back(rule_install);

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->cca.has_value());

    const auto& cca = result->cca.value();
    ASSERT_FALSE(cca.charging_rule_install.empty());

    const auto& install = cca.charging_rule_install[0];
    ASSERT_FALSE(install.charging_rule_definition.empty());

    const auto& rule = install.charging_rule_definition[0];
    EXPECT_EQ(rule.charging_rule_name, "rule_with_flow");
    ASSERT_FALSE(rule.flow_information.empty());

    const auto& flow = rule.flow_information[0];
    EXPECT_EQ(flow.flow_description, "permit out ip from 10.0.0.1 to 192.168.1.100");
    EXPECT_TRUE(flow.tos_traffic_class.has_value());
    EXPECT_EQ(flow.tos_traffic_class.value(), 0xb8);
}

// ============================================================================
// Integration Tests
// ============================================================================

TEST_F(DiameterGxParserTest, IntegrationTest_DataSessionLifecycle) {
    // Test complete Gx session: CCR-I -> CCA-I -> CCR-T -> CCA-T

    // 1. CCR-Initial
    DiameterMessage ccr_initial = createBasicGxMessage(true);
    ccr_initial.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(DiameterAVPCode::CC_REQUEST_TYPE), 1));  // INITIAL_REQUEST
    ccr_initial.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(DiameterAVPCode::CC_REQUEST_NUMBER), 0));
    ccr_initial.avps.push_back(createStringAVP(
        static_cast<uint32_t>(GxAVPCode::CALLED_STATION_ID), "internet.apn"));

    auto framed_ip_avp = std::make_shared<DiameterAVP>();
    framed_ip_avp->code = static_cast<uint32_t>(GxAVPCode::FRAMED_IP_ADDRESS);
    framed_ip_avp->data = {0x00, 0x01, 10, 20, 30, 40};
    ccr_initial.avps.push_back(framed_ip_avp);

    auto ccr_i_result = parser.parse(ccr_initial);
    ASSERT_TRUE(ccr_i_result.has_value());
    ASSERT_TRUE(ccr_i_result->ccr.has_value());
    EXPECT_EQ(ccr_i_result->ccr->cc_request_type, CCRequestType::INITIAL_REQUEST);

    // 2. CCA-Initial
    DiameterMessage cca_initial = createBasicGxMessage(false);
    cca_initial.result_code = static_cast<uint32_t>(DiameterResultCode::DIAMETER_SUCCESS);
    cca_initial.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(DiameterAVPCode::CC_REQUEST_TYPE), 1));
    cca_initial.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(DiameterAVPCode::CC_REQUEST_NUMBER), 0));

    // Add default QoS
    std::vector<std::shared_ptr<DiameterAVP>> arp_avps;
    arp_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GxAVPCode::PRIORITY_LEVEL), 15));
    arp_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GxAVPCode::PRE_EMPTION_CAPABILITY), 1));
    arp_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GxAVPCode::PRE_EMPTION_VULNERABILITY), 0));

    auto arp = createGroupedAVP(
        static_cast<uint32_t>(GxAVPCode::ALLOCATION_RETENTION_PRIORITY),
        arp_avps, true);

    std::vector<std::shared_ptr<DiameterAVP>> qos_avps;
    qos_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GxAVPCode::QOS_CLASS_IDENTIFIER), 9));  // QCI-9 for default bearer
    qos_avps.push_back(arp);

    auto default_qos = createGroupedAVP(
        static_cast<uint32_t>(GxAVPCode::DEFAULT_EPS_BEARER_QOS),
        qos_avps, true);

    cca_initial.avps.push_back(default_qos);

    auto cca_i_result = parser.parse(cca_initial);
    ASSERT_TRUE(cca_i_result.has_value());
    ASSERT_TRUE(cca_i_result->cca.has_value());
    EXPECT_EQ(cca_i_result->cca->result_code,
              static_cast<uint32_t>(DiameterResultCode::DIAMETER_SUCCESS));
    EXPECT_TRUE(cca_i_result->cca->default_eps_bearer_qos.has_value());

    // 3. CCR-Termination
    DiameterMessage ccr_term = createBasicGxMessage(true);
    ccr_term.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(DiameterAVPCode::CC_REQUEST_TYPE), 3));  // TERMINATION_REQUEST
    ccr_term.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(DiameterAVPCode::CC_REQUEST_NUMBER), 1));

    auto ccr_t_result = parser.parse(ccr_term);
    ASSERT_TRUE(ccr_t_result.has_value());
    ASSERT_TRUE(ccr_t_result->ccr.has_value());
    EXPECT_EQ(ccr_t_result->ccr->cc_request_type, CCRequestType::TERMINATION_REQUEST);

    // 4. CCA-Termination
    DiameterMessage cca_term = createBasicGxMessage(false);
    cca_term.result_code = static_cast<uint32_t>(DiameterResultCode::DIAMETER_SUCCESS);
    cca_term.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(DiameterAVPCode::CC_REQUEST_TYPE), 3));
    cca_term.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(DiameterAVPCode::CC_REQUEST_NUMBER), 1));

    auto cca_t_result = parser.parse(cca_term);
    ASSERT_TRUE(cca_t_result.has_value());
    ASSERT_TRUE(cca_t_result->cca.has_value());
    EXPECT_EQ(cca_t_result->cca->result_code,
              static_cast<uint32_t>(DiameterResultCode::DIAMETER_SUCCESS));
}

TEST_F(DiameterGxParserTest, IntegrationTest_VoLTEDedicatedBearer) {
    // Test VoLTE dedicated bearer installation via RAR/RAA

    // 1. Parse RAR from PCRF to install VoLTE bearer
    DiameterMessage rar_msg;
    rar_msg.header.version = 1;
    rar_msg.header.command_code = static_cast<uint32_t>(DiameterCommandCode::RE_AUTH);
    rar_msg.header.application_id = DIAMETER_GX_APPLICATION_ID;
    rar_msg.header.request = true;
    rar_msg.auth_application_id = DIAMETER_GX_APPLICATION_ID;

    rar_msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(DiameterAVPCode::RE_AUTH_REQUEST_TYPE), 0));

    // Create VoLTE QoS with GBR
    std::vector<std::shared_ptr<DiameterAVP>> arp_avps;
    arp_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GxAVPCode::PRIORITY_LEVEL), 2));  // High priority
    arp_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GxAVPCode::PRE_EMPTION_CAPABILITY), 0));
    arp_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GxAVPCode::PRE_EMPTION_VULNERABILITY), 1));

    auto arp = createGroupedAVP(
        static_cast<uint32_t>(GxAVPCode::ALLOCATION_RETENTION_PRIORITY),
        arp_avps, true);

    std::vector<std::shared_ptr<DiameterAVP>> qos_avps;
    qos_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GxAVPCode::QOS_CLASS_IDENTIFIER), 1));  // QCI-1
    qos_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GxAVPCode::MAX_REQUESTED_BANDWIDTH_UL), 128000));
    qos_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GxAVPCode::MAX_REQUESTED_BANDWIDTH_DL), 128000));
    qos_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GxAVPCode::GUARANTEED_BITRATE_UL), 88000));
    qos_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GxAVPCode::GUARANTEED_BITRATE_DL), 88000));
    qos_avps.push_back(arp);

    auto qos_info = createGroupedAVP(
        static_cast<uint32_t>(GxAVPCode::QOS_INFORMATION),
        qos_avps, true);

    std::vector<std::shared_ptr<DiameterAVP>> rule_def_avps;
    rule_def_avps.push_back(createStringAVP(
        static_cast<uint32_t>(GxAVPCode::CHARGING_RULE_NAME), "IMS_VoLTE"));
    rule_def_avps.push_back(qos_info);
    rule_def_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GxAVPCode::SERVICE_IDENTIFIER), 1000));
    rule_def_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GxAVPCode::RATING_GROUP), 100));
    rule_def_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GxAVPCode::PRECEDENCE), 100));

    auto rule_def = createGroupedAVP(
        static_cast<uint32_t>(GxAVPCode::CHARGING_RULE_DEFINITION),
        rule_def_avps, true);

    std::vector<std::shared_ptr<DiameterAVP>> install_avps;
    install_avps.push_back(rule_def);
    install_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GxAVPCode::BEARER_IDENTIFIER), 5));
    install_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GxAVPCode::BEARER_OPERATION), 1));  // ESTABLISHMENT

    auto rule_install = createGroupedAVP(
        static_cast<uint32_t>(GxAVPCode::CHARGING_RULE_INSTALL),
        install_avps, true);

    rar_msg.avps.push_back(rule_install);

    // Add event trigger
    rar_msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GxAVPCode::EVENT_TRIGGER),
        static_cast<uint32_t>(EventTrigger::SUCCESSFUL_RESOURCE_ALLOCATION), true));

    auto rar_result = parser.parse(rar_msg);
    ASSERT_TRUE(rar_result.has_value());
    ASSERT_TRUE(rar_result->rar.has_value());

    const auto& rar = rar_result->rar.value();
    ASSERT_FALSE(rar.charging_rule_install.empty());
    ASSERT_FALSE(rar.charging_rule_install[0].charging_rule_definition.empty());

    const auto& rule = rar.charging_rule_install[0].charging_rule_definition[0];
    EXPECT_EQ(rule.charging_rule_name, "IMS_VoLTE");
    EXPECT_TRUE(rule.qos_information.has_value());
    EXPECT_EQ(rule.qos_information->qos_class_identifier.value(), 1);
    EXPECT_EQ(rule.qos_information->guaranteed_bitrate_ul.value(), 88000);
    EXPECT_TRUE(rule.service_identifier.has_value());
    EXPECT_EQ(rule.service_identifier.value(), 1000);

    // 2. Parse RAA response
    DiameterMessage raa_msg;
    raa_msg.header.version = 1;
    raa_msg.header.command_code = static_cast<uint32_t>(DiameterCommandCode::RE_AUTH);
    raa_msg.header.application_id = DIAMETER_GX_APPLICATION_ID;
    raa_msg.header.request = false;
    raa_msg.auth_application_id = DIAMETER_GX_APPLICATION_ID;
    raa_msg.result_code = static_cast<uint32_t>(DiameterResultCode::DIAMETER_SUCCESS);

    auto raa_result = parser.parse(raa_msg);
    ASSERT_TRUE(raa_result.has_value());
    ASSERT_TRUE(raa_result->raa.has_value());
    EXPECT_EQ(raa_result->raa->result_code,
              static_cast<uint32_t>(DiameterResultCode::DIAMETER_SUCCESS));
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
