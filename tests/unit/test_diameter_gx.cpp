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

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
