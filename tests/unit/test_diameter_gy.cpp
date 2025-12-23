#include <gtest/gtest.h>
#include "protocol_parsers/diameter/diameter_gy.h"
#include "protocol_parsers/diameter/diameter_avp_parser.h"
#include <arpa/inet.h>

using namespace callflow::diameter;

class DiameterGyParserTest : public ::testing::Test {
protected:
    DiameterGyParser parser;

    DiameterMessage createBasicGyMessage(bool is_request) {
        DiameterMessage msg;
        msg.header.version = 1;
        msg.header.command_code = static_cast<uint32_t>(DiameterCommandCode::CREDIT_CONTROL);
        msg.header.application_id = DIAMETER_GY_APPLICATION_ID;
        msg.header.request = is_request;
        msg.acct_application_id = DIAMETER_GY_APPLICATION_ID;
        return msg;
    }

    std::shared_ptr<DiameterAVP> createUint32AVP(uint32_t code, uint32_t value) {
        auto avp = std::make_shared<DiameterAVP>();
        avp->code = code;
        uint32_t network_value = htonl(value);
        avp->data.resize(4);
        std::memcpy(avp->data.data(), &network_value, 4);
        avp->decoded_value = value;
        return avp;
    }

    std::shared_ptr<DiameterAVP> createUint64AVP(uint32_t code, uint64_t value) {
        auto avp = std::make_shared<DiameterAVP>();
        avp->code = code;
        uint64_t network_value = htobe64(value);
        avp->data.resize(8);
        std::memcpy(avp->data.data(), &network_value, 8);
        avp->decoded_value = value;
        return avp;
    }

    std::shared_ptr<DiameterAVP> createStringAVP(uint32_t code, const std::string& value) {
        auto avp = std::make_shared<DiameterAVP>();
        avp->code = code;
        avp->data.assign(value.begin(), value.end());
        avp->decoded_value = value;
        return avp;
    }

    std::shared_ptr<DiameterAVP> createGroupedAVP(uint32_t code,
                                                   std::vector<std::shared_ptr<DiameterAVP>> children) {
        auto avp = std::make_shared<DiameterAVP>();
        avp->code = code;
        avp->decoded_value = children;
        return avp;
    }
};

TEST_F(DiameterGyParserTest, IsGyMessage) {
    DiameterMessage msg = createBasicGyMessage(true);
    EXPECT_TRUE(DiameterGyParser::isGyMessage(msg));
}

TEST_F(DiameterGyParserTest, ParseCCR_Initial) {
    DiameterMessage msg = createBasicGyMessage(true);

    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::CC_REQUEST_TYPE), 1));
    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::CC_REQUEST_NUMBER), 0));
    msg.avps.push_back(createStringAVP(
        static_cast<uint32_t>(GyAVPCode::SERVICE_CONTEXT_ID), "32260@3gpp.org"));

    // Add subscription ID
    std::vector<std::shared_ptr<DiameterAVP>> sub_id_avps;
    sub_id_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::SUBSCRIPTION_ID_TYPE),
        static_cast<uint32_t>(SubscriptionIdType::END_USER_IMSI)));
    sub_id_avps.push_back(createStringAVP(
        static_cast<uint32_t>(GyAVPCode::SUBSCRIPTION_ID_DATA), "123456789012345"));

    auto sub_id = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::SUBSCRIPTION_ID), sub_id_avps);

    msg.avps.push_back(sub_id);

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->ccr.has_value());

    const auto& ccr = result->ccr.value();
    EXPECT_EQ(ccr.cc_request_type, CCRequestType::INITIAL_REQUEST);
    EXPECT_EQ(ccr.cc_request_number, 0);
    EXPECT_TRUE(ccr.service_context_id.has_value());
    EXPECT_EQ(ccr.service_context_id.value(), "32260@3gpp.org");
    ASSERT_EQ(ccr.subscription_ids.size(), 1);
    EXPECT_EQ(ccr.subscription_ids[0].subscription_id_type, SubscriptionIdType::END_USER_IMSI);
    EXPECT_EQ(ccr.subscription_ids[0].subscription_id_data, "123456789012345");
}

TEST_F(DiameterGyParserTest, ParseMSCC_WithGrantedUnits) {
    DiameterMessage msg = createBasicGyMessage(false);
    msg.result_code = static_cast<uint32_t>(DiameterResultCode::DIAMETER_SUCCESS);

    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::CC_REQUEST_TYPE), 1));
    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::CC_REQUEST_NUMBER), 0));

    // Create granted service unit
    std::vector<std::shared_ptr<DiameterAVP>> gsu_avps;
    gsu_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::CC_TIME), 3600));
    gsu_avps.push_back(createUint64AVP(
        static_cast<uint32_t>(GyAVPCode::CC_TOTAL_OCTETS), 1073741824));  // 1GB

    auto gsu = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::GRANTED_SERVICE_UNIT), gsu_avps);

    // Create MSCC
    std::vector<std::shared_ptr<DiameterAVP>> mscc_avps;
    mscc_avps.push_back(gsu);
    mscc_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::RATING_GROUP), 100));
    mscc_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::VALIDITY_TIME), 7200));

    auto mscc = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::MULTIPLE_SERVICES_CREDIT_CONTROL), mscc_avps);

    msg.avps.push_back(mscc);

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->cca.has_value());

    const auto& cca = result->cca.value();
    ASSERT_EQ(cca.mscc.size(), 1);

    const auto& mscc_parsed = cca.mscc[0];
    EXPECT_TRUE(mscc_parsed.granted_service_unit.has_value());
    EXPECT_TRUE(mscc_parsed.granted_service_unit->cc_time.has_value());
    EXPECT_EQ(mscc_parsed.granted_service_unit->cc_time.value(), 3600);
    EXPECT_TRUE(mscc_parsed.granted_service_unit->cc_total_octets.has_value());
    EXPECT_EQ(mscc_parsed.granted_service_unit->cc_total_octets.value(), 1073741824);
    EXPECT_TRUE(mscc_parsed.rating_group.has_value());
    EXPECT_EQ(mscc_parsed.rating_group.value(), 100);
    EXPECT_TRUE(mscc_parsed.validity_time.has_value());
    EXPECT_EQ(mscc_parsed.validity_time.value(), 7200);
}

TEST_F(DiameterGyParserTest, ParseMSCC_WithUsedUnits) {
    DiameterMessage msg = createBasicGyMessage(true);

    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::CC_REQUEST_TYPE), 2));  // UPDATE
    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::CC_REQUEST_NUMBER), 1));

    // Create used service unit
    std::vector<std::shared_ptr<DiameterAVP>> usu_avps;
    usu_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::CC_TIME), 1800));
    usu_avps.push_back(createUint64AVP(
        static_cast<uint32_t>(GyAVPCode::CC_INPUT_OCTETS), 52428800));   // 50MB
    usu_avps.push_back(createUint64AVP(
        static_cast<uint32_t>(GyAVPCode::CC_OUTPUT_OCTETS), 524288000));  // 500MB

    auto usu = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::USED_SERVICE_UNIT), usu_avps);

    // Create MSCC
    std::vector<std::shared_ptr<DiameterAVP>> mscc_avps;
    mscc_avps.push_back(usu);
    mscc_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::RATING_GROUP), 100));
    mscc_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::REPORTING_REASON),
        static_cast<uint32_t>(ReportingReason::THRESHOLD)));

    auto mscc = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::MULTIPLE_SERVICES_CREDIT_CONTROL), mscc_avps);

    msg.avps.push_back(mscc);

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->ccr.has_value());

    const auto& ccr = result->ccr.value();
    ASSERT_EQ(ccr.mscc.size(), 1);

    const auto& mscc_parsed = ccr.mscc[0];
    EXPECT_TRUE(mscc_parsed.used_service_unit.has_value());
    EXPECT_TRUE(mscc_parsed.used_service_unit->cc_time.has_value());
    EXPECT_EQ(mscc_parsed.used_service_unit->cc_time.value(), 1800);
    EXPECT_TRUE(mscc_parsed.used_service_unit->cc_input_octets.has_value());
    EXPECT_EQ(mscc_parsed.used_service_unit->cc_input_octets.value(), 52428800);
    EXPECT_TRUE(mscc_parsed.used_service_unit->cc_output_octets.has_value());
    EXPECT_EQ(mscc_parsed.used_service_unit->cc_output_octets.value(), 524288000);
    EXPECT_TRUE(mscc_parsed.reporting_reason.has_value());
    EXPECT_EQ(mscc_parsed.reporting_reason.value(), ReportingReason::THRESHOLD);
}

TEST_F(DiameterGyParserTest, ParseFinalUnitIndication) {
    DiameterMessage msg = createBasicGyMessage(false);
    msg.result_code = static_cast<uint32_t>(DiameterResultCode::DIAMETER_SUCCESS);

    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::CC_REQUEST_TYPE), 2));
    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::CC_REQUEST_NUMBER), 1));

    // Create final unit indication
    std::vector<std::shared_ptr<DiameterAVP>> fui_avps;
    fui_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::FINAL_UNIT_ACTION),
        static_cast<uint32_t>(FinalUnitAction::TERMINATE)));

    auto fui = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::FINAL_UNIT_INDICATION), fui_avps);

    // Create MSCC with final unit indication
    std::vector<std::shared_ptr<DiameterAVP>> mscc_avps;
    mscc_avps.push_back(fui);
    mscc_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::RATING_GROUP), 100));

    auto mscc = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::MULTIPLE_SERVICES_CREDIT_CONTROL), mscc_avps);

    msg.avps.push_back(mscc);

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->cca.has_value());

    const auto& cca = result->cca.value();
    ASSERT_EQ(cca.mscc.size(), 1);

    const auto& mscc_parsed = cca.mscc[0];
    EXPECT_TRUE(mscc_parsed.final_unit_indication.has_value());
    EXPECT_EQ(mscc_parsed.final_unit_indication->final_unit_action,
              FinalUnitAction::TERMINATE);
}

TEST_F(DiameterGyParserTest, ParseCCR_Termination) {
    DiameterMessage msg = createBasicGyMessage(true);

    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::CC_REQUEST_TYPE), 3));  // TERMINATION
    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::CC_REQUEST_NUMBER), 5));

    // Add used service unit for final report
    std::vector<std::shared_ptr<DiameterAVP>> usu_avps;
    usu_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::CC_TIME), 7200));  // 2 hours
    usu_avps.push_back(createUint64AVP(
        static_cast<uint32_t>(GyAVPCode::CC_TOTAL_OCTETS), 2147483648));  // 2GB

    auto usu = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::USED_SERVICE_UNIT), usu_avps);

    std::vector<std::shared_ptr<DiameterAVP>> mscc_avps;
    mscc_avps.push_back(usu);
    mscc_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::RATING_GROUP), 100));
    mscc_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::REPORTING_REASON),
        static_cast<uint32_t>(ReportingReason::FINAL)));

    auto mscc = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::MULTIPLE_SERVICES_CREDIT_CONTROL), mscc_avps);

    msg.avps.push_back(mscc);

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->ccr.has_value());

    const auto& ccr = result->ccr.value();
    EXPECT_EQ(ccr.cc_request_type, CCRequestType::TERMINATION_REQUEST);
    EXPECT_EQ(ccr.cc_request_number, 5);
    ASSERT_EQ(ccr.mscc.size(), 1);

    const auto& mscc_parsed = ccr.mscc[0];
    EXPECT_TRUE(mscc_parsed.used_service_unit.has_value());
    EXPECT_EQ(mscc_parsed.used_service_unit->cc_time.value(), 7200);
    EXPECT_EQ(mscc_parsed.used_service_unit->cc_total_octets.value(), 2147483648);
    EXPECT_EQ(mscc_parsed.reporting_reason.value(), ReportingReason::FINAL);
}

TEST_F(DiameterGyParserTest, ParseCCA_Termination) {
    DiameterMessage msg = createBasicGyMessage(false);
    msg.result_code = static_cast<uint32_t>(DiameterResultCode::DIAMETER_SUCCESS);

    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::CC_REQUEST_TYPE), 3));  // TERMINATION
    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::CC_REQUEST_NUMBER), 5));

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->cca.has_value());

    const auto& cca = result->cca.value();
    EXPECT_EQ(cca.cc_request_type, CCRequestType::TERMINATION_REQUEST);
    EXPECT_EQ(cca.cc_request_number, 5);
    EXPECT_EQ(cca.result_code, static_cast<uint32_t>(DiameterResultCode::DIAMETER_SUCCESS));
}

TEST_F(DiameterGyParserTest, ParsePSInformation) {
    DiameterMessage msg = createBasicGyMessage(true);

    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::CC_REQUEST_TYPE), 1));
    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::CC_REQUEST_NUMBER), 0));

    // Create PS-Information
    std::vector<std::shared_ptr<DiameterAVP>> ps_info_avps;
    ps_info_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::TGPP_CHARGING_ID), 0x12345678));
    ps_info_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::TGPP_PDP_TYPE), 0));  // IPv4
    ps_info_avps.push_back(createStringAVP(
        static_cast<uint32_t>(GyAVPCode::CALLED_STATION_ID), "internet.apn"));
    ps_info_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::TGPP_RAT_TYPE), 6));  // EUTRAN

    auto ps_info = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::PS_INFORMATION), ps_info_avps);

    // Create Service-Information
    std::vector<std::shared_ptr<DiameterAVP>> svc_info_avps;
    svc_info_avps.push_back(ps_info);

    auto svc_info = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::SERVICE_INFORMATION), svc_info_avps);
    svc_info->vendor_id = DIAMETER_VENDOR_3GPP;

    msg.avps.push_back(svc_info);

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->ccr.has_value());

    const auto& ccr = result->ccr.value();
    ASSERT_TRUE(ccr.service_information.has_value());
    ASSERT_TRUE(ccr.service_information->ps_information.has_value());

    const auto& ps = ccr.service_information->ps_information.value();
    EXPECT_TRUE(ps.tgpp_charging_id.has_value());
    EXPECT_EQ(ps.tgpp_charging_id.value(), 0x12345678);
    EXPECT_TRUE(ps.called_station_id.has_value());
    EXPECT_EQ(ps.called_station_id.value(), "internet.apn");
    EXPECT_TRUE(ps.tgpp_rat_type.has_value());
    EXPECT_EQ(ps.tgpp_rat_type.value(), 6);
}

TEST_F(DiameterGyParserTest, ParseCCA_WithCostInformation) {
    DiameterMessage msg = createBasicGyMessage(false);
    msg.result_code = static_cast<uint32_t>(DiameterResultCode::DIAMETER_SUCCESS);

    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::CC_REQUEST_TYPE), 2));  // UPDATE
    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::CC_REQUEST_NUMBER), 1));

    // Create cost information
    std::vector<std::shared_ptr<DiameterAVP>> cost_avps;
    cost_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::UNIT_VALUE), 1250));
    cost_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::CURRENCY_CODE), 840));  // USD

    auto cost_info = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::COST_INFORMATION), cost_avps);

    msg.avps.push_back(cost_info);

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->cca.has_value());

    const auto& cca = result->cca.value();
    ASSERT_TRUE(cca.cost_information.has_value());
    EXPECT_EQ(cca.cost_information->unit_value, 1250);
    EXPECT_EQ(cca.cost_information->currency_code, 840);
}

TEST_F(DiameterGyParserTest, ParseMultipleRatingGroups) {
    DiameterMessage msg = createBasicGyMessage(false);
    msg.result_code = static_cast<uint32_t>(DiameterResultCode::DIAMETER_SUCCESS);

    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::CC_REQUEST_TYPE), 1));
    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::CC_REQUEST_NUMBER), 0));

    // Create first MSCC for rating group 100
    std::vector<std::shared_ptr<DiameterAVP>> gsu1_avps;
    gsu1_avps.push_back(createUint64AVP(
        static_cast<uint32_t>(GyAVPCode::CC_TOTAL_OCTETS), 1073741824));  // 1GB

    auto gsu1 = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::GRANTED_SERVICE_UNIT), gsu1_avps);

    std::vector<std::shared_ptr<DiameterAVP>> mscc1_avps;
    mscc1_avps.push_back(gsu1);
    mscc1_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::RATING_GROUP), 100));
    mscc1_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::SERVICE_IDENTIFIER), 1));

    auto mscc1 = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::MULTIPLE_SERVICES_CREDIT_CONTROL), mscc1_avps);

    // Create second MSCC for rating group 200
    std::vector<std::shared_ptr<DiameterAVP>> gsu2_avps;
    gsu2_avps.push_back(createUint64AVP(
        static_cast<uint32_t>(GyAVPCode::CC_TOTAL_OCTETS), 536870912));  // 512MB

    auto gsu2 = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::GRANTED_SERVICE_UNIT), gsu2_avps);

    std::vector<std::shared_ptr<DiameterAVP>> mscc2_avps;
    mscc2_avps.push_back(gsu2);
    mscc2_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::RATING_GROUP), 200));
    mscc2_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::SERVICE_IDENTIFIER), 2));

    auto mscc2 = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::MULTIPLE_SERVICES_CREDIT_CONTROL), mscc2_avps);

    msg.avps.push_back(mscc1);
    msg.avps.push_back(mscc2);

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->cca.has_value());

    const auto& cca = result->cca.value();
    ASSERT_EQ(cca.mscc.size(), 2);

    EXPECT_EQ(cca.mscc[0].rating_group.value(), 100);
    EXPECT_EQ(cca.mscc[0].service_identifier.value(), 1);
    EXPECT_EQ(cca.mscc[0].granted_service_unit->cc_total_octets.value(), 1073741824);

    EXPECT_EQ(cca.mscc[1].rating_group.value(), 200);
    EXPECT_EQ(cca.mscc[1].service_identifier.value(), 2);
    EXPECT_EQ(cca.mscc[1].granted_service_unit->cc_total_octets.value(), 536870912);
}

TEST_F(DiameterGyParserTest, ParseTriggers) {
    DiameterMessage msg = createBasicGyMessage(false);
    msg.result_code = static_cast<uint32_t>(DiameterResultCode::DIAMETER_SUCCESS);

    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::CC_REQUEST_TYPE), 1));
    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::CC_REQUEST_NUMBER), 0));

    // Create MSCC with multiple triggers
    std::vector<std::shared_ptr<DiameterAVP>> mscc_avps;
    mscc_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::RATING_GROUP), 100));
    mscc_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::TRIGGER_TYPE),
        static_cast<uint32_t>(TriggerType::CHANGE_IN_QOS)));
    mscc_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::TRIGGER_TYPE),
        static_cast<uint32_t>(TriggerType::CHANGE_IN_LOCATION)));
    mscc_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::TRIGGER_TYPE),
        static_cast<uint32_t>(TriggerType::CHANGE_IN_RAT)));

    auto mscc = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::MULTIPLE_SERVICES_CREDIT_CONTROL), mscc_avps);

    msg.avps.push_back(mscc);

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->cca.has_value());

    const auto& cca = result->cca.value();
    ASSERT_EQ(cca.mscc.size(), 1);

    const auto& mscc_parsed = cca.mscc[0];
    EXPECT_EQ(mscc_parsed.triggers.size(), 3);
    EXPECT_EQ(mscc_parsed.triggers[0], TriggerType::CHANGE_IN_QOS);
    EXPECT_EQ(mscc_parsed.triggers[1], TriggerType::CHANGE_IN_LOCATION);
    EXPECT_EQ(mscc_parsed.triggers[2], TriggerType::CHANGE_IN_RAT);
}

TEST_F(DiameterGyParserTest, ParseUserEquipmentInfo) {
    DiameterMessage msg = createBasicGyMessage(true);

    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::CC_REQUEST_TYPE), 1));
    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::CC_REQUEST_NUMBER), 0));

    // Create user equipment info
    std::vector<std::shared_ptr<DiameterAVP>> ue_avps;
    ue_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::USER_EQUIPMENT_INFO_TYPE),
        static_cast<uint32_t>(UserEquipmentInfoType::IMEISV)));
    ue_avps.push_back(createStringAVP(
        static_cast<uint32_t>(GyAVPCode::USER_EQUIPMENT_INFO_VALUE), "1234567890123456"));

    auto ue_info = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::USER_EQUIPMENT_INFO), ue_avps);

    msg.avps.push_back(ue_info);

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->ccr.has_value());

    const auto& ccr = result->ccr.value();
    ASSERT_TRUE(ccr.user_equipment_info.has_value());
    EXPECT_EQ(ccr.user_equipment_info->user_equipment_info_type,
              UserEquipmentInfoType::IMEISV);
    EXPECT_EQ(ccr.user_equipment_info->user_equipment_info_value, "1234567890123456");
}

TEST_F(DiameterGyParserTest, IntegrationTest_FullDataSession) {
    // Simulate full data session: CCR-I -> CCA-I -> CCR-U -> CCA-U -> CCR-T -> CCA-T

    // 1. CCR-Initial
    DiameterMessage ccr_i = createBasicGyMessage(true);
    ccr_i.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::CC_REQUEST_TYPE), 1));
    ccr_i.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::CC_REQUEST_NUMBER), 0));

    // Add requested service unit
    std::vector<std::shared_ptr<DiameterAVP>> rsu_avps;
    rsu_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::CC_TIME), 0));
    rsu_avps.push_back(createUint64AVP(
        static_cast<uint32_t>(GyAVPCode::CC_TOTAL_OCTETS), 0));

    auto rsu = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::REQUESTED_SERVICE_UNIT), rsu_avps);

    std::vector<std::shared_ptr<DiameterAVP>> mscc_i_avps;
    mscc_i_avps.push_back(rsu);
    mscc_i_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::RATING_GROUP), 100));

    auto mscc_i = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::MULTIPLE_SERVICES_CREDIT_CONTROL), mscc_i_avps);
    ccr_i.avps.push_back(mscc_i);

    auto ccr_i_result = parser.parse(ccr_i);
    ASSERT_TRUE(ccr_i_result.has_value());
    EXPECT_EQ(ccr_i_result->ccr->cc_request_type, CCRequestType::INITIAL_REQUEST);

    // 2. CCA-Initial with granted quota
    DiameterMessage cca_i = createBasicGyMessage(false);
    cca_i.result_code = static_cast<uint32_t>(DiameterResultCode::DIAMETER_SUCCESS);
    cca_i.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::CC_REQUEST_TYPE), 1));
    cca_i.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::CC_REQUEST_NUMBER), 0));

    std::vector<std::shared_ptr<DiameterAVP>> gsu_avps;
    gsu_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::CC_TIME), 3600));  // 1 hour
    gsu_avps.push_back(createUint64AVP(
        static_cast<uint32_t>(GyAVPCode::CC_TOTAL_OCTETS), 1073741824));  // 1GB

    auto gsu = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::GRANTED_SERVICE_UNIT), gsu_avps);

    std::vector<std::shared_ptr<DiameterAVP>> mscc_cca_i_avps;
    mscc_cca_i_avps.push_back(gsu);
    mscc_cca_i_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::RATING_GROUP), 100));
    mscc_cca_i_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::VALIDITY_TIME), 7200));

    auto mscc_cca_i = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::MULTIPLE_SERVICES_CREDIT_CONTROL), mscc_cca_i_avps);
    cca_i.avps.push_back(mscc_cca_i);

    auto cca_i_result = parser.parse(cca_i);
    ASSERT_TRUE(cca_i_result.has_value());
    EXPECT_EQ(cca_i_result->cca->result_code,
              static_cast<uint32_t>(DiameterResultCode::DIAMETER_SUCCESS));
    ASSERT_EQ(cca_i_result->cca->mscc.size(), 1);
    EXPECT_TRUE(cca_i_result->cca->mscc[0].granted_service_unit.has_value());

    // 3. CCR-Update with usage report
    DiameterMessage ccr_u = createBasicGyMessage(true);
    ccr_u.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::CC_REQUEST_TYPE), 2));  // UPDATE
    ccr_u.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::CC_REQUEST_NUMBER), 1));

    std::vector<std::shared_ptr<DiameterAVP>> usu_avps;
    usu_avps.push_back(createUint64AVP(
        static_cast<uint32_t>(GyAVPCode::CC_TOTAL_OCTETS), 536870912));  // 512MB used

    auto usu = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::USED_SERVICE_UNIT), usu_avps);

    std::vector<std::shared_ptr<DiameterAVP>> mscc_u_avps;
    mscc_u_avps.push_back(usu);
    mscc_u_avps.push_back(rsu);  // Request more quota
    mscc_u_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::RATING_GROUP), 100));

    auto mscc_u = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::MULTIPLE_SERVICES_CREDIT_CONTROL), mscc_u_avps);
    ccr_u.avps.push_back(mscc_u);

    auto ccr_u_result = parser.parse(ccr_u);
    ASSERT_TRUE(ccr_u_result.has_value());
    EXPECT_EQ(ccr_u_result->ccr->cc_request_type, CCRequestType::UPDATE_REQUEST);
    ASSERT_EQ(ccr_u_result->ccr->mscc.size(), 1);
    EXPECT_TRUE(ccr_u_result->ccr->mscc[0].used_service_unit.has_value());

    // 4. CCR-Termination with final usage
    DiameterMessage ccr_t = createBasicGyMessage(true);
    ccr_t.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::CC_REQUEST_TYPE), 3));  // TERMINATION
    ccr_t.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::CC_REQUEST_NUMBER), 2));

    std::vector<std::shared_ptr<DiameterAVP>> usu_final_avps;
    usu_final_avps.push_back(createUint64AVP(
        static_cast<uint32_t>(GyAVPCode::CC_TOTAL_OCTETS), 104857600));  // 100MB final usage
    usu_final_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::REPORTING_REASON),
        static_cast<uint32_t>(ReportingReason::FINAL)));

    auto usu_final = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::USED_SERVICE_UNIT), usu_final_avps);

    std::vector<std::shared_ptr<DiameterAVP>> mscc_t_avps;
    mscc_t_avps.push_back(usu_final);
    mscc_t_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::RATING_GROUP), 100));

    auto mscc_t = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::MULTIPLE_SERVICES_CREDIT_CONTROL), mscc_t_avps);
    ccr_t.avps.push_back(mscc_t);

    auto ccr_t_result = parser.parse(ccr_t);
    ASSERT_TRUE(ccr_t_result.has_value());
    EXPECT_EQ(ccr_t_result->ccr->cc_request_type, CCRequestType::TERMINATION_REQUEST);
    EXPECT_EQ(ccr_t_result->ccr->cc_request_number, 2);
}

TEST_F(DiameterGyParserTest, IntegrationTest_QuotaExhaustion) {
    // Simulate quota exhaustion scenario

    // CCR-Update when quota is exhausted
    DiameterMessage ccr = createBasicGyMessage(true);
    ccr.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::CC_REQUEST_TYPE), 2));  // UPDATE
    ccr.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::CC_REQUEST_NUMBER), 1));

    std::vector<std::shared_ptr<DiameterAVP>> usu_avps;
    usu_avps.push_back(createUint64AVP(
        static_cast<uint32_t>(GyAVPCode::CC_TOTAL_OCTETS), 1073741824));  // 1GB (all quota used)
    usu_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::REPORTING_REASON),
        static_cast<uint32_t>(ReportingReason::QUOTA_EXHAUSTED)));

    auto usu = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::USED_SERVICE_UNIT), usu_avps);

    std::vector<std::shared_ptr<DiameterAVP>> rsu_avps;
    rsu_avps.push_back(createUint64AVP(
        static_cast<uint32_t>(GyAVPCode::CC_TOTAL_OCTETS), 0));  // Request more

    auto rsu = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::REQUESTED_SERVICE_UNIT), rsu_avps);

    std::vector<std::shared_ptr<DiameterAVP>> mscc_avps;
    mscc_avps.push_back(usu);
    mscc_avps.push_back(rsu);
    mscc_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::RATING_GROUP), 100));

    auto mscc = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::MULTIPLE_SERVICES_CREDIT_CONTROL), mscc_avps);
    ccr.avps.push_back(mscc);

    auto ccr_result = parser.parse(ccr);
    ASSERT_TRUE(ccr_result.has_value());
    ASSERT_EQ(ccr_result->ccr->mscc.size(), 1);
    EXPECT_TRUE(ccr_result->ccr->mscc[0].used_service_unit.has_value());
    EXPECT_EQ(ccr_result->ccr->mscc[0].reporting_reason.value(),
              ReportingReason::QUOTA_EXHAUSTED);

    // CCA with final unit indication (terminate or redirect)
    DiameterMessage cca = createBasicGyMessage(false);
    cca.result_code = static_cast<uint32_t>(DiameterResultCode::DIAMETER_SUCCESS);
    cca.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::CC_REQUEST_TYPE), 2));
    cca.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::CC_REQUEST_NUMBER), 1));

    // Final unit indication with redirect
    std::vector<std::shared_ptr<DiameterAVP>> rs_avps;
    rs_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::REDIRECT_ADDRESS_TYPE),
        static_cast<uint32_t>(RedirectAddressType::URL)));
    rs_avps.push_back(createStringAVP(
        static_cast<uint32_t>(GyAVPCode::REDIRECT_SERVER_ADDRESS),
        "http://operator.com/topup"));

    auto rs = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::REDIRECT_SERVER), rs_avps);

    std::vector<std::shared_ptr<DiameterAVP>> fui_avps;
    fui_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::FINAL_UNIT_ACTION),
        static_cast<uint32_t>(FinalUnitAction::REDIRECT)));
    fui_avps.push_back(rs);

    auto fui = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::FINAL_UNIT_INDICATION), fui_avps);

    std::vector<std::shared_ptr<DiameterAVP>> mscc_cca_avps;
    mscc_cca_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::RATING_GROUP), 100));
    mscc_cca_avps.push_back(fui);

    auto mscc_cca = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::MULTIPLE_SERVICES_CREDIT_CONTROL), mscc_cca_avps);
    cca.avps.push_back(mscc_cca);

    auto cca_result = parser.parse(cca);
    ASSERT_TRUE(cca_result.has_value());
    ASSERT_EQ(cca_result->cca->mscc.size(), 1);
    EXPECT_TRUE(cca_result->cca->mscc[0].final_unit_indication.has_value());
    EXPECT_EQ(cca_result->cca->mscc[0].final_unit_indication->final_unit_action,
              FinalUnitAction::REDIRECT);
}

TEST_F(DiameterGyParserTest, ToJson) {
    DiameterMessage msg = createBasicGyMessage(true);

    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::CC_REQUEST_TYPE), 1));
    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::CC_REQUEST_NUMBER), 0));
    msg.avps.push_back(createStringAVP(
        static_cast<uint32_t>(GyAVPCode::CALLED_STATION_ID), "internet.apn"));

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());

    auto json = result->toJson();
    EXPECT_TRUE(json.contains("interface"));
    EXPECT_EQ(json["interface"], "Gy");
    EXPECT_TRUE(json.contains("called_station_id"));
    EXPECT_EQ(json["called_station_id"], "internet.apn");
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
