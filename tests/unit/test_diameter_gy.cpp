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
