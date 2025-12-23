#include <gtest/gtest.h>
#include "protocol_parsers/diameter/diameter_gy.h"
#include "protocol_parsers/diameter/diameter_avp_parser.h"
#include <arpa/inet.h>

using namespace callflow::diameter;

class GyMSCCTest : public ::testing::Test {
protected:
    DiameterGyParser parser;

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

TEST_F(GyMSCCTest, ParseMSCC_BasicStructure) {
    std::vector<std::shared_ptr<DiameterAVP>> mscc_avps;
    mscc_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::RATING_GROUP), 100));
    mscc_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::SERVICE_IDENTIFIER), 1));

    auto mscc_avp = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::MULTIPLE_SERVICES_CREDIT_CONTROL), mscc_avps);

    auto result = parser.parseMSCC(mscc_avp);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->rating_group.has_value());
    EXPECT_EQ(result->rating_group.value(), 100);
    EXPECT_TRUE(result->service_identifier.has_value());
    EXPECT_EQ(result->service_identifier.value(), 1);
}

TEST_F(GyMSCCTest, ParseMSCC_WithValidityTime) {
    std::vector<std::shared_ptr<DiameterAVP>> mscc_avps;
    mscc_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::RATING_GROUP), 100));
    mscc_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::VALIDITY_TIME), 3600));  // 1 hour

    auto mscc_avp = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::MULTIPLE_SERVICES_CREDIT_CONTROL), mscc_avps);

    auto result = parser.parseMSCC(mscc_avp);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->validity_time.has_value());
    EXPECT_EQ(result->validity_time.value(), 3600);
}

TEST_F(GyMSCCTest, ParseMSCC_WithResultCode) {
    std::vector<std::shared_ptr<DiameterAVP>> mscc_avps;
    mscc_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::RATING_GROUP), 100));
    mscc_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::RESULT_CODE),
        static_cast<uint32_t>(DiameterResultCode::DIAMETER_SUCCESS)));

    auto mscc_avp = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::MULTIPLE_SERVICES_CREDIT_CONTROL), mscc_avps);

    auto result = parser.parseMSCC(mscc_avp);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->result_code.has_value());
    EXPECT_EQ(result->result_code.value(),
              static_cast<uint32_t>(DiameterResultCode::DIAMETER_SUCCESS));
}

TEST_F(GyMSCCTest, ParseMSCC_WithFinalUnitIndication_Terminate) {
    // Create Final Unit Indication
    std::vector<std::shared_ptr<DiameterAVP>> fui_avps;
    fui_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::FINAL_UNIT_ACTION),
        static_cast<uint32_t>(FinalUnitAction::TERMINATE)));

    auto fui_avp = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::FINAL_UNIT_INDICATION), fui_avps);

    // Create MSCC with FUI
    std::vector<std::shared_ptr<DiameterAVP>> mscc_avps;
    mscc_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::RATING_GROUP), 100));
    mscc_avps.push_back(fui_avp);

    auto mscc_avp = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::MULTIPLE_SERVICES_CREDIT_CONTROL), mscc_avps);

    auto result = parser.parseMSCC(mscc_avp);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->final_unit_indication.has_value());
    EXPECT_EQ(result->final_unit_indication->final_unit_action, FinalUnitAction::TERMINATE);
}

TEST_F(GyMSCCTest, ParseMSCC_WithFinalUnitIndication_Redirect) {
    // Create Redirect Server
    std::vector<std::shared_ptr<DiameterAVP>> rs_avps;
    rs_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::REDIRECT_ADDRESS_TYPE),
        static_cast<uint32_t>(RedirectAddressType::URL)));
    rs_avps.push_back(createStringAVP(
        static_cast<uint32_t>(GyAVPCode::REDIRECT_SERVER_ADDRESS),
        "http://operator.com/portal"));

    auto rs_avp = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::REDIRECT_SERVER), rs_avps);

    // Create Final Unit Indication with redirect
    std::vector<std::shared_ptr<DiameterAVP>> fui_avps;
    fui_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::FINAL_UNIT_ACTION),
        static_cast<uint32_t>(FinalUnitAction::REDIRECT)));
    fui_avps.push_back(rs_avp);

    auto fui_avp = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::FINAL_UNIT_INDICATION), fui_avps);

    // Create MSCC
    std::vector<std::shared_ptr<DiameterAVP>> mscc_avps;
    mscc_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::RATING_GROUP), 100));
    mscc_avps.push_back(fui_avp);

    auto mscc_avp = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::MULTIPLE_SERVICES_CREDIT_CONTROL), mscc_avps);

    auto result = parser.parseMSCC(mscc_avp);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->final_unit_indication.has_value());
    EXPECT_EQ(result->final_unit_indication->final_unit_action, FinalUnitAction::REDIRECT);
    ASSERT_TRUE(result->final_unit_indication->redirect_server.has_value());
    EXPECT_EQ(result->final_unit_indication->redirect_server->redirect_address_type,
              RedirectAddressType::URL);
    EXPECT_EQ(result->final_unit_indication->redirect_server->redirect_server_address,
              "http://operator.com/portal");
}

TEST_F(GyMSCCTest, ParseMSCC_WithFinalUnitIndication_RestrictAccess) {
    // Create Final Unit Indication with restriction filters
    std::vector<std::shared_ptr<DiameterAVP>> fui_avps;
    fui_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::FINAL_UNIT_ACTION),
        static_cast<uint32_t>(FinalUnitAction::RESTRICT_ACCESS)));
    fui_avps.push_back(createStringAVP(
        static_cast<uint32_t>(GyAVPCode::RESTRICTION_FILTER_RULE),
        "permit out from any to 10.0.0.0/8"));
    fui_avps.push_back(createStringAVP(
        static_cast<uint32_t>(GyAVPCode::FILTER_ID), "PORTAL_ONLY"));

    auto fui_avp = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::FINAL_UNIT_INDICATION), fui_avps);

    // Create MSCC
    std::vector<std::shared_ptr<DiameterAVP>> mscc_avps;
    mscc_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::RATING_GROUP), 100));
    mscc_avps.push_back(fui_avp);

    auto mscc_avp = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::MULTIPLE_SERVICES_CREDIT_CONTROL), mscc_avps);

    auto result = parser.parseMSCC(mscc_avp);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->final_unit_indication.has_value());
    EXPECT_EQ(result->final_unit_indication->final_unit_action, FinalUnitAction::RESTRICT_ACCESS);
    EXPECT_EQ(result->final_unit_indication->restriction_filter_rule.size(), 1);
    EXPECT_EQ(result->final_unit_indication->filter_id.size(), 1);
}

TEST_F(GyMSCCTest, ParseMSCC_CompleteWithAllFields) {
    // Create Granted Service Unit
    std::vector<std::shared_ptr<DiameterAVP>> gsu_avps;
    gsu_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::CC_TIME), 3600));
    gsu_avps.push_back(createUint64AVP(
        static_cast<uint32_t>(GyAVPCode::CC_TOTAL_OCTETS), 1073741824));

    auto gsu_avp = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::GRANTED_SERVICE_UNIT), gsu_avps);

    // Create Requested Service Unit
    std::vector<std::shared_ptr<DiameterAVP>> rsu_avps;
    rsu_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::CC_TIME), 0));
    rsu_avps.push_back(createUint64AVP(
        static_cast<uint32_t>(GyAVPCode::CC_TOTAL_OCTETS), 0));

    auto rsu_avp = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::REQUESTED_SERVICE_UNIT), rsu_avps);

    // Create Used Service Unit
    std::vector<std::shared_ptr<DiameterAVP>> usu_avps;
    usu_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::CC_TIME), 1800));
    usu_avps.push_back(createUint64AVP(
        static_cast<uint32_t>(GyAVPCode::CC_TOTAL_OCTETS), 536870912));

    auto usu_avp = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::USED_SERVICE_UNIT), usu_avps);

    // Create complete MSCC
    std::vector<std::shared_ptr<DiameterAVP>> mscc_avps;
    mscc_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::RATING_GROUP), 100));
    mscc_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::SERVICE_IDENTIFIER), 1));
    mscc_avps.push_back(gsu_avp);
    mscc_avps.push_back(rsu_avp);
    mscc_avps.push_back(usu_avp);
    mscc_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::VALIDITY_TIME), 7200));
    mscc_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::RESULT_CODE),
        static_cast<uint32_t>(DiameterResultCode::DIAMETER_SUCCESS)));

    auto mscc_avp = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::MULTIPLE_SERVICES_CREDIT_CONTROL), mscc_avps);

    auto result = parser.parseMSCC(mscc_avp);
    ASSERT_TRUE(result.has_value());

    // Verify all fields
    EXPECT_EQ(result->rating_group.value(), 100);
    EXPECT_EQ(result->service_identifier.value(), 1);
    EXPECT_TRUE(result->granted_service_unit.has_value());
    EXPECT_TRUE(result->requested_service_unit.has_value());
    EXPECT_TRUE(result->used_service_unit.has_value());
    EXPECT_EQ(result->validity_time.value(), 7200);
    EXPECT_EQ(result->result_code.value(),
              static_cast<uint32_t>(DiameterResultCode::DIAMETER_SUCCESS));
}

TEST_F(GyMSCCTest, ParseMSCC_WithReportingReason) {
    std::vector<std::shared_ptr<DiameterAVP>> mscc_avps;
    mscc_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::RATING_GROUP), 100));
    mscc_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::REPORTING_REASON),
        static_cast<uint32_t>(ReportingReason::QUOTA_EXHAUSTED)));

    auto mscc_avp = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::MULTIPLE_SERVICES_CREDIT_CONTROL), mscc_avps);

    auto result = parser.parseMSCC(mscc_avp);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->reporting_reason.has_value());
    EXPECT_EQ(result->reporting_reason.value(), ReportingReason::QUOTA_EXHAUSTED);
}

TEST_F(GyMSCCTest, ParseMSCC_WithMultipleTriggers) {
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
    mscc_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::TRIGGER_TYPE),
        static_cast<uint32_t>(TriggerType::CHANGE_IN_SGSN_IP_ADDRESS)));

    auto mscc_avp = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::MULTIPLE_SERVICES_CREDIT_CONTROL), mscc_avps);

    auto result = parser.parseMSCC(mscc_avp);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->triggers.size(), 4);
    EXPECT_EQ(result->triggers[0], TriggerType::CHANGE_IN_QOS);
    EXPECT_EQ(result->triggers[1], TriggerType::CHANGE_IN_LOCATION);
    EXPECT_EQ(result->triggers[2], TriggerType::CHANGE_IN_RAT);
    EXPECT_EQ(result->triggers[3], TriggerType::CHANGE_IN_SGSN_IP_ADDRESS);
}

TEST_F(GyMSCCTest, MSCCToJson) {
    // Create a complete MSCC
    std::vector<std::shared_ptr<DiameterAVP>> gsu_avps;
    gsu_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::CC_TIME), 3600));
    gsu_avps.push_back(createUint64AVP(
        static_cast<uint32_t>(GyAVPCode::CC_TOTAL_OCTETS), 1073741824));

    auto gsu_avp = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::GRANTED_SERVICE_UNIT), gsu_avps);

    std::vector<std::shared_ptr<DiameterAVP>> mscc_avps;
    mscc_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::RATING_GROUP), 100));
    mscc_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::SERVICE_IDENTIFIER), 1));
    mscc_avps.push_back(gsu_avp);
    mscc_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::VALIDITY_TIME), 7200));

    auto mscc_avp = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::MULTIPLE_SERVICES_CREDIT_CONTROL), mscc_avps);

    auto result = parser.parseMSCC(mscc_avp);
    ASSERT_TRUE(result.has_value());

    auto json = result->toJson();
    EXPECT_TRUE(json.contains("rating_group"));
    EXPECT_EQ(json["rating_group"], 100);
    EXPECT_TRUE(json.contains("service_identifier"));
    EXPECT_EQ(json["service_identifier"], 1);
    EXPECT_TRUE(json.contains("granted_service_unit"));
    EXPECT_TRUE(json.contains("validity_time"));
    EXPECT_EQ(json["validity_time"], 7200);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
