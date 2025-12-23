#include <gtest/gtest.h>
#include "protocol_parsers/diameter/diameter_gy.h"
#include "protocol_parsers/diameter/diameter_avp_parser.h"
#include <arpa/inet.h>

using namespace callflow::diameter;

class GyServiceUnitsTest : public ::testing::Test {
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

    std::shared_ptr<DiameterAVP> createGroupedAVP(uint32_t code,
                                                   std::vector<std::shared_ptr<DiameterAVP>> children) {
        auto avp = std::make_shared<DiameterAVP>();
        avp->code = code;
        avp->decoded_value = children;
        return avp;
    }
};

TEST_F(GyServiceUnitsTest, ParseGrantedServiceUnit_TimeOnly) {
    std::vector<std::shared_ptr<DiameterAVP>> gsu_avps;
    gsu_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::CC_TIME), 3600));  // 1 hour

    auto gsu_avp = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::GRANTED_SERVICE_UNIT), gsu_avps);

    auto result = parser.parseServiceUnit(gsu_avp);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->cc_time.has_value());
    EXPECT_EQ(result->cc_time.value(), 3600);
    EXPECT_FALSE(result->cc_total_octets.has_value());
}

TEST_F(GyServiceUnitsTest, ParseGrantedServiceUnit_OctetsOnly) {
    std::vector<std::shared_ptr<DiameterAVP>> gsu_avps;
    gsu_avps.push_back(createUint64AVP(
        static_cast<uint32_t>(GyAVPCode::CC_TOTAL_OCTETS), 1073741824));  // 1GB

    auto gsu_avp = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::GRANTED_SERVICE_UNIT), gsu_avps);

    auto result = parser.parseServiceUnit(gsu_avp);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->cc_total_octets.has_value());
    EXPECT_EQ(result->cc_total_octets.value(), 1073741824);
    EXPECT_FALSE(result->cc_time.has_value());
}

TEST_F(GyServiceUnitsTest, ParseGrantedServiceUnit_TimeAndOctets) {
    std::vector<std::shared_ptr<DiameterAVP>> gsu_avps;
    gsu_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::CC_TIME), 7200));  // 2 hours
    gsu_avps.push_back(createUint64AVP(
        static_cast<uint32_t>(GyAVPCode::CC_TOTAL_OCTETS), 2147483648));  // 2GB

    auto gsu_avp = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::GRANTED_SERVICE_UNIT), gsu_avps);

    auto result = parser.parseServiceUnit(gsu_avp);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->cc_time.has_value());
    EXPECT_EQ(result->cc_time.value(), 7200);
    EXPECT_TRUE(result->cc_total_octets.has_value());
    EXPECT_EQ(result->cc_total_octets.value(), 2147483648);
}

TEST_F(GyServiceUnitsTest, ParseGrantedServiceUnit_InputOutputOctets) {
    std::vector<std::shared_ptr<DiameterAVP>> gsu_avps;
    gsu_avps.push_back(createUint64AVP(
        static_cast<uint32_t>(GyAVPCode::CC_INPUT_OCTETS), 536870912));   // 512MB uplink
    gsu_avps.push_back(createUint64AVP(
        static_cast<uint32_t>(GyAVPCode::CC_OUTPUT_OCTETS), 5368709120));  // 5GB downlink

    auto gsu_avp = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::GRANTED_SERVICE_UNIT), gsu_avps);

    auto result = parser.parseServiceUnit(gsu_avp);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->cc_input_octets.has_value());
    EXPECT_EQ(result->cc_input_octets.value(), 536870912);
    EXPECT_TRUE(result->cc_output_octets.has_value());
    EXPECT_EQ(result->cc_output_octets.value(), 5368709120);
}

TEST_F(GyServiceUnitsTest, ParseUsedServiceUnit_WithReportingReason) {
    std::vector<std::shared_ptr<DiameterAVP>> usu_avps;
    usu_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::CC_TIME), 1800));  // 30 minutes
    usu_avps.push_back(createUint64AVP(
        static_cast<uint32_t>(GyAVPCode::CC_TOTAL_OCTETS), 104857600));  // 100MB
    usu_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::REPORTING_REASON),
        static_cast<uint32_t>(ReportingReason::THRESHOLD)));

    auto usu_avp = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::USED_SERVICE_UNIT), usu_avps);

    auto result = parser.parseUsedServiceUnit(usu_avp);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->cc_time.has_value());
    EXPECT_EQ(result->cc_time.value(), 1800);
    EXPECT_TRUE(result->cc_total_octets.has_value());
    EXPECT_EQ(result->cc_total_octets.value(), 104857600);
    EXPECT_TRUE(result->reporting_reason.has_value());
    EXPECT_EQ(result->reporting_reason.value(), static_cast<uint32_t>(ReportingReason::THRESHOLD));
}

TEST_F(GyServiceUnitsTest, ParseUsedServiceUnit_QuotaExhausted) {
    std::vector<std::shared_ptr<DiameterAVP>> usu_avps;
    usu_avps.push_back(createUint64AVP(
        static_cast<uint32_t>(GyAVPCode::CC_TOTAL_OCTETS), 1073741824));  // 1GB
    usu_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::REPORTING_REASON),
        static_cast<uint32_t>(ReportingReason::QUOTA_EXHAUSTED)));

    auto usu_avp = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::USED_SERVICE_UNIT), usu_avps);

    auto result = parser.parseUsedServiceUnit(usu_avp);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->cc_total_octets.has_value());
    EXPECT_EQ(result->cc_total_octets.value(), 1073741824);
    EXPECT_TRUE(result->reporting_reason.has_value());
    EXPECT_EQ(result->reporting_reason.value(),
              static_cast<uint32_t>(ReportingReason::QUOTA_EXHAUSTED));
}

TEST_F(GyServiceUnitsTest, ParseUsedServiceUnit_FinalReport) {
    std::vector<std::shared_ptr<DiameterAVP>> usu_avps;
    usu_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::CC_TIME), 10800));  // 3 hours
    usu_avps.push_back(createUint64AVP(
        static_cast<uint32_t>(GyAVPCode::CC_INPUT_OCTETS), 104857600));   // 100MB uplink
    usu_avps.push_back(createUint64AVP(
        static_cast<uint32_t>(GyAVPCode::CC_OUTPUT_OCTETS), 1073741824));  // 1GB downlink
    usu_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::REPORTING_REASON),
        static_cast<uint32_t>(ReportingReason::FINAL)));

    auto usu_avp = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::USED_SERVICE_UNIT), usu_avps);

    auto result = parser.parseUsedServiceUnit(usu_avp);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->cc_time.value(), 10800);
    EXPECT_EQ(result->cc_input_octets.value(), 104857600);
    EXPECT_EQ(result->cc_output_octets.value(), 1073741824);
    EXPECT_EQ(result->reporting_reason.value(), static_cast<uint32_t>(ReportingReason::FINAL));
}

TEST_F(GyServiceUnitsTest, ParseUsedServiceUnit_WithTariffChange) {
    std::vector<std::shared_ptr<DiameterAVP>> usu_avps;
    usu_avps.push_back(createUint64AVP(
        static_cast<uint32_t>(GyAVPCode::CC_TOTAL_OCTETS), 536870912));  // 512MB
    usu_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::TARIFF_CHANGE_USAGE),
        static_cast<uint32_t>(TariffChangeUsage::UNIT_BEFORE_TARIFF_CHANGE)));

    auto usu_avp = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::USED_SERVICE_UNIT), usu_avps);

    auto result = parser.parseUsedServiceUnit(usu_avp);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->cc_total_octets.has_value());
    EXPECT_TRUE(result->tariff_change_usage.has_value());
    EXPECT_EQ(result->tariff_change_usage.value(),
              TariffChangeUsage::UNIT_BEFORE_TARIFF_CHANGE);
}

TEST_F(GyServiceUnitsTest, ParseRequestedServiceUnit_AllTypes) {
    std::vector<std::shared_ptr<DiameterAVP>> rsu_avps;
    rsu_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::CC_TIME), 0));  // Request quota
    rsu_avps.push_back(createUint64AVP(
        static_cast<uint32_t>(GyAVPCode::CC_TOTAL_OCTETS), 0));  // Request quota
    rsu_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::CC_SERVICE_SPECIFIC_UNITS), 0));

    auto rsu_avp = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::REQUESTED_SERVICE_UNIT), rsu_avps);

    auto result = parser.parseServiceUnit(rsu_avp);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->cc_time.has_value());
    EXPECT_TRUE(result->cc_total_octets.has_value());
    EXPECT_TRUE(result->cc_service_specific_units.has_value());
}

TEST_F(GyServiceUnitsTest, ServiceUnitToJson) {
    std::vector<std::shared_ptr<DiameterAVP>> gsu_avps;
    gsu_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(GyAVPCode::CC_TIME), 3600));
    gsu_avps.push_back(createUint64AVP(
        static_cast<uint32_t>(GyAVPCode::CC_TOTAL_OCTETS), 1073741824));
    gsu_avps.push_back(createUint64AVP(
        static_cast<uint32_t>(GyAVPCode::CC_INPUT_OCTETS), 104857600));
    gsu_avps.push_back(createUint64AVP(
        static_cast<uint32_t>(GyAVPCode::CC_OUTPUT_OCTETS), 1048576000));

    auto gsu_avp = createGroupedAVP(
        static_cast<uint32_t>(GyAVPCode::GRANTED_SERVICE_UNIT), gsu_avps);

    auto result = parser.parseServiceUnit(gsu_avp);
    ASSERT_TRUE(result.has_value());

    auto json = result->toJson();
    EXPECT_TRUE(json.contains("cc_time"));
    EXPECT_EQ(json["cc_time"], 3600);
    EXPECT_TRUE(json.contains("cc_total_octets"));
    EXPECT_EQ(json["cc_total_octets"], 1073741824);
    EXPECT_TRUE(json.contains("cc_input_octets"));
    EXPECT_EQ(json["cc_input_octets"], 104857600);
    EXPECT_TRUE(json.contains("cc_output_octets"));
    EXPECT_EQ(json["cc_output_octets"], 1048576000);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
