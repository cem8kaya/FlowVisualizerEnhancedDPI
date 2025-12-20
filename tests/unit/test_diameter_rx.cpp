#include <gtest/gtest.h>
#include "protocol_parsers/diameter/diameter_rx.h"
#include "protocol_parsers/diameter/diameter_avp_parser.h"
#include <arpa/inet.h>

using namespace callflow::diameter;

class DiameterRxParserTest : public ::testing::Test {
protected:
    DiameterRxParser parser;

    DiameterMessage createBasicRxMessage(bool is_request, DiameterCommandCode cmd) {
        DiameterMessage msg;
        msg.header.version = 1;
        msg.header.command_code = static_cast<uint32_t>(cmd);
        msg.header.application_id = DIAMETER_RX_APPLICATION_ID;
        msg.header.request = is_request;
        msg.auth_application_id = DIAMETER_RX_APPLICATION_ID;
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

TEST_F(DiameterRxParserTest, IsRxMessage) {
    DiameterMessage msg = createBasicRxMessage(true, DiameterCommandCode::AA_REQUEST);
    EXPECT_TRUE(DiameterRxParser::isRxMessage(msg));
}

TEST_F(DiameterRxParserTest, ParseAAR_Basic) {
    DiameterMessage msg = createBasicRxMessage(true, DiameterCommandCode::AA_REQUEST);

    // Add Framed-IP-Address
    auto framed_ip_avp = std::make_shared<DiameterAVP>();
    framed_ip_avp->code = static_cast<uint32_t>(RxAVPCode::FRAMED_IP_ADDRESS);
    framed_ip_avp->data = {0x00, 0x01, 192, 168, 1, 100};
    msg.avps.push_back(framed_ip_avp);

    // Add AF Application Identifier
    msg.avps.push_back(createStringAVP(
        static_cast<uint32_t>(RxAVPCode::AF_APPLICATION_IDENTIFIER), "ims-volte"));

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->aar.has_value());

    const auto& aar = result->aar.value();
    EXPECT_TRUE(aar.framed_ip_address.has_value());
    EXPECT_EQ(aar.framed_ip_address.value(), "192.168.1.100");
    EXPECT_TRUE(aar.af_application_identifier.has_value());
    EXPECT_EQ(aar.af_application_identifier.value(), "ims-volte");
}

TEST_F(DiameterRxParserTest, ParseMediaComponentDescription) {
    DiameterMessage msg = createBasicRxMessage(true, DiameterCommandCode::AA_REQUEST);

    // Create media sub-component
    std::vector<std::shared_ptr<DiameterAVP>> sub_comp_avps;
    sub_comp_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(RxAVPCode::FLOW_NUMBER), 1));
    sub_comp_avps.push_back(createStringAVP(
        static_cast<uint32_t>(RxAVPCode::FLOW_DESCRIPTION),
        "permit in ip from 10.0.0.1 to 10.0.0.2"));
    sub_comp_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(RxAVPCode::FLOW_USAGE),
        static_cast<uint32_t>(FlowUsage::RTCP)));

    auto sub_comp = createGroupedAVP(
        static_cast<uint32_t>(RxAVPCode::MEDIA_SUB_COMPONENT), sub_comp_avps);

    // Create media component description
    std::vector<std::shared_ptr<DiameterAVP>> media_comp_avps;
    media_comp_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(RxAVPCode::MEDIA_COMPONENT_NUMBER), 1));
    media_comp_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(RxAVPCode::MEDIA_TYPE),
        static_cast<uint32_t>(MediaType::AUDIO)));
    media_comp_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(RxAVPCode::MAX_REQUESTED_BANDWIDTH_DL), 64000));
    media_comp_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(RxAVPCode::MAX_REQUESTED_BANDWIDTH_UL), 64000));
    media_comp_avps.push_back(sub_comp);

    auto media_comp = createGroupedAVP(
        static_cast<uint32_t>(RxAVPCode::MEDIA_COMPONENT_DESCRIPTION), media_comp_avps);

    msg.avps.push_back(media_comp);

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->aar.has_value());

    const auto& aar = result->aar.value();
    ASSERT_EQ(aar.media_components.size(), 1);

    const auto& media = aar.media_components[0];
    EXPECT_EQ(media.media_component_number, 1);
    EXPECT_TRUE(media.media_type.has_value());
    EXPECT_EQ(media.media_type.value(), MediaType::AUDIO);
    EXPECT_TRUE(media.max_requested_bandwidth_dl.has_value());
    EXPECT_EQ(media.max_requested_bandwidth_dl.value(), 64000);
    EXPECT_TRUE(media.max_requested_bandwidth_ul.has_value());
    EXPECT_EQ(media.max_requested_bandwidth_ul.value(), 64000);
    ASSERT_EQ(media.media_sub_components.size(), 1);

    const auto& sub = media.media_sub_components[0];
    EXPECT_EQ(sub.flow_number, 1);
    EXPECT_EQ(sub.flow_usage, FlowUsage::RTCP);
    ASSERT_EQ(sub.flow_descriptions.size(), 1);
}

TEST_F(DiameterRxParserTest, ParseAAA_Success) {
    DiameterMessage msg = createBasicRxMessage(false, DiameterCommandCode::AA_REQUEST);
    msg.result_code = static_cast<uint32_t>(DiameterResultCode::DIAMETER_SUCCESS);

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->aaa.has_value());

    const auto& aaa = result->aaa.value();
    EXPECT_EQ(aaa.result_code, static_cast<uint32_t>(DiameterResultCode::DIAMETER_SUCCESS));
}

TEST_F(DiameterRxParserTest, ParseSpecificActions) {
    DiameterMessage msg = createBasicRxMessage(true, DiameterCommandCode::AA_REQUEST);

    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(RxAVPCode::SPECIFIC_ACTION),
        static_cast<uint32_t>(SpecificAction::CHARGING_CORRELATION_EXCHANGE)));
    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(RxAVPCode::SPECIFIC_ACTION),
        static_cast<uint32_t>(SpecificAction::USAGE_REPORT)));

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->aar.has_value());

    const auto& aar = result->aar.value();
    EXPECT_EQ(aar.specific_actions.size(), 2);
    EXPECT_EQ(aar.specific_actions[0], SpecificAction::CHARGING_CORRELATION_EXCHANGE);
    EXPECT_EQ(aar.specific_actions[1], SpecificAction::USAGE_REPORT);
}

TEST_F(DiameterRxParserTest, ParseSTR) {
    DiameterMessage msg = createBasicRxMessage(true, DiameterCommandCode::SESSION_TERMINATION);

    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(DiameterAVPCode::TERMINATION_CAUSE), 1));

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->str.has_value());

    const auto& str = result->str.value();
    EXPECT_EQ(str.termination_cause, 1);
}

TEST_F(DiameterRxParserTest, ParseASR_WithAbortCause) {
    DiameterMessage msg = createBasicRxMessage(true, DiameterCommandCode::ABORT_SESSION);

    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(RxAVPCode::ABORT_CAUSE),
        static_cast<uint32_t>(AbortCause::BEARER_RELEASED)));

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->asr.has_value());

    const auto& asr = result->asr.value();
    EXPECT_TRUE(asr.abort_cause.has_value());
    EXPECT_EQ(asr.abort_cause.value(), AbortCause::BEARER_RELEASED);
}

TEST_F(DiameterRxParserTest, ToJson) {
    DiameterMessage msg = createBasicRxMessage(true, DiameterCommandCode::AA_REQUEST);
    msg.avps.push_back(createStringAVP(
        static_cast<uint32_t>(RxAVPCode::AF_APPLICATION_IDENTIFIER), "ims-volte"));

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());

    auto json = result->toJson();
    EXPECT_TRUE(json.contains("interface"));
    EXPECT_EQ(json["interface"], "Rx");
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
