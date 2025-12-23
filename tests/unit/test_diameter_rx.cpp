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

// ============================================================================
// VoLTE Audio Call Tests
// ============================================================================

TEST_F(DiameterRxParserTest, ParseAAR_VoLTEAudioCall) {
    DiameterMessage msg = createBasicRxMessage(true, DiameterCommandCode::AA_REQUEST);

    // Add Framed-IP-Address
    auto framed_ip_avp = std::make_shared<DiameterAVP>();
    framed_ip_avp->code = static_cast<uint32_t>(RxAVPCode::FRAMED_IP_ADDRESS);
    framed_ip_avp->data = {0x00, 0x01, 192, 168, 1, 100};
    msg.avps.push_back(framed_ip_avp);

    // Add AF Application Identifier
    msg.avps.push_back(createStringAVP(
        static_cast<uint32_t>(RxAVPCode::AF_APPLICATION_IDENTIFIER), "IMS_VoLTE"));

    // Add AF Charging Identifier (ICID) for correlation
    auto af_charging_avp = std::make_shared<DiameterAVP>();
    af_charging_avp->code = static_cast<uint32_t>(RxAVPCode::AF_CHARGING_IDENTIFIER);
    std::string icid = "icid-123-456-789-abc";
    af_charging_avp->data.assign(icid.begin(), icid.end());
    msg.avps.push_back(af_charging_avp);

    // Create media sub-component for audio RTP
    std::vector<std::shared_ptr<DiameterAVP>> sub_comp_avps;
    sub_comp_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(RxAVPCode::FLOW_NUMBER), 1));
    sub_comp_avps.push_back(createStringAVP(
        static_cast<uint32_t>(RxAVPCode::FLOW_DESCRIPTION),
        "permit in ip from 10.0.0.1 49152-49200 to 192.168.1.100 49152-49200"));
    sub_comp_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(RxAVPCode::FLOW_USAGE),
        static_cast<uint32_t>(FlowUsage::NO_INFORMATION)));

    auto sub_comp = createGroupedAVP(
        static_cast<uint32_t>(RxAVPCode::MEDIA_SUB_COMPONENT), sub_comp_avps);

    // Create media component description for audio
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
    media_comp_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(RxAVPCode::MIN_REQUESTED_BANDWIDTH_DL), 32000));
    media_comp_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(RxAVPCode::MIN_REQUESTED_BANDWIDTH_UL), 32000));
    media_comp_avps.push_back(createStringAVP(
        static_cast<uint32_t>(RxAVPCode::CODEC_DATA), "AMR"));
    media_comp_avps.push_back(sub_comp);

    auto media_comp = createGroupedAVP(
        static_cast<uint32_t>(RxAVPCode::MEDIA_COMPONENT_DESCRIPTION), media_comp_avps);

    msg.avps.push_back(media_comp);

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->aar.has_value());

    const auto& aar = result->aar.value();
    EXPECT_TRUE(aar.framed_ip_address.has_value());
    EXPECT_EQ(aar.framed_ip_address.value(), "192.168.1.100");
    EXPECT_TRUE(aar.af_application_identifier.has_value());
    EXPECT_EQ(aar.af_application_identifier.value(), "IMS_VoLTE");
    EXPECT_TRUE(aar.af_charging_identifier.has_value());

    ASSERT_EQ(aar.media_components.size(), 1);
    const auto& media = aar.media_components[0];
    EXPECT_EQ(media.media_component_number, 1);
    EXPECT_EQ(media.media_type.value(), MediaType::AUDIO);
    EXPECT_TRUE(media.codec_data.has_value());
    EXPECT_EQ(media.codec_data.value(), "AMR");
    ASSERT_EQ(media.media_sub_components.size(), 1);
}

// ============================================================================
// Video Call Tests
// ============================================================================

TEST_F(DiameterRxParserTest, ParseAAR_VideoCall) {
    DiameterMessage msg = createBasicRxMessage(true, DiameterCommandCode::AA_REQUEST);

    // Add Framed-IP-Address
    auto framed_ip_avp = std::make_shared<DiameterAVP>();
    framed_ip_avp->code = static_cast<uint32_t>(RxAVPCode::FRAMED_IP_ADDRESS);
    framed_ip_avp->data = {0x00, 0x01, 192, 168, 1, 100};
    msg.avps.push_back(framed_ip_avp);

    // Add AF Application Identifier
    msg.avps.push_back(createStringAVP(
        static_cast<uint32_t>(RxAVPCode::AF_APPLICATION_IDENTIFIER), "IMS_Video"));

    // Media Component 1: Audio
    std::vector<std::shared_ptr<DiameterAVP>> audio_sub_comp_avps;
    audio_sub_comp_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(RxAVPCode::FLOW_NUMBER), 1));
    audio_sub_comp_avps.push_back(createStringAVP(
        static_cast<uint32_t>(RxAVPCode::FLOW_DESCRIPTION),
        "permit in ip from 10.0.0.1 to 192.168.1.100"));
    audio_sub_comp_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(RxAVPCode::FLOW_USAGE),
        static_cast<uint32_t>(FlowUsage::NO_INFORMATION)));

    auto audio_sub_comp = createGroupedAVP(
        static_cast<uint32_t>(RxAVPCode::MEDIA_SUB_COMPONENT), audio_sub_comp_avps);

    std::vector<std::shared_ptr<DiameterAVP>> audio_comp_avps;
    audio_comp_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(RxAVPCode::MEDIA_COMPONENT_NUMBER), 1));
    audio_comp_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(RxAVPCode::MEDIA_TYPE),
        static_cast<uint32_t>(MediaType::AUDIO)));
    audio_comp_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(RxAVPCode::MAX_REQUESTED_BANDWIDTH_DL), 64000));
    audio_comp_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(RxAVPCode::MAX_REQUESTED_BANDWIDTH_UL), 64000));
    audio_comp_avps.push_back(createStringAVP(
        static_cast<uint32_t>(RxAVPCode::CODEC_DATA), "AMR-WB"));
    audio_comp_avps.push_back(audio_sub_comp);

    auto audio_comp = createGroupedAVP(
        static_cast<uint32_t>(RxAVPCode::MEDIA_COMPONENT_DESCRIPTION), audio_comp_avps);

    // Media Component 2: Video
    std::vector<std::shared_ptr<DiameterAVP>> video_sub_comp_avps;
    video_sub_comp_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(RxAVPCode::FLOW_NUMBER), 2));
    video_sub_comp_avps.push_back(createStringAVP(
        static_cast<uint32_t>(RxAVPCode::FLOW_DESCRIPTION),
        "permit in ip from 10.0.0.1 to 192.168.1.100"));
    video_sub_comp_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(RxAVPCode::FLOW_USAGE),
        static_cast<uint32_t>(FlowUsage::NO_INFORMATION)));

    auto video_sub_comp = createGroupedAVP(
        static_cast<uint32_t>(RxAVPCode::MEDIA_SUB_COMPONENT), video_sub_comp_avps);

    std::vector<std::shared_ptr<DiameterAVP>> video_comp_avps;
    video_comp_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(RxAVPCode::MEDIA_COMPONENT_NUMBER), 2));
    video_comp_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(RxAVPCode::MEDIA_TYPE),
        static_cast<uint32_t>(MediaType::VIDEO)));
    video_comp_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(RxAVPCode::MAX_REQUESTED_BANDWIDTH_DL), 384000));  // 384 kbps
    video_comp_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(RxAVPCode::MAX_REQUESTED_BANDWIDTH_UL), 384000));
    video_comp_avps.push_back(createStringAVP(
        static_cast<uint32_t>(RxAVPCode::CODEC_DATA), "H264"));
    video_comp_avps.push_back(video_sub_comp);

    auto video_comp = createGroupedAVP(
        static_cast<uint32_t>(RxAVPCode::MEDIA_COMPONENT_DESCRIPTION), video_comp_avps);

    msg.avps.push_back(audio_comp);
    msg.avps.push_back(video_comp);

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->aar.has_value());

    const auto& aar = result->aar.value();
    ASSERT_EQ(aar.media_components.size(), 2);

    // Check audio component
    const auto& audio = aar.media_components[0];
    EXPECT_EQ(audio.media_component_number, 1);
    EXPECT_EQ(audio.media_type.value(), MediaType::AUDIO);
    EXPECT_EQ(audio.codec_data.value(), "AMR-WB");

    // Check video component
    const auto& video = aar.media_components[1];
    EXPECT_EQ(video.media_component_number, 2);
    EXPECT_EQ(video.media_type.value(), MediaType::VIDEO);
    EXPECT_EQ(video.codec_data.value(), "H264");
    EXPECT_EQ(video.max_requested_bandwidth_dl.value(), 384000);
}

// ============================================================================
// ICID Extraction Tests
// ============================================================================

TEST_F(DiameterRxParserTest, ExtractICID_FromAFChargingIdentifier) {
    DiameterMessage msg = createBasicRxMessage(true, DiameterCommandCode::AA_REQUEST);

    // Add AF Charging Identifier (ICID)
    auto af_charging_avp = std::make_shared<DiameterAVP>();
    af_charging_avp->code = static_cast<uint32_t>(RxAVPCode::AF_CHARGING_IDENTIFIER);
    std::string icid = "icid-volte-call-12345";
    af_charging_avp->data.assign(icid.begin(), icid.end());
    msg.avps.push_back(af_charging_avp);

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->aar.has_value());

    const auto& aar = result->aar.value();
    EXPECT_TRUE(aar.af_charging_identifier.has_value());

    // ICID is stored as binary data
    std::string extracted_icid(aar.af_charging_identifier.value().begin(),
                                aar.af_charging_identifier.value().end());
    EXPECT_EQ(extracted_icid, "icid-volte-call-12345");
}

// ============================================================================
// AAA with Experimental Result Code
// ============================================================================

TEST_F(DiameterRxParserTest, ParseAAA_WithExperimentalResult) {
    DiameterMessage msg = createBasicRxMessage(false, DiameterCommandCode::AA_REQUEST);
    msg.result_code = 5002;  // DIAMETER_RESOURCES_EXCEEDED

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->aaa.has_value());

    const auto& aaa = result->aaa.value();
    EXPECT_EQ(aaa.result_code, 5002);
}

// ============================================================================
// RAR/RAA Bearer Loss Tests
// ============================================================================

TEST_F(DiameterRxParserTest, ParseRAR_BearerLossNotification) {
    DiameterMessage msg = createBasicRxMessage(true, DiameterCommandCode::RE_AUTH);

    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(DiameterAVPCode::RE_AUTH_REQUEST_TYPE), 0));

    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(RxAVPCode::SPECIFIC_ACTION),
        static_cast<uint32_t>(SpecificAction::INDICATION_OF_LOSS_OF_BEARER)));

    msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(RxAVPCode::ABORT_CAUSE),
        static_cast<uint32_t>(AbortCause::INSUFFICIENT_BEARER_RESOURCES)));

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->rar.has_value());

    const auto& rar = result->rar.value();
    EXPECT_EQ(rar.specific_actions.size(), 1);
    EXPECT_EQ(rar.specific_actions[0], SpecificAction::INDICATION_OF_LOSS_OF_BEARER);
    EXPECT_TRUE(rar.abort_cause.has_value());
    EXPECT_EQ(rar.abort_cause.value(), AbortCause::INSUFFICIENT_BEARER_RESOURCES);
}

TEST_F(DiameterRxParserTest, ParseRAA_Response) {
    DiameterMessage msg = createBasicRxMessage(false, DiameterCommandCode::RE_AUTH);
    msg.result_code = static_cast<uint32_t>(DiameterResultCode::DIAMETER_SUCCESS);

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->raa.has_value());

    const auto& raa = result->raa.value();
    EXPECT_EQ(raa.result_code, static_cast<uint32_t>(DiameterResultCode::DIAMETER_SUCCESS));
}

// ============================================================================
// STA Tests
// ============================================================================

TEST_F(DiameterRxParserTest, ParseSTA_Success) {
    DiameterMessage msg = createBasicRxMessage(false, DiameterCommandCode::SESSION_TERMINATION);
    msg.result_code = static_cast<uint32_t>(DiameterResultCode::DIAMETER_SUCCESS);

    auto result = parser.parse(msg);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->sta.has_value());

    const auto& sta = result->sta.value();
    EXPECT_EQ(sta.result_code, static_cast<uint32_t>(DiameterResultCode::DIAMETER_SUCCESS));
}

// ============================================================================
// Integration Tests
// ============================================================================

TEST_F(DiameterRxParserTest, IntegrationTest_VoLTESessionLifecycle) {
    // Test complete Rx session for VoLTE: AAR -> AAA -> STR -> STA

    // 1. Parse AAR from P-CSCF to PCRF
    DiameterMessage aar_msg = createBasicRxMessage(true, DiameterCommandCode::AA_REQUEST);

    auto framed_ip_avp = std::make_shared<DiameterAVP>();
    framed_ip_avp->code = static_cast<uint32_t>(RxAVPCode::FRAMED_IP_ADDRESS);
    framed_ip_avp->data = {0x00, 0x01, 192, 168, 1, 100};
    aar_msg.avps.push_back(framed_ip_avp);

    aar_msg.avps.push_back(createStringAVP(
        static_cast<uint32_t>(RxAVPCode::AF_APPLICATION_IDENTIFIER), "IMS_VoLTE"));

    // Add ICID for correlation
    auto af_charging_avp = std::make_shared<DiameterAVP>();
    af_charging_avp->code = static_cast<uint32_t>(RxAVPCode::AF_CHARGING_IDENTIFIER);
    std::string icid = "call-id-123";
    af_charging_avp->data.assign(icid.begin(), icid.end());
    aar_msg.avps.push_back(af_charging_avp);

    // Add specific actions to subscribe to
    aar_msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(RxAVPCode::SPECIFIC_ACTION),
        static_cast<uint32_t>(SpecificAction::INDICATION_OF_LOSS_OF_BEARER)));
    aar_msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(RxAVPCode::SPECIFIC_ACTION),
        static_cast<uint32_t>(SpecificAction::INDICATION_OF_RECOVERY_OF_BEARER)));

    // Create media component
    std::vector<std::shared_ptr<DiameterAVP>> sub_comp_avps;
    sub_comp_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(RxAVPCode::FLOW_NUMBER), 1));
    sub_comp_avps.push_back(createStringAVP(
        static_cast<uint32_t>(RxAVPCode::FLOW_DESCRIPTION),
        "permit in ip from 10.0.0.1 to 192.168.1.100"));
    sub_comp_avps.push_back(createUint32AVP(
        static_cast<uint32_t>(RxAVPCode::FLOW_USAGE),
        static_cast<uint32_t>(FlowUsage::NO_INFORMATION)));

    auto sub_comp = createGroupedAVP(
        static_cast<uint32_t>(RxAVPCode::MEDIA_SUB_COMPONENT), sub_comp_avps);

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

    aar_msg.avps.push_back(media_comp);

    auto aar_result = parser.parse(aar_msg);
    ASSERT_TRUE(aar_result.has_value());
    ASSERT_TRUE(aar_result->aar.has_value());
    EXPECT_EQ(aar_result->aar->media_components.size(), 1);
    EXPECT_EQ(aar_result->aar->specific_actions.size(), 2);

    // 2. Parse AAA from PCRF to P-CSCF
    DiameterMessage aaa_msg = createBasicRxMessage(false, DiameterCommandCode::AA_REQUEST);
    aaa_msg.result_code = static_cast<uint32_t>(DiameterResultCode::DIAMETER_SUCCESS);

    auto aaa_result = parser.parse(aaa_msg);
    ASSERT_TRUE(aaa_result.has_value());
    ASSERT_TRUE(aaa_result->aaa.has_value());
    EXPECT_EQ(aaa_result->aaa->result_code,
              static_cast<uint32_t>(DiameterResultCode::DIAMETER_SUCCESS));

    // 3. Parse STR from P-CSCF to PCRF (call ended)
    DiameterMessage str_msg = createBasicRxMessage(true, DiameterCommandCode::SESSION_TERMINATION);
    str_msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(DiameterAVPCode::TERMINATION_CAUSE), 1));  // DIAMETER_LOGOUT

    auto str_result = parser.parse(str_msg);
    ASSERT_TRUE(str_result.has_value());
    ASSERT_TRUE(str_result->str.has_value());
    EXPECT_EQ(str_result->str->termination_cause, 1);

    // 4. Parse STA from PCRF to P-CSCF
    DiameterMessage sta_msg = createBasicRxMessage(false, DiameterCommandCode::SESSION_TERMINATION);
    sta_msg.result_code = static_cast<uint32_t>(DiameterResultCode::DIAMETER_SUCCESS);

    auto sta_result = parser.parse(sta_msg);
    ASSERT_TRUE(sta_result.has_value());
    ASSERT_TRUE(sta_result->sta.has_value());
    EXPECT_EQ(sta_result->sta->result_code,
              static_cast<uint32_t>(DiameterResultCode::DIAMETER_SUCCESS));
}

TEST_F(DiameterRxParserTest, IntegrationTest_BearerLossRecovery) {
    // Test bearer loss and recovery notification via RAR/RAA

    // 1. Parse RAR from PCRF indicating bearer loss
    DiameterMessage rar_loss_msg = createBasicRxMessage(true, DiameterCommandCode::RE_AUTH);

    rar_loss_msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(DiameterAVPCode::RE_AUTH_REQUEST_TYPE), 0));

    rar_loss_msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(RxAVPCode::SPECIFIC_ACTION),
        static_cast<uint32_t>(SpecificAction::INDICATION_OF_LOSS_OF_BEARER)));

    rar_loss_msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(RxAVPCode::ABORT_CAUSE),
        static_cast<uint32_t>(AbortCause::BEARER_RELEASED)));

    auto rar_loss_result = parser.parse(rar_loss_msg);
    ASSERT_TRUE(rar_loss_result.has_value());
    ASSERT_TRUE(rar_loss_result->rar.has_value());

    const auto& rar_loss = rar_loss_result->rar.value();
    EXPECT_EQ(rar_loss.specific_actions[0], SpecificAction::INDICATION_OF_LOSS_OF_BEARER);
    EXPECT_EQ(rar_loss.abort_cause.value(), AbortCause::BEARER_RELEASED);

    // 2. Parse RAA acknowledging bearer loss
    DiameterMessage raa_loss_msg = createBasicRxMessage(false, DiameterCommandCode::RE_AUTH);
    raa_loss_msg.result_code = static_cast<uint32_t>(DiameterResultCode::DIAMETER_SUCCESS);

    auto raa_loss_result = parser.parse(raa_loss_msg);
    ASSERT_TRUE(raa_loss_result.has_value());
    ASSERT_TRUE(raa_loss_result->raa.has_value());
    EXPECT_EQ(raa_loss_result->raa->result_code,
              static_cast<uint32_t>(DiameterResultCode::DIAMETER_SUCCESS));

    // 3. Parse RAR from PCRF indicating bearer recovery
    DiameterMessage rar_recovery_msg = createBasicRxMessage(true, DiameterCommandCode::RE_AUTH);

    rar_recovery_msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(DiameterAVPCode::RE_AUTH_REQUEST_TYPE), 0));

    rar_recovery_msg.avps.push_back(createUint32AVP(
        static_cast<uint32_t>(RxAVPCode::SPECIFIC_ACTION),
        static_cast<uint32_t>(SpecificAction::INDICATION_OF_RECOVERY_OF_BEARER)));

    auto rar_recovery_result = parser.parse(rar_recovery_msg);
    ASSERT_TRUE(rar_recovery_result.has_value());
    ASSERT_TRUE(rar_recovery_result->rar.has_value());

    const auto& rar_recovery = rar_recovery_result->rar.value();
    EXPECT_EQ(rar_recovery.specific_actions[0], SpecificAction::INDICATION_OF_RECOVERY_OF_BEARER);

    // 4. Parse RAA acknowledging bearer recovery
    DiameterMessage raa_recovery_msg = createBasicRxMessage(false, DiameterCommandCode::RE_AUTH);
    raa_recovery_msg.result_code = static_cast<uint32_t>(DiameterResultCode::DIAMETER_SUCCESS);

    auto raa_recovery_result = parser.parse(raa_recovery_msg);
    ASSERT_TRUE(raa_recovery_result.has_value());
    ASSERT_TRUE(raa_recovery_result->raa.has_value());
    EXPECT_EQ(raa_recovery_result->raa->result_code,
              static_cast<uint32_t>(DiameterResultCode::DIAMETER_SUCCESS));
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
