#include <gtest/gtest.h>
#include "protocol_parsers/sip_parser.h"
#include "ndpi_engine/protocol_detector.h"
#include <cstring>

using namespace callflow;

// ============================================================================
// SipParser::isSipMessage() Tests - All 14 SIP Methods
// ============================================================================

TEST(SipParserTest, DetectInviteMethod) {
    const char* msg = "INVITE sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/TCP x;branch=z9\r\n";
    EXPECT_TRUE(SipParser::isSipMessage(reinterpret_cast<const uint8_t*>(msg), strlen(msg)));
}

TEST(SipParserTest, DetectAckMethod) {
    const char* msg = "ACK sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/UDP x;branch=z9\r\n";
    EXPECT_TRUE(SipParser::isSipMessage(reinterpret_cast<const uint8_t*>(msg), strlen(msg)));
}

TEST(SipParserTest, DetectByeMethod) {
    const char* msg = "BYE sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/UDP x;branch=z9\r\n";
    EXPECT_TRUE(SipParser::isSipMessage(reinterpret_cast<const uint8_t*>(msg), strlen(msg)));
}

TEST(SipParserTest, DetectCancelMethod) {
    const char* msg = "CANCEL sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/UDP x;branch=z9\r\n";
    EXPECT_TRUE(SipParser::isSipMessage(reinterpret_cast<const uint8_t*>(msg), strlen(msg)));
}

TEST(SipParserTest, DetectOptionsMethod) {
    const char* msg = "OPTIONS sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/UDP x;branch=z9\r\n";
    EXPECT_TRUE(SipParser::isSipMessage(reinterpret_cast<const uint8_t*>(msg), strlen(msg)));
}

TEST(SipParserTest, DetectRegisterMethod) {
    const char* msg = "REGISTER sip:registrar.example.com SIP/2.0\r\nVia: SIP/2.0/UDP x;branch=z9\r\n";
    EXPECT_TRUE(SipParser::isSipMessage(reinterpret_cast<const uint8_t*>(msg), strlen(msg)));
}

TEST(SipParserTest, DetectUpdateMethod) {
    const char* msg = "UPDATE sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/UDP x;branch=z9\r\n";
    EXPECT_TRUE(SipParser::isSipMessage(reinterpret_cast<const uint8_t*>(msg), strlen(msg)));
}

TEST(SipParserTest, DetectPrackMethod) {
    const char* msg = "PRACK sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/UDP x;branch=z9\r\n";
    EXPECT_TRUE(SipParser::isSipMessage(reinterpret_cast<const uint8_t*>(msg), strlen(msg)));
}

TEST(SipParserTest, DetectInfoMethod) {
    const char* msg = "INFO sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/UDP x;branch=z9\r\n";
    EXPECT_TRUE(SipParser::isSipMessage(reinterpret_cast<const uint8_t*>(msg), strlen(msg)));
}

// IMS/VoLTE specific methods
TEST(SipParserTest, DetectMessageMethod) {
    // MESSAGE is used for SMS-over-IMS
    const char* msg = "MESSAGE sip:service@ims.de SIP/2.0\r\nVia: SIP/2.0/TCP x;branch=z9\r\n";
    EXPECT_TRUE(SipParser::isSipMessage(reinterpret_cast<const uint8_t*>(msg), strlen(msg)));
}

TEST(SipParserTest, DetectNotifyMethod) {
    // NOTIFY is used for reg-event, presence notifications
    const char* msg = "NOTIFY sip:user@[2a01::2]:7100 SIP/2.0\r\nEvent: reg\r\n";
    EXPECT_TRUE(SipParser::isSipMessage(reinterpret_cast<const uint8_t*>(msg), strlen(msg)));
}

TEST(SipParserTest, DetectSubscribeMethod) {
    // SUBSCRIBE is used for event subscriptions (reg-event, presence)
    const char* msg = "SUBSCRIBE sip:reg@ims.de SIP/2.0\r\nEvent: reg\r\n";
    EXPECT_TRUE(SipParser::isSipMessage(reinterpret_cast<const uint8_t*>(msg), strlen(msg)));
}

TEST(SipParserTest, DetectReferMethod) {
    // REFER is used for call transfer
    const char* msg = "REFER sip:bob@example.com SIP/2.0\r\nRefer-To: <sip:charlie@example.com>\r\n";
    EXPECT_TRUE(SipParser::isSipMessage(reinterpret_cast<const uint8_t*>(msg), strlen(msg)));
}

TEST(SipParserTest, DetectPublishMethod) {
    // PUBLISH is used for event state publication
    const char* msg = "PUBLISH sip:presentity@example.com SIP/2.0\r\nEvent: presence\r\n";
    EXPECT_TRUE(SipParser::isSipMessage(reinterpret_cast<const uint8_t*>(msg), strlen(msg)));
}

// ============================================================================
// SIP Response Detection Tests
// ============================================================================

TEST(SipParserTest, Detect200OkResponse) {
    const char* msg = "SIP/2.0 200 OK\r\nVia: SIP/2.0/TCP x;branch=z9\r\n";
    EXPECT_TRUE(SipParser::isSipMessage(reinterpret_cast<const uint8_t*>(msg), strlen(msg)));
}

TEST(SipParserTest, Detect100TryingResponse) {
    const char* msg = "SIP/2.0 100 Trying\r\nVia: SIP/2.0/TCP x;branch=z9\r\n";
    EXPECT_TRUE(SipParser::isSipMessage(reinterpret_cast<const uint8_t*>(msg), strlen(msg)));
}

TEST(SipParserTest, Detect180RingingResponse) {
    const char* msg = "SIP/2.0 180 Ringing\r\nVia: SIP/2.0/TCP x;branch=z9\r\n";
    EXPECT_TRUE(SipParser::isSipMessage(reinterpret_cast<const uint8_t*>(msg), strlen(msg)));
}

TEST(SipParserTest, Detect183SessionProgressResponse) {
    const char* msg = "SIP/2.0 183 Session Progress\r\nVia: SIP/2.0/TCP x;branch=z9\r\n";
    EXPECT_TRUE(SipParser::isSipMessage(reinterpret_cast<const uint8_t*>(msg), strlen(msg)));
}

TEST(SipParserTest, Detect202AcceptedResponse) {
    // 202 Accepted is used for MESSAGE and REFER responses
    const char* msg = "SIP/2.0 202 Accepted\r\nVia: SIP/2.0/TCP x;branch=z9\r\n";
    EXPECT_TRUE(SipParser::isSipMessage(reinterpret_cast<const uint8_t*>(msg), strlen(msg)));
}

TEST(SipParserTest, Detect503ServiceUnavailableResponse) {
    const char* msg = "SIP/2.0 503 Service Unavailable\r\nVia: SIP/2.0/TCP x;branch=z9\r\n";
    EXPECT_TRUE(SipParser::isSipMessage(reinterpret_cast<const uint8_t*>(msg), strlen(msg)));
}

// ============================================================================
// ProtocolDetector::isSipPayload() Tests
// ============================================================================

TEST(ProtocolDetectorTest, DetectMessageMethod) {
    const char* msg = "MESSAGE sip:svc@ims.de SIP/2.0\r\nVia: SIP/2.0/TCP x;branch=z9\r\n";
    auto result = ProtocolDetector::detectFromPayload(
        reinterpret_cast<const uint8_t*>(msg), strlen(msg), 45535, 5063, 6);  // TCP
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), ProtocolType::SIP);
}

TEST(ProtocolDetectorTest, DetectNotifyMethod) {
    const char* msg = "NOTIFY sip:user@[2a01::2]:7100 SIP/2.0\r\nEvent: reg\r\n";
    auto result = ProtocolDetector::detectFromPayload(
        reinterpret_cast<const uint8_t*>(msg), strlen(msg), 39448, 5060, 6);  // TCP
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), ProtocolType::SIP);
}

TEST(ProtocolDetectorTest, DetectSubscribeMethod) {
    const char* msg = "SUBSCRIBE sip:reg@ims.de SIP/2.0\r\nEvent: reg\r\n";
    auto result = ProtocolDetector::detectFromPayload(
        reinterpret_cast<const uint8_t*>(msg), strlen(msg), 5063, 5064, 6);  // TCP
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), ProtocolType::SIP);
}

TEST(ProtocolDetectorTest, DetectSipOnNonStandardPort5063) {
    const char* msg = "MESSAGE sip:svc@ims.de SIP/2.0\r\n";
    auto result = ProtocolDetector::detectFromPayload(
        reinterpret_cast<const uint8_t*>(msg), strlen(msg), 45535, 5063, 6);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), ProtocolType::SIP);
}

TEST(ProtocolDetectorTest, DetectSipOnNonStandardPort5064) {
    const char* msg = "INVITE sip:user@ims.de SIP/2.0\r\n";
    auto result = ProtocolDetector::detectFromPayload(
        reinterpret_cast<const uint8_t*>(msg), strlen(msg), 45535, 5064, 6);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), ProtocolType::SIP);
}

TEST(ProtocolDetectorTest, DetectSipOnNonStandardPort6101) {
    const char* msg = "REGISTER sip:registrar@ims.de SIP/2.0\r\n";
    auto result = ProtocolDetector::detectFromPayload(
        reinterpret_cast<const uint8_t*>(msg), strlen(msg), 6101, 6101, 6);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), ProtocolType::SIP);
}

TEST(ProtocolDetectorTest, DetectSipOnNonStandardPort7100) {
    const char* msg = "SUBSCRIBE sip:user@[2a01::2] SIP/2.0\r\n";
    auto result = ProtocolDetector::detectFromPayload(
        reinterpret_cast<const uint8_t*>(msg), strlen(msg), 39448, 7100, 6);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), ProtocolType::SIP);
}

TEST(ProtocolDetectorTest, DetectSipOnNonStandardPort7200) {
    const char* msg = "NOTIFY sip:user@ims.de SIP/2.0\r\n";
    auto result = ProtocolDetector::detectFromPayload(
        reinterpret_cast<const uint8_t*>(msg), strlen(msg), 7200, 39448, 6);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), ProtocolType::SIP);
}

// ============================================================================
// SIP Parser Full Parsing Tests
// ============================================================================

TEST(SipParserTest, ParseMessageMethodFull) {
    const char* msg =
        "MESSAGE sip:service@ims.telekom.de SIP/2.0\r\n"
        "Via: SIP/2.0/TCP 10.0.0.1:45535;branch=z9hG4bK776asdhds\r\n"
        "Call-ID: sms123@ims.telekom.de\r\n"
        "From: <sip:+491234567890@ims.telekom.de>;tag=abc\r\n"
        "To: <sip:+499876543210@ims.telekom.de>\r\n"
        "CSeq: 1 MESSAGE\r\n"
        "Content-Type: application/vnd.3gpp.sms\r\n"
        "Content-Length: 10\r\n"
        "\r\n"
        "SMS DATA..";

    SipParser parser;
    auto result = parser.parse(reinterpret_cast<const uint8_t*>(msg), strlen(msg));

    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->is_request);
    EXPECT_EQ(result->method, "MESSAGE");
    EXPECT_EQ(result->content_type, "application/vnd.3gpp.sms");
}

TEST(SipParserTest, ParseNotifyMethodWithXml) {
    const char* msg =
        "NOTIFY sip:user@[2a01:598:a0:7e01::15]:7100 SIP/2.0\r\n"
        "Via: SIP/2.0/TCP 10.0.0.1:39448;branch=z9hG4bK776asdhds\r\n"
        "Call-ID: notify123@ims.telekom.de\r\n"
        "From: <sip:registrar@ims.telekom.de>;tag=abc\r\n"
        "To: <sip:+491234567890@ims.telekom.de>;tag=def\r\n"
        "CSeq: 2 NOTIFY\r\n"
        "Event: reg\r\n"
        "Subscription-State: active;expires=600\r\n"
        "Content-Type: application/reginfo+xml\r\n"
        "Content-Length: 0\r\n"
        "\r\n";

    SipParser parser;
    auto result = parser.parse(reinterpret_cast<const uint8_t*>(msg), strlen(msg));

    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->is_request);
    EXPECT_EQ(result->method, "NOTIFY");
    EXPECT_EQ(result->content_type, "application/reginfo+xml");
    ASSERT_TRUE(result->event.has_value());
    EXPECT_EQ(result->event.value(), "reg");
    ASSERT_TRUE(result->subscription_state.has_value());
}

TEST(SipParserTest, ParseSubscribeMethod) {
    const char* msg =
        "SUBSCRIBE sip:reg@ims.telekom.de SIP/2.0\r\n"
        "Via: SIP/2.0/TCP 10.0.0.1:39448;branch=z9hG4bK776asdhds\r\n"
        "Call-ID: subscribe123@ims.telekom.de\r\n"
        "From: <sip:+491234567890@ims.telekom.de>;tag=abc\r\n"
        "To: <sip:+491234567890@ims.telekom.de>\r\n"
        "CSeq: 1 SUBSCRIBE\r\n"
        "Event: reg\r\n"
        "Expires: 600000\r\n"
        "Content-Length: 0\r\n"
        "\r\n";

    SipParser parser;
    auto result = parser.parse(reinterpret_cast<const uint8_t*>(msg), strlen(msg));

    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->is_request);
    EXPECT_EQ(result->method, "SUBSCRIBE");
    ASSERT_TRUE(result->event.has_value());
    EXPECT_EQ(result->event.value(), "reg");
}

// ============================================================================
// Edge Cases
// ============================================================================

TEST(SipParserTest, RejectNonSipMessage) {
    const char* msg = "GET / HTTP/1.1\r\nHost: example.com\r\n";
    EXPECT_FALSE(SipParser::isSipMessage(reinterpret_cast<const uint8_t*>(msg), strlen(msg)));
}

TEST(SipParserTest, RejectTooShortPayload) {
    const char* msg = "INVITE ";
    EXPECT_FALSE(SipParser::isSipMessage(reinterpret_cast<const uint8_t*>(msg), strlen(msg)));
}

TEST(SipParserTest, RejectNullPayload) {
    EXPECT_FALSE(SipParser::isSipMessage(nullptr, 100));
}

TEST(SipParserTest, RejectZeroLengthPayload) {
    const char* msg = "";
    EXPECT_FALSE(SipParser::isSipMessage(reinterpret_cast<const uint8_t*>(msg), 0));
}

TEST(SipParserTest, RejectPartialMethodWithoutSipVersion) {
    // Has method but no SIP/2.0
    const char* msg = "MESSAGE sip:test@example.com HTTP/1.1\r\n";
    EXPECT_FALSE(SipParser::isSipMessage(reinterpret_cast<const uint8_t*>(msg), strlen(msg)));
}

// ============================================================================
// IPv6 URI Support (IMS uses IPv6)
// ============================================================================

TEST(SipParserTest, DetectSipWithIpv6Uri) {
    const char* msg = "INVITE sip:user@[2a01:598:a0:7e01::15]:5060 SIP/2.0\r\n";
    EXPECT_TRUE(SipParser::isSipMessage(reinterpret_cast<const uint8_t*>(msg), strlen(msg)));
}

TEST(SipParserTest, DetectNotifyWithIpv6AndNonStandardPort) {
    const char* msg = "NOTIFY sip:user@[2a01:598:a0:7e01::15]:7100 SIP/2.0\r\n";
    EXPECT_TRUE(SipParser::isSipMessage(reinterpret_cast<const uint8_t*>(msg), strlen(msg)));
}

// ============================================================================
// Tel URI Support (IMS uses tel: URIs)
// ============================================================================

TEST(SipParserTest, DetectInviteWithTelUri) {
    const char* msg = "INVITE tel:+491234567890 SIP/2.0\r\nVia: SIP/2.0/TCP x;branch=z9\r\n";
    EXPECT_TRUE(SipParser::isSipMessage(reinterpret_cast<const uint8_t*>(msg), strlen(msg)));
}

// Entry point
int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
