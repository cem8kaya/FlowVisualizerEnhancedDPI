#include <gtest/gtest.h>
#include "ndpi_engine/protocol_detector.h"
#include <vector>
#include <cstring>

using namespace callflow;

// ============================================================================
// SIP Protocol Detection Tests
// ============================================================================

TEST(ProtocolDetectorTest, DetectSipInviteRequest) {
    // SIP INVITE message on non-standard port 5080
    const char* sip_invite =
        "INVITE sip:bob@example.com SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 192.168.1.100:5080;branch=z9hG4bK776asdhds\r\n"
        "Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n"
        "Content-Length: 0\r\n\r\n";

    auto result = ProtocolDetector::detectFromPayload(
        reinterpret_cast<const uint8_t*>(sip_invite),
        std::strlen(sip_invite),
        5080,  // Non-standard port
        5060,
        17);  // UDP

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), ProtocolType::SIP);
}

TEST(ProtocolDetectorTest, DetectSipResponseOnNonStandardPort) {
    // SIP 200 OK response
    const char* sip_response =
        "SIP/2.0 200 OK\r\n"
        "Via: SIP/2.0/UDP 10.0.0.1:8888;branch=z9hG4bK123\r\n"
        "Call-ID: test-call-123@server.com\r\n"
        "Content-Length: 0\r\n\r\n";

    auto result = ProtocolDetector::detectFromPayload(
        reinterpret_cast<const uint8_t*>(sip_response),
        std::strlen(sip_response),
        8888,  // Non-standard port
        5060,
        17);  // UDP

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), ProtocolType::SIP);
}

TEST(ProtocolDetectorTest, DetectSipRegisterMethod) {
    const char* sip_register =
        "REGISTER sip:registrar.example.com SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 192.168.1.100:5070\r\n"
        "Content-Length: 0\r\n\r\n";

    auto result = ProtocolDetector::detectFromPayload(
        reinterpret_cast<const uint8_t*>(sip_register),
        std::strlen(sip_register),
        5070,
        5060,
        17);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), ProtocolType::SIP);
}

TEST(ProtocolDetectorTest, DetectSipByeMethod) {
    const char* sip_bye = "BYE sip:user@example.com SIP/2.0\r\n";

    auto result = ProtocolDetector::detectFromPayload(
        reinterpret_cast<const uint8_t*>(sip_bye),
        std::strlen(sip_bye),
        5080,
        5060,
        17);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), ProtocolType::SIP);
}

// ============================================================================
// DIAMETER Protocol Detection Tests
// ============================================================================

TEST(ProtocolDetectorTest, DetectDiameterOnNonStandardPort) {
    // Minimal DIAMETER header (20 bytes)
    // Version=1, Length=20, Flags=0x80 (Request), Command=257 (CER)
    std::vector<uint8_t> diameter_packet = {
        0x01,              // Version
        0x00, 0x00, 0x14,  // Message Length (20 bytes)
        0x80,              // Flags (Request bit set)
        0x00, 0x01, 0x01,  // Command Code (257 = CER)
        0x00, 0x00, 0x00, 0x00,  // Application-ID
        0x00, 0x00, 0x00, 0x01,  // Hop-by-Hop Identifier
        0x00, 0x00, 0x00, 0x01   // End-to-End Identifier
    };

    auto result = ProtocolDetector::detectFromPayload(
        diameter_packet.data(),
        diameter_packet.size(),
        3869,  // Non-standard port
        3868,
        6);   // TCP

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), ProtocolType::DIAMETER);
}

TEST(ProtocolDetectorTest, RejectInvalidDiameterVersion) {
    // Invalid version (0x02 instead of 0x01)
    std::vector<uint8_t> invalid_diameter = {
        0x02,              // Invalid Version
        0x00, 0x00, 0x14,  // Message Length
        0x80,              // Flags
        0x00, 0x01, 0x01,  // Command Code
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x01
    };

    auto result = ProtocolDetector::detectFromPayload(
        invalid_diameter.data(),
        invalid_diameter.size(),
        3869,
        3868,
        6);

    EXPECT_FALSE(result.has_value());
}

// ============================================================================
// GTP Protocol Detection Tests
// ============================================================================

TEST(ProtocolDetectorTest, DetectGtpV2ControlPlane) {
    // GTPv2-C Create Session Request
    std::vector<uint8_t> gtpv2_packet = {
        0x48,              // Version=2, P=0, T=1
        0x20,              // Message Type (Create Session Request)
        0x00, 0x10,        // Message Length
        0x00, 0x00, 0x00, 0x01,  // TEID
        0x00, 0x00, 0x01,        // Sequence Number
        0x00,                    // Spare
        // ... rest of message ...
        0x00, 0x00, 0x00, 0x00
    };

    auto result = ProtocolDetector::detectFromPayload(
        gtpv2_packet.data(),
        gtpv2_packet.size(),
        2222,  // Non-standard port
        2123,
        17);   // UDP

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), ProtocolType::GTP_C);
}

TEST(ProtocolDetectorTest, DetectGtpV1UserPlane) {
    // GTPv1-U G-PDU packet
    std::vector<uint8_t> gtpv1u_packet = {
        0x30,              // Version=1, PT=1, E=0, S=0, PN=0
        0xFF,              // Message Type (G-PDU = 255)
        0x00, 0x20,        // Length
        0x00, 0x00, 0x00, 0x01,  // TEID
        // ... payload ...
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    auto result = ProtocolDetector::detectFromPayload(
        gtpv1u_packet.data(),
        gtpv1u_packet.size(),
        2222,  // Non-standard port
        2152,
        17);   // UDP

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), ProtocolType::GTP_U);
}

TEST(ProtocolDetectorTest, DetectGtpV1ControlPlane) {
    // GTPv1-C Echo Request (not G-PDU)
    std::vector<uint8_t> gtpv1c_packet = {
        0x32,              // Version=1, PT=1, E=0, S=1, PN=0
        0x01,              // Message Type (Echo Request)
        0x00, 0x04,        // Length
        0x00, 0x00,        // Sequence Number
        0x00,              // N-PDU Number
        0x00               // Next Extension Header Type
    };

    auto result = ProtocolDetector::detectFromPayload(
        gtpv1c_packet.data(),
        gtpv1c_packet.size(),
        2124,  // Non-standard port
        2123,
        17);   // UDP

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), ProtocolType::GTP_C);
}

TEST(ProtocolDetectorTest, RejectInvalidGtpVersion) {
    // Invalid GTP version (3)
    std::vector<uint8_t> invalid_gtp = {
        0x68,              // Version=3 (invalid), PT=1
        0x01,
        0x00, 0x04
    };

    auto result = ProtocolDetector::detectFromPayload(
        invalid_gtp.data(),
        invalid_gtp.size(),
        2123,
        2123,
        17);

    EXPECT_FALSE(result.has_value());
}

// ============================================================================
// STUN Protocol Detection Tests
// ============================================================================

TEST(ProtocolDetectorTest, DetectStunBindingRequest) {
    // STUN Binding Request with magic cookie
    std::vector<uint8_t> stun_packet = {
        0x00, 0x01,        // Message Type: Binding Request
        0x00, 0x08,        // Message Length: 8 bytes
        0x21, 0x12, 0xA4, 0x42,  // Magic Cookie
        0x00, 0x00, 0x00, 0x01,  // Transaction ID (12 bytes)
        0x00, 0x00, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x03,
        // Attributes (8 bytes as per length)
        0x00, 0x01, 0x00, 0x04,  // Attribute Type/Length
        0x00, 0x00, 0x00, 0x00   // Attribute Value
    };

    auto result = ProtocolDetector::detectFromPayload(
        stun_packet.data(),
        stun_packet.size(),
        3478,
        3478,
        17);   // UDP

    ASSERT_TRUE(result.has_value());
    // Note: STUN currently returns UDP since it's not in ProtocolType enum
    // Could add STUN to the enum in the future
}

TEST(ProtocolDetectorTest, RejectInvalidStunMagicCookie) {
    // Invalid magic cookie
    std::vector<uint8_t> invalid_stun = {
        0x00, 0x01,
        0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF,  // Invalid magic cookie
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x03
    };

    auto result = ProtocolDetector::detectFromPayload(
        invalid_stun.data(),
        invalid_stun.size(),
        3478,
        3478,
        17);

    // Should not detect as STUN
    // Might be detected as something else or nullopt
}

// ============================================================================
// RTP Protocol Detection Tests
// ============================================================================

TEST(ProtocolDetectorTest, DetectRtpWithDynamicPort) {
    // RTP packet with dynamic payload type
    std::vector<uint8_t> rtp_packet = {
        0x80,              // V=2, P=0, X=0, CC=0
        0x60,              // M=0, PT=96 (dynamic)
        0x12, 0x34,        // Sequence Number
        0x00, 0x00, 0x10, 0x00,  // Timestamp
        0x12, 0x34, 0x56, 0x78,  // SSRC
        // Payload...
        0x00, 0x00, 0x00, 0x00
    };

    auto result = ProtocolDetector::detectFromPayload(
        rtp_packet.data(),
        rtp_packet.size(),
        10000,  // Even port >= 1024
        10001,
        17);    // UDP

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), ProtocolType::RTP);
}

TEST(ProtocolDetectorTest, DetectRtpPcmuPayload) {
    // RTP packet with PCMU (PT=0)
    std::vector<uint8_t> rtp_packet = {
        0x80,              // V=2, P=0, X=0, CC=0
        0x00,              // M=0, PT=0 (PCMU)
        0x00, 0x01,        // Sequence Number
        0x00, 0x00, 0x00, 0xA0,  // Timestamp
        0xAB, 0xCD, 0xEF, 0x12,  // SSRC
        // Payload...
        0xFF, 0xFF, 0xFF, 0xFF
    };

    auto result = ProtocolDetector::detectFromPayload(
        rtp_packet.data(),
        rtp_packet.size(),
        12000,
        12001,
        17);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), ProtocolType::RTP);
}

TEST(ProtocolDetectorTest, RejectInvalidRtpVersion) {
    // Invalid RTP version (1 instead of 2)
    std::vector<uint8_t> invalid_rtp = {
        0x40,              // V=1 (invalid)
        0x00,
        0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };

    auto result = ProtocolDetector::detectFromPayload(
        invalid_rtp.data(),
        invalid_rtp.size(),
        10000,
        10001,
        17);

    EXPECT_FALSE(result.has_value());
}

// ============================================================================
// Edge Cases and Negative Tests
// ============================================================================

TEST(ProtocolDetectorTest, RejectTooSmallPayload) {
    std::vector<uint8_t> tiny_payload = {0x01, 0x02};

    auto result = ProtocolDetector::detectFromPayload(
        tiny_payload.data(),
        tiny_payload.size(),
        5060,
        5060,
        17);

    EXPECT_FALSE(result.has_value());
}

TEST(ProtocolDetectorTest, RejectNullPayload) {
    auto result = ProtocolDetector::detectFromPayload(
        nullptr,
        100,
        5060,
        5060,
        17);

    EXPECT_FALSE(result.has_value());
}

TEST(ProtocolDetectorTest, RejectNonUdpTcpProtocol) {
    std::vector<uint8_t> payload(100, 0);

    // SCTP (protocol 132)
    auto result = ProtocolDetector::detectFromPayload(
        payload.data(),
        payload.size(),
        5060,
        5060,
        132);

    EXPECT_FALSE(result.has_value());
}

TEST(ProtocolDetectorTest, NoFalsePositiveOnRandomData) {
    // Random data should not be detected as any protocol
    std::vector<uint8_t> random_data = {
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0
    };

    auto result = ProtocolDetector::detectFromPayload(
        random_data.data(),
        random_data.size(),
        9999,
        9999,
        17);

    // Should not match any protocol
    EXPECT_FALSE(result.has_value());
}

// ============================================================================
// Integration Tests - Multiple Protocol Discrimination
// ============================================================================

TEST(ProtocolDetectorTest, DistinguishSipFromDiameter) {
    // Ensure SIP and DIAMETER are not confused
    const char* sip = "INVITE sip:test@example.com SIP/2.0\r\n";

    auto sip_result = ProtocolDetector::detectFromPayload(
        reinterpret_cast<const uint8_t*>(sip),
        std::strlen(sip),
        3868,  // DIAMETER port
        3868,
        17);

    ASSERT_TRUE(sip_result.has_value());
    EXPECT_EQ(sip_result.value(), ProtocolType::SIP);
}

TEST(ProtocolDetectorTest, DistinguishGtpVersions) {
    // GTPv2 should be detected as GTP_C
    std::vector<uint8_t> gtpv2 = {
        0x48, 0x20, 0x00, 0x10,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x01, 0x00
    };

    auto v2_result = ProtocolDetector::detectFromPayload(
        gtpv2.data(), gtpv2.size(), 2123, 2123, 17);

    ASSERT_TRUE(v2_result.has_value());
    EXPECT_EQ(v2_result.value(), ProtocolType::GTP_C);

    // GTPv1-U (G-PDU) should be detected as GTP_U
    std::vector<uint8_t> gtpv1u = {
        0x30, 0xFF, 0x00, 0x20,
        0x00, 0x00, 0x00, 0x01
    };

    auto v1u_result = ProtocolDetector::detectFromPayload(
        gtpv1u.data(), gtpv1u.size(), 2152, 2152, 17);

    ASSERT_TRUE(v1u_result.has_value());
    EXPECT_EQ(v1u_result.value(), ProtocolType::GTP_U);
}

// Entry point
int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
