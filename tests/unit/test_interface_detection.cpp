#include <gtest/gtest.h>
#include "pcap_ingest/interface_detector.h"
#include <set>
#include <map>

using namespace callflow;
using TI = PcapngInterfaceInfo::TelecomInterface;

/**
 * Test fixture for Interface Detection
 */
class InterfaceDetectionTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

// Test S1-MME detection from name
TEST_F(InterfaceDetectionTest, DetectS1MMEFromName) {
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("eth0-S1-MME", ""), TI::S1_MME);
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("S1-MME", ""), TI::S1_MME);
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("s1-mme", ""), TI::S1_MME);
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("S1_MME", ""), TI::S1_MME);
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("", "S1-MME Control Plane"), TI::S1_MME);
}

// Test S1-U detection from name
TEST_F(InterfaceDetectionTest, DetectS1UFromName) {
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("eth0-S1-U", ""), TI::S1_U);
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("S1-U", ""), TI::S1_U);
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("s1-u", ""), TI::S1_U);
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("S1_U", ""), TI::S1_U);
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("", "S1-U User Plane"), TI::S1_U);
}

// Test N2 detection from name (5G)
TEST_F(InterfaceDetectionTest, DetectN2FromName) {
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("N2", ""), TI::N2);
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("n2", ""), TI::N2);
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("", "N2 NGAP Interface"), TI::N2);
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("", "AMF to gNB"), TI::N2);
}

// Test N3 detection from name (5G)
TEST_F(InterfaceDetectionTest, DetectN3FromName) {
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("N3", ""), TI::N3);
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("n3", ""), TI::N3);
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("", "N3 User Plane"), TI::N3);
}

// Test N4 detection from name (5G)
TEST_F(InterfaceDetectionTest, DetectN4FromName) {
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("N4", ""), TI::N4);
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("", "N4 PFCP"), TI::N4);
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("", "SMF to UPF"), TI::N4);
}

// Test N6 detection from name (5G)
TEST_F(InterfaceDetectionTest, DetectN6FromName) {
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("N6", ""), TI::N6);
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("", "N6 Data Network"), TI::N6);
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("", "5G Internet"), TI::N6);
}

// Test Gx detection from name
TEST_F(InterfaceDetectionTest, DetectGxFromName) {
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("Gx", ""), TI::GX);
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("gx", ""), TI::GX);
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("", "Gx PCRF"), TI::GX);
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("", "PCRF to PCEF"), TI::GX);
}

// Test S6a detection from name
TEST_F(InterfaceDetectionTest, DetectS6aFromName) {
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("S6a", ""), TI::S6A);
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("s6a", ""), TI::S6A);
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("", "S6a HSS"), TI::S6A);
}

// Test SGi detection from name
TEST_F(InterfaceDetectionTest, DetectSGiFromName) {
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("SGi", ""), TI::SG_I);
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("sgi", ""), TI::SG_I);
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("Gi", ""), TI::SG_I);
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("", "SGi Internet"), TI::SG_I);
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("", "PDN Gateway"), TI::SG_I);
}

// Test IMS SIP detection from name
TEST_F(InterfaceDetectionTest, DetectIMSSIPFromName) {
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("IMS", ""), TI::IMS_SIP);
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("SIP", ""), TI::IMS_SIP);
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("", "IMS SIP Interface"), TI::IMS_SIP);
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("", "P-CSCF"), TI::IMS_SIP);
}

// Test RTP Media detection from name
TEST_F(InterfaceDetectionTest, DetectRTPFromName) {
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("RTP", ""), TI::RTP_MEDIA);
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("", "RTP Media"), TI::RTP_MEDIA);
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("", "Voice Media"), TI::RTP_MEDIA);
}

// Test X2-C detection from name
TEST_F(InterfaceDetectionTest, DetectX2CFromName) {
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("X2-C", ""), TI::X2_C);
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("X2C", ""), TI::X2_C);
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("", "X2AP Control"), TI::X2_C);
}

// Test S5/S8 Control detection from name
TEST_F(InterfaceDetectionTest, DetectS5S8CFromName) {
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("S5-C", ""), TI::S5_S8_C);
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("S8-C", ""), TI::S5_S8_C);
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("", "S5 Control Plane"), TI::S5_S8_C);
}

// Test S5/S8 User detection from name
TEST_F(InterfaceDetectionTest, DetectS5S8UFromName) {
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("S5-U", ""), TI::S5_S8_U);
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("S8-U", ""), TI::S5_S8_U);
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("", "S5 User Plane"), TI::S5_S8_U);
}

// Test Rx detection from name
TEST_F(InterfaceDetectionTest, DetectRxFromName) {
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("Rx", ""), TI::RX);
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("", "Rx P-CSCF"), TI::RX);
}

// Test Gy detection from name
TEST_F(InterfaceDetectionTest, DetectGyFromName) {
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("Gy", ""), TI::GY);
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("", "Gy OCS"), TI::GY);
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("", "Online Charging"), TI::GY);
}

// Test detection from SCTP ports
TEST_F(InterfaceDetectionTest, DetectFromSCTPPorts) {
    std::set<uint16_t> ports_s1_mme = {36412};
    EXPECT_EQ(InterfaceDetector::detectFromSctpPorts(ports_s1_mme), TI::S1_MME);

    std::set<uint16_t> ports_n2 = {38412};
    EXPECT_EQ(InterfaceDetector::detectFromSctpPorts(ports_n2), TI::N2);

    std::set<uint16_t> ports_x2 = {36422};
    EXPECT_EQ(InterfaceDetector::detectFromSctpPorts(ports_x2), TI::X2_C);

    std::set<uint16_t> ports_unknown = {12345};
    EXPECT_EQ(InterfaceDetector::detectFromSctpPorts(ports_unknown), TI::UNKNOWN);
}

// Test detection from GTP ports
TEST_F(InterfaceDetectionTest, DetectFromGTPPorts) {
    std::set<uint16_t> ports_gtpc = {2123};
    EXPECT_EQ(InterfaceDetector::detectFromGtpPorts(ports_gtpc), TI::S5_S8_C);

    std::set<uint16_t> ports_gtpu = {2152};
    EXPECT_EQ(InterfaceDetector::detectFromGtpPorts(ports_gtpu), TI::S1_U);

    std::set<uint16_t> ports_pfcp = {8805};
    EXPECT_EQ(InterfaceDetector::detectFromGtpPorts(ports_pfcp), TI::N4);

    std::set<uint16_t> ports_unknown = {9999};
    EXPECT_EQ(InterfaceDetector::detectFromGtpPorts(ports_unknown), TI::UNKNOWN);
}

// Test detection from Diameter
TEST_F(InterfaceDetectionTest, DetectFromDiameter) {
    std::set<uint16_t> ports_diameter = {3868};

    EXPECT_EQ(InterfaceDetector::detectFromDiameter(ports_diameter, true), TI::S6A);
    EXPECT_EQ(InterfaceDetector::detectFromDiameter(ports_diameter, false), TI::UNKNOWN);

    std::set<uint16_t> ports_no_diameter = {12345};
    EXPECT_EQ(InterfaceDetector::detectFromDiameter(ports_no_diameter, true), TI::UNKNOWN);
}

// Test detection from traffic patterns
TEST_F(InterfaceDetectionTest, DetectFromTrafficPatterns) {
    // S1-MME traffic
    std::set<uint16_t> ports_s1_mme = {36412};
    std::map<std::string, uint64_t> protocols;
    EXPECT_EQ(InterfaceDetector::detectFromTraffic(ports_s1_mme, protocols), TI::S1_MME);

    // GTP-U traffic
    std::set<uint16_t> ports_gtpu = {2152};
    EXPECT_EQ(InterfaceDetector::detectFromTraffic(ports_gtpu, protocols), TI::S1_U);

    // SIP traffic
    std::set<uint16_t> ports_sip = {5060};
    EXPECT_EQ(InterfaceDetector::detectFromTraffic(ports_sip, protocols), TI::IMS_SIP);

    // HTTP/HTTPS traffic (SGi)
    std::set<uint16_t> ports_http = {80, 443};
    EXPECT_EQ(InterfaceDetector::detectFromTraffic(ports_http, protocols), TI::SG_I);

    // HTTP/HTTPS traffic with 5G indicators (N6)
    protocols["NGAP"] = 10;
    EXPECT_EQ(InterfaceDetector::detectFromTraffic(ports_http, protocols), TI::N6);
}

// Test toString method
TEST_F(InterfaceDetectionTest, ToStringConversion) {
    EXPECT_EQ(InterfaceDetector::toString(TI::UNKNOWN), "UNKNOWN");
    EXPECT_EQ(InterfaceDetector::toString(TI::S1_MME), "S1-MME");
    EXPECT_EQ(InterfaceDetector::toString(TI::S1_U), "S1-U");
    EXPECT_EQ(InterfaceDetector::toString(TI::S5_S8_C), "S5/S8-C");
    EXPECT_EQ(InterfaceDetector::toString(TI::S5_S8_U), "S5/S8-U");
    EXPECT_EQ(InterfaceDetector::toString(TI::S6A), "S6a");
    EXPECT_EQ(InterfaceDetector::toString(TI::SG_I), "SGi");
    EXPECT_EQ(InterfaceDetector::toString(TI::GX), "Gx");
    EXPECT_EQ(InterfaceDetector::toString(TI::RX), "Rx");
    EXPECT_EQ(InterfaceDetector::toString(TI::GY), "Gy");
    EXPECT_EQ(InterfaceDetector::toString(TI::X2_C), "X2-C");
    EXPECT_EQ(InterfaceDetector::toString(TI::N2), "N2");
    EXPECT_EQ(InterfaceDetector::toString(TI::N3), "N3");
    EXPECT_EQ(InterfaceDetector::toString(TI::N4), "N4");
    EXPECT_EQ(InterfaceDetector::toString(TI::N6), "N6");
    EXPECT_EQ(InterfaceDetector::toString(TI::IMS_SIP), "IMS-SIP");
    EXPECT_EQ(InterfaceDetector::toString(TI::RTP_MEDIA), "RTP-Media");
}

// Test getWellKnownPorts
TEST_F(InterfaceDetectionTest, GetWellKnownPorts) {
    auto s1_mme_ports = InterfaceDetector::getWellKnownPorts(TI::S1_MME);
    ASSERT_FALSE(s1_mme_ports.empty());
    EXPECT_EQ(s1_mme_ports[0], 36412);

    auto gtpu_ports = InterfaceDetector::getWellKnownPorts(TI::S1_U);
    ASSERT_FALSE(gtpu_ports.empty());
    EXPECT_EQ(gtpu_ports[0], 2152);

    auto n2_ports = InterfaceDetector::getWellKnownPorts(TI::N2);
    ASSERT_FALSE(n2_ports.empty());
    EXPECT_EQ(n2_ports[0], 38412);

    auto diameter_ports = InterfaceDetector::getWellKnownPorts(TI::GX);
    ASSERT_FALSE(diameter_ports.empty());
    EXPECT_EQ(diameter_ports[0], 3868);
}

// Test getExpectedProtocols
TEST_F(InterfaceDetectionTest, GetExpectedProtocols) {
    auto s1_mme_protocols = InterfaceDetector::getExpectedProtocols(TI::S1_MME);
    ASSERT_FALSE(s1_mme_protocols.empty());
    EXPECT_EQ(s1_mme_protocols[0], "SCTP");

    auto gtpu_protocols = InterfaceDetector::getExpectedProtocols(TI::S1_U);
    ASSERT_FALSE(gtpu_protocols.empty());
    EXPECT_EQ(gtpu_protocols[0], "UDP");

    auto sgi_protocols = InterfaceDetector::getExpectedProtocols(TI::SG_I);
    ASSERT_FALSE(sgi_protocols.empty());

    auto sip_protocols = InterfaceDetector::getExpectedProtocols(TI::IMS_SIP);
    ASSERT_FALSE(sip_protocols.empty());
}

// Test RTP port range detection
TEST_F(InterfaceDetectionTest, DetectRTPPortRange) {
    std::set<uint16_t> ports_rtp = {10000, 15000, 20000};
    std::map<std::string, uint64_t> protocols;

    auto detected_type = InterfaceDetector::detectFromTraffic(ports_rtp, protocols);
    EXPECT_EQ(detected_type, TI::RTP_MEDIA);
}

// Test unknown interface
TEST_F(InterfaceDetectionTest, DetectUnknownInterface) {
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("unknown", ""), TI::UNKNOWN);
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("", ""), TI::UNKNOWN);
    EXPECT_EQ(InterfaceDetector::detectTelecomInterface("random", "random desc"), TI::UNKNOWN);

    std::set<uint16_t> unknown_ports = {99999};
    std::map<std::string, uint64_t> protocols;
    EXPECT_EQ(InterfaceDetector::detectFromTraffic(unknown_ports, protocols), TI::UNKNOWN);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
