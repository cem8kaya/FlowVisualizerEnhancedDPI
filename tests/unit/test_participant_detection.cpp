#include <gtest/gtest.h>

#include "../../include/correlation/participant_detector.h"
#include "../../include/session/session_types.h"

using namespace flowviz;
using namespace callflow;

class ParticipantDetectorTest : public ::testing::Test {
protected:
    void SetUp() override { detector = std::make_unique<ParticipantDetector>(); }

    SessionMessageRef createMessage(const std::string& src_ip, uint16_t src_port,
                                    const std::string& dst_ip, uint16_t dst_port,
                                    ProtocolType protocol, MessageType msg_type) {
        SessionMessageRef msg;
        msg.message_id = "msg_" + std::to_string(msg_counter_++);
        msg.timestamp = std::chrono::system_clock::now();
        msg.src_ip = src_ip;
        msg.src_port = src_port;
        msg.dst_ip = dst_ip;
        msg.dst_port = dst_port;
        msg.protocol = protocol;
        msg.message_type = msg_type;
        return msg;
    }

    std::unique_ptr<ParticipantDetector> detector;
    static int msg_counter_;
};

int ParticipantDetectorTest::msg_counter_ = 0;

TEST_F(ParticipantDetectorTest, DetectUEFromSIPRegister) {
    auto msg = createMessage("192.0.2.100", 5060, "10.0.1.50", 5060, ProtocolType::SIP,
                             MessageType::SIP_REGISTER);

    auto participant = detector->detectParticipant(msg, true);

    EXPECT_EQ(participant.type, ParticipantType::UE);
    EXPECT_EQ(participant.ip_address, "192.0.2.100");
    EXPECT_EQ(participant.id, "UE");
}

TEST_F(ParticipantDetectorTest, DetectPCSCFFromSIPRegister) {
    auto msg = createMessage("192.0.2.100", 5060, "10.0.1.50", 5060, ProtocolType::SIP,
                             MessageType::SIP_REGISTER);

    auto participant = detector->detectParticipant(msg, false);

    EXPECT_EQ(participant.type, ParticipantType::P_CSCF);
    EXPECT_EQ(participant.ip_address, "10.0.1.50");
}

TEST_F(ParticipantDetectorTest, DetectENodeBFromS1AP) {
    auto msg = createMessage("10.0.1.50", 36412, "10.0.2.10", 36412, ProtocolType::S1AP,
                             MessageType::S1AP_INITIAL_UE_MESSAGE);

    auto participant = detector->detectParticipant(msg, true);

    EXPECT_EQ(participant.type, ParticipantType::ENODEB);
    EXPECT_EQ(participant.ip_address, "10.0.1.50");
}

TEST_F(ParticipantDetectorTest, DetectMMEFromS1AP) {
    auto msg = createMessage("10.0.1.50", 36412, "10.0.2.10", 36412, ProtocolType::S1AP,
                             MessageType::S1AP_INITIAL_UE_MESSAGE);

    auto participant = detector->detectParticipant(msg, false);

    EXPECT_EQ(participant.type, ParticipantType::MME);
    EXPECT_EQ(participant.ip_address, "10.0.2.10");
}

TEST_F(ParticipantDetectorTest, DetectGNodeBFromNGAP) {
    auto msg = createMessage("10.0.1.60", 38412, "10.0.2.20", 38412, ProtocolType::NGAP,
                             MessageType::NGAP_INITIAL_UE_MESSAGE);

    auto participant = detector->detectParticipant(msg, true);

    EXPECT_EQ(participant.type, ParticipantType::GNODEB);
    EXPECT_EQ(participant.ip_address, "10.0.1.60");
}

TEST_F(ParticipantDetectorTest, DetectAMFFromNGAP) {
    auto msg = createMessage("10.0.1.60", 38412, "10.0.2.20", 38412, ProtocolType::NGAP,
                             MessageType::NGAP_INITIAL_UE_MESSAGE);

    auto participant = detector->detectParticipant(msg, false);

    EXPECT_EQ(participant.type, ParticipantType::AMF);
    EXPECT_EQ(participant.ip_address, "10.0.2.20");
}

TEST_F(ParticipantDetectorTest, DetectMMEFromGTPCreateSessionRequest) {
    auto msg = createMessage("10.0.2.10", 2123, "10.0.3.10", 2123, ProtocolType::GTP_C,
                             MessageType::GTP_CREATE_SESSION_REQ);

    auto participant = detector->detectParticipant(msg, true);

    EXPECT_EQ(participant.type, ParticipantType::MME);
    EXPECT_EQ(participant.ip_address, "10.0.2.10");
}

TEST_F(ParticipantDetectorTest, DetectSGWFromGTPCreateSessionRequest) {
    auto msg = createMessage("10.0.2.10", 2123, "10.0.3.10", 2123, ProtocolType::GTP_C,
                             MessageType::GTP_CREATE_SESSION_REQ);

    auto participant = detector->detectParticipant(msg, false);

    EXPECT_EQ(participant.type, ParticipantType::SGW);
    EXPECT_EQ(participant.ip_address, "10.0.3.10");
}

TEST_F(ParticipantDetectorTest, DetectHSSFromDiameterS6a) {
    auto msg = createMessage("10.0.2.10", 3868, "10.0.5.10", 3868, ProtocolType::DIAMETER,
                             MessageType::DIAMETER_AAR);

    // Add Diameter S6a Application-ID
    msg.parsed_data["application_id"] = 16777251;

    auto participant = detector->detectParticipant(msg, false);

    EXPECT_EQ(participant.type, ParticipantType::HSS);
    EXPECT_EQ(participant.ip_address, "10.0.5.10");
}

TEST_F(ParticipantDetectorTest, DetectPCRFFromDiameterGx) {
    auto msg = createMessage("10.0.4.10", 3868, "10.0.6.10", 3868, ProtocolType::DIAMETER,
                             MessageType::DIAMETER_CCR);

    // Add Diameter Gx Application-ID
    msg.parsed_data["application_id"] = 16777238;

    auto participant = detector->detectParticipant(msg, false);

    EXPECT_EQ(participant.type, ParticipantType::PCRF);
    EXPECT_EQ(participant.ip_address, "10.0.6.10");
}

TEST_F(ParticipantDetectorTest, DetectSMFFromPFCP) {
    auto msg = createMessage("10.0.7.10", 8805, "10.0.8.10", 8805, ProtocolType::PFCP,
                             MessageType::PFCP_SESSION_ESTABLISHMENT_REQ);

    auto participant = detector->detectParticipant(msg, true);

    EXPECT_EQ(participant.type, ParticipantType::SMF);
    EXPECT_EQ(participant.ip_address, "10.0.7.10");
}

TEST_F(ParticipantDetectorTest, DetectUPFFromPFCP) {
    auto msg = createMessage("10.0.7.10", 8805, "10.0.8.10", 8805, ProtocolType::PFCP,
                             MessageType::PFCP_SESSION_ESTABLISHMENT_REQ);

    auto participant = detector->detectParticipant(msg, false);

    EXPECT_EQ(participant.type, ParticipantType::UPF);
    EXPECT_EQ(participant.ip_address, "10.0.8.10");
}

TEST_F(ParticipantDetectorTest, ExplicitMapping) {
    detector->addExplicitMapping("10.0.1.100", "MyMME", ParticipantType::MME);

    auto msg = createMessage("10.0.1.100", 36412, "10.0.2.10", 36412, ProtocolType::S1AP,
                             MessageType::S1AP_INITIAL_UE_MESSAGE);

    auto participant = detector->detectParticipant(msg, true);

    EXPECT_EQ(participant.type, ParticipantType::MME);
    EXPECT_EQ(participant.id, "MyMME");
    EXPECT_EQ(participant.ip_address, "10.0.1.100");
    EXPECT_TRUE(participant.friendly_name.has_value());
    EXPECT_EQ(participant.friendly_name.value(), "MyMME");
}

TEST_F(ParticipantDetectorTest, GetAllParticipants) {
    auto msg1 = createMessage("10.0.1.50", 36412, "10.0.2.10", 36412, ProtocolType::S1AP,
                              MessageType::S1AP_INITIAL_UE_MESSAGE);

    auto msg2 = createMessage("10.0.2.10", 2123, "10.0.3.10", 2123, ProtocolType::GTP_C,
                              MessageType::GTP_CREATE_SESSION_REQ);

    detector->detectParticipant(msg1, true);   // eNodeB
    detector->detectParticipant(msg1, false);  // MME
    detector->detectParticipant(msg2, false);  // S-GW

    auto participants = detector->getAllParticipants();

    EXPECT_EQ(participants.size(), 3);
}

TEST_F(ParticipantDetectorTest, ClearParticipants) {
    auto msg = createMessage("10.0.1.50", 36412, "10.0.2.10", 36412, ProtocolType::S1AP,
                             MessageType::S1AP_INITIAL_UE_MESSAGE);

    detector->detectParticipant(msg, true);
    EXPECT_EQ(detector->getAllParticipants().size(), 1);

    detector->clear();
    EXPECT_EQ(detector->getAllParticipants().size(), 0);
}

TEST_F(ParticipantDetectorTest, ParticipantCaching) {
    auto msg = createMessage("10.0.2.10", 36412, "10.0.1.50", 36412, ProtocolType::S1AP,
                             MessageType::S1AP_INITIAL_UE_MESSAGE);

    // First detection
    auto participant1 = detector->detectParticipant(msg, true);

    // Second detection should return cached result
    auto participant2 = detector->detectParticipant(msg, true);

    EXPECT_EQ(participant1.id, participant2.id);
    EXPECT_EQ(participant1.type, participant2.type);
    EXPECT_EQ(participant1.ip_address, participant2.ip_address);
}

TEST_F(ParticipantDetectorTest, MultipleInstancesOfSameType) {
    auto msg1 = createMessage("10.0.1.50", 36412, "10.0.2.10", 36412, ProtocolType::S1AP,
                              MessageType::S1AP_INITIAL_UE_MESSAGE);

    auto msg2 = createMessage("10.0.1.60", 36412, "10.0.2.10", 36412, ProtocolType::S1AP,
                              MessageType::S1AP_INITIAL_UE_MESSAGE);

    auto enb1 = detector->detectParticipant(msg1, true);
    auto enb2 = detector->detectParticipant(msg2, true);

    EXPECT_EQ(enb1.type, ParticipantType::ENODEB);
    EXPECT_EQ(enb2.type, ParticipantType::ENODEB);
    EXPECT_NE(enb1.id, enb2.id);  // Different IDs for different eNodeBs
}
