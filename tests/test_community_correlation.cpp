#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "event_extractor/json_exporter.h"
#include "session/session_correlator.h"

using namespace callflow;

class CommunityCorrelationTest : public ::testing::Test {
protected:
    EnhancedSessionCorrelator correlator;

    SessionMessageRef createGtpCreateSession(const std::string& imsi, const std::string& ue_ip) {
        SessionMessageRef msg;
        msg.protocol = ProtocolType::GTP_C;
        msg.message_type = MessageType::GTP_CREATE_SESSION_REQ;
        msg.interface = InterfaceType::S11;
        msg.timestamp = std::chrono::system_clock::now();
        msg.src_ip = "10.0.0.1";
        msg.dst_ip = "10.0.0.2";
        msg.src_port = 2123;
        msg.dst_port = 2123;
        msg.correlation_key.imsi = imsi;
        msg.correlation_key.ue_ipv4 = ue_ip;
        msg.correlation_key.teid_s1u = 123456;
        return msg;
    }

    SessionMessageRef createSipInvite(const std::string& src_ip) {
        SessionMessageRef msg;
        msg.protocol = ProtocolType::SIP;
        msg.message_type = MessageType::SIP_INVITE;
        msg.interface = InterfaceType::IMS_SIP;
        msg.timestamp = std::chrono::system_clock::now();
        msg.src_ip = src_ip;
        msg.dst_ip = "192.168.1.50";
        msg.src_port = 5060;
        msg.dst_port = 5060;
        msg.correlation_key.sip_call_id = "call-id-12345";
        return msg;
    }

    SessionMessageRef createDiameterMessage(const std::string& imsi) {
        SessionMessageRef msg;
        msg.protocol = ProtocolType::DIAMETER;
        msg.message_type = MessageType::DIAMETER_CCR;  // Placeholder type
        msg.interface = InterfaceType::DIAMETER;
        msg.timestamp = std::chrono::system_clock::now();
        msg.src_ip = "192.168.1.20";
        msg.dst_ip = "192.168.1.30";
        msg.src_port = 3868;
        msg.dst_port = 3868;
        msg.correlation_key.imsi = imsi;
        msg.correlation_key.icid = "icid-123";
        return msg;
    }
};

TEST_F(CommunityCorrelationTest, EndToEndVoLTECorrelation) {
    std::string imsi = "222333444555666";
    std::string ue_ip = "192.168.200.50";

    // 1. GTP Create Session (Anchoring)
    auto gtp_msg = createGtpCreateSession(imsi, ue_ip);
    correlator.addMessage(gtp_msg);

    // Check Mapping
    auto master = correlator.getMasterSession(imsi);
    ASSERT_TRUE(master.has_value());
    EXPECT_EQ(master->imsi, imsi);
    EXPECT_TRUE(master->gtp_session_id.has_value());

    // 2. SIP Invite (Linking via IP)
    auto sip_msg = createSipInvite(ue_ip);
    correlator.addMessage(sip_msg);

    // Verify SIP linked
    master = correlator.getMasterSession(imsi);  // Re-fetch
    ASSERT_TRUE(master.has_value());
    EXPECT_EQ(master->sip_session_ids.size(), 1);

    // 3. Diameter CCR (Linking via IMSI)
    auto diameter_msg = createDiameterMessage(imsi);
    correlator.addMessage(diameter_msg);

    // Verify Diameter linked
    master = correlator.getMasterSession(imsi);
    ASSERT_TRUE(master.has_value());
    EXPECT_EQ(master->diameter_session_ids.size(), 1);

    // 4. Verify JSON Export
    JsonExporter exporter;
    std::string json_output = exporter.exportMasterSessions(correlator);

    // Parse back to verify
    auto j = nlohmann::json::parse(json_output);
    ASSERT_TRUE(j.is_array());
    ASSERT_EQ(j.size(), 1);

    auto& m = j[0];
    EXPECT_EQ(m["imsi"], imsi);
    EXPECT_EQ(m["protocols"].size(), 3);  // GTP, SIP, DIAMETER
    EXPECT_EQ(m["events"].size(), 3);     // 3 messages total
}
