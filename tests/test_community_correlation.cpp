#include <cassert>
#include <iostream>
#include <string>
#include <vector>

#include "common/logger.h"
#include "flow_manager/session_correlator.h"
#include "protocol_parsers/sip_parser.h"

using namespace callflow;

void testSipParser() {
    std::string sip_msg =
        "INVITE sip:bob@biloxi.com SIP/2.0\r\n"
        "Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n"
        "Max-Forwards: 70\r\n"
        "To: Bob <sip:bob@biloxi.com>\r\n"
        "From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n"
        "Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n"
        "CSeq: 314159 INVITE\r\n"
        "Contact: <sip:alice@pc33.atlanta.com>\r\n"
        "Content-Type: application/sdp\r\n"
        "Content-Length: 0\r\n"
        "Reason: Q.850;cause=16;text=\"Normal Call Clearing\"\r\n"
        "P-Asserted-Identity: <sip:alice@atlanta.com>, <tel:+15551234567>\r\n"  // Contains numeric
                                                                                // part
        "Diversion: <sip:divert@atlanta.com>;reason=user-busy\r\n"
        "History-Info: <sip:history@atlanta.com>;index=1\r\n"
        "\r\n";

    SipParser parser;
    auto msg_opt =
        parser.parse(reinterpret_cast<const uint8_t*>(sip_msg.c_str()), sip_msg.length());

    assert(msg_opt.has_value());
    const auto& msg = msg_opt.value();

    // Check new headers
    assert(msg.reason.has_value());
    assert(msg.reason.value() == "Q.850;cause=16;text=\"Normal Call Clearing\"");

    // PAI is parsed into struct but we want to check it
    assert(msg.p_asserted_identity.has_value());

    assert(!msg.diversion.empty());
    assert(msg.diversion[0] == "<sip:divert@atlanta.com>;reason=user-busy");

    assert(!msg.history_info.empty());
    assert(msg.history_info[0] == "<sip:history@atlanta.com>;index=1");

    std::cout << "[PASS] SipParser test passed" << std::endl;
}

// Minimal mock config for SessionCorrelator
struct MockConfig : public Config {
    // Add necessary config fields if any
};

void testCorrelationLogic() {
    Config config;
    SessionCorrelator correlator(config);

    // 1. Simulate GTP Create Session (Anchor)
    // We can't easily construct a raw GTP packet without manual binary construction,
    // so we will bypass processPacket and inject logic via JSON data if possible or simulate
    // processPacket with simpler flow. However, processPacket parses data internally if we pass raw
    // packet. Or it takes parsed_data json as argument! SessionCorrelator::processPacket(const
    // PacketMetadata& packet, ProtocolType protocol, const nlohmann::json& parsed_data);

    PacketMetadata gtp_packet;
    gtp_packet.timestamp = std::chrono::system_clock::from_time_t(1000);
    gtp_packet.five_tuple.src_ip = "10.0.0.1";  // GTP src
    gtp_packet.five_tuple.dst_ip = "10.0.0.2";  // GTP dst
    gtp_packet.packet_id = 1;

    nlohmann::json gtp_data;
    gtp_data["teid"] = 1001;
    gtp_data["imsi"] = "123456789012345";
    gtp_data["ue_ip"] = "192.168.1.100";  // UE IP
    gtp_data["msisdn"] = "15551234567";
    gtp_data["message_type_name"] = "Create-Session-Request";
    gtp_data["header"]["message_type"] = 32;  // Create Session Req

    correlator.processPacket(gtp_packet, ProtocolType::GTP_C, gtp_data);

    // 2. Simulate SIP INVITE from the UE IP
    PacketMetadata sip_packet;
    sip_packet.timestamp = std::chrono::system_clock::from_time_t(2000);
    sip_packet.five_tuple.src_ip = "192.168.1.100";  // Matching UE IP
    sip_packet.five_tuple.dst_ip = "10.0.0.5";       // P-CSCF
    sip_packet.packet_id = 2;

    nlohmann::json sip_data;
    sip_data["call_id"] = "sip-call-1";
    sip_data["is_request"] = true;
    sip_data["method"] = "INVITE";

    correlator.processPacket(sip_packet, ProtocolType::SIP, sip_data);

    // 3. Export and Verify
    auto master_sessions = correlator.exportMasterSessions();

    assert(master_sessions.size() == 1);
    auto master = master_sessions[0];

    assert(master["imsi"] == "123456789012345");
    assert(master.contains("gtp_anchor"));
    assert(master.contains("sip_legs"));
    assert(master["sip_legs"].size() == 1);

    std::cout << "[PASS] Correlation logic test passed" << std::endl;
}

int main() {
    Logger::getInstance().setLevel(LogLevel::DEBUG);

    testSipParser();
    testCorrelationLogic();

    return 0;
}
