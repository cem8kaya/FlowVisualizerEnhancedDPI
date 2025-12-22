#include <cassert>
#include <chrono>
#include <iostream>

#include "common/logger.h"
#include "session/session_correlator.h"

using namespace callflow;

int main() {
    Logger::getInstance().setLevel(LogLevel::DEBUG);
    EnhancedSessionCorrelator correlator;

    // 1. Simulate SIP INVITE with MSISDN in P-Asserted-Identity
    // MSISDN: 1234567890
    nlohmann::json sip_json;
    sip_json["message_type"] = "SIP_INVITE";
    sip_json["call_id"] = "sip-call-id-1";
    sip_json["interface_type"] = "IMS_SIP";
    sip_json["p_asserted_identity"] = nlohmann::json::array(
        {{{"username", "1234567890"}, {"domain", "ims.mnc001.mcc001.3gppnetwork.org"}}});

    SessionMessageRef sip_msg;
    sip_msg.protocol = ProtocolType::SIP;
    sip_msg.interface = InterfaceType::IMS_SIP;
    sip_msg.timestamp = std::chrono::system_clock::now();
    sip_msg.parsed_data = sip_json;

    // Manual key populate to simulate what extractCorrelationKey SHOULD do
    sip_msg.correlation_key = correlator.extractCorrelationKey(sip_json, ProtocolType::SIP);

    std::cout << "SIP Key MSISDN: "
              << (sip_msg.correlation_key.msisdn.has_value()
                      ? sip_msg.correlation_key.msisdn.value()
                      : "NULL")
              << std::endl;

    correlator.addMessage(sip_msg);

    // 2. Simulate Diameter CCR with MSISDN in Subscription-Id
    nlohmann::json diam_json;
    diam_json["header"]["command_code"] = 272;  // CCR
    diam_json["avps"] = nlohmann::json::array();

    // Verify by simulating Hex data which the new logic expects for Grouped AVPs
    nlohmann::json sub_id_avp;
    sub_id_avp["code"] = 443;

    // Construct fake hex payload for:
    // AVP 450 (Type) = 0 (E164)
    // AVP 444 (Data) = "1234567890"

    // 450 Header: 00 00 01 C2, Flags: 40 (M), Len: 00 00 0C (12)
    // Data: 00 00 00 00

    // 444 Header: 00 00 01 BC, Flags: 40 (M), Len: 00 00 12 (18) -> 8 header + 10 data
    // Data: "1234567890" -> 31 32 33 34 35 36 37 38 39 30
    // Padding: 2 bytes (to 20)

    // Use int to ensure JSON array serialization
    std::vector<int> payload = {
        // AVP 450 (Type=0)
        0x00, 0x00, 0x01, 0xC2, 0x40, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00,

        // AVP 444 (Data="1234567890")
        0x00, 0x00, 0x01, 0xBC, 0x40, 0x00, 0x00, 0x12, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x30, 0x00, 0x00  // Padding
    };

    sub_id_avp["data_hex"] = payload;

    diam_json["avps"].push_back(sub_id_avp);

    SessionMessageRef diam_msg;
    diam_msg.protocol = ProtocolType::DIAMETER;
    diam_msg.parsed_data = diam_json;
    diam_msg.correlation_key = correlator.extractCorrelationKey(diam_json, ProtocolType::DIAMETER);

    std::cout << "Diameter Key MSISDN: "
              << (diam_msg.correlation_key.msisdn.has_value()
                      ? diam_msg.correlation_key.msisdn.value()
                      : "NULL")
              << std::endl;

    correlator.addMessage(diam_msg);

    // 3. Verify
    auto sessions = correlator.getAllSessions();
    std::cout << "Total Sessions: " << sessions.size() << std::endl;

    if (sessions.size() == 1) {
        std::cout << "SUCCESS: Sessions Merged" << std::endl;
    } else {
        std::cout << "FAILURE: Sessions NOT Merged" << std::endl;
    }

    return 0;
}
