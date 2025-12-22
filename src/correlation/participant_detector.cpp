#include "../../include/correlation/participant_detector.h"
#include <sstream>

namespace flowviz {

// Well-known ports for 3GPP protocols
constexpr uint16_t S1AP_PORT = 36412;
constexpr uint16_t NGAP_PORT = 38412;
constexpr uint16_t GTP_C_PORT = 2123;
constexpr uint16_t GTP_U_PORT = 2152;
constexpr uint16_t PFCP_PORT = 8805;
constexpr uint16_t DIAMETER_PORT = 3868;

// Diameter Application IDs
constexpr uint32_t DIAMETER_S6A_APP_ID = 16777251;
constexpr uint32_t DIAMETER_GX_APP_ID = 16777238;
constexpr uint32_t DIAMETER_RX_APP_ID = 16777236;
constexpr uint32_t DIAMETER_SH_APP_ID = 16777217;

ParticipantDetector::ParticipantDetector() {
    // Initialize type counters
    type_counters_[ParticipantType::ENODEB] = 0;
    type_counters_[ParticipantType::GNODEB] = 0;
    type_counters_[ParticipantType::MME] = 0;
    type_counters_[ParticipantType::AMF] = 0;
    type_counters_[ParticipantType::SGW] = 0;
    type_counters_[ParticipantType::PGW] = 0;
    type_counters_[ParticipantType::UPF] = 0;
    type_counters_[ParticipantType::HSS] = 0;
    type_counters_[ParticipantType::PCRF] = 0;
    type_counters_[ParticipantType::P_CSCF] = 0;
    type_counters_[ParticipantType::UNKNOWN] = 0;
}

ParticipantInfo ParticipantDetector::detectParticipant(
    const callflow::SessionMessageRef& msg,
    bool is_source
) {
    std::string ip = is_source ? msg.src_ip : msg.dst_ip;
    uint16_t port = is_source ? msg.src_port : msg.dst_port;

    // Check if already detected with port
    std::string ip_port_key = makeIpPortKey(ip, port);
    auto it_port = ip_port_to_participant_.find(ip_port_key);
    if (it_port != ip_port_to_participant_.end()) {
        return it_port->second;
    }

    // Check if already detected (without port)
    auto it = ip_to_participant_.find(ip);
    if (it != ip_to_participant_.end()) {
        return it->second;
    }

    // Detect new participant
    ParticipantType type = ParticipantType::UNKNOWN;

    // Try to detect from protocol
    ParticipantType protocol_type = detectTypeFromProtocol(msg, is_source);
    if (protocol_type != ParticipantType::UNKNOWN) {
        type = protocol_type;
    }

    // Try to detect from message type
    if (type == ParticipantType::UNKNOWN) {
        ParticipantType message_type = detectTypeFromMessageType(msg, is_source);
        if (message_type != ParticipantType::UNKNOWN) {
            type = message_type;
        }
    }

    // Try to detect from Diameter application
    if (type == ParticipantType::UNKNOWN && msg.protocol == callflow::ProtocolType::DIAMETER) {
        ParticipantType diameter_type = detectTypeFromDiameter(msg, is_source);
        if (diameter_type != ParticipantType::UNKNOWN) {
            type = diameter_type;
        }
    }

    // Generate participant info
    std::string participant_id = generateParticipantId(type, ip, port);

    ParticipantInfo info;
    info.id = participant_id;
    info.type = type;
    info.ip_address = ip;
    info.port = port;

    // Store for future lookups
    ip_to_participant_[ip] = info;
    if (port != 0) {
        ip_port_to_participant_[ip_port_key] = info;
    }

    return info;
}

void ParticipantDetector::addExplicitMapping(
    const std::string& ip,
    const std::string& name,
    ParticipantType type
) {
    ParticipantInfo info;
    info.id = name;
    info.type = type;
    info.ip_address = ip;
    info.friendly_name = name;

    ip_to_participant_[ip] = info;
}

void ParticipantDetector::addExplicitMappingWithPort(
    const std::string& ip,
    uint16_t port,
    const std::string& name,
    ParticipantType type
) {
    ParticipantInfo info;
    info.id = name;
    info.type = type;
    info.ip_address = ip;
    info.port = port;
    info.friendly_name = name;

    ip_to_participant_[ip] = info;
    ip_port_to_participant_[makeIpPortKey(ip, port)] = info;
}

std::optional<ParticipantInfo> ParticipantDetector::getParticipant(const std::string& ip) const {
    auto it = ip_to_participant_.find(ip);
    if (it != ip_to_participant_.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<ParticipantInfo> ParticipantDetector::getAllParticipants() const {
    std::vector<ParticipantInfo> participants;
    for (const auto& [ip, info] : ip_to_participant_) {
        participants.push_back(info);
    }
    return participants;
}

void ParticipantDetector::clear() {
    ip_to_participant_.clear();
    ip_port_to_participant_.clear();
    type_counters_.clear();
}

ParticipantType ParticipantDetector::detectTypeFromProtocol(
    const callflow::SessionMessageRef& msg,
    bool is_source
) {
    uint16_t port = is_source ? msg.src_port : msg.dst_port;

    // S1AP: eNodeB (source) or MME (destination)
    if (msg.protocol == callflow::ProtocolType::S1AP || port == S1AP_PORT) {
        return is_source ? ParticipantType::ENODEB : ParticipantType::MME;
    }

    // NGAP: gNodeB (source) or AMF (destination)
    if (msg.protocol == callflow::ProtocolType::NGAP || port == NGAP_PORT) {
        return is_source ? ParticipantType::GNODEB : ParticipantType::AMF;
    }

    // HTTP/2: Likely 5G SBI (SMF, AMF, UPF, etc.)
    if (msg.protocol == callflow::ProtocolType::HTTP2) {
        // Cannot determine specific type from HTTP/2 alone
        return ParticipantType::UNKNOWN;
    }

    // PFCP: SMF (source) or UPF (destination)
    if (msg.protocol == callflow::ProtocolType::PFCP || port == PFCP_PORT) {
        return is_source ? ParticipantType::SMF : ParticipantType::UPF;
    }

    return ParticipantType::UNKNOWN;
}

ParticipantType ParticipantDetector::detectTypeFromMessageType(
    const callflow::SessionMessageRef& msg,
    bool is_source
) {
    // S1AP Initial UE Message: eNodeB -> MME
    if (msg.message_type == callflow::MessageType::S1AP_INITIAL_UE_MESSAGE) {
        return is_source ? ParticipantType::ENODEB : ParticipantType::MME;
    }

    // NGAP Initial UE Message: gNodeB -> AMF
    if (msg.message_type == callflow::MessageType::NGAP_INITIAL_UE_MESSAGE) {
        return is_source ? ParticipantType::GNODEB : ParticipantType::AMF;
    }

    // GTP-C Create Session Request
    if (msg.message_type == callflow::MessageType::GTP_CREATE_SESSION_REQ) {
        // MME -> S-GW (S11) or S-GW -> P-GW (S5/S8)
        // Need more context to distinguish, default to MME -> SGW
        return is_source ? ParticipantType::MME : ParticipantType::SGW;
    }

    // GTP-C Create Session Response
    if (msg.message_type == callflow::MessageType::GTP_CREATE_SESSION_RESP) {
        return is_source ? ParticipantType::SGW : ParticipantType::MME;
    }

    // PFCP Session Establishment Request
    if (msg.message_type == callflow::MessageType::PFCP_SESSION_ESTABLISHMENT_REQ) {
        return is_source ? ParticipantType::SMF : ParticipantType::UPF;
    }

    // SIP REGISTER: UE -> P-CSCF
    if (msg.message_type == callflow::MessageType::SIP_REGISTER) {
        return is_source ? ParticipantType::UE : ParticipantType::P_CSCF;
    }

    // SIP INVITE: Could be UE or P-CSCF depending on direction
    if (msg.message_type == callflow::MessageType::SIP_INVITE) {
        // Cannot determine without more context
        return ParticipantType::UNKNOWN;
    }

    return ParticipantType::UNKNOWN;
}

ParticipantType ParticipantDetector::detectTypeFromDiameter(
    const callflow::SessionMessageRef& msg,
    bool is_source
) {
    auto app_id = extractDiameterAppId(msg);
    if (!app_id.has_value()) {
        return ParticipantType::UNKNOWN;
    }

    switch (app_id.value()) {
        case DIAMETER_S6A_APP_ID:
            // S6a: MME <-> HSS
            return is_source ? ParticipantType::MME : ParticipantType::HSS;

        case DIAMETER_GX_APP_ID:
            // Gx: PCRF <-> P-GW
            return is_source ? ParticipantType::PGW : ParticipantType::PCRF;

        case DIAMETER_RX_APP_ID:
            // Rx: P-CSCF <-> PCRF
            return is_source ? ParticipantType::P_CSCF : ParticipantType::PCRF;

        case DIAMETER_SH_APP_ID:
            // Sh: AS <-> HSS
            return is_source ? ParticipantType::AS : ParticipantType::HSS;

        default:
            return ParticipantType::UNKNOWN;
    }
}

std::string ParticipantDetector::generateParticipantId(
    ParticipantType type,
    const std::string& ip,
    uint16_t port
) {
    std::stringstream ss;

    // Special case for UE - always just "UE"
    if (type == ParticipantType::UE) {
        return "UE";
    }

    // Get base name
    std::string base_name = toString(type);

    // If UNKNOWN, use IP address as ID
    if (type == ParticipantType::UNKNOWN) {
        ss << "UNKNOWN-" << ip;
        if (port != 0) {
            ss << ":" << port;
        }
        return ss.str();
    }

    // For known types, use type name with counter
    uint32_t& counter = type_counters_[type];
    counter++;

    // For single instances, just use the type name
    if (counter == 1) {
        return base_name;
    }

    // For multiple instances, append counter
    ss << base_name << "-" << std::setfill('0') << std::setw(2) << counter;
    return ss.str();
}

std::optional<uint32_t> ParticipantDetector::extractDiameterAppId(
    const callflow::SessionMessageRef& msg
) const {
    // Try to extract from parsed_data
    if (msg.parsed_data.contains("application_id")) {
        return msg.parsed_data["application_id"].get<uint32_t>();
    }

    // Try alternative field names
    if (msg.parsed_data.contains("app_id")) {
        return msg.parsed_data["app_id"].get<uint32_t>();
    }

    if (msg.parsed_data.contains("ApplicationId")) {
        return msg.parsed_data["ApplicationId"].get<uint32_t>();
    }

    return std::nullopt;
}

} // namespace flowviz
