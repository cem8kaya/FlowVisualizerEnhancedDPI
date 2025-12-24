#include "common/types.h"

#include <iomanip>
#include <sstream>

namespace callflow {

// Direction conversions
std::string directionToString(Direction dir) {
    switch (dir) {
        case Direction::CLIENT_TO_SERVER:
            return "client->server";
        case Direction::SERVER_TO_CLIENT:
            return "server->client";
        case Direction::BIDIRECTIONAL:
            return "bidirectional";
        default:
            return "unknown";
    }
}

Direction stringToDirection(const std::string& str) {
    if (str == "client->server")
        return Direction::CLIENT_TO_SERVER;
    if (str == "server->client")
        return Direction::SERVER_TO_CLIENT;
    if (str == "bidirectional")
        return Direction::BIDIRECTIONAL;
    return Direction::UNKNOWN;
}

// Protocol type conversions
std::string protocolTypeToString(ProtocolType proto) {
    switch (proto) {
        case ProtocolType::SIP:
            return "SIP";
        case ProtocolType::RTP:
            return "RTP";
        case ProtocolType::RTCP:
            return "RTCP";
        case ProtocolType::GTP_C:
            return "GTP-C";
        case ProtocolType::GTP_U:
            return "GTP-U";
        case ProtocolType::PFCP:
            return "PFCP";
        case ProtocolType::DIAMETER:
            return "DIAMETER";
        case ProtocolType::HTTP2:
            return "HTTP2";
        case ProtocolType::HTTP:
            return "HTTP";
        case ProtocolType::DNS:
            return "DNS";
        case ProtocolType::SCTP:
            return "SCTP";
        case ProtocolType::TCP:
            return "TCP";
        case ProtocolType::UDP:
            return "UDP";
        case ProtocolType::IP:
            return "IP";
        default:
            return "UNKNOWN";
    }
}

ProtocolType stringToProtocolType(const std::string& str) {
    if (str == "SIP")
        return ProtocolType::SIP;
    if (str == "RTP")
        return ProtocolType::RTP;
    if (str == "RTCP")
        return ProtocolType::RTCP;
    if (str == "GTP-C")
        return ProtocolType::GTP_C;
    if (str == "GTP-U")
        return ProtocolType::GTP_U;
    if (str == "PFCP")
        return ProtocolType::PFCP;
    if (str == "DIAMETER")
        return ProtocolType::DIAMETER;
    if (str == "HTTP2")
        return ProtocolType::HTTP2;
    if (str == "HTTP")
        return ProtocolType::HTTP;
    if (str == "DNS")
        return ProtocolType::DNS;
    if (str == "SCTP")
        return ProtocolType::SCTP;
    if (str == "TCP")
        return ProtocolType::TCP;
    if (str == "UDP")
        return ProtocolType::UDP;
    if (str == "IP")
        return ProtocolType::IP;
    return ProtocolType::UNKNOWN;
}

// Session type conversions
std::string sessionTypeToString(SessionType type) {
    switch (type) {
        case SessionType::VOLTE:
            return "VoLTE";
        case SessionType::GTP:
            return "GTP";
        case SessionType::PFCP:
            return "PFCP";
        case SessionType::DIAMETER:
            return "DIAMETER";
        case SessionType::HTTP2:
            return "HTTP2";
        case SessionType::MIXED:
            return "MIXED";
        default:
            return "UNKNOWN";
    }
}

SessionType stringToSessionType(const std::string& str) {
    if (str == "VoLTE")
        return SessionType::VOLTE;
    if (str == "GTP")
        return SessionType::GTP;
    if (str == "PFCP")
        return SessionType::PFCP;
    if (str == "DIAMETER")
        return SessionType::DIAMETER;
    if (str == "HTTP2")
        return SessionType::HTTP2;
    if (str == "MIXED")
        return SessionType::MIXED;
    return SessionType::UNKNOWN;
}

// Job status conversions
std::string jobStatusToString(JobStatus status) {
    switch (status) {
        case JobStatus::QUEUED:
            return "queued";
        case JobStatus::RUNNING:
            return "running";
        case JobStatus::COMPLETED:
            return "completed";
        case JobStatus::FAILED:
            return "failed";
        default:
            return "unknown";
    }
}

JobStatus stringToJobStatus(const std::string& str) {
    if (str == "queued")
        return JobStatus::QUEUED;
    if (str == "running")
        return JobStatus::RUNNING;
    if (str == "completed")
        return JobStatus::COMPLETED;
    if (str == "failed")
        return JobStatus::FAILED;
    return JobStatus::QUEUED;
}

// Message type to string
std::string messageTypeToString(MessageType type) {
    switch (type) {
        case MessageType::SIP_INVITE:
            return "INVITE";
        case MessageType::SIP_TRYING:
            return "100 Trying";
        case MessageType::SIP_RINGING:
            return "180 Ringing";
        case MessageType::SIP_SESSION_PROGRESS:
            return "183 Session Progress";
        case MessageType::SIP_OK:
            return "200 OK";
        case MessageType::SIP_ACK:
            return "ACK";
        case MessageType::SIP_BYE:
            return "BYE";
        case MessageType::SIP_CANCEL:
            return "CANCEL";
        case MessageType::SIP_REGISTER:
            return "REGISTER";
        case MessageType::SIP_OPTIONS:
            return "OPTIONS";
        case MessageType::SIP_UPDATE:
            return "UPDATE";
        case MessageType::SIP_PRACK:
            return "PRACK";
        case MessageType::DIAMETER_CCR:
            return "CCR";
        case MessageType::DIAMETER_CCA:
            return "CCA";
        case MessageType::DIAMETER_AAR:
            return "AAR";
        case MessageType::DIAMETER_AAA:
            return "AAA";
        case MessageType::GTP_CREATE_SESSION_REQ:
            return "Create Session Request";
        case MessageType::GTP_CREATE_SESSION_RESP:
            return "Create Session Response";
        case MessageType::GTP_DELETE_SESSION_REQ:
            return "Delete Session Request";
        case MessageType::GTP_DELETE_SESSION_RESP:
            return "Delete Session Response";
        case MessageType::GTP_ECHO_REQ:
            return "Echo Request";
        case MessageType::GTP_ECHO_RESP:
            return "Echo Response";
        case MessageType::PFCP_HEARTBEAT_REQ:
            return "Heartbeat Request";
        case MessageType::PFCP_HEARTBEAT_RESP:
            return "Heartbeat Response";
        case MessageType::PFCP_ASSOCIATION_SETUP_REQ:
            return "Association Setup Request";
        case MessageType::PFCP_ASSOCIATION_SETUP_RESP:
            return "Association Setup Response";
        case MessageType::PFCP_SESSION_ESTABLISHMENT_REQ:
            return "Session Establishment Request";
        case MessageType::PFCP_SESSION_ESTABLISHMENT_RESP:
            return "Session Establishment Response";
        case MessageType::PFCP_SESSION_MODIFICATION_REQ:
            return "Session Modification Request";
        case MessageType::PFCP_SESSION_MODIFICATION_RESP:
            return "Session Modification Response";
        case MessageType::PFCP_SESSION_DELETION_REQ:
            return "Session Deletion Request";
        case MessageType::PFCP_SESSION_DELETION_RESP:
            return "Session Deletion Response";
        case MessageType::PFCP_SESSION_REPORT_REQ:
            return "Session Report Request";
        case MessageType::PFCP_SESSION_REPORT_RESP:
            return "Session Report Response";
        case MessageType::HTTP2_HEADERS:
            return "HEADERS";
        case MessageType::HTTP2_DATA:
            return "DATA";
        case MessageType::HTTP2_SETTINGS:
            return "SETTINGS";
        case MessageType::HTTP2_PING:
            return "PING";
        case MessageType::HTTP2_GOAWAY:
            return "GOAWAY";
        case MessageType::X2AP_HANDOVER_PREPARATION:
            return "X2AP Handover Preparation";
        case MessageType::X2AP_HANDOVER_CANCEL:
            return "X2AP Handover Cancel";
        case MessageType::X2AP_SN_STATUS_TRANSFER:
            return "X2AP SN Status Transfer";
        case MessageType::X2AP_UE_CONTEXT_RELEASE:
            return "X2AP UE Context Release";
        case MessageType::X2AP_SETUP:
            return "X2AP Setup";
        case MessageType::X2AP_RESET:
            return "X2AP Reset";
        case MessageType::X2AP_ENB_CONFIGURATION_UPDATE:
            return "X2AP eNB Configuration Update";
        case MessageType::X2AP_RESOURCE_STATUS_REPORTING:
            return "X2AP Resource Status Reporting";
        case MessageType::X2AP_CELL_ACTIVATION:
            return "X2AP Cell Activation";
        case MessageType::NGAP_INITIAL_UE_MESSAGE:
            return "NGAP Initial UE Message";
        case MessageType::NGAP_DOWNLINK_NAS_TRANSPORT:
            return "NGAP Downlink NAS Transport";
        case MessageType::NGAP_UPLINK_NAS_TRANSPORT:
            return "NGAP Uplink NAS Transport";
        case MessageType::NGAP_PDU_SESSION_RESOURCE_SETUP_REQ:
            return "NGAP PDU Session Resource Setup Request";
        case MessageType::NGAP_PDU_SESSION_RESOURCE_SETUP_RESP:
            return "NGAP PDU Session Resource Setup Response";
        case MessageType::NGAP_PDU_SESSION_RESOURCE_RELEASE:
            return "NGAP PDU Session Resource Release";
        case MessageType::NGAP_HANDOVER_PREPARATION:
            return "NGAP Handover Preparation";
        case MessageType::NGAP_PATH_SWITCH_REQUEST:
            return "NGAP Path Switch Request";
        case MessageType::NGAP_NG_SETUP:
            return "NGAP NG Setup";
        case MessageType::NGAP_AMF_CONFIGURATION_UPDATE:
            return "NGAP AMF Configuration Update";
        case MessageType::NAS5G_REGISTRATION_REQUEST:
            return "5G NAS Registration Request";
        case MessageType::NAS5G_REGISTRATION_ACCEPT:
            return "5G NAS Registration Accept";
        case MessageType::NAS5G_DEREGISTRATION_REQUEST:
            return "5G NAS Deregistration Request";
        case MessageType::NAS5G_PDU_SESSION_ESTABLISHMENT_REQUEST:
            return "5G NAS PDU Session Establishment Request";
        case MessageType::NAS5G_PDU_SESSION_MODIFICATION:
            return "5G NAS PDU Session Modification";
        case MessageType::FIVEG_SBA_INTERACTION:
            return "5G SBA Interaction";
        default:
            return "UNKNOWN";
    }
}

// FiveTuple methods
bool FiveTuple::operator==(const FiveTuple& other) const {
    return src_ip == other.src_ip && dst_ip == other.dst_ip && src_port == other.src_port &&
           dst_port == other.dst_port && protocol == other.protocol;
}

std::string FiveTuple::toString() const {
    std::ostringstream oss;
    oss << src_ip << ":" << src_port << " -> " << dst_ip << ":" << dst_port
        << " [proto=" << (int)protocol << "]";
    return oss.str();
}

size_t FiveTuple::hash() const {
    // Simple hash combination
    size_t h1 = std::hash<std::string>{}(src_ip);
    size_t h2 = std::hash<std::string>{}(dst_ip);
    size_t h3 = std::hash<uint16_t>{}(src_port);
    size_t h4 = std::hash<uint16_t>{}(dst_port);
    size_t h5 = std::hash<uint8_t>{}(protocol);
    return h1 ^ (h2 << 1) ^ (h3 << 2) ^ (h4 << 3) ^ (h5 << 4);
}

}  // namespace callflow
