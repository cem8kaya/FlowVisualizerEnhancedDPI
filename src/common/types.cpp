#include "common/types.h"
#include <sstream>
#include <iomanip>

namespace callflow {

// Direction conversions
std::string directionToString(Direction dir) {
    switch (dir) {
        case Direction::CLIENT_TO_SERVER: return "client->server";
        case Direction::SERVER_TO_CLIENT: return "server->client";
        case Direction::BIDIRECTIONAL: return "bidirectional";
        default: return "unknown";
    }
}

Direction stringToDirection(const std::string& str) {
    if (str == "client->server") return Direction::CLIENT_TO_SERVER;
    if (str == "server->client") return Direction::SERVER_TO_CLIENT;
    if (str == "bidirectional") return Direction::BIDIRECTIONAL;
    return Direction::UNKNOWN;
}

// Protocol type conversions
std::string protocolTypeToString(ProtocolType proto) {
    switch (proto) {
        case ProtocolType::SIP: return "SIP";
        case ProtocolType::RTP: return "RTP";
        case ProtocolType::RTCP: return "RTCP";
        case ProtocolType::GTP_C: return "GTP-C";
        case ProtocolType::GTP_U: return "GTP-U";
        case ProtocolType::DIAMETER: return "DIAMETER";
        case ProtocolType::HTTP2: return "HTTP2";
        case ProtocolType::HTTP: return "HTTP";
        case ProtocolType::DNS: return "DNS";
        case ProtocolType::SCTP: return "SCTP";
        case ProtocolType::TCP: return "TCP";
        case ProtocolType::UDP: return "UDP";
        case ProtocolType::IP: return "IP";
        default: return "UNKNOWN";
    }
}

ProtocolType stringToProtocolType(const std::string& str) {
    if (str == "SIP") return ProtocolType::SIP;
    if (str == "RTP") return ProtocolType::RTP;
    if (str == "RTCP") return ProtocolType::RTCP;
    if (str == "GTP-C") return ProtocolType::GTP_C;
    if (str == "GTP-U") return ProtocolType::GTP_U;
    if (str == "DIAMETER") return ProtocolType::DIAMETER;
    if (str == "HTTP2") return ProtocolType::HTTP2;
    if (str == "HTTP") return ProtocolType::HTTP;
    if (str == "DNS") return ProtocolType::DNS;
    if (str == "SCTP") return ProtocolType::SCTP;
    if (str == "TCP") return ProtocolType::TCP;
    if (str == "UDP") return ProtocolType::UDP;
    if (str == "IP") return ProtocolType::IP;
    return ProtocolType::UNKNOWN;
}

// Session type conversions
std::string sessionTypeToString(SessionType type) {
    switch (type) {
        case SessionType::VOLTE: return "VoLTE";
        case SessionType::GTP: return "GTP";
        case SessionType::DIAMETER: return "DIAMETER";
        case SessionType::HTTP2: return "HTTP2";
        case SessionType::MIXED: return "MIXED";
        default: return "UNKNOWN";
    }
}

SessionType stringToSessionType(const std::string& str) {
    if (str == "VoLTE") return SessionType::VOLTE;
    if (str == "GTP") return SessionType::GTP;
    if (str == "DIAMETER") return SessionType::DIAMETER;
    if (str == "HTTP2") return SessionType::HTTP2;
    if (str == "MIXED") return SessionType::MIXED;
    return SessionType::UNKNOWN;
}

// Message type to string
std::string messageTypeToString(MessageType type) {
    switch (type) {
        case MessageType::SIP_INVITE: return "INVITE";
        case MessageType::SIP_TRYING: return "100 Trying";
        case MessageType::SIP_RINGING: return "180 Ringing";
        case MessageType::SIP_OK: return "200 OK";
        case MessageType::SIP_ACK: return "ACK";
        case MessageType::SIP_BYE: return "BYE";
        case MessageType::SIP_CANCEL: return "CANCEL";
        case MessageType::SIP_REGISTER: return "REGISTER";
        case MessageType::SIP_OPTIONS: return "OPTIONS";
        case MessageType::SIP_UPDATE: return "UPDATE";
        case MessageType::SIP_PRACK: return "PRACK";
        case MessageType::DIAMETER_CCR: return "CCR";
        case MessageType::DIAMETER_CCA: return "CCA";
        case MessageType::DIAMETER_AAR: return "AAR";
        case MessageType::DIAMETER_AAA: return "AAA";
        case MessageType::GTP_CREATE_SESSION_REQ: return "Create Session Request";
        case MessageType::GTP_CREATE_SESSION_RESP: return "Create Session Response";
        case MessageType::GTP_DELETE_SESSION_REQ: return "Delete Session Request";
        case MessageType::GTP_DELETE_SESSION_RESP: return "Delete Session Response";
        case MessageType::GTP_ECHO_REQ: return "Echo Request";
        case MessageType::GTP_ECHO_RESP: return "Echo Response";
        case MessageType::HTTP2_HEADERS: return "HEADERS";
        case MessageType::HTTP2_DATA: return "DATA";
        case MessageType::HTTP2_SETTINGS: return "SETTINGS";
        case MessageType::HTTP2_PING: return "PING";
        case MessageType::HTTP2_GOAWAY: return "GOAWAY";
        default: return "UNKNOWN";
    }
}

// FiveTuple methods
bool FiveTuple::operator==(const FiveTuple& other) const {
    return src_ip == other.src_ip && dst_ip == other.dst_ip &&
           src_port == other.src_port && dst_port == other.dst_port &&
           protocol == other.protocol;
}

std::string FiveTuple::toString() const {
    std::ostringstream oss;
    oss << src_ip << ":" << src_port << " -> "
        << dst_ip << ":" << dst_port << " [proto=" << (int)protocol << "]";
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
