#include "protocol_parsers/pfcp_parser.h"

#include <arpa/inet.h>

#include <cstring>
#include <sstream>

#include "common/logger.h"
#include "common/utils.h"

namespace callflow {

// PFCP Header JSON serialization
nlohmann::json PfcpHeader::toJson() const {
    nlohmann::json j;
    j["version"] = version;
    j["mp_flag"] = mp;
    j["s_flag"] = s;
    j["message_type"] = message_type;
    j["message_length"] = message_length;
    if (s) {
        j["seid"] = seid;
    }
    j["sequence_number"] = sequence_number;
    if (mp) {
        j["message_priority"] = message_priority;
    }
    return j;
}

// PFCP IE JSON serialization
nlohmann::json PfcpInformationElement::toJson() const {
    nlohmann::json j;
    j["type"] = type;
    j["type_name"] = getTypeName();
    j["length"] = length;

    // Try to interpret data based on type
    if (type == static_cast<uint16_t>(PfcpIeType::CAUSE) && data.size() >= 1) {
        j["cause"] = data[0];
    } else if (type == static_cast<uint16_t>(PfcpIeType::RECOVERY_TIME_STAMP) && data.size() >= 4) {
        uint32_t timestamp = ntohl(*reinterpret_cast<const uint32_t*>(data.data()));
        j["recovery_timestamp"] = timestamp;
    } else {
        // For other types, just include hex dump of first few bytes
        if (data.size() > 0) {
            std::stringstream ss;
            size_t max_bytes = std::min(data.size(), size_t(16));
            for (size_t i = 0; i < max_bytes; ++i) {
                if (i > 0)
                    ss << " ";
                ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
            }
            if (data.size() > max_bytes) {
                ss << "...";
            }
            j["data_hex"] = ss.str();
        }
    }

    return j;
}

std::string PfcpInformationElement::getDataAsString() const {
    return std::string(data.begin(), data.end());
}

std::optional<uint32_t> PfcpInformationElement::getDataAsUint32() const {
    if (data.size() < 4) {
        return std::nullopt;
    }
    return ntohl(*reinterpret_cast<const uint32_t*>(data.data()));
}

std::optional<uint64_t> PfcpInformationElement::getDataAsUint64() const {
    if (data.size() < 8) {
        return std::nullopt;
    }
    uint64_t val = 0;
    for (size_t i = 0; i < 8; ++i) {
        val = (val << 8) | data[i];
    }
    return val;
}

std::string PfcpInformationElement::getTypeName() const {
    switch (static_cast<PfcpIeType>(type)) {
        case PfcpIeType::CAUSE:
            return "Cause";
        case PfcpIeType::SOURCE_INTERFACE:
            return "Source Interface";
        case PfcpIeType::F_TEID:
            return "F-TEID";
        case PfcpIeType::NETWORK_INSTANCE:
            return "Network Instance";
        case PfcpIeType::F_SEID:
            return "F-SEID";
        case PfcpIeType::NODE_ID:
            return "Node ID";
        case PfcpIeType::PDR_ID:
            return "PDR ID";
        case PfcpIeType::FAR_ID:
            return "FAR ID";
        case PfcpIeType::QER_ID:
            return "QER ID";
        case PfcpIeType::URR_ID:
            return "URR ID";
        case PfcpIeType::CREATE_PDR:
            return "Create PDR";
        case PfcpIeType::CREATE_FAR:
            return "Create FAR";
        case PfcpIeType::CREATE_QER:
            return "Create QER";
        case PfcpIeType::CREATE_URR:
            return "Create URR";
        case PfcpIeType::UE_IP_ADDRESS:
            return "UE IP Address";
        case PfcpIeType::RECOVERY_TIME_STAMP:
            return "Recovery Time Stamp";
        case PfcpIeType::UP_FUNCTION_FEATURES:
            return "UP Function Features";
        case PfcpIeType::CP_FUNCTION_FEATURES:
            return "CP Function Features";
        default:
            return "Unknown (" + std::to_string(type) + ")";
    }
}

// PFCP Message JSON serialization
nlohmann::json PfcpMessage::toJson() const {
    nlohmann::json j;
    j["header"] = header.toJson();
    j["message_type_name"] = getMessageTypeName();

    // Add IEs
    nlohmann::json ies_json = nlohmann::json::array();
    for (const auto& ie : ies) {
        ies_json.push_back(ie.toJson());
    }
    j["ies"] = ies_json;

    // Add extracted common fields
    if (f_seid.has_value()) {
        j["f_seid"] = f_seid.value();
    }
    if (f_teid.has_value()) {
        j["f_teid"] = f_teid.value();
    }
    if (node_id.has_value()) {
        j["node_id"] = node_id.value();
    }
    if (cause.has_value()) {
        j["cause"] = cause.value();
    }
    if (ue_ip_address.has_value()) {
        j["ue_ip_address"] = ue_ip_address.value();
    }
    if (recovery_timestamp.has_value()) {
        j["recovery_timestamp"] = recovery_timestamp.value();
    }

    return j;
}

MessageType PfcpMessage::getMessageType() const {
    switch (static_cast<PfcpMessageType>(header.message_type)) {
        case PfcpMessageType::HEARTBEAT_REQUEST:
            return MessageType::PFCP_HEARTBEAT_REQ;
        case PfcpMessageType::HEARTBEAT_RESPONSE:
            return MessageType::PFCP_HEARTBEAT_RESP;
        case PfcpMessageType::ASSOCIATION_SETUP_REQUEST:
            return MessageType::PFCP_ASSOCIATION_SETUP_REQ;
        case PfcpMessageType::ASSOCIATION_SETUP_RESPONSE:
            return MessageType::PFCP_ASSOCIATION_SETUP_RESP;
        case PfcpMessageType::SESSION_ESTABLISHMENT_REQUEST:
            return MessageType::PFCP_SESSION_ESTABLISHMENT_REQ;
        case PfcpMessageType::SESSION_ESTABLISHMENT_RESPONSE:
            return MessageType::PFCP_SESSION_ESTABLISHMENT_RESP;
        case PfcpMessageType::SESSION_MODIFICATION_REQUEST:
            return MessageType::PFCP_SESSION_MODIFICATION_REQ;
        case PfcpMessageType::SESSION_MODIFICATION_RESPONSE:
            return MessageType::PFCP_SESSION_MODIFICATION_RESP;
        case PfcpMessageType::SESSION_DELETION_REQUEST:
            return MessageType::PFCP_SESSION_DELETION_REQ;
        case PfcpMessageType::SESSION_DELETION_RESPONSE:
            return MessageType::PFCP_SESSION_DELETION_RESP;
        case PfcpMessageType::SESSION_REPORT_REQUEST:
            return MessageType::PFCP_SESSION_REPORT_REQ;
        case PfcpMessageType::SESSION_REPORT_RESPONSE:
            return MessageType::PFCP_SESSION_REPORT_RESP;
        default:
            return MessageType::UNKNOWN;
    }
}

std::string PfcpMessage::getMessageTypeName() const {
    switch (static_cast<PfcpMessageType>(header.message_type)) {
        case PfcpMessageType::HEARTBEAT_REQUEST:
            return "Heartbeat Request";
        case PfcpMessageType::HEARTBEAT_RESPONSE:
            return "Heartbeat Response";
        case PfcpMessageType::PFD_MANAGEMENT_REQUEST:
            return "PFD Management Request";
        case PfcpMessageType::PFD_MANAGEMENT_RESPONSE:
            return "PFD Management Response";
        case PfcpMessageType::ASSOCIATION_SETUP_REQUEST:
            return "Association Setup Request";
        case PfcpMessageType::ASSOCIATION_SETUP_RESPONSE:
            return "Association Setup Response";
        case PfcpMessageType::ASSOCIATION_UPDATE_REQUEST:
            return "Association Update Request";
        case PfcpMessageType::ASSOCIATION_UPDATE_RESPONSE:
            return "Association Update Response";
        case PfcpMessageType::ASSOCIATION_RELEASE_REQUEST:
            return "Association Release Request";
        case PfcpMessageType::ASSOCIATION_RELEASE_RESPONSE:
            return "Association Release Response";
        case PfcpMessageType::NODE_REPORT_REQUEST:
            return "Node Report Request";
        case PfcpMessageType::NODE_REPORT_RESPONSE:
            return "Node Report Response";
        case PfcpMessageType::SESSION_SET_DELETION_REQUEST:
            return "Session Set Deletion Request";
        case PfcpMessageType::SESSION_SET_DELETION_RESPONSE:
            return "Session Set Deletion Response";
        case PfcpMessageType::SESSION_ESTABLISHMENT_REQUEST:
            return "Session Establishment Request";
        case PfcpMessageType::SESSION_ESTABLISHMENT_RESPONSE:
            return "Session Establishment Response";
        case PfcpMessageType::SESSION_MODIFICATION_REQUEST:
            return "Session Modification Request";
        case PfcpMessageType::SESSION_MODIFICATION_RESPONSE:
            return "Session Modification Response";
        case PfcpMessageType::SESSION_DELETION_REQUEST:
            return "Session Deletion Request";
        case PfcpMessageType::SESSION_DELETION_RESPONSE:
            return "Session Deletion Response";
        case PfcpMessageType::SESSION_REPORT_REQUEST:
            return "Session Report Request";
        case PfcpMessageType::SESSION_REPORT_RESPONSE:
            return "Session Report Response";
        default:
            return "Unknown (" + std::to_string(header.message_type) + ")";
    }
}

// Parser implementation

bool PfcpParser::isPfcp(const uint8_t* data, size_t len) {
    if (len < 4) {
        return false;
    }

    // Check version (first 3 bits should be 001 for PFCP version 1)
    uint8_t version = (data[0] >> 5) & 0x07;
    if (version != 1) {
        return false;
    }

    // Check message type (valid PFCP message types)
    uint8_t msg_type = data[1];
    return (msg_type == 1 || msg_type == 2 ||     // Heartbeat
            (msg_type >= 3 && msg_type <= 15) ||  // Node management
            (msg_type >= 50 && msg_type <= 57));  // Session management
}

std::optional<PfcpMessage> PfcpParser::parse(const uint8_t* data, size_t len) {
    if (!isPfcp(data, len)) {
        return std::nullopt;
    }

    PfcpMessage msg;

    // Parse header
    auto header = parseHeader(data, len);
    if (!header.has_value()) {
        LOG_WARN("Failed to parse PFCP header");
        return std::nullopt;
    }
    msg.header = header.value();

    // Calculate offset for IEs
    size_t header_len = 4;  // Version/Flags (1) + Type (1) + Length (2)
    if (msg.header.s) {
        header_len += 8;  // SEID (8 bytes)
    }
    header_len += 3;  // Sequence number (3 bytes)
    if (msg.header.mp) {
        header_len += 1;  // Message priority (4 bits) + spare (4 bits)
    }

    // Parse IEs
    if (!parseIes(data, len, header_len, msg.ies)) {
        LOG_WARN("Failed to parse PFCP IEs");
    }

    // Extract common fields
    extractCommonFields(msg);

    return msg;
}

std::optional<PfcpHeader> PfcpParser::parseHeader(const uint8_t* data, size_t len) {
    if (len < 8) {
        return std::nullopt;
    }

    PfcpHeader header;

    // Byte 0: Version (3 bits) + Spare (2 bits) + MP (1 bit) + S (1 bit) + Spare (1 bit)
    header.version = (data[0] >> 5) & 0x07;
    header.spare = (data[0] >> 4) & 0x01;
    header.mp = (data[0] >> 1) & 0x01;
    header.s = data[0] & 0x01;

    // Byte 1: Message Type
    header.message_type = data[1];

    // Bytes 2-3: Message Length (network byte order)
    header.message_length = ntohs(*reinterpret_cast<const uint16_t*>(&data[2]));

    size_t offset = 4;

    // SEID (if S flag is set)
    if (header.s) {
        if (len < offset + 8) {
            return std::nullopt;
        }
        header.seid = 0;
        for (int i = 0; i < 8; ++i) {
            header.seid = (header.seid << 8) | data[offset + i];
        }
        offset += 8;
    } else {
        header.seid = 0;
    }

    // Sequence number (3 bytes)
    if (len < offset + 3) {
        return std::nullopt;
    }
    header.sequence_number = (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2];
    offset += 3;

    // Message Priority (if MP flag is set)
    if (header.mp) {
        if (len < offset + 1) {
            return std::nullopt;
        }
        header.message_priority = (data[offset] >> 4) & 0x0F;
    } else {
        header.message_priority = 0;
    }

    return header;
}

bool PfcpParser::parseIes(const uint8_t* data, size_t len, size_t offset,
                          std::vector<PfcpInformationElement>& ies) {
    while (offset < len) {
        auto ie = parseIe(data, len, offset);
        if (!ie.has_value()) {
            break;
        }
        ies.push_back(ie.value());
    }
    return true;
}

std::optional<PfcpInformationElement> PfcpParser::parseIe(const uint8_t* data, size_t len,
                                                          size_t& offset) {
    if (offset + 4 > len) {
        return std::nullopt;
    }

    PfcpInformationElement ie;

    // Bytes 0-1: IE Type (network byte order)
    ie.type = ntohs(*reinterpret_cast<const uint16_t*>(&data[offset]));
    offset += 2;

    // Bytes 2-3: IE Length (network byte order, excluding type and length fields)
    ie.length = ntohs(*reinterpret_cast<const uint16_t*>(&data[offset]));
    offset += 2;

    // IE Data
    if (offset + ie.length > len) {
        LOG_DEBUG("PFCP IE length " << ie.length << " exceeds remaining data");
        return std::nullopt;
    }

    ie.data.assign(data + offset, data + offset + ie.length);
    offset += ie.length;

    return ie;
}

void PfcpParser::extractCommonFields(PfcpMessage& msg) {
    for (const auto& ie : msg.ies) {
        switch (static_cast<PfcpIeType>(ie.type)) {
            case PfcpIeType::CAUSE:
                if (ie.data.size() >= 1) {
                    msg.cause = ie.data[0];
                }
                break;

            case PfcpIeType::F_SEID:
                msg.f_seid = decodeFSeid(ie.data);
                break;

            case PfcpIeType::F_TEID:
                msg.f_teid = decodeFTeid(ie.data);
                break;

            case PfcpIeType::NODE_ID:
                msg.node_id = decodeNodeId(ie.data);
                break;

            case PfcpIeType::UE_IP_ADDRESS:
                msg.ue_ip_address = decodeUeIpAddress(ie.data);
                break;

            case PfcpIeType::RECOVERY_TIME_STAMP:
                if (ie.data.size() >= 4) {
                    msg.recovery_timestamp =
                        ntohl(*reinterpret_cast<const uint32_t*>(ie.data.data()));
                }
                break;

            default:
                break;
        }
    }
}

std::string PfcpParser::decodeNodeId(const std::vector<uint8_t>& data) {
    if (data.size() < 1) {
        return "";
    }

    uint8_t type = data[0] & 0x0F;  // Node ID Type (4 bits)

    if (type == 0 && data.size() >= 5) {
        // IPv4 address
        std::stringstream ss;
        ss << static_cast<int>(data[1]) << "." << static_cast<int>(data[2]) << "."
           << static_cast<int>(data[3]) << "." << static_cast<int>(data[4]);
        return ss.str();
    } else if (type == 1 && data.size() >= 17) {
        // IPv6 address
        std::stringstream ss;
        ss << std::hex;
        for (size_t i = 1; i < 17; i += 2) {
            if (i > 1)
                ss << ":";
            ss << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]) << std::setw(2)
               << std::setfill('0') << static_cast<int>(data[i + 1]);
        }
        return ss.str();
    } else if (type == 2 && data.size() > 1) {
        // FQDN
        return std::string(data.begin() + 1, data.end());
    }

    return "";
}

std::string PfcpParser::decodeUeIpAddress(const std::vector<uint8_t>& data) {
    if (data.size() < 1) {
        return "";
    }

    uint8_t flags = data[0];
    bool v4 = flags & 0x02;
    bool v6 = flags & 0x01;

    size_t offset = 1;

    if (v4 && data.size() >= offset + 4) {
        // IPv4 address
        std::stringstream ss;
        ss << static_cast<int>(data[offset]) << "." << static_cast<int>(data[offset + 1]) << "."
           << static_cast<int>(data[offset + 2]) << "." << static_cast<int>(data[offset + 3]);
        return ss.str();
    } else if (v6 && data.size() >= offset + 16) {
        // IPv6 address
        std::stringstream ss;
        ss << std::hex;
        for (size_t i = 0; i < 16; i += 2) {
            if (i > 0)
                ss << ":";
            ss << std::setw(2) << std::setfill('0') << static_cast<int>(data[offset + i])
               << std::setw(2) << std::setfill('0') << static_cast<int>(data[offset + i + 1]);
        }
        return ss.str();
    }

    return "";
}

std::optional<uint64_t> PfcpParser::decodeFSeid(const std::vector<uint8_t>& data) {
    if (data.size() < 9) {
        return std::nullopt;
    }

    // F-SEID: Flags (1 byte) + SEID (8 bytes) + IPv4/IPv6 address
    uint64_t seid = 0;
    for (size_t i = 1; i < 9; ++i) {
        seid = (seid << 8) | data[i];
    }

    return seid;
}

std::optional<uint32_t> PfcpParser::decodeFTeid(const std::vector<uint8_t>& data) {
    if (data.size() < 5) {
        return std::nullopt;
    }

    // F-TEID: Flags (1 byte) + TEID (4 bytes) + IPv4/IPv6 address
    uint32_t teid = ntohl(*reinterpret_cast<const uint32_t*>(&data[1]));
    return teid;
}

}  // namespace callflow
