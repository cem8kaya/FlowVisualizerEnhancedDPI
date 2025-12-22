#include "protocol_parsers/gtp_parser.h"

#include <arpa/inet.h>

#include <cstring>
#include <iomanip>
#include <sstream>

#include "common/logger.h"

namespace callflow {

// ============================================================================
// GtpHeader Methods
// ============================================================================

nlohmann::json GtpHeader::toJson() const {
    nlohmann::json j;
    j["version"] = version;
    j["piggybacking"] = piggybacking;
    j["teid_present"] = teid_present;
    j["message_type"] = message_type;
    j["message_length"] = message_length;
    if (teid_present) {
        j["teid"] = teid;
    }
    j["sequence_number"] = sequence_number;
    return j;
}

// ============================================================================
// GtpInformationElement Methods
// ============================================================================

nlohmann::json GtpInformationElement::toJson() const {
    nlohmann::json j;
    j["type"] = type;
    j["type_name"] = getTypeName();
    j["length"] = length;
    j["instance"] = instance;

    // Try to represent data as string if appropriate
    std::string str_data = getDataAsString();
    if (!str_data.empty()) {
        j["data"] = str_data;
    } else {
        // Otherwise represent as hex array
        j["data_hex"] = nlohmann::json::array();
        for (auto byte : data) {
            j["data_hex"].push_back(byte);
        }
    }

    return j;
}

std::string GtpInformationElement::getDataAsString() const {
    if (data.empty()) {
        return "";
    }

    // Check if data is printable ASCII
    for (auto byte : data) {
        if (byte < 0x20 || byte > 0x7E) {
            return "";  // Non-printable character
        }
    }

    return std::string(reinterpret_cast<const char*>(data.data()), data.size());
}

std::optional<uint32_t> GtpInformationElement::getDataAsUint32() const {
    if (data.size() < 4) {
        return std::nullopt;
    }

    uint32_t value;
    std::memcpy(&value, data.data(), 4);
    return ntohl(value);
}

std::string GtpInformationElement::getTypeName() const {
    switch (static_cast<GtpIeType>(type)) {
        case GtpIeType::IMSI:
            return "IMSI";
        case GtpIeType::CAUSE:
            return "Cause";
        case GtpIeType::RECOVERY:
            return "Recovery";
        case GtpIeType::APN:
            return "APN";
        case GtpIeType::AMBR:
            return "AMBR";
        case GtpIeType::EBI:
            return "EBI";
        case GtpIeType::IP_ADDRESS:
            return "IP-Address";
        case GtpIeType::MEI:
            return "MEI";
        case GtpIeType::MSISDN:
            return "MSISDN";
        case GtpIeType::INDICATION:
            return "Indication";
        case GtpIeType::PCO:
            return "PCO";
        case GtpIeType::PAA:
            return "PAA";
        case GtpIeType::BEARER_QOS:
            return "Bearer-QoS";
        case GtpIeType::CHARGING_ID:
            return "Charging-ID";
        case GtpIeType::BEARER_CONTEXT:
            return "Bearer-Context";
        case GtpIeType::F_TEID:
            return "F-TEID";
        case GtpIeType::ULI:
            return "ULI";
        case GtpIeType::SERVING_NETWORK:
            return "Serving-Network";
        case GtpIeType::RAT_TYPE:
            return "RAT-Type";
        case GtpIeType::APN_RESTRICTION:
            return "APN-Restriction";
        default:
            return "Unknown-" + std::to_string(type);
    }
}

// ============================================================================
// GtpMessage Methods
// ============================================================================

nlohmann::json GtpMessage::toJson() const {
    nlohmann::json j;
    j["header"] = header.toJson();
    j["message_type_name"] = getMessageTypeName();

    // Add extracted common fields
    if (imsi.has_value()) {
        j["imsi"] = imsi.value();
    }
    if (apn.has_value()) {
        j["apn"] = apn.value();
    }
    if (msisdn.has_value()) {
        j["msisdn"] = msisdn.value();
    }
    if (cause.has_value()) {
        j["cause"] = cause.value();
    }
    if (f_teid.has_value()) {
        j["teid"] = f_teid.value();  // Expose as "teid" for session correlation
    }
    if (user_location_info.has_value()) {
        j["uli_raw"] = user_location_info.value();  // Raw bytes for now
    }
    if (rat_type.has_value()) {
        j["rat_type"] = rat_type.value();
    }

    // Add IEs
    nlohmann::json ies_json = nlohmann::json::array();
    for (const auto& ie : ies) {
        ies_json.push_back(ie.toJson());
    }
    j["ies"] = ies_json;
    j["ie_count"] = ies.size();

    return j;
}

MessageType GtpMessage::getMessageType() const {
    switch (static_cast<GtpMessageType>(header.message_type)) {
        case GtpMessageType::CREATE_SESSION_REQUEST:
            return MessageType::GTP_CREATE_SESSION_REQ;
        case GtpMessageType::CREATE_SESSION_RESPONSE:
            return MessageType::GTP_CREATE_SESSION_RESP;
        case GtpMessageType::DELETE_SESSION_REQUEST:
            return MessageType::GTP_DELETE_SESSION_REQ;
        case GtpMessageType::DELETE_SESSION_RESPONSE:
            return MessageType::GTP_DELETE_SESSION_RESP;
        case GtpMessageType::ECHO_REQUEST:
            return MessageType::GTP_ECHO_REQ;
        case GtpMessageType::ECHO_RESPONSE:
            return MessageType::GTP_ECHO_RESP;
        default:
            return MessageType::UNKNOWN;
    }
}

std::string GtpMessage::getMessageTypeName() const {
    switch (static_cast<GtpMessageType>(header.message_type)) {
        case GtpMessageType::ECHO_REQUEST:
            return "Echo-Request";
        case GtpMessageType::ECHO_RESPONSE:
            return "Echo-Response";
        case GtpMessageType::CREATE_SESSION_REQUEST:
            return "Create-Session-Request";
        case GtpMessageType::CREATE_SESSION_RESPONSE:
            return "Create-Session-Response";
        case GtpMessageType::MODIFY_BEARER_REQUEST:
            return "Modify-Bearer-Request";
        case GtpMessageType::MODIFY_BEARER_RESPONSE:
            return "Modify-Bearer-Response";
        case GtpMessageType::DELETE_SESSION_REQUEST:
            return "Delete-Session-Request";
        case GtpMessageType::DELETE_SESSION_RESPONSE:
            return "Delete-Session-Response";
        case GtpMessageType::MODIFY_BEARER_COMMAND:
            return "Modify-Bearer-Command";
        case GtpMessageType::MODIFY_BEARER_FAILURE_INDICATION:
            return "Modify-Bearer-Failure-Indication";
        case GtpMessageType::DELETE_BEARER_COMMAND:
            return "Delete-Bearer-Command";
        case GtpMessageType::DELETE_BEARER_FAILURE_INDICATION:
            return "Delete-Bearer-Failure-Indication";
        case GtpMessageType::BEARER_RESOURCE_COMMAND:
            return "Bearer-Resource-Command";
        case GtpMessageType::BEARER_RESOURCE_FAILURE_INDICATION:
            return "Bearer-Resource-Failure-Indication";
        case GtpMessageType::CREATE_BEARER_REQUEST:
            return "Create-Bearer-Request";
        case GtpMessageType::CREATE_BEARER_RESPONSE:
            return "Create-Bearer-Response";
        case GtpMessageType::UPDATE_BEARER_REQUEST:
            return "Update-Bearer-Request";
        case GtpMessageType::UPDATE_BEARER_RESPONSE:
            return "Update-Bearer-Response";
        case GtpMessageType::DELETE_BEARER_REQUEST:
            return "Delete-Bearer-Request";
        case GtpMessageType::DELETE_BEARER_RESPONSE:
            return "Delete-Bearer-Response";
        default:
            return "Unknown-" + std::to_string(header.message_type);
    }
}

// ============================================================================
// GtpParser Methods
// ============================================================================

bool GtpParser::isGtp(const uint8_t* data, size_t len) {
    if (!data || len < 8) {
        return false;
    }

    // Check for GTPv2 (version 2)
    uint8_t flags = data[0];
    uint8_t version = (flags >> 5) & 0x07;

    if (version != 2) {
        return false;
    }

    // Check message length is reasonable
    uint16_t msg_len;
    std::memcpy(&msg_len, data + 2, 2);
    msg_len = ntohs(msg_len);

    // Message length should be reasonable (not too large)
    if (msg_len > 65535) {
        return false;
    }

    return true;
}

std::optional<GtpMessage> GtpParser::parse(const uint8_t* data, size_t len) {
    if (!isGtp(data, len)) {
        LOG_DEBUG("Not a valid GTP message");
        return std::nullopt;
    }

    // Parse header
    auto header_opt = parseHeader(data, len);
    if (!header_opt.has_value()) {
        LOG_ERROR("Failed to parse GTP header");
        return std::nullopt;
    }

    GtpMessage msg;
    msg.header = header_opt.value();

    // Calculate header length
    size_t header_len = msg.header.teid_present ? 12 : 8;

    // Check if we have the complete message
    // Note: message_length doesn't include the first 4 bytes
    size_t total_len = 4 + msg.header.message_length;
    if (len < total_len) {
        LOG_DEBUG("Incomplete GTP message: have " << len << " bytes, need " << total_len);
        return std::nullopt;
    }

    // Parse IEs
    if (!parseIes(data, total_len, header_len, msg.ies)) {
        LOG_ERROR("Failed to parse GTP IEs");
        return std::nullopt;
    }

    // Extract common fields
    extractCommonFields(msg);

    LOG_DEBUG("Parsed GTP message: " << msg.getMessageTypeName() << " with " << msg.ies.size()
                                     << " IEs");

    return msg;
}

std::optional<GtpHeader> GtpParser::parseHeader(const uint8_t* data, size_t len) {
    if (len < 8) {
        return std::nullopt;
    }

    GtpHeader header;

    // Byte 0: Flags
    uint8_t flags = data[0];
    header.version = (flags >> 5) & 0x07;       // Version (bits 5-7)
    header.piggybacking = (flags & 0x10) != 0;  // P flag (bit 4)
    header.teid_present = (flags & 0x08) != 0;  // T flag (bit 3)

    // Byte 1: Message Type
    header.message_type = data[1];

    // Bytes 2-3: Message Length
    std::memcpy(&header.message_length, data + 2, 2);
    header.message_length = ntohs(header.message_length);

    if (header.teid_present) {
        // Extended header with TEID
        if (len < 12) {
            return std::nullopt;
        }

        // Bytes 4-7: TEID
        std::memcpy(&header.teid, data + 4, 4);
        header.teid = ntohl(header.teid);

        // Bytes 8-10: Sequence Number (24 bits)
        header.sequence_number = (static_cast<uint32_t>(data[8]) << 16) |
                                 (static_cast<uint32_t>(data[9]) << 8) |
                                 static_cast<uint32_t>(data[10]);
        // Byte 11: Spare
    } else {
        // No TEID
        header.teid = 0;

        // Bytes 4-6: Sequence Number (24 bits)
        header.sequence_number = (static_cast<uint32_t>(data[4]) << 16) |
                                 (static_cast<uint32_t>(data[5]) << 8) |
                                 static_cast<uint32_t>(data[6]);
        // Byte 7: Spare
    }

    return header;
}

bool GtpParser::parseIes(const uint8_t* data, size_t len, size_t offset,
                         std::vector<GtpInformationElement>& ies) {
    while (offset < len) {
        auto ie_opt = parseIe(data, len, offset);
        if (!ie_opt.has_value()) {
            // Failed to parse IE - might be end of valid data
            break;
        }

        ies.push_back(ie_opt.value());
    }

    return true;
}

std::optional<GtpInformationElement> GtpParser::parseIe(const uint8_t* data, size_t len,
                                                        size_t& offset) {
    // IE header is at least 4 bytes
    if (offset + 4 > len) {
        LOG_DEBUG("Not enough data for IE header at offset " << offset);
        return std::nullopt;
    }

    GtpInformationElement ie;

    // Byte 0: IE Type
    ie.type = data[offset];

    // Bytes 1-2: IE Length (2 bytes)
    std::memcpy(&ie.length, data + offset + 1, 2);
    ie.length = ntohs(ie.length);

    // Byte 3: Instance (4 bits) + Spare (4 bits)
    ie.instance = (data[offset + 3] >> 4) & 0x0F;

    // Check if we have enough data
    if (offset + 4 + ie.length > len) {
        LOG_DEBUG("Not enough data for IE data at offset " << offset);
        return std::nullopt;
    }

    // Copy IE data
    ie.data.resize(ie.length);
    std::memcpy(ie.data.data(), data + offset + 4, ie.length);

    offset += 4 + ie.length;

    return ie;
}

void GtpParser::extractCommonFields(GtpMessage& msg) {
    for (const auto& ie : msg.ies) {
        switch (static_cast<GtpIeType>(ie.type)) {
            case GtpIeType::IMSI:
                msg.imsi = decodeImsi(ie.data);
                break;
            case GtpIeType::APN:
                msg.apn = decodeApn(ie.data);
                break;
            case GtpIeType::MSISDN:
                msg.msisdn = decodeMsisdn(ie.data);
                break;
            case GtpIeType::CAUSE:
                if (ie.data.size() >= 2) {
                    msg.cause = ie.data[0];  // Cause value is in first byte
                }
                break;
            case GtpIeType::F_TEID:
                // F-TEID contains interface type (1 byte) + TEID (4 bytes) + IP address
                if (ie.data.size() >= 5) {
                    uint32_t teid;
                    std::memcpy(&teid, ie.data.data() + 1, 4);
                    msg.f_teid = ntohl(teid);
                }
                break;
            case GtpIeType::ULI:
                msg.user_location_info = ie.data;
                break;
            case GtpIeType::RAT_TYPE:
                if (!ie.data.empty()) {
                    msg.rat_type = ie.data[0];
                }
                break;
            default:
                break;
        }
    }
}

std::string GtpParser::decodeImsi(const std::vector<uint8_t>& data) {
    if (data.empty()) {
        return "";
    }

    std::ostringstream oss;

    // IMSI is encoded in BCD (Binary Coded Decimal)
    // Each byte contains two digits (nibbles)
    for (size_t i = 0; i < data.size(); ++i) {
        uint8_t byte = data[i];

        // Lower nibble (first digit)
        uint8_t digit1 = byte & 0x0F;
        if (digit1 <= 9) {
            oss << static_cast<char>('0' + digit1);
        }

        // Upper nibble (second digit)
        uint8_t digit2 = (byte >> 4) & 0x0F;
        if (digit2 <= 9) {
            oss << static_cast<char>('0' + digit2);
        } else if (digit2 == 0x0F) {
            // Filler digit, stop here
            break;
        }
    }

    return oss.str();
}

std::string GtpParser::decodeMsisdn(const std::vector<uint8_t>& data) {
    if (data.size() < 2) {
        return "";
    }

    std::ostringstream oss;

    // Skip first byte (contains extension, type of number, numbering plan)
    // Decode remaining bytes as BCD
    for (size_t i = 1; i < data.size(); ++i) {
        uint8_t byte = data[i];

        // Lower nibble
        uint8_t digit1 = byte & 0x0F;
        if (digit1 <= 9) {
            oss << static_cast<char>('0' + digit1);
        }

        // Upper nibble
        uint8_t digit2 = (byte >> 4) & 0x0F;
        if (digit2 <= 9) {
            oss << static_cast<char>('0' + digit2);
        } else if (digit2 == 0x0F) {
            // Filler digit
            break;
        }
    }

    return oss.str();
}

std::string GtpParser::decodeApn(const std::vector<uint8_t>& data) {
    if (data.empty()) {
        return "";
    }

    std::ostringstream oss;

    // APN is encoded as length-prefixed labels (like DNS names)
    size_t offset = 0;
    bool first = true;

    while (offset < data.size()) {
        uint8_t label_len = data[offset];
        if (label_len == 0) {
            break;  // End of APN
        }

        offset++;

        if (offset + label_len > data.size()) {
            break;  // Invalid length
        }

        if (!first) {
            oss << '.';
        }
        first = false;

        for (size_t i = 0; i < label_len; ++i) {
            oss << static_cast<char>(data[offset + i]);
        }

        offset += label_len;
    }

    return oss.str();
}

}  // namespace callflow
