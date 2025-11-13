#include "protocol_parsers/diameter_parser.h"
#include "common/logger.h"
#include <cstring>
#include <arpa/inet.h>

namespace callflow {

// ============================================================================
// DiameterHeader Methods
// ============================================================================

nlohmann::json DiameterHeader::toJson() const {
    nlohmann::json j;
    j["version"] = version;
    j["message_length"] = message_length;
    j["request_flag"] = request_flag;
    j["proxiable_flag"] = proxiable_flag;
    j["error_flag"] = error_flag;
    j["retransmit_flag"] = retransmit_flag;
    j["command_code"] = command_code;
    j["application_id"] = application_id;
    j["hop_by_hop_id"] = hop_by_hop_id;
    j["end_to_end_id"] = end_to_end_id;
    return j;
}

// ============================================================================
// DiameterAvp Methods
// ============================================================================

nlohmann::json DiameterAvp::toJson() const {
    nlohmann::json j;
    j["code"] = code;
    j["vendor_flag"] = vendor_flag;
    j["mandatory_flag"] = mandatory_flag;
    j["protected_flag"] = protected_flag;
    j["length"] = length;

    if (vendor_flag) {
        j["vendor_id"] = vendor_id;
    }

    // Try to represent data as string if it looks like text
    std::string str_data = getDataAsString();
    if (!str_data.empty()) {
        j["data"] = str_data;
    } else {
        // Otherwise represent as hex
        j["data_hex"] = nlohmann::json::array();
        for (auto byte : data) {
            j["data_hex"].push_back(byte);
        }
    }

    return j;
}

std::string DiameterAvp::getDataAsString() const {
    if (data.empty()) {
        return "";
    }

    // Check if data is printable ASCII/UTF-8
    for (auto byte : data) {
        if (byte == 0) break;  // Null terminator
        if (byte < 0x20 && byte != 0x09 && byte != 0x0A && byte != 0x0D) {
            return "";  // Non-printable character
        }
        if (byte > 0x7E && byte < 0x80) {
            return "";  // Non-ASCII, non-UTF8
        }
    }

    return std::string(reinterpret_cast<const char*>(data.data()), data.size());
}

std::optional<uint32_t> DiameterAvp::getDataAsUint32() const {
    if (data.size() != 4) {
        return std::nullopt;
    }

    uint32_t value;
    std::memcpy(&value, data.data(), 4);
    return ntohl(value);
}

// ============================================================================
// DiameterMessage Methods
// ============================================================================

nlohmann::json DiameterMessage::toJson() const {
    nlohmann::json j;
    j["header"] = header.toJson();
    j["command_name"] = getCommandName();

    // Add extracted common fields
    if (session_id.has_value()) {
        j["session_id"] = session_id.value();
    }
    if (origin_host.has_value()) {
        j["origin_host"] = origin_host.value();
    }
    if (destination_realm.has_value()) {
        j["destination_realm"] = destination_realm.value();
    }
    if (result_code.has_value()) {
        j["result_code"] = result_code.value();
    }

    // Add AVPs
    nlohmann::json avps_json = nlohmann::json::array();
    for (const auto& avp : avps) {
        avps_json.push_back(avp.toJson());
    }
    j["avps"] = avps_json;
    j["avp_count"] = avps.size();

    return j;
}

MessageType DiameterMessage::getMessageType() const {
    switch (header.command_code) {
        case static_cast<uint32_t>(DiameterCommandCode::CREDIT_CONTROL):
            return header.request_flag ? MessageType::DIAMETER_CCR : MessageType::DIAMETER_CCA;
        case static_cast<uint32_t>(DiameterCommandCode::AA_REQUEST):
            return header.request_flag ? MessageType::DIAMETER_AAR : MessageType::DIAMETER_AAA;
        default:
            return MessageType::UNKNOWN;
    }
}

std::string DiameterMessage::getCommandName() const {
    std::string name;

    switch (header.command_code) {
        case static_cast<uint32_t>(DiameterCommandCode::CAPABILITIES_EXCHANGE):
            name = "Capabilities-Exchange";
            break;
        case static_cast<uint32_t>(DiameterCommandCode::RE_AUTH):
            name = "Re-Auth";
            break;
        case static_cast<uint32_t>(DiameterCommandCode::ACCOUNTING):
            name = "Accounting";
            break;
        case static_cast<uint32_t>(DiameterCommandCode::CREDIT_CONTROL):
            name = "Credit-Control";
            break;
        case static_cast<uint32_t>(DiameterCommandCode::AA_REQUEST):
            name = "AA";
            break;
        case static_cast<uint32_t>(DiameterCommandCode::ABORT_SESSION):
            name = "Abort-Session";
            break;
        case static_cast<uint32_t>(DiameterCommandCode::SESSION_TERMINATION):
            name = "Session-Termination";
            break;
        case static_cast<uint32_t>(DiameterCommandCode::DEVICE_WATCHDOG):
            name = "Device-Watchdog";
            break;
        case static_cast<uint32_t>(DiameterCommandCode::DISCONNECT_PEER):
            name = "Disconnect-Peer";
            break;
        default:
            name = "Unknown-" + std::to_string(header.command_code);
            break;
    }

    return name + (header.request_flag ? "-Request" : "-Answer");
}

// ============================================================================
// DiameterParser Methods
// ============================================================================

bool DiameterParser::isDiameter(const uint8_t* data, size_t len) {
    if (!data || len < 20) {
        return false;
    }

    // Check version (should be 1)
    uint8_t version = data[0];
    if (version != 1) {
        return false;
    }

    // Check message length
    uint32_t msg_len = (static_cast<uint32_t>(data[1]) << 16) |
                       (static_cast<uint32_t>(data[2]) << 8) |
                       static_cast<uint32_t>(data[3]);

    // Message length should be at least 20 (header size)
    if (msg_len < 20 || msg_len > 16777215) {  // Max 24-bit value
        return false;
    }

    return true;
}

std::optional<DiameterMessage> DiameterParser::parse(const uint8_t* data, size_t len) {
    if (!isDiameter(data, len)) {
        LOG_DEBUG("Not a valid DIAMETER message");
        return std::nullopt;
    }

    // Parse header
    auto header_opt = parseHeader(data, len);
    if (!header_opt.has_value()) {
        LOG_ERROR("Failed to parse DIAMETER header");
        return std::nullopt;
    }

    DiameterMessage msg;
    msg.header = header_opt.value();

    // Check if we have the complete message
    if (len < msg.header.message_length) {
        LOG_DEBUG("Incomplete DIAMETER message: have " << len << " bytes, need "
                  << msg.header.message_length);
        return std::nullopt;
    }

    // Parse AVPs
    if (!parseAvps(data, msg.header.message_length, 20, msg.avps)) {
        LOG_ERROR("Failed to parse DIAMETER AVPs");
        return std::nullopt;
    }

    // Extract common fields
    extractCommonFields(msg);

    LOG_DEBUG("Parsed DIAMETER message: " << msg.getCommandName()
              << " with " << msg.avps.size() << " AVPs");

    return msg;
}

std::optional<DiameterHeader> DiameterParser::parseHeader(const uint8_t* data, size_t len) {
    if (len < 20) {
        return std::nullopt;
    }

    DiameterHeader header;

    // Byte 0: Version
    header.version = data[0];

    // Bytes 1-3: Message Length (24 bits)
    header.message_length = (static_cast<uint32_t>(data[1]) << 16) |
                           (static_cast<uint32_t>(data[2]) << 8) |
                           static_cast<uint32_t>(data[3]);

    // Byte 4: Flags
    uint8_t flags = data[4];
    header.request_flag = (flags & 0x80) != 0;      // R bit
    header.proxiable_flag = (flags & 0x40) != 0;    // P bit
    header.error_flag = (flags & 0x20) != 0;        // E bit
    header.retransmit_flag = (flags & 0x10) != 0;   // T bit

    // Bytes 5-7: Command Code (24 bits)
    header.command_code = (static_cast<uint32_t>(data[5]) << 16) |
                         (static_cast<uint32_t>(data[6]) << 8) |
                         static_cast<uint32_t>(data[7]);

    // Bytes 8-11: Application ID
    std::memcpy(&header.application_id, data + 8, 4);
    header.application_id = ntohl(header.application_id);

    // Bytes 12-15: Hop-by-Hop Identifier
    std::memcpy(&header.hop_by_hop_id, data + 12, 4);
    header.hop_by_hop_id = ntohl(header.hop_by_hop_id);

    // Bytes 16-19: End-to-End Identifier
    std::memcpy(&header.end_to_end_id, data + 16, 4);
    header.end_to_end_id = ntohl(header.end_to_end_id);

    return header;
}

bool DiameterParser::parseAvps(const uint8_t* data, size_t len, size_t offset,
                               std::vector<DiameterAvp>& avps) {
    while (offset < len) {
        auto avp_opt = parseAvp(data, len, offset);
        if (!avp_opt.has_value()) {
            // Failed to parse AVP
            return false;
        }

        avps.push_back(avp_opt.value());
    }

    return true;
}

std::optional<DiameterAvp> DiameterParser::parseAvp(const uint8_t* data, size_t len,
                                                    size_t& offset) {
    // AVP header is at least 8 bytes (without vendor ID)
    if (offset + 8 > len) {
        LOG_DEBUG("Not enough data for AVP header at offset " << offset);
        return std::nullopt;
    }

    DiameterAvp avp;

    // Bytes 0-3: AVP Code
    std::memcpy(&avp.code, data + offset, 4);
    avp.code = ntohl(avp.code);

    // Byte 4: Flags
    uint8_t flags = data[offset + 4];
    avp.vendor_flag = (flags & 0x80) != 0;      // V bit
    avp.mandatory_flag = (flags & 0x40) != 0;   // M bit
    avp.protected_flag = (flags & 0x20) != 0;   // P bit

    // Bytes 5-7: AVP Length (24 bits)
    avp.length = (static_cast<uint32_t>(data[offset + 5]) << 16) |
                 (static_cast<uint32_t>(data[offset + 6]) << 8) |
                 static_cast<uint32_t>(data[offset + 7]);

    if (avp.length < 8) {
        LOG_ERROR("Invalid AVP length: " << avp.length);
        return std::nullopt;
    }

    size_t header_len = 8;

    // Bytes 8-11: Vendor ID (if V flag set)
    if (avp.vendor_flag) {
        if (offset + 12 > len) {
            LOG_DEBUG("Not enough data for vendor ID at offset " << offset);
            return std::nullopt;
        }
        std::memcpy(&avp.vendor_id, data + offset + 8, 4);
        avp.vendor_id = ntohl(avp.vendor_id);
        header_len = 12;
    } else {
        avp.vendor_id = 0;
    }

    // Calculate data length
    if (avp.length < header_len) {
        LOG_ERROR("AVP length " << avp.length << " is less than header length " << header_len);
        return std::nullopt;
    }

    size_t data_len = avp.length - header_len;

    // Check if we have enough data
    if (offset + header_len + data_len > len) {
        LOG_DEBUG("Not enough data for AVP data at offset " << offset);
        return std::nullopt;
    }

    // Copy AVP data
    avp.data.resize(data_len);
    std::memcpy(avp.data.data(), data + offset + header_len, data_len);

    // Calculate padding (AVPs are padded to 4-byte boundaries)
    size_t padding = calculatePadding(avp.length);
    offset += avp.length + padding;

    return avp;
}

void DiameterParser::extractCommonFields(DiameterMessage& msg) {
    for (const auto& avp : msg.avps) {
        switch (avp.code) {
            case static_cast<uint32_t>(DiameterAvpCode::SESSION_ID):
                msg.session_id = avp.getDataAsString();
                break;
            case static_cast<uint32_t>(DiameterAvpCode::ORIGIN_HOST):
                msg.origin_host = avp.getDataAsString();
                break;
            case static_cast<uint32_t>(DiameterAvpCode::DESTINATION_REALM):
                msg.destination_realm = avp.getDataAsString();
                break;
            case static_cast<uint32_t>(DiameterAvpCode::RESULT_CODE):
                msg.result_code = avp.getDataAsUint32();
                break;
            default:
                break;
        }
    }
}

size_t DiameterParser::calculatePadding(size_t length) {
    size_t remainder = length % 4;
    return remainder == 0 ? 0 : (4 - remainder);
}

}  // namespace callflow
