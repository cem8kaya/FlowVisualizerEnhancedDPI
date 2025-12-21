#include "protocol_parsers/gtpv1_parser.h"

#include <arpa/inet.h>

#include <cstring>
#include <iomanip>
#include <sstream>

#include "common/logger.h"

namespace callflow {

// ============================================================================
// GtpV1ExtensionHeader Methods
// ============================================================================

nlohmann::json GtpV1ExtensionHeader::toJson() const {
    nlohmann::json j;
    j["type"] = static_cast<uint8_t>(type);
    j["type_name"] = getTypeName();
    j["length"] = length;

    // Represent content as hex array
    j["content_hex"] = nlohmann::json::array();
    for (auto byte : content) {
        j["content_hex"].push_back(byte);
    }

    if (next_extension_header_type.has_value()) {
        j["next_extension_header_type"] = next_extension_header_type.value();
    }

    return j;
}

std::string GtpV1ExtensionHeader::getTypeName() const {
    switch (type) {
        case GtpV1ExtensionType::NO_MORE_EXTENSION_HEADERS:
            return "No-More-Extensions";
        case GtpV1ExtensionType::MBMS_SUPPORT_INDICATION:
            return "MBMS-Support-Indication";
        case GtpV1ExtensionType::MS_INFO_CHANGE_REPORTING_SUPPORT_INDICATION:
            return "MS-Info-Change-Reporting-Support";
        case GtpV1ExtensionType::SERVICE_CLASS_INDICATOR:
            return "Service-Class-Indicator";
        case GtpV1ExtensionType::UDP_PORT:
            return "UDP-Port";
        case GtpV1ExtensionType::RAN_CONTAINER:
            return "RAN-Container";
        case GtpV1ExtensionType::LONG_PDCP_PDU_NUMBER:
            return "Long-PDCP-PDU-Number";
        case GtpV1ExtensionType::XW_RAN_CONTAINER:
            return "XW-RAN-Container";
        case GtpV1ExtensionType::NR_RAN_CONTAINER:
            return "NR-RAN-Container";
        case GtpV1ExtensionType::PDU_SESSION_CONTAINER:
            return "PDU-Session-Container";
        case GtpV1ExtensionType::PDCP_PDU_NUMBER:
            return "PDCP-PDU-Number";
        case GtpV1ExtensionType::SUSPEND_REQUEST:
            return "Suspend-Request";
        case GtpV1ExtensionType::SUSPEND_RESPONSE:
            return "Suspend-Response";
        default:
            return "Unknown-Extension-" + std::to_string(static_cast<uint8_t>(type));
    }
}

// ============================================================================
// EncapsulatedPacket Methods
// ============================================================================

nlohmann::json EncapsulatedPacket::toJson() const {
    nlohmann::json j;
    j["is_ipv4"] = is_ipv4;
    j["src_ip"] = src_ip;
    j["dst_ip"] = dst_ip;
    j["protocol"] = protocol;
    j["protocol_name"] = getProtocolName();

    if (src_port.has_value()) {
        j["src_port"] = src_port.value();
    }
    if (dst_port.has_value()) {
        j["dst_port"] = dst_port.value();
    }

    j["payload_offset"] = payload_offset;
    j["payload_length"] = payload_length;

    return j;
}

std::string EncapsulatedPacket::getProtocolName() const {
    switch (protocol) {
        case 1:
            return "ICMP";
        case 6:
            return "TCP";
        case 17:
            return "UDP";
        case 58:
            return "ICMPv6";
        case 132:
            return "SCTP";
        default:
            return "Unknown-" + std::to_string(protocol);
    }
}

// ============================================================================
// GtpV1Header Methods
// ============================================================================

nlohmann::json GtpV1Header::toJson() const {
    nlohmann::json j;
    j["version"] = version;
    j["protocol_type"] = protocol_type;
    j["extension_header"] = extension_header;
    j["sequence_number_flag"] = sequence_number_flag;
    j["n_pdu_number_flag"] = n_pdu_number_flag;
    j["message_type"] = message_type;
    j["message_length"] = message_length;
    j["teid"] = teid;

    if (sequence_number.has_value()) {
        j["sequence_number"] = sequence_number.value();
    }
    if (n_pdu_number.has_value()) {
        j["n_pdu_number"] = n_pdu_number.value();
    }
    if (next_extension_header.has_value()) {
        j["next_extension_header"] = next_extension_header.value();
    }

    return j;
}

// ============================================================================
// GtpV1InformationElement Methods
// ============================================================================

nlohmann::json GtpV1InformationElement::toJson() const {
    nlohmann::json j;
    j["type"] = type;
    j["type_name"] = getTypeName();
    j["length"] = data.size();

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

std::string GtpV1InformationElement::getDataAsString() const {
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

std::string GtpV1InformationElement::getTypeName() const {
    switch (static_cast<GtpV1IeType>(type)) {
        case GtpV1IeType::CAUSE:
            return "Cause";
        case GtpV1IeType::IMSI:
            return "IMSI";
        case GtpV1IeType::RAI:
            return "RAI";
        case GtpV1IeType::TLLI:
            return "TLLI";
        case GtpV1IeType::P_TMSI:
            return "P-TMSI";
        case GtpV1IeType::QOS_PROFILE:
            return "QoS-Profile";
        case GtpV1IeType::RECOVERY:
            return "Recovery";
        case GtpV1IeType::SELECTION_MODE:
            return "Selection-Mode";
        case GtpV1IeType::TEID_DATA_I:
            return "TEID-Data-I";
        case GtpV1IeType::TEID_CONTROL_PLANE:
            return "TEID-Control-Plane";
        case GtpV1IeType::TEID_DATA_II:
            return "TEID-Data-II";
        case GtpV1IeType::TEARDOWN_IND:
            return "Teardown-Ind";
        case GtpV1IeType::NSAPI:
            return "NSAPI";
        case GtpV1IeType::CHARGING_ID:
            return "Charging-ID";
        case GtpV1IeType::END_USER_ADDRESS:
            return "End-User-Address";
        case GtpV1IeType::MM_CONTEXT:
            return "MM-Context";
        case GtpV1IeType::PDP_CONTEXT:
            return "PDP-Context";
        case GtpV1IeType::APN:
            return "APN";
        case GtpV1IeType::PROTOCOL_CONFIG_OPTIONS:
            return "Protocol-Config-Options";
        case GtpV1IeType::GSN_ADDRESS:
            return "GSN-Address";
        case GtpV1IeType::MSISDN:
            return "MSISDN";
        case GtpV1IeType::QOS:
            return "QoS";
        case GtpV1IeType::TRAFFIC_FLOW_TEMPLATE:
            return "Traffic-Flow-Template";
        case GtpV1IeType::RAT_TYPE:
            return "RAT-Type";
        case GtpV1IeType::USER_LOCATION_INFO:
            return "User-Location-Info";
        case GtpV1IeType::MS_TIME_ZONE:
            return "MS-Time-Zone";
        case GtpV1IeType::IMEI_SV:
            return "IMEI-SV";
        case GtpV1IeType::CHARGING_GATEWAY_ADDRESS:
            return "Charging-Gateway-Address";
        case GtpV1IeType::PRIVATE_EXTENSION:
            return "Private-Extension";
        default:
            return "Unknown-" + std::to_string(type);
    }
}

uint16_t GtpV1InformationElement::getLength() const {
    return static_cast<uint16_t>(data.size());
}

// ============================================================================
// GtpV1Message Methods
// ============================================================================

nlohmann::json GtpV1Message::toJson() const {
    nlohmann::json j;
    j["header"] = header.toJson();
    j["message_type_name"] = getMessageTypeName();
    j["is_user_plane"] = isUserPlane();

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
    if (teid_data.has_value()) {
        j["teid_data"] = teid_data.value();
    }
    if (teid_control.has_value()) {
        j["teid_control"] = teid_control.value();
    }
    if (nsapi.has_value()) {
        j["nsapi"] = nsapi.value();
    }
    if (!qos_profile.empty()) {
        j["qos_profile_hex"] = nlohmann::json::array();
        for (auto byte : qos_profile) {
            j["qos_profile_hex"].push_back(byte);
        }
    }
    if (gsn_address.has_value()) {
        j["gsn_address"] = gsn_address.value();
    }

    // Add IEs
    nlohmann::json ies_json = nlohmann::json::array();
    for (const auto& ie : ies) {
        ies_json.push_back(ie.toJson());
    }
    j["ies"] = ies_json;
    j["ie_count"] = ies.size();

    // Add extension headers
    if (!extension_headers.empty()) {
        nlohmann::json ext_headers_json = nlohmann::json::array();
        for (const auto& ext : extension_headers) {
            ext_headers_json.push_back(ext.toJson());
        }
        j["extension_headers"] = ext_headers_json;
        j["extension_header_count"] = extension_headers.size();
    }

    // Add user plane data
    if (!user_data.empty()) {
        j["user_data_length"] = user_data.size();
    }

    // Add encapsulated packet info
    if (encapsulated.has_value()) {
        j["encapsulated"] = encapsulated.value().toJson();
    }

    return j;
}

MessageType GtpV1Message::getMessageType() const {
    switch (static_cast<GtpV1MessageType>(header.message_type)) {
        case GtpV1MessageType::CREATE_PDP_CONTEXT_REQUEST:
            return MessageType::GTP_CREATE_SESSION_REQ;
        case GtpV1MessageType::CREATE_PDP_CONTEXT_RESPONSE:
            return MessageType::GTP_CREATE_SESSION_RESP;
        case GtpV1MessageType::DELETE_PDP_CONTEXT_REQUEST:
            return MessageType::GTP_DELETE_SESSION_REQ;
        case GtpV1MessageType::DELETE_PDP_CONTEXT_RESPONSE:
            return MessageType::GTP_DELETE_SESSION_RESP;
        case GtpV1MessageType::ECHO_REQUEST:
            return MessageType::GTP_ECHO_REQ;
        case GtpV1MessageType::ECHO_RESPONSE:
            return MessageType::GTP_ECHO_RESP;
        default:
            return MessageType::UNKNOWN;
    }
}

std::string GtpV1Message::getMessageTypeName() const {
    switch (static_cast<GtpV1MessageType>(header.message_type)) {
        case GtpV1MessageType::ECHO_REQUEST:
            return "Echo-Request";
        case GtpV1MessageType::ECHO_RESPONSE:
            return "Echo-Response";
        case GtpV1MessageType::VERSION_NOT_SUPPORTED:
            return "Version-Not-Supported";
        case GtpV1MessageType::CREATE_PDP_CONTEXT_REQUEST:
            return "Create-PDP-Context-Request";
        case GtpV1MessageType::CREATE_PDP_CONTEXT_RESPONSE:
            return "Create-PDP-Context-Response";
        case GtpV1MessageType::UPDATE_PDP_CONTEXT_REQUEST:
            return "Update-PDP-Context-Request";
        case GtpV1MessageType::UPDATE_PDP_CONTEXT_RESPONSE:
            return "Update-PDP-Context-Response";
        case GtpV1MessageType::DELETE_PDP_CONTEXT_REQUEST:
            return "Delete-PDP-Context-Request";
        case GtpV1MessageType::DELETE_PDP_CONTEXT_RESPONSE:
            return "Delete-PDP-Context-Response";
        case GtpV1MessageType::ERROR_INDICATION:
            return "Error-Indication";
        case GtpV1MessageType::PDU_NOTIFICATION_REQUEST:
            return "PDU-Notification-Request";
        case GtpV1MessageType::PDU_NOTIFICATION_RESPONSE:
            return "PDU-Notification-Response";
        case GtpV1MessageType::G_PDU:
            return "G-PDU";
        case GtpV1MessageType::END_MARKER:
            return "End-Marker";
        default:
            return "Unknown-" + std::to_string(header.message_type);
    }
}

bool GtpV1Message::isUserPlane() const {
    return static_cast<GtpV1MessageType>(header.message_type) == GtpV1MessageType::G_PDU;
}

// ============================================================================
// GtpV1Parser Methods
// ============================================================================

bool GtpV1Parser::isGtpV1(const uint8_t* data, size_t len) {
    if (!data || len < 8) {
        return false;
    }

    // Check for GTPv1 (version 1)
    uint8_t flags = data[0];
    uint8_t version = (flags >> 5) & 0x07;

    if (version != 1) {
        return false;
    }

    // Check protocol type (bit 4, should be 1 for GTP)
    uint8_t protocol_type = (flags >> 4) & 0x01;
    if (protocol_type != 1) {
        return false;  // GTP' (0) is not supported
    }

    // Check message length is reasonable
    uint16_t msg_len;
    std::memcpy(&msg_len, data + 2, 2);
    msg_len = ntohs(msg_len);

    // Message length should be reasonable
    // Message length should be reasonable
    // Note: msg_len is uint16_t, so it cannot exceed 65535.
    // The check (msg_len > 65535) was redundant and caused a compiler warning.

    return true;
}

std::optional<GtpV1Message> GtpV1Parser::parse(const uint8_t* data, size_t len) {
    if (!isGtpV1(data, len)) {
        LOG_DEBUG("Not a valid GTPv1 message");
        return std::nullopt;
    }

    // Parse header
    auto header_opt = parseHeader(data, len);
    if (!header_opt.has_value()) {
        LOG_ERROR("Failed to parse GTPv1 header");
        return std::nullopt;
    }

    GtpV1Message msg;
    msg.header = header_opt.value();

    // Calculate header length
    // Minimum header is 8 bytes (fixed part)
    // If any of the optional flags are set, we have 4 more bytes
    size_t header_len = 8;
    if (msg.header.sequence_number_flag || msg.header.n_pdu_number_flag ||
        msg.header.extension_header) {
        header_len = 12;
    }

    // Check if we have the complete message
    // Note: message_length doesn't include the first 8 bytes
    size_t total_len = 8 + msg.header.message_length;
    if (len < total_len) {
        LOG_DEBUG("Incomplete GTPv1 message: have " << len << " bytes, need " << total_len);
        return std::nullopt;
    }

    size_t offset = header_len;

    // Parse extension headers if present
    if (msg.header.extension_header && msg.header.next_extension_header.has_value() &&
        msg.header.next_extension_header.value() != 0) {
        if (!parseExtensionHeaders(data, total_len, offset,
                                   msg.header.next_extension_header.value(),
                                   msg.extension_headers)) {
            LOG_WARN("Failed to parse GTPv1 extension headers, continuing anyway");
            // Don't fail - extension headers are optional
        }
    }

    // For G-PDU messages, extract user plane data
    if (msg.isUserPlane()) {
        // Extract user data payload
        if (offset < total_len) {
            size_t payload_len = total_len - offset;
            msg.user_data.resize(payload_len);
            std::memcpy(msg.user_data.data(), data + offset, payload_len);

            // Parse encapsulated IP packet
            EncapsulatedPacket encap;
            if (parseEncapsulatedPacket(data, total_len, offset, encap)) {
                msg.encapsulated = encap;
                LOG_DEBUG("Parsed GTPv1 G-PDU with encapsulated "
                          << (encap.is_ipv4 ? "IPv4" : "IPv6") << " packet: " << encap.src_ip
                          << " -> " << encap.dst_ip);
            } else {
                LOG_DEBUG("Failed to parse encapsulated packet (may not be IP)");
            }
        }
        LOG_DEBUG("Parsed GTPv1 G-PDU message (user plane data)");
        return msg;
    }

    // Parse IEs for control plane messages
    if (!parseIes(data, total_len, header_len, msg.ies)) {
        LOG_ERROR("Failed to parse GTPv1 IEs");
        return std::nullopt;
    }

    // Extract common fields
    extractCommonFields(msg);

    LOG_DEBUG("Parsed GTPv1 message: " << msg.getMessageTypeName() << " with " << msg.ies.size()
                                       << " IEs");

    return msg;
}

std::optional<GtpV1Header> GtpV1Parser::parseHeader(const uint8_t* data, size_t len) {
    if (len < 8) {
        return std::nullopt;
    }

    GtpV1Header header;

    // Byte 0: Flags
    uint8_t flags = data[0];
    header.version = (flags >> 5) & 0x07;               // Version (bits 5-7)
    header.protocol_type = (flags >> 4) & 0x01;         // PT flag (bit 4)
    header.extension_header = (flags & 0x04) != 0;      // E flag (bit 2)
    header.sequence_number_flag = (flags & 0x02) != 0;  // S flag (bit 1)
    header.n_pdu_number_flag = (flags & 0x01) != 0;     // PN flag (bit 0)

    // Byte 1: Message Type
    header.message_type = data[1];

    // Bytes 2-3: Message Length
    std::memcpy(&header.message_length, data + 2, 2);
    header.message_length = ntohs(header.message_length);

    // Bytes 4-7: TEID
    std::memcpy(&header.teid, data + 4, 4);
    header.teid = ntohl(header.teid);

    // Optional fields (bytes 8-11) - present if any flag is set
    if (header.sequence_number_flag || header.n_pdu_number_flag || header.extension_header) {
        if (len < 12) {
            return std::nullopt;
        }

        // Bytes 8-9: Sequence Number
        uint16_t seq_num;
        std::memcpy(&seq_num, data + 8, 2);
        header.sequence_number = ntohs(seq_num);

        // Byte 10: N-PDU Number
        header.n_pdu_number = data[10];

        // Byte 11: Next Extension Header Type
        header.next_extension_header = data[11];
    }

    return header;
}

bool GtpV1Parser::parseIes(const uint8_t* data, size_t len, size_t offset,
                           std::vector<GtpV1InformationElement>& ies) {
    while (offset < len) {
        // Need at least 1 byte for IE type
        if (offset >= len) {
            break;
        }

        uint8_t ie_type = data[offset];

        auto ie_opt = parseIe(data, len, offset, ie_type);
        if (!ie_opt.has_value()) {
            // Failed to parse IE - might be end of valid data or unsupported IE
            break;
        }

        ies.push_back(ie_opt.value());
    }

    return true;
}

std::optional<GtpV1InformationElement> GtpV1Parser::parseIe(const uint8_t* data, size_t len,
                                                            size_t& offset, uint8_t ie_type) {
    // Get IE length based on type
    auto ie_len_opt = getIeLength(ie_type, data, len, offset);
    if (!ie_len_opt.has_value()) {
        LOG_DEBUG("Failed to get IE length for type " << static_cast<int>(ie_type) << " at offset "
                                                      << offset);
        return std::nullopt;
    }

    size_t ie_len = ie_len_opt.value();

    // Check if we have enough data
    if (offset + ie_len > len) {
        LOG_DEBUG("Not enough data for IE at offset " << offset << ": need " << ie_len
                                                      << " bytes, have " << (len - offset));
        return std::nullopt;
    }

    GtpV1InformationElement ie;
    ie.type = ie_type;

    // Copy IE data (excluding the type byte itself)
    ie.data.resize(ie_len - 1);
    std::memcpy(ie.data.data(), data + offset + 1, ie_len - 1);

    offset += ie_len;

    return ie;
}

void GtpV1Parser::extractCommonFields(GtpV1Message& msg) {
    for (const auto& ie : msg.ies) {
        switch (static_cast<GtpV1IeType>(ie.type)) {
            case GtpV1IeType::IMSI:
                msg.imsi = decodeImsi(ie.data);
                break;
            case GtpV1IeType::APN:
                msg.apn = decodeApn(ie.data);
                break;
            case GtpV1IeType::MSISDN:
                msg.msisdn = decodeMsisdn(ie.data);
                break;
            case GtpV1IeType::CAUSE:
                if (!ie.data.empty()) {
                    msg.cause = ie.data[0];
                }
                break;
            case GtpV1IeType::TEID_DATA_I:
                if (ie.data.size() >= 4) {
                    uint32_t teid;
                    std::memcpy(&teid, ie.data.data(), 4);
                    msg.teid_data = ntohl(teid);
                }
                break;
            case GtpV1IeType::TEID_CONTROL_PLANE:
                if (ie.data.size() >= 4) {
                    uint32_t teid;
                    std::memcpy(&teid, ie.data.data(), 4);
                    msg.teid_control = ntohl(teid);
                }
                break;
            case GtpV1IeType::NSAPI:
                if (!ie.data.empty()) {
                    msg.nsapi = ie.data[0] & 0x0F;  // NSAPI is in lower 4 bits
                }
                break;
            case GtpV1IeType::QOS_PROFILE:
                msg.qos_profile = ie.data;
                break;
            case GtpV1IeType::GSN_ADDRESS:
                msg.gsn_address = decodeGsnAddress(ie.data);
                break;
            default:
                break;
        }
    }
}

std::string GtpV1Parser::decodeImsi(const std::vector<uint8_t>& data) {
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

std::string GtpV1Parser::decodeMsisdn(const std::vector<uint8_t>& data) {
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

std::string GtpV1Parser::decodeApn(const std::vector<uint8_t>& data) {
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

std::string GtpV1Parser::decodeGsnAddress(const std::vector<uint8_t>& data) {
    if (data.size() < 4) {
        return "";
    }

    std::ostringstream oss;

    if (data.size() == 4) {
        // IPv4 address
        oss << static_cast<int>(data[0]) << "." << static_cast<int>(data[1]) << "."
            << static_cast<int>(data[2]) << "." << static_cast<int>(data[3]);
    } else if (data.size() == 16) {
        // IPv6 address
        for (size_t i = 0; i < 16; i += 2) {
            if (i > 0) {
                oss << ":";
            }
            oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(data[i])
                << std::setw(2) << static_cast<int>(data[i + 1]);
        }
    } else {
        // Unknown format
        return "";
    }

    return oss.str();
}

std::optional<size_t> GtpV1Parser::getIeLength(uint8_t type, const uint8_t* data, size_t len,
                                               size_t offset) {
    auto ie_type = static_cast<GtpV1IeType>(type);

    // Fixed-length IEs (Type-Value)
    switch (ie_type) {
        case GtpV1IeType::CAUSE:
            return 2;  // 1 byte type + 1 byte value
        case GtpV1IeType::IMSI:
            return 9;  // 1 byte type + 8 bytes IMSI
        case GtpV1IeType::RAI:
            return 7;  // 1 byte type + 6 bytes RAI
        case GtpV1IeType::TLLI:
            return 5;  // 1 byte type + 4 bytes TLLI
        case GtpV1IeType::P_TMSI:
            return 5;  // 1 byte type + 4 bytes P-TMSI
        case GtpV1IeType::REORDERING_REQUIRED:
            return 2;  // 1 byte type + 1 byte value
        case GtpV1IeType::MAP_CAUSE:
            return 2;  // 1 byte type + 1 byte value
        case GtpV1IeType::P_TMSI_SIGNATURE:
            return 4;  // 1 byte type + 3 bytes signature
        case GtpV1IeType::MS_VALIDATED:
            return 2;  // 1 byte type + 1 byte value
        case GtpV1IeType::RECOVERY:
            return 2;  // 1 byte type + 1 byte restart counter
        case GtpV1IeType::SELECTION_MODE:
            return 2;  // 1 byte type + 1 byte mode
        case GtpV1IeType::TEID_DATA_I:
            return 5;  // 1 byte type + 4 bytes TEID
        case GtpV1IeType::TEID_CONTROL_PLANE:
            return 5;  // 1 byte type + 4 bytes TEID
        case GtpV1IeType::TEID_DATA_II:
            return 6;  // 1 byte type + 1 byte NSAPI + 4 bytes TEID
        case GtpV1IeType::TEARDOWN_IND:
            return 2;  // 1 byte type + 1 byte value
        case GtpV1IeType::NSAPI:
            return 2;  // 1 byte type + 1 byte NSAPI
        case GtpV1IeType::RANAP_CAUSE:
            return 2;  // 1 byte type + 1 byte cause
        case GtpV1IeType::RADIO_PRIORITY_SMS:
            return 2;  // 1 byte type + 1 byte priority
        case GtpV1IeType::RADIO_PRIORITY:
            return 2;  // 1 byte type + 1 byte priority
        case GtpV1IeType::PACKET_FLOW_ID:
            return 3;  // 1 byte type + 1 byte NSAPI + 1 byte packet flow ID
        case GtpV1IeType::CHARGING_CHARACTERISTICS:
            return 3;  // 1 byte type + 2 bytes characteristics
        case GtpV1IeType::TRACE_REFERENCE:
            return 3;  // 1 byte type + 2 bytes reference
        case GtpV1IeType::TRACE_TYPE:
            return 3;  // 1 byte type + 2 bytes type
        case GtpV1IeType::MS_NOT_REACHABLE_REASON:
            return 2;  // 1 byte type + 1 byte reason
        case GtpV1IeType::CHARGING_ID:
            return 5;  // 1 byte type + 4 bytes charging ID
        default:
            break;
    }

    // Variable-length IEs (Type-Length-Value)
    // Need at least 3 bytes: type (1) + length (2)
    if (offset + 3 > len) {
        return std::nullopt;
    }

    // Extract length field (2 bytes after type)
    uint16_t ie_len;
    std::memcpy(&ie_len, data + offset + 1, 2);
    ie_len = ntohs(ie_len);

    // Total IE size = type (1 byte) + length field (2 bytes) + data
    return 1 + 2 + ie_len;
}

bool GtpV1Parser::parseExtensionHeaders(const uint8_t* data, size_t len, size_t& offset,
                                        uint8_t first_ext_type,
                                        std::vector<GtpV1ExtensionHeader>& ext_headers) {
    uint8_t next_type = first_ext_type;

    // Extension headers form a chain, each pointing to the next
    while (next_type != 0 && offset < len) {
        // Need at least 2 bytes: length (1) + content + next_type (1)
        if (offset + 2 > len) {
            LOG_DEBUG("Not enough data for extension header at offset " << offset);
            return false;
        }

        GtpV1ExtensionHeader ext;
        ext.type = static_cast<GtpV1ExtensionType>(next_type);

        // First byte is length in 4-byte units (excluding first 2 bytes)
        ext.length = data[offset];

        if (ext.length == 0) {
            LOG_WARN("GTPv1 extension header with zero length at offset " << offset);
            return false;
        }

        // Total extension header size in bytes
        size_t ext_total_len = ext.length * 4;

        if (offset + ext_total_len > len) {
            LOG_DEBUG("Extension header extends beyond packet boundary");
            return false;
        }

        // Content is everything except first byte (length) and last byte (next_type)
        if (ext_total_len >= 2) {
            ext.content.resize(ext_total_len - 2);
            std::memcpy(ext.content.data(), data + offset + 1, ext_total_len - 2);
        }

        // Last byte is next extension header type
        next_type = data[offset + ext_total_len - 1];
        ext.next_extension_header_type = next_type;

        ext_headers.push_back(ext);
        offset += ext_total_len;
    }

    return true;
}

bool GtpV1Parser::parseEncapsulatedPacket(const uint8_t* data, size_t len, size_t offset,
                                          EncapsulatedPacket& encap) {
    if (offset + 20 > len) {  // Minimum IP header size
        return false;
    }

    const uint8_t* ip_data = data + offset;
    size_t ip_len = len - offset;

    uint8_t version = (ip_data[0] >> 4) & 0x0F;

    if (version == 4) {
        // IPv4 packet
        encap.is_ipv4 = true;

        if (ip_len < 20) {
            return false;
        }

        // Extract IP addresses (bytes 12-15: src, 16-19: dst)
        char src_ip_str[INET_ADDRSTRLEN];
        char dst_ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, ip_data + 12, src_ip_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, ip_data + 16, dst_ip_str, INET_ADDRSTRLEN);
        encap.src_ip = src_ip_str;
        encap.dst_ip = dst_ip_str;

        // Extract protocol (byte 9)
        encap.protocol = ip_data[9];

        // Calculate IP header length (IHL field in lower 4 bits of byte 0)
        uint8_t ihl = (ip_data[0] & 0x0F) * 4;

        if (ihl < 20 || offset + ihl > len) {
            return false;  // Invalid IHL
        }

        // Extract ports for TCP/UDP
        if ((encap.protocol == 6 || encap.protocol == 17) && offset + ihl + 4 <= len) {
            // TCP and UDP both have src_port and dst_port in first 4 bytes
            uint16_t src_port, dst_port;
            std::memcpy(&src_port, ip_data + ihl, 2);
            std::memcpy(&dst_port, ip_data + ihl + 2, 2);
            encap.src_port = ntohs(src_port);
            encap.dst_port = ntohs(dst_port);
        }

        encap.payload_offset = offset + ihl;
        encap.payload_length = ip_len - ihl;

    } else if (version == 6) {
        // IPv6 packet
        encap.is_ipv4 = false;

        if (ip_len < 40) {  // IPv6 header is always 40 bytes
            return false;
        }

        // Extract IP addresses (bytes 8-23: src, 24-39: dst)
        char src_ip_str[INET6_ADDRSTRLEN];
        char dst_ip_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, ip_data + 8, src_ip_str, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, ip_data + 24, dst_ip_str, INET6_ADDRSTRLEN);
        encap.src_ip = src_ip_str;
        encap.dst_ip = dst_ip_str;

        // Extract next header (byte 6)
        encap.protocol = ip_data[6];

        // For simplicity, assume no IPv6 extension headers
        // In production, you'd need to parse the extension header chain
        size_t ipv6_hdr_len = 40;

        // Extract ports for TCP/UDP
        if ((encap.protocol == 6 || encap.protocol == 17) && offset + ipv6_hdr_len + 4 <= len) {
            uint16_t src_port, dst_port;
            std::memcpy(&src_port, ip_data + ipv6_hdr_len, 2);
            std::memcpy(&dst_port, ip_data + ipv6_hdr_len + 2, 2);
            encap.src_port = ntohs(src_port);
            encap.dst_port = ntohs(dst_port);
        }

        encap.payload_offset = offset + ipv6_hdr_len;
        encap.payload_length = ip_len - ipv6_hdr_len;

    } else {
        // Unknown IP version
        LOG_DEBUG("Unknown IP version in encapsulated packet: " << static_cast<int>(version));
        return false;
    }

    return true;
}

}  // namespace callflow
