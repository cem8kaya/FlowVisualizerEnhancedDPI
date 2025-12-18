#include "protocol_parsers/nas5g_parser.h"
#include "common/logger.h"
#include <cstring>
#include <sstream>
#include <iomanip>

namespace callflow {

// ============================================================================
// Nas5gMessage Methods
// ============================================================================

nlohmann::json Nas5gMessage::toJson() const {
    nlohmann::json j;
    j["security_header_type"] = static_cast<int>(security_header_type);
    j["message_type"] = message_type;
    j["message_type_name"] = getMessageTypeName();
    j["payload_length"] = payload.size();
    j["is_5gmm"] = is5gmm();
    j["is_5gsm"] = is5gsm();

    // Add decoded fields
    if (supi.has_value()) {
        j["supi"] = supi.value();
    }
    if (five_g_guti.has_value()) {
        j["five_g_guti"] = five_g_guti.value();
    }
    if (pdu_session_id.has_value()) {
        j["pdu_session_id"] = pdu_session_id.value();
    }
    if (pti.has_value()) {
        j["pti"] = pti.value();
    }
    if (request_type.has_value()) {
        j["request_type"] = request_type.value();
    }
    if (dnn.has_value()) {
        j["dnn"] = dnn.value();
    }
    if (s_nssai.has_value()) {
        j["s_nssai"] = s_nssai.value();
    }

    return j;
}

MessageType Nas5gMessage::getMessageType() const {
    switch (static_cast<Nas5gMessageType>(message_type)) {
        case Nas5gMessageType::REGISTRATION_REQUEST:
            return MessageType::NAS5G_REGISTRATION_REQUEST;
        case Nas5gMessageType::REGISTRATION_ACCEPT:
            return MessageType::NAS5G_REGISTRATION_ACCEPT;
        case Nas5gMessageType::DEREGISTRATION_REQUEST_UE_ORIGINATING:
        case Nas5gMessageType::DEREGISTRATION_REQUEST_UE_TERMINATED:
            return MessageType::NAS5G_DEREGISTRATION_REQUEST;
        case Nas5gMessageType::PDU_SESSION_ESTABLISHMENT_REQUEST:
            return MessageType::NAS5G_PDU_SESSION_ESTABLISHMENT_REQUEST;
        case Nas5gMessageType::PDU_SESSION_MODIFICATION_REQUEST:
        case Nas5gMessageType::PDU_SESSION_MODIFICATION_COMMAND:
            return MessageType::NAS5G_PDU_SESSION_MODIFICATION;
        default:
            return MessageType::UNKNOWN;
    }
}

std::string Nas5gMessage::getMessageTypeName() const {
    switch (static_cast<Nas5gMessageType>(message_type)) {
        // 5GMM messages
        case Nas5gMessageType::REGISTRATION_REQUEST: return "Registration-Request";
        case Nas5gMessageType::REGISTRATION_ACCEPT: return "Registration-Accept";
        case Nas5gMessageType::REGISTRATION_COMPLETE: return "Registration-Complete";
        case Nas5gMessageType::REGISTRATION_REJECT: return "Registration-Reject";
        case Nas5gMessageType::DEREGISTRATION_REQUEST_UE_ORIGINATING: return "Deregistration-Request-UE-Orig";
        case Nas5gMessageType::DEREGISTRATION_ACCEPT_UE_ORIGINATING: return "Deregistration-Accept-UE-Orig";
        case Nas5gMessageType::DEREGISTRATION_REQUEST_UE_TERMINATED: return "Deregistration-Request-UE-Term";
        case Nas5gMessageType::DEREGISTRATION_ACCEPT_UE_TERMINATED: return "Deregistration-Accept-UE-Term";
        case Nas5gMessageType::SERVICE_REQUEST: return "Service-Request";
        case Nas5gMessageType::SERVICE_REJECT: return "Service-Reject";
        case Nas5gMessageType::SERVICE_ACCEPT: return "Service-Accept";
        case Nas5gMessageType::CONFIGURATION_UPDATE_COMMAND: return "Configuration-Update-Command";
        case Nas5gMessageType::CONFIGURATION_UPDATE_COMPLETE: return "Configuration-Update-Complete";
        case Nas5gMessageType::AUTHENTICATION_REQUEST: return "Authentication-Request";
        case Nas5gMessageType::AUTHENTICATION_RESPONSE: return "Authentication-Response";
        case Nas5gMessageType::AUTHENTICATION_REJECT: return "Authentication-Reject";
        case Nas5gMessageType::AUTHENTICATION_FAILURE: return "Authentication-Failure";
        case Nas5gMessageType::AUTHENTICATION_RESULT: return "Authentication-Result";
        case Nas5gMessageType::IDENTITY_REQUEST: return "Identity-Request";
        case Nas5gMessageType::IDENTITY_RESPONSE: return "Identity-Response";
        case Nas5gMessageType::SECURITY_MODE_COMMAND: return "Security-Mode-Command";
        case Nas5gMessageType::SECURITY_MODE_COMPLETE: return "Security-Mode-Complete";
        case Nas5gMessageType::SECURITY_MODE_REJECT: return "Security-Mode-Reject";
        // 5GSM messages
        case Nas5gMessageType::PDU_SESSION_ESTABLISHMENT_REQUEST: return "PDU-Session-Establishment-Request";
        case Nas5gMessageType::PDU_SESSION_ESTABLISHMENT_ACCEPT: return "PDU-Session-Establishment-Accept";
        case Nas5gMessageType::PDU_SESSION_ESTABLISHMENT_REJECT: return "PDU-Session-Establishment-Reject";
        case Nas5gMessageType::PDU_SESSION_AUTHENTICATION_COMMAND: return "PDU-Session-Authentication-Command";
        case Nas5gMessageType::PDU_SESSION_AUTHENTICATION_COMPLETE: return "PDU-Session-Authentication-Complete";
        case Nas5gMessageType::PDU_SESSION_AUTHENTICATION_RESULT: return "PDU-Session-Authentication-Result";
        case Nas5gMessageType::PDU_SESSION_MODIFICATION_REQUEST: return "PDU-Session-Modification-Request";
        case Nas5gMessageType::PDU_SESSION_MODIFICATION_REJECT: return "PDU-Session-Modification-Reject";
        case Nas5gMessageType::PDU_SESSION_MODIFICATION_COMMAND: return "PDU-Session-Modification-Command";
        case Nas5gMessageType::PDU_SESSION_MODIFICATION_COMPLETE: return "PDU-Session-Modification-Complete";
        case Nas5gMessageType::PDU_SESSION_MODIFICATION_COMMAND_REJECT: return "PDU-Session-Modification-Command-Reject";
        case Nas5gMessageType::PDU_SESSION_RELEASE_REQUEST: return "PDU-Session-Release-Request";
        case Nas5gMessageType::PDU_SESSION_RELEASE_REJECT: return "PDU-Session-Release-Reject";
        case Nas5gMessageType::PDU_SESSION_RELEASE_COMMAND: return "PDU-Session-Release-Command";
        case Nas5gMessageType::PDU_SESSION_RELEASE_COMPLETE: return "PDU-Session-Release-Complete";
        default: return "Unknown-5G-NAS-Message-" + std::to_string(message_type);
    }
}

bool Nas5gMessage::is5gmm() const {
    return (message_type >= 0x40 && message_type < 0xc0);
}

bool Nas5gMessage::is5gsm() const {
    return (message_type >= 0xc0);
}

// ============================================================================
// Nas5gParser Methods
// ============================================================================

bool Nas5gParser::isNas5g(const uint8_t* data, size_t len) {
    if (!data || len < 3) {
        return false;
    }

    // Check Extended Protocol Discriminator (EPD)
    uint8_t epd = data[0];
    // EPD for 5GMM is 0x7E, for 5GSM is 0x2E
    if (epd != 0x7E && epd != 0x2E) {
        return false;
    }

    return true;
}

std::optional<Nas5gMessage> Nas5gParser::parse(const uint8_t* data, size_t len) {
    if (!isNas5g(data, len)) {
        LOG_DEBUG("Not a valid 5G NAS message");
        return std::nullopt;
    }

    auto msg_opt = parseHeader(data, len);
    if (!msg_opt.has_value()) {
        LOG_ERROR("Failed to parse 5G NAS header");
        return std::nullopt;
    }

    Nas5gMessage msg = msg_opt.value();

    // Parse message body based on type
    if (msg.is5gmm()) {
        parse5gmmMessage(msg);
    } else if (msg.is5gsm()) {
        parse5gsmMessage(msg);
    }

    // Extract IEs
    extractIEs(msg);

    LOG_DEBUG("Parsed 5G NAS message: " << msg.getMessageTypeName());

    return msg;
}

std::optional<Nas5gMessage> Nas5gParser::parseHeader(const uint8_t* data, size_t len) {
    if (len < 3) {
        return std::nullopt;
    }

    Nas5gMessage msg;
    size_t offset = 0;

    // Byte 0: Extended Protocol Discriminator (EPD)
    uint8_t epd = data[offset];
    offset++;

    // Byte 1: Security Header Type (4 bits) + Spare (4 bits)
    uint8_t sec_hdr = data[offset];
    msg.security_header_type = static_cast<Nas5gSecurityHeaderType>((sec_hdr >> 4) & 0x0F);
    offset++;

    // If security header is present, skip additional security header fields
    if (msg.security_header_type != Nas5gSecurityHeaderType::PLAIN_NAS_MESSAGE) {
        // Skip Message Authentication Code (4 bytes) and Sequence Number (1 byte)
        if (len < offset + 5) {
            return std::nullopt;
        }
        offset += 5;

        // After security header, there's another EPD and security header type
        if (len < offset + 2) {
            return std::nullopt;
        }
        offset += 2;  // Skip inner EPD and security header type
    }

    // Message Type
    if (offset >= len) {
        return std::nullopt;
    }
    msg.message_type = data[offset];
    offset++;

    // For 5GSM messages, extract PDU Session ID and PTI
    if (epd == 0x2E) {  // 5GSM
        if (len < offset + 2) {
            return std::nullopt;
        }
        msg.pdu_session_id = data[offset];
        offset++;
        msg.pti = data[offset];
        offset++;
    }

    // Copy remaining payload
    if (offset < len) {
        msg.payload.resize(len - offset);
        std::memcpy(msg.payload.data(), data + offset, len - offset);
    }

    return msg;
}

void Nas5gParser::parse5gmmMessage(Nas5gMessage& msg) {
    // Parse 5GMM-specific fields
    if (msg.payload.empty()) {
        return;
    }

    // Different 5GMM messages have different structures
    // This is a simplified parsing - full implementation would decode all IEs
}

void Nas5gParser::parse5gsmMessage(Nas5gMessage& msg) {
    // Parse 5GSM-specific fields
    if (msg.payload.empty()) {
        return;
    }

    // For PDU Session Establishment Request, extract common fields
    if (msg.message_type == static_cast<uint8_t>(Nas5gMessageType::PDU_SESSION_ESTABLISHMENT_REQUEST)) {
        // Typically contains: PDU session type, SSC mode, etc.
        // Simplified parsing
    }
}

void Nas5gParser::extractIEs(Nas5gMessage& msg) {
    if (msg.payload.empty()) {
        return;
    }

    size_t offset = 0;
    const uint8_t* data = msg.payload.data();
    size_t len = msg.payload.size();

    // Simplified IE extraction
    // In a full implementation, we would properly parse all IEs
    // For now, we'll look for common IE patterns

    // Look for Mobile Identity IE (type 0x77)
    while (offset + 2 < len) {
        uint8_t iei = data[offset];

        if (iei == 0x77) {  // Mobile Identity IE
            offset++;
            uint8_t ie_len = data[offset];
            offset++;

            if (offset + ie_len <= len) {
                auto mobile_id = decodeMobileIdentity(data + offset, ie_len);
                if (mobile_id.has_value()) {
                    msg.supi = mobile_id.value();
                }
            }
            break;
        }

        // Look for 5G-GUTI (type 0x75)
        if (iei == 0x75) {
            offset++;
            uint8_t ie_len = data[offset];
            offset++;

            if (offset + ie_len <= len) {
                auto guti = decode5gGuti(data + offset, ie_len);
                if (guti.has_value()) {
                    msg.five_g_guti = guti.value();
                    msg.supi = guti.value();  // Use GUTI as identifier
                }
            }
            break;
        }

        // Look for DNN (Data Network Name, type 0x25)
        if (iei == 0x25) {
            offset++;
            uint8_t ie_len = data[offset];
            offset++;

            if (offset + ie_len <= len) {
                auto dnn = decodeDnn(data + offset, ie_len);
                if (dnn.has_value()) {
                    msg.dnn = dnn.value();
                }
            }
            offset += ie_len;
            continue;
        }

        // Look for S-NSSAI (type 0x22)
        if (iei == 0x22) {
            offset++;
            uint8_t ie_len = data[offset];
            offset++;

            if (offset + ie_len <= len) {
                auto nssai = decodeSNssai(data + offset, ie_len);
                if (nssai.has_value()) {
                    msg.s_nssai = nssai.value();
                }
            }
            offset += ie_len;
            continue;
        }

        offset++;
    }
}

std::optional<std::string> Nas5gParser::decodeMobileIdentity(const uint8_t* data, size_t len) {
    if (!data || len < 1) {
        return std::nullopt;
    }

    // First byte contains type of identity
    uint8_t id_type = data[0] & 0x07;

    switch (static_cast<Nas5gMobileIdentityType>(id_type)) {
        case Nas5gMobileIdentityType::SUCI:
            return decodeSupci(data, len);
        case Nas5gMobileIdentityType::FIVE_G_GUTI:
            return decode5gGuti(data, len);
        default:
            return std::nullopt;
    }
}

std::optional<std::string> Nas5gParser::decodeSupci(const uint8_t* data, size_t len) {
    if (!data || len < 8) {
        return std::nullopt;
    }

    // SUCI format: SUPI type (IMSI/NAI) + routing indicator + protection scheme + ...
    // Simplified: just convert to hex string
    std::ostringstream oss;
    oss << "SUCI-";
    for (size_t i = 0; i < len && i < 16; ++i) {
        oss << std::hex << std::setfill('0') << std::setw(2)
            << static_cast<int>(data[i]);
    }
    return oss.str();
}

std::optional<std::string> Nas5gParser::decode5gGuti(const uint8_t* data, size_t len) {
    if (!data || len < 11) {
        return std::nullopt;
    }

    // 5G-GUTI: PLMN ID (3 bytes) + AMF ID (3 bytes) + 5G-TMSI (4 bytes)
    std::ostringstream oss;
    oss << "5G-GUTI-";

    // PLMN ID
    for (size_t i = 1; i < 4 && i < len; ++i) {
        oss << std::hex << std::setfill('0') << std::setw(2)
            << static_cast<int>(data[i]);
    }

    oss << "-";

    // 5G-TMSI (last 4 bytes)
    if (len >= 11) {
        for (size_t i = 7; i < 11; ++i) {
            oss << std::hex << std::setfill('0') << std::setw(2)
                << static_cast<int>(data[i]);
        }
    }

    return oss.str();
}

std::optional<std::string> Nas5gParser::decodeDnn(const uint8_t* data, size_t len) {
    if (!data || len == 0) {
        return std::nullopt;
    }

    std::ostringstream oss;

    // DNN is encoded like APN (length-prefixed labels)
    size_t offset = 0;
    bool first = true;

    while (offset < len) {
        uint8_t label_len = data[offset];
        if (label_len == 0) {
            break;
        }

        offset++;
        if (offset + label_len > len) {
            break;
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

std::optional<std::string> Nas5gParser::decodeSNssai(const uint8_t* data, size_t len) {
    if (!data || len < 1) {
        return std::nullopt;
    }

    // S-NSSAI: SST (1 byte) + optional SD (3 bytes)
    std::ostringstream oss;
    oss << "SST-" << std::hex << std::setfill('0') << std::setw(2)
        << static_cast<int>(data[0]);

    if (len >= 4) {
        oss << "-SD-";
        for (size_t i = 1; i < 4; ++i) {
            oss << std::hex << std::setfill('0') << std::setw(2)
                << static_cast<int>(data[i]);
        }
    }

    return oss.str();
}

}  // namespace callflow
