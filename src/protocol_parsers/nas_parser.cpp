#include "protocol_parsers/nas_parser.h"
#include "common/logger.h"
#include <cstring>
#include <sstream>
#include <iomanip>
#include <arpa/inet.h>

namespace callflow {

// ============================================================================
// Helper Functions for String Conversion
// ============================================================================

std::string nasSecurityHeaderTypeToString(NasSecurityHeaderType type) {
    switch (type) {
        case NasSecurityHeaderType::PLAIN_NAS_MESSAGE:
            return "Plain-NAS-Message";
        case NasSecurityHeaderType::INTEGRITY_PROTECTED:
            return "Integrity-Protected";
        case NasSecurityHeaderType::INTEGRITY_PROTECTED_CIPHERED:
            return "Integrity-Protected-Ciphered";
        case NasSecurityHeaderType::INTEGRITY_PROTECTED_NEW_EPS_CONTEXT:
            return "Integrity-Protected-New-EPS-Context";
        case NasSecurityHeaderType::INTEGRITY_PROTECTED_CIPHERED_NEW_EPS_CONTEXT:
            return "Integrity-Protected-Ciphered-New-EPS-Context";
        case NasSecurityHeaderType::SECURITY_HEADER_FOR_SERVICE_REQUEST:
            return "Security-Header-For-Service-Request";
        default:
            return "Unknown";
    }
}

std::string nasProtocolDiscriminatorToString(NasProtocolDiscriminator pd) {
    switch (pd) {
        case NasProtocolDiscriminator::EPS_SESSION_MANAGEMENT:
            return "EPS-Session-Management";
        case NasProtocolDiscriminator::EPS_MOBILITY_MANAGEMENT:
            return "EPS-Mobility-Management";
        default:
            return "Unknown";
    }
}

std::string emmMessageTypeToString(EmmMessageType type) {
    switch (type) {
        case EmmMessageType::ATTACH_REQUEST: return "Attach-Request";
        case EmmMessageType::ATTACH_ACCEPT: return "Attach-Accept";
        case EmmMessageType::ATTACH_COMPLETE: return "Attach-Complete";
        case EmmMessageType::ATTACH_REJECT: return "Attach-Reject";
        case EmmMessageType::DETACH_REQUEST: return "Detach-Request";
        case EmmMessageType::DETACH_ACCEPT: return "Detach-Accept";
        case EmmMessageType::TRACKING_AREA_UPDATE_REQUEST: return "TAU-Request";
        case EmmMessageType::TRACKING_AREA_UPDATE_ACCEPT: return "TAU-Accept";
        case EmmMessageType::TRACKING_AREA_UPDATE_COMPLETE: return "TAU-Complete";
        case EmmMessageType::TRACKING_AREA_UPDATE_REJECT: return "TAU-Reject";
        case EmmMessageType::EXTENDED_SERVICE_REQUEST: return "Extended-Service-Request";
        case EmmMessageType::SERVICE_REQUEST: return "Service-Request";
        case EmmMessageType::SERVICE_REJECT: return "Service-Reject";
        case EmmMessageType::GUTI_REALLOCATION_COMMAND: return "GUTI-Reallocation-Command";
        case EmmMessageType::GUTI_REALLOCATION_COMPLETE: return "GUTI-Reallocation-Complete";
        case EmmMessageType::AUTHENTICATION_REQUEST: return "Authentication-Request";
        case EmmMessageType::AUTHENTICATION_RESPONSE: return "Authentication-Response";
        case EmmMessageType::AUTHENTICATION_REJECT: return "Authentication-Reject";
        case EmmMessageType::AUTHENTICATION_FAILURE: return "Authentication-Failure";
        case EmmMessageType::IDENTITY_REQUEST: return "Identity-Request";
        case EmmMessageType::IDENTITY_RESPONSE: return "Identity-Response";
        case EmmMessageType::SECURITY_MODE_COMMAND: return "Security-Mode-Command";
        case EmmMessageType::SECURITY_MODE_COMPLETE: return "Security-Mode-Complete";
        case EmmMessageType::SECURITY_MODE_REJECT: return "Security-Mode-Reject";
        case EmmMessageType::EMM_STATUS: return "EMM-Status";
        case EmmMessageType::EMM_INFORMATION: return "EMM-Information";
        case EmmMessageType::DOWNLINK_NAS_TRANSPORT: return "Downlink-NAS-Transport";
        case EmmMessageType::UPLINK_NAS_TRANSPORT: return "Uplink-NAS-Transport";
        case EmmMessageType::CS_SERVICE_NOTIFICATION: return "CS-Service-Notification";
        default: return "Unknown-EMM-" + std::to_string(static_cast<uint8_t>(type));
    }
}

std::string esmMessageTypeToString(EsmMessageType type) {
    switch (type) {
        case EsmMessageType::ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST:
            return "Activate-Default-Bearer-Request";
        case EsmMessageType::ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_ACCEPT:
            return "Activate-Default-Bearer-Accept";
        case EsmMessageType::ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REJECT:
            return "Activate-Default-Bearer-Reject";
        case EsmMessageType::ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_REQUEST:
            return "Activate-Dedicated-Bearer-Request";
        case EsmMessageType::ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_ACCEPT:
            return "Activate-Dedicated-Bearer-Accept";
        case EsmMessageType::ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_REJECT:
            return "Activate-Dedicated-Bearer-Reject";
        case EsmMessageType::MODIFY_EPS_BEARER_CONTEXT_REQUEST:
            return "Modify-Bearer-Request";
        case EsmMessageType::MODIFY_EPS_BEARER_CONTEXT_ACCEPT:
            return "Modify-Bearer-Accept";
        case EsmMessageType::MODIFY_EPS_BEARER_CONTEXT_REJECT:
            return "Modify-Bearer-Reject";
        case EsmMessageType::DEACTIVATE_EPS_BEARER_CONTEXT_REQUEST:
            return "Deactivate-Bearer-Request";
        case EsmMessageType::DEACTIVATE_EPS_BEARER_CONTEXT_ACCEPT:
            return "Deactivate-Bearer-Accept";
        case EsmMessageType::PDN_CONNECTIVITY_REQUEST:
            return "PDN-Connectivity-Request";
        case EsmMessageType::PDN_CONNECTIVITY_REJECT:
            return "PDN-Connectivity-Reject";
        case EsmMessageType::PDN_DISCONNECT_REQUEST:
            return "PDN-Disconnect-Request";
        case EsmMessageType::PDN_DISCONNECT_REJECT:
            return "PDN-Disconnect-Reject";
        case EsmMessageType::BEARER_RESOURCE_ALLOCATION_REQUEST:
            return "Bearer-Resource-Allocation-Request";
        case EsmMessageType::BEARER_RESOURCE_ALLOCATION_REJECT:
            return "Bearer-Resource-Allocation-Reject";
        case EsmMessageType::BEARER_RESOURCE_MODIFICATION_REQUEST:
            return "Bearer-Resource-Modification-Request";
        case EsmMessageType::BEARER_RESOURCE_MODIFICATION_REJECT:
            return "Bearer-Resource-Modification-Reject";
        case EsmMessageType::ESM_INFORMATION_REQUEST:
            return "ESM-Information-Request";
        case EsmMessageType::ESM_INFORMATION_RESPONSE:
            return "ESM-Information-Response";
        case EsmMessageType::ESM_STATUS:
            return "ESM-Status";
        default:
            return "Unknown-ESM-" + std::to_string(static_cast<uint8_t>(type));
    }
}

// ============================================================================
// LteNasMessage Methods
// ============================================================================

std::string LteNasMessage::getMessageTypeName() const {
    if (isEmm()) {
        return emmMessageTypeToString(static_cast<EmmMessageType>(message_type));
    } else if (isEsm()) {
        return esmMessageTypeToString(static_cast<EsmMessageType>(message_type));
    }
    return "Unknown";
}

bool LteNasMessage::isEmm() const {
    return protocol_discriminator == NasProtocolDiscriminator::EPS_MOBILITY_MANAGEMENT;
}

bool LteNasMessage::isEsm() const {
    return protocol_discriminator == NasProtocolDiscriminator::EPS_SESSION_MANAGEMENT;
}

bool LteNasMessage::isProtected() const {
    return security_header_type != NasSecurityHeaderType::PLAIN_NAS_MESSAGE;
}

nlohmann::json LteNasMessage::toJson() const {
    nlohmann::json j;
    j["security_header_type"] = nasSecurityHeaderTypeToString(security_header_type);
    j["protocol_discriminator"] = nasProtocolDiscriminatorToString(protocol_discriminator);
    j["message_type"] = message_type;
    j["message_type_name"] = getMessageTypeName();
    j["is_protected"] = isProtected();

    if (message_authentication_code.has_value()) {
        j["message_authentication_code"] = message_authentication_code.value();
    }
    if (sequence_number.has_value()) {
        j["sequence_number"] = sequence_number.value();
    }
    if (imsi.has_value()) {
        j["imsi"] = imsi.value();
    }
    if (guti.has_value()) {
        j["guti"] = guti.value();
    }
    if (tmsi.has_value()) {
        j["tmsi"] = tmsi.value();
    }
    if (apn.has_value()) {
        j["apn"] = apn.value();
    }
    if (pdn_type.has_value()) {
        j["pdn_type"] = pdn_type.value();
    }
    if (esm_cause.has_value()) {
        j["esm_cause"] = esm_cause.value();
    }

    j["raw_data_length"] = raw_data.size();

    return j;
}

// ============================================================================
// NasParser Methods
// ============================================================================

bool NasParser::isNas(const uint8_t* data, size_t len) {
    if (!data || len < 2) {
        return false;
    }

    // Check security header type (upper 4 bits of first byte)
    uint8_t sec_header = (data[0] >> 4) & 0x0F;
    if (sec_header > 12 && sec_header != 0x0F) {
        return false;
    }

    // Check protocol discriminator (lower 4 bits of first byte or second byte)
    uint8_t pd = data[0] & 0x0F;
    if (pd != 0x02 && pd != 0x07) {
        // Not ESM or EMM
        return false;
    }

    return true;
}

std::optional<LteNasMessage> NasParser::parse(const uint8_t* data, size_t len) {
    if (!isNas(data, len)) {
        LOG_DEBUG("Not a valid NAS message");
        return std::nullopt;
    }

    LteNasMessage msg;
    msg.raw_data.assign(data, data + len);

    size_t offset = 0;

    // Parse security header
    if (!parseSecurityHeader(data, len, msg, offset)) {
        LOG_ERROR("Failed to parse NAS security header");
        return std::nullopt;
    }

    // If security protected, we can't decode the message without keys
    if (msg.isProtected()) {
        LOG_DEBUG("NAS message is security protected - cannot decode without keys");
        return msg;  // Return with security header info only
    }

    // Parse plain message
    if (!parsePlainMessage(data + offset, len - offset, msg)) {
        LOG_ERROR("Failed to parse plain NAS message");
        return std::nullopt;
    }

    LOG_DEBUG("Parsed NAS message: " << msg.getMessageTypeName());

    return msg;
}

bool NasParser::parseSecurityHeader(const uint8_t* data, size_t len,
                                   LteNasMessage& msg, size_t& offset) {
    if (len < 1) {
        return false;
    }

    // Byte 0: Security header type (4 bits) + Protocol discriminator (4 bits)
    uint8_t byte0 = data[0];
    msg.security_header_type = static_cast<NasSecurityHeaderType>((byte0 >> 4) & 0x0F);
    msg.protocol_discriminator = static_cast<NasProtocolDiscriminator>(byte0 & 0x0F);

    offset = 1;

    // If security header type is not plain, extract MAC and sequence number
    if (msg.security_header_type != NasSecurityHeaderType::PLAIN_NAS_MESSAGE &&
        msg.security_header_type != NasSecurityHeaderType::SECURITY_HEADER_FOR_SERVICE_REQUEST) {

        if (len < 6) {
            return false;
        }

        // Bytes 1-4: Message Authentication Code (MAC)
        uint32_t mac;
        std::memcpy(&mac, data + 1, 4);
        msg.message_authentication_code = ntohl(mac);

        // Byte 5: Sequence number
        msg.sequence_number = data[5];

        offset = 6;

        // After security header, there's another PD + message type
        if (offset < len) {
            msg.protocol_discriminator = static_cast<NasProtocolDiscriminator>(data[offset] & 0x0F);
            offset++;
        }
    }

    return true;
}

bool NasParser::parsePlainMessage(const uint8_t* data, size_t len, LteNasMessage& msg) {
    if (len < 1) {
        return false;
    }

    // Byte 0: Message type
    msg.message_type = data[0];

    size_t offset = 1;

    // Parse based on protocol discriminator
    if (msg.protocol_discriminator == NasProtocolDiscriminator::EPS_MOBILITY_MANAGEMENT) {
        return parseEmmMessage(data, len, offset, msg);
    } else if (msg.protocol_discriminator == NasProtocolDiscriminator::EPS_SESSION_MANAGEMENT) {
        return parseEsmMessage(data, len, offset, msg);
    }

    return false;
}

bool NasParser::parseEmmMessage(const uint8_t* data, size_t len,
                               size_t offset, LteNasMessage& msg) {
    // Parse EMM-specific IEs based on message type
    // For now, we do basic IE extraction for common messages

    auto msg_type = static_cast<EmmMessageType>(msg.message_type);

    if (msg_type == EmmMessageType::ATTACH_REQUEST) {
        // Attach Request contains:
        // - EPS attach type (1/2 byte)
        // - NAS key set identifier (1/2 byte)
        // - Old GUTI or IMSI (variable)
        // - UE network capability (variable)
        // - ESM message container (variable)

        if (offset + 1 < len) {
            // Skip EPS attach type and NAS key set identifier
            offset += 1;

            // Next is EPS mobile identity (LV format: Length + Value)
            if (offset + 1 < len) {
                uint8_t id_length = data[offset];
                offset++;

                if (offset + id_length <= len) {
                    // Check identity type (bits 0-2 of first byte)
                    uint8_t id_type = data[offset] & 0x07;

                    if (id_type == 1) {
                        // IMSI
                        msg.imsi = extractImsi(data + offset, id_length);
                    } else if (id_type == 6) {
                        // GUTI
                        msg.guti = extractGuti(data + offset, id_length);
                    }
                }
            }
        }
    } else if (msg_type == EmmMessageType::IDENTITY_RESPONSE) {
        // Identity Response contains Mobile Identity IE
        if (offset + 1 < len) {
            uint8_t id_length = data[offset];
            offset++;

            if (offset + id_length <= len) {
                uint8_t id_type = data[offset] & 0x07;

                if (id_type == 1) {
                    msg.imsi = extractImsi(data + offset, id_length);
                }
            }
        }
    }

    return true;
}

bool NasParser::parseEsmMessage(const uint8_t* data, size_t len,
                               size_t offset, LteNasMessage& msg) {
    // Parse ESM-specific IEs
    auto msg_type = static_cast<EsmMessageType>(msg.message_type);

    if (msg_type == EsmMessageType::PDN_CONNECTIVITY_REQUEST) {
        // PDN Connectivity Request contains:
        // - PDN type (1/2 byte)
        // - Request type (1/2 byte)
        // - Optional IEs (APN, etc.)

        if (offset + 1 < len) {
            uint8_t pdn_and_req = data[offset];
            msg.pdn_type = (pdn_and_req >> 4) & 0x0F;
            offset++;

            // Parse optional IEs
            while (offset < len) {
                uint8_t iei = data[offset];

                if (iei == static_cast<uint8_t>(NasIeType::ACCESS_POINT_NAME)) {
                    offset++;
                    if (offset + 1 < len) {
                        uint8_t apn_length = data[offset];
                        offset++;
                        if (offset + apn_length <= len) {
                            msg.apn = decodeApn(data + offset, apn_length);
                            offset += apn_length;
                        }
                    }
                } else {
                    break;
                }
            }
        }
    } else if (msg_type == EsmMessageType::ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST) {
        // Contains EPS QoS, APN, PDN address, etc.
        // Skip for now - would need full IE parsing
    }

    return true;
}

std::optional<std::string> NasParser::extractImsi(const uint8_t* data, size_t len) {
    if (!data || len < 1) {
        return std::nullopt;
    }

    std::ostringstream oss;

    // First byte contains odd/even indicator and identity type
    // Skip first byte, IMSI digits start from second byte

    // IMSI is BCD encoded in remaining bytes
    for (size_t i = 1; i < len; ++i) {
        uint8_t byte = data[i];

        // Lower nibble
        uint8_t digit1 = byte & 0x0F;
        if (digit1 <= 9) {
            oss << static_cast<char>('0' + digit1);
        } else if (digit1 == 0x0F) {
            break;
        }

        // Upper nibble
        uint8_t digit2 = (byte >> 4) & 0x0F;
        if (digit2 <= 9) {
            oss << static_cast<char>('0' + digit2);
        } else if (digit2 == 0x0F) {
            break;
        }
    }

    std::string imsi = oss.str();
    return imsi.empty() ? std::nullopt : std::make_optional(imsi);
}

std::optional<std::string> NasParser::extractGuti(const uint8_t* data, size_t len) {
    if (!data || len < 11) {
        return std::nullopt;
    }

    // GUTI structure:
    // - Odd/even + type of identity (1 byte)
    // - MCC + MNC (3 bytes)
    // - MME Group ID (2 bytes)
    // - MME Code (1 byte)
    // - M-TMSI (4 bytes)

    std::ostringstream oss;
    oss << "GUTI[";

    // Extract M-TMSI (last 4 bytes)
    uint32_t tmsi;
    std::memcpy(&tmsi, data + len - 4, 4);
    tmsi = ntohl(tmsi);
    oss << "TMSI:" << std::hex << tmsi << "]";

    return oss.str();
}

std::string NasParser::decodeApn(const uint8_t* data, size_t len) {
    if (!data || len == 0) {
        return "";
    }

    std::ostringstream oss;

    // APN is encoded as length-prefixed labels
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

}  // namespace callflow
