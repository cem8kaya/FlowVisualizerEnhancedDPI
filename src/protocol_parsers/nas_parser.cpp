#include "protocol_parsers/nas_parser.h"

#include <arpa/inet.h>

#include <cstring>
#include <iomanip>
#include <sstream>

#include "common/logger.h"
#include "common/nas_security_context.h"

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
        case EmmMessageType::ATTACH_REQUEST:
            return "Attach-Request";
        case EmmMessageType::ATTACH_ACCEPT:
            return "Attach-Accept";
        case EmmMessageType::ATTACH_COMPLETE:
            return "Attach-Complete";
        case EmmMessageType::ATTACH_REJECT:
            return "Attach-Reject";
        case EmmMessageType::DETACH_REQUEST:
            return "Detach-Request";
        case EmmMessageType::DETACH_ACCEPT:
            return "Detach-Accept";
        case EmmMessageType::TRACKING_AREA_UPDATE_REQUEST:
            return "TAU-Request";
        case EmmMessageType::TRACKING_AREA_UPDATE_ACCEPT:
            return "TAU-Accept";
        case EmmMessageType::TRACKING_AREA_UPDATE_COMPLETE:
            return "TAU-Complete";
        case EmmMessageType::TRACKING_AREA_UPDATE_REJECT:
            return "TAU-Reject";
        case EmmMessageType::EXTENDED_SERVICE_REQUEST:
            return "Extended-Service-Request";
        case EmmMessageType::SERVICE_REQUEST:
            return "Service-Request";
        case EmmMessageType::SERVICE_REJECT:
            return "Service-Reject";
        case EmmMessageType::GUTI_REALLOCATION_COMMAND:
            return "GUTI-Reallocation-Command";
        case EmmMessageType::GUTI_REALLOCATION_COMPLETE:
            return "GUTI-Reallocation-Complete";
        case EmmMessageType::AUTHENTICATION_REQUEST:
            return "Authentication-Request";
        case EmmMessageType::AUTHENTICATION_RESPONSE:
            return "Authentication-Response";
        case EmmMessageType::AUTHENTICATION_REJECT:
            return "Authentication-Reject";
        case EmmMessageType::AUTHENTICATION_FAILURE:
            return "Authentication-Failure";
        case EmmMessageType::IDENTITY_REQUEST:
            return "Identity-Request";
        case EmmMessageType::IDENTITY_RESPONSE:
            return "Identity-Response";
        case EmmMessageType::SECURITY_MODE_COMMAND:
            return "Security-Mode-Command";
        case EmmMessageType::SECURITY_MODE_COMPLETE:
            return "Security-Mode-Complete";
        case EmmMessageType::SECURITY_MODE_REJECT:
            return "Security-Mode-Reject";
        case EmmMessageType::EMM_STATUS:
            return "EMM-Status";
        case EmmMessageType::EMM_INFORMATION:
            return "EMM-Information";
        case EmmMessageType::DOWNLINK_NAS_TRANSPORT:
            return "Downlink-NAS-Transport";
        case EmmMessageType::UPLINK_NAS_TRANSPORT:
            return "Uplink-NAS-Transport";
        case EmmMessageType::CS_SERVICE_NOTIFICATION:
            return "CS-Service-Notification";
        default:
            return "Unknown-EMM-" + std::to_string(static_cast<uint8_t>(type));
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

    if (!ies.empty()) {
        j["ies"] = nlohmann::json::array();
        for (const auto& ie : ies) {
            j["ies"].push_back(ie.toJson());
        }
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

std::optional<LteNasMessage> NasParser::parse(const uint8_t* data, size_t len,
                                              NasSecurityContext* context) {
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

    // If security protected
    if (msg.isProtected()) {
        if (context && offset < len && msg.sequence_number.has_value()) {
            // Handle Decryption
            uint32_t count = msg.sequence_number.value();  // Simplify: use SN as count

            // Extract Payload (MAC+SEQ already skipped)
            std::vector<uint8_t> encrypted_payload(data + offset, data + len);

            // Verify Integrity? Skip for now.

            // Decrypt
            std::vector<uint8_t> decrypted_payload =
                context->decrypt(encrypted_payload, count, NasDirection::UPLINK);  // Assume UL?

            // If valid
            if (!decrypted_payload.empty()) {
                LteNasIe decrypted_ie;
                decrypted_ie.name = "Decrypted Payload";
                decrypted_ie.raw_data = decrypted_payload;
                msg.ies.push_back(decrypted_ie);

                // Parse Inner
                if (isNas(decrypted_payload.data(), decrypted_payload.size())) {
                    auto inner = parse(decrypted_payload.data(), decrypted_payload.size(), nullptr);
                    if (inner.has_value()) {
                        return inner.value();
                    }
                }
            }
        }

        // Return outer message if cannot decrypt
        return msg;
    }

    // Parse plain message
    if (!parsePlainMessage(data + offset, len - offset, msg)) {
        // Even if extraction fails, return what we found
        LOG_DEBUG("Partial parsing of plain NAS message");
    }

    return msg;
}

bool NasParser::parseSecurityHeader(const uint8_t* data, size_t len, LteNasMessage& msg,
                                    size_t& offset) {
    if (len < 1) {
        return false;
    }

    uint8_t byte0 = data[0];
    msg.security_header_type = static_cast<NasSecurityHeaderType>((byte0 >> 4) & 0x0F);
    msg.protocol_discriminator = static_cast<NasProtocolDiscriminator>(byte0 & 0x0F);

    offset = 1;

    // SERVICE_REQUEST is special (short header)
    if (msg.security_header_type == NasSecurityHeaderType::SECURITY_HEADER_FOR_SERVICE_REQUEST) {
        // Service Request (short MAC, no SQN)
        // KSIV (8-5), SN (4-0 of byte 1).
        // Actually, Service Request structure:
        // Byte 0: SecHdr(0xC) + Disc(0x7)
        // Byte 1: KSIV(4) + SeqNum(5) (short)
        // Bytes 2-3: Short MAC
        if (len < 4)
            return false;
        // TODO: Handle Service Request details
        offset = 4;  // Skip short MAC
        return true;
    }

    if (msg.security_header_type != NasSecurityHeaderType::PLAIN_NAS_MESSAGE) {
        if (len < 6) {
            return false;
        }
        uint32_t mac;
        std::memcpy(&mac, data + 1, 4);
        msg.message_authentication_code = ntohl(mac);
        msg.sequence_number = data[5];
        offset = 6;
    }

    return true;
}

bool NasParser::parsePlainMessage(const uint8_t* data, size_t len, LteNasMessage& msg) {
    if (len < 1) {
        return false;
    }

    msg.message_type = data[0];
    size_t offset = 1;

    if (msg.protocol_discriminator == NasProtocolDiscriminator::EPS_MOBILITY_MANAGEMENT) {
        return parseEmmMessage(data, len, offset, msg);
    } else if (msg.protocol_discriminator == NasProtocolDiscriminator::EPS_SESSION_MANAGEMENT) {
        return parseEsmMessage(data, len, offset, msg);
    }

    return false;
}

bool NasParser::parseEmmMessage(const uint8_t* data, size_t len, size_t offset,
                                LteNasMessage& msg) {
    auto msg_type = static_cast<EmmMessageType>(msg.message_type);

    if (msg_type == EmmMessageType::ATTACH_REQUEST) {
        if (offset + 1 < len) {
            offset += 1;  // Skip EPS attach type/NAS key set identifier
            if (offset + 1 < len) {
                uint8_t id_length = data[offset++];
                if (offset + id_length <= len) {
                    // Mobile Identity
                    LteNasIe ie;
                    ie.name = "EPS Mobile Identity";
                    ie.raw_data.assign(data + offset, data + offset + id_length);
                    ie.decoded_value = decodeMobileIdentity(data + offset, id_length).value_or("");
                    msg.ies.push_back(ie);

                    if (ie.decoded_value.find("IMSI") != std::string::npos)
                        msg.imsi = ie.decoded_value;
                    if (ie.decoded_value.find("GUTI") != std::string::npos)
                        msg.guti = ie.decoded_value;

                    offset += id_length;
                }
            }
        }
    }

    // Continue parsing remaining optional IEs
    extractIEs(msg);
    return true;
}

bool NasParser::parseEsmMessage(const uint8_t* data, size_t len, size_t offset,
                                LteNasMessage& msg) {
    extractIEs(msg);
    return true;
}

void NasParser::extractIEs(LteNasMessage& msg) {
    // Basic iterative IE extraction (Placeholder for full recursive logic)
    // Needs to know offset where optional IEs start.
    // Since parseEmmMessage handles mandatory, we need to pass current offset.
    // But extractIEs takes only msg?
    // TODO: Ideally pass buffer and offset.
    // For now, assume IEs are later in raw_data matching remaining bytes?
    // Or just skip for this simplified implementation step.
}

std::optional<std::string> NasParser::extractImsi(const uint8_t* data, size_t len) {
    return decodeMobileIdentity(data, len);
}

std::optional<std::string> NasParser::extractGuti(const uint8_t* data, size_t len) {
    return decodeMobileIdentity(data, len);
}

std::optional<std::string> NasParser::decodeMobileIdentity(const uint8_t* data, size_t len) {
    if (len < 1)
        return std::nullopt;
    uint8_t type = data[0] & 0x07;
    if (type == 1) {  // IMSI
        return "IMSI-" + utils::bcdToString(data, len, 1);
    } else if (type == 6) {  // GUTI
        std::ostringstream oss;
        oss << "GUTI[TMSI:Enc]";  // Simplified
        return oss.str();
    }
    return "Unknown-ID-" + std::to_string(type);
}

std::string NasParser::decodeApn(const uint8_t* data, size_t len) {
    if (!data || len == 0)
        return "";
    std::ostringstream oss;
    size_t offset = 0;
    bool first = true;
    while (offset < len) {
        uint8_t label_len = data[offset];
        if (label_len == 0)
            break;
        offset++;
        if (offset + label_len > len)
            break;
        if (!first)
            oss << '.';
        first = false;
        for (size_t i = 0; i < label_len; ++i)
            oss << (char)data[offset + i];
        offset += label_len;
    }
    return oss.str();
}

}  // namespace callflow
