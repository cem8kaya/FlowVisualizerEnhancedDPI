#include "correlation/nas/nas_message.h"
#include "correlation/nas/nas_ie_parser.h"
#include <sstream>

namespace callflow {
namespace correlation {

std::string NasMessage::TrackingAreaIdentity::toString() const {
    return mcc + mnc + "-" + std::to_string(tac);
}

bool NasMessage::isIntegrityProtected() const {
    return security_header_type_ != NasSecurityHeaderType::PLAIN_NAS &&
           security_header_type_ != NasSecurityHeaderType::SECURITY_HEADER_FOR_SERVICE_REQUEST;
}

bool NasMessage::isCiphered() const {
    return security_header_type_ == NasSecurityHeaderType::INTEGRITY_PROTECTED_CIPHERED ||
           security_header_type_ == NasSecurityHeaderType::INTEGRITY_PROTECTED_CIPHERED_NEW_EPS_SECURITY_CONTEXT;
}

NasMessage::Direction NasMessage::getDirection() const {
    if (emm_message_type_.has_value()) {
        // Check if it's an uplink or downlink message based on type
        switch (*emm_message_type_) {
            case NasEmmMessageType::ATTACH_REQUEST:
            case NasEmmMessageType::ATTACH_COMPLETE:
            case NasEmmMessageType::DETACH_REQUEST:
            case NasEmmMessageType::TAU_REQUEST:
            case NasEmmMessageType::TAU_COMPLETE:
            case NasEmmMessageType::SERVICE_REQUEST:
            case NasEmmMessageType::EXTENDED_SERVICE_REQUEST:
            case NasEmmMessageType::AUTH_RESPONSE:
            case NasEmmMessageType::AUTH_FAILURE:
            case NasEmmMessageType::IDENTITY_RESPONSE:
            case NasEmmMessageType::SECURITY_MODE_COMPLETE:
            case NasEmmMessageType::SECURITY_MODE_REJECT:
            case NasEmmMessageType::GUTI_REALLOC_COMPLETE:
            case NasEmmMessageType::UPLINK_NAS_TRANSPORT:
                return Direction::UPLINK;

            case NasEmmMessageType::ATTACH_ACCEPT:
            case NasEmmMessageType::ATTACH_REJECT:
            case NasEmmMessageType::DETACH_ACCEPT:
            case NasEmmMessageType::TAU_ACCEPT:
            case NasEmmMessageType::TAU_REJECT:
            case NasEmmMessageType::SERVICE_REJECT:
            case NasEmmMessageType::AUTH_REQUEST:
            case NasEmmMessageType::AUTH_REJECT:
            case NasEmmMessageType::IDENTITY_REQUEST:
            case NasEmmMessageType::SECURITY_MODE_COMMAND:
            case NasEmmMessageType::GUTI_REALLOC_COMMAND:
            case NasEmmMessageType::EMM_INFORMATION:
            case NasEmmMessageType::DOWNLINK_NAS_TRANSPORT:
                return Direction::DOWNLINK;

            default:
                break;
        }
    }

    if (esm_message_type_.has_value()) {
        switch (*esm_message_type_) {
            case NasEsmMessageType::PDN_CONNECTIVITY_REQUEST:
            case NasEsmMessageType::PDN_DISCONNECT_REQUEST:
            case NasEsmMessageType::ACTIVATE_DEFAULT_BEARER_ACC:
            case NasEsmMessageType::ACTIVATE_DEFAULT_BEARER_REJ:
            case NasEsmMessageType::ACTIVATE_DEDICATED_BEARER_ACC:
            case NasEsmMessageType::ACTIVATE_DEDICATED_BEARER_REJ:
            case NasEsmMessageType::MODIFY_BEARER_ACC:
            case NasEsmMessageType::MODIFY_BEARER_REJ:
            case NasEsmMessageType::DEACTIVATE_BEARER_ACC:
            case NasEsmMessageType::ESM_INFO_RESPONSE:
                return Direction::UPLINK;

            case NasEsmMessageType::ACTIVATE_DEFAULT_BEARER_REQ:
            case NasEsmMessageType::ACTIVATE_DEDICATED_BEARER_REQ:
            case NasEsmMessageType::MODIFY_BEARER_REQ:
            case NasEsmMessageType::DEACTIVATE_BEARER_REQ:
            case NasEsmMessageType::PDN_CONNECTIVITY_REJECT:
            case NasEsmMessageType::PDN_DISCONNECT_REJECT:
            case NasEsmMessageType::ESM_INFO_REQUEST:
                return Direction::DOWNLINK;

            default:
                break;
        }
    }

    return Direction::UNKNOWN;
}

std::optional<NasMessage> NasMessage::parse(const uint8_t* data,
                                             size_t length,
                                             uint32_t frame_num,
                                             double timestamp) {
    if (!data || length < 2) {
        return std::nullopt;
    }

    NasMessage msg;
    msg.frame_num_ = frame_num;
    msg.timestamp_ = timestamp;
    msg.setRawData(data, length);

    size_t offset = 0;

    // Parse security header type and protocol discriminator (octet 1)
    uint8_t octet1 = data[offset++];
    msg.security_header_type_ = static_cast<NasSecurityHeaderType>((octet1 >> 4) & 0x0F);
    msg.protocol_discriminator_ = static_cast<NasProtocolDiscriminator>(octet1 & 0x0F);

    // If security header present, skip security-related fields
    if (msg.security_header_type_ != NasSecurityHeaderType::PLAIN_NAS) {
        // Skip MAC (4 bytes) and Sequence Number (1 byte)
        if (length < offset + 5) {
            return std::nullopt;
        }
        offset += 5;

        // Next octet is plain NAS message security header + PD
        if (offset >= length) {
            return std::nullopt;
        }
        octet1 = data[offset++];
        msg.protocol_discriminator_ = static_cast<NasProtocolDiscriminator>(octet1 & 0x0F);
    }

    // Parse message type based on protocol discriminator
    if (msg.protocol_discriminator_ == NasProtocolDiscriminator::EPS_MOBILITY_MANAGEMENT) {
        if (offset >= length) {
            return std::nullopt;
        }
        msg.emm_message_type_ = static_cast<NasEmmMessageType>(data[offset++]);
    } else if (msg.protocol_discriminator_ == NasProtocolDiscriminator::EPS_SESSION_MANAGEMENT) {
        // ESM: next is EPS Bearer Identity + PTI
        if (offset >= length) {
            return std::nullopt;
        }
        msg.eps_bearer_id_ = data[offset] & 0x0F;
        msg.pti_ = data[offset + 1];
        offset += 2;

        if (offset >= length) {
            return std::nullopt;
        }
        msg.esm_message_type_ = static_cast<NasEsmMessageType>(data[offset++]);
    }

    // Parse IEs from remaining data
    if (offset < length) {
        NasIEParser::parseAllIEs(msg, data + offset, length - offset);
    }

    return msg;
}

std::string NasMessage::toString() const {
    std::ostringstream oss;

    if (emm_message_type_) {
        oss << getEmmMessageTypeName(*emm_message_type_);
    } else if (esm_message_type_) {
        oss << getEsmMessageTypeName(*esm_message_type_);
    } else {
        oss << "Unknown NAS Message";
    }

    oss << " [Frame=" << frame_num_ << ", Time=" << timestamp_ << "]";

    return oss.str();
}

} // namespace correlation
} // namespace callflow
