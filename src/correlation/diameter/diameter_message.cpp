#include "correlation/diameter/diameter_message.h"
#include "protocol_parsers/diameter/diameter_avp_parser.h"
#include <algorithm>

namespace callflow {
namespace correlation {

DiameterMessage::DiameterMessage(std::shared_ptr<diameter::DiameterMessage> msg)
    : protocol_msg_(msg) {}

// ============================================================================
// Message Identification
// ============================================================================

std::string DiameterMessage::getSessionId() const {
    if (!protocol_msg_) return "";
    return protocol_msg_->session_id.value_or("");
}

uint32_t DiameterMessage::getHopByHopId() const {
    if (!protocol_msg_) return 0;
    return protocol_msg_->header.hop_by_hop_id;
}

uint32_t DiameterMessage::getEndToEndId() const {
    if (!protocol_msg_) return 0;
    return protocol_msg_->header.end_to_end_id;
}

uint32_t DiameterMessage::getCommandCode() const {
    if (!protocol_msg_) return 0;
    return protocol_msg_->header.command_code;
}

uint32_t DiameterMessage::getApplicationId() const {
    if (!protocol_msg_) return 0;
    return protocol_msg_->header.application_id;
}

// ============================================================================
// Message Type
// ============================================================================

bool DiameterMessage::isRequest() const {
    if (!protocol_msg_) return false;
    return protocol_msg_->isRequest();
}

bool DiameterMessage::isAnswer() const {
    if (!protocol_msg_) return false;
    return protocol_msg_->isAnswer();
}

DiameterDirection DiameterMessage::getDirection() const {
    return isRequest() ? DiameterDirection::REQUEST : DiameterDirection::ANSWER;
}

DiameterInterface DiameterMessage::getInterface() const {
    if (!protocol_msg_) return DiameterInterface::UNKNOWN;
    return protocol_msg_->getInterface();
}

std::string DiameterMessage::getCommandName() const {
    if (!protocol_msg_) return "UNKNOWN";
    return protocol_msg_->getCommandName();
}

// ============================================================================
// Result Information
// ============================================================================

std::optional<uint32_t> DiameterMessage::getResultCode() const {
    if (!protocol_msg_) return std::nullopt;
    return protocol_msg_->result_code;
}

std::optional<DiameterResultCode> DiameterMessage::getParsedResultCode() const {
    auto rc = getResultCode();
    if (!rc) return std::nullopt;
    return DiameterResultCode::parse(*rc);
}

bool DiameterMessage::isSuccess() const {
    if (!protocol_msg_) return false;
    return protocol_msg_->isSuccess();
}

bool DiameterMessage::isError() const {
    if (!protocol_msg_) return false;
    return protocol_msg_->isError();
}

// ============================================================================
// Common AVP Access
// ============================================================================

std::optional<std::string> DiameterMessage::getOriginHost() const {
    if (!protocol_msg_) return std::nullopt;
    return protocol_msg_->origin_host;
}

std::optional<std::string> DiameterMessage::getOriginRealm() const {
    if (!protocol_msg_) return std::nullopt;
    return protocol_msg_->origin_realm;
}

std::optional<std::string> DiameterMessage::getDestinationHost() const {
    if (!protocol_msg_) return std::nullopt;
    return protocol_msg_->destination_host;
}

std::optional<std::string> DiameterMessage::getDestinationRealm() const {
    if (!protocol_msg_) return std::nullopt;
    return protocol_msg_->destination_realm;
}

// ============================================================================
// Subscriber Identity Extraction
// ============================================================================

std::optional<std::string> DiameterMessage::extractImsi() const {
    if (!protocol_msg_) return std::nullopt;

    // Try User-Name AVP (often contains IMSI in format "1234567890@realm" or just digits)
    auto user_name_avp = protocol_msg_->findAVP(
        static_cast<uint32_t>(diameter::DiameterAVPCode::USER_NAME));
    if (user_name_avp) {
        std::string user_name = user_name_avp->getDataAsString();
        // Extract digits only (IMSI is 15 digits)
        std::string digits;
        for (char c : user_name) {
            if (std::isdigit(c)) {
                digits += c;
            }
        }
        if (digits.length() == 15) {
            return digits;
        }
    }

    // Try Subscription-Id with type IMSI
    auto imsi_from_sub = extractFromSubscriptionId(SubscriptionIdType::END_USER_IMSI);
    if (imsi_from_sub) {
        return imsi_from_sub;
    }

    // Try 3GPP-IMSI vendor-specific AVP (Vendor-ID 10415, Code 1)
    auto tgpp_imsi_avp = protocol_msg_->findAVP(AVPCode3GPP::TGPP_IMSI, diameter::DIAMETER_VENDOR_3GPP);
    if (tgpp_imsi_avp) {
        return tgpp_imsi_avp->getDataAsString();
    }

    return std::nullopt;
}

std::optional<std::string> DiameterMessage::extractMsisdn() const {
    if (!protocol_msg_) return std::nullopt;

    // Try Subscription-Id with type E.164 (MSISDN)
    auto msisdn_from_sub = extractFromSubscriptionId(SubscriptionIdType::END_USER_E164);
    if (msisdn_from_sub) {
        return msisdn_from_sub;
    }

    // Try 3GPP-MSISDN vendor-specific AVP (Vendor-ID 10415, Code 701)
    auto tgpp_msisdn_avp = protocol_msg_->findAVP(AVPCode3GPP::TGPP_MSISDN, diameter::DIAMETER_VENDOR_3GPP);
    if (tgpp_msisdn_avp) {
        // MSISDN is often stored as TBCD (Telephony Binary Coded Decimal)
        // For simplicity, try to extract as string first
        return tgpp_msisdn_avp->getDataAsString();
    }

    return std::nullopt;
}

std::optional<std::string> DiameterMessage::extractFramedIp() const {
    return extractIpAddressFromAVP(AVPCode3GPP::FRAMED_IP_ADDRESS);
}

std::optional<std::string> DiameterMessage::extractFramedIpv6Prefix() const {
    if (!protocol_msg_) return std::nullopt;

    auto avp = protocol_msg_->findAVP(AVPCode3GPP::FRAMED_IPV6_PREFIX);
    if (avp) {
        return avp->getDataAsString();
    }

    return std::nullopt;
}

std::optional<std::string> DiameterMessage::extractApn() const {
    if (!protocol_msg_) return std::nullopt;

    // Try Called-Station-Id (standard RADIUS AVP)
    auto called_station_avp = protocol_msg_->findAVP(AVPCode3GPP::CALLED_STATION_ID);
    if (called_station_avp) {
        return called_station_avp->getDataAsString();
    }

    // Try Service-Selection (3GPP TS 29.272)
    auto service_selection_avp = protocol_msg_->findAVP(
        static_cast<uint32_t>(diameter::DiameterAVPCode::SERVICE_SELECTION));
    if (service_selection_avp) {
        return service_selection_avp->getDataAsString();
    }

    return std::nullopt;
}

std::optional<std::string> DiameterMessage::extractPublicIdentity() const {
    if (!protocol_msg_) return std::nullopt;

    auto avp = protocol_msg_->findAVP(AVPCode3GPP::PUBLIC_IDENTITY, diameter::DIAMETER_VENDOR_3GPP);
    if (avp) {
        return avp->getDataAsString();
    }

    return std::nullopt;
}

// ============================================================================
// Gx-Specific Extraction
// ============================================================================

std::optional<DiameterCCRequestType> DiameterMessage::extractCCRequestType() const {
    if (!protocol_msg_) return std::nullopt;

    auto avp = protocol_msg_->findAVP(
        static_cast<uint32_t>(diameter::DiameterAVPCode::CC_REQUEST_TYPE));
    if (avp) {
        auto type_val = avp->getDataAsUint32();
        if (type_val) {
            return static_cast<DiameterCCRequestType>(*type_val);
        }
    }

    return std::nullopt;
}

std::optional<uint32_t> DiameterMessage::extractCCRequestNumber() const {
    if (!protocol_msg_) return std::nullopt;

    auto avp = protocol_msg_->findAVP(
        static_cast<uint32_t>(diameter::DiameterAVPCode::CC_REQUEST_NUMBER));
    if (avp) {
        return avp->getDataAsUint32();
    }

    return std::nullopt;
}

std::optional<uint8_t> DiameterMessage::extractQci() const {
    if (!protocol_msg_) return std::nullopt;

    // QCI can be in QoS-Information grouped AVP or directly
    auto qci_avp = protocol_msg_->findAVP(AVPCode3GPP::QOS_CLASS_IDENTIFIER, diameter::DIAMETER_VENDOR_3GPP);
    if (qci_avp) {
        auto qci_val = qci_avp->getDataAsUint32();
        if (qci_val && *qci_val <= 255) {
            return static_cast<uint8_t>(*qci_val);
        }
    }

    return std::nullopt;
}

std::vector<std::string> DiameterMessage::extractChargingRuleNames() const {
    std::vector<std::string> rules;
    if (!protocol_msg_) return rules;

    // Find all Charging-Rule-Name AVPs
    auto rule_avps = protocol_msg_->findAllAVPs(AVPCode3GPP::CHARGING_RULE_NAME,
                                                  diameter::DIAMETER_VENDOR_3GPP);
    for (const auto& avp : rule_avps) {
        if (avp) {
            std::string rule_name = avp->getDataAsString();
            if (!rule_name.empty()) {
                rules.push_back(rule_name);
            }
        }
    }

    return rules;
}

std::optional<uint32_t> DiameterMessage::extractBearerIdentifier() const {
    if (!protocol_msg_) return std::nullopt;

    auto avp = protocol_msg_->findAVP(AVPCode3GPP::BEARER_IDENTIFIER, diameter::DIAMETER_VENDOR_3GPP);
    if (avp) {
        return avp->getDataAsUint32();
    }

    return std::nullopt;
}

// ============================================================================
// Rx-Specific Extraction
// ============================================================================

std::optional<std::string> DiameterMessage::extractAfApplicationId() const {
    if (!protocol_msg_) return std::nullopt;

    auto avp = protocol_msg_->findAVP(AVPCode3GPP::AF_APPLICATION_IDENTIFIER, diameter::DIAMETER_VENDOR_3GPP);
    if (avp) {
        return avp->getDataAsString();
    }

    return std::nullopt;
}

std::optional<uint32_t> DiameterMessage::extractMediaType() const {
    if (!protocol_msg_) return std::nullopt;

    auto avp = protocol_msg_->findAVP(AVPCode3GPP::MEDIA_TYPE, diameter::DIAMETER_VENDOR_3GPP);
    if (avp) {
        return avp->getDataAsUint32();
    }

    return std::nullopt;
}

// ============================================================================
// S6a-Specific Extraction
// ============================================================================

std::optional<std::string> DiameterMessage::extractVisitedPlmnId() const {
    if (!protocol_msg_) return std::nullopt;

    auto avp = protocol_msg_->findAVP(AVPCode3GPP::VISITED_PLMN_ID, diameter::DIAMETER_VENDOR_3GPP);
    if (avp) {
        // PLMN ID is 3 bytes (MCC + MNC in TBCD format)
        // For now, return as hex string
        const auto& data = avp->data;
        if (data.size() >= 3) {
            char buf[7];
            snprintf(buf, sizeof(buf), "%02X%02X%02X", data[0], data[1], data[2]);
            return std::string(buf);
        }
    }

    return std::nullopt;
}

std::optional<RatType> DiameterMessage::extractRatType() const {
    if (!protocol_msg_) return std::nullopt;

    // Try standard RAT-Type AVP
    auto avp = protocol_msg_->findAVP(
        static_cast<uint32_t>(diameter::DiameterAVPCode::RAT_TYPE));
    if (avp) {
        auto rat_val = avp->getDataAsUint32();
        if (rat_val) {
            return static_cast<RatType>(*rat_val);
        }
    }

    // Try 3GPP-RAT-Type vendor-specific AVP
    auto tgpp_avp = protocol_msg_->findAVP(AVPCode3GPP::TGPP_RAT_TYPE, diameter::DIAMETER_VENDOR_3GPP);
    if (tgpp_avp) {
        auto rat_val = tgpp_avp->getDataAsUint32();
        if (rat_val) {
            return static_cast<RatType>(*rat_val);
        }
    }

    return std::nullopt;
}

// ============================================================================
// AVP Access
// ============================================================================

std::shared_ptr<diameter::DiameterAVP> DiameterMessage::findAVP(uint32_t code) const {
    if (!protocol_msg_) return nullptr;
    return protocol_msg_->findAVP(code);
}

std::shared_ptr<diameter::DiameterAVP> DiameterMessage::findAVP(uint32_t code, uint32_t vendor_id) const {
    if (!protocol_msg_) return nullptr;
    return protocol_msg_->findAVP(code, vendor_id);
}

std::vector<std::shared_ptr<diameter::DiameterAVP>> DiameterMessage::findAllAVPs(uint32_t code) const {
    if (!protocol_msg_) return {};
    return protocol_msg_->findAllAVPs(code);
}

// ============================================================================
// Helper Methods
// ============================================================================

std::optional<std::string> DiameterMessage::extractFromSubscriptionId(SubscriptionIdType type) const {
    if (!protocol_msg_) return std::nullopt;

    // Find Subscription-Id grouped AVP
    auto sub_id_avps = protocol_msg_->findAllAVPs(AVPCode3GPP::SUBSCRIPTION_ID);

    for (const auto& sub_id_avp : sub_id_avps) {
        if (!sub_id_avp) continue;

        // Get grouped AVPs
        auto grouped = sub_id_avp->getGroupedAVPs();
        if (!grouped) continue;

        // Find Subscription-Id-Type and Subscription-Id-Data
        std::optional<uint32_t> sub_type;
        std::optional<std::string> sub_data;

        for (const auto& inner_avp : *grouped) {
            if (inner_avp->code == AVPCode3GPP::SUBSCRIPTION_ID_TYPE) {
                sub_type = inner_avp->getDataAsUint32();
            } else if (inner_avp->code == AVPCode3GPP::SUBSCRIPTION_ID_DATA) {
                sub_data = inner_avp->getDataAsString();
            }
        }

        // Check if this matches the requested type
        if (sub_type && *sub_type == static_cast<uint32_t>(type) && sub_data) {
            return sub_data;
        }
    }

    return std::nullopt;
}

std::optional<std::string> DiameterMessage::extractIpAddressFromAVP(uint32_t code) const {
    if (!protocol_msg_) return std::nullopt;

    auto avp = protocol_msg_->findAVP(code);
    if (!avp) return std::nullopt;

    // Try to parse as IP address
    auto ip_str = diameter::DiameterAVPParser::parseIPAddress(avp->data);
    return ip_str;
}

} // namespace correlation
} // namespace callflow
