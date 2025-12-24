#include "correlation/gtpv2/gtpv2_types.h"
#include "protocol_parsers/gtp/gtpv2_types.h"
#include <algorithm>

namespace callflow {
namespace correlation {

std::string getMessageTypeName(GtpV2MessageType type) {
    return gtp::getMessageTypeName(type);
}

bool isRequest(GtpV2MessageType type) {
    // Most GTPv2 messages follow pattern: even = request, odd = response
    // But let's be explicit for important ones
    switch (type) {
        case GtpV2MessageType::ECHO_REQUEST:
        case GtpV2MessageType::CREATE_SESSION_REQUEST:
        case GtpV2MessageType::MODIFY_BEARER_REQUEST:
        case GtpV2MessageType::DELETE_SESSION_REQUEST:
        case GtpV2MessageType::CREATE_BEARER_REQUEST:
        case GtpV2MessageType::UPDATE_BEARER_REQUEST:
        case GtpV2MessageType::DELETE_BEARER_REQUEST:
        case GtpV2MessageType::MODIFY_ACCESS_BEARERS_REQUEST:
        case GtpV2MessageType::RELEASE_ACCESS_BEARERS_REQUEST:
        case GtpV2MessageType::DOWNLINK_DATA_NOTIFICATION:
        case GtpV2MessageType::CONTEXT_REQUEST:
        case GtpV2MessageType::FORWARD_RELOCATION_REQUEST:
            return true;
        default:
            return false;
    }
}

bool isResponse(GtpV2MessageType type) {
    switch (type) {
        case GtpV2MessageType::ECHO_RESPONSE:
        case GtpV2MessageType::CREATE_SESSION_RESPONSE:
        case GtpV2MessageType::MODIFY_BEARER_RESPONSE:
        case GtpV2MessageType::DELETE_SESSION_RESPONSE:
        case GtpV2MessageType::CREATE_BEARER_RESPONSE:
        case GtpV2MessageType::UPDATE_BEARER_RESPONSE:
        case GtpV2MessageType::DELETE_BEARER_RESPONSE:
        case GtpV2MessageType::MODIFY_ACCESS_BEARERS_RESPONSE:
        case GtpV2MessageType::RELEASE_ACCESS_BEARERS_RESPONSE:
        case GtpV2MessageType::DOWNLINK_DATA_NOTIFICATION_ACKNOWLEDGE:
        case GtpV2MessageType::DOWNLINK_DATA_NOTIFICATION_FAILURE_INDICATION:
        case GtpV2MessageType::CONTEXT_RESPONSE:
        case GtpV2MessageType::FORWARD_RELOCATION_RESPONSE:
            return true;
        default:
            return false;
    }
}

Gtpv2Direction getDirection(GtpV2MessageType type) {
    return isRequest(type) ? Gtpv2Direction::REQUEST : Gtpv2Direction::RESPONSE;
}

PdnClass classifyPdnFromApn(const std::string& apn) {
    std::string apn_lower = apn;
    std::transform(apn_lower.begin(), apn_lower.end(), apn_lower.begin(), ::tolower);

    if (apn_lower.find("ims") != std::string::npos) {
        return PdnClass::IMS;
    } else if (apn_lower.find("emergency") != std::string::npos ||
               apn_lower.find("sos") != std::string::npos) {
        return PdnClass::EMERGENCY;
    } else if (apn_lower.find("mms") != std::string::npos) {
        return PdnClass::MMS;
    } else if (apn_lower.find("internet") != std::string::npos ||
               apn_lower.find("default") != std::string::npos) {
        return PdnClass::INTERNET;
    }

    return PdnClass::OTHER;
}

bool isSuccessCause(CauseValue cause) {
    return cause == CauseValue::REQUEST_ACCEPTED ||
           cause == CauseValue::REQUEST_ACCEPTED_PARTIALLY ||
           cause == CauseValue::NEW_PDN_TYPE_DUE_TO_NETWORK_PREFERENCE ||
           cause == CauseValue::NEW_PDN_TYPE_DUE_TO_SINGLE_ADDRESS_BEARER_ONLY;
}

bool isSessionEstablishment(GtpV2MessageType type) {
    return type == GtpV2MessageType::CREATE_SESSION_REQUEST ||
           type == GtpV2MessageType::CREATE_SESSION_RESPONSE;
}

bool isSessionTermination(GtpV2MessageType type) {
    return type == GtpV2MessageType::DELETE_SESSION_REQUEST ||
           type == GtpV2MessageType::DELETE_SESSION_RESPONSE;
}

bool isBearerCreation(GtpV2MessageType type) {
    return type == GtpV2MessageType::CREATE_BEARER_REQUEST ||
           type == GtpV2MessageType::CREATE_BEARER_RESPONSE;
}

bool isBearerModification(GtpV2MessageType type) {
    return type == GtpV2MessageType::MODIFY_BEARER_REQUEST ||
           type == GtpV2MessageType::MODIFY_BEARER_RESPONSE ||
           type == GtpV2MessageType::UPDATE_BEARER_REQUEST ||
           type == GtpV2MessageType::UPDATE_BEARER_RESPONSE ||
           type == GtpV2MessageType::MODIFY_ACCESS_BEARERS_REQUEST ||
           type == GtpV2MessageType::MODIFY_ACCESS_BEARERS_RESPONSE;
}

bool isBearerDeletion(GtpV2MessageType type) {
    return type == GtpV2MessageType::DELETE_BEARER_REQUEST ||
           type == GtpV2MessageType::DELETE_BEARER_RESPONSE;
}

std::string getFteidInterfaceName(FTEIDInterfaceType type) {
    switch (type) {
        case FTEIDInterfaceType::S1_U_ENODEB_GTP_U: return "S1-U eNodeB";
        case FTEIDInterfaceType::S1_U_SGW_GTP_U: return "S1-U SGW";
        case FTEIDInterfaceType::S12_RNC_GTP_U: return "S12 RNC";
        case FTEIDInterfaceType::S12_SGW_GTP_U: return "S12 SGW";
        case FTEIDInterfaceType::S5_S8_SGW_GTP_U: return "S5/S8 SGW";
        case FTEIDInterfaceType::S5_S8_PGW_GTP_U: return "S5/S8 PGW";
        case FTEIDInterfaceType::S5_S8_SGW_GTP_C: return "S5/S8 SGW GTP-C";
        case FTEIDInterfaceType::S5_S8_PGW_GTP_C: return "S5/S8 PGW GTP-C";
        case FTEIDInterfaceType::S11_MME_GTP_C: return "S11 MME";
        case FTEIDInterfaceType::S11_S4_SGW_GTP_C: return "S11/S4 SGW";
        case FTEIDInterfaceType::S2B_EPDG_GTP_C: return "S2b ePDG";
        case FTEIDInterfaceType::S2B_U_EPDG_GTP_U: return "S2b-U ePDG";
        case FTEIDInterfaceType::S2B_PGW_GTP_C: return "S2b PGW";
        case FTEIDInterfaceType::S2B_U_PGW_GTP_U: return "S2b-U PGW";
        default: return "Unknown";
    }
}

std::string getRatTypeName(RATType rat) {
    return gtp::getRATTypeName(rat);
}

std::string getPdnTypeName(PDNType pdn) {
    return gtp::getPDNTypeName(pdn);
}

std::string getPdnClassName(PdnClass pdn_class) {
    switch (pdn_class) {
        case PdnClass::IMS: return "IMS";
        case PdnClass::INTERNET: return "Internet";
        case PdnClass::EMERGENCY: return "Emergency";
        case PdnClass::MMS: return "MMS";
        case PdnClass::OTHER: return "Other";
        default: return "Unknown";
    }
}

std::string getCauseValueName(CauseValue cause) {
    switch (cause) {
        case CauseValue::REQUEST_ACCEPTED: return "Request accepted";
        case CauseValue::REQUEST_ACCEPTED_PARTIALLY: return "Request accepted partially";
        case CauseValue::NEW_PDN_TYPE_DUE_TO_NETWORK_PREFERENCE: return "New PDN type due to network preference";
        case CauseValue::NEW_PDN_TYPE_DUE_TO_SINGLE_ADDRESS_BEARER_ONLY: return "New PDN type due to single address bearer only";
        case CauseValue::CONTEXT_NOT_FOUND: return "Context not found";
        case CauseValue::INVALID_MESSAGE_FORMAT: return "Invalid message format";
        case CauseValue::SYSTEM_FAILURE: return "System failure";
        case CauseValue::NO_RESOURCES_AVAILABLE: return "No resources available";
        case CauseValue::MISSING_OR_UNKNOWN_APN: return "Missing or unknown APN";
        case CauseValue::USER_AUTHENTICATION_FAILED: return "User authentication failed";
        case CauseValue::APN_ACCESS_DENIED_NO_SUBSCRIPTION: return "APN access denied - no subscription";
        default: return "Unknown cause";
    }
}

} // namespace correlation
} // namespace callflow
