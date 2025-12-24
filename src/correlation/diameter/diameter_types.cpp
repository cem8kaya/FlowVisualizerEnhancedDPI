#include "correlation/diameter/diameter_types.h"
#include <unordered_map>

namespace callflow {
namespace correlation {

// ============================================================================
// DiameterResultCode
// ============================================================================

DiameterResultCode DiameterResultCode::parse(uint32_t result_code) {
    DiameterResultCode rc;
    rc.code = result_code;
    rc.is_success = (result_code >= 2000 && result_code < 3000);
    rc.is_protocol_error = (result_code >= 3000 && result_code < 4000);
    rc.is_transient = (result_code >= 4000 && result_code < 5000);
    rc.is_permanent = (result_code >= 5000 && result_code < 6000);

    // Map standard result codes
    static const std::unordered_map<uint32_t, std::string> descriptions = {
        {2001, "DIAMETER_SUCCESS"},
        {2002, "DIAMETER_LIMITED_SUCCESS"},
        {3001, "DIAMETER_COMMAND_UNSUPPORTED"},
        {3002, "DIAMETER_UNABLE_TO_DELIVER"},
        {3003, "DIAMETER_REALM_NOT_SERVED"},
        {3004, "DIAMETER_TOO_BUSY"},
        {3005, "DIAMETER_LOOP_DETECTED"},
        {3006, "DIAMETER_REDIRECT_INDICATION"},
        {3007, "DIAMETER_APPLICATION_UNSUPPORTED"},
        {3008, "DIAMETER_INVALID_HDR_BITS"},
        {3009, "DIAMETER_INVALID_AVP_BITS"},
        {3010, "DIAMETER_UNKNOWN_PEER"},
        {4001, "DIAMETER_AUTHENTICATION_REJECTED"},
        {4002, "DIAMETER_OUT_OF_SPACE"},
        {4003, "DIAMETER_ELECTION_LOST"},
        {5001, "DIAMETER_AVP_UNSUPPORTED"},
        {5002, "DIAMETER_UNKNOWN_SESSION_ID"},
        {5003, "DIAMETER_AUTHORIZATION_REJECTED"},
        {5004, "DIAMETER_INVALID_AVP_VALUE"},
        {5005, "DIAMETER_MISSING_AVP"},
        {5006, "DIAMETER_RESOURCES_EXCEEDED"},
        {5007, "DIAMETER_CONTRADICTING_AVPS"},
        {5008, "DIAMETER_AVP_NOT_ALLOWED"},
        {5009, "DIAMETER_AVP_OCCURS_TOO_MANY_TIMES"},
        {5010, "DIAMETER_NO_COMMON_APPLICATION"},
        {5011, "DIAMETER_UNSUPPORTED_VERSION"},
        {5012, "DIAMETER_UNABLE_TO_COMPLY"},
        {5013, "DIAMETER_INVALID_BIT_IN_HEADER"},
        {5014, "DIAMETER_INVALID_AVP_LENGTH"},
        {5015, "DIAMETER_INVALID_MESSAGE_LENGTH"},
        {5016, "DIAMETER_INVALID_AVP_BIT_COMBO"},
        {5017, "DIAMETER_NO_COMMON_SECURITY"}
    };

    auto it = descriptions.find(result_code);
    if (it != descriptions.end()) {
        rc.description = it->second;
    } else {
        rc.description = "UNKNOWN_RESULT_CODE_" + std::to_string(result_code);
    }

    return rc;
}

DiameterResultCode DiameterResultCode::parseExperimental(uint32_t vendor_id,
                                                          uint32_t result_code) {
    DiameterResultCode rc = parse(result_code);

    // Add 3GPP-specific experimental result codes (Vendor-ID 10415)
    if (vendor_id == 10415) {
        static const std::unordered_map<uint32_t, std::string> tgpp_codes = {
            {2001, "DIAMETER_FIRST_REGISTRATION"},
            {2002, "DIAMETER_SUBSEQUENT_REGISTRATION"},
            {2003, "DIAMETER_UNREGISTERED_SERVICE"},
            {2004, "DIAMETER_SUCCESS_SERVER_NAME_NOT_STORED"},
            {4100, "DIAMETER_USER_DATA_NOT_AVAILABLE"},
            {4101, "DIAMETER_PRIOR_UPDATE_IN_PROGRESS"},
            {5001, "DIAMETER_ERROR_USER_UNKNOWN"},
            {5002, "DIAMETER_ERROR_IDENTITIES_DONT_MATCH"},
            {5003, "DIAMETER_ERROR_IDENTITY_NOT_REGISTERED"},
            {5004, "DIAMETER_ERROR_ROAMING_NOT_ALLOWED"},
            {5005, "DIAMETER_ERROR_IDENTITY_ALREADY_REGISTERED"},
            {5006, "DIAMETER_ERROR_AUTH_SCHEME_NOT_SUPPORTED"},
            {5007, "DIAMETER_ERROR_IN_ASSIGNMENT_TYPE"},
            {5008, "DIAMETER_ERROR_TOO_MUCH_DATA"},
            {5009, "DIAMETER_ERROR_NOT_SUPPORTED_USER_DATA"},
            {5011, "DIAMETER_ERROR_FEATURE_UNSUPPORTED"},
            {5012, "DIAMETER_ERROR_SERVING_NODE_FEATURE_UNSUPPORTED"},
            {5401, "DIAMETER_ERROR_USER_NO_NON_3GPP_SUBSCRIPTION"},
            {5402, "DIAMETER_ERROR_USER_NO_APN_SUBSCRIPTION"},
            {5403, "DIAMETER_ERROR_RAT_NOT_ALLOWED"},
            {5420, "DIAMETER_ERROR_UNKNOWN_EPS_SUBSCRIPTION"},
            {5421, "DIAMETER_ERROR_RAT_TYPE_NOT_ALLOWED"},
            {5450, "DIAMETER_ERROR_EQUIPMENT_UNKNOWN"}
        };

        auto it = tgpp_codes.find(result_code);
        if (it != tgpp_codes.end()) {
            rc.description = "3GPP_" + it->second;
        }
    }

    return rc;
}

// ============================================================================
// Helper Functions
// ============================================================================

DiameterInterface getInterfaceFromAppId(uint32_t application_id) {
    return diameter::getInterfaceFromApplicationID(application_id);
}

std::string interfaceToString(DiameterInterface iface) {
    return diameter::getInterfaceName(iface);
}

std::string getCommandDescription(uint32_t command_code) {
    return diameter::getCommandCodeName(command_code);
}

std::string getCCRequestTypeName(DiameterCCRequestType type) {
    switch (type) {
        case DiameterCCRequestType::INITIAL:     return "INITIAL_REQUEST";
        case DiameterCCRequestType::UPDATE:      return "UPDATE_REQUEST";
        case DiameterCCRequestType::TERMINATION: return "TERMINATION_REQUEST";
        case DiameterCCRequestType::EVENT:       return "EVENT_REQUEST";
        default:                                 return "UNKNOWN";
    }
}

std::string getRatTypeName(RatType rat) {
    switch (rat) {
        case RatType::WLAN:           return "WLAN";
        case RatType::VIRTUAL:        return "VIRTUAL";
        case RatType::UTRAN:          return "UTRAN (3G)";
        case RatType::GERAN:          return "GERAN (2G)";
        case RatType::GAN:            return "GAN";
        case RatType::HSPA_EVOLUTION: return "HSPA_EVOLUTION";
        case RatType::EUTRAN:         return "E-UTRAN (4G LTE)";
        case RatType::CDMA2000_1X:    return "CDMA2000_1X";
        case RatType::HRPD:           return "HRPD";
        case RatType::UMB:            return "UMB";
        case RatType::EHRPD:          return "eHRPD";
        case RatType::NR:             return "NR (5G)";
        default:                      return "UNKNOWN";
    }
}

bool isSessionEstablishment(uint32_t command_code, DiameterInterface iface) {
    // Check if this is a session establishment message
    switch (iface) {
        case DiameterInterface::GX:
        case DiameterInterface::GY:
        case DiameterInterface::RO:
            // For Gx/Gy: CCR with type INITIAL
            return (command_code == static_cast<uint32_t>(DiameterCommandCode::CREDIT_CONTROL));
        case DiameterInterface::S6A:
            // Update-Location-Request or Authentication-Information-Request
            return (command_code == static_cast<uint32_t>(DiameterCommandCode::UPDATE_LOCATION) ||
                    command_code == static_cast<uint32_t>(DiameterCommandCode::AUTHENTICATION_INFORMATION));
        case DiameterInterface::RX:
            // AA-Request
            return (command_code == static_cast<uint32_t>(DiameterCommandCode::AA_REQUEST));
        case DiameterInterface::CX:
            // User-Authorization-Request or Server-Assignment-Request
            return (command_code == static_cast<uint32_t>(DiameterCommandCode::USER_AUTHORIZATION) ||
                    command_code == static_cast<uint32_t>(DiameterCommandCode::SERVER_ASSIGNMENT));
        case DiameterInterface::SH:
            // User-Data-Request
            return (command_code == static_cast<uint32_t>(DiameterCommandCode::USER_DATA));
        default:
            return false;
    }
}

bool isSessionTermination(uint32_t command_code, DiameterInterface iface) {
    // Check if this is a session termination message
    switch (iface) {
        case DiameterInterface::GX:
        case DiameterInterface::GY:
        case DiameterInterface::RO:
            // For Gx/Gy: CCR with type TERMINATION or STR
            return (command_code == static_cast<uint32_t>(DiameterCommandCode::CREDIT_CONTROL) ||
                    command_code == static_cast<uint32_t>(DiameterCommandCode::SESSION_TERMINATION));
        case DiameterInterface::S6A:
            // Cancel-Location-Request or Purge-UE-Request
            return (command_code == static_cast<uint32_t>(DiameterCommandCode::CANCEL_LOCATION) ||
                    command_code == static_cast<uint32_t>(DiameterCommandCode::PURGE_UE));
        case DiameterInterface::RX:
            // Session-Termination-Request or Abort-Session-Request
            return (command_code == static_cast<uint32_t>(DiameterCommandCode::SESSION_TERMINATION) ||
                    command_code == static_cast<uint32_t>(DiameterCommandCode::ABORT_SESSION));
        case DiameterInterface::CX:
            // Registration-Termination-Request
            return (command_code == static_cast<uint32_t>(DiameterCommandCode::REGISTRATION_TERMINATION));
        default:
            return false;
    }
}

} // namespace correlation
} // namespace callflow
