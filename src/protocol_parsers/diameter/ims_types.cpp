#include "protocol_parsers/diameter/ims_types.h"
#include <sstream>

namespace callflow {
namespace diameter {

// ============================================================================
// Structure toJson() Methods
// ============================================================================

nlohmann::json ServerCapabilities::toJson() const {
    nlohmann::json j;

    if (!mandatory_capabilities.empty()) {
        j["mandatory_capabilities"] = mandatory_capabilities;
    }

    if (!optional_capabilities.empty()) {
        j["optional_capabilities"] = optional_capabilities;
    }

    if (!server_names.empty()) {
        j["server_names"] = server_names;
    }

    return j;
}

nlohmann::json SIPAuthDataItem::toJson() const {
    nlohmann::json j;
    j["sip_item_number"] = sip_item_number;

    if (sip_authentication_scheme.has_value()) {
        j["sip_authentication_scheme"] = sip_authentication_scheme.value();
    }

    if (sip_authenticate.has_value()) {
        j["sip_authenticate"] = sip_authenticate.value();
    }

    if (sip_authorization.has_value()) {
        j["sip_authorization"] = sip_authorization.value();
    }

    if (sip_authentication_context.has_value()) {
        j["sip_authentication_context"] = sip_authentication_context.value();
    }

    if (confidentiality_key.has_value()) {
        j["confidentiality_key"] = confidentiality_key.value();
    }

    if (integrity_key.has_value()) {
        j["integrity_key"] = integrity_key.value();
    }

    if (line_identifier.has_value() && !line_identifier.value().empty()) {
        j["line_identifier"] = line_identifier.value();
    }

    return j;
}

nlohmann::json SIPNumberAuthItems::toJson() const {
    nlohmann::json j;

    if (!auth_data_items.empty()) {
        nlohmann::json items = nlohmann::json::array();
        for (const auto& item : auth_data_items) {
            items.push_back(item.toJson());
        }
        j["auth_data_items"] = items;
    }

    return j;
}

nlohmann::json ChargingInformation::toJson() const {
    nlohmann::json j;

    if (primary_event_charging_function_name.has_value()) {
        j["primary_event_charging_function_name"] =
            primary_event_charging_function_name.value();
    }

    if (secondary_event_charging_function_name.has_value()) {
        j["secondary_event_charging_function_name"] =
            secondary_event_charging_function_name.value();
    }

    if (primary_charging_collection_function_name.has_value()) {
        j["primary_charging_collection_function_name"] =
            primary_charging_collection_function_name.value();
    }

    if (secondary_charging_collection_function_name.has_value()) {
        j["secondary_charging_collection_function_name"] =
            secondary_charging_collection_function_name.value();
    }

    return j;
}

nlohmann::json UserIdentity::toJson() const {
    nlohmann::json j;

    if (public_identity.has_value()) {
        j["public_identity"] = public_identity.value();
    }

    if (msisdn.has_value()) {
        j["msisdn"] = msisdn.value();
    }

    if (external_identifier.has_value()) {
        j["external_identifier"] = external_identifier.value();
    }

    return j;
}

nlohmann::json SupportedFeatures::toJson() const {
    nlohmann::json j;
    j["vendor_id"] = vendor_id;
    j["feature_list_id"] = feature_list_id;
    j["feature_list"] = feature_list;
    return j;
}

nlohmann::json DeregistrationReason::toJson() const {
    nlohmann::json j;
    j["reason_code"] = reason_code;
    j["reason_code_name"] = reasonCodeToString(static_cast<ReasonCode>(reason_code));

    if (reason_info.has_value()) {
        j["reason_info"] = reason_info.value();
    }

    return j;
}

nlohmann::json RepositoryDataID::toJson() const {
    nlohmann::json j;

    if (service_indication.has_value()) {
        j["service_indication"] = service_indication.value();
    }

    j["sequence_number"] = sequence_number;

    return j;
}

nlohmann::json UserDataSH::toJson() const {
    nlohmann::json j;
    j["raw_xml"] = raw_xml;

    if (public_identities.has_value() && !public_identities.value().empty()) {
        j["public_identities"] = public_identities.value();
    }

    if (service_profile.has_value()) {
        j["service_profile"] = service_profile.value();
    }

    return j;
}

// ============================================================================
// Helper Functions
// ============================================================================

std::string serverAssignmentTypeToString(ServerAssignmentType type) {
    switch (type) {
        case ServerAssignmentType::NO_ASSIGNMENT:
            return "NO_ASSIGNMENT";
        case ServerAssignmentType::REGISTRATION:
            return "REGISTRATION";
        case ServerAssignmentType::RE_REGISTRATION:
            return "RE_REGISTRATION";
        case ServerAssignmentType::UNREGISTERED_USER:
            return "UNREGISTERED_USER";
        case ServerAssignmentType::TIMEOUT_DEREGISTRATION:
            return "TIMEOUT_DEREGISTRATION";
        case ServerAssignmentType::USER_DEREGISTRATION:
            return "USER_DEREGISTRATION";
        case ServerAssignmentType::TIMEOUT_DEREGISTRATION_STORE_SERVER_NAME:
            return "TIMEOUT_DEREGISTRATION_STORE_SERVER_NAME";
        case ServerAssignmentType::USER_DEREGISTRATION_STORE_SERVER_NAME:
            return "USER_DEREGISTRATION_STORE_SERVER_NAME";
        case ServerAssignmentType::ADMINISTRATIVE_DEREGISTRATION:
            return "ADMINISTRATIVE_DEREGISTRATION";
        case ServerAssignmentType::AUTHENTICATION_FAILURE:
            return "AUTHENTICATION_FAILURE";
        case ServerAssignmentType::AUTHENTICATION_TIMEOUT:
            return "AUTHENTICATION_TIMEOUT";
        case ServerAssignmentType::DEREGISTRATION_TOO_MUCH_DATA:
            return "DEREGISTRATION_TOO_MUCH_DATA";
        case ServerAssignmentType::AAA_USER_DATA_REQUEST:
            return "AAA_USER_DATA_REQUEST";
        case ServerAssignmentType::PGW_UPDATE:
            return "PGW_UPDATE";
        case ServerAssignmentType::RESTORATION:
            return "RESTORATION";
        default:
            return "UNKNOWN";
    }
}

std::string userAuthorizationTypeToString(UserAuthorizationType type) {
    switch (type) {
        case UserAuthorizationType::REGISTRATION:
            return "REGISTRATION";
        case UserAuthorizationType::DE_REGISTRATION:
            return "DE_REGISTRATION";
        case UserAuthorizationType::REGISTRATION_AND_CAPABILITIES:
            return "REGISTRATION_AND_CAPABILITIES";
        default:
            return "UNKNOWN";
    }
}

std::string dataReferenceToString(DataReference ref) {
    switch (ref) {
        case DataReference::REPOSITORY_DATA:
            return "REPOSITORY_DATA";
        case DataReference::IMS_PUBLIC_IDENTITY:
            return "IMS_PUBLIC_IDENTITY";
        case DataReference::IMS_USER_STATE:
            return "IMS_USER_STATE";
        case DataReference::S_CSCF_NAME:
            return "S_CSCF_NAME";
        case DataReference::INITIAL_FILTER_CRITERIA:
            return "INITIAL_FILTER_CRITERIA";
        case DataReference::LOCATION_INFORMATION:
            return "LOCATION_INFORMATION";
        case DataReference::USER_STATE:
            return "USER_STATE";
        case DataReference::CHARGING_INFORMATION:
            return "CHARGING_INFORMATION";
        case DataReference::MSISDN:
            return "MSISDN";
        case DataReference::PSI_ACTIVATION:
            return "PSI_ACTIVATION";
        case DataReference::DSAI:
            return "DSAI";
        case DataReference::SERVICE_LEVEL_TRACE_INFO:
            return "SERVICE_LEVEL_TRACE_INFO";
        case DataReference::IP_ADDRESS_SECURE_BINDING_INFO:
            return "IP_ADDRESS_SECURE_BINDING_INFO";
        case DataReference::SERVICE_PRIORITY_LEVEL:
            return "SERVICE_PRIORITY_LEVEL";
        case DataReference::SMSF_3GPP_ADDRESS:
            return "SMSF_3GPP_ADDRESS";
        case DataReference::SMSF_NON_3GPP_ADDRESS:
            return "SMSF_NON_3GPP_ADDRESS";
        case DataReference::UE_SRVCC_CAPABILITY:
            return "UE_SRVCC_CAPABILITY";
        default:
            return "UNKNOWN";
    }
}

std::string subscriptionRequestTypeToString(SubscriptionRequestType type) {
    switch (type) {
        case SubscriptionRequestType::SUBSCRIBE:
            return "SUBSCRIBE";
        case SubscriptionRequestType::UNSUBSCRIBE:
            return "UNSUBSCRIBE";
        default:
            return "UNKNOWN";
    }
}

std::string imsUserStateToString(IMSUserState state) {
    switch (state) {
        case IMSUserState::NOT_REGISTERED:
            return "NOT_REGISTERED";
        case IMSUserState::REGISTERED:
            return "REGISTERED";
        case IMSUserState::UNREGISTERED:
            return "UNREGISTERED";
        case IMSUserState::AUTHENTICATION_PENDING:
            return "AUTHENTICATION_PENDING";
        default:
            return "UNKNOWN";
    }
}

std::string reasonCodeToString(ReasonCode code) {
    switch (code) {
        case ReasonCode::PERMANENT_TERMINATION:
            return "PERMANENT_TERMINATION";
        case ReasonCode::NEW_SERVER_ASSIGNED:
            return "NEW_SERVER_ASSIGNED";
        case ReasonCode::SERVER_CHANGE:
            return "SERVER_CHANGE";
        case ReasonCode::REMOVE_S_CSCF:
            return "REMOVE_S_CSCF";
        default:
            return "UNKNOWN";
    }
}

std::string cxDxExperimentalResultCodeToString(CxDxExperimentalResultCode code) {
    switch (code) {
        case CxDxExperimentalResultCode::DIAMETER_FIRST_REGISTRATION:
            return "DIAMETER_FIRST_REGISTRATION";
        case CxDxExperimentalResultCode::DIAMETER_SUBSEQUENT_REGISTRATION:
            return "DIAMETER_SUBSEQUENT_REGISTRATION";
        case CxDxExperimentalResultCode::DIAMETER_UNREGISTERED_SERVICE:
            return "DIAMETER_UNREGISTERED_SERVICE";
        case CxDxExperimentalResultCode::DIAMETER_SUCCESS_SERVER_NAME_NOT_STORED:
            return "DIAMETER_SUCCESS_SERVER_NAME_NOT_STORED";
        case CxDxExperimentalResultCode::DIAMETER_SERVER_SELECTION:
            return "DIAMETER_SERVER_SELECTION";
        case CxDxExperimentalResultCode::DIAMETER_ERROR_USER_UNKNOWN:
            return "DIAMETER_ERROR_USER_UNKNOWN";
        case CxDxExperimentalResultCode::DIAMETER_ERROR_IDENTITIES_DONT_MATCH:
            return "DIAMETER_ERROR_IDENTITIES_DONT_MATCH";
        case CxDxExperimentalResultCode::DIAMETER_ERROR_IDENTITY_NOT_REGISTERED:
            return "DIAMETER_ERROR_IDENTITY_NOT_REGISTERED";
        case CxDxExperimentalResultCode::DIAMETER_ERROR_ROAMING_NOT_ALLOWED:
            return "DIAMETER_ERROR_ROAMING_NOT_ALLOWED";
        case CxDxExperimentalResultCode::DIAMETER_ERROR_IDENTITY_ALREADY_REGISTERED:
            return "DIAMETER_ERROR_IDENTITY_ALREADY_REGISTERED";
        case CxDxExperimentalResultCode::DIAMETER_ERROR_AUTH_SCHEME_NOT_SUPPORTED:
            return "DIAMETER_ERROR_AUTH_SCHEME_NOT_SUPPORTED";
        case CxDxExperimentalResultCode::DIAMETER_ERROR_IN_ASSIGNMENT_TYPE:
            return "DIAMETER_ERROR_IN_ASSIGNMENT_TYPE";
        case CxDxExperimentalResultCode::DIAMETER_ERROR_TOO_MUCH_DATA:
            return "DIAMETER_ERROR_TOO_MUCH_DATA";
        case CxDxExperimentalResultCode::DIAMETER_ERROR_NOT_SUPPORTED_USER_DATA:
            return "DIAMETER_ERROR_NOT_SUPPORTED_USER_DATA";
        default:
            return "UNKNOWN";
    }
}

std::string shExperimentalResultCodeToString(ShExperimentalResultCode code) {
    switch (code) {
        case ShExperimentalResultCode::DIAMETER_ERROR_USER_DATA_NOT_AVAILABLE:
            return "DIAMETER_ERROR_USER_DATA_NOT_AVAILABLE";
        case ShExperimentalResultCode::DIAMETER_ERROR_PRIOR_UPDATE_IN_PROGRESS:
            return "DIAMETER_ERROR_PRIOR_UPDATE_IN_PROGRESS";
        case ShExperimentalResultCode::DIAMETER_ERROR_USER_DATA_CANNOT_BE_READ:
            return "DIAMETER_ERROR_USER_DATA_CANNOT_BE_READ";
        case ShExperimentalResultCode::DIAMETER_ERROR_USER_DATA_CANNOT_BE_MODIFIED:
            return "DIAMETER_ERROR_USER_DATA_CANNOT_BE_MODIFIED";
        case ShExperimentalResultCode::DIAMETER_ERROR_USER_DATA_CANNOT_BE_NOTIFIED:
            return "DIAMETER_ERROR_USER_DATA_CANNOT_BE_NOTIFIED";
        case ShExperimentalResultCode::DIAMETER_ERROR_TRANSPARENT_DATA_OUT_OF_SYNC:
            return "DIAMETER_ERROR_TRANSPARENT_DATA_OUT_OF_SYNC";
        case ShExperimentalResultCode::DIAMETER_ERROR_SUBS_DATA_ABSENT:
            return "DIAMETER_ERROR_SUBS_DATA_ABSENT";
        case ShExperimentalResultCode::DIAMETER_ERROR_NO_SUBSCRIPTION_TO_DATA:
            return "DIAMETER_ERROR_NO_SUBSCRIPTION_TO_DATA";
        case ShExperimentalResultCode::DIAMETER_ERROR_DSAI_NOT_AVAILABLE:
            return "DIAMETER_ERROR_DSAI_NOT_AVAILABLE";
        case ShExperimentalResultCode::DIAMETER_ERROR_UNKNOWN_SERVICE_INDICATION:
            return "DIAMETER_ERROR_UNKNOWN_SERVICE_INDICATION";
        case ShExperimentalResultCode::DIAMETER_ERROR_FEATURE_UNSUPPORTED:
            return "DIAMETER_ERROR_FEATURE_UNSUPPORTED";
        default:
            return "UNKNOWN";
    }
}

}  // namespace diameter
}  // namespace callflow
