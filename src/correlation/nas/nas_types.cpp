#include "correlation/nas/nas_types.h"
#include <unordered_map>

namespace callflow {
namespace correlation {

namespace {

// EMM message type names
const std::unordered_map<NasEmmMessageType, std::string> emm_type_names = {
    {NasEmmMessageType::ATTACH_REQUEST, "Attach Request"},
    {NasEmmMessageType::ATTACH_ACCEPT, "Attach Accept"},
    {NasEmmMessageType::ATTACH_COMPLETE, "Attach Complete"},
    {NasEmmMessageType::ATTACH_REJECT, "Attach Reject"},
    {NasEmmMessageType::DETACH_REQUEST, "Detach Request"},
    {NasEmmMessageType::DETACH_ACCEPT, "Detach Accept"},
    {NasEmmMessageType::TAU_REQUEST, "TAU Request"},
    {NasEmmMessageType::TAU_ACCEPT, "TAU Accept"},
    {NasEmmMessageType::TAU_COMPLETE, "TAU Complete"},
    {NasEmmMessageType::TAU_REJECT, "TAU Reject"},
    {NasEmmMessageType::SERVICE_REQUEST, "Service Request"},
    {NasEmmMessageType::SERVICE_REJECT, "Service Reject"},
    {NasEmmMessageType::EXTENDED_SERVICE_REQUEST, "Extended Service Request"},
    {NasEmmMessageType::GUTI_REALLOC_COMMAND, "GUTI Reallocation Command"},
    {NasEmmMessageType::GUTI_REALLOC_COMPLETE, "GUTI Reallocation Complete"},
    {NasEmmMessageType::AUTH_REQUEST, "Authentication Request"},
    {NasEmmMessageType::AUTH_RESPONSE, "Authentication Response"},
    {NasEmmMessageType::AUTH_FAILURE, "Authentication Failure"},
    {NasEmmMessageType::AUTH_REJECT, "Authentication Reject"},
    {NasEmmMessageType::IDENTITY_REQUEST, "Identity Request"},
    {NasEmmMessageType::IDENTITY_RESPONSE, "Identity Response"},
    {NasEmmMessageType::SECURITY_MODE_COMMAND, "Security Mode Command"},
    {NasEmmMessageType::SECURITY_MODE_COMPLETE, "Security Mode Complete"},
    {NasEmmMessageType::SECURITY_MODE_REJECT, "Security Mode Reject"},
    {NasEmmMessageType::EMM_INFORMATION, "EMM Information"},
    {NasEmmMessageType::EMM_STATUS, "EMM Status"},
    {NasEmmMessageType::DOWNLINK_NAS_TRANSPORT, "Downlink NAS Transport"},
    {NasEmmMessageType::UPLINK_NAS_TRANSPORT, "Uplink NAS Transport"},
    {NasEmmMessageType::CS_SERVICE_NOTIFICATION, "CS Service Notification"},
};

// ESM message type names
const std::unordered_map<NasEsmMessageType, std::string> esm_type_names = {
    {NasEsmMessageType::ACTIVATE_DEFAULT_BEARER_REQ, "Activate Default Bearer Request"},
    {NasEsmMessageType::ACTIVATE_DEFAULT_BEARER_ACC, "Activate Default Bearer Accept"},
    {NasEsmMessageType::ACTIVATE_DEFAULT_BEARER_REJ, "Activate Default Bearer Reject"},
    {NasEsmMessageType::ACTIVATE_DEDICATED_BEARER_REQ, "Activate Dedicated Bearer Request"},
    {NasEsmMessageType::ACTIVATE_DEDICATED_BEARER_ACC, "Activate Dedicated Bearer Accept"},
    {NasEsmMessageType::ACTIVATE_DEDICATED_BEARER_REJ, "Activate Dedicated Bearer Reject"},
    {NasEsmMessageType::MODIFY_BEARER_REQ, "Modify Bearer Request"},
    {NasEsmMessageType::MODIFY_BEARER_ACC, "Modify Bearer Accept"},
    {NasEsmMessageType::MODIFY_BEARER_REJ, "Modify Bearer Reject"},
    {NasEsmMessageType::DEACTIVATE_BEARER_REQ, "Deactivate Bearer Request"},
    {NasEsmMessageType::DEACTIVATE_BEARER_ACC, "Deactivate Bearer Accept"},
    {NasEsmMessageType::PDN_CONNECTIVITY_REQUEST, "PDN Connectivity Request"},
    {NasEsmMessageType::PDN_CONNECTIVITY_REJECT, "PDN Connectivity Reject"},
    {NasEsmMessageType::PDN_DISCONNECT_REQUEST, "PDN Disconnect Request"},
    {NasEsmMessageType::PDN_DISCONNECT_REJECT, "PDN Disconnect Reject"},
    {NasEsmMessageType::BEARER_RESOURCE_ALLOC_REQ, "Bearer Resource Allocation Request"},
    {NasEsmMessageType::BEARER_RESOURCE_ALLOC_REJ, "Bearer Resource Allocation Reject"},
    {NasEsmMessageType::BEARER_RESOURCE_MODIFY_REQ, "Bearer Resource Modification Request"},
    {NasEsmMessageType::BEARER_RESOURCE_MODIFY_REJ, "Bearer Resource Modification Reject"},
    {NasEsmMessageType::ESM_INFO_REQUEST, "ESM Information Request"},
    {NasEsmMessageType::ESM_INFO_RESPONSE, "ESM Information Response"},
    {NasEsmMessageType::ESM_STATUS, "ESM Status"},
    {NasEsmMessageType::ESM_NOTIFICATION, "ESM Notification"},
};

} // anonymous namespace

std::string getEmmMessageTypeName(NasEmmMessageType type) {
    auto it = emm_type_names.find(type);
    if (it != emm_type_names.end()) {
        return it->second;
    }
    return "Unknown EMM (" + std::to_string(static_cast<uint8_t>(type)) + ")";
}

std::string getEsmMessageTypeName(NasEsmMessageType type) {
    auto it = esm_type_names.find(type);
    if (it != esm_type_names.end()) {
        return it->second;
    }
    return "Unknown ESM (" + std::to_string(static_cast<uint8_t>(type)) + ")";
}

std::string getMobileIdentityTypeName(MobileIdentityType type) {
    switch (type) {
        case MobileIdentityType::NO_IDENTITY: return "No Identity";
        case MobileIdentityType::IMSI: return "IMSI";
        case MobileIdentityType::IMEI: return "IMEI";
        case MobileIdentityType::IMEISV: return "IMEISV";
        case MobileIdentityType::TMSI: return "TMSI";
        case MobileIdentityType::TMGI: return "TMGI";
        case MobileIdentityType::GUTI: return "GUTI";
        default: return "Unknown";
    }
}

std::string getNasPdnTypeName(NasPdnType type) {
    switch (type) {
        case NasPdnType::IPV4: return "IPv4";
        case NasPdnType::IPV6: return "IPv6";
        case NasPdnType::IPV4V6: return "IPv4v6";
        case NasPdnType::NON_IP: return "Non-IP";
        default: return "Unknown";
    }
}

std::string getEsmCauseName(EsmCause cause) {
    switch (cause) {
        case EsmCause::OPERATOR_DETERMINED_BARRING: return "Operator Determined Barring";
        case EsmCause::INSUFFICIENT_RESOURCES: return "Insufficient Resources";
        case EsmCause::UNKNOWN_APN: return "Unknown APN";
        case EsmCause::UNKNOWN_PDN_TYPE: return "Unknown PDN Type";
        case EsmCause::USER_AUTHENTICATION_FAILED: return "User Authentication Failed";
        case EsmCause::REQUEST_REJECTED_BY_GW: return "Request Rejected by GW";
        case EsmCause::REGULAR_DEACTIVATION: return "Regular Deactivation";
        case EsmCause::NETWORK_FAILURE: return "Network Failure";
        default: return "Unknown ESM Cause (" + std::to_string(static_cast<uint8_t>(cause)) + ")";
    }
}

std::string getEmmCauseName(EmmCause cause) {
    switch (cause) {
        case EmmCause::IMSI_UNKNOWN_IN_HSS: return "IMSI Unknown in HSS";
        case EmmCause::ILLEGAL_UE: return "Illegal UE";
        case EmmCause::IMEI_NOT_ACCEPTED: return "IMEI Not Accepted";
        case EmmCause::ILLEGAL_ME: return "Illegal ME";
        case EmmCause::EPS_SERVICES_NOT_ALLOWED: return "EPS Services Not Allowed";
        case EmmCause::PLMN_NOT_ALLOWED: return "PLMN Not Allowed";
        case EmmCause::TA_NOT_ALLOWED: return "TA Not Allowed";
        case EmmCause::ROAMING_NOT_ALLOWED_IN_TA: return "Roaming Not Allowed in TA";
        case EmmCause::NETWORK_FAILURE: return "Network Failure";
        case EmmCause::MAC_FAILURE: return "MAC Failure";
        case EmmCause::SYNCH_FAILURE: return "Synch Failure";
        case EmmCause::CONGESTION: return "Congestion";
        default: return "Unknown EMM Cause (" + std::to_string(static_cast<uint8_t>(cause)) + ")";
    }
}

bool isEmmRequest(NasEmmMessageType type) {
    switch (type) {
        case NasEmmMessageType::ATTACH_REQUEST:
        case NasEmmMessageType::DETACH_REQUEST:
        case NasEmmMessageType::TAU_REQUEST:
        case NasEmmMessageType::SERVICE_REQUEST:
        case NasEmmMessageType::EXTENDED_SERVICE_REQUEST:
        case NasEmmMessageType::AUTH_RESPONSE:
        case NasEmmMessageType::IDENTITY_RESPONSE:
        case NasEmmMessageType::SECURITY_MODE_COMPLETE:
        case NasEmmMessageType::GUTI_REALLOC_COMPLETE:
            return true;
        default:
            return false;
    }
}

bool isEsmRequest(NasEsmMessageType type) {
    switch (type) {
        case NasEsmMessageType::ACTIVATE_DEFAULT_BEARER_ACC:
        case NasEsmMessageType::ACTIVATE_DEDICATED_BEARER_ACC:
        case NasEsmMessageType::MODIFY_BEARER_ACC:
        case NasEsmMessageType::DEACTIVATE_BEARER_ACC:
        case NasEsmMessageType::PDN_CONNECTIVITY_REQUEST:
        case NasEsmMessageType::PDN_DISCONNECT_REQUEST:
        case NasEsmMessageType::BEARER_RESOURCE_ALLOC_REQ:
        case NasEsmMessageType::BEARER_RESOURCE_MODIFY_REQ:
        case NasEsmMessageType::ESM_INFO_RESPONSE:
            return true;
        default:
            return false;
    }
}

bool isEsmSuccess(EsmCause cause) {
    // Only REGULAR_DEACTIVATION is considered "success"
    return cause == EsmCause::REGULAR_DEACTIVATION;
}

} // namespace correlation
} // namespace callflow
