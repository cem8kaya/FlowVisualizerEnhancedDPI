#include "correlation/s1ap/s1ap_types.h"
#include <unordered_map>

namespace callflow {
namespace correlation {

namespace {

// S1AP procedure code names
const std::unordered_map<S1apProcedureCode, std::string> procedure_code_names = {
    {S1apProcedureCode::HANDOVER_PREPARATION, "Handover Preparation"},
    {S1apProcedureCode::HANDOVER_RESOURCE_ALLOCATION, "Handover Resource Allocation"},
    {S1apProcedureCode::HANDOVER_NOTIFY, "Handover Notify"},
    {S1apProcedureCode::PATH_SWITCH_REQUEST, "Path Switch Request"},
    {S1apProcedureCode::HANDOVER_CANCEL, "Handover Cancel"},
    {S1apProcedureCode::E_RAB_SETUP, "E-RAB Setup"},
    {S1apProcedureCode::E_RAB_MODIFY, "E-RAB Modify"},
    {S1apProcedureCode::E_RAB_RELEASE, "E-RAB Release"},
    {S1apProcedureCode::E_RAB_RELEASE_INDICATION, "E-RAB Release Indication"},
    {S1apProcedureCode::INITIAL_CONTEXT_SETUP, "Initial Context Setup"},
    {S1apProcedureCode::PAGING, "Paging"},
    {S1apProcedureCode::DOWNLINK_NAS_TRANSPORT, "Downlink NAS Transport"},
    {S1apProcedureCode::INITIAL_UE_MESSAGE, "Initial UE Message"},
    {S1apProcedureCode::UPLINK_NAS_TRANSPORT, "Uplink NAS Transport"},
    {S1apProcedureCode::RESET, "Reset"},
    {S1apProcedureCode::ERROR_INDICATION, "Error Indication"},
    {S1apProcedureCode::NAS_NON_DELIVERY_INDICATION, "NAS Non-Delivery Indication"},
    {S1apProcedureCode::S1_SETUP, "S1 Setup"},
    {S1apProcedureCode::UE_CONTEXT_RELEASE_REQUEST, "UE Context Release Request"},
    {S1apProcedureCode::UE_CONTEXT_MODIFICATION, "UE Context Modification"},
    {S1apProcedureCode::UE_CAPABILITY_INFO_INDICATION, "UE Capability Info Indication"},
    {S1apProcedureCode::UE_CONTEXT_RELEASE, "UE Context Release"},
    {S1apProcedureCode::ENB_STATUS_TRANSFER, "eNB Status Transfer"},
    {S1apProcedureCode::MME_STATUS_TRANSFER, "MME Status Transfer"},
    {S1apProcedureCode::ENB_CONFIGURATION_UPDATE, "eNB Configuration Update"},
    {S1apProcedureCode::MME_CONFIGURATION_UPDATE, "MME Configuration Update"},
};

} // anonymous namespace

std::string getS1apProcedureCodeName(S1apProcedureCode code) {
    auto it = procedure_code_names.find(code);
    if (it != procedure_code_names.end()) {
        return it->second;
    }
    return "Unknown Procedure (" + std::to_string(static_cast<uint8_t>(code)) + ")";
}

std::string getS1apMessageTypeName(S1apMessageType type) {
    switch (type) {
        case S1apMessageType::INITIAL_UE_MESSAGE: return "Initial UE Message";
        case S1apMessageType::DOWNLINK_NAS_TRANSPORT: return "Downlink NAS Transport";
        case S1apMessageType::UPLINK_NAS_TRANSPORT: return "Uplink NAS Transport";
        case S1apMessageType::INITIAL_CONTEXT_SETUP_REQUEST: return "Initial Context Setup Request";
        case S1apMessageType::INITIAL_CONTEXT_SETUP_RESPONSE: return "Initial Context Setup Response";
        case S1apMessageType::INITIAL_CONTEXT_SETUP_FAILURE: return "Initial Context Setup Failure";
        case S1apMessageType::UE_CONTEXT_RELEASE_REQUEST: return "UE Context Release Request";
        case S1apMessageType::UE_CONTEXT_RELEASE_COMMAND: return "UE Context Release Command";
        case S1apMessageType::UE_CONTEXT_RELEASE_COMPLETE: return "UE Context Release Complete";
        case S1apMessageType::E_RAB_SETUP_REQUEST: return "E-RAB Setup Request";
        case S1apMessageType::E_RAB_SETUP_RESPONSE: return "E-RAB Setup Response";
        case S1apMessageType::E_RAB_MODIFY_REQUEST: return "E-RAB Modify Request";
        case S1apMessageType::E_RAB_MODIFY_RESPONSE: return "E-RAB Modify Response";
        case S1apMessageType::E_RAB_RELEASE_COMMAND: return "E-RAB Release Command";
        case S1apMessageType::E_RAB_RELEASE_RESPONSE: return "E-RAB Release Response";
        case S1apMessageType::E_RAB_RELEASE_INDICATION: return "E-RAB Release Indication";
        case S1apMessageType::HANDOVER_REQUIRED: return "Handover Required";
        case S1apMessageType::HANDOVER_REQUEST: return "Handover Request";
        case S1apMessageType::HANDOVER_NOTIFY: return "Handover Notify";
        case S1apMessageType::PATH_SWITCH_REQUEST: return "Path Switch Request";
        case S1apMessageType::PAGING: return "Paging";
        case S1apMessageType::S1_SETUP_REQUEST: return "S1 Setup Request";
        default: return "Unknown";
    }
}

std::string getS1apCauseTypeName(S1apCauseType type) {
    switch (type) {
        case S1apCauseType::RADIO_NETWORK: return "Radio Network";
        case S1apCauseType::TRANSPORT: return "Transport";
        case S1apCauseType::NAS: return "NAS";
        case S1apCauseType::PROTOCOL: return "Protocol";
        case S1apCauseType::MISC: return "Misc";
        default: return "Unknown";
    }
}

std::string getS1apRadioNetworkCauseName(S1apRadioNetworkCause cause) {
    switch (cause) {
        case S1apRadioNetworkCause::UNSPECIFIED: return "Unspecified";
        case S1apRadioNetworkCause::SUCCESSFUL_HANDOVER: return "Successful Handover";
        case S1apRadioNetworkCause::RELEASE_DUE_TO_EUTRAN_GENERATED_REASON: return "Release due to E-UTRAN generated reason";
        case S1apRadioNetworkCause::HANDOVER_CANCELLED: return "Handover Cancelled";
        case S1apRadioNetworkCause::USER_INACTIVITY: return "User Inactivity";
        case S1apRadioNetworkCause::RADIO_CONNECTION_WITH_UE_LOST: return "Radio Connection with UE Lost";
        case S1apRadioNetworkCause::LOAD_BALANCING_TAU_REQUIRED: return "Load Balancing TAU Required";
        case S1apRadioNetworkCause::CS_FALLBACK_TRIGGERED: return "CS Fallback Triggered";
        case S1apRadioNetworkCause::UE_NOT_AVAILABLE_FOR_PS_SERVICE: return "UE Not Available for PS Service";
        default: return "Unknown Radio Network Cause (" + std::to_string(static_cast<uint8_t>(cause)) + ")";
    }
}

std::string getS1apNasCauseName(S1apNasCause cause) {
    switch (cause) {
        case S1apNasCause::NORMAL_RELEASE: return "Normal Release";
        case S1apNasCause::AUTHENTICATION_FAILURE: return "Authentication Failure";
        case S1apNasCause::DETACH: return "Detach";
        case S1apNasCause::UNSPECIFIED: return "Unspecified";
        case S1apNasCause::CSG_SUBSCRIPTION_EXPIRY: return "CSG Subscription Expiry";
        default: return "Unknown";
    }
}

std::string getRrcEstablishmentCauseName(RrcEstablishmentCause cause) {
    switch (cause) {
        case RrcEstablishmentCause::EMERGENCY: return "Emergency";
        case RrcEstablishmentCause::HIGH_PRIORITY_ACCESS: return "High Priority Access";
        case RrcEstablishmentCause::MT_ACCESS: return "MT Access";
        case RrcEstablishmentCause::MO_SIGNALLING: return "MO Signalling";
        case RrcEstablishmentCause::MO_DATA: return "MO Data";
        case RrcEstablishmentCause::DELAY_TOLERANT_ACCESS: return "Delay Tolerant Access";
        case RrcEstablishmentCause::MO_VOICE_CALL: return "MO Voice Call";
        default: return "Unknown";
    }
}

bool isUeAssociated(S1apProcedureCode code) {
    switch (code) {
        case S1apProcedureCode::INITIAL_UE_MESSAGE:
        case S1apProcedureCode::DOWNLINK_NAS_TRANSPORT:
        case S1apProcedureCode::UPLINK_NAS_TRANSPORT:
        case S1apProcedureCode::INITIAL_CONTEXT_SETUP:
        case S1apProcedureCode::UE_CONTEXT_RELEASE_REQUEST:
        case S1apProcedureCode::UE_CONTEXT_RELEASE:
        case S1apProcedureCode::UE_CONTEXT_MODIFICATION:
        case S1apProcedureCode::E_RAB_SETUP:
        case S1apProcedureCode::E_RAB_MODIFY:
        case S1apProcedureCode::E_RAB_RELEASE:
        case S1apProcedureCode::E_RAB_RELEASE_INDICATION:
        case S1apProcedureCode::HANDOVER_PREPARATION:
        case S1apProcedureCode::HANDOVER_RESOURCE_ALLOCATION:
        case S1apProcedureCode::HANDOVER_NOTIFY:
        case S1apProcedureCode::PATH_SWITCH_REQUEST:
        case S1apProcedureCode::HANDOVER_CANCEL:
        case S1apProcedureCode::UE_CAPABILITY_INFO_INDICATION:
            return true;
        default:
            return false;
    }
}

bool containsNasPdu(S1apProcedureCode code) {
    switch (code) {
        case S1apProcedureCode::INITIAL_UE_MESSAGE:
        case S1apProcedureCode::DOWNLINK_NAS_TRANSPORT:
        case S1apProcedureCode::UPLINK_NAS_TRANSPORT:
            return true;
        default:
            return false;
    }
}

} // namespace correlation
} // namespace callflow
