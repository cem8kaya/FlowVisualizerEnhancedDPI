#pragma once

#include "common/types.h"
#include <optional>
#include <vector>
#include <cstdint>
#include <string>

namespace callflow {

/**
 * S1AP Procedure Codes (3GPP TS 36.413)
 */
enum class S1apProcedureCode : uint8_t {
    // Handover
    HANDOVER_PREPARATION = 0,
    HANDOVER_RESOURCE_ALLOCATION = 1,
    HANDOVER_NOTIFICATION = 2,
    PATH_SWITCH_REQUEST = 3,
    HANDOVER_CANCEL = 4,

    // Initial context setup
    INITIAL_CONTEXT_SETUP = 9,

    // Paging
    PAGING = 10,

    // NAS transport
    DOWNLINK_NAS_TRANSPORT = 11,
    INITIAL_UE_MESSAGE = 12,
    UPLINK_NAS_TRANSPORT = 13,

    // Reset and error handling
    RESET = 14,
    ERROR_INDICATION = 15,

    // S1 Setup
    S1_SETUP = 17,

    // UE context
    UE_CONTEXT_RELEASE_REQUEST = 18,
    UE_CONTEXT_MODIFICATION = 21,
    UE_CONTEXT_RELEASE = 23,

    // E-RAB management
    E_RAB_SETUP = 5,
    E_RAB_MODIFY = 6,
    E_RAB_RELEASE = 7,

    // Unknown
    UNKNOWN = 0xFF
};

/**
 * S1AP Message Type
 */
enum class S1apMessageType : uint8_t {
    INITIATING_MESSAGE = 0,
    SUCCESSFUL_OUTCOME = 1,
    UNSUCCESSFUL_OUTCOME = 2,
    UNKNOWN = 0xFF
};

/**
 * S1AP Criticality
 */
enum class S1apCriticality : uint8_t {
    REJECT = 0,
    IGNORE = 1,
    NOTIFY = 2
};

/**
 * S1AP Information Element Type
 */
enum class S1apIeType : uint8_t {
    // Identity IEs
    MME_UE_S1AP_ID = 0,
    ENB_UE_S1AP_ID = 8,

    // NAS and message IEs
    NAS_PDU = 26,

    // Subscriber identity
    IMSI = 74,

    // Cause
    CAUSE = 2,

    // E-RAB IEs
    E_RAB_SETUP_LIST_CTXT_SU_REQ = 24,
    E_RAB_SETUP_LIST_CTXT_SU_RES = 51,
    E_RAB_TO_BE_SETUP_LIST = 16,
    E_RAB_ADMITTED_LIST = 18,

    // TAI (Tracking Area Identity)
    TAI = 67,

    // EUTRAN CGI (Cell Global Identifier)
    EUTRAN_CGI = 100,

    // UE Security Capabilities
    UE_SECURITY_CAPABILITIES = 107,

    // UE aggregate maximum bit rate
    UE_AGGREGATE_MAXIMUM_BIT_RATE = 66,

    // Unknown
    UNKNOWN = 0xFF
};

/**
 * S1AP Information Element
 */
struct S1apInformationElement {
    S1apIeType type;
    S1apCriticality criticality;
    std::vector<uint8_t> value;

    /**
     * Get IE type name
     */
    std::string getTypeName() const;

    /**
     * Convert to JSON
     */
    nlohmann::json toJson() const;
};

/**
 * S1AP Message Structure
 */
struct S1apMessage {
    S1apMessageType message_type;
    S1apProcedureCode procedure_code;
    S1apCriticality criticality;
    std::vector<S1apInformationElement> ies;

    // Decoded common fields
    std::optional<uint32_t> enb_ue_s1ap_id;
    std::optional<uint32_t> mme_ue_s1ap_id;
    std::optional<std::string> imsi;
    std::optional<std::vector<uint8_t>> nas_pdu;

    /**
     * Get procedure code name
     */
    std::string getProcedureCodeName() const;

    /**
     * Get message type name
     */
    std::string getMessageTypeName() const;

    /**
     * Convert to JSON
     */
    nlohmann::json toJson() const;

    /**
     * Get callflow message type
     */
    MessageType getMessageType() const;
};

/**
 * Convert S1AP procedure code to string
 */
std::string s1apProcedureCodeToString(S1apProcedureCode code);

/**
 * Convert S1AP message type to string
 */
std::string s1apMessageTypeToString(S1apMessageType type);

/**
 * Convert S1AP criticality to string
 */
std::string s1apCriticalityToString(S1apCriticality crit);

/**
 * Convert S1AP IE type to string
 */
std::string s1apIeTypeToString(S1apIeType type);

}  // namespace callflow
