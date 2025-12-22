#pragma once

#include <cstdint>
#include <optional>
#include <vector>
#include <string>
#include <nlohmann/json.hpp>

namespace callflow {
namespace s1ap {

/**
 * S1AP Message Types (Procedure Codes from 3GPP TS 36.413)
 */
enum class S1APMessageType : uint8_t {
    // Connection Management
    HANDOVER_PREPARATION = 0,
    HANDOVER_RESOURCE_ALLOCATION = 1,
    HANDOVER_NOTIFICATION = 2,
    PATH_SWITCH_REQUEST = 3,
    HANDOVER_CANCEL = 4,
    E_RAB_SETUP = 5,
    E_RAB_MODIFY = 6,
    E_RAB_RELEASE = 7,
    INITIAL_CONTEXT_SETUP = 9,
    PAGING = 10,
    DOWNLINK_NAS_TRANSPORT = 11,
    INITIAL_UE_MESSAGE = 12,
    UPLINK_NAS_TRANSPORT = 13,
    RESET = 14,
    ERROR_INDICATION = 15,
    NAS_NON_DELIVERY_INDICATION = 16,
    S1_SETUP = 17,
    UE_CONTEXT_RELEASE_REQUEST = 18,
    DOWNLINK_S1_CDMA2000_TUNNELLING = 19,
    UPLINK_S1_CDMA2000_TUNNELLING = 20,
    UE_CONTEXT_MODIFICATION = 21,
    UE_CAPABILITY_INFO_INDICATION = 22,
    UE_CONTEXT_RELEASE = 23,
    ENB_STATUS_TRANSFER = 24,
    MME_STATUS_TRANSFER = 25,
    DEACTIVATE_TRACE = 26,
    TRACE_START = 27,
    TRACE_FAILURE_INDICATION = 28,
    ENB_CONFIGURATION_UPDATE = 29,
    MME_CONFIGURATION_UPDATE = 30,
    LOCATION_REPORTING_CONTROL = 31,
    LOCATION_REPORTING_FAILURE_INDICATION = 32,
    LOCATION_REPORT = 33,
    OVERLOAD_START = 34,
    OVERLOAD_STOP = 35,
    WRITE_REPLACE_WARNING = 36,
    ENB_DIRECT_INFORMATION_TRANSFER = 37,
    MME_DIRECT_INFORMATION_TRANSFER = 38,
    UNKNOWN = 255
};

/**
 * PDU Type
 */
enum class S1APPDUType : uint8_t {
    INITIATING_MESSAGE = 0,
    SUCCESSFUL_OUTCOME = 1,
    UNSUCCESSFUL_OUTCOME = 2
};

/**
 * Criticality
 */
enum class S1APCriticality : uint8_t {
    REJECT = 0,
    IGNORE = 1,
    NOTIFY = 2
};

/**
 * Cause Types (for failures and releases)
 */
enum class S1APCauseType : uint8_t {
    RADIO_NETWORK = 0,
    TRANSPORT = 1,
    NAS = 2,
    PROTOCOL = 3,
    MISC = 4
};

/**
 * Tracking Area Identity (3GPP TS 36.413)
 */
struct TrackingAreaIdentity {
    std::string plmn_identity;  // MCC+MNC in format "001010"
    uint16_t tac;              // Tracking Area Code

    nlohmann::json toJson() const {
        nlohmann::json j;
        j["plmn_identity"] = plmn_identity;
        j["tac"] = tac;
        return j;
    }
};

/**
 * E-UTRAN Cell Global Identifier (3GPP TS 36.413)
 */
struct EUTRAN_CGI {
    std::string plmn_identity;  // MCC+MNC
    uint32_t cell_identity;     // 28-bit Cell Identity

    nlohmann::json toJson() const {
        nlohmann::json j;
        j["plmn_identity"] = plmn_identity;
        j["cell_identity"] = cell_identity;
        return j;
    }
};

/**
 * Allocation and Retention Priority
 */
struct AllocationRetentionPriority {
    uint8_t priority_level;      // 1-15
    bool pre_emption_capability;  // MAY_TRIGGER_PRE_EMPTION or SHALL_NOT_TRIGGER_PRE_EMPTION
    bool pre_emption_vulnerability; // PRE_EMPTABLE or NOT_PRE_EMPTABLE

    nlohmann::json toJson() const {
        nlohmann::json j;
        j["priority_level"] = priority_level;
        j["pre_emption_capability"] = pre_emption_capability;
        j["pre_emption_vulnerability"] = pre_emption_vulnerability;
        return j;
    }
};

/**
 * GBR QoS Information
 */
struct GBR_QoSInformation {
    uint64_t e_rab_maximum_bitrate_dl;  // bps
    uint64_t e_rab_maximum_bitrate_ul;  // bps
    uint64_t e_rab_guaranteed_bitrate_dl; // bps
    uint64_t e_rab_guaranteed_bitrate_ul; // bps

    nlohmann::json toJson() const {
        nlohmann::json j;
        j["max_bitrate_dl"] = e_rab_maximum_bitrate_dl;
        j["max_bitrate_ul"] = e_rab_maximum_bitrate_ul;
        j["guaranteed_bitrate_dl"] = e_rab_guaranteed_bitrate_dl;
        j["guaranteed_bitrate_ul"] = e_rab_guaranteed_bitrate_ul;
        return j;
    }
};

/**
 * E-RAB Level QoS Parameters
 */
struct E_RAB_LevelQoSParameters {
    uint8_t qci;  // QoS Class Identifier (1-9)
    AllocationRetentionPriority arp;
    std::optional<GBR_QoSInformation> gbr_qos_info;

    nlohmann::json toJson() const {
        nlohmann::json j;
        j["qci"] = qci;
        j["arp"] = arp.toJson();
        if (gbr_qos_info.has_value()) {
            j["gbr_qos_info"] = gbr_qos_info->toJson();
        }
        return j;
    }
};

/**
 * E-RAB To Be Setup Item (Initial Context Setup Request)
 */
struct E_RAB_ToBeSetupItem {
    uint8_t e_rab_id;  // 0-15
    E_RAB_LevelQoSParameters qos_parameters;
    std::vector<uint8_t> transport_layer_address;  // IP address (4 or 16 bytes)
    uint32_t gtp_teid;  // GTP Tunnel Endpoint Identifier
    std::optional<std::vector<uint8_t>> nas_pdu;  // Embedded ESM message

    nlohmann::json toJson() const {
        nlohmann::json j;
        j["e_rab_id"] = e_rab_id;
        j["qos_parameters"] = qos_parameters.toJson();

        // Format IP address
        if (transport_layer_address.size() == 4) {
            char ip_str[16];
            snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d",
                    transport_layer_address[0], transport_layer_address[1],
                    transport_layer_address[2], transport_layer_address[3]);
            j["transport_layer_address"] = ip_str;
        } else if (transport_layer_address.size() == 16) {
            // IPv6 - simplified representation
            j["transport_layer_address"] = "IPv6";
        }

        j["gtp_teid"] = gtp_teid;

        if (nas_pdu.has_value()) {
            j["nas_pdu_length"] = nas_pdu->size();
        }

        return j;
    }
};

/**
 * E-RAB Setup Item (Initial Context Setup Response)
 */
struct E_RAB_SetupItem {
    uint8_t e_rab_id;
    std::vector<uint8_t> transport_layer_address;  // IP address
    uint32_t gtp_teid;  // GTP TEID

    nlohmann::json toJson() const {
        nlohmann::json j;
        j["e_rab_id"] = e_rab_id;

        if (transport_layer_address.size() == 4) {
            char ip_str[16];
            snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d",
                    transport_layer_address[0], transport_layer_address[1],
                    transport_layer_address[2], transport_layer_address[3]);
            j["transport_layer_address"] = ip_str;
        }

        j["gtp_teid"] = gtp_teid;
        return j;
    }
};

/**
 * E-RAB Item (for releases)
 */
struct E_RAB_Item {
    uint8_t e_rab_id;
    std::optional<S1APCauseType> cause_type;
    std::optional<uint8_t> cause_value;

    nlohmann::json toJson() const {
        nlohmann::json j;
        j["e_rab_id"] = e_rab_id;
        if (cause_type.has_value()) {
            j["cause_type"] = static_cast<int>(cause_type.value());
        }
        if (cause_value.has_value()) {
            j["cause_value"] = cause_value.value();
        }
        return j;
    }
};

/**
 * UE Security Capabilities
 */
struct UESecurityCapabilities {
    uint16_t encryption_algorithms;  // Bitmap
    uint16_t integrity_algorithms;   // Bitmap

    nlohmann::json toJson() const {
        nlohmann::json j;
        j["encryption_algorithms"] = encryption_algorithms;
        j["integrity_algorithms"] = integrity_algorithms;
        return j;
    }
};

/**
 * S1AP Message Structure
 */
struct S1APMessage {
    // PDU Information
    S1APPDUType pdu_type;
    uint8_t procedure_code;
    S1APMessageType message_type;
    S1APCriticality criticality;

    // UE Identifiers (IE 8 and IE 0)
    std::optional<uint32_t> enb_ue_s1ap_id;  // IE 8: eNB-UE-S1AP-ID
    std::optional<uint32_t> mme_ue_s1ap_id;  // IE 0: MME-UE-S1AP-ID

    // NAS-PDU (IE 26) - embedded NAS message
    std::optional<std::vector<uint8_t>> nas_pdu;

    // Location Information
    std::optional<TrackingAreaIdentity> tai;         // IE 67: TAI
    std::optional<EUTRAN_CGI> eutran_cgi;           // IE 100: EUTRAN-CGI

    // Security
    std::optional<UESecurityCapabilities> ue_security_capabilities;  // IE 107

    // E-RAB Lists
    std::vector<E_RAB_ToBeSetupItem> e_rab_to_be_setup_list;
    std::vector<E_RAB_SetupItem> e_rab_setup_list;
    std::vector<E_RAB_Item> e_rab_list;  // For releases

    // Cause (IE 2) - for failures and releases
    std::optional<S1APCauseType> cause_type;
    std::optional<uint8_t> cause_value;

    // RRC Establishment Cause (IE 134) - for Initial UE Message
    std::optional<uint8_t> rrc_establishment_cause;

    // Additional fields for specific messages
    std::optional<std::vector<uint8_t>> source_to_target_transparent_container;
    std::optional<std::vector<uint8_t>> target_to_source_transparent_container;

    /**
     * Convert to JSON for visualization
     */
    nlohmann::json toJson() const {
        nlohmann::json j;

        j["pdu_type"] = static_cast<int>(pdu_type);
        j["procedure_code"] = procedure_code;
        j["message_type"] = static_cast<int>(message_type);
        j["criticality"] = static_cast<int>(criticality);

        if (enb_ue_s1ap_id.has_value()) {
            j["enb_ue_s1ap_id"] = enb_ue_s1ap_id.value();
        }
        if (mme_ue_s1ap_id.has_value()) {
            j["mme_ue_s1ap_id"] = mme_ue_s1ap_id.value();
        }
        if (nas_pdu.has_value()) {
            j["nas_pdu_present"] = true;
            j["nas_pdu_length"] = nas_pdu->size();
        }
        if (tai.has_value()) {
            j["tai"] = tai->toJson();
        }
        if (eutran_cgi.has_value()) {
            j["eutran_cgi"] = eutran_cgi->toJson();
        }
        if (ue_security_capabilities.has_value()) {
            j["ue_security_capabilities"] = ue_security_capabilities->toJson();
        }
        if (cause_type.has_value()) {
            j["cause_type"] = static_cast<int>(cause_type.value());
        }
        if (cause_value.has_value()) {
            j["cause_value"] = cause_value.value();
        }
        if (rrc_establishment_cause.has_value()) {
            j["rrc_establishment_cause"] = rrc_establishment_cause.value();
        }

        // E-RAB lists
        if (!e_rab_to_be_setup_list.empty()) {
            nlohmann::json erab_array = nlohmann::json::array();
            for (const auto& erab : e_rab_to_be_setup_list) {
                erab_array.push_back(erab.toJson());
            }
            j["e_rab_to_be_setup_list"] = erab_array;
        }

        if (!e_rab_setup_list.empty()) {
            nlohmann::json erab_array = nlohmann::json::array();
            for (const auto& erab : e_rab_setup_list) {
                erab_array.push_back(erab.toJson());
            }
            j["e_rab_setup_list"] = erab_array;
        }

        if (!e_rab_list.empty()) {
            nlohmann::json erab_array = nlohmann::json::array();
            for (const auto& erab : e_rab_list) {
                erab_array.push_back(erab.toJson());
            }
            j["e_rab_list"] = erab_array;
        }

        return j;
    }

    /**
     * Get human-readable message type name
     */
    std::string getMessageTypeName() const {
        switch (message_type) {
            case S1APMessageType::INITIAL_UE_MESSAGE:
                return "Initial UE Message";
            case S1APMessageType::DOWNLINK_NAS_TRANSPORT:
                return "Downlink NAS Transport";
            case S1APMessageType::UPLINK_NAS_TRANSPORT:
                return "Uplink NAS Transport";
            case S1APMessageType::INITIAL_CONTEXT_SETUP:
                return "Initial Context Setup";
            case S1APMessageType::UE_CONTEXT_RELEASE_REQUEST:
                return "UE Context Release Request";
            case S1APMessageType::UE_CONTEXT_RELEASE:
                return "UE Context Release";
            case S1APMessageType::PATH_SWITCH_REQUEST:
                return "Path Switch Request";
            case S1APMessageType::HANDOVER_PREPARATION:
                return "Handover Preparation";
            case S1APMessageType::HANDOVER_RESOURCE_ALLOCATION:
                return "Handover Resource Allocation";
            case S1APMessageType::HANDOVER_NOTIFICATION:
                return "Handover Notification";
            case S1APMessageType::E_RAB_SETUP:
                return "E-RAB Setup";
            case S1APMessageType::E_RAB_MODIFY:
                return "E-RAB Modify";
            case S1APMessageType::E_RAB_RELEASE:
                return "E-RAB Release";
            case S1APMessageType::S1_SETUP:
                return "S1 Setup";
            case S1APMessageType::ERROR_INDICATION:
                return "Error Indication";
            case S1APMessageType::RESET:
                return "Reset";
            case S1APMessageType::PAGING:
                return "Paging";
            default:
                return "Unknown";
        }
    }
};

} // namespace s1ap
} // namespace callflow
