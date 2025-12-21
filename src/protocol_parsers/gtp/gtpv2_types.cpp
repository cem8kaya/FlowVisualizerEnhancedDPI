#include "protocol_parsers/gtp/gtpv2_types.h"

#include <iomanip>
#include <sstream>

namespace callflow {
namespace gtp {

// ============================================================================
// GtpV2IEHeader Methods
// ============================================================================

nlohmann::json GtpV2IEHeader::toJson() const {
    nlohmann::json j;
    j["type"] = static_cast<uint8_t>(type);
    j["type_name"] = getIETypeName(type);
    j["length"] = length;
    j["instance"] = instance;
    j["cr_flag"] = cr_flag;
    return j;
}

// ============================================================================
// GtpV2IMSI Methods
// ============================================================================

nlohmann::json GtpV2IMSI::toJson() const {
    nlohmann::json j;
    j["imsi"] = imsi;
    return j;
}

// ============================================================================
// GtpV2FTEID Methods
// ============================================================================

nlohmann::json GtpV2FTEID::toJson() const {
    nlohmann::json j;
    j["interface_type"] = static_cast<uint8_t>(interface_type);
    j["interface_type_name"] = getInterfaceTypeName();
    j["teid"] = teid;
    if (ipv4_address.has_value()) {
        j["ipv4_address"] = ipv4_address.value();
    }
    if (ipv6_address.has_value()) {
        j["ipv6_address"] = ipv6_address.value();
    }
    return j;
}

std::string GtpV2FTEID::getInterfaceTypeName() const {
    switch (interface_type) {
        case FTEIDInterfaceType::S1_U_ENODEB_GTP_U:
            return "S1-U eNodeB GTP-U";
        case FTEIDInterfaceType::S1_U_SGW_GTP_U:
            return "S1-U SGW GTP-U";
        case FTEIDInterfaceType::S12_RNC_GTP_U:
            return "S12 RNC GTP-U";
        case FTEIDInterfaceType::S12_SGW_GTP_U:
            return "S12 SGW GTP-U";
        case FTEIDInterfaceType::S5_S8_SGW_GTP_U:
            return "S5/S8 SGW GTP-U";
        case FTEIDInterfaceType::S5_S8_PGW_GTP_U:
            return "S5/S8 PGW GTP-U";
        case FTEIDInterfaceType::S5_S8_SGW_GTP_C:
            return "S5/S8 SGW GTP-C";
        case FTEIDInterfaceType::S5_S8_PGW_GTP_C:
            return "S5/S8 PGW GTP-C";
        case FTEIDInterfaceType::S5_S8_SGW_PMIPV6:
            return "S5/S8 SGW PMIPv6";
        case FTEIDInterfaceType::S5_S8_PGW_PMIPV6:
            return "S5/S8 PGW PMIPv6";
        case FTEIDInterfaceType::S11_MME_GTP_C:
            return "S11 MME GTP-C";
        case FTEIDInterfaceType::S11_S4_SGW_GTP_C:
            return "S11/S4 SGW GTP-C";
        case FTEIDInterfaceType::S10_MME_GTP_C:
            return "S10 MME GTP-C";
        case FTEIDInterfaceType::S3_MME_GTP_C:
            return "S3 MME GTP-C";
        case FTEIDInterfaceType::S3_SGSN_GTP_C:
            return "S3 SGSN GTP-C";
        case FTEIDInterfaceType::S4_SGSN_GTP_U:
            return "S4 SGSN GTP-U";
        case FTEIDInterfaceType::S4_SGW_GTP_U:
            return "S4 SGW GTP-U";
        case FTEIDInterfaceType::S4_SGSN_GTP_C:
            return "S4 SGSN GTP-C";
        case FTEIDInterfaceType::S16_SGSN_GTP_C:
            return "S16 SGSN GTP-C";
        case FTEIDInterfaceType::S2B_EPDG_GTP_C:
            return "S2b ePDG GTP-C";
        case FTEIDInterfaceType::S2B_U_EPDG_GTP_U:
            return "S2b-U ePDG GTP-U";
        case FTEIDInterfaceType::S2B_PGW_GTP_C:
            return "S2b PGW GTP-C";
        case FTEIDInterfaceType::S2B_U_PGW_GTP_U:
            return "S2b-U PGW GTP-U";
        case FTEIDInterfaceType::S2A_TWAN_GTP_U:
            return "S2a TWAN GTP-U";
        case FTEIDInterfaceType::S2A_TWAN_GTP_C:
            return "S2a TWAN GTP-C";
        case FTEIDInterfaceType::S2A_PGW_GTP_C:
            return "S2a PGW GTP-C";
        case FTEIDInterfaceType::S2A_PGW_GTP_U:
            return "S2a PGW GTP-U";
        default:
            return "Unknown-" + std::to_string(static_cast<uint8_t>(interface_type));
    }
}

// ============================================================================
// GtpV2BearerQoS Methods
// ============================================================================

nlohmann::json GtpV2BearerQoS::toJson() const {
    nlohmann::json j;
    j["pci"] = pci;
    j["pl"] = pl;
    j["pvi"] = pvi;
    j["qci"] = qci;
    j["qci_name"] = getQCIName();
    j["max_bitrate_uplink"] = max_bitrate_uplink;
    j["max_bitrate_downlink"] = max_bitrate_downlink;
    j["guaranteed_bitrate_uplink"] = guaranteed_bitrate_uplink;
    j["guaranteed_bitrate_downlink"] = guaranteed_bitrate_downlink;
    return j;
}

std::string GtpV2BearerQoS::getQCIName() const {
    switch (qci) {
        case 1:
            return "Conversational Voice";
        case 2:
            return "Conversational Video (Live Streaming)";
        case 3:
            return "Real Time Gaming, V2X messages";
        case 4:
            return "Non-Conversational Video (Buffered Streaming)";
        case 5:
            return "IMS Signalling";
        case 6:
            return "Video (Buffered Streaming), TCP-based (e.g., www, e-mail, chat, ftp, p2p file "
                   "sharing, progressive video, etc.)";
        case 7:
            return "Voice, Video (Live Streaming), Interactive Gaming";
        case 8:
            return "Video (Buffered Streaming), TCP-based (e.g., www, e-mail, chat, ftp, p2p file "
                   "sharing, progressive video, etc.)";
        case 9:
            return "Video (Buffered Streaming), TCP-based (e.g., www, e-mail, chat, ftp, p2p file "
                   "sharing, progressive video, etc.)";
        default:
            if (qci >= 128 && qci <= 254) {
                return "Operator-specific-" + std::to_string(qci);
            }
            return "Reserved-" + std::to_string(qci);
    }
}

// ============================================================================
// GtpV2PDNAddressAllocation Methods
// ============================================================================

nlohmann::json GtpV2PDNAddressAllocation::toJson() const {
    nlohmann::json j;
    j["pdn_type"] = static_cast<uint8_t>(pdn_type);
    j["pdn_type_name"] = getPDNTypeName(pdn_type);
    if (ipv4_address.has_value()) {
        j["ipv4_address"] = ipv4_address.value();
    }
    if (ipv6_address.has_value()) {
        j["ipv6_address"] = ipv6_address.value();
    }
    if (ipv6_prefix_length.has_value()) {
        j["ipv6_prefix_length"] = ipv6_prefix_length.value();
    }
    return j;
}

// ============================================================================
// GtpV2BearerContext Methods
// ============================================================================

nlohmann::json GtpV2BearerContext::toJson() const {
    nlohmann::json j;
    if (eps_bearer_id.has_value()) {
        j["eps_bearer_id"] = eps_bearer_id.value();
    }
    if (qos.has_value()) {
        j["qos"] = qos.value().toJson();
    }
    if (!fteids.empty()) {
        nlohmann::json fteids_json = nlohmann::json::array();
        for (const auto& fteid : fteids) {
            fteids_json.push_back(fteid.toJson());
        }
        j["fteids"] = fteids_json;
    }
    if (charging_id.has_value()) {
        j["charging_id"] = charging_id.value();
    }
    if (cause.has_value()) {
        j["cause"] = static_cast<uint8_t>(cause.value());
    }
    if (bearer_flags.has_value()) {
        j["bearer_flags"] = bearer_flags.value();
    }
    return j;
}

// ============================================================================
// GtpV2Cause Methods
// ============================================================================

nlohmann::json GtpV2Cause::toJson() const {
    nlohmann::json j;
    j["cause_value"] = static_cast<uint8_t>(cause_value);
    j["cause_name"] = getCauseName();
    j["pce"] = pce;
    j["bce"] = bce;
    j["cs"] = cs;
    if (offending_ie_type.has_value()) {
        j["offending_ie_type"] = static_cast<uint8_t>(offending_ie_type.value());
        j["offending_ie_type_name"] = getIETypeName(offending_ie_type.value());
    }
    if (offending_ie_length.has_value()) {
        j["offending_ie_length"] = offending_ie_length.value();
    }
    if (offending_ie_instance.has_value()) {
        j["offending_ie_instance"] = offending_ie_instance.value();
    }
    return j;
}

std::string GtpV2Cause::getCauseName() const {
    switch (cause_value) {
        case CauseValue::REQUEST_ACCEPTED:
            return "Request accepted";
        case CauseValue::REQUEST_ACCEPTED_PARTIALLY:
            return "Request accepted partially";
        case CauseValue::NEW_PDN_TYPE_DUE_TO_NETWORK_PREFERENCE:
            return "New PDN type due to network preference";
        case CauseValue::NEW_PDN_TYPE_DUE_TO_SINGLE_ADDRESS_BEARER_ONLY:
            return "New PDN type due to single address bearer only";
        case CauseValue::CONTEXT_NOT_FOUND:
            return "Context not found";
        case CauseValue::INVALID_MESSAGE_FORMAT:
            return "Invalid message format";
        case CauseValue::VERSION_NOT_SUPPORTED_BY_NEXT_PEER:
            return "Version not supported by next peer";
        case CauseValue::INVALID_LENGTH:
            return "Invalid length";
        case CauseValue::SERVICE_NOT_SUPPORTED:
            return "Service not supported";
        case CauseValue::MANDATORY_IE_INCORRECT:
            return "Mandatory IE incorrect";
        case CauseValue::MANDATORY_IE_MISSING:
            return "Mandatory IE missing";
        case CauseValue::SYSTEM_FAILURE:
            return "System failure";
        case CauseValue::NO_RESOURCES_AVAILABLE:
            return "No resources available";
        case CauseValue::SEMANTIC_ERROR_IN_THE_TFT_OPERATION:
            return "Semantic error in TFT operation";
        case CauseValue::SYNTACTIC_ERROR_IN_THE_TFT_OPERATION:
            return "Syntactic error in TFT operation";
        case CauseValue::SEMANTIC_ERRORS_IN_PACKET_FILTER:
            return "Semantic errors in packet filter";
        case CauseValue::SYNTACTIC_ERRORS_IN_PACKET_FILTER:
            return "Syntactic errors in packet filter";
        case CauseValue::MISSING_OR_UNKNOWN_APN:
            return "Missing or unknown APN";
        case CauseValue::GRE_KEY_NOT_FOUND:
            return "GRE key not found";
        case CauseValue::RELOCATION_FAILURE:
            return "Relocation failure";
        case CauseValue::DENIED_IN_RAT:
            return "Denied in RAT";
        case CauseValue::PREFERRED_PDN_TYPE_NOT_SUPPORTED:
            return "Preferred PDN type not supported";
        case CauseValue::ALL_DYNAMIC_ADDRESSES_ARE_OCCUPIED:
            return "All dynamic addresses are occupied";
        case CauseValue::UE_CONTEXT_WITHOUT_TFT_ALREADY_ACTIVATED:
            return "UE context without TFT already activated";
        case CauseValue::PROTOCOL_TYPE_NOT_SUPPORTED:
            return "Protocol type not supported";
        case CauseValue::UE_NOT_RESPONDING:
            return "UE not responding";
        case CauseValue::UE_REFUSES:
            return "UE refuses";
        case CauseValue::SERVICE_DENIED:
            return "Service denied";
        case CauseValue::UNABLE_TO_PAGE_UE:
            return "Unable to page UE";
        case CauseValue::NO_MEMORY_AVAILABLE:
            return "No memory available";
        case CauseValue::USER_AUTHENTICATION_FAILED:
            return "User authentication failed";
        case CauseValue::APN_ACCESS_DENIED_NO_SUBSCRIPTION:
            return "APN access denied - no subscription";
        case CauseValue::REQUEST_REJECTED:
            return "Request rejected";
        case CauseValue::P_TMSI_SIGNATURE_MISMATCH:
            return "P-TMSI signature mismatch";
        default:
            return "Unknown-" + std::to_string(static_cast<uint8_t>(cause_value));
    }
}

// ============================================================================
// GtpV2AMBR Methods
// ============================================================================

nlohmann::json GtpV2AMBR::toJson() const {
    nlohmann::json j;
    j["uplink_kbps"] = uplink;
    j["downlink_kbps"] = downlink;
    return j;
}

// ============================================================================
// GtpV2ServingNetwork Methods
// ============================================================================

nlohmann::json GtpV2ServingNetwork::toJson() const {
    nlohmann::json j;
    j["mcc"] = mcc;
    j["mnc"] = mnc;
    j["plmn_id"] = getPlmnId();
    return j;
}

std::string GtpV2ServingNetwork::getPlmnId() const {
    return mcc + mnc;
}

// ============================================================================
// GtpV2ULI Methods
// ============================================================================

nlohmann::json GtpV2ULI::toJson() const {
    nlohmann::json j;
    j["cgi_present"] = cgi_present;
    j["sai_present"] = sai_present;
    j["rai_present"] = rai_present;
    j["tai_present"] = tai_present;
    j["ecgi_present"] = ecgi_present;
    j["lai_present"] = lai_present;

    if (tai_present) {
        nlohmann::json tai;
        if (tai_mcc.has_value())
            tai["mcc"] = tai_mcc.value();
        if (tai_mnc.has_value())
            tai["mnc"] = tai_mnc.value();
        if (tai_tac.has_value())
            tai["tac"] = tai_tac.value();
        j["tai"] = tai;
    }

    if (ecgi_present) {
        nlohmann::json ecgi;
        if (ecgi_mcc.has_value())
            ecgi["mcc"] = ecgi_mcc.value();
        if (ecgi_mnc.has_value())
            ecgi["mnc"] = ecgi_mnc.value();
        if (ecgi_eci.has_value())
            ecgi["eci"] = ecgi_eci.value();
        j["ecgi"] = ecgi;
    }

    return j;
}

// ============================================================================
// GtpV2Indication Methods
// ============================================================================

nlohmann::json GtpV2Indication::toJson() const {
    nlohmann::json j;
    j["flags"] = flags;
    std::ostringstream oss;
    oss << "0x" << std::hex << std::setfill('0') << std::setw(16) << flags;
    j["flags_hex"] = oss.str();
    return j;
}

// ============================================================================
// Helper Functions
// ============================================================================

std::string getIETypeName(GtpV2IEType type) {
    switch (type) {
        case GtpV2IEType::RESERVED:
            return "Reserved";
        case GtpV2IEType::IMSI:
            return "IMSI";
        case GtpV2IEType::CAUSE:
            return "Cause";
        case GtpV2IEType::RECOVERY:
            return "Recovery";
        case GtpV2IEType::STN_SR:
            return "STN-SR";
        case GtpV2IEType::APN:
            return "APN";
        case GtpV2IEType::AMBR:
            return "AMBR";
        case GtpV2IEType::EPS_BEARER_ID:
            return "EPS-Bearer-ID";
        case GtpV2IEType::IP_ADDRESS_V4:
            return "IP-Address";
        case GtpV2IEType::MEI:
            return "MEI";
        case GtpV2IEType::MSISDN:
            return "MSISDN";
        case GtpV2IEType::INDICATION:
            return "Indication";
        case GtpV2IEType::PCO:
            return "PCO";
        case GtpV2IEType::PAA:
            return "PAA";
        case GtpV2IEType::BEARER_QOS:
            return "Bearer-QoS";
        case GtpV2IEType::FLOW_QOS:
            return "Flow-QoS";
        case GtpV2IEType::RAT_TYPE:
            return "RAT-Type";
        case GtpV2IEType::SERVING_NETWORK:
            return "Serving-Network";
        case GtpV2IEType::BEARER_TFT:
            return "Bearer-TFT";
        case GtpV2IEType::TAD:
            return "TAD";
        case GtpV2IEType::ULI:
            return "ULI";
        case GtpV2IEType::F_TEID:
            return "F-TEID";
        case GtpV2IEType::TMSI:
            return "TMSI";
        case GtpV2IEType::GLOBAL_CN_ID:
            return "Global-CN-ID";
        case GtpV2IEType::S103PDF:
            return "S103PDF";
        case GtpV2IEType::S1UDF:
            return "S1UDF";
        case GtpV2IEType::DELAY_VALUE:
            return "Delay-Value";
        case GtpV2IEType::BEARER_CONTEXT:
            return "Bearer-Context";
        case GtpV2IEType::CHARGING_ID:
            return "Charging-ID";
        case GtpV2IEType::CHARGING_CHARACTERISTICS:
            return "Charging-Characteristics";
        case GtpV2IEType::TRACE_INFORMATION:
            return "Trace-Information";
        case GtpV2IEType::BEARER_FLAGS:
            return "Bearer-Flags";
        case GtpV2IEType::PDN_TYPE:
            return "PDN-Type";
        case GtpV2IEType::PTI:
            return "PTI";
        case GtpV2IEType::DRX_PARAMETER:
            return "DRX-Parameter";
        case GtpV2IEType::UE_NETWORK_CAPABILITY:
            return "UE-Network-Capability";
        case GtpV2IEType::MM_CONTEXT:
            return "MM-Context";
        case GtpV2IEType::PDN_CONNECTION:
            return "PDN-Connection";
        case GtpV2IEType::PDU_NUMBERS:
            return "PDU-Numbers";
        case GtpV2IEType::P_TMSI:
            return "P-TMSI";
        case GtpV2IEType::P_TMSI_SIGNATURE:
            return "P-TMSI-Signature";
        case GtpV2IEType::HOP_COUNTER:
            return "Hop-Counter";
        case GtpV2IEType::UE_TIME_ZONE:
            return "UE-Time-Zone";
        case GtpV2IEType::TRACE_REFERENCE:
            return "Trace-Reference";
        case GtpV2IEType::COMPLETE_REQUEST_MESSAGE:
            return "Complete-Request-Message";
        case GtpV2IEType::GUTI:
            return "GUTI";
        case GtpV2IEType::F_CONTAINER:
            return "F-Container";
        case GtpV2IEType::F_CAUSE:
            return "F-Cause";
        case GtpV2IEType::PLMN_ID:
            return "PLMN-ID";
        case GtpV2IEType::TARGET_IDENTIFICATION:
            return "Target-Identification";
        case GtpV2IEType::PACKET_FLOW_ID:
            return "Packet-Flow-ID";
        case GtpV2IEType::RAB_CONTEXT:
            return "RAB-Context";
        case GtpV2IEType::SOURCE_RNC_PDCP_CONTEXT_INFO:
            return "Source-RNC-PDCP-Context-Info";
        case GtpV2IEType::PORT_NUMBER:
            return "Port-Number";
        case GtpV2IEType::APN_RESTRICTION:
            return "APN-Restriction";
        case GtpV2IEType::SELECTION_MODE:
            return "Selection-Mode";
        case GtpV2IEType::SOURCE_IDENTIFICATION:
            return "Source-Identification";
        case GtpV2IEType::CHANGE_REPORTING_ACTION:
            return "Change-Reporting-Action";
        case GtpV2IEType::FQ_CSID:
            return "FQ-CSID";
        case GtpV2IEType::CHANNEL:
            return "Channel";
        case GtpV2IEType::EMLPP_PRIORITY:
            return "EMLPP-Priority";
        case GtpV2IEType::NODE_TYPE:
            return "Node-Type";
        case GtpV2IEType::NODE_IDENTIFIER:
            return "Node-Identifier / FQDN";
        case GtpV2IEType::TI:
            return "TI";
        case GtpV2IEType::MBMS_SESSION_DURATION:
            return "MBMS-Session-Duration";
        case GtpV2IEType::MBMS_SERVICE_AREA:
            return "MBMS-Service-Area";
        case GtpV2IEType::MBMS_SESSION_IDENTIFIER:
            return "MBMS-Session-Identifier";
        case GtpV2IEType::MBMS_FLOW_IDENTIFIER:
            return "MBMS-Flow-Identifier";
        case GtpV2IEType::MBMS_IP_MULTICAST_DISTRIBUTION:
            return "MBMS-IP-Multicast-Distribution";
        case GtpV2IEType::MBMS_DISTRIBUTION_ACKNOWLEDGE:
            return "MBMS-Distribution-Acknowledge";
        case GtpV2IEType::RFSP_INDEX:
            return "RFSP-Index";
        case GtpV2IEType::UCI:
            return "UCI";
        case GtpV2IEType::CSG_INFORMATION_REPORTING_ACTION:
            return "CSG-Information-Reporting-Action";
        case GtpV2IEType::CSG_ID:
            return "CSG-ID";
        case GtpV2IEType::CMI:
            return "CMI";
        case GtpV2IEType::SERVICE_INDICATOR:
            return "Service-Indicator";
        case GtpV2IEType::DETACH_TYPE:
            return "Detach-Type";
        case GtpV2IEType::LDN:
            return "LDN";
        case GtpV2IEType::NODE_FEATURES:
            return "Node-Features";
        case GtpV2IEType::MBMS_TIME_TO_DATA_TRANSFER:
            return "MBMS-Time-To-Data-Transfer";
        case GtpV2IEType::THROTTLING:
            return "Throttling";
        case GtpV2IEType::ARP:
            return "ARP";
        case GtpV2IEType::EPC_TIMER:
            return "EPC-Timer";
        case GtpV2IEType::SIGNALLING_PRIORITY_INDICATION:
            return "Signalling-Priority-Indication";
        case GtpV2IEType::TMGI:
            return "TMGI";
        case GtpV2IEType::ADDITIONAL_MM_CONTEXT_FOR_SRVCC:
            return "Additional-MM-Context-For-SRVCC";
        case GtpV2IEType::ADDITIONAL_FLAGS_FOR_SRVCC:
            return "Additional-Flags-For-SRVCC";
        case GtpV2IEType::MDT_CONFIGURATION:
            return "MDT-Configuration";
        case GtpV2IEType::APCO:
            return "APCO";
        case GtpV2IEType::ABSOLUTE_TIME_OF_MBMS_DATA_TRANSFER:
            return "Absolute-Time-Of-MBMS-Data-Transfer";
        case GtpV2IEType::PRIVATE_EXTENSION:
            return "Private-Extension";
        default:
            return "Unknown-" + std::to_string(static_cast<uint8_t>(type));
    }
}

std::string getMessageTypeName(GtpV2MessageType type) {
    switch (type) {
        case GtpV2MessageType::ECHO_REQUEST:
            return "Echo-Request";
        case GtpV2MessageType::ECHO_RESPONSE:
            return "Echo-Response";
        case GtpV2MessageType::VERSION_NOT_SUPPORTED_INDICATION:
            return "Version-Not-Supported-Indication";
        case GtpV2MessageType::CREATE_SESSION_REQUEST:
            return "Create-Session-Request";
        case GtpV2MessageType::CREATE_SESSION_RESPONSE:
            return "Create-Session-Response";
        case GtpV2MessageType::MODIFY_BEARER_REQUEST:
            return "Modify-Bearer-Request";
        case GtpV2MessageType::MODIFY_BEARER_RESPONSE:
            return "Modify-Bearer-Response";
        case GtpV2MessageType::DELETE_SESSION_REQUEST:
            return "Delete-Session-Request";
        case GtpV2MessageType::DELETE_SESSION_RESPONSE:
            return "Delete-Session-Response";
        case GtpV2MessageType::CHANGE_NOTIFICATION_REQUEST:
            return "Change-Notification-Request";
        case GtpV2MessageType::CHANGE_NOTIFICATION_RESPONSE:
            return "Change-Notification-Response";
        case GtpV2MessageType::MODIFY_BEARER_COMMAND:
            return "Modify-Bearer-Command";
        case GtpV2MessageType::MODIFY_BEARER_FAILURE_INDICATION:
            return "Modify-Bearer-Failure-Indication";
        case GtpV2MessageType::DELETE_BEARER_COMMAND:
            return "Delete-Bearer-Command";
        case GtpV2MessageType::DELETE_BEARER_FAILURE_INDICATION:
            return "Delete-Bearer-Failure-Indication";
        case GtpV2MessageType::BEARER_RESOURCE_COMMAND:
            return "Bearer-Resource-Command";
        case GtpV2MessageType::BEARER_RESOURCE_FAILURE_INDICATION:
            return "Bearer-Resource-Failure-Indication";
        case GtpV2MessageType::DOWNLINK_DATA_NOTIFICATION_FAILURE_INDICATION:
            return "Downlink-Data-Notification-Failure-Indication";
        case GtpV2MessageType::CREATE_BEARER_REQUEST:
            return "Create-Bearer-Request";
        case GtpV2MessageType::CREATE_BEARER_RESPONSE:
            return "Create-Bearer-Response";
        case GtpV2MessageType::UPDATE_BEARER_REQUEST:
            return "Update-Bearer-Request";
        case GtpV2MessageType::UPDATE_BEARER_RESPONSE:
            return "Update-Bearer-Response";
        case GtpV2MessageType::DELETE_BEARER_REQUEST:
            return "Delete-Bearer-Request";
        case GtpV2MessageType::DELETE_BEARER_RESPONSE:
            return "Delete-Bearer-Response";
        case GtpV2MessageType::DOWNLINK_DATA_NOTIFICATION:
            return "Downlink-Data-Notification";
        case GtpV2MessageType::DOWNLINK_DATA_NOTIFICATION_ACKNOWLEDGE:
            return "Downlink-Data-Notification-Acknowledge";
        case GtpV2MessageType::MODIFY_ACCESS_BEARERS_REQUEST:
            return "Modify-Access-Bearers-Request";
        case GtpV2MessageType::MODIFY_ACCESS_BEARERS_RESPONSE:
            return "Modify-Access-Bearers-Response";
        default:
            return "Unknown-" + std::to_string(static_cast<uint8_t>(type));
    }
}

std::string getRATTypeName(RATType rat) {
    switch (rat) {
        case RATType::UTRAN:
            return "UTRAN";
        case RATType::GERAN:
            return "GERAN";
        case RATType::WLAN:
            return "WLAN";
        case RATType::GAN:
            return "GAN";
        case RATType::HSPA_EVOLUTION:
            return "HSPA-Evolution";
        case RATType::EUTRAN:
            return "E-UTRAN";
        case RATType::VIRTUAL:
            return "Virtual";
        case RATType::EUTRAN_NB_IOT:
            return "E-UTRAN-NB-IoT";
        case RATType::LTE_M:
            return "LTE-M";
        case RATType::NR:
            return "NR";
        default:
            return "Unknown-" + std::to_string(static_cast<uint8_t>(rat));
    }
}

std::string getPDNTypeName(PDNType pdn) {
    switch (pdn) {
        case PDNType::IPv4:
            return "IPv4";
        case PDNType::IPv6:
            return "IPv6";
        case PDNType::IPv4v6:
            return "IPv4v6";
        case PDNType::NON_IP:
            return "Non-IP";
        default:
            return "Unknown-" + std::to_string(static_cast<uint8_t>(pdn));
    }
}

}  // namespace gtp
}  // namespace callflow
