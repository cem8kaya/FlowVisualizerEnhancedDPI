#include "protocol_parsers/ngap_parser.h"
#include "common/logger.h"
#include <cstring>
#include <arpa/inet.h>
#include <sstream>
#include <iomanip>

namespace callflow {

// ============================================================================
// NgapInformationElement Methods
// ============================================================================

nlohmann::json NgapInformationElement::toJson() const {
    nlohmann::json j;
    j["id"] = id;
    j["id_name"] = getIeName();
    j["criticality"] = static_cast<int>(criticality);
    j["value_length"] = value.size();
    return j;
}

std::string NgapInformationElement::getIeName() const {
    using asn1::NgapIeId;
    switch (static_cast<NgapIeId>(id)) {
        case NgapIeId::AMF_UE_NGAP_ID: return "AMF-UE-NGAP-ID";
        case NgapIeId::RAN_UE_NGAP_ID: return "RAN-UE-NGAP-ID";
        case NgapIeId::NAS_PDU: return "NAS-PDU";
        case NgapIeId::CAUSE: return "Cause";
        case NgapIeId::PDU_SESSION_RESOURCE_SETUP_LIST: return "PDU-Session-Resource-Setup-List";
        case NgapIeId::PDU_SESSION_RESOURCE_RELEASE_LIST: return "PDU-Session-Resource-Release-List";
        case NgapIeId::GUAMI: return "GUAMI";
        case NgapIeId::ALLOWED_NSSAI: return "Allowed-NSSAI";
        case NgapIeId::UE_AGGREGATE_MAXIMUM_BIT_RATE: return "UE-Aggregate-Maximum-Bit-Rate";
        case NgapIeId::CORE_NETWORK_ASSISTANCE_INFORMATION: return "Core-Network-Assistance-Information";
        case NgapIeId::PDU_SESSION_ID: return "PDU-Session-ID";
        case NgapIeId::QOS_FLOW_SETUP_REQUEST_LIST: return "QoS-Flow-Setup-Request-List";
        case NgapIeId::USER_LOCATION_INFORMATION: return "User-Location-Information";
        case NgapIeId::ROUTING_ID: return "Routing-ID";
        case NgapIeId::S_NSSAI: return "S-NSSAI";
        default: return "Unknown-IE-" + std::to_string(id);
    }
}

// ============================================================================
// NgapMessage Methods
// ============================================================================

nlohmann::json NgapMessage::toJson() const {
    nlohmann::json j;
    j["message_type"] = static_cast<int>(message_type);
    j["procedure_code"] = static_cast<int>(procedure_code);
    j["procedure_name"] = getProcedureName();
    j["criticality"] = static_cast<int>(criticality);

    // Add decoded fields
    if (ran_ue_ngap_id.has_value()) {
        j["ran_ue_ngap_id"] = ran_ue_ngap_id.value();
    }
    if (amf_ue_ngap_id.has_value()) {
        j["amf_ue_ngap_id"] = amf_ue_ngap_id.value();
    }
    if (pdu_session_id.has_value()) {
        j["pdu_session_id"] = pdu_session_id.value();
    }
    if (nas_pdu.has_value()) {
        j["nas_pdu_length"] = nas_pdu.value().size();
    }
    if (supi.has_value()) {
        j["supi"] = supi.value();
    }
    if (guami.has_value()) {
        j["guami"] = guami.value();
    }
    if (cause.has_value()) {
        j["cause"] = cause.value();
    }

    // Add IEs
    nlohmann::json ies_json = nlohmann::json::array();
    for (const auto& ie : ies) {
        ies_json.push_back(ie.toJson());
    }
    j["ies"] = ies_json;
    j["ie_count"] = ies.size();

    return j;
}

MessageType NgapMessage::getMessageType() const {
    using asn1::NgapProcedureCode;
    switch (procedure_code) {
        case NgapProcedureCode::INITIAL_UE_MESSAGE:
            return MessageType::NGAP_INITIAL_UE_MESSAGE;
        case NgapProcedureCode::DOWNLINK_NAS_TRANSPORT:
            return MessageType::NGAP_DOWNLINK_NAS_TRANSPORT;
        case NgapProcedureCode::UPLINK_NAS_TRANSPORT:
            return MessageType::NGAP_UPLINK_NAS_TRANSPORT;
        case NgapProcedureCode::PDU_SESSION_RESOURCE_SETUP:
            return MessageType::NGAP_PDU_SESSION_RESOURCE_SETUP_REQ;
        case NgapProcedureCode::PDU_SESSION_RESOURCE_RELEASE:
            return MessageType::NGAP_PDU_SESSION_RESOURCE_RELEASE;
        case NgapProcedureCode::HANDOVER_PREPARATION:
            return MessageType::NGAP_HANDOVER_PREPARATION;
        case NgapProcedureCode::PATH_SWITCH_REQUEST:
            return MessageType::NGAP_PATH_SWITCH_REQUEST;
        case NgapProcedureCode::NG_SETUP:
            return MessageType::NGAP_NG_SETUP;
        case NgapProcedureCode::AMF_CONFIGURATION_UPDATE:
            return MessageType::NGAP_AMF_CONFIGURATION_UPDATE;
        default:
            return MessageType::UNKNOWN;
    }
}

std::string NgapMessage::getProcedureName() const {
    using asn1::NgapProcedureCode;
    switch (procedure_code) {
        case NgapProcedureCode::AMF_CONFIGURATION_UPDATE: return "AMF-Configuration-Update";
        case NgapProcedureCode::AMF_STATUS_INDICATION: return "AMF-Status-Indication";
        case NgapProcedureCode::CELL_TRAFFIC_TRACE: return "Cell-Traffic-Trace";
        case NgapProcedureCode::DEACTIVATE_TRACE: return "Deactivate-Trace";
        case NgapProcedureCode::DOWNLINK_NAS_TRANSPORT: return "Downlink-NAS-Transport";
        case NgapProcedureCode::DOWNLINK_NON_UE_ASSOCIATED_NRPPA_TRANSPORT: return "Downlink-Non-UE-Associated-NRPPA-Transport";
        case NgapProcedureCode::DOWNLINK_RAN_CONFIGURATION_TRANSFER: return "Downlink-RAN-Configuration-Transfer";
        case NgapProcedureCode::DOWNLINK_RAN_STATUS_TRANSFER: return "Downlink-RAN-Status-Transfer";
        case NgapProcedureCode::DOWNLINK_UE_ASSOCIATED_NRPPA_TRANSPORT: return "Downlink-UE-Associated-NRPPA-Transport";
        case NgapProcedureCode::ERROR_INDICATION: return "Error-Indication";
        case NgapProcedureCode::HANDOVER_CANCEL: return "Handover-Cancel";
        case NgapProcedureCode::HANDOVER_NOTIFICATION: return "Handover-Notification";
        case NgapProcedureCode::HANDOVER_PREPARATION: return "Handover-Preparation";
        case NgapProcedureCode::HANDOVER_RESOURCE_ALLOCATION: return "Handover-Resource-Allocation";
        case NgapProcedureCode::INITIAL_CONTEXT_SETUP: return "Initial-Context-Setup";
        case NgapProcedureCode::INITIAL_UE_MESSAGE: return "Initial-UE-Message";
        case NgapProcedureCode::LOCATION_REPORTING_CONTROL: return "Location-Reporting-Control";
        case NgapProcedureCode::LOCATION_REPORTING_FAILURE_INDICATION: return "Location-Reporting-Failure-Indication";
        case NgapProcedureCode::LOCATION_REPORT: return "Location-Report";
        case NgapProcedureCode::NAS_NON_DELIVERY_INDICATION: return "NAS-Non-Delivery-Indication";
        case NgapProcedureCode::NG_RESET: return "NG-Reset";
        case NgapProcedureCode::NG_SETUP: return "NG-Setup";
        case NgapProcedureCode::OVERLOAD_START: return "Overload-Start";
        case NgapProcedureCode::OVERLOAD_STOP: return "Overload-Stop";
        case NgapProcedureCode::PAGING: return "Paging";
        case NgapProcedureCode::PATH_SWITCH_REQUEST: return "Path-Switch-Request";
        case NgapProcedureCode::PDU_SESSION_RESOURCE_MODIFY: return "PDU-Session-Resource-Modify";
        case NgapProcedureCode::PDU_SESSION_RESOURCE_MODIFY_INDICATION: return "PDU-Session-Resource-Modify-Indication";
        case NgapProcedureCode::PDU_SESSION_RESOURCE_NOTIFY: return "PDU-Session-Resource-Notify";
        case NgapProcedureCode::PDU_SESSION_RESOURCE_RELEASE: return "PDU-Session-Resource-Release";
        case NgapProcedureCode::PDU_SESSION_RESOURCE_SETUP: return "PDU-Session-Resource-Setup";
        case NgapProcedureCode::PRIVATE_MESSAGE: return "Private-Message";
        case NgapProcedureCode::PWS_CANCEL: return "PWS-Cancel";
        case NgapProcedureCode::PWS_FAILURE_INDICATION: return "PWS-Failure-Indication";
        case NgapProcedureCode::PWS_RESTART_INDICATION: return "PWS-Restart-Indication";
        case NgapProcedureCode::RAN_CONFIGURATION_UPDATE: return "RAN-Configuration-Update";
        case NgapProcedureCode::RAN_CONFIGURATION_UPDATE_ACKNOWLEDGE: return "RAN-Configuration-Update-Acknowledge";
        case NgapProcedureCode::RRC_INACTIVE_TRANSITION_REPORT: return "RRC-Inactive-Transition-Report";
        case NgapProcedureCode::REROUTE_NAS_REQUEST: return "Reroute-NAS-Request";
        case NgapProcedureCode::TRACE_FAILURE_INDICATION: return "Trace-Failure-Indication";
        case NgapProcedureCode::TRACE_START: return "Trace-Start";
        case NgapProcedureCode::UE_CONTEXT_MODIFICATION: return "UE-Context-Modification";
        case NgapProcedureCode::UE_CONTEXT_RELEASE: return "UE-Context-Release";
        case NgapProcedureCode::UE_CONTEXT_RESUME: return "UE-Context-Resume";
        case NgapProcedureCode::UE_CONTEXT_SUSPEND: return "UE-Context-Suspend";
        case NgapProcedureCode::UE_RADIO_CAPABILITY_CHECK: return "UE-Radio-Capability-Check";
        case NgapProcedureCode::UPLINK_NAS_TRANSPORT: return "Uplink-NAS-Transport";
        case NgapProcedureCode::UPLINK_NON_UE_ASSOCIATED_NRPPA_TRANSPORT: return "Uplink-Non-UE-Associated-NRPPA-Transport";
        case NgapProcedureCode::UPLINK_RAN_CONFIGURATION_TRANSFER: return "Uplink-RAN-Configuration-Transfer";
        case NgapProcedureCode::UPLINK_RAN_STATUS_TRANSFER: return "Uplink-RAN-Status-Transfer";
        case NgapProcedureCode::UPLINK_UE_ASSOCIATED_NRPPA_TRANSPORT: return "Uplink-UE-Associated-NRPPA-Transport";
        case NgapProcedureCode::WRITE_REPLACE_WARNING: return "Write-Replace-Warning";
        default: return "Unknown-Procedure-" + std::to_string(static_cast<int>(procedure_code));
    }
}

std::optional<std::string> NgapMessage::getUeIdentifier() const {
    // Use RAN UE NGAP ID as primary identifier
    if (ran_ue_ngap_id.has_value()) {
        return "NGAP-UE-" + std::to_string(ran_ue_ngap_id.value());
    }
    if (amf_ue_ngap_id.has_value()) {
        return "NGAP-UE-AMF-" + std::to_string(amf_ue_ngap_id.value());
    }
    if (supi.has_value()) {
        return supi.value();
    }
    return std::nullopt;
}

// ============================================================================
// NgapParser Methods
// ============================================================================

bool NgapParser::isNgap(const uint8_t* data, size_t len) {
    if (!data || len < 8) {
        return false;
    }

    // NGAP uses ASN.1 PER aligned encoding
    // First byte typically contains the message type
    uint8_t first_byte = data[0];

    // Check if it matches NGAP PDU choice pattern
    if ((first_byte & 0xE0) != 0x00 && (first_byte & 0xE0) != 0x20 &&
        (first_byte & 0xE0) != 0x40) {
        return false;
    }

    // Additional heuristic: procedure code should be valid (0-51)
    if (len > 1 && data[1] > 51) {
        return false;
    }

    return true;
}

std::optional<NgapMessage> NgapParser::parse(const uint8_t* data, size_t len) {
    if (!isNgap(data, len)) {
        LOG_DEBUG("Not a valid NGAP message");
        return std::nullopt;
    }

    size_t offset = 0;
    auto msg_opt = parsePdu(data, len, offset);
    if (!msg_opt.has_value()) {
        LOG_ERROR("Failed to parse NGAP PDU");
        return std::nullopt;
    }

    NgapMessage msg = msg_opt.value();

    // Extract common fields
    extractCommonFields(msg);

    LOG_DEBUG("Parsed NGAP message: " << msg.getProcedureName()
              << " with " << msg.ies.size() << " IEs");

    return msg;
}

std::optional<NgapMessage> NgapParser::parsePdu(const uint8_t* data, size_t len,
                                                 size_t& offset) {
    if (offset >= len) {
        return std::nullopt;
    }

    NgapMessage msg;

    // Byte 0: PDU choice (3 bits) + extension bit + length determinant
    uint8_t pdu_choice = (data[offset] >> 5) & 0x07;
    msg.message_type = static_cast<asn1::NgapMessageType>(pdu_choice);
    offset++;

    if (offset >= len) {
        return std::nullopt;
    }

    // Procedure code (typically 1 byte)
    msg.procedure_code = static_cast<asn1::NgapProcedureCode>(data[offset]);
    offset++;

    if (offset >= len) {
        return std::nullopt;
    }

    // Criticality (2 bits) + IE count length
    uint8_t crit_byte = data[offset];
    msg.criticality = static_cast<asn1::NgapCriticality>((crit_byte >> 6) & 0x03);
    offset++;

    // Parse IEs
    if (!parseIes(data, len, offset, msg.ies)) {
        LOG_ERROR("Failed to parse NGAP IEs");
        return std::nullopt;
    }

    return msg;
}

bool NgapParser::parseIes(const uint8_t* data, size_t len, size_t& offset,
                          std::vector<NgapInformationElement>& ies) {
    // Parse IE count (simplified - assumes small count)
    if (offset >= len) {
        return true;  // No IEs
    }

    // Try to parse IEs until we run out of data or hit an error
    while (offset < len) {
        size_t start_offset = offset;
        auto ie_opt = parseIe(data, len, offset);
        if (!ie_opt.has_value()) {
            // If we parsed at least some data, consider it successful
            if (offset > start_offset) {
                break;
            }
            return !ies.empty();  // Success if we got at least one IE
        }
        ies.push_back(ie_opt.value());
    }

    return true;
}

std::optional<NgapInformationElement> NgapParser::parseIe(const uint8_t* data, size_t len,
                                                           size_t& offset) {
    if (offset + 3 > len) {
        return std::nullopt;
    }

    NgapInformationElement ie;

    // IE ID (16 bits in PER)
    ie.id = (static_cast<uint16_t>(data[offset]) << 8) | data[offset + 1];
    offset += 2;

    // Criticality (2 bits)
    ie.criticality = static_cast<asn1::NgapCriticality>((data[offset] >> 6) & 0x03);
    offset++;

    // Length
    auto len_opt = decodeLength(data, len, offset);
    if (!len_opt.has_value()) {
        return std::nullopt;
    }

    size_t value_len = len_opt.value();
    if (offset + value_len > len) {
        return std::nullopt;
    }

    // Copy IE value
    ie.value.resize(value_len);
    std::memcpy(ie.value.data(), data + offset, value_len);
    offset += value_len;

    return ie;
}

void NgapParser::extractCommonFields(NgapMessage& msg) {
    using asn1::NgapIeId;

    for (const auto& ie : msg.ies) {
        switch (static_cast<NgapIeId>(ie.id)) {
            case NgapIeId::RAN_UE_NGAP_ID:
                msg.ran_ue_ngap_id = decodeUeNgapId(ie.value);
                break;
            case NgapIeId::AMF_UE_NGAP_ID:
                msg.amf_ue_ngap_id = decodeUeNgapId(ie.value);
                break;
            case NgapIeId::NAS_PDU:
                msg.nas_pdu = decodeNasPdu(ie.value);
                break;
            case NgapIeId::PDU_SESSION_ID:
                if (!ie.value.empty()) {
                    msg.pdu_session_id = ie.value[0];
                }
                break;
            case NgapIeId::GUAMI:
                msg.guami = decodeGuami(ie.value);
                break;
            case NgapIeId::CAUSE:
                if (!ie.value.empty()) {
                    msg.cause = ie.value[0];
                }
                break;
            default:
                break;
        }
    }
}

std::optional<uint64_t> NgapParser::decodeUeNgapId(const std::vector<uint8_t>& data) {
    if (data.empty()) {
        return std::nullopt;
    }

    // Decode up to 8 bytes as a 64-bit integer
    uint64_t value = 0;
    for (size_t i = 0; i < data.size() && i < 8; ++i) {
        value = (value << 8) | data[i];
    }
    return value;
}

std::optional<std::vector<uint8_t>> NgapParser::decodeNasPdu(const std::vector<uint8_t>& data) {
    if (data.empty()) {
        return std::nullopt;
    }

    // NAS PDU is typically OCTET STRING, so just return the data
    return data;
}

std::optional<std::string> NgapParser::decodeSupi(const std::vector<uint8_t>& data) {
    if (data.empty()) {
        return std::nullopt;
    }

    // SUPI can be IMSI-based or NAI-based
    // Simplified decoding - just convert to hex string for now
    std::ostringstream oss;
    oss << "SUPI-";
    for (size_t i = 0; i < data.size() && i < 8; ++i) {
        oss << std::hex << std::setfill('0') << std::setw(2)
            << static_cast<int>(data[i]);
    }
    return oss.str();
}

std::optional<std::string> NgapParser::decodeGuami(const std::vector<uint8_t>& data) {
    if (data.size() < 8) {
        return std::nullopt;
    }

    // GUAMI consists of PLMN identity (3 bytes) + AMF Region ID + AMF Set ID + AMF Pointer
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');

    // PLMN ID
    for (size_t i = 0; i < 3 && i < data.size(); ++i) {
        oss << std::setw(2) << static_cast<int>(data[i]);
    }

    return oss.str();
}

std::optional<size_t> NgapParser::decodeLength(const uint8_t* data, size_t len,
                                                size_t& offset) {
    if (offset >= len) {
        return std::nullopt;
    }

    uint8_t first_byte = data[offset];
    offset++;

    // ASN.1 PER aligned length encoding
    if ((first_byte & 0x80) == 0) {
        // Short form: 0-127 bytes
        return static_cast<size_t>(first_byte & 0x7F);
    } else if ((first_byte & 0xC0) == 0x80) {
        // Long form: 128-16383 bytes (2 bytes)
        if (offset >= len) {
            return std::nullopt;
        }
        uint8_t second_byte = data[offset];
        offset++;
        return static_cast<size_t>(((first_byte & 0x3F) << 8) | second_byte);
    } else {
        // Fragmented encoding not supported in this simplified implementation
        return std::nullopt;
    }
}

}  // namespace callflow
