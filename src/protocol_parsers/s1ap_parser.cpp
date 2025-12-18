#include "protocol_parsers/s1ap_parser.h"
#include "thirdparty/asn1c/s1ap_asn1_wrapper.h"
#include "common/logger.h"
#include <cstring>
#include <sstream>
#include <iomanip>

namespace callflow {

// ============================================================================
// Helper Functions for String Conversion
// ============================================================================

std::string s1apProcedureCodeToString(S1apProcedureCode code) {
    switch (code) {
        case S1apProcedureCode::HANDOVER_PREPARATION: return "Handover-Preparation";
        case S1apProcedureCode::HANDOVER_RESOURCE_ALLOCATION: return "Handover-Resource-Allocation";
        case S1apProcedureCode::HANDOVER_NOTIFICATION: return "Handover-Notification";
        case S1apProcedureCode::PATH_SWITCH_REQUEST: return "Path-Switch-Request";
        case S1apProcedureCode::HANDOVER_CANCEL: return "Handover-Cancel";
        case S1apProcedureCode::INITIAL_CONTEXT_SETUP: return "Initial-Context-Setup";
        case S1apProcedureCode::PAGING: return "Paging";
        case S1apProcedureCode::DOWNLINK_NAS_TRANSPORT: return "Downlink-NAS-Transport";
        case S1apProcedureCode::INITIAL_UE_MESSAGE: return "Initial-UE-Message";
        case S1apProcedureCode::UPLINK_NAS_TRANSPORT: return "Uplink-NAS-Transport";
        case S1apProcedureCode::RESET: return "Reset";
        case S1apProcedureCode::ERROR_INDICATION: return "Error-Indication";
        case S1apProcedureCode::S1_SETUP: return "S1-Setup";
        case S1apProcedureCode::UE_CONTEXT_RELEASE_REQUEST: return "UE-Context-Release-Request";
        case S1apProcedureCode::UE_CONTEXT_MODIFICATION: return "UE-Context-Modification";
        case S1apProcedureCode::UE_CONTEXT_RELEASE: return "UE-Context-Release";
        case S1apProcedureCode::E_RAB_SETUP: return "E-RAB-Setup";
        case S1apProcedureCode::E_RAB_MODIFY: return "E-RAB-Modify";
        case S1apProcedureCode::E_RAB_RELEASE: return "E-RAB-Release";
        default: return "Unknown-" + std::to_string(static_cast<uint8_t>(code));
    }
}

std::string s1apMessageTypeToString(S1apMessageType type) {
    switch (type) {
        case S1apMessageType::INITIATING_MESSAGE: return "Initiating-Message";
        case S1apMessageType::SUCCESSFUL_OUTCOME: return "Successful-Outcome";
        case S1apMessageType::UNSUCCESSFUL_OUTCOME: return "Unsuccessful-Outcome";
        default: return "Unknown";
    }
}

std::string s1apCriticalityToString(S1apCriticality crit) {
    switch (crit) {
        case S1apCriticality::REJECT: return "reject";
        case S1apCriticality::IGNORE: return "ignore";
        case S1apCriticality::NOTIFY: return "notify";
        default: return "unknown";
    }
}

std::string s1apIeTypeToString(S1apIeType type) {
    switch (type) {
        case S1apIeType::MME_UE_S1AP_ID: return "MME-UE-S1AP-ID";
        case S1apIeType::ENB_UE_S1AP_ID: return "ENB-UE-S1AP-ID";
        case S1apIeType::NAS_PDU: return "NAS-PDU";
        case S1apIeType::IMSI: return "IMSI";
        case S1apIeType::CAUSE: return "Cause";
        case S1apIeType::E_RAB_SETUP_LIST_CTXT_SU_REQ: return "E-RAB-Setup-List-CtxtSuReq";
        case S1apIeType::E_RAB_SETUP_LIST_CTXT_SU_RES: return "E-RAB-Setup-List-CtxtSuRes";
        case S1apIeType::E_RAB_TO_BE_SETUP_LIST: return "E-RAB-ToBeSetup-List";
        case S1apIeType::E_RAB_ADMITTED_LIST: return "E-RAB-Admitted-List";
        case S1apIeType::TAI: return "TAI";
        case S1apIeType::EUTRAN_CGI: return "EUTRAN-CGI";
        case S1apIeType::UE_SECURITY_CAPABILITIES: return "UE-Security-Capabilities";
        case S1apIeType::UE_AGGREGATE_MAXIMUM_BIT_RATE: return "UE-Aggregate-Maximum-Bit-Rate";
        default: return "Unknown-" + std::to_string(static_cast<uint8_t>(type));
    }
}

// ============================================================================
// S1apInformationElement Methods
// ============================================================================

std::string S1apInformationElement::getTypeName() const {
    return s1apIeTypeToString(type);
}

nlohmann::json S1apInformationElement::toJson() const {
    nlohmann::json j;
    j["type"] = static_cast<uint8_t>(type);
    j["type_name"] = getTypeName();
    j["criticality"] = s1apCriticalityToString(criticality);
    j["value_length"] = value.size();

    // Represent value as hex for debugging
    std::ostringstream hex_stream;
    hex_stream << std::hex << std::setfill('0');
    for (size_t i = 0; i < std::min(value.size(), size_t(32)); ++i) {
        hex_stream << std::setw(2) << static_cast<int>(value[i]);
    }
    if (value.size() > 32) {
        hex_stream << "...";
    }
    j["value_hex"] = hex_stream.str();

    return j;
}

// ============================================================================
// S1apMessage Methods
// ============================================================================

std::string S1apMessage::getProcedureCodeName() const {
    return s1apProcedureCodeToString(procedure_code);
}

std::string S1apMessage::getMessageTypeName() const {
    return s1apMessageTypeToString(message_type);
}

nlohmann::json S1apMessage::toJson() const {
    nlohmann::json j;
    j["message_type"] = getMessageTypeName();
    j["procedure_code"] = static_cast<uint8_t>(procedure_code);
    j["procedure_code_name"] = getProcedureCodeName();
    j["criticality"] = s1apCriticalityToString(criticality);

    // Add decoded fields
    if (enb_ue_s1ap_id.has_value()) {
        j["enb_ue_s1ap_id"] = enb_ue_s1ap_id.value();
    }
    if (mme_ue_s1ap_id.has_value()) {
        j["mme_ue_s1ap_id"] = mme_ue_s1ap_id.value();
    }
    if (imsi.has_value()) {
        j["imsi"] = imsi.value();
    }
    if (nas_pdu.has_value()) {
        j["nas_pdu_length"] = nas_pdu.value().size();
    }

    // Add IEs
    j["ie_count"] = ies.size();
    nlohmann::json ies_json = nlohmann::json::array();
    for (const auto& ie : ies) {
        ies_json.push_back(ie.toJson());
    }
    j["ies"] = ies_json;

    return j;
}

MessageType S1apMessage::getMessageType() const {
    // Map S1AP procedures to callflow message types
    // For now, return UNKNOWN - can be extended based on needs
    return MessageType::UNKNOWN;
}

// ============================================================================
// S1apParser Methods
// ============================================================================

bool S1apParser::isS1ap(const uint8_t* data, size_t len) {
    if (!data || len < 3) {
        return false;
    }

    // S1AP uses ASN.1 PER encoding
    // First byte typically has high bits set for CHOICE encoding
    // This is a heuristic - not foolproof

    // Check if first byte looks like a CHOICE (typically 0x00 - 0x02 for message type)
    if (data[0] > 0x02) {
        return false;
    }

    // Procedure codes are 0-255, typically < 50 for common procedures
    if (data[1] > 100) {
        return false;
    }

    return true;
}

std::optional<S1apMessage> S1apParser::parse(const uint8_t* data, size_t len) {
    if (!isS1ap(data, len)) {
        LOG_DEBUG("Not a valid S1AP message");
        return std::nullopt;
    }

    S1apMessage msg;

    // Parse PDU header using ASN.1 decoder
    auto pdu_opt = asn1::decodeS1apPdu(data, len);
    if (!pdu_opt.has_value()) {
        LOG_ERROR("Failed to decode S1AP PDU header");
        return std::nullopt;
    }

    const auto& pdu = pdu_opt.value();

    // Set message fields
    msg.message_type = static_cast<S1apMessageType>(pdu.choice);
    msg.procedure_code = static_cast<S1apProcedureCode>(pdu.procedure_code);
    msg.criticality = static_cast<S1apCriticality>(pdu.criticality);

    // Extract IEs from PDU value
    auto ie_tuples = asn1::extractS1apIes(pdu.value.data(), pdu.value.size());

    for (const auto& ie_tuple : ie_tuples) {
        S1apInformationElement ie;
        ie.type = static_cast<S1apIeType>(ie_tuple.id);
        ie.criticality = static_cast<S1apCriticality>(ie_tuple.criticality);
        ie.value = ie_tuple.value;
        msg.ies.push_back(ie);
    }

    // Extract common fields
    extractCommonFields(msg);

    LOG_DEBUG("Parsed S1AP message: " << msg.getProcedureCodeName()
              << " (" << msg.getMessageTypeName() << ") with "
              << msg.ies.size() << " IEs");

    return msg;
}

void S1apParser::extractCommonFields(S1apMessage& msg) {
    extractUeIds(msg);
    extractImsi(msg);
    extractNasPdu(msg);
}

void S1apParser::extractUeIds(S1apMessage& msg) {
    for (const auto& ie : msg.ies) {
        if (ie.type == S1apIeType::ENB_UE_S1AP_ID) {
            auto id_opt = asn1::decodeUeId(ie.value.data(), ie.value.size());
            if (id_opt.has_value()) {
                msg.enb_ue_s1ap_id = id_opt.value();
                LOG_DEBUG("Extracted ENB-UE-S1AP-ID: " << id_opt.value());
            }
        } else if (ie.type == S1apIeType::MME_UE_S1AP_ID) {
            auto id_opt = asn1::decodeUeId(ie.value.data(), ie.value.size());
            if (id_opt.has_value()) {
                msg.mme_ue_s1ap_id = id_opt.value();
                LOG_DEBUG("Extracted MME-UE-S1AP-ID: " << id_opt.value());
            }
        }
    }
}

void S1apParser::extractImsi(S1apMessage& msg) {
    for (const auto& ie : msg.ies) {
        if (ie.type == S1apIeType::IMSI) {
            auto imsi_opt = asn1::decodeImsi(ie.value.data(), ie.value.size());
            if (imsi_opt.has_value()) {
                msg.imsi = imsi_opt.value();
                LOG_DEBUG("Extracted IMSI: " << imsi_opt.value());
            }
        }
    }
}

void S1apParser::extractNasPdu(S1apMessage& msg) {
    for (const auto& ie : msg.ies) {
        if (ie.type == S1apIeType::NAS_PDU) {
            auto nas_opt = asn1::decodeNasPdu(ie.value.data(), ie.value.size());
            if (nas_opt.has_value()) {
                msg.nas_pdu = nas_opt.value();
                LOG_DEBUG("Extracted NAS-PDU: " << nas_opt.value().size() << " bytes");
            }
        }
    }
}

}  // namespace callflow
