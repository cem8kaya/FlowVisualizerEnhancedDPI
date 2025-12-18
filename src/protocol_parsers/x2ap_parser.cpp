#include "protocol_parsers/x2ap_parser.h"
#include "common/logger.h"
#include <cstring>
#include <arpa/inet.h>
#include <sstream>
#include <iomanip>

namespace callflow {

// ============================================================================
// X2apInformationElement Methods
// ============================================================================

nlohmann::json X2apInformationElement::toJson() const {
    nlohmann::json j;
    j["id"] = id;
    j["id_name"] = getIeName();
    j["criticality"] = static_cast<int>(criticality);
    j["value_length"] = value.size();
    return j;
}

std::string X2apInformationElement::getIeName() const {
    using asn1::X2apIeId;
    switch (static_cast<X2apIeId>(id)) {
        case X2apIeId::OLD_ENB_UE_X2AP_ID: return "Old-eNB-UE-X2AP-ID";
        case X2apIeId::NEW_ENB_UE_X2AP_ID: return "New-eNB-UE-X2AP-ID";
        case X2apIeId::CAUSE: return "Cause";
        case X2apIeId::TARGET_CELL_ID: return "Target-Cell-ID";
        case X2apIeId::GUMMEI: return "GUMMEI";
        case X2apIeId::UE_CONTEXT_INFORMATION: return "UE-Context-Information";
        case X2apIeId::UE_HISTORY_INFORMATION: return "UE-History-Information";
        case X2apIeId::E_RABs_TO_BE_SETUP: return "E-RABs-To-Be-Setup";
        case X2apIeId::E_RABs_ADMITTED: return "E-RABs-Admitted";
        case X2apIeId::GLOBAL_ENB_ID: return "Global-eNB-ID";
        case X2apIeId::ENB_NAME: return "eNB-Name";
        case X2apIeId::SERVED_CELLS: return "Served-Cells";
        case X2apIeId::CSG_MEMBERSHIP_STATUS: return "CSG-Membership-Status";
        default: return "Unknown-IE-" + std::to_string(id);
    }
}

// ============================================================================
// X2apMessage Methods
// ============================================================================

nlohmann::json X2apMessage::toJson() const {
    nlohmann::json j;
    j["message_type"] = static_cast<int>(message_type);
    j["procedure_code"] = static_cast<int>(procedure_code);
    j["procedure_name"] = getProcedureName();
    j["criticality"] = static_cast<int>(criticality);

    // Add decoded fields
    if (old_enb_ue_x2ap_id.has_value()) {
        j["old_enb_ue_x2ap_id"] = old_enb_ue_x2ap_id.value();
    }
    if (new_enb_ue_x2ap_id.has_value()) {
        j["new_enb_ue_x2ap_id"] = new_enb_ue_x2ap_id.value();
    }
    if (target_cell_id.has_value()) {
        j["target_cell_id"] = target_cell_id.value();
    }
    if (handover_cause.has_value()) {
        j["handover_cause"] = handover_cause.value();
    }
    if (global_enb_id.has_value()) {
        j["global_enb_id"] = global_enb_id.value();
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

MessageType X2apMessage::getMessageType() const {
    using asn1::X2apProcedureCode;
    switch (procedure_code) {
        case X2apProcedureCode::HANDOVER_PREPARATION:
            return MessageType::X2AP_HANDOVER_PREPARATION;
        case X2apProcedureCode::HANDOVER_CANCEL:
            return MessageType::X2AP_HANDOVER_CANCEL;
        case X2apProcedureCode::SN_STATUS_TRANSFER:
            return MessageType::X2AP_SN_STATUS_TRANSFER;
        case X2apProcedureCode::UE_CONTEXT_RELEASE:
            return MessageType::X2AP_UE_CONTEXT_RELEASE;
        case X2apProcedureCode::X2_SETUP:
            return MessageType::X2AP_SETUP;
        case X2apProcedureCode::RESET:
            return MessageType::X2AP_RESET;
        case X2apProcedureCode::ENB_CONFIGURATION_UPDATE:
            return MessageType::X2AP_ENB_CONFIGURATION_UPDATE;
        case X2apProcedureCode::RESOURCE_STATUS_REPORTING:
            return MessageType::X2AP_RESOURCE_STATUS_REPORTING;
        case X2apProcedureCode::CELL_ACTIVATION:
            return MessageType::X2AP_CELL_ACTIVATION;
        default:
            return MessageType::UNKNOWN;
    }
}

std::string X2apMessage::getProcedureName() const {
    using asn1::X2apProcedureCode;
    switch (procedure_code) {
        case X2apProcedureCode::HANDOVER_PREPARATION: return "Handover-Preparation";
        case X2apProcedureCode::HANDOVER_CANCEL: return "Handover-Cancel";
        case X2apProcedureCode::LOAD_INDICATION: return "Load-Indication";
        case X2apProcedureCode::ERROR_INDICATION: return "Error-Indication";
        case X2apProcedureCode::SN_STATUS_TRANSFER: return "SN-Status-Transfer";
        case X2apProcedureCode::UE_CONTEXT_RELEASE: return "UE-Context-Release";
        case X2apProcedureCode::X2_SETUP: return "X2-Setup";
        case X2apProcedureCode::RESET: return "Reset";
        case X2apProcedureCode::ENB_CONFIGURATION_UPDATE: return "eNB-Configuration-Update";
        case X2apProcedureCode::RESOURCE_STATUS_REPORTING: return "Resource-Status-Reporting";
        case X2apProcedureCode::MOBILITY_SETTINGS_CHANGE: return "Mobility-Settings-Change";
        case X2apProcedureCode::RADIO_LINK_FAILURE_INDICATION: return "Radio-Link-Failure-Indication";
        case X2apProcedureCode::HANDOVER_REPORT: return "Handover-Report";
        case X2apProcedureCode::CELL_ACTIVATION: return "Cell-Activation";
        default: return "Unknown-Procedure-" + std::to_string(static_cast<int>(procedure_code));
    }
}

std::optional<std::string> X2apMessage::getUeIdentifier() const {
    // Use old_enb_ue_x2ap_id as primary identifier, fallback to new_enb_ue_x2ap_id
    if (old_enb_ue_x2ap_id.has_value()) {
        return "X2AP-UE-" + std::to_string(old_enb_ue_x2ap_id.value());
    }
    if (new_enb_ue_x2ap_id.has_value()) {
        return "X2AP-UE-" + std::to_string(new_enb_ue_x2ap_id.value());
    }
    return std::nullopt;
}

// ============================================================================
// X2apParser Methods
// ============================================================================

bool X2apParser::isX2ap(const uint8_t* data, size_t len) {
    if (!data || len < 8) {
        return false;
    }

    // X2AP uses ASN.1 PER encoding
    // First byte typically contains the message type (0x00, 0x20, or 0x40)
    // for InitiatingMessage, SuccessfulOutcome, or UnsuccessfulOutcome
    uint8_t first_byte = data[0];

    // Check if it matches X2AP PDU choice pattern
    if ((first_byte & 0xE0) != 0x00 && (first_byte & 0xE0) != 0x20 &&
        (first_byte & 0xE0) != 0x40) {
        return false;
    }

    return true;
}

std::optional<X2apMessage> X2apParser::parse(const uint8_t* data, size_t len) {
    if (!isX2ap(data, len)) {
        LOG_DEBUG("Not a valid X2AP message");
        return std::nullopt;
    }

    size_t offset = 0;
    auto msg_opt = parsePdu(data, len, offset);
    if (!msg_opt.has_value()) {
        LOG_ERROR("Failed to parse X2AP PDU");
        return std::nullopt;
    }

    X2apMessage msg = msg_opt.value();

    // Extract common fields
    extractCommonFields(msg);

    LOG_DEBUG("Parsed X2AP message: " << msg.getProcedureName()
              << " with " << msg.ies.size() << " IEs");

    return msg;
}

std::optional<X2apMessage> X2apParser::parsePdu(const uint8_t* data, size_t len,
                                                 size_t& offset) {
    if (offset >= len) {
        return std::nullopt;
    }

    X2apMessage msg;

    // Byte 0: PDU choice (3 bits) + extension bit + length determinant
    uint8_t pdu_choice = (data[offset] >> 5) & 0x07;
    msg.message_type = static_cast<asn1::X2apMessageType>(pdu_choice);
    offset++;

    if (offset >= len) {
        return std::nullopt;
    }

    // Procedure code (typically 1 byte)
    msg.procedure_code = static_cast<asn1::X2apProcedureCode>(data[offset]);
    offset++;

    if (offset >= len) {
        return std::nullopt;
    }

    // Criticality (2 bits) + IE count length
    uint8_t crit_byte = data[offset];
    msg.criticality = static_cast<asn1::X2apCriticality>((crit_byte >> 6) & 0x03);
    offset++;

    // Parse IEs
    if (!parseIes(data, len, offset, msg.ies)) {
        LOG_ERROR("Failed to parse X2AP IEs");
        return std::nullopt;
    }

    return msg;
}

bool X2apParser::parseIes(const uint8_t* data, size_t len, size_t& offset,
                          std::vector<X2apInformationElement>& ies) {
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

std::optional<X2apInformationElement> X2apParser::parseIe(const uint8_t* data, size_t len,
                                                           size_t& offset) {
    if (offset + 3 > len) {
        return std::nullopt;
    }

    X2apInformationElement ie;

    // IE ID (16 bits in PER)
    ie.id = (static_cast<uint16_t>(data[offset]) << 8) | data[offset + 1];
    offset += 2;

    // Criticality (2 bits)
    ie.criticality = static_cast<asn1::X2apCriticality>((data[offset] >> 6) & 0x03);
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

void X2apParser::extractCommonFields(X2apMessage& msg) {
    using asn1::X2apIeId;

    for (const auto& ie : msg.ies) {
        switch (static_cast<X2apIeId>(ie.id)) {
            case X2apIeId::OLD_ENB_UE_X2AP_ID:
                msg.old_enb_ue_x2ap_id = decodeUeX2apId(ie.value);
                break;
            case X2apIeId::NEW_ENB_UE_X2AP_ID:
                msg.new_enb_ue_x2ap_id = decodeUeX2apId(ie.value);
                break;
            case X2apIeId::TARGET_CELL_ID:
                msg.target_cell_id = decodeCellId(ie.value);
                break;
            case X2apIeId::CAUSE:
                if (!ie.value.empty()) {
                    msg.handover_cause = ie.value[0];
                }
                break;
            case X2apIeId::GLOBAL_ENB_ID:
                msg.global_enb_id = decodeGlobalEnbId(ie.value);
                break;
            default:
                break;
        }
    }
}

std::optional<uint32_t> X2apParser::decodeUeX2apId(const std::vector<uint8_t>& data) {
    if (data.size() < 4) {
        // Try to decode from available bytes
        if (data.empty()) {
            return std::nullopt;
        }
        uint32_t value = 0;
        for (size_t i = 0; i < data.size() && i < 4; ++i) {
            value = (value << 8) | data[i];
        }
        return value;
    }

    uint32_t value;
    std::memcpy(&value, data.data(), 4);
    return ntohl(value);
}

std::optional<uint32_t> X2apParser::decodeCellId(const std::vector<uint8_t>& data) {
    if (data.size() < 4) {
        return std::nullopt;
    }

    // Cell ID is typically 28 bits within the encoded structure
    uint32_t value;
    std::memcpy(&value, data.data(), 4);
    return ntohl(value) & 0x0FFFFFFF;
}

std::optional<std::string> X2apParser::decodeGlobalEnbId(const std::vector<uint8_t>& data) {
    if (data.size() < 8) {
        return std::nullopt;
    }

    // Global eNB ID consists of PLMN identity (3 bytes) + eNB ID (20 or 28 bits)
    std::ostringstream oss;

    // PLMN ID (MCC + MNC)
    if (data.size() >= 3) {
        // Decode PLMN (simplified)
        oss << std::hex << std::setfill('0');
        oss << std::setw(2) << static_cast<int>(data[0]);
        oss << std::setw(2) << static_cast<int>(data[1]);
        oss << std::setw(2) << static_cast<int>(data[2]);
    }

    return oss.str();
}

std::optional<size_t> X2apParser::decodeLength(const uint8_t* data, size_t len,
                                                size_t& offset) {
    if (offset >= len) {
        return std::nullopt;
    }

    uint8_t first_byte = data[offset];
    offset++;

    // ASN.1 PER length encoding
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
