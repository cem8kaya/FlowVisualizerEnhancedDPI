#include "protocol_parsers/s1ap/s1ap_parser.h"

#include <cstring>

#include "common/logger.h"
#include "protocol_parsers/s1ap/s1ap_ie_parser.h"

namespace callflow {
namespace s1ap {

bool S1APParser::isS1AP(uint16_t port, uint32_t sctp_ppid) {
    return (port == constants::S1AP_PORT || port == constants::S1AP_PORT) &&
           sctp_ppid == constants::S1AP_SCTP_PPID;
}

std::optional<S1APMessage> S1APParser::parse(const uint8_t* data, size_t len) {
    if (!data || len < 4) {
        LOG_ERROR("S1AP: Invalid input data");
        stats_.parse_errors++;
        return std::nullopt;
    }

    S1APMessage msg;
    const uint8_t* ptr = data;
    size_t remaining = len;

    try {
        // S1AP PDU Structure (ASN.1 PER encoded):
        // 1. PDU type (CHOICE: initiatingMessage, successfulOutcome, unsuccessfulOutcome)
        // 2. Procedure code
        // 3. Criticality
        // 4. Protocol IEs (SEQUENCE OF)

        // Parse PDU type (first byte contains choice index)
        if (remaining < 1) {
            throw std::runtime_error("Not enough data for PDU type");
        }

        // PDU type is in the first byte (choice index)
        uint8_t pdu_choice = ptr[0];
        msg.pdu_type = static_cast<S1APPDUType>(pdu_choice & 0x03);
        ptr++;
        remaining--;

        // Parse Procedure Code (1 byte)
        if (remaining < 1) {
            throw std::runtime_error("Not enough data for procedure code");
        }
        msg.procedure_code = ptr[0];
        ptr++;
        remaining--;

        // Parse Criticality (1 byte, enumerated)
        if (remaining < 1) {
            throw std::runtime_error("Not enough data for criticality");
        }
        msg.criticality = static_cast<S1APCriticality>(ptr[0] & 0x03);
        ptr++;
        remaining--;

        // Map procedure code to message type
        msg.message_type = mapProcedureCodeToMessageType(msg.procedure_code, msg.pdu_type);

        LOG_DEBUG("S1AP: Parsing message type "
                  << static_cast<int>(msg.message_type)
                  << " (proc_code=" << static_cast<int>(msg.procedure_code) << ")");

        // Parse Protocol IEs (SEQUENCE OF ProtocolIE)
        // Skip to IE list (may have length encoding)
        if (remaining < 2) {
            throw std::runtime_error("Not enough data for IE list");
        }

        // Check for length encoding (may vary based on ASN.1 encoding)
        // For simplicity, we'll try to parse IEs directly

        // Parse IEs - each IE has: ID, Criticality, Value
        while (remaining >= 4) {
            // Save position for error recovery

            // IE ID (16-bit)
            uint16_t ie_id = (ptr[0] << 8) | ptr[1];
            ptr += 2;
            remaining -= 2;

            if (remaining < 1)
                break;

            // IE Criticality (encoded in 1 byte)
            // Unused: S1APCriticality ie_criticality = static_cast<S1APCriticality>(ptr[0] & 0x03);
            ptr++;
            remaining--;

            if (remaining < 2)
                break;

            // IE Value Length (variable encoding, simplified to 2 bytes for common cases)
            size_t ie_len = 0;
            if (ptr[0] & 0x80) {
                // Long form (multi-byte length)
                size_t len_bytes = ptr[0] & 0x7F;
                if (len_bytes > remaining || len_bytes > 4) {
                    LOG_WARN("S1AP: Invalid IE length encoding");
                    break;
                }
                ptr++;
                remaining--;
                for (size_t i = 0; i < len_bytes && i < 4; i++) {
                    ie_len = (ie_len << 8) | ptr[0];
                    ptr++;
                    remaining--;
                }
            } else {
                // Short form (single byte)
                ie_len = ptr[0];
                ptr++;
                remaining--;
            }

            if (ie_len > remaining) {
                LOG_WARN("S1AP: IE length " << ie_len << " exceeds remaining " << remaining);
                break;
            }

            // Parse specific IEs
            const uint8_t* ie_value = ptr;

            switch (ie_id) {
                case constants::IE_ID::MME_UE_S1AP_ID:
                    msg.mme_ue_s1ap_id = S1APIEParser::parseMME_UE_S1AP_ID(ie_value, ie_len);
                    LOG_DEBUG("S1AP: Parsed MME-UE-S1AP-ID = " << msg.mme_ue_s1ap_id.value_or(0));
                    break;

                case constants::IE_ID::ENB_UE_S1AP_ID:
                    msg.enb_ue_s1ap_id = S1APIEParser::parseENB_UE_S1AP_ID(ie_value, ie_len);
                    LOG_DEBUG("S1AP: Parsed eNB-UE-S1AP-ID = " << msg.enb_ue_s1ap_id.value_or(0));
                    break;

                case constants::IE_ID::NAS_PDU:
                    msg.nas_pdu = S1APIEParser::parseNAS_PDU(ie_value, ie_len);
                    if (msg.nas_pdu.has_value()) {
                        LOG_DEBUG("S1AP: Parsed NAS-PDU, length = " << msg.nas_pdu->size());
                        stats_.nas_pdus_extracted++;
                    }
                    break;

                case constants::IE_ID::TAI:
                    msg.tai = S1APIEParser::parseTAI(ie_value, ie_len);
                    if (msg.tai.has_value()) {
                        LOG_DEBUG("S1AP: Parsed TAI: PLMN=" << msg.tai->plmn_identity
                                                            << ", TAC=" << msg.tai->tac);
                    }
                    break;

                case constants::IE_ID::EUTRAN_CGI:
                    msg.eutran_cgi = S1APIEParser::parseEUTRAN_CGI(ie_value, ie_len);
                    if (msg.eutran_cgi.has_value()) {
                        LOG_DEBUG("S1AP: Parsed EUTRAN-CGI: PLMN="
                                  << msg.eutran_cgi->plmn_identity
                                  << ", CID=" << msg.eutran_cgi->cell_identity);
                    }
                    break;

                case constants::IE_ID::UE_SECURITY_CAPABILITIES:
                    msg.ue_security_capabilities =
                        S1APIEParser::parseUESecurityCapabilities(ie_value, ie_len);
                    break;

                case constants::IE_ID::CAUSE: {
                    auto cause = S1APIEParser::parseCause(ie_value, ie_len);
                    if (cause.has_value()) {
                        msg.cause_type = cause->first;
                        msg.cause_value = cause->second;
                    }
                } break;

                case constants::IE_ID::RRC_ESTABLISHMENT_CAUSE:
                    msg.rrc_establishment_cause =
                        S1APIEParser::parseRRCEstablishmentCause(ie_value, ie_len);
                    break;

                case constants::IE_ID::E_RAB_TO_BE_SETUP_LIST_CTXT_SU_REQ:
                    // Parse E-RAB list for Initial Context Setup Request
                    // This is a SEQUENCE OF, so we need to parse multiple items
                    {
                        const uint8_t* list_ptr = ie_value;
                        size_t list_remaining = ie_len;

                        // Skip SEQUENCE OF header and parse items
                        // Simplified: try to parse items until we run out of data
                        while (list_remaining > 4) {
                            auto erab =
                                S1APIEParser::parseE_RAB_ToBeSetupItem(list_ptr, list_remaining);
                            if (erab.has_value()) {
                                msg.e_rab_to_be_setup_list.push_back(erab.value());
                                stats_.e_rabs_extracted++;
                                // Move pointer (simplified - actual advancement depends on ASN.1
                                // encoding) For now, we'll break after first item to avoid
                                // complexity
                                break;
                            } else {
                                break;
                            }
                        }
                    }
                    break;

                case constants::IE_ID::E_RAB_SETUP_LIST_CTXT_SU_RES:
                    // Parse E-RAB list for Initial Context Setup Response
                    {
                        const uint8_t* list_ptr = ie_value;
                        size_t list_remaining = ie_len;

                        while (list_remaining > 4) {
                            auto erab =
                                S1APIEParser::parseE_RAB_SetupItem(list_ptr, list_remaining);
                            if (erab.has_value()) {
                                msg.e_rab_setup_list.push_back(erab.value());
                                break;  // Simplified
                            } else {
                                break;
                            }
                        }
                    }
                    break;

                default:
                    LOG_DEBUG("S1AP: Skipping IE " << ie_id);
                    break;
            }

            // Move to next IE
            ptr += ie_len;
            remaining -= ie_len;
        }

        // Update statistics
        stats_.messages_parsed++;

        switch (msg.message_type) {
            case S1APMessageType::INITIAL_UE_MESSAGE:
                stats_.initial_ue_messages++;
                break;
            case S1APMessageType::INITIAL_CONTEXT_SETUP:
                if (msg.pdu_type == S1APPDUType::INITIATING_MESSAGE) {
                    stats_.context_setup_requests++;
                }
                break;
            default:
                break;
        }

        return msg;

    } catch (const std::exception& e) {
        LOG_ERROR("S1AP: Parse exception: " << e.what());
        stats_.parse_errors++;
        return std::nullopt;
    }
}

S1APMessageType S1APParser::mapProcedureCodeToMessageType(uint8_t procedure_code,
                                                          S1APPDUType pdu_type) const {
    (void)pdu_type;  // Suppress unused parameter warning
    // Map procedure codes to message types
    // Note: Some procedure codes have different message types for request/response
    switch (procedure_code) {
        case 0:
            return S1APMessageType::HANDOVER_PREPARATION;
        case 1:
            return S1APMessageType::HANDOVER_RESOURCE_ALLOCATION;
        case 2:
            return S1APMessageType::HANDOVER_NOTIFICATION;
        case 3:
            return S1APMessageType::PATH_SWITCH_REQUEST;
        case 4:
            return S1APMessageType::HANDOVER_CANCEL;
        case 5:
            return S1APMessageType::E_RAB_SETUP;
        case 6:
            return S1APMessageType::E_RAB_MODIFY;
        case 7:
            return S1APMessageType::E_RAB_RELEASE;
        case 9:
            return S1APMessageType::INITIAL_CONTEXT_SETUP;
        case 10:
            return S1APMessageType::PAGING;
        case 11:
            return S1APMessageType::DOWNLINK_NAS_TRANSPORT;
        case 12:
            return S1APMessageType::INITIAL_UE_MESSAGE;
        case 13:
            return S1APMessageType::UPLINK_NAS_TRANSPORT;
        case 14:
            return S1APMessageType::RESET;
        case 15:
            return S1APMessageType::ERROR_INDICATION;
        case 16:
            return S1APMessageType::NAS_NON_DELIVERY_INDICATION;
        case 17:
            return S1APMessageType::S1_SETUP;
        case 18:
            return S1APMessageType::UE_CONTEXT_RELEASE_REQUEST;
        case 19:
            return S1APMessageType::DOWNLINK_S1_CDMA2000_TUNNELLING;
        case 20:
            return S1APMessageType::UPLINK_S1_CDMA2000_TUNNELLING;
        case 21:
            return S1APMessageType::UE_CONTEXT_MODIFICATION;
        case 22:
            return S1APMessageType::UE_CAPABILITY_INFO_INDICATION;
        case 23:
            return S1APMessageType::UE_CONTEXT_RELEASE;
        case 24:
            return S1APMessageType::ENB_STATUS_TRANSFER;
        case 25:
            return S1APMessageType::MME_STATUS_TRANSFER;
        case 26:
            return S1APMessageType::DEACTIVATE_TRACE;
        case 27:
            return S1APMessageType::TRACE_START;
        case 28:
            return S1APMessageType::TRACE_FAILURE_INDICATION;
        case 29:
            return S1APMessageType::ENB_CONFIGURATION_UPDATE;
        case 30:
            return S1APMessageType::MME_CONFIGURATION_UPDATE;
        case 31:
            return S1APMessageType::LOCATION_REPORTING_CONTROL;
        case 32:
            return S1APMessageType::LOCATION_REPORTING_FAILURE_INDICATION;
        case 33:
            return S1APMessageType::LOCATION_REPORT;
        case 34:
            return S1APMessageType::OVERLOAD_START;
        case 35:
            return S1APMessageType::OVERLOAD_STOP;
        case 36:
            return S1APMessageType::WRITE_REPLACE_WARNING;
        case 37:
            return S1APMessageType::ENB_DIRECT_INFORMATION_TRANSFER;
        case 38:
            return S1APMessageType::MME_DIRECT_INFORMATION_TRANSFER;
        default:
            LOG_WARN("S1AP: Unknown procedure code " << static_cast<int>(procedure_code));
            return S1APMessageType::UNKNOWN;
    }
}

}  // namespace s1ap
}  // namespace callflow
