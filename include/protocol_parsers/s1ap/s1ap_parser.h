#pragma once

#include "protocol_parsers/s1ap/s1ap_types.h"
#include <cstdint>
#include <optional>
#include <vector>
#include <memory>

namespace callflow {
namespace s1ap {

/**
 * S1AP Parser
 *
 * Parses S1 Application Protocol messages (3GPP TS 36.413).
 * S1AP runs over SCTP with PPID=18 on port 36412.
 *
 * This is a simplified manual parser focusing on critical IEs
 * for MVP. Full ASN.1 PER compliance can be added later using asn1c.
 *
 * Performance Targets:
 * - Parse rate: 100,000+ messages/sec
 * - Memory: < 500 bytes per message
 * - Latency: < 10µs per message
 */
class S1APParser {
public:
    S1APParser() = default;
    ~S1APParser() = default;

    /**
     * Parse S1AP message
     *
     * @param data Raw S1AP message data
     * @param len Length of data
     * @return Parsed S1APMessage or nullopt if parsing fails
     */
    std::optional<S1APMessage> parse(const uint8_t* data, size_t len);

    /**
     * Check if packet is S1AP based on SCTP port and PPID
     *
     * @param port SCTP port (36412 for S1AP)
     * @param sctp_ppid SCTP Payload Protocol Identifier (18 for S1AP)
     * @return true if packet is S1AP
     */
    static bool isS1AP(uint16_t port, uint32_t sctp_ppid);

    /**
     * Get statistics
     */
    struct Statistics {
        uint64_t messages_parsed;
        uint64_t parse_errors;
        uint64_t initial_ue_messages;
        uint64_t context_setup_requests;
        uint64_t nas_pdus_extracted;
        uint64_t e_rabs_extracted;
    };

    const Statistics& getStatistics() const { return stats_; }
    void resetStatistics() { stats_ = Statistics{}; }

private:
    Statistics stats_{};

    // Parser helper functions
    S1APMessageType mapProcedureCodeToMessageType(uint8_t procedure_code, S1APPDUType pdu_type) const;

    friend class S1APIEParser;
};

/**
 * S1AP Protocol Constants
 */
namespace constants {
    constexpr uint16_t S1AP_PORT = 36412;
    constexpr uint32_t S1AP_SCTP_PPID = 18;

    // S1AP Information Element IDs (3GPP TS 36.413)
    namespace IE_ID {
        constexpr uint16_t MME_UE_S1AP_ID = 0;
        constexpr uint16_t HANDOVER_TYPE = 1;
        constexpr uint16_t CAUSE = 2;
        constexpr uint16_t SOURCE_ID = 3;
        constexpr uint16_t TARGET_ID = 4;
        constexpr uint16_t ENB_UE_S1AP_ID = 8;
        constexpr uint16_t E_RAB_SUBJECT_TO_DATA_FORWARDING_LIST = 12;
        constexpr uint16_t E_RAB_TO_RELEASE_LIST_HO_CMD = 13;
        constexpr uint16_t E_RAB_DATA_FORWARDING_ITEM = 14;
        constexpr uint16_t E_RAB_RELEASE_LIST_BEARER_REL_COMP = 15;
        constexpr uint16_t E_RAB_TO_BE_SETUP_LIST_BEARER_SU_REQ = 16;
        constexpr uint16_t E_RAB_TO_BE_SETUP_LIST_CTXT_SU_REQ = 24;
        constexpr uint16_t NAS_PDU = 26;
        constexpr uint16_t E_RAB_ADMITTED_LIST = 27;
        constexpr uint16_t E_RAB_FAILED_TO_SETUP_LIST_CTXT_SU_RES = 28;
        constexpr uint16_t E_RAB_TO_BE_RELEASED_LIST = 29;
        constexpr uint16_t E_RAB_SETUP_LIST_BEARER_SU_RES = 33;
        constexpr uint16_t E_RAB_SETUP_LIST_CTXT_SU_RES = 50;
        constexpr uint16_t SECURITY_CONTEXT = 53;
        constexpr uint16_t HANDOVER_RESTRICTION_LIST = 54;
        constexpr uint16_t UE_PAGING_ID = 58;
        constexpr uint16_t PAGING_DRX = 59;
        constexpr uint16_t TAI_LIST = 62;
        constexpr uint16_t TAI = 67;
        constexpr uint16_t E_RAB_FAILED_TO_SETUP_LIST_HO_REQ_ACK = 68;
        constexpr uint16_t S_TMSI = 96;
        constexpr uint16_t EUTRAN_CGI = 100;
        constexpr uint16_t UE_SECURITY_CAPABILITIES = 107;
        constexpr uint16_t CSG_ID = 109;
        constexpr uint16_t CSG_ID_LIST = 110;
        constexpr uint16_t RRC_ESTABLISHMENT_CAUSE = 134;
        constexpr uint16_t SOURCE_TO_TARGET_TRANSPARENT_CONTAINER = 104;
        constexpr uint16_t TARGET_TO_SOURCE_TRANSPARENT_CONTAINER = 105;
    }
}

} // namespace s1ap
} // namespace callflow
