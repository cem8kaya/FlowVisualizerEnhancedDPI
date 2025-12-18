#pragma once

#include <nlohmann/json.hpp>
#include <optional>
#include <vector>

#include "asn1c/ngap_asn1_wrapper.h"
#include "common/types.h"

namespace callflow {

/**
 * NGAP Information Element structure
 */
struct NgapInformationElement {
    uint16_t id;  // IE ID
    asn1::NgapCriticality criticality;
    std::vector<uint8_t> value;  // IE value (encoded)

    nlohmann::json toJson() const;
    std::string getIeName() const;
};

/**
 * NGAP message structure (5G control plane)
 */
struct NgapMessage {
    asn1::NgapMessageType message_type;
    asn1::NgapProcedureCode procedure_code;
    asn1::NgapCriticality criticality;
    std::vector<NgapInformationElement> ies;

    // Decoded common fields
    std::optional<uint64_t> ran_ue_ngap_id;
    std::optional<uint64_t> amf_ue_ngap_id;
    std::optional<uint8_t> pdu_session_id;
    std::optional<std::vector<uint8_t>> nas_pdu;
    std::optional<std::string> supi;   // 5G Subscription Permanent Identifier
    std::optional<std::string> guami;  // Globally Unique AMF Identifier
    std::optional<uint8_t> cause;

    nlohmann::json toJson() const;

    /**
     * Get message type for session correlation
     */
    MessageType getMessageType() const;

    /**
     * Get human-readable procedure name
     */
    std::string getProcedureName() const;

    /**
     * Get UE identifier for session tracking
     */
    std::optional<std::string> getUeIdentifier() const;
};

/**
 * NGAP protocol parser (3GPP TS 38.413)
 * Handles 5G control plane between gNB and AMF
 */
class NgapParser {
public:
    NgapParser() = default;
    ~NgapParser() = default;

    /**
     * Parse NGAP message from SCTP payload
     * @param data SCTP payload data
     * @param len Payload length
     * @return Parsed NGAP message or nullopt if parsing fails
     */
    std::optional<NgapMessage> parse(const uint8_t* data, size_t len);

    /**
     * Check if data appears to be an NGAP message
     * NGAP uses ASN.1 PER encoding (aligned variant)
     */
    static bool isNgap(const uint8_t* data, size_t len);

private:
    /**
     * Parse NGAP PDU header
     */
    std::optional<NgapMessage> parsePdu(const uint8_t* data, size_t len, size_t& offset);

    /**
     * Parse NGAP IEs
     */
    bool parseIes(const uint8_t* data, size_t len, size_t& offset,
                  std::vector<NgapInformationElement>& ies);

    /**
     * Parse single NGAP IE
     */
    std::optional<NgapInformationElement> parseIe(const uint8_t* data, size_t len, size_t& offset);

    /**
     * Extract common fields from IEs
     */
    void extractCommonFields(NgapMessage& msg);

    /**
     * Decode UE NGAP ID from IE value
     */
    static std::optional<uint64_t> decodeUeNgapId(const std::vector<uint8_t>& data);

    /**
     * Decode NAS PDU from IE value
     */
    static std::optional<std::vector<uint8_t>> decodeNasPdu(const std::vector<uint8_t>& data);

    /**
     * Decode SUPI (5G identifier) from IE value
     */
    static std::optional<std::string> decodeSupi(const std::vector<uint8_t>& data);

    /**
     * Decode GUAMI from IE value
     */
    static std::optional<std::string> decodeGuami(const std::vector<uint8_t>& data);

    /**
     * Decode length field (ASN.1 PER aligned)
     */
    static std::optional<size_t> decodeLength(const uint8_t* data, size_t len, size_t& offset);
};

}  // namespace callflow
