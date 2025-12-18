#pragma once

#include "common/types.h"
#include "thirdparty/asn1c/x2ap_asn1_wrapper.h"
#include <optional>
#include <vector>
#include <nlohmann/json.hpp>

namespace callflow {

/**
 * X2AP Information Element structure
 */
struct X2apInformationElement {
    uint16_t id;                      // IE ID
    asn1::X2apCriticality criticality;
    std::vector<uint8_t> value;       // IE value (encoded)

    nlohmann::json toJson() const;
    std::string getIeName() const;
};

/**
 * X2AP message structure
 */
struct X2apMessage {
    asn1::X2apMessageType message_type;
    asn1::X2apProcedureCode procedure_code;
    asn1::X2apCriticality criticality;
    std::vector<X2apInformationElement> ies;

    // Decoded common fields
    std::optional<uint32_t> old_enb_ue_x2ap_id;
    std::optional<uint32_t> new_enb_ue_x2ap_id;
    std::optional<uint32_t> target_cell_id;
    std::optional<uint8_t> handover_cause;
    std::optional<std::string> global_enb_id;

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
 * X2AP protocol parser (3GPP TS 36.423)
 * Handles LTE handover and inter-eNodeB communication
 */
class X2apParser {
public:
    X2apParser() = default;
    ~X2apParser() = default;

    /**
     * Parse X2AP message from SCTP payload
     * @param data SCTP payload data
     * @param len Payload length
     * @return Parsed X2AP message or nullopt if parsing fails
     */
    std::optional<X2apMessage> parse(const uint8_t* data, size_t len);

    /**
     * Check if data appears to be an X2AP message
     * X2AP uses ASN.1 PER encoding
     */
    static bool isX2ap(const uint8_t* data, size_t len);

private:
    /**
     * Parse X2AP PDU header
     */
    std::optional<X2apMessage> parsePdu(const uint8_t* data, size_t len, size_t& offset);

    /**
     * Parse X2AP IEs
     */
    bool parseIes(const uint8_t* data, size_t len, size_t& offset,
                  std::vector<X2apInformationElement>& ies);

    /**
     * Parse single X2AP IE
     */
    std::optional<X2apInformationElement> parseIe(const uint8_t* data, size_t len,
                                                   size_t& offset);

    /**
     * Extract common fields from IEs
     */
    void extractCommonFields(X2apMessage& msg);

    /**
     * Decode UE X2AP ID from IE value
     */
    static std::optional<uint32_t> decodeUeX2apId(const std::vector<uint8_t>& data);

    /**
     * Decode Cell ID from IE value
     */
    static std::optional<uint32_t> decodeCellId(const std::vector<uint8_t>& data);

    /**
     * Decode Global eNB ID from IE value
     */
    static std::optional<std::string> decodeGlobalEnbId(const std::vector<uint8_t>& data);

    /**
     * Decode length field (ASN.1 PER)
     */
    static std::optional<size_t> decodeLength(const uint8_t* data, size_t len,
                                              size_t& offset);
};

}  // namespace callflow
