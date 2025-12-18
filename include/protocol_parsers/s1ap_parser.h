#pragma once

#include "protocol_parsers/s1ap_ie.h"
#include "common/types.h"
#include <optional>
#include <vector>
#include <nlohmann/json.hpp>

namespace callflow {

/**
 * S1AP Protocol Parser (3GPP TS 36.413)
 *
 * Parses S1 Application Protocol messages between eNodeB and MME
 * Uses lightweight ASN.1 PER decoder for common Information Elements
 */
class S1apParser {
public:
    S1apParser() = default;
    ~S1apParser() = default;

    /**
     * Parse S1AP message from SCTP payload
     * @param data SCTP payload data
     * @param len Payload length
     * @return Parsed S1AP message or nullopt if parsing fails
     */
    std::optional<S1apMessage> parse(const uint8_t* data, size_t len);

    /**
     * Check if data appears to be an S1AP message
     * Basic heuristic check before full parsing
     */
    static bool isS1ap(const uint8_t* data, size_t len);

private:
    /**
     * Parse S1AP PDU header (message type, procedure code, criticality)
     */
    bool parseHeader(const uint8_t* data, size_t len, S1apMessage& msg);

    /**
     * Parse Information Elements from S1AP message
     */
    bool parseIes(const uint8_t* data, size_t len, size_t offset,
                  std::vector<S1apInformationElement>& ies);

    /**
     * Extract UE identifiers from IEs
     */
    void extractUeIds(S1apMessage& msg);

    /**
     * Extract IMSI from IEs
     */
    void extractImsi(S1apMessage& msg);

    /**
     * Extract NAS-PDU from IEs
     */
    void extractNasPdu(S1apMessage& msg);

    /**
     * Extract all common fields
     */
    void extractCommonFields(S1apMessage& msg);
};

}  // namespace callflow
