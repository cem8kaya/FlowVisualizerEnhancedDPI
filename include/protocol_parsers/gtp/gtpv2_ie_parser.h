#pragma once

#include "gtpv2_types.h"
#include "common/logger.h"
#include <vector>
#include <cstdint>
#include <optional>

namespace callflow {
namespace gtp {

/**
 * GTPv2-C Information Element structure
 */
struct GtpV2IE {
    GtpV2IEHeader header;
    std::vector<uint8_t> value;

    nlohmann::json toJson() const;
};

/**
 * GTPv2-C Information Element Parser
 * Handles parsing of GTPv2-C IEs according to 3GPP TS 29.274
 */
class GtpV2IEParser {
public:
    /**
     * Parse all IEs from GTPv2-C message payload
     * @param data Pointer to IE data (after GTPv2-C header)
     * @param length Length of IE data
     * @return Vector of parsed IEs
     */
    static std::vector<GtpV2IE> parseIEs(const uint8_t* data, size_t length);

    /**
     * Parse single IE at given offset
     * @param data Pointer to IE data
     * @param length Total length of data
     * @param offset Current offset, will be updated to next IE
     * @return Parsed IE or nullopt if parsing fails
     */
    static std::optional<GtpV2IE> parseIE(const uint8_t* data, size_t length, size_t& offset);

    /**
     * Decode BCD (Binary Coded Decimal) data
     * Used for IMSI, MSISDN, etc.
     * @param data BCD encoded data
     * @param length Length of data
     * @return Decoded decimal string
     */
    static std::string decodeBCD(const uint8_t* data, size_t length);

    /**
     * Decode APN from IE data
     * @param data APN encoded data (length-prefixed labels)
     * @return Decoded APN string (e.g., "internet.mnc001.mcc001.gprs")
     */
    static std::string decodeAPN(const std::vector<uint8_t>& data);

    /**
     * Parse IMSI IE
     */
    static std::optional<GtpV2IMSI> parseIMSI(const GtpV2IE& ie);

    /**
     * Parse F-TEID IE
     */
    static std::optional<GtpV2FTEID> parseFTEID(const GtpV2IE& ie);

    /**
     * Parse Bearer QoS IE
     */
    static std::optional<GtpV2BearerQoS> parseBearerQoS(const GtpV2IE& ie);

    /**
     * Parse PDN Address Allocation IE
     */
    static std::optional<GtpV2PDNAddressAllocation> parsePAA(const GtpV2IE& ie);

    /**
     * Parse Bearer Context grouped IE
     */
    static std::optional<GtpV2BearerContext> parseBearerContext(const GtpV2IE& ie);

    /**
     * Parse Cause IE
     */
    static std::optional<GtpV2Cause> parseCause(const GtpV2IE& ie);

    /**
     * Parse APN IE
     */
    static std::optional<std::string> parseAPN(const GtpV2IE& ie);

    /**
     * Parse AMBR IE
     */
    static std::optional<GtpV2AMBR> parseAMBR(const GtpV2IE& ie);

    /**
     * Parse Serving Network IE
     */
    static std::optional<GtpV2ServingNetwork> parseServingNetwork(const GtpV2IE& ie);

    /**
     * Parse ULI (User Location Information) IE
     */
    static std::optional<GtpV2ULI> parseULI(const GtpV2IE& ie);

    /**
     * Parse RAT Type IE
     */
    static std::optional<RATType> parseRATType(const GtpV2IE& ie);

    /**
     * Parse Recovery IE
     */
    static std::optional<uint8_t> parseRecovery(const GtpV2IE& ie);

    /**
     * Parse EPS Bearer ID IE
     */
    static std::optional<uint8_t> parseEPSBearerID(const GtpV2IE& ie);

    /**
     * Parse MSISDN IE
     */
    static std::optional<std::string> parseMSISDN(const GtpV2IE& ie);

    /**
     * Parse MEI (IMEI) IE
     */
    static std::optional<std::string> parseMEI(const GtpV2IE& ie);

    /**
     * Parse Indication IE
     */
    static std::optional<GtpV2Indication> parseIndication(const GtpV2IE& ie);

    /**
     * Parse PDN Type IE
     */
    static std::optional<PDNType> parsePDNType(const GtpV2IE& ie);

    /**
     * Parse Charging ID IE
     */
    static std::optional<uint32_t> parseChargingID(const GtpV2IE& ie);

private:
    /**
     * Decode bit rate value from IE encoding
     * @param encoded Encoded bit rate value
     * @return Bit rate in bps
     */
    static uint64_t decodeBitRate(uint8_t encoded);
};

}  // namespace gtp
}  // namespace callflow
