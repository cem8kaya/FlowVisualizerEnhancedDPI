#pragma once

#include "protocol_parsers/s1ap/s1ap_types.h"
#include <cstdint>
#include <optional>
#include <vector>
#include <string>

namespace callflow {
namespace s1ap {

/**
 * S1AP Information Element Parser
 *
 * Provides utilities for parsing S1AP IEs from ASN.1 PER encoded data.
 * This is a simplified manual parser focused on critical IEs.
 *
 * Note: Full ASN.1 PER parsing is complex. This implementation handles
 * the most common cases for MVP. Future enhancement can use asn1c.
 */
class S1APIEParser {
public:
    /**
     * Parse eNB-UE-S1AP-ID (IE 8)
     * Range: 0..16777215 (24-bit)
     */
    static std::optional<uint32_t> parseENB_UE_S1AP_ID(const uint8_t* data, size_t len);

    /**
     * Parse MME-UE-S1AP-ID (IE 0)
     * Range: 0..4294967295 (32-bit)
     */
    static std::optional<uint32_t> parseMME_UE_S1AP_ID(const uint8_t* data, size_t len);

    /**
     * Parse NAS-PDU (IE 26)
     * Returns embedded NAS message as octet string
     */
    static std::optional<std::vector<uint8_t>> parseNAS_PDU(const uint8_t* data, size_t len);

    /**
     * Parse TAI (Tracking Area Identity) (IE 67)
     */
    static std::optional<TrackingAreaIdentity> parseTAI(const uint8_t* data, size_t len);

    /**
     * Parse E-UTRAN CGI (Cell Global Identifier) (IE 100)
     */
    static std::optional<EUTRAN_CGI> parseEUTRAN_CGI(const uint8_t* data, size_t len);

    /**
     * Parse UE Security Capabilities (IE 107)
     */
    static std::optional<UESecurityCapabilities> parseUESecurityCapabilities(const uint8_t* data, size_t len);

    /**
     * Parse E-RAB To Be Setup Item (for Initial Context Setup Request)
     */
    static std::optional<E_RAB_ToBeSetupItem> parseE_RAB_ToBeSetupItem(const uint8_t* data, size_t len);

    /**
     * Parse E-RAB Setup Item (for Initial Context Setup Response)
     */
    static std::optional<E_RAB_SetupItem> parseE_RAB_SetupItem(const uint8_t* data, size_t len);

    /**
     * Parse E-RAB Item (for releases)
     */
    static std::optional<E_RAB_Item> parseE_RAB_Item(const uint8_t* data, size_t len);

    /**
     * Parse Cause (IE 2)
     */
    static std::optional<std::pair<S1APCauseType, uint8_t>> parseCause(const uint8_t* data, size_t len);

    /**
     * Parse RRC Establishment Cause (IE 134)
     */
    static std::optional<uint8_t> parseRRCEstablishmentCause(const uint8_t* data, size_t len);

    /**
     * Parse E-RAB Level QoS Parameters
     */
    static std::optional<E_RAB_LevelQoSParameters> parseE_RAB_LevelQoSParameters(const uint8_t* data, size_t len);

    /**
     * Parse Transport Layer Address (IP address)
     */
    static std::optional<std::vector<uint8_t>> parseTransportLayerAddress(const uint8_t* data, size_t len);

    /**
     * Parse GTP-TEID (32-bit)
     */
    static std::optional<uint32_t> parseGTP_TEID(const uint8_t* data, size_t len);

private:
    // ASN.1 PER Helper Functions

    /**
     * Decode PLMN Identity (3 bytes in BCD)
     * Format: MCC (3 digits) + MNC (2 or 3 digits)
     * Example: "001010" for MCC=001, MNC=010
     */
    static std::string decodePLMN(const uint8_t* data);

    /**
     * Decode length field from ASN.1 PER
     * Supports short form and long form
     */
    static std::optional<size_t> decodeLength(const uint8_t*& ptr, size_t& remaining);

    /**
     * Decode constrained integer from ASN.1 PER
     */
    static std::optional<uint32_t> decodeConstrainedInteger(const uint8_t*& ptr, size_t& remaining,
                                                             uint32_t min, uint32_t max);

    /**
     * Decode unconstrained integer from ASN.1 PER
     */
    static std::optional<uint32_t> decodeUnconstrainedInteger(const uint8_t*& ptr, size_t& remaining);

    /**
     * Decode octet string from ASN.1 PER
     */
    static std::optional<std::vector<uint8_t>> decodeOctetString(const uint8_t*& ptr, size_t& remaining);

    /**
     * Decode bit string from ASN.1 PER
     */
    static std::optional<std::vector<uint8_t>> decodeBitString(const uint8_t*& ptr, size_t& remaining,
                                                                size_t& bits_count);

    /**
     * Decode enumerated value from ASN.1 PER
     */
    static std::optional<uint8_t> decodeEnumerated(const uint8_t*& ptr, size_t& remaining,
                                                    uint8_t max_value);

    /**
     * Skip IE (when we don't need to parse it)
     */
    static bool skipIE(const uint8_t*& ptr, size_t& remaining);

    /**
     * Read bits from buffer (for PER encoding)
     */
    static uint32_t readBits(const uint8_t*& ptr, size_t& bit_offset, size_t num_bits);
};

/**
 * ASN.1 PER Utilities
 */
namespace asn1_per {

    /**
     * Calculate number of bits needed to encode a constrained integer
     */
    inline size_t calculateConstrainedIntegerBits(uint32_t min, uint32_t max) {
        if (min == max) return 0;
        uint32_t range = max - min + 1;
        size_t bits = 0;
        while ((1u << bits) < range) {
            bits++;
        }
        return bits;
    }

    /**
     * Align to byte boundary
     */
    inline void alignToByte(size_t& bit_offset) {
        if (bit_offset % 8 != 0) {
            bit_offset = (bit_offset + 7) & ~7;
        }
    }

    /**
     * Check if we have enough remaining bytes
     */
    inline bool hasBytes(size_t remaining, size_t needed) {
        return remaining >= needed;
    }

} // namespace asn1_per

} // namespace s1ap
} // namespace callflow
