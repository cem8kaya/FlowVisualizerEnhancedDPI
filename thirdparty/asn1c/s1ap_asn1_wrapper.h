#pragma once

#include <cstdint>
#include <optional>
#include <vector>
#include <string>

namespace callflow {
namespace asn1 {

/**
 * Simple ASN.1 PER (Packed Encoding Rules) decoder
 * Lightweight implementation for S1AP common IEs
 * Not a full ASN.1 decoder - handles specific S1AP patterns
 */
class PerDecoder {
public:
    PerDecoder(const uint8_t* data, size_t len);

    /**
     * Read bits from the stream
     */
    bool readBits(uint8_t num_bits, uint32_t& value);

    /**
     * Read a byte-aligned octet
     */
    bool readOctet(uint8_t& value);

    /**
     * Read multiple octets
     */
    bool readOctets(uint8_t* dest, size_t num_octets);

    /**
     * Align to byte boundary
     */
    void alignToByte();

    /**
     * Skip bits
     */
    bool skipBits(size_t num_bits);

    /**
     * Check if more data is available
     */
    bool hasMore() const;

    /**
     * Get current position in bits
     */
    size_t getCurrentBitPosition() const { return bit_offset_; }

    /**
     * Get current position in bytes
     */
    size_t getCurrentBytePosition() const { return bit_offset_ / 8; }

    /**
     * Decode constrained whole number
     * Used for enumerated types and integers with constraints
     */
    std::optional<uint32_t> decodeConstrainedWholeNumber(uint32_t min_val, uint32_t max_val);

    /**
     * Decode length determinant (for variable-length fields)
     */
    std::optional<uint32_t> decodeLength();

    /**
     * Decode octet string with length
     */
    std::optional<std::vector<uint8_t>> decodeOctetString();

    /**
     * Decode boolean
     */
    std::optional<bool> decodeBoolean();

    /**
     * Decode enumerated value
     */
    std::optional<uint32_t> decodeEnumerated(uint32_t num_values);

private:
    const uint8_t* data_;
    size_t length_;
    size_t bit_offset_;

    /**
     * Calculate number of bits needed to represent a value
     */
    static uint8_t bitsNeeded(uint32_t range);
};

/**
 * S1AP PDU structure (simplified)
 */
struct S1apPdu {
    uint8_t choice;  // 0 = initiating, 1 = successful, 2 = unsuccessful
    uint8_t procedure_code;
    uint8_t criticality;
    std::vector<uint8_t> value;  // Remaining encoded data
};

/**
 * Decode S1AP PDU header
 */
std::optional<S1apPdu> decodeS1apPdu(const uint8_t* data, size_t len);

/**
 * Extract protocol IEs from S1AP PDU value
 * Returns list of (IE ID, criticality, IE value) tuples
 */
struct S1apIeTuple {
    uint32_t id;
    uint8_t criticality;
    std::vector<uint8_t> value;
};

std::vector<S1apIeTuple> extractS1apIes(const uint8_t* data, size_t len);

/**
 * Decode IMSI from S1AP IE value
 * IMSI is TBCD-encoded (Telephony Binary Coded Decimal)
 */
std::optional<std::string> decodeImsi(const uint8_t* data, size_t len);

/**
 * Decode UE IDs (ENB-UE-S1AP-ID, MME-UE-S1AP-ID)
 */
std::optional<uint32_t> decodeUeId(const uint8_t* data, size_t len);

/**
 * Decode NAS-PDU (returns the NAS message bytes)
 */
std::optional<std::vector<uint8_t>> decodeNasPdu(const uint8_t* data, size_t len);

}  // namespace asn1
}  // namespace callflow
