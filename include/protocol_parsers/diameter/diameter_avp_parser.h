#pragma once

#include "diameter_base.h"
#include "diameter_types.h"
#include <array>
#include <memory>

namespace callflow {
namespace diameter {

// ============================================================================
// Diameter AVP Parser
// ============================================================================

class DiameterAVPParser {
public:
    DiameterAVPParser() = default;
    ~DiameterAVPParser() = default;

    /**
     * Parse single AVP from data
     * @param data Pointer to AVP data
     * @param length Length of data available
     * @param offset Current offset (will be updated)
     * @return Parsed AVP or nullptr if parsing fails
     */
    static std::shared_ptr<DiameterAVP> parseAVP(const uint8_t* data, size_t length, size_t& offset);

    /**
     * Parse multiple AVPs from data
     * @param data Pointer to AVPs data
     * @param length Total length of data
     * @param offset Starting offset
     * @return Vector of parsed AVPs
     */
    static std::vector<std::shared_ptr<DiameterAVP>> parseAVPs(const uint8_t* data, size_t length, size_t offset = 0);

    /**
     * Decode AVP data based on data type
     * @param avp AVP to decode
     * @param type Expected data type
     * @return true if decoding succeeded
     */
    static bool decodeAVPData(std::shared_ptr<DiameterAVP> avp, DiameterAVPDataType type);

    // ========================================================================
    // Data Type Parsers
    // ========================================================================

    /**
     * Parse Integer32 (4 bytes, signed, network byte order)
     */
    static std::optional<int32_t> parseInt32(const std::vector<uint8_t>& data);

    /**
     * Parse Integer64 (8 bytes, signed, network byte order)
     */
    static std::optional<int64_t> parseInt64(const std::vector<uint8_t>& data);

    /**
     * Parse Unsigned32 (4 bytes, unsigned, network byte order)
     */
    static std::optional<uint32_t> parseUnsigned32(const std::vector<uint8_t>& data);

    /**
     * Parse Unsigned64 (8 bytes, unsigned, network byte order)
     */
    static std::optional<uint64_t> parseUnsigned64(const std::vector<uint8_t>& data);

    /**
     * Parse Float32 (4 bytes, IEEE 754 single precision)
     */
    static std::optional<float> parseFloat32(const std::vector<uint8_t>& data);

    /**
     * Parse Float64 (8 bytes, IEEE 754 double precision)
     */
    static std::optional<double> parseFloat64(const std::vector<uint8_t>& data);

    /**
     * Parse UTF8String (variable length, UTF-8 encoded)
     */
    static std::optional<std::string> parseUTF8String(const std::vector<uint8_t>& data);

    /**
     * Parse DiameterIdentity (UTF8String containing FQDN)
     */
    static std::optional<std::string> parseDiameterIdentity(const std::vector<uint8_t>& data);

    /**
     * Parse DiameterURI (UTF8String in URI format)
     */
    static std::optional<std::string> parseDiameterURI(const std::vector<uint8_t>& data);

    /**
     * Parse Grouped AVP (contains nested AVPs)
     */
    static std::optional<std::vector<std::shared_ptr<DiameterAVP>>> parseGrouped(const std::vector<uint8_t>& data);

    /**
     * Parse IPv4 Address (6 bytes: 2 bytes AF + 4 bytes address)
     */
    static std::optional<std::array<uint8_t, 4>> parseIPv4Address(const std::vector<uint8_t>& data);

    /**
     * Parse IPv6 Address (18 bytes: 2 bytes AF + 16 bytes address)
     */
    static std::optional<std::array<uint8_t, 16>> parseIPv6Address(const std::vector<uint8_t>& data);

    /**
     * Parse IP Address (generic, detects IPv4 or IPv6)
     * Returns string representation (e.g., "192.168.1.1" or "2001:db8::1")
     */
    static std::optional<std::string> parseIPAddress(const std::vector<uint8_t>& data);

    /**
     * Parse Time (4 bytes, NTP timestamp, seconds since 1900-01-01 00:00:00 UTC)
     */
    static std::optional<std::chrono::system_clock::time_point> parseTime(const std::vector<uint8_t>& data);

    /**
     * Parse OctetString (variable length, arbitrary binary data)
     */
    static std::vector<uint8_t> parseOctetString(const std::vector<uint8_t>& data);

    // ========================================================================
    // Helper Functions
    // ========================================================================

    /**
     * Get data type for known AVP code
     * @param code AVP code
     * @param vendor_id Vendor ID (if vendor-specific)
     * @return Expected data type
     */
    static DiameterAVPDataType getAVPDataType(uint32_t code, std::optional<uint32_t> vendor_id = std::nullopt);

    /**
     * Calculate padding needed for 4-byte alignment
     */
    static size_t calculatePadding(size_t length);

    /**
     * Validate AVP structure
     */
    static bool validateAVP(const DiameterAVP& avp);

    /**
     * Check if data appears to be printable UTF-8
     */
    static bool isPrintableUTF8(const std::vector<uint8_t>& data);

private:
    /**
     * Read 32-bit value from network byte order
     */
    static uint32_t readUint32(const uint8_t* data);

    /**
     * Read 64-bit value from network byte order
     */
    static uint64_t readUint64(const uint8_t* data);

    /**
     * Read 24-bit value from network byte order
     */
    static uint32_t readUint24(const uint8_t* data);
};

}  // namespace diameter
}  // namespace callflow
