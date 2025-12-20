#pragma once

#include "diameter_types.h"
#include <nlohmann/json.hpp>
#include <memory>

namespace callflow {
namespace diameter {

// Forward declaration
struct DiameterAVP;

// ============================================================================
// Diameter Header Structure (20 bytes, RFC 6733 Section 3)
// ============================================================================

struct DiameterHeader {
    uint8_t version;              // Version (must be 1)
    uint32_t message_length : 24; // Message length including header (3 bytes)

    // Flags (1 byte)
    bool request;                 // R bit (Request)
    bool proxyable;               // P bit (Proxyable)
    bool error;                   // E bit (Error)
    bool potentially_retransmitted; // T bit (Potentially retransmitted)

    uint32_t command_code : 24;   // Command code (3 bytes)
    uint32_t application_id;      // Application ID (4 bytes)
    uint32_t hop_by_hop_id;       // Hop-by-Hop Identifier (4 bytes)
    uint32_t end_to_end_id;       // End-to-End Identifier (4 bytes)

    DiameterHeader();

    /**
     * Convert to JSON for logging/debugging
     */
    nlohmann::json toJson() const;

    /**
     * Get human-readable command name
     */
    std::string getCommandName() const;

    /**
     * Check if this is a request message
     */
    bool isRequest() const { return request; }

    /**
     * Check if this is an answer message
     */
    bool isAnswer() const { return !request; }

    /**
     * Get message direction string
     */
    std::string getDirection() const { return request ? "Request" : "Answer"; }
};

// ============================================================================
// Diameter AVP Structure (RFC 6733 Section 4)
// ============================================================================

struct DiameterAVP {
    uint32_t code;                // AVP code (4 bytes)

    // Flags (1 byte)
    bool vendor_specific;         // V bit (Vendor-Specific)
    bool mandatory;               // M bit (Mandatory)
    bool protected_;              // P bit (Protected) - renamed to avoid keyword

    uint32_t length : 24;         // AVP length including header (3 bytes)
    std::optional<uint32_t> vendor_id;  // Vendor ID (4 bytes, only if V flag set)
    std::vector<uint8_t> data;    // AVP data

    // Decoded value (populated by AVP parser)
    std::variant<
        std::monostate,           // Not decoded
        int32_t,                  // INTEGER32
        int64_t,                  // INTEGER64
        uint32_t,                 // UNSIGNED32
        uint64_t,                 // UNSIGNED64
        float,                    // FLOAT32
        double,                   // FLOAT64
        std::string,              // UTF8String, DiameterIdentity, DiameterURI
        std::vector<uint8_t>,     // OctetString, IPAddress
        std::vector<std::shared_ptr<DiameterAVP>>  // Grouped AVP
    > decoded_value;

    DiameterAVP();

    /**
     * Convert to JSON for logging/debugging
     */
    nlohmann::json toJson() const;

    /**
     * Get AVP data as string (for UTF8String AVPs)
     */
    std::string getDataAsString() const;

    /**
     * Get AVP data as uint32 (for Unsigned32 AVPs)
     */
    std::optional<uint32_t> getDataAsUint32() const;

    /**
     * Get AVP data as uint64 (for Unsigned64 AVPs)
     */
    std::optional<uint64_t> getDataAsUint64() const;

    /**
     * Get AVP data as int32 (for Integer32 AVPs)
     */
    std::optional<int32_t> getDataAsInt32() const;

    /**
     * Get AVP data as int64 (for Integer64 AVPs)
     */
    std::optional<int64_t> getDataAsInt64() const;

    /**
     * Get grouped AVPs (if this is a grouped AVP)
     */
    std::optional<std::vector<std::shared_ptr<DiameterAVP>>> getGroupedAVPs() const;

    /**
     * Get AVP name
     */
    std::string getAVPName() const;

    /**
     * Check if AVP has vendor-specific flag
     */
    bool isVendorSpecific() const { return vendor_specific; }

    /**
     * Check if AVP is mandatory
     */
    bool isMandatory() const { return mandatory; }

    /**
     * Check if AVP is protected
     */
    bool isProtected() const { return protected_; }

    /**
     * Get actual data length (excluding header and padding)
     */
    size_t getDataLength() const;

    /**
     * Get total AVP length including padding
     */
    size_t getTotalLength() const;
};

// ============================================================================
// Diameter Message Structure
// ============================================================================

struct DiameterMessage {
    DiameterHeader header;
    std::vector<std::shared_ptr<DiameterAVP>> avps;

    // Commonly used AVPs (extracted for convenience)
    std::optional<std::string> session_id;
    std::optional<std::string> origin_host;
    std::optional<std::string> origin_realm;
    std::optional<std::string> destination_host;
    std::optional<std::string> destination_realm;
    std::optional<uint32_t> result_code;
    std::optional<uint32_t> auth_application_id;
    std::optional<uint32_t> acct_application_id;

    DiameterMessage();

    /**
     * Convert to JSON for logging/debugging
     */
    nlohmann::json toJson() const;

    /**
     * Get human-readable command name
     */
    std::string getCommandName() const { return header.getCommandName(); }

    /**
     * Check if this is a request message
     */
    bool isRequest() const { return header.isRequest(); }

    /**
     * Check if this is an answer message
     */
    bool isAnswer() const { return header.isAnswer(); }

    /**
     * Get result code name (if answer message)
     */
    std::optional<std::string> getResultCodeName() const;

    /**
     * Check if message was successful (2xxx result code)
     */
    bool isSuccess() const;

    /**
     * Check if message is an error
     */
    bool isError() const;

    /**
     * Find AVP by code
     */
    std::shared_ptr<DiameterAVP> findAVP(uint32_t code) const;

    /**
     * Find all AVPs with given code
     */
    std::vector<std::shared_ptr<DiameterAVP>> findAllAVPs(uint32_t code) const;

    /**
     * Find AVP by code and vendor ID
     */
    std::shared_ptr<DiameterAVP> findAVP(uint32_t code, uint32_t vendor_id) const;

    /**
     * Get interface type based on application ID
     */
    DiameterInterface getInterface() const;

    /**
     * Extract common fields from AVPs
     */
    void extractCommonFields();
};

}  // namespace diameter
}  // namespace callflow
