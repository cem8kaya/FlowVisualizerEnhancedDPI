#pragma once

#include "common/types.h"
#include <optional>
#include <vector>
#include <nlohmann/json.hpp>

namespace callflow {

/**
 * DIAMETER command codes
 */
enum class DiameterCommandCode {
    UNKNOWN = 0,
    CAPABILITIES_EXCHANGE = 257,
    RE_AUTH = 258,
    ACCOUNTING = 271,
    CREDIT_CONTROL = 272,  // CCR/CCA
    AA_REQUEST = 265,      // AAR/AAA
    ABORT_SESSION = 274,
    SESSION_TERMINATION = 275,
    DEVICE_WATCHDOG = 280,
    DISCONNECT_PEER = 282
};

/**
 * DIAMETER AVP codes
 */
enum class DiameterAvpCode {
    SESSION_ID = 263,
    ORIGIN_HOST = 264,
    ORIGIN_REALM = 296,
    DESTINATION_HOST = 293,
    DESTINATION_REALM = 283,
    RESULT_CODE = 268,
    AUTH_APPLICATION_ID = 258,
    ACCT_APPLICATION_ID = 259
};

/**
 * DIAMETER header structure (20 bytes)
 */
struct DiameterHeader {
    uint8_t version;              // Version (1 byte)
    uint32_t message_length;      // Message length including header (3 bytes)
    bool request_flag;            // R flag
    bool proxiable_flag;          // P flag
    bool error_flag;              // E flag
    bool retransmit_flag;         // T flag
    uint32_t command_code;        // Command code (3 bytes)
    uint32_t application_id;      // Application ID (4 bytes)
    uint32_t hop_by_hop_id;       // Hop-by-Hop ID (4 bytes)
    uint32_t end_to_end_id;       // End-to-End ID (4 bytes)

    nlohmann::json toJson() const;
};

/**
 * DIAMETER AVP (Attribute-Value Pair) structure
 */
struct DiameterAvp {
    uint32_t code;                // AVP code (4 bytes)
    bool vendor_flag;             // V flag
    bool mandatory_flag;          // M flag
    bool protected_flag;          // P flag
    uint32_t length;              // AVP length including header (3 bytes)
    uint32_t vendor_id;           // Vendor ID (4 bytes, only if V flag set)
    std::vector<uint8_t> data;    // AVP data

    nlohmann::json toJson() const;

    /**
     * Get AVP data as string (for UTF8String AVPs)
     */
    std::string getDataAsString() const;

    /**
     * Get AVP data as uint32 (for Unsigned32 AVPs)
     */
    std::optional<uint32_t> getDataAsUint32() const;
};

/**
 * Complete DIAMETER message structure
 */
struct DiameterMessage {
    DiameterHeader header;
    std::vector<DiameterAvp> avps;

    // Common extracted fields
    std::optional<std::string> session_id;
    std::optional<std::string> origin_host;
    std::optional<std::string> destination_realm;
    std::optional<uint32_t> result_code;

    nlohmann::json toJson() const;

    /**
     * Get message type for session correlation
     */
    MessageType getMessageType() const;

    /**
     * Get human-readable command name
     */
    std::string getCommandName() const;
};

/**
 * DIAMETER protocol parser
 */
class DiameterParser {
public:
    DiameterParser() = default;
    ~DiameterParser() = default;

    /**
     * Parse DIAMETER message from packet payload
     * @param data Packet payload data
     * @param len Payload length
     * @return Parsed DIAMETER message or nullopt if parsing fails
     */
    std::optional<DiameterMessage> parse(const uint8_t* data, size_t len);

    /**
     * Check if data appears to be a DIAMETER message
     */
    static bool isDiameter(const uint8_t* data, size_t len);

private:
    /**
     * Parse DIAMETER header
     */
    std::optional<DiameterHeader> parseHeader(const uint8_t* data, size_t len);

    /**
     * Parse AVPs from message
     */
    bool parseAvps(const uint8_t* data, size_t len, size_t offset,
                   std::vector<DiameterAvp>& avps);

    /**
     * Parse single AVP
     */
    std::optional<DiameterAvp> parseAvp(const uint8_t* data, size_t len, size_t& offset);

    /**
     * Extract common fields from AVPs
     */
    void extractCommonFields(DiameterMessage& msg);

    /**
     * Calculate padding needed for 4-byte alignment
     */
    static size_t calculatePadding(size_t length);
};

}  // namespace callflow
