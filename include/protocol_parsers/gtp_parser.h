#pragma once

#include "common/types.h"
#include <optional>
#include <vector>
#include <nlohmann/json.hpp>

namespace callflow {

/**
 * GTP message types (GTPv2-C)
 */
enum class GtpMessageType : uint8_t {
    ECHO_REQUEST = 1,
    ECHO_RESPONSE = 2,
    CREATE_SESSION_REQUEST = 32,
    CREATE_SESSION_RESPONSE = 33,
    MODIFY_BEARER_REQUEST = 34,
    MODIFY_BEARER_RESPONSE = 35,
    DELETE_SESSION_REQUEST = 36,
    DELETE_SESSION_RESPONSE = 37,
    MODIFY_BEARER_COMMAND = 64,
    MODIFY_BEARER_FAILURE_INDICATION = 65,
    DELETE_BEARER_COMMAND = 66,
    DELETE_BEARER_FAILURE_INDICATION = 67,
    BEARER_RESOURCE_COMMAND = 68,
    BEARER_RESOURCE_FAILURE_INDICATION = 69,
    CREATE_BEARER_REQUEST = 95,
    CREATE_BEARER_RESPONSE = 96,
    UPDATE_BEARER_REQUEST = 97,
    UPDATE_BEARER_RESPONSE = 98,
    DELETE_BEARER_REQUEST = 99,
    DELETE_BEARER_RESPONSE = 100
};

/**
 * GTP Information Element types
 */
enum class GtpIeType : uint8_t {
    IMSI = 1,
    CAUSE = 2,
    RECOVERY = 3,
    APN = 71,
    AMBR = 72,
    EBI = 73,  // EPS Bearer ID
    IP_ADDRESS = 74,
    MEI = 75,  // Mobile Equipment Identity
    MSISDN = 76,
    INDICATION = 77,
    PCO = 78,  // Protocol Configuration Options
    PAA = 79,  // PDN Address Allocation
    BEARER_QOS = 80,
    CHARGING_ID = 94,
    BEARER_CONTEXT = 93,
    F_TEID = 87,  // Fully Qualified TEID
    ULI = 86,     // User Location Information
    SERVING_NETWORK = 83,
    RAT_TYPE = 82,
    APN_RESTRICTION = 127
};

/**
 * GTP header structure (GTPv2-C)
 */
struct GtpHeader {
    uint8_t version;              // Version (3 bits)
    bool piggybacking;            // P flag
    bool teid_present;            // T flag
    uint8_t message_type;         // Message type (1 byte)
    uint16_t message_length;      // Message length (2 bytes, excluding initial 4 bytes)
    uint32_t teid;                // Tunnel Endpoint Identifier (4 bytes, if T flag)
    uint32_t sequence_number;     // Sequence number (3 bytes)

    nlohmann::json toJson() const;
};

/**
 * GTP Information Element structure
 */
struct GtpInformationElement {
    uint8_t type;                 // IE type (1 byte)
    uint16_t length;              // IE length (2 bytes)
    uint8_t instance;             // Instance (4 bits)
    std::vector<uint8_t> data;    // IE data

    nlohmann::json toJson() const;

    /**
     * Get IE data as string (for IMSI, MSISDN, APN, etc.)
     */
    std::string getDataAsString() const;

    /**
     * Get IE data as uint32 (for TEID, Cause, etc.)
     */
    std::optional<uint32_t> getDataAsUint32() const;

    /**
     * Get IE type name
     */
    std::string getTypeName() const;
};

/**
 * Complete GTP message structure
 */
struct GtpMessage {
    GtpHeader header;
    std::vector<GtpInformationElement> ies;

    // Common extracted fields
    std::optional<std::string> imsi;
    std::optional<std::string> apn;
    std::optional<std::string> msisdn;
    std::optional<uint32_t> cause;
    std::optional<uint32_t> f_teid;

    nlohmann::json toJson() const;

    /**
     * Get message type for session correlation
     */
    MessageType getMessageType() const;

    /**
     * Get human-readable message type name
     */
    std::string getMessageTypeName() const;
};

/**
 * GTP protocol parser (GTPv2-C)
 */
class GtpParser {
public:
    GtpParser() = default;
    ~GtpParser() = default;

    /**
     * Parse GTP message from packet payload
     * @param data Packet payload data
     * @param len Payload length
     * @return Parsed GTP message or nullopt if parsing fails
     */
    std::optional<GtpMessage> parse(const uint8_t* data, size_t len);

    /**
     * Check if data appears to be a GTP message
     */
    static bool isGtp(const uint8_t* data, size_t len);

private:
    /**
     * Parse GTP header
     */
    std::optional<GtpHeader> parseHeader(const uint8_t* data, size_t len);

    /**
     * Parse IEs from message
     */
    bool parseIes(const uint8_t* data, size_t len, size_t offset,
                  std::vector<GtpInformationElement>& ies);

    /**
     * Parse single IE
     */
    std::optional<GtpInformationElement> parseIe(const uint8_t* data, size_t len,
                                                 size_t& offset);

    /**
     * Extract common fields from IEs
     */
    void extractCommonFields(GtpMessage& msg);

    /**
     * Decode IMSI from IE data
     */
    static std::string decodeImsi(const std::vector<uint8_t>& data);

    /**
     * Decode MSISDN from IE data
     */
    static std::string decodeMsisdn(const std::vector<uint8_t>& data);

    /**
     * Decode APN from IE data
     */
    static std::string decodeApn(const std::vector<uint8_t>& data);
};

}  // namespace callflow
