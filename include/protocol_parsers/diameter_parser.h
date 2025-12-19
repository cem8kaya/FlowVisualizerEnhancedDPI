#pragma once

#include "common/types.h"
#include <optional>
#include <vector>
#include <nlohmann/json.hpp>

namespace callflow {

/**
 * DIAMETER command codes (RFC 6733 + 3GPP)
 */
enum class DiameterCommandCode : uint32_t {
    UNKNOWN = 0,

    // Base Protocol (RFC 6733)
    CAPABILITIES_EXCHANGE = 257,   // CER/CEA
    RE_AUTH = 258,                 // RAR/RAA
    AA_REQUEST = 265,              // AAR/AAA
    ACCOUNTING = 271,              // ACR/ACA
    CREDIT_CONTROL = 272,          // CCR/CCA (RFC 4006)
    ABORT_SESSION = 274,           // ASR/ASA
    SESSION_TERMINATION = 275,     // STR/STA
    DEVICE_WATCHDOG = 280,         // DWR/DWA
    DISCONNECT_PEER = 282,         // DPR/DPA

    // 3GPP Cx/Dx Interface (TS 29.228, TS 29.229)
    USER_AUTHORIZATION = 300,      // UAR/UAA
    SERVER_ASSIGNMENT = 301,       // SAR/SAA
    LOCATION_INFO = 302,           // LIR/LIA
    MULTIMEDIA_AUTH = 303,         // MAR/MAA
    REGISTRATION_TERMINATION = 304,// RTR/RTA
    PUSH_PROFILE = 305,            // PPR/PPA

    // 3GPP Sh Interface (TS 29.328, TS 29.329)
    USER_DATA = 306,               // UDR/UDA
    PROFILE_UPDATE = 307,          // PUR/PUA
    SUBSCRIBE_NOTIFICATIONS = 308, // SNR/SNA
    PUSH_NOTIFICATION = 309,       // PNR/PNA

    // 3GPP S6a/S6d Interface (TS 29.272)
    UPDATE_LOCATION = 316,         // ULR/ULA
    CANCEL_LOCATION = 317,         // CLR/CLA
    AUTHENTICATION_INFORMATION = 318, // AIR/AIA
    INSERT_SUBSCRIBER_DATA = 319,  // IDR/IDA
    DELETE_SUBSCRIBER_DATA = 320,  // DSR/DSA
    PURGE_UE = 321,                // PUR/PUA
    RESET = 322,                   // RSR/RSA
    NOTIFY = 323,                  // NOR/NOA

    // 3GPP Gx Interface (TS 29.212)
    // Uses CREDIT_CONTROL = 272

    // 3GPP Rx Interface (TS 29.214)
    AA_REQUEST_RX = 265,           // AAR/AAA (same code, different interface)

    // 3GPP Gy/Ro Interface (TS 32.299)
    // Uses CREDIT_CONTROL = 272
};

/**
 * DIAMETER AVP codes (RFC 6733 + 3GPP)
 */
enum class DiameterAvpCode : uint32_t {
    // Base Protocol (RFC 6733)
    USER_NAME = 1,
    CLASS = 25,
    SESSION_TIMEOUT = 27,
    PROXY_STATE = 33,
    ACCOUNTING_SESSION_ID = 44,
    ACCT_MULTI_SESSION_ID = 50,
    EVENT_TIMESTAMP = 55,
    ACCT_INTERIM_INTERVAL = 85,
    HOST_IP_ADDRESS = 257,
    AUTH_APPLICATION_ID = 258,
    ACCT_APPLICATION_ID = 259,
    VENDOR_SPECIFIC_APPLICATION_ID = 260,
    REDIRECT_HOST_USAGE = 261,
    REDIRECT_MAX_CACHE_TIME = 262,
    SESSION_ID = 263,
    ORIGIN_HOST = 264,
    SUPPORTED_VENDOR_ID = 265,
    VENDOR_ID = 266,
    FIRMWARE_REVISION = 267,
    RESULT_CODE = 268,
    PRODUCT_NAME = 269,
    SESSION_BINDING = 270,
    SESSION_SERVER_FAILOVER = 271,
    MULTI_ROUND_TIME_OUT = 272,
    DISCONNECT_CAUSE = 273,
    AUTH_REQUEST_TYPE = 274,
    AUTH_GRACE_PERIOD = 276,
    AUTH_SESSION_STATE = 277,
    ORIGIN_STATE_ID = 278,
    FAILED_AVP = 279,
    PROXY_HOST = 280,
    ERROR_MESSAGE = 281,
    ROUTE_RECORD = 282,
    DESTINATION_REALM = 283,
    PROXY_INFO = 284,
    RE_AUTH_REQUEST_TYPE = 285,
    DESTINATION_HOST = 293,
    ERROR_REPORTING_HOST = 294,
    TERMINATION_CAUSE = 295,
    ORIGIN_REALM = 296,
    EXPERIMENTAL_RESULT = 297,
    EXPERIMENTAL_RESULT_CODE = 298,
    INBAND_SECURITY_ID = 299,

    // Credit Control (RFC 4006)
    CC_REQUEST_TYPE = 416,
    CC_REQUEST_NUMBER = 415,
    CC_SESSION_FAILOVER = 418,
    CC_SUB_SESSION_ID = 419,
    CC_CORRELATION_ID = 411,

    // Network Access Server (NAS) (RFC 7155)
    NAS_PORT = 5,
    NAS_PORT_ID = 87,
    NAS_PORT_TYPE = 61,

    // QoS (3GPP)
    QOS_CLASS_IDENTIFIER = 1028,
    MAX_REQUESTED_BANDWIDTH_UL = 516,
    MAX_REQUESTED_BANDWIDTH_DL = 515,
    GUARANTEED_BITRATE_UL = 1025,
    GUARANTEED_BITRATE_DL = 1026,

    // 3GPP Common
    RAT_TYPE = 1032,
    SERVICE_SELECTION = 493,  // APN
};

/**
 * DIAMETER Result Codes (RFC 6733)
 */
enum class DiameterResultCode : uint32_t {
    // Success (2xxx)
    DIAMETER_SUCCESS = 2001,
    DIAMETER_LIMITED_SUCCESS = 2002,

    // Protocol Errors (3xxx)
    DIAMETER_COMMAND_UNSUPPORTED = 3001,
    DIAMETER_UNABLE_TO_DELIVER = 3002,
    DIAMETER_REALM_NOT_SERVED = 3003,
    DIAMETER_TOO_BUSY = 3004,
    DIAMETER_LOOP_DETECTED = 3005,
    DIAMETER_REDIRECT_INDICATION = 3006,
    DIAMETER_APPLICATION_UNSUPPORTED = 3007,
    DIAMETER_INVALID_HDR_BITS = 3008,
    DIAMETER_INVALID_AVP_BITS = 3009,
    DIAMETER_UNKNOWN_PEER = 3010,

    // Transient Failures (4xxx)
    DIAMETER_AUTHENTICATION_REJECTED = 4001,
    DIAMETER_OUT_OF_SPACE = 4002,
    DIAMETER_ELECTION_LOST = 4003,

    // Permanent Failures (5xxx)
    DIAMETER_AVP_UNSUPPORTED = 5001,
    DIAMETER_UNKNOWN_SESSION_ID = 5002,
    DIAMETER_AUTHORIZATION_REJECTED = 5003,
    DIAMETER_INVALID_AVP_VALUE = 5004,
    DIAMETER_MISSING_AVP = 5005,
    DIAMETER_RESOURCES_EXCEEDED = 5006,
    DIAMETER_CONTRADICTING_AVPS = 5007,
    DIAMETER_AVP_NOT_ALLOWED = 5008,
    DIAMETER_AVP_OCCURS_TOO_MANY_TIMES = 5009,
    DIAMETER_NO_COMMON_APPLICATION = 5010,
    DIAMETER_UNSUPPORTED_VERSION = 5011,
    DIAMETER_UNABLE_TO_COMPLY = 5012,
    DIAMETER_INVALID_BIT_IN_HEADER = 5013,
    DIAMETER_INVALID_AVP_LENGTH = 5014,
    DIAMETER_INVALID_MESSAGE_LENGTH = 5015,
    DIAMETER_INVALID_AVP_BIT_COMBO = 5016,
    DIAMETER_NO_COMMON_SECURITY = 5017,
};

/**
 * Get result code category (success, protocol error, transient failure, permanent failure)
 */
std::string getResultCodeCategory(uint32_t result_code);

/**
 * Get human-readable result code name
 */
std::string getResultCodeName(uint32_t result_code);

/**
 * DIAMETER AVP Data Types (RFC 6733 Section 4.2)
 */
enum class DiameterAvpDataType {
    OCTET_STRING,       // Arbitrary data
    INTEGER32,          // Signed 32-bit integer
    INTEGER64,          // Signed 64-bit integer
    UNSIGNED32,         // Unsigned 32-bit integer
    UNSIGNED64,         // Unsigned 64-bit integer
    FLOAT32,            // 32-bit floating point
    FLOAT64,            // 64-bit floating point
    GROUPED,            // Grouped AVP (contains other AVPs)

    // Derived types (OctetString)
    UTF8STRING,         // UTF-8 encoded string
    DIAMETER_IDENTITY,  // Diameter identity (FQDN)
    DIAMETER_URI,       // Diameter URI
    ENUMERATED,         // Enumerated (Unsigned32)
    IP_ADDRESS,         // IPv4 or IPv6 address (4 or 16 bytes + 2 byte AF)
    TIME,               // NTP timestamp (Unsigned32)
};

/**
 * Get AVP data type name
 */
std::string getAvpDataTypeName(DiameterAvpDataType type);

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
