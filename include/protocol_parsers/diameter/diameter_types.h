#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace callflow {
namespace diameter {

// ============================================================================
// Diameter Constants
// ============================================================================

constexpr uint8_t DIAMETER_VERSION = 1;
constexpr size_t DIAMETER_HEADER_SIZE = 20;
constexpr size_t DIAMETER_AVP_HEADER_MIN_SIZE = 8;
constexpr size_t DIAMETER_AVP_HEADER_VENDOR_SIZE = 12;
constexpr uint32_t DIAMETER_VENDOR_3GPP = 10415;
constexpr uint16_t DIAMETER_DEFAULT_PORT = 3868;
constexpr uint16_t DIAMETER_TLS_PORT = 5868;

// ============================================================================
// Diameter Command Codes (RFC 6733 + 3GPP)
// ============================================================================

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
    NOTIFY = 323                   // NOR/NOA
};

// ============================================================================
// Diameter AVP Codes (RFC 6733 + 3GPP)
// ============================================================================

enum class DiameterAVPCode : uint32_t {
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
    SERVICE_SELECTION = 493  // APN
};

// ============================================================================
// Diameter Result Codes (RFC 6733)
// ============================================================================

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
    DIAMETER_NO_COMMON_SECURITY = 5017
};

// ============================================================================
// Diameter AVP Data Types (RFC 6733 Section 4.2)
// ============================================================================

enum class DiameterAVPDataType {
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
    TIME                // NTP timestamp (Unsigned32)
};

// ============================================================================
// Diameter Application IDs
// ============================================================================

enum class DiameterApplicationID : uint32_t {
    DIAMETER_COMMON_MESSAGES = 0,
    NASREQ = 1,                    // RFC 7155
    MOBILE_IP = 2,                 // RFC 4004
    BASE_ACCOUNTING = 3,           // RFC 6733
    CREDIT_CONTROL = 4,            // RFC 4006
    EAP = 5,                       // RFC 4072
    SIP_APPLICATION = 6,           // RFC 4740

    // 3GPP Applications
    TGPP_CX = 16777216,            // 3GPP TS 29.228/29.229
    TGPP_SH = 16777217,            // 3GPP TS 29.328/29.329
    TGPP_GX = 16777238,            // 3GPP TS 29.212
    TGPP_S6A_S6D = 16777251,       // 3GPP TS 29.272
    TGPP_S13_S13 = 16777252,       // 3GPP TS 29.272
    TGPP_SLG = 16777255,           // 3GPP TS 29.172
    TGPP_SWX = 16777265,           // 3GPP TS 29.273
    TGPP_S6B = 16777272,           // 3GPP TS 29.273
    TGPP_RX = 16777236,            // 3GPP TS 29.214
    TGPP_GY_RO = 16777238          // 3GPP TS 32.299 (uses same as Gx)
};

// ============================================================================
// Diameter Interface Types
// ============================================================================

enum class DiameterInterface {
    UNKNOWN,
    BASE,       // Base protocol
    CX,         // Cx/Dx (IMS)
    SH,         // Sh (IMS)
    S6A,        // S6a/S6d (LTE)
    S13,        // S13 (LTE)
    GX,         // Gx (Policy)
    RX,         // Rx (Policy)
    GY,         // Gy (Charging)
    RO,         // Ro (Charging)
    SWX,        // SWx (Non-3GPP)
    S6B,        // S6b (Non-3GPP)
    SLG         // SLg (Location)
};

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Get result code category (success, protocol error, transient failure, permanent failure)
 */
std::string getResultCodeCategory(uint32_t result_code);

/**
 * Get human-readable result code name
 */
std::string getResultCodeName(uint32_t result_code);

/**
 * Get AVP data type name
 */
std::string getAVPDataTypeName(DiameterAVPDataType type);

/**
 * Get command code name
 */
std::string getCommandCodeName(uint32_t command_code);

/**
 * Get application ID name
 */
std::string getApplicationIDName(uint32_t app_id);

/**
 * Determine interface type from application ID
 */
DiameterInterface getInterfaceFromApplicationID(uint32_t app_id);

/**
 * Get interface name
 */
std::string getInterfaceName(DiameterInterface interface);

}  // namespace diameter
}  // namespace callflow
