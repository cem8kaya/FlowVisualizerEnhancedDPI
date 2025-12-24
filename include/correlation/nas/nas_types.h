#pragma once

#include <cstdint>
#include <string>

namespace callflow {
namespace correlation {

/**
 * @brief NAS Security Header Type (TS 24.301 section 9.3.1)
 */
enum class NasSecurityHeaderType : uint8_t {
    PLAIN_NAS = 0x00,
    INTEGRITY_PROTECTED = 0x01,
    INTEGRITY_PROTECTED_CIPHERED = 0x02,
    INTEGRITY_PROTECTED_NEW_EPS_SECURITY_CONTEXT = 0x03,
    INTEGRITY_PROTECTED_CIPHERED_NEW_EPS_SECURITY_CONTEXT = 0x04,
    SECURITY_HEADER_FOR_SERVICE_REQUEST = 0x0C
};

/**
 * @brief NAS Protocol Discriminator (TS 24.301 section 9.2)
 */
enum class NasProtocolDiscriminator : uint8_t {
    EPS_MOBILITY_MANAGEMENT = 0x07,  // EMM
    EPS_SESSION_MANAGEMENT = 0x02    // ESM
};

/**
 * @brief EMM Message Types (TS 24.301 section 9.8)
 */
enum class NasEmmMessageType : uint8_t {
    // Attach procedure
    ATTACH_REQUEST = 0x41,
    ATTACH_ACCEPT = 0x42,
    ATTACH_COMPLETE = 0x43,
    ATTACH_REJECT = 0x44,

    // Detach procedure
    DETACH_REQUEST = 0x45,
    DETACH_ACCEPT = 0x46,

    // Tracking Area Update (TAU)
    TAU_REQUEST = 0x48,
    TAU_ACCEPT = 0x49,
    TAU_COMPLETE = 0x4A,
    TAU_REJECT = 0x4B,

    // Service Request
    SERVICE_REQUEST = 0x4C,
    SERVICE_REJECT = 0x4E,

    // Extended Service Request
    EXTENDED_SERVICE_REQUEST = 0x4D,

    // GUTI Reallocation
    GUTI_REALLOC_COMMAND = 0x50,
    GUTI_REALLOC_COMPLETE = 0x51,

    // Authentication
    AUTH_REQUEST = 0x52,
    AUTH_RESPONSE = 0x53,
    AUTH_REJECT = 0x54,
    AUTH_FAILURE = 0x5C,

    // Identity
    IDENTITY_REQUEST = 0x55,
    IDENTITY_RESPONSE = 0x56,

    // Security Mode
    SECURITY_MODE_COMMAND = 0x5D,
    SECURITY_MODE_COMPLETE = 0x5E,
    SECURITY_MODE_REJECT = 0x5F,

    // EMM Information
    EMM_INFORMATION = 0x61,
    EMM_STATUS = 0x60,

    // Downlink NAS Transport
    DOWNLINK_NAS_TRANSPORT = 0x62,
    UPLINK_NAS_TRANSPORT = 0x63,

    // CS Service Notification
    CS_SERVICE_NOTIFICATION = 0x64,

    // Uplink Generic NAS Transport
    UPLINK_GENERIC_NAS_TRANSPORT = 0x65,
    DOWNLINK_GENERIC_NAS_TRANSPORT = 0x68
};

/**
 * @brief ESM Message Types (TS 24.301 section 9.8)
 */
enum class NasEsmMessageType : uint8_t {
    // Default Bearer procedures
    ACTIVATE_DEFAULT_BEARER_REQ = 0xC1,
    ACTIVATE_DEFAULT_BEARER_ACC = 0xC2,
    ACTIVATE_DEFAULT_BEARER_REJ = 0xC3,

    // Dedicated Bearer procedures
    ACTIVATE_DEDICATED_BEARER_REQ = 0xC5,
    ACTIVATE_DEDICATED_BEARER_ACC = 0xC6,
    ACTIVATE_DEDICATED_BEARER_REJ = 0xC7,

    // Modify Bearer procedures
    MODIFY_BEARER_REQ = 0xC9,
    MODIFY_BEARER_ACC = 0xCA,
    MODIFY_BEARER_REJ = 0xCB,

    // Deactivate Bearer procedures
    DEACTIVATE_BEARER_REQ = 0xCD,
    DEACTIVATE_BEARER_ACC = 0xCE,

    // PDN Connectivity procedures
    PDN_CONNECTIVITY_REQUEST = 0xD0,
    PDN_CONNECTIVITY_REJECT = 0xD1,

    // PDN Disconnect procedures
    PDN_DISCONNECT_REQUEST = 0xD2,
    PDN_DISCONNECT_REJECT = 0xD3,

    // Bearer Resource Allocation
    BEARER_RESOURCE_ALLOC_REQ = 0xD4,
    BEARER_RESOURCE_ALLOC_REJ = 0xD5,

    // Bearer Resource Modification
    BEARER_RESOURCE_MODIFY_REQ = 0xD6,
    BEARER_RESOURCE_MODIFY_REJ = 0xD7,

    // ESM Information
    ESM_INFO_REQUEST = 0xD9,
    ESM_INFO_RESPONSE = 0xDA,

    // ESM Status
    ESM_STATUS = 0xE8,

    // ESM Notification
    ESM_NOTIFICATION = 0xDB,

    // ESM Dummy Message
    ESM_DUMMY_MESSAGE = 0xC4
};

/**
 * @brief NAS IE Type (Information Element Type)
 */
enum class NasIEType : uint8_t {
    // Mobile Identity
    MOBILE_IDENTITY = 0x23,

    // EPS Mobile Identity
    EPS_MOBILE_IDENTITY = 0x50,

    // UE Network Capability
    UE_NETWORK_CAPABILITY = 0x58,

    // ESM Message Container
    ESM_MESSAGE_CONTAINER = 0x78,

    // PDN Address
    PDN_ADDRESS = 0x29,

    // APN
    ACCESS_POINT_NAME = 0x28,

    // Protocol Configuration Options
    PROTOCOL_CONFIG_OPTIONS = 0x27,

    // EPS Quality of Service
    EPS_QOS = 0x5B,

    // EPS Bearer Identity
    EPS_BEARER_IDENTITY = 0x00,  // Lower 4 bits of octet 1

    // Linked EPS Bearer Identity
    LINKED_EPS_BEARER_IDENTITY = 0x5D,

    // Transaction Identifier
    TRANSACTION_IDENTIFIER = 0x5A,

    // ESM Cause
    ESM_CAUSE = 0x5F,

    // EMM Cause
    EMM_CAUSE = 0x53,

    // GUTI
    EPS_GUTI = 0x50,

    // IMSI
    IMSI_IE = 0x17,

    // IMEI
    IMEI_IE = 0x23,

    // IMEISV
    IMEISV_IE = 0x23,

    // TMSI Status
    TMSI_STATUS = 0x19,

    // Tracking Area Identity
    TAI = 0x52,

    // Tracking Area Identity List
    TAI_LIST = 0x54,

    // EPS Update Type
    EPS_UPDATE_TYPE = 0x53,

    // EPS Attach Type
    EPS_ATTACH_TYPE = 0x51,

    // Old GUTI Type
    OLD_GUTI_TYPE = 0x55,

    // KSI and sequence number
    NAS_KEY_SET_ID = 0x08,

    // Short MAC
    SHORT_MAC = 0x09,

    // Security algorithms
    NAS_SECURITY_ALGORITHMS = 0x57
};

/**
 * @brief Mobile Identity Type (TS 24.301 section 9.9.2.3)
 */
enum class MobileIdentityType : uint8_t {
    NO_IDENTITY = 0,
    IMSI = 1,
    IMEI = 2,
    IMEISV = 3,
    TMSI = 4,
    TMGI = 5,
    GUTI = 6
};

/**
 * @brief EPS Attach Type (TS 24.301 section 9.9.3.11)
 */
enum class EpsAttachType : uint8_t {
    EPS_ATTACH = 1,
    COMBINED_EPS_IMSI_ATTACH = 2,
    EPS_EMERGENCY_ATTACH = 6,
    RESERVED = 7
};

/**
 * @brief EPS Update Type (TS 24.301 section 9.9.3.38)
 */
enum class EpsUpdateType : uint8_t {
    TA_UPDATING = 0,
    COMBINED_TA_LA_UPDATING = 1,
    COMBINED_TA_LA_UPDATING_WITH_IMSI_ATTACH = 2,
    PERIODIC_UPDATING = 3
};

/**
 * @brief PDN Type (TS 24.301 section 9.9.4.10)
 */
enum class NasPdnType : uint8_t { IPV4 = 1, IPV6 = 2, IPV4V6 = 3, UNUSED = 4, NON_IP = 5 };

/**
 * @brief Request Type (TS 24.301 section 9.9.4.14)
 */
enum class PdnRequestType : uint8_t {
    INITIAL_REQUEST = 1,
    HANDOVER = 2,
    UNUSED = 3,
    EMERGENCY = 4
};

/**
 * @brief ESM Cause values (TS 24.301 section 9.9.4.4)
 */
enum class EsmCause : uint8_t {
    OPERATOR_DETERMINED_BARRING = 8,
    INSUFFICIENT_RESOURCES = 26,
    UNKNOWN_APN = 27,
    UNKNOWN_PDN_TYPE = 28,
    USER_AUTHENTICATION_FAILED = 29,
    REQUEST_REJECTED_BY_GW = 30,
    REQUEST_REJECTED_UNSPECIFIED = 31,
    SERVICE_OPTION_NOT_SUPPORTED = 32,
    REQUESTED_SERVICE_NOT_SUBSCRIBED = 33,
    SERVICE_TEMPORARILY_OUT_OF_ORDER = 34,
    PTI_ALREADY_IN_USE = 35,
    REGULAR_DEACTIVATION = 36,
    EPS_QOS_NOT_ACCEPTED = 37,
    NETWORK_FAILURE = 38,
    REACTIVATION_REQUESTED = 39,
    SEMANTIC_ERROR_IN_TFT = 41,
    SYNTACTICAL_ERROR_IN_TFT = 42,
    INVALID_EPS_BEARER_IDENTITY = 43,
    SEMANTIC_ERRORS_IN_PACKET_FILTER = 44,
    SYNTACTICAL_ERROR_IN_PACKET_FILTER = 45,
    BEARER_WITHOUT_TFT_ACTIVATED = 46,
    PTI_MISMATCH = 47,
    LAST_PDN_DISCONNECTION_NOT_ALLOWED = 49,
    PDN_TYPE_IPV4_ONLY_ALLOWED = 50,
    PDN_TYPE_IPV6_ONLY_ALLOWED = 51,
    SINGLE_ADDRESS_BEARERS_ONLY = 52,
    ESM_INFORMATION_NOT_RECEIVED = 53,
    PDN_CONNECTION_DOES_NOT_EXIST = 54,
    MULTIPLE_PDN_CONNECTIONS_SAME_APN_NOT_ALLOWED = 55,
    COLLISION_WITH_NETWORK_INITIATED_REQUEST = 56,
    UNSUPPORTED_QCI_VALUE = 59,
    BEARER_HANDLING_NOT_SUPPORTED = 60,
    INVALID_PTI_VALUE = 81,
    SEMANTICALLY_INCORRECT_MESSAGE = 95,
    INVALID_MANDATORY_INFORMATION = 96,
    MESSAGE_TYPE_NON_EXISTENT = 97,
    MESSAGE_TYPE_NOT_COMPATIBLE = 98,
    IE_NON_EXISTENT = 99,
    CONDITIONAL_IE_ERROR = 100,
    MESSAGE_NOT_COMPATIBLE = 101,
    PROTOCOL_ERROR_UNSPECIFIED = 111,
    APN_RESTRICTION_INCOMPATIBLE = 112
};

/**
 * @brief EMM Cause values (TS 24.301 section 9.9.3.9)
 */
enum class EmmCause : uint8_t {
    IMSI_UNKNOWN_IN_HSS = 2,
    ILLEGAL_UE = 3,
    IMEI_NOT_ACCEPTED = 5,
    ILLEGAL_ME = 6,
    EPS_SERVICES_NOT_ALLOWED = 7,
    EPS_AND_NON_EPS_NOT_ALLOWED = 8,
    UE_IDENTITY_CANNOT_BE_DERIVED = 9,
    IMPLICITLY_DETACHED = 10,
    PLMN_NOT_ALLOWED = 11,
    TA_NOT_ALLOWED = 12,
    ROAMING_NOT_ALLOWED_IN_TA = 13,
    EPS_SERVICES_NOT_ALLOWED_IN_PLMN = 14,
    NO_SUITABLE_CELLS_IN_TA = 15,
    MSC_TEMPORARILY_NOT_REACHABLE = 16,
    NETWORK_FAILURE = 17,
    CS_DOMAIN_NOT_AVAILABLE = 18,
    ESM_FAILURE = 19,
    MAC_FAILURE = 20,
    SYNCH_FAILURE = 21,
    CONGESTION = 22,
    UE_SECURITY_CAPABILITIES_MISMATCH = 23,
    SECURITY_MODE_REJECTED_UNSPECIFIED = 24,
    NOT_AUTHORIZED_FOR_CSG = 25,
    NON_EPS_AUTH_UNACCEPTABLE = 26,
    REQUESTED_SERVICE_OPTION_NOT_AUTHORIZED = 35,
    CS_SERVICE_TEMPORARILY_NOT_AVAILABLE = 39,
    NO_EPS_BEARER_CONTEXT_ACTIVATED = 40,
    SEMANTICALLY_INCORRECT_MESSAGE = 95,
    INVALID_MANDATORY_INFORMATION = 96,
    MESSAGE_TYPE_NON_EXISTENT = 97,
    MESSAGE_TYPE_NOT_COMPATIBLE = 98,
    IE_NON_EXISTENT = 99,
    CONDITIONAL_IE_ERROR = 100,
    MESSAGE_NOT_COMPATIBLE = 101,
    PROTOCOL_ERROR_UNSPECIFIED = 111
};

/**
 * @brief Helper Functions
 */

/**
 * @brief Get EMM message type name
 */
std::string getEmmMessageTypeName(NasEmmMessageType type);

/**
 * @brief Get ESM message type name
 */
std::string getEsmMessageTypeName(NasEsmMessageType type);

/**
 * @brief Get Mobile Identity type name
 */
std::string getMobileIdentityTypeName(MobileIdentityType type);

/**
 * @brief Get PDN type name
 */
std::string getNasPdnTypeName(NasPdnType type);

/**
 * @brief Get ESM cause name
 */
std::string getEsmCauseName(EsmCause cause);

/**
 * @brief Get EMM cause name
 */
std::string getEmmCauseName(EmmCause cause);

/**
 * @brief Check if EMM message is request
 */
bool isEmmRequest(NasEmmMessageType type);

/**
 * @brief Check if ESM message is request
 */
bool isEsmRequest(NasEsmMessageType type);

/**
 * @brief Check if ESM cause is success
 */
bool isEsmSuccess(EsmCause cause);

}  // namespace correlation
}  // namespace callflow
