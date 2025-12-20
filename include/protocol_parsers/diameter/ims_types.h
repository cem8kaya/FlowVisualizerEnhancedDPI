#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace callflow {
namespace diameter {

// ============================================================================
// IMS Common Structures (Used across Cx/Dx and Sh interfaces)
// ============================================================================

/**
 * Server Capabilities (AVP 603)
 * Indicates capabilities that the S-CSCF supports
 */
struct ServerCapabilities {
    std::vector<uint32_t> mandatory_capabilities;
    std::vector<uint32_t> optional_capabilities;
    std::vector<std::string> server_names;

    nlohmann::json toJson() const;
};

/**
 * SIP Authentication Scheme (AVP 608)
 * Defines the authentication mechanism (Digest-AKAv1-MD5, Digest-MD5, etc.)
 */
enum class SIPAuthenticationScheme : uint32_t {
    UNKNOWN = 0,
    DIGEST_AKAV1_MD5 = 1,
    DIGEST_AKAV2_MD5 = 2,
    DIGEST_MD5 = 3,
    DIGEST_HTTP = 4,
    NASS_BUNDLED = 5,
    SIP_DIGEST = 6
};

/**
 * SIP Authentication Data Item (AVP 612)
 * Contains authentication vectors for SIP registration
 */
struct SIPAuthDataItem {
    uint32_t sip_item_number;
    std::optional<std::string> sip_authentication_scheme;
    std::optional<std::string> sip_authenticate;          // Challenge
    std::optional<std::string> sip_authorization;         // Expected response
    std::optional<std::string> sip_authentication_context;// AKA context
    std::optional<std::string> confidentiality_key;       // CK for AKA
    std::optional<std::string> integrity_key;             // IK for AKA
    std::optional<std::vector<uint8_t>> line_identifier;  // For NASS bundled auth

    nlohmann::json toJson() const;
};

/**
 * SIP Number of Auth Items (AVP 607)
 * Grouped AVP containing multiple authentication items
 */
struct SIPNumberAuthItems {
    std::vector<SIPAuthDataItem> auth_data_items;

    nlohmann::json toJson() const;
};

/**
 * Charging Information (AVP 618)
 * Contains primary and secondary charging function names
 */
struct ChargingInformation {
    std::optional<std::string> primary_event_charging_function_name;
    std::optional<std::string> secondary_event_charging_function_name;
    std::optional<std::string> primary_charging_collection_function_name;
    std::optional<std::string> secondary_charging_collection_function_name;

    nlohmann::json toJson() const;
};

/**
 * User Identity for Sh interface (AVP 700)
 * Can contain public identity, MSISDN, or external identifier
 */
struct UserIdentity {
    std::optional<std::string> public_identity;      // SIP URI or Tel URI
    std::optional<std::string> msisdn;              // E.164 format
    std::optional<std::string> external_identifier; // NAI format

    nlohmann::json toJson() const;
};

/**
 * Supported Features (AVP 628)
 * Feature negotiation between entities
 */
struct SupportedFeatures {
    uint32_t vendor_id;
    uint32_t feature_list_id;
    uint32_t feature_list;  // Bitmask of supported features

    nlohmann::json toJson() const;
};

/**
 * Server Assignment Type (AVP 614)
 * Indicates the type of server assignment operation
 */
enum class ServerAssignmentType : uint32_t {
    NO_ASSIGNMENT = 0,
    REGISTRATION = 1,
    RE_REGISTRATION = 2,
    UNREGISTERED_USER = 3,
    TIMEOUT_DEREGISTRATION = 4,
    USER_DEREGISTRATION = 5,
    TIMEOUT_DEREGISTRATION_STORE_SERVER_NAME = 6,
    USER_DEREGISTRATION_STORE_SERVER_NAME = 7,
    ADMINISTRATIVE_DEREGISTRATION = 8,
    AUTHENTICATION_FAILURE = 9,
    AUTHENTICATION_TIMEOUT = 10,
    DEREGISTRATION_TOO_MUCH_DATA = 11,
    AAA_USER_DATA_REQUEST = 12,
    PGW_UPDATE = 13,
    RESTORATION = 14
};

/**
 * User Authorization Type (AVP 623)
 * Indicates the reason for authorization request
 */
enum class UserAuthorizationType : uint32_t {
    REGISTRATION = 0,
    DE_REGISTRATION = 1,
    REGISTRATION_AND_CAPABILITIES = 2
};

/**
 * Data Reference (AVP 703) - Sh interface
 * Indicates what type of user data is being requested
 */
enum class DataReference : uint32_t {
    REPOSITORY_DATA = 0,
    IMS_PUBLIC_IDENTITY = 10,
    IMS_USER_STATE = 11,
    S_CSCF_NAME = 12,
    INITIAL_FILTER_CRITERIA = 13,
    LOCATION_INFORMATION = 14,
    USER_STATE = 15,
    CHARGING_INFORMATION = 16,
    MSISDN = 17,
    PSI_ACTIVATION = 18,
    DSAI = 19,
    SERVICE_LEVEL_TRACE_INFO = 21,
    IP_ADDRESS_SECURE_BINDING_INFO = 22,
    SERVICE_PRIORITY_LEVEL = 23,
    SMSF_3GPP_ADDRESS = 24,
    SMSF_NON_3GPP_ADDRESS = 25,
    UE_SRVCC_CAPABILITY = 26
};

/**
 * Subscription Request Type (AVP 705) - Sh interface
 */
enum class SubscriptionRequestType : uint32_t {
    SUBSCRIBE = 0,
    UNSUBSCRIBE = 1
};

/**
 * User Data Already Available (AVP 624)
 * Indicates if the S-CSCF already has the user data
 */
enum class UserDataAlreadyAvailable : uint32_t {
    USER_DATA_NOT_AVAILABLE = 0,
    USER_DATA_ALREADY_AVAILABLE = 1
};

/**
 * Deregistration Reason (AVP 615)
 * Contains reason code and optional info for deregistration
 */
struct DeregistrationReason {
    uint32_t reason_code;
    std::optional<std::string> reason_info;

    nlohmann::json toJson() const;
};

/**
 * Reason Code (AVP 616)
 * Specific reason for deregistration/termination
 */
enum class ReasonCode : uint32_t {
    PERMANENT_TERMINATION = 0,
    NEW_SERVER_ASSIGNED = 1,
    SERVER_CHANGE = 2,
    REMOVE_S_CSCF = 3
};

/**
 * Repository Data ID (AVP 715) - Sh interface
 * Identifies specific repository data
 */
struct RepositoryDataID {
    std::optional<std::string> service_indication;
    uint32_t sequence_number;

    nlohmann::json toJson() const;
};

/**
 * Identity Set (AVP 708) - Sh interface
 */
enum class IdentitySet : uint32_t {
    ALL_IDENTITIES = 0,
    REGISTERED_IDENTITIES = 1,
    IMPLICIT_IDENTITIES = 2,
    ALIAS_IDENTITIES = 3
};

/**
 * User State (AVP 15) - Sh interface
 * Current registration state of the user
 */
enum class IMSUserState : uint32_t {
    NOT_REGISTERED = 0,
    REGISTERED = 1,
    UNREGISTERED = 2,
    AUTHENTICATION_PENDING = 3
};

/**
 * Requested Domain (AVP 706) - Sh interface
 */
enum class RequestedDomain : uint32_t {
    CS_DOMAIN = 0,
    PS_DOMAIN = 1
};

/**
 * Current Location (AVP 707) - Sh interface
 */
enum class CurrentLocation : uint32_t {
    DO_NOT_NEED_INITIATE_ACTIVE_LOCATION_RETRIEVAL = 0,
    INITIATE_ACTIVE_LOCATION_RETRIEVAL = 1
};

/**
 * Send Data Indication (AVP 710) - Sh interface
 */
enum class SendDataIndication : uint32_t {
    USER_DATA_NOT_REQUESTED = 0,
    USER_DATA_REQUESTED = 1
};

/**
 * User Data XML Container
 * Contains parsed IMS user data (IMSSubscription from TS 29.228)
 * The actual XML parsing is handled separately
 */
struct UserDataSH {
    std::string raw_xml;  // Raw XML data
    // Parsed fields can be added as needed
    std::optional<std::vector<std::string>> public_identities;
    std::optional<std::string> service_profile;

    nlohmann::json toJson() const;
};

/**
 * IMS Cx/Dx Experimental Result Codes (TS 29.229 Section 6.2)
 */
enum class CxDxExperimentalResultCode : uint32_t {
    DIAMETER_FIRST_REGISTRATION = 2001,
    DIAMETER_SUBSEQUENT_REGISTRATION = 2002,
    DIAMETER_UNREGISTERED_SERVICE = 2003,
    DIAMETER_SUCCESS_SERVER_NAME_NOT_STORED = 2004,
    DIAMETER_SERVER_SELECTION = 2005,

    DIAMETER_ERROR_USER_UNKNOWN = 5001,
    DIAMETER_ERROR_IDENTITIES_DONT_MATCH = 5002,
    DIAMETER_ERROR_IDENTITY_NOT_REGISTERED = 5003,
    DIAMETER_ERROR_ROAMING_NOT_ALLOWED = 5004,
    DIAMETER_ERROR_IDENTITY_ALREADY_REGISTERED = 5005,
    DIAMETER_ERROR_AUTH_SCHEME_NOT_SUPPORTED = 5006,
    DIAMETER_ERROR_IN_ASSIGNMENT_TYPE = 5007,
    DIAMETER_ERROR_TOO_MUCH_DATA = 5008,
    DIAMETER_ERROR_NOT_SUPPORTED_USER_DATA = 5009
};

/**
 * IMS Sh Experimental Result Codes (TS 29.329 Section 6.2)
 */
enum class ShExperimentalResultCode : uint32_t {
    DIAMETER_ERROR_USER_DATA_NOT_AVAILABLE = 4100,
    DIAMETER_ERROR_PRIOR_UPDATE_IN_PROGRESS = 4101,

    DIAMETER_ERROR_USER_DATA_CANNOT_BE_READ = 5100,
    DIAMETER_ERROR_USER_DATA_CANNOT_BE_MODIFIED = 5101,
    DIAMETER_ERROR_USER_DATA_CANNOT_BE_NOTIFIED = 5102,
    DIAMETER_ERROR_TRANSPARENT_DATA_OUT_OF_SYNC = 5103,
    DIAMETER_ERROR_SUBS_DATA_ABSENT = 5104,
    DIAMETER_ERROR_NO_SUBSCRIPTION_TO_DATA = 5105,
    DIAMETER_ERROR_DSAI_NOT_AVAILABLE = 5106,
    DIAMETER_ERROR_UNKNOWN_SERVICE_INDICATION = 5107,
    DIAMETER_ERROR_FEATURE_UNSUPPORTED = 5108
};

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Convert Server Assignment Type to string
 */
std::string serverAssignmentTypeToString(ServerAssignmentType type);

/**
 * Convert User Authorization Type to string
 */
std::string userAuthorizationTypeToString(UserAuthorizationType type);

/**
 * Convert Data Reference to string
 */
std::string dataReferenceToString(DataReference ref);

/**
 * Convert Subscription Request Type to string
 */
std::string subscriptionRequestTypeToString(SubscriptionRequestType type);

/**
 * Convert IMS User State to string
 */
std::string imsUserStateToString(IMSUserState state);

/**
 * Convert Reason Code to string
 */
std::string reasonCodeToString(ReasonCode code);

/**
 * Convert Cx/Dx Experimental Result Code to string
 */
std::string cxDxExperimentalResultCodeToString(CxDxExperimentalResultCode code);

/**
 * Convert Sh Experimental Result Code to string
 */
std::string shExperimentalResultCodeToString(ShExperimentalResultCode code);

}  // namespace diameter
}  // namespace callflow
