#pragma once

#include "protocol_parsers/diameter/diameter_base.h"
#include "protocol_parsers/diameter/ims_types.h"
#include "common/types.h"
#include <optional>
#include <vector>
#include <nlohmann/json.hpp>

namespace callflow {
namespace diameter {

/**
 * Cx/Dx Application ID (3GPP TS 29.228/29.229)
 * IMS I-CSCF/S-CSCF to HSS interface
 */
constexpr uint32_t DIAMETER_CX_APPLICATION_ID = 16777216;

/**
 * Cx/Dx-specific AVP Codes (3GPP TS 29.229)
 */
enum class CxDxAVPCode : uint32_t {
    // User Identity
    PUBLIC_IDENTITY = 601,              // Public-Identity (UTF8String)
    PRIVATE_IDENTITY = 601,             // Alias for consistency

    // Server Information
    SERVER_NAME = 602,                  // S-CSCF name (UTF8String)
    SERVER_CAPABILITIES = 603,          // Grouped
    MANDATORY_CAPABILITY = 604,         // Unsigned32
    OPTIONAL_CAPABILITY = 605,          // Unsigned32

    // User Data
    USER_DATA = 606,                    // OctetString (XML)

    // Authentication
    SIP_NUMBER_AUTH_ITEMS = 607,        // Grouped
    SIP_AUTHENTICATION_SCHEME = 608,    // UTF8String
    SIP_AUTHENTICATE = 609,             // OctetString
    SIP_AUTHORIZATION = 610,            // OctetString
    SIP_AUTHENTICATION_CONTEXT = 611,   // OctetString
    SIP_AUTH_DATA_ITEM = 612,           // Grouped
    SIP_ITEM_NUMBER = 613,              // Unsigned32

    // Server Assignment
    SERVER_ASSIGNMENT_TYPE = 614,       // Enumerated
    DEREGISTRATION_REASON = 615,        // Grouped
    REASON_CODE = 616,                  // Enumerated
    REASON_INFO = 617,                  // UTF8String

    // Charging
    CHARGING_INFORMATION = 618,         // Grouped
    PRIMARY_EVENT_CHARGING_FUNCTION_NAME = 619,    // DiameterURI
    SECONDARY_EVENT_CHARGING_FUNCTION_NAME = 620,  // DiameterURI
    PRIMARY_CHARGING_COLLECTION_FUNCTION_NAME = 621,  // DiameterURI
    SECONDARY_CHARGING_COLLECTION_FUNCTION_NAME = 622, // DiameterURI

    // Authorization
    USER_AUTHORIZATION_TYPE = 623,      // Enumerated
    USER_DATA_ALREADY_AVAILABLE = 624,  // Enumerated

    // AKA Security
    CONFIDENTIALITY_KEY = 625,          // OctetString
    INTEGRITY_KEY = 626,                // OctetString

    // Wildcarded Public Identity
    WILDCARDED_PUBLIC_IDENTITY = 634,   // UTF8String
    WILDCARDED_IMPU = 636,              // UTF8String

    // UAR Flags
    UAR_FLAGS = 637,                    // Unsigned32

    // Loose Route Indication
    LOOSE_ROUTE_INDICATION = 638,       // Enumerated

    // SCSCF Restoration Info
    SCSCF_RESTORATION_INFO = 639,       // Grouped
    PATH = 640,                         // OctetString
    CONTACT = 641,                      // OctetString
    SUBSCRIPTION_INFO = 642,            // Grouped
    CALL_ID_SIP_HEADER = 643,           // OctetString
    FROM_SIP_HEADER = 644,              // OctetString
    TO_SIP_HEADER = 645,                // OctetString
    RECORD_ROUTE = 646,                 // OctetString

    // Associated Identities
    ASSOCIATED_IDENTITIES = 632,        // Grouped

    // Identity with Emergency Registration
    IDENTITY_WITH_EMERGENCY_REGISTRATION = 651, // Grouped

    // Supported Features (shared with other interfaces)
    SUPPORTED_FEATURES = 628,           // Grouped
    FEATURE_LIST_ID = 629,              // Unsigned32
    FEATURE_LIST = 630,                 // Unsigned32

    // Visit Network Identifier
    VISITED_NETWORK_IDENTIFIER = 600,   // OctetString

    // Public Identity
    USER_NAME = 1,                      // UTF8String (from base protocol)

    // Associated Private Identities
    ASSOCIATED_PRIVATE_IDENTITIES = 647, // Grouped

    // Originating Request
    ORIGINATING_REQUEST = 633,          // Enumerated

    // Line Identifier (for NASS bundled auth)
    LINE_IDENTIFIER = 500,              // OctetString

    // Multiple Registration Indication
    MULTIPLE_REGISTRATION_INDICATION = 648, // Enumerated

    // Session Priority
    SESSION_PRIORITY = 650,             // Enumerated

    // Identities with Emergency Registration
    IDENTITIES_WITH_EMERGENCY_REGISTRATION = 651, // Grouped

    // Priviledged Sender Indication
    PRIVILEDGED_SENDER_INDICATION = 652, // Enumerated

    // Restoration Info
    RESTORATION_INFO = 649,             // Grouped

    // SIP Digest Authenticate
    SIP_DIGEST_AUTHENTICATE = 635       // Grouped
};

/**
 * Cx/Dx Command Codes (3GPP TS 29.229)
 * Request bit determines if it's a request or answer
 */
enum class CxDxCommandCode : uint32_t {
    USER_AUTHORIZATION = 300,           // UAR (Request) / UAA (Answer)
    SERVER_ASSIGNMENT = 301,            // SAR (Request) / SAA (Answer)
    LOCATION_INFO = 302,                // LIR (Request) / LIA (Answer)
    MULTIMEDIA_AUTH = 303,              // MAR (Request) / MAA (Answer)
    REGISTRATION_TERMINATION = 304,     // RTR (Request) / RTA (Answer)
    PUSH_PROFILE = 305                  // PPR (Request) / PPA (Answer)
};

// ============================================================================
// Cx/Dx Message Structures
// ============================================================================

/**
 * User-Authorization-Request (UAR)
 * Sent by I-CSCF to HSS to get S-CSCF assignment info
 */
struct UserAuthorizationRequest {
    std::string public_identity;                        // Mandatory
    std::optional<std::string> visited_network_identifier; // Mandatory
    std::optional<UserAuthorizationType> user_authorization_type; // Optional
    std::optional<uint32_t> uar_flags;                  // Optional
    std::optional<std::string> user_name;               // Optional (private identity)
    std::vector<SupportedFeatures> supported_features;  // Optional

    nlohmann::json toJson() const;
};

/**
 * User-Authorization-Answer (UAA)
 * Response from HSS with S-CSCF capabilities or name
 */
struct UserAuthorizationAnswer {
    std::optional<uint32_t> experimental_result_code;   // Mandatory (in Experimental-Result)
    std::optional<ServerCapabilities> server_capabilities; // Conditional
    std::optional<std::string> server_name;             // Conditional
    std::vector<SupportedFeatures> supported_features;  // Optional

    nlohmann::json toJson() const;
};

/**
 * Server-Assignment-Request (SAR)
 * Sent by S-CSCF to HSS to register/deregister user or get user profile
 */
struct ServerAssignmentRequest {
    std::string public_identity;                        // Mandatory
    std::string server_name;                            // Mandatory
    std::optional<std::string> user_name;               // Optional (private identity)
    std::optional<ServerAssignmentType> server_assignment_type; // Mandatory
    std::optional<UserDataAlreadyAvailable> user_data_already_available; // Mandatory
    std::optional<DeregistrationReason> deregistration_reason; // Conditional
    std::vector<SupportedFeatures> supported_features;  // Optional
    std::vector<std::string> public_identities;         // Optional (multiple)
    std::optional<std::string> wildcarded_public_identity; // Optional
    std::optional<uint32_t> multiple_registration_indication; // Optional
    std::optional<uint32_t> session_priority;           // Optional

    nlohmann::json toJson() const;
};

/**
 * Server-Assignment-Answer (SAA)
 * Response from HSS with user profile data
 */
struct ServerAssignmentAnswer {
    std::optional<uint32_t> experimental_result_code;   // Mandatory (in Experimental-Result)
    std::optional<UserDataSH> user_data;                // Conditional
    std::optional<ChargingInformation> charging_information; // Optional
    std::vector<SupportedFeatures> supported_features;  // Optional
    std::optional<std::string> wildcarded_public_identity; // Optional
    std::vector<std::string> associated_identities;     // Optional

    nlohmann::json toJson() const;
};

/**
 * Location-Info-Request (LIR)
 * Sent by I-CSCF to HSS to get S-CSCF name for a registered user
 */
struct LocationInfoRequest {
    std::string public_identity;                        // Mandatory
    std::optional<std::string> user_name;               // Optional (private identity)
    std::optional<uint32_t> originating_request;        // Optional
    std::vector<SupportedFeatures> supported_features;  // Optional
    std::optional<uint32_t> session_priority;           // Optional

    nlohmann::json toJson() const;
};

/**
 * Location-Info-Answer (LIA)
 * Response from HSS with S-CSCF name and capabilities
 */
struct LocationInfoAnswer {
    std::optional<uint32_t> experimental_result_code;   // Mandatory (in Experimental-Result)
    std::optional<std::string> server_name;             // Conditional
    std::optional<ServerCapabilities> server_capabilities; // Conditional
    std::vector<SupportedFeatures> supported_features;  // Optional
    std::optional<std::string> wildcarded_public_identity; // Optional

    nlohmann::json toJson() const;
};

/**
 * Multimedia-Auth-Request (MAR)
 * Sent by S-CSCF to HSS to get authentication vectors
 */
struct MultimediaAuthRequest {
    std::string public_identity;                        // Mandatory
    std::string user_name;                              // Mandatory (private identity)
    std::optional<std::string> server_name;             // Mandatory
    std::optional<uint32_t> sip_number_auth_items;      // Mandatory
    std::optional<std::string> sip_auth_data_item;      // Conditional
    std::vector<SupportedFeatures> supported_features;  // Optional

    nlohmann::json toJson() const;
};

/**
 * Multimedia-Auth-Answer (MAA)
 * Response from HSS with authentication vectors
 */
struct MultimediaAuthAnswer {
    std::optional<uint32_t> experimental_result_code;   // Mandatory (in Experimental-Result)
    std::optional<std::string> user_name;               // Conditional
    std::optional<std::string> public_identity;         // Conditional
    std::optional<SIPNumberAuthItems> sip_number_auth_items; // Conditional
    std::vector<SupportedFeatures> supported_features;  // Optional

    nlohmann::json toJson() const;
};

/**
 * Registration-Termination-Request (RTR)
 * Sent by HSS to S-CSCF to deregister user
 */
struct RegistrationTerminationRequest {
    std::optional<DeregistrationReason> deregistration_reason; // Mandatory
    std::optional<std::string> user_name;                   // Optional
    std::vector<std::string> public_identities;             // Optional
    std::vector<SupportedFeatures> supported_features;      // Optional
    std::vector<std::string> associated_identities;         // Optional

    nlohmann::json toJson() const;
};

/**
 * Registration-Termination-Answer (RTA)
 * Response from S-CSCF acknowledging deregistration
 */
struct RegistrationTerminationAnswer {
    std::optional<uint32_t> experimental_result_code;   // Mandatory (in Experimental-Result)
    std::vector<std::string> associated_identities;     // Optional
    std::vector<SupportedFeatures> supported_features;  // Optional

    nlohmann::json toJson() const;
};

/**
 * Push-Profile-Request (PPR)
 * Sent by HSS to S-CSCF to update user profile
 */
struct PushProfileRequest {
    std::optional<std::string> user_name;               // Mandatory
    std::optional<UserDataSH> user_data;                // Conditional
    std::optional<ChargingInformation> charging_information; // Optional
    std::vector<SupportedFeatures> supported_features;  // Optional

    nlohmann::json toJson() const;
};

/**
 * Push-Profile-Answer (PPA)
 * Response from S-CSCF acknowledging profile update
 */
struct PushProfileAnswer {
    std::optional<uint32_t> experimental_result_code;   // Mandatory (in Experimental-Result)
    std::vector<SupportedFeatures> supported_features;  // Optional

    nlohmann::json toJson() const;
};

/**
 * Top-level Cx/Dx Message Container
 * Contains the base Diameter message plus parsed Cx/Dx-specific data
 */
struct DiameterCxMessage {
    DiameterMessage base;

    // Message-specific fields (only one will be populated based on command code)
    std::optional<UserAuthorizationRequest> uar;
    std::optional<UserAuthorizationAnswer> uaa;
    std::optional<ServerAssignmentRequest> sar;
    std::optional<ServerAssignmentAnswer> saa;
    std::optional<LocationInfoRequest> lir;
    std::optional<LocationInfoAnswer> lia;
    std::optional<MultimediaAuthRequest> mar;
    std::optional<MultimediaAuthAnswer> maa;
    std::optional<RegistrationTerminationRequest> rtr;
    std::optional<RegistrationTerminationAnswer> rta;
    std::optional<PushProfileRequest> ppr;
    std::optional<PushProfileAnswer> ppa;

    nlohmann::json toJson() const;
};

// ============================================================================
// Cx/Dx Parser
// ============================================================================

/**
 * Parser for Cx/Dx Diameter messages
 * Handles all command codes defined in 3GPP TS 29.229
 */
class DiameterCxParser {
public:
    /**
     * Parse a Diameter message as Cx/Dx
     * @param msg The base Diameter message to parse
     * @return Parsed Cx/Dx message, or nullopt if parsing fails
     */
    std::optional<DiameterCxMessage> parse(const DiameterMessage& msg);

    /**
     * Check if a message is a Cx/Dx message
     * @param msg The Diameter message to check
     * @return true if message is Cx/Dx (application ID 16777216)
     */
    static bool isCxMessage(const DiameterMessage& msg);

private:
    // Request parsers
    UserAuthorizationRequest parseUAR(const DiameterMessage& msg);
    ServerAssignmentRequest parseSAR(const DiameterMessage& msg);
    LocationInfoRequest parseLIR(const DiameterMessage& msg);
    MultimediaAuthRequest parseMAR(const DiameterMessage& msg);
    RegistrationTerminationRequest parseRTR(const DiameterMessage& msg);
    PushProfileRequest parsePPR(const DiameterMessage& msg);

    // Answer parsers
    UserAuthorizationAnswer parseUAA(const DiameterMessage& msg);
    ServerAssignmentAnswer parseSAA(const DiameterMessage& msg);
    LocationInfoAnswer parseLIA(const DiameterMessage& msg);
    MultimediaAuthAnswer parseMAA(const DiameterMessage& msg);
    RegistrationTerminationAnswer parseRTA(const DiameterMessage& msg);
    PushProfileAnswer parsePPA(const DiameterMessage& msg);

    // AVP parsers for grouped/complex types
    std::optional<ServerCapabilities> parseServerCapabilities(
        std::shared_ptr<DiameterAVP> avp);
    std::optional<SIPNumberAuthItems> parseSIPNumberAuthItems(
        std::shared_ptr<DiameterAVP> avp);
    std::optional<SIPAuthDataItem> parseSIPAuthDataItem(
        std::shared_ptr<DiameterAVP> avp);
    std::optional<ChargingInformation> parseChargingInformation(
        std::shared_ptr<DiameterAVP> avp);
    std::optional<DeregistrationReason> parseDeregistrationReason(
        std::shared_ptr<DiameterAVP> avp);
    std::optional<SupportedFeatures> parseSupportedFeatures(
        std::shared_ptr<DiameterAVP> avp);
    std::optional<UserDataSH> parseUserData(std::shared_ptr<DiameterAVP> avp);
};

}  // namespace diameter
}  // namespace callflow
