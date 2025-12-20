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
 * Sh Application ID (3GPP TS 29.328/29.329)
 * IMS Application Server to HSS interface
 */
constexpr uint32_t DIAMETER_SH_APPLICATION_ID = 16777217;

/**
 * Sh-specific AVP Codes (3GPP TS 29.329)
 */
enum class ShAVPCode : uint32_t {
    // User Identity
    USER_IDENTITY = 700,                // Grouped
    MSISDN = 701,                       // OctetString
    USER_DATA = 702,                    // OctetString (XML)
    DATA_REFERENCE = 703,               // Enumerated
    SERVICE_INDICATION = 704,           // OctetString
    SUBS_REQ_TYPE = 705,                // Enumerated
    REQUESTED_DOMAIN = 706,             // Enumerated
    CURRENT_LOCATION = 707,             // Enumerated

    // Identity and Subscription Info
    IDENTITY_SET = 708,                 // Enumerated
    EXPIRY_TIME = 709,                  // Time
    SEND_DATA_INDICATION = 710,         // Enumerated

    // DSAI (Dynamic Service Activation Information)
    DSAI_TAG = 711,                     // OctetString

    // One Time Notification
    ONE_TIME_NOTIFICATION = 712,        // Enumerated

    // Repository Data
    REPOSITORY_DATA_ID = 715,           // Grouped
    SEQUENCE_NUMBER = 716,              // Unsigned32

    // Pre-paging support
    PRE_PAGING_SUPPORTED = 717,         // Enumerated

    // Local Time Zone
    LOCAL_TIME_ZONE_INDICATION = 718,   // Enumerated

    // UDR flags
    UDR_FLAGS = 719,                    // Unsigned32

    // Call Reference Info
    CALL_REFERENCE_INFO = 720,          // Grouped
    CALL_REFERENCE_NUMBER = 721,        // OctetString
    AS_NUMBER = 722,                    // OctetString

    // Originating Request
    ORIGINATING_REQUEST = 633,          // Enumerated

    // Wildcarded Public Identity
    WILDCARDED_PUBLIC_IDENTITY = 634,   // UTF8String
    WILDCARDED_IMPU = 636,              // UTF8String

    // Session Priority
    SESSION_PRIORITY = 650,             // Enumerated

    // Supported Features (shared with Cx/Dx)
    SUPPORTED_FEATURES = 628,           // Grouped
    FEATURE_LIST_ID = 629,              // Unsigned32
    FEATURE_LIST = 630,                 // Unsigned32

    // Public Identity
    PUBLIC_IDENTITY = 601,              // UTF8String

    // Server Name
    SERVER_NAME = 602,                  // UTF8String

    // Requested Nodes
    REQUESTED_NODES = 713,              // Unsigned32

    // Serving Node Indication
    SERVING_NODE_INDICATION = 714,      // Enumerated

    // User Data (already defined above, but commonly used)
    // USER_DATA = 702

    // External Identifier
    EXTERNAL_IDENTIFIER = 653           // UTF8String
};

/**
 * Sh Command Codes (3GPP TS 29.329)
 * Request bit determines if it's a request or answer
 */
enum class ShCommandCode : uint32_t {
    USER_DATA = 306,                    // UDR (Request) / UDA (Answer)
    PROFILE_UPDATE = 307,               // PUR (Request) / PUA (Answer)
    SUBSCRIBE_NOTIFICATIONS = 308,      // SNR (Request) / SNA (Answer)
    PUSH_NOTIFICATION = 309             // PNR (Request) / PNA (Answer)
};

/**
 * One Time Notification (AVP 712)
 */
enum class OneTimeNotification : uint32_t {
    ONE_TIME_NOTIFICATION_REQUESTED = 0
};

/**
 * Pre-paging Supported (AVP 717)
 */
enum class PrePagingSupported : uint32_t {
    PREPAGING_NOT_SUPPORTED = 0,
    PREPAGING_SUPPORTED = 1
};

/**
 * Local Time Zone Indication (AVP 718)
 */
enum class LocalTimeZoneIndication : uint32_t {
    ONLY_LOCAL_TIME_ZONE_REQUESTED = 0,
    LOCAL_TIME_ZONE_WITH_LOCATION_INFO_REQUESTED = 1
};

/**
 * Serving Node Indication (AVP 714)
 */
enum class ServingNodeIndication : uint32_t {
    ONLY_SERVING_NODES_REQUIRED = 0
};

// ============================================================================
// Sh Message Structures
// ============================================================================

/**
 * User-Data-Request (UDR)
 * Sent by AS to HSS to request user data
 */
struct UserDataRequest {
    std::vector<UserIdentity> user_identities;          // Mandatory
    std::vector<DataReference> data_references;         // Mandatory
    std::optional<std::string> service_indication;      // Conditional
    std::vector<IdentitySet> identity_sets;             // Optional
    std::optional<RequestedDomain> requested_domain;    // Optional
    std::optional<CurrentLocation> current_location;    // Optional
    std::vector<SupportedFeatures> supported_features;  // Optional
    std::optional<uint32_t> requested_nodes;            // Optional
    std::optional<ServingNodeIndication> serving_node_indication; // Optional
    std::optional<LocalTimeZoneIndication> local_time_zone_indication; // Optional
    std::optional<uint32_t> udr_flags;                  // Optional
    std::optional<std::string> call_reference_info;     // Optional
    std::optional<uint32_t> originating_request;        // Optional
    std::optional<uint32_t> session_priority;           // Optional

    nlohmann::json toJson() const;
};

/**
 * User-Data-Answer (UDA)
 * Response from HSS with requested user data
 */
struct UserDataAnswer {
    std::optional<uint32_t> experimental_result_code;   // Mandatory (in Experimental-Result)
    std::optional<UserDataSH> user_data;                // Conditional
    std::vector<SupportedFeatures> supported_features;  // Optional
    std::optional<std::string> wildcarded_public_identity; // Optional

    nlohmann::json toJson() const;
};

/**
 * Profile-Update-Request (PUR)
 * Sent by AS to HSS to update repository data
 */
struct ProfileUpdateRequest {
    std::vector<UserIdentity> user_identities;          // Mandatory
    std::optional<UserDataSH> user_data;                // Mandatory
    std::optional<DataReference> data_reference;        // Mandatory
    std::optional<std::string> service_indication;      // Conditional
    std::optional<RepositoryDataID> repository_data_id; // Optional
    std::vector<SupportedFeatures> supported_features;  // Optional
    std::optional<std::string> wildcarded_public_identity; // Optional
    std::optional<uint32_t> originating_request;        // Optional
    std::optional<uint32_t> session_priority;           // Optional

    nlohmann::json toJson() const;
};

/**
 * Profile-Update-Answer (PUA)
 * Response from HSS acknowledging profile update
 */
struct ProfileUpdateAnswer {
    std::optional<uint32_t> experimental_result_code;   // Mandatory (in Experimental-Result)
    std::optional<RepositoryDataID> repository_data_id; // Optional
    std::vector<SupportedFeatures> supported_features;  // Optional
    std::optional<std::string> wildcarded_public_identity; // Optional

    nlohmann::json toJson() const;
};

/**
 * Subscribe-Notifications-Request (SNR)
 * Sent by AS to HSS to subscribe to user data changes
 */
struct SubscribeNotificationsRequest {
    std::vector<UserIdentity> user_identities;          // Mandatory
    std::optional<SubscriptionRequestType> subs_req_type; // Mandatory
    std::vector<DataReference> data_references;         // Mandatory
    std::optional<std::string> service_indication;      // Conditional
    std::optional<SendDataIndication> send_data_indication; // Optional
    std::optional<std::string> server_name;             // Optional
    std::vector<SupportedFeatures> supported_features;  // Optional
    std::optional<std::vector<std::string>> dsai_tags;  // Optional
    std::optional<std::string> wildcarded_public_identity; // Optional
    std::optional<uint32_t> expiry_time;                // Optional
    std::optional<uint32_t> session_priority;           // Optional

    nlohmann::json toJson() const;
};

/**
 * Subscribe-Notifications-Answer (SNA)
 * Response from HSS acknowledging subscription
 */
struct SubscribeNotificationsAnswer {
    std::optional<uint32_t> experimental_result_code;   // Mandatory (in Experimental-Result)
    std::optional<UserDataSH> user_data;                // Conditional
    std::optional<uint32_t> expiry_time;                // Optional
    std::vector<SupportedFeatures> supported_features;  // Optional
    std::optional<std::string> wildcarded_public_identity; // Optional

    nlohmann::json toJson() const;
};

/**
 * Push-Notification-Request (PNR)
 * Sent by HSS to AS to notify of user data changes
 */
struct PushNotificationRequest {
    std::vector<UserIdentity> user_identities;          // Mandatory
    std::optional<UserDataSH> user_data;                // Mandatory
    std::vector<SupportedFeatures> supported_features;  // Optional
    std::optional<std::string> wildcarded_public_identity; // Optional

    nlohmann::json toJson() const;
};

/**
 * Push-Notification-Answer (PNA)
 * Response from AS acknowledging notification
 */
struct PushNotificationAnswer {
    std::optional<uint32_t> experimental_result_code;   // Mandatory (in Experimental-Result)
    std::vector<SupportedFeatures> supported_features;  // Optional

    nlohmann::json toJson() const;
};

/**
 * Top-level Sh Message Container
 * Contains the base Diameter message plus parsed Sh-specific data
 */
struct DiameterShMessage {
    DiameterMessage base;

    // Message-specific fields (only one will be populated based on command code)
    std::optional<UserDataRequest> udr;
    std::optional<UserDataAnswer> uda;
    std::optional<ProfileUpdateRequest> pur;
    std::optional<ProfileUpdateAnswer> pua;
    std::optional<SubscribeNotificationsRequest> snr;
    std::optional<SubscribeNotificationsAnswer> sna;
    std::optional<PushNotificationRequest> pnr;
    std::optional<PushNotificationAnswer> pna;

    nlohmann::json toJson() const;
};

// ============================================================================
// Sh Parser
// ============================================================================

/**
 * Parser for Sh Diameter messages
 * Handles all command codes defined in 3GPP TS 29.329
 */
class DiameterShParser {
public:
    /**
     * Parse a Diameter message as Sh
     * @param msg The base Diameter message to parse
     * @return Parsed Sh message, or nullopt if parsing fails
     */
    std::optional<DiameterShMessage> parse(const DiameterMessage& msg);

    /**
     * Check if a message is a Sh message
     * @param msg The Diameter message to check
     * @return true if message is Sh (application ID 16777217)
     */
    static bool isShMessage(const DiameterMessage& msg);

private:
    // Request parsers
    UserDataRequest parseUDR(const DiameterMessage& msg);
    ProfileUpdateRequest parsePUR(const DiameterMessage& msg);
    SubscribeNotificationsRequest parseSNR(const DiameterMessage& msg);
    PushNotificationRequest parsePNR(const DiameterMessage& msg);

    // Answer parsers
    UserDataAnswer parseUDA(const DiameterMessage& msg);
    ProfileUpdateAnswer parsePUA(const DiameterMessage& msg);
    SubscribeNotificationsAnswer parseSNA(const DiameterMessage& msg);
    PushNotificationAnswer parsePNA(const DiameterMessage& msg);

    // AVP parsers for grouped/complex types
    std::optional<UserIdentity> parseUserIdentity(std::shared_ptr<DiameterAVP> avp);
    std::optional<RepositoryDataID> parseRepositoryDataID(std::shared_ptr<DiameterAVP> avp);
    std::optional<SupportedFeatures> parseSupportedFeatures(std::shared_ptr<DiameterAVP> avp);
    std::optional<UserDataSH> parseUserData(std::shared_ptr<DiameterAVP> avp);
};

}  // namespace diameter
}  // namespace callflow
