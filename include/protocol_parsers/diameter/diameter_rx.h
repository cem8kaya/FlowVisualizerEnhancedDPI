#pragma once

#include "protocol_parsers/diameter/diameter_base.h"
#include "protocol_parsers/diameter/diameter_policy_types.h"
#include "common/types.h"
#include <optional>
#include <vector>
#include <nlohmann/json.hpp>

namespace callflow {
namespace diameter {

/**
 * Rx Application ID (3GPP TS 29.214)
 * Media policy control - AF (P-CSCF) to PCRF
 */
constexpr uint32_t DIAMETER_RX_APPLICATION_ID = 16777236;

/**
 * Rx-specific AVP Codes (3GPP TS 29.214)
 */
enum class RxAVPCode : uint32_t {
    // Media components
    MEDIA_COMPONENT_DESCRIPTION = 517,
    MEDIA_COMPONENT_NUMBER = 518,
    MEDIA_SUB_COMPONENT = 519,
    MEDIA_TYPE = 520,

    // Flow information
    FLOW_DESCRIPTION = 507,
    FLOW_NUMBER = 509,
    FLOW_STATUS = 511,
    FLOW_USAGE = 512,

    // AF application
    AF_APPLICATION_IDENTIFIER = 504,
    AF_CHARGING_IDENTIFIER = 505,

    // Service info
    SERVICE_INFO_STATUS = 527,
    SERVICE_URN = 525,
    SPECIFIC_ACTION = 513,

    // Codec and bandwidth
    CODEC_DATA = 524,
    RR_BANDWIDTH = 521,      // Receive-Receive bandwidth
    RS_BANDWIDTH = 522,      // Receive-Send bandwidth
    MAX_REQUESTED_BANDWIDTH_DL = 515,
    MAX_REQUESTED_BANDWIDTH_UL = 516,

    // QoS
    MIN_REQUESTED_BANDWIDTH_DL = 534,
    MIN_REQUESTED_BANDWIDTH_UL = 535,

    // Framing
    FRAMED_IP_ADDRESS = 8,
    FRAMED_IPV6_PREFIX = 97,

    // Service authorization
    SERVICE_AUTHORIZATION_INFO = 548,

    // Access network info
    ACCESS_NETWORK_CHARGING_IDENTIFIER = 502,
    ACCESS_NETWORK_CHARGING_IDENTIFIER_VALUE = 503,

    // Acceptable/Required service info
    ACCEPTABLE_SERVICE_INFO = 526,
    REQUIRED_ACCESS_INFO = 536,

    // Sharing key
    SHARING_KEY_DL = 539,
    SHARING_KEY_UL = 540,

    // Content version
    CONTENT_VERSION = 552,

    // Supported features
    SUPPORTED_FEATURES = 628,
    FEATURE_LIST_ID = 629,
    FEATURE_LIST = 630,

    // Abort cause
    ABORT_CAUSE = 500,

    // IP domain
    IP_DOMAIN_ID = 537,

    // Sponsoring
    SPONSORED_CONNECTIVITY_DATA = 530,
    SPONSOR_IDENTITY = 531,
    APPLICATION_SERVICE_PROVIDER_IDENTITY = 532,

    // Session linking
    RX_REQUEST_TYPE = 533
};

/**
 * Abort Cause
 */
enum class AbortCause : uint32_t {
    BEARER_RELEASED = 0,
    INSUFFICIENT_SERVER_RESOURCES = 1,
    INSUFFICIENT_BEARER_RESOURCES = 2
};

/**
 * Rx Request Type
 */
enum class RxRequestType : uint32_t {
    INITIAL_REQUEST = 0,
    UPDATE_REQUEST = 1
};

// ============================================================================
// Rx-specific Structures
// ============================================================================

/**
 * Media Sub-Component
 */
struct MediaSubComponent {
    uint32_t flow_number;
    std::vector<std::string> flow_descriptions;  // IPFilterRule format
    FlowUsage flow_usage;
    std::optional<FlowStatus> flow_status;
    std::optional<uint32_t> tos_traffic_class;

    nlohmann::json toJson() const;
};

/**
 * Media Component Description
 */
struct MediaComponentDescription {
    uint32_t media_component_number;
    std::vector<MediaSubComponent> media_sub_components;
    std::optional<MediaType> media_type;
    std::optional<uint32_t> max_requested_bandwidth_dl;
    std::optional<uint32_t> max_requested_bandwidth_ul;
    std::optional<uint32_t> min_requested_bandwidth_dl;
    std::optional<uint32_t> min_requested_bandwidth_ul;
    std::optional<uint32_t> rr_bandwidth;
    std::optional<uint32_t> rs_bandwidth;
    std::optional<FlowStatus> flow_status;
    std::optional<std::string> codec_data;
    std::optional<uint32_t> sharing_key_dl;
    std::optional<uint32_t> sharing_key_ul;
    std::optional<uint64_t> content_version;

    nlohmann::json toJson() const;
};

/**
 * Access Network Charging Identifier
 */
struct AccessNetworkChargingIdentifier {
    std::vector<uint8_t> access_network_charging_identifier_value;
    std::vector<std::string> flows;

    nlohmann::json toJson() const;
};

/**
 * Sponsored Connectivity Data
 */
struct SponsoredConnectivityData {
    std::optional<std::string> sponsor_identity;
    std::optional<std::string> application_service_provider_identity;

    nlohmann::json toJson() const;
};

// ============================================================================
// Rx Messages
// ============================================================================

/**
 * AA-Request (AAR) - Rx specific fields
 */
struct RxAARequest {
    // Session info
    std::optional<std::string> framed_ip_address;
    std::optional<std::string> framed_ipv6_prefix;

    // Media components
    std::vector<MediaComponentDescription> media_components;

    // AF application
    std::optional<std::string> af_application_identifier;
    std::optional<std::vector<uint8_t>> af_charging_identifier;

    // Service info
    std::optional<ServiceInfoStatus> service_info_status;
    std::optional<std::string> service_urn;

    // Specific actions
    std::vector<SpecificAction> specific_actions;

    // Access network charging
    std::vector<AccessNetworkChargingIdentifier> access_network_charging_identifiers;

    // Rx request type
    std::optional<RxRequestType> rx_request_type;

    // Sponsored connectivity
    std::optional<SponsoredConnectivityData> sponsored_connectivity_data;

    nlohmann::json toJson() const;
};

/**
 * AA-Answer (AAA) - Rx specific fields
 */
struct RxAAAnswer {
    uint32_t result_code;

    // Media component authorization
    std::vector<MediaComponentDescription> media_components;

    // Access network charging identifier
    std::vector<AccessNetworkChargingIdentifier> access_network_charging_identifiers;

    // Service authorization
    std::optional<std::string> service_authorization_info;

    // IP-CAN type
    std::optional<IPCANType> ip_can_type;

    // Acceptable service info
    std::optional<std::string> acceptable_service_info;

    nlohmann::json toJson() const;
};

/**
 * Re-Auth Request (RAR) - Rx specific fields
 */
struct RxReAuthRequest {
    uint32_t re_auth_request_type;

    // Specific actions
    std::vector<SpecificAction> specific_actions;

    // Access network charging identifier
    std::vector<AccessNetworkChargingIdentifier> access_network_charging_identifiers;

    // Abort cause
    std::optional<AbortCause> abort_cause;

    nlohmann::json toJson() const;
};

/**
 * Re-Auth Answer (RAA) - Rx specific fields
 */
struct RxReAuthAnswer {
    uint32_t result_code;

    // Media components
    std::vector<MediaComponentDescription> media_components;

    // Access network charging identifier
    std::vector<AccessNetworkChargingIdentifier> access_network_charging_identifiers;

    nlohmann::json toJson() const;
};

/**
 * Session Termination Request (STR) - Rx specific fields
 */
struct RxSessionTerminationRequest {
    uint32_t termination_cause;

    nlohmann::json toJson() const;
};

/**
 * Session Termination Answer (STA) - Rx specific fields
 */
struct RxSessionTerminationAnswer {
    uint32_t result_code;

    nlohmann::json toJson() const;
};

/**
 * Abort Session Request (ASR) - Rx specific fields
 */
struct RxAbortSessionRequest {
    std::optional<AbortCause> abort_cause;

    nlohmann::json toJson() const;
};

/**
 * Abort Session Answer (ASA) - Rx specific fields
 */
struct RxAbortSessionAnswer {
    uint32_t result_code;

    nlohmann::json toJson() const;
};

/**
 * Rx Message (extends Diameter base message)
 */
struct DiameterRxMessage {
    DiameterMessage base;

    // Parsed message-specific data
    std::optional<RxAARequest> aar;
    std::optional<RxAAAnswer> aaa;
    std::optional<RxReAuthRequest> rar;
    std::optional<RxReAuthAnswer> raa;
    std::optional<RxSessionTerminationRequest> str;
    std::optional<RxSessionTerminationAnswer> sta;
    std::optional<RxAbortSessionRequest> asr;
    std::optional<RxAbortSessionAnswer> asa;

    // Common extracted fields
    std::optional<std::string> framed_ip_address;
    std::optional<std::string> af_application_identifier;

    nlohmann::json toJson() const;
};

/**
 * Diameter Rx Parser
 *
 * Parses Rx-specific Diameter messages for the AF to PCRF interface.
 */
class DiameterRxParser {
public:
    DiameterRxParser() = default;
    ~DiameterRxParser() = default;

    /**
     * Parse Rx message from Diameter base message
     * @param msg Diameter base message
     * @return Parsed Rx message or nullopt if not Rx
     */
    std::optional<DiameterRxMessage> parse(const DiameterMessage& msg);

    /**
     * Check if message is Rx
     */
    static bool isRxMessage(const DiameterMessage& msg);

private:
    // Message-specific parsers
    RxAARequest parseAAR(const DiameterMessage& msg);
    RxAAAnswer parseAAA(const DiameterMessage& msg);
    RxReAuthRequest parseRAR(const DiameterMessage& msg);
    RxReAuthAnswer parseRAA(const DiameterMessage& msg);
    RxSessionTerminationRequest parseSTR(const DiameterMessage& msg);
    RxSessionTerminationAnswer parseSTA(const DiameterMessage& msg);
    RxAbortSessionRequest parseASR(const DiameterMessage& msg);
    RxAbortSessionAnswer parseASA(const DiameterMessage& msg);

    // AVP parsers
    std::optional<MediaComponentDescription> parseMediaComponentDescription(std::shared_ptr<DiameterAVP> avp);
    std::optional<MediaSubComponent> parseMediaSubComponent(std::shared_ptr<DiameterAVP> avp);
    std::optional<AccessNetworkChargingIdentifier> parseAccessNetworkChargingIdentifier(std::shared_ptr<DiameterAVP> avp);
    std::optional<SponsoredConnectivityData> parseSponsoredConnectivityData(std::shared_ptr<DiameterAVP> avp);

    // Helper functions
    std::vector<SpecificAction> parseSpecificActions(const DiameterMessage& msg);
};

}  // namespace diameter
}  // namespace callflow
