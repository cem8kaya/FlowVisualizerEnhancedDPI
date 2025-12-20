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
 * Gx Application ID (3GPP TS 29.212)
 * Policy and Charging Control (PCC) - P-GW to PCRF
 */
constexpr uint32_t DIAMETER_GX_APPLICATION_ID = 16777238;

/**
 * Gx-specific AVP Codes (3GPP TS 29.212)
 */
enum class GxAVPCode : uint32_t {
    // Charging rules
    CHARGING_RULE_INSTALL = 1001,
    CHARGING_RULE_REMOVE = 1002,
    CHARGING_RULE_DEFINITION = 1003,
    CHARGING_RULE_BASE_NAME = 1004,
    CHARGING_RULE_NAME = 1005,

    // Event triggers
    EVENT_TRIGGER = 1006,

    // Metering
    METERING_METHOD = 1007,
    OFFLINE = 1008,
    ONLINE = 1009,
    PRECEDENCE = 1010,
    REPORTING_LEVEL = 1011,

    // QoS
    QOS_INFORMATION = 1016,
    QOS_CLASS_IDENTIFIER = 1028,
    MAX_REQUESTED_BANDWIDTH_DL = 515,
    MAX_REQUESTED_BANDWIDTH_UL = 516,
    GUARANTEED_BITRATE_DL = 1025,
    GUARANTEED_BITRATE_UL = 1026,
    BEARER_IDENTIFIER = 1020,

    // Flow information
    FLOW_INFORMATION = 1058,
    FLOW_DESCRIPTION = 507,
    FLOW_NUMBER = 509,
    FLOW_STATUS = 511,
    FLOW_USAGE = 512,
    TOS_TRAFFIC_CLASS = 1014,

    // Usage monitoring
    USAGE_MONITORING_INFORMATION = 1067,
    MONITORING_KEY = 1066,
    GRANTED_SERVICE_UNIT = 1068,
    USED_SERVICE_UNIT = 1069,

    // Session management
    BEARER_CONTROL_MODE = 1023,
    NETWORK_REQUEST_SUPPORT = 1024,
    BEARER_OPERATION = 1021,

    // IP CAN
    IP_CAN_TYPE = 1027,
    RAT_TYPE = 1032,

    // Default EPS bearer QoS
    DEFAULT_EPS_BEARER_QOS = 1049,
    ALLOCATION_RETENTION_PRIORITY = 1034,
    PRIORITY_LEVEL = 1046,
    PRE_EMPTION_CAPABILITY = 1047,
    PRE_EMPTION_VULNERABILITY = 1048,

    // Service data container
    RATING_GROUP = 1032,
    SERVICE_IDENTIFIER = 439,

    // Network address
    FRAMED_IP_ADDRESS = 8,
    FRAMED_IPV6_PREFIX = 97,
    CALLED_STATION_ID = 30,  // APN

    // PCC rule status
    PCC_RULE_STATUS = 1019,
    RULE_FAILURE_CODE = 1031,

    // Access network info
    AN_GW_ADDRESS = 1050,
    TGPP_SGSN_ADDRESS = 6,
    TGPP_SGSN_IPV6_ADDRESS = 15,

    // Packet filters
    PACKET_FILTER_CONTENT = 1064,
    PACKET_FILTER_IDENTIFIER = 1060,
    PACKET_FILTER_INFORMATION = 1061,
    PACKET_FILTER_OPERATION = 1062,

    // Revalidation
    REVALIDATION_TIME = 1042,
    RULE_ACTIVATION_TIME = 1043,
    RULE_DEACTIVATION_TIME = 1044,

    // Session release cause
    SESSION_RELEASE_CAUSE = 1045,

    // Credit management
    CREDIT_MANAGEMENT_STATUS = 1082,

    // TDF
    TDF_INFORMATION = 1087,
    TDF_APPLICATION_IDENTIFIER = 1088,
    TDF_DESTINATION_HOST = 1089,
    TDF_DESTINATION_REALM = 1090,
    TDF_IP_ADDRESS = 1091,

    // Supported features
    SUPPORTED_FEATURES = 628,
    FEATURE_LIST_ID = 629,
    FEATURE_LIST = 630
};

/**
 * Event Trigger values (3GPP TS 29.212)
 */
enum class EventTrigger : uint32_t {
    SGSN_CHANGE = 0,
    QOS_CHANGE = 1,
    RAT_CHANGE = 2,
    TFT_CHANGE = 3,
    PLMN_CHANGE = 4,
    LOSS_OF_BEARER = 5,
    RECOVERY_OF_BEARER = 6,
    IP_CAN_CHANGE = 7,
    GW_PCEF_MALFUNCTION = 8,
    RESOURCES_LIMITATION = 9,
    MAX_NR_BEARERS_REACHED = 10,
    QOS_CHANGE_EXCEEDING_AUTHORIZATION = 11,
    RAI_CHANGE = 12,
    USER_LOCATION_CHANGE = 13,
    NO_EVENT_TRIGGERS = 14,
    OUT_OF_CREDIT = 15,
    REALLOCATION_OF_CREDIT = 16,
    REVALIDATION_TIMEOUT = 17,
    UE_IP_ADDRESS_ALLOCATE = 18,
    UE_IP_ADDRESS_RELEASE = 19,
    DEFAULT_EPS_BEARER_QOS_CHANGE = 20,
    AN_GW_CHANGE = 21,
    SUCCESSFUL_RESOURCE_ALLOCATION = 22,
    RESOURCE_MODIFICATION_REQUEST = 23,
    PGW_TRACE_CONTROL = 24,
    UE_TIME_ZONE_CHANGE = 25,
    TAI_CHANGE = 26,
    ECGI_CHANGE = 27,
    CHARGING_CORRELATION_EXCHANGE = 28,
    APN_AMBR_MODIFICATION_FAILURE = 29,
    USER_CSG_INFORMATION_CHANGE = 30,
    USAGE_REPORT = 33,
    DEFAULT_EPS_BEARER_QOS_MODIFICATION_FAILURE = 34,
    USER_CSG_HYBRID_SUBSCRIBED_INFORMATION_CHANGE = 35,
    USER_CSG_HYBRID_UNSUBSCRIBED_INFORMATION_CHANGE = 36,
    ROUTING_RULE_CHANGE = 37,
    APPLICATION_START = 39,
    APPLICATION_STOP = 40,
    CS_TO_PS_HANDOVER = 42,
    UE_LOCAL_IP_ADDRESS_CHANGE = 43,
    HENB_LOCAL_IP_ADDRESS_CHANGE = 44,
    ACCESS_NETWORK_INFO_REPORT = 45,
    CREDIT_MANAGEMENT_SESSION_FAILURE = 46,
    DEFAULT_QOS_CHANGE = 47,
    CHANGE_OF_UE_PRESENCE_IN_PRESENCE_REPORTING_AREA = 48
};

/**
 * PCC Rule Status
 */
enum class PCCRuleStatus : uint32_t {
    ACTIVE = 0,
    INACTIVE = 1,
    TEMPORARILY_INACTIVE = 2
};

/**
 * Rule Failure Code
 */
enum class RuleFailureCode : uint32_t {
    UNKNOWN_RULE_NAME = 1,
    RATING_GROUP_ERROR = 2,
    SERVICE_IDENTIFIER_ERROR = 3,
    GW_PCEF_MALFUNCTION = 4,
    RESOURCES_LIMITATION = 5,
    MAX_NR_BEARERS_REACHED = 6,
    UNKNOWN_BEARER_ID = 7,
    MISSING_BEARER_ID = 8,
    MISSING_FLOW_INFORMATION = 9,
    RESOURCE_ALLOCATION_FAILURE = 10,
    UNSUCCESSFUL_QOS_VALIDATION = 11,
    INCORRECT_FLOW_INFORMATION = 12,
    PS_TO_CS_HANDOVER = 13,
    TDF_APPLICATION_IDENTIFIER_ERROR = 14,
    NO_BEARER_BOUND = 15,
    FILTER_RESTRICTIONS = 16,
    AN_GW_FAILED = 17,
    MISSING_REDIRECT_SERVER_ADDRESS = 18,
    CM_END_USER_SERVICE_DENIED = 19,
    CM_CREDIT_CONTROL_NOT_APPLICABLE = 20,
    CM_AUTHORIZATION_REJECTED = 21,
    CM_USER_UNKNOWN = 22,
    CM_RATING_FAILED = 23
};

/**
 * Session Release Cause
 */
enum class SessionReleaseCause : uint32_t {
    UNSPECIFIED_REASON = 0,
    UE_SUBSCRIPTION_REASON = 1,
    INSUFFICIENT_SERVER_RESOURCES = 2,
    IP_CAN_SESSION_TERMINATION = 3,
    UE_IP_ADDRESS_RELEASE = 4
};

// ============================================================================
// Gx-specific Structures
// ============================================================================

/**
 * Charging Rule Definition
 */
struct ChargingRuleDefinition {
    std::string charging_rule_name;
    std::optional<uint32_t> service_identifier;
    std::optional<uint32_t> rating_group;
    std::vector<FlowInformation> flow_information;
    std::optional<QoSInformation> qos_information;
    std::optional<uint32_t> precedence;
    std::optional<FlowStatus> flow_status;
    std::optional<MeteringMethod> metering_method;
    std::optional<ReportingLevel> reporting_level;
    std::optional<uint32_t> online;
    std::optional<uint32_t> offline;
    std::optional<std::chrono::system_clock::time_point> rule_activation_time;
    std::optional<std::chrono::system_clock::time_point> rule_deactivation_time;

    nlohmann::json toJson() const;
};

/**
 * Charging Rule Install
 */
struct ChargingRuleInstall {
    std::vector<ChargingRuleDefinition> charging_rule_definition;
    std::vector<std::string> charging_rule_name;
    std::vector<std::string> charging_rule_base_name;
    std::optional<uint32_t> bearer_identifier;
    std::optional<BearerOperation> bearer_operation;
    std::optional<std::chrono::system_clock::time_point> rule_activation_time;
    std::optional<std::chrono::system_clock::time_point> rule_deactivation_time;

    nlohmann::json toJson() const;
};

/**
 * Charging Rule Remove
 */
struct ChargingRuleRemove {
    std::vector<std::string> charging_rule_name;
    std::vector<std::string> charging_rule_base_name;

    nlohmann::json toJson() const;
};

/**
 * Usage Monitoring Information
 */
struct UsageMonitoringInformation {
    std::optional<std::vector<uint8_t>> monitoring_key;
    std::optional<GrantedServiceUnit> granted_service_unit;
    std::optional<UsedServiceUnit> used_service_unit;
    std::optional<uint32_t> usage_monitoring_level;
    std::optional<uint32_t> usage_monitoring_report;
    std::optional<uint32_t> usage_monitoring_support;

    nlohmann::json toJson() const;
};

/**
 * PCC Rule Status Report
 */
struct PCCRuleStatusReport {
    std::vector<std::string> rule_names;
    PCCRuleStatus pcc_rule_status;
    std::optional<RuleFailureCode> rule_failure_code;

    nlohmann::json toJson() const;
};

// ============================================================================
// Gx Messages
// ============================================================================

/**
 * Credit Control Request (CCR) - Gx specific fields
 */
struct GxCreditControlRequest {
    CCRequestType cc_request_type;
    uint32_t cc_request_number;

    // Network information
    std::optional<std::string> network_request_support;
    std::optional<BearerControlMode> bearer_control_mode;
    std::optional<IPCANType> ip_can_type;
    std::optional<uint32_t> rat_type;

    // Subscriber information
    std::optional<std::string> framed_ip_address;
    std::optional<std::string> framed_ipv6_prefix;
    std::optional<std::string> called_station_id;  // APN
    std::optional<SubscriptionId> subscription_id;

    // Event reporting
    std::vector<EventTrigger> event_triggers;

    // Usage monitoring
    std::vector<UsageMonitoringInformation> usage_monitoring;

    // PCC rule reports
    std::vector<PCCRuleStatusReport> pcc_rule_status_reports;

    // Access network info
    std::optional<std::string> an_gw_address;
    std::optional<std::string> tgpp_sgsn_address;

    nlohmann::json toJson() const;
};

/**
 * Credit Control Answer (CCA) - Gx specific fields
 */
struct GxCreditControlAnswer {
    uint32_t result_code;
    CCRequestType cc_request_type;
    uint32_t cc_request_number;

    // Charging rules
    std::vector<ChargingRuleInstall> charging_rule_install;
    std::vector<ChargingRuleRemove> charging_rule_remove;

    // QoS
    std::optional<QoSInformation> qos_information;
    std::optional<DefaultEPSBearerQoS> default_eps_bearer_qos;

    // Bearer control
    std::optional<BearerControlMode> bearer_control_mode;
    std::optional<BearerOperation> bearer_operation;

    // Usage monitoring
    std::vector<UsageMonitoringInformation> usage_monitoring;

    // Event triggers
    std::vector<EventTrigger> event_triggers;

    // Revalidation
    std::optional<std::chrono::system_clock::time_point> revalidation_time;

    // Session control
    std::optional<SessionReleaseCause> session_release_cause;

    // Supported features
    std::optional<uint32_t> supported_features;

    nlohmann::json toJson() const;
};

/**
 * Re-Auth Request (RAR) - Gx specific fields
 */
struct GxReAuthRequest {
    uint32_t re_auth_request_type;

    // Charging rules
    std::vector<ChargingRuleInstall> charging_rule_install;
    std::vector<ChargingRuleRemove> charging_rule_remove;

    // QoS updates
    std::optional<QoSInformation> qos_information;
    std::optional<DefaultEPSBearerQoS> default_eps_bearer_qos;

    // Event triggers
    std::vector<EventTrigger> event_triggers;

    // Usage monitoring
    std::vector<UsageMonitoringInformation> usage_monitoring;

    nlohmann::json toJson() const;
};

/**
 * Re-Auth Answer (RAA) - Gx specific fields
 */
struct GxReAuthAnswer {
    uint32_t result_code;

    // PCC rule reports
    std::vector<PCCRuleStatusReport> pcc_rule_status_reports;

    nlohmann::json toJson() const;
};

/**
 * Gx Message (extends Diameter base message)
 */
struct DiameterGxMessage {
    DiameterMessage base;

    // Parsed message-specific data
    std::optional<GxCreditControlRequest> ccr;
    std::optional<GxCreditControlAnswer> cca;
    std::optional<GxReAuthRequest> rar;
    std::optional<GxReAuthAnswer> raa;

    // Common extracted fields
    std::optional<std::string> framed_ip_address;
    std::optional<std::string> called_station_id;  // APN
    std::optional<CCRequestType> cc_request_type;

    nlohmann::json toJson() const;
};

/**
 * Diameter Gx Parser
 *
 * Parses Gx-specific Diameter messages for the P-GW to PCRF interface.
 */
class DiameterGxParser {
public:
    DiameterGxParser() = default;
    ~DiameterGxParser() = default;

    /**
     * Parse Gx message from Diameter base message
     * @param msg Diameter base message
     * @return Parsed Gx message or nullopt if not Gx
     */
    std::optional<DiameterGxMessage> parse(const DiameterMessage& msg);

    /**
     * Check if message is Gx
     */
    static bool isGxMessage(const DiameterMessage& msg);

private:
    // Message-specific parsers
    GxCreditControlRequest parseCCR(const DiameterMessage& msg);
    GxCreditControlAnswer parseCCA(const DiameterMessage& msg);
    GxReAuthRequest parseRAR(const DiameterMessage& msg);
    GxReAuthAnswer parseRAA(const DiameterMessage& msg);

    // AVP parsers
    std::optional<ChargingRuleInstall> parseChargingRuleInstall(std::shared_ptr<DiameterAVP> avp);
    std::optional<ChargingRuleRemove> parseChargingRuleRemove(std::shared_ptr<DiameterAVP> avp);
    std::optional<ChargingRuleDefinition> parseChargingRuleDefinition(std::shared_ptr<DiameterAVP> avp);
    std::optional<QoSInformation> parseQoSInformation(std::shared_ptr<DiameterAVP> avp);
    std::optional<DefaultEPSBearerQoS> parseDefaultEPSBearerQoS(std::shared_ptr<DiameterAVP> avp);
    std::optional<AllocationRetentionPriority> parseAllocationRetentionPriority(std::shared_ptr<DiameterAVP> avp);
    std::optional<FlowInformation> parseFlowInformation(std::shared_ptr<DiameterAVP> avp);
    std::optional<UsageMonitoringInformation> parseUsageMonitoringInformation(std::shared_ptr<DiameterAVP> avp);
    std::optional<ServiceUnit> parseServiceUnit(std::shared_ptr<DiameterAVP> avp);
    std::optional<UsedServiceUnit> parseUsedServiceUnit(std::shared_ptr<DiameterAVP> avp);
    std::optional<PCCRuleStatusReport> parsePCCRuleStatusReport(std::shared_ptr<DiameterAVP> avp);

    // Helper functions
    std::vector<EventTrigger> parseEventTriggers(const DiameterMessage& msg);
};

}  // namespace diameter
}  // namespace callflow
