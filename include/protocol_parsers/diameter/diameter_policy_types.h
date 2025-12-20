#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace callflow {
namespace diameter {

// ============================================================================
// Common Policy and Charging Types
// ============================================================================

/**
 * Flow Direction
 */
enum class FlowDirection : uint32_t {
    UNSPECIFIED = 0,
    DOWNLINK = 1,
    UPLINK = 2,
    BIDIRECTIONAL = 3
};

/**
 * Flow Status
 */
enum class FlowStatus : uint32_t {
    ENABLED_UPLINK = 0,
    ENABLED_DOWNLINK = 1,
    ENABLED = 2,
    DISABLED = 3,
    REMOVED = 4
};

/**
 * Flow Usage
 */
enum class FlowUsage : uint32_t {
    NO_INFORMATION = 0,
    RTCP = 1,
    AF_SIGNALLING = 2
};

/**
 * Media Type
 */
enum class MediaType : uint32_t {
    AUDIO = 0,
    VIDEO = 1,
    DATA = 2,
    APPLICATION = 3,
    CONTROL = 4,
    TEXT = 5,
    MESSAGE = 6,
    OTHER = 0xFFFFFFFF
};

/**
 * Service Info Status
 */
enum class ServiceInfoStatus : uint32_t {
    FINAL_SERVICE_INFORMATION = 0,
    PRELIMINARY_SERVICE_INFORMATION = 1
};

/**
 * Specific Action
 */
enum class SpecificAction : uint32_t {
    SERVICE_INFORMATION_REQUEST = 0,
    CHARGING_CORRELATION_EXCHANGE = 1,
    INDICATION_OF_LOSS_OF_BEARER = 2,
    INDICATION_OF_RECOVERY_OF_BEARER = 3,
    INDICATION_OF_RELEASE_OF_BEARER = 4,
    IP_CAN_CHANGE = 6,
    INDICATION_OF_OUT_OF_CREDIT = 7,
    INDICATION_OF_SUCCESSFUL_RESOURCES_ALLOCATION = 8,
    INDICATION_OF_FAILED_RESOURCES_ALLOCATION = 9,
    INDICATION_OF_LIMITED_PCC_DEPLOYMENT = 10,
    USAGE_REPORT = 11,
    ACCESS_NETWORK_INFO_REPORT = 12,
    INDICATION_OF_RECOVERY_FROM_LIMITED_PCC_DEPLOYMENT = 13,
    INDICATION_OF_ACCESS_NETWORK_INFO_REPORTING_FAILURE = 14,
    INDICATION_OF_TRANSFER_POLICY_EXPIRED = 15
};

/**
 * CC-Request-Type (Credit Control Request Type)
 */
enum class CCRequestType : uint32_t {
    INITIAL_REQUEST = 1,
    UPDATE_REQUEST = 2,
    TERMINATION_REQUEST = 3,
    EVENT_REQUEST = 4
};

/**
 * Bearer Control Mode
 */
enum class BearerControlMode : uint32_t {
    UE_ONLY = 0,
    RESERVED = 1,
    UE_NW = 2
};

/**
 * Bearer Operation
 */
enum class BearerOperation : uint32_t {
    TERMINATION = 0,
    ESTABLISHMENT = 1,
    MODIFICATION = 2
};

/**
 * Network Request Support
 */
enum class NetworkRequestSupport : uint32_t {
    NETWORK_REQUEST_NOT_SUPPORTED = 0,
    NETWORK_REQUEST_SUPPORTED = 1
};

/**
 * IP-CAN-Type
 */
enum class IPCANType : uint32_t {
    TGPP_GPRS = 0,
    DOCSIS = 1,
    XDSL = 2,
    WIMAX = 3,
    TGPP2 = 4,
    TGPP_EPS = 5,
    NON_3GPP_EPS = 6,
    FBA = 7,
    TGPP_5GS = 8,
    NON_3GPP_5GS = 9
};

/**
 * Metering Method
 */
enum class MeteringMethod : uint32_t {
    DURATION = 0,
    VOLUME = 1,
    DURATION_VOLUME = 2,
    EVENT = 3
};

/**
 * Reporting Level
 */
enum class ReportingLevel : uint32_t {
    SERVICE_IDENTIFIER_LEVEL = 0,
    RATING_GROUP_LEVEL = 1,
    SPONSORED_CONNECTIVITY_LEVEL = 2
};

/**
 * Final Unit Action
 */
enum class FinalUnitAction : uint32_t {
    TERMINATE = 0,
    REDIRECT = 1,
    RESTRICT_ACCESS = 2
};

/**
 * Redirect Address Type
 */
enum class RedirectAddressType : uint32_t {
    IPv4_ADDRESS = 0,
    IPv6_ADDRESS = 1,
    URL = 2,
    SIP_URI = 3
};

/**
 * Tariff Change Usage
 */
enum class TariffChangeUsage : uint32_t {
    UNIT_BEFORE_TARIFF_CHANGE = 0,
    UNIT_AFTER_TARIFF_CHANGE = 1,
    UNIT_INDETERMINATE = 2
};

/**
 * Pre-emption Capability
 */
enum class PreemptionCapability : uint32_t {
    PRE_EMPTION_CAPABILITY_ENABLED = 0,
    PRE_EMPTION_CAPABILITY_DISABLED = 1
};

/**
 * Pre-emption Vulnerability
 */
enum class PreemptionVulnerability : uint32_t {
    PRE_EMPTION_VULNERABILITY_ENABLED = 0,
    PRE_EMPTION_VULNERABILITY_DISABLED = 1
};

// ============================================================================
// Common Structures
// ============================================================================

/**
 * Allocation Retention Priority (ARP)
 */
struct AllocationRetentionPriority {
    uint32_t priority_level;  // 1-15, 1 is highest
    PreemptionCapability pre_emption_capability;
    PreemptionVulnerability pre_emption_vulnerability;

    nlohmann::json toJson() const;
};

/**
 * QoS Information
 */
struct QoSInformation {
    std::optional<uint32_t> qos_class_identifier;  // QCI (1-9 standardized)
    std::optional<uint32_t> max_requested_bandwidth_ul;
    std::optional<uint32_t> max_requested_bandwidth_dl;
    std::optional<uint32_t> guaranteed_bitrate_ul;
    std::optional<uint32_t> guaranteed_bitrate_dl;
    std::optional<uint32_t> bearer_identifier;
    std::optional<AllocationRetentionPriority> allocation_retention_priority;
    std::optional<uint32_t> apn_aggregate_max_bitrate_ul;
    std::optional<uint32_t> apn_aggregate_max_bitrate_dl;

    nlohmann::json toJson() const;
};

/**
 * Default EPS Bearer QoS
 */
struct DefaultEPSBearerQoS {
    uint32_t qos_class_identifier;  // QCI
    AllocationRetentionPriority allocation_retention_priority;

    nlohmann::json toJson() const;
};

/**
 * Flow Information
 */
struct FlowInformation {
    FlowDirection flow_direction;
    std::string flow_description;  // IPFilterRule format
    std::optional<uint32_t> tos_traffic_class;

    nlohmann::json toJson() const;
};

/**
 * Service Unit (for credit control)
 */
struct ServiceUnit {
    std::optional<uint32_t> cc_time;            // seconds
    std::optional<uint64_t> cc_total_octets;    // bytes
    std::optional<uint64_t> cc_input_octets;    // bytes (uplink)
    std::optional<uint64_t> cc_output_octets;   // bytes (downlink)
    std::optional<uint32_t> cc_service_specific_units;

    nlohmann::json toJson() const;
};

/**
 * Granted Service Unit
 */
using GrantedServiceUnit = ServiceUnit;

/**
 * Requested Service Unit
 */
using RequestedServiceUnit = ServiceUnit;

/**
 * Used Service Unit (with tariff change info)
 */
struct UsedServiceUnit {
    std::optional<uint32_t> cc_time;
    std::optional<uint64_t> cc_total_octets;
    std::optional<uint64_t> cc_input_octets;
    std::optional<uint64_t> cc_output_octets;
    std::optional<uint32_t> cc_service_specific_units;
    std::optional<TariffChangeUsage> tariff_change_usage;
    std::optional<uint32_t> reporting_reason;

    nlohmann::json toJson() const;
};

/**
 * Redirect Server
 */
struct RedirectServer {
    RedirectAddressType redirect_address_type;
    std::string redirect_server_address;

    nlohmann::json toJson() const;
};

/**
 * Final Unit Indication
 */
struct FinalUnitIndication {
    FinalUnitAction final_unit_action;
    std::vector<std::string> restriction_filter_rule;
    std::vector<std::string> filter_id;
    std::optional<RedirectServer> redirect_server;

    nlohmann::json toJson() const;
};

/**
 * Subscription-Id-Type
 */
enum class SubscriptionIdType : uint32_t {
    END_USER_E164 = 0,
    END_USER_IMSI = 1,
    END_USER_SIP_URI = 2,
    END_USER_NAI = 3,
    END_USER_PRIVATE = 4
};

/**
 * Subscription ID
 */
struct SubscriptionId {
    SubscriptionIdType subscription_id_type;
    std::string subscription_id_data;

    nlohmann::json toJson() const;
};

/**
 * User Equipment Info Type
 */
enum class UserEquipmentInfoType : uint32_t {
    IMEISV = 0,
    MAC = 1,
    EUI64 = 2,
    MODIFIED_EUI64 = 3
};

/**
 * User Equipment Info
 */
struct UserEquipmentInfo {
    UserEquipmentInfoType user_equipment_info_type;
    std::string user_equipment_info_value;

    nlohmann::json toJson() const;
};

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Get flow direction name
 */
std::string getFlowDirectionName(FlowDirection direction);

/**
 * Get flow status name
 */
std::string getFlowStatusName(FlowStatus status);

/**
 * Get flow usage name
 */
std::string getFlowUsageName(FlowUsage usage);

/**
 * Get media type name
 */
std::string getMediaTypeName(MediaType type);

/**
 * Get CC request type name
 */
std::string getCCRequestTypeName(CCRequestType type);

/**
 * Get IP-CAN type name
 */
std::string getIPCANTypeName(IPCANType type);

/**
 * Get final unit action name
 */
std::string getFinalUnitActionName(FinalUnitAction action);

}  // namespace diameter
}  // namespace callflow
