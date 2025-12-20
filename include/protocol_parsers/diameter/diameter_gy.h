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
 * Gy/Ro Application ID (3GPP TS 32.299)
 * Diameter Credit Control Application (DCCA) - Online Charging
 */
constexpr uint32_t DIAMETER_GY_APPLICATION_ID = 4;  // RFC 4006

/**
 * Gy/Ro-specific AVP Codes (3GPP TS 32.299 + RFC 4006)
 */
enum class GyAVPCode : uint32_t {
    // Credit Control (RFC 4006)
    CC_REQUEST_TYPE = 416,
    CC_REQUEST_NUMBER = 415,
    CC_SESSION_FAILOVER = 418,
    CC_SUB_SESSION_ID = 419,
    SUBSCRIPTION_ID = 443,
    SUBSCRIPTION_ID_TYPE = 450,
    SUBSCRIPTION_ID_DATA = 444,

    // Multiple Services Credit Control
    MULTIPLE_SERVICES_CREDIT_CONTROL = 456,
    REQUESTED_SERVICE_UNIT = 437,
    GRANTED_SERVICE_UNIT = 431,
    USED_SERVICE_UNIT = 446,

    // Service units
    CC_TIME = 420,
    CC_MONEY = 413,
    CC_TOTAL_OCTETS = 421,
    CC_INPUT_OCTETS = 412,
    CC_OUTPUT_OCTETS = 414,
    CC_SERVICE_SPECIFIC_UNITS = 417,

    // Rating and service
    RATING_GROUP = 432,
    SERVICE_IDENTIFIER = 439,
    SERVICE_CONTEXT_ID = 461,

    // Validity and quota management
    VALIDITY_TIME = 448,
    FINAL_UNIT_INDICATION = 430,
    FINAL_UNIT_ACTION = 449,
    RESTRICTION_FILTER_RULE = 438,
    FILTER_ID = 11,
    REDIRECT_SERVER = 434,
    REDIRECT_ADDRESS_TYPE = 433,
    REDIRECT_SERVER_ADDRESS = 435,

    // Result codes
    RESULT_CODE = 268,
    COST_INFORMATION = 423,
    UNIT_VALUE = 445,
    CURRENCY_CODE = 425,
    COST_UNIT = 424,

    // User equipment info
    USER_EQUIPMENT_INFO = 458,
    USER_EQUIPMENT_INFO_TYPE = 459,
    USER_EQUIPMENT_INFO_VALUE = 460,

    // Service information
    SERVICE_INFORMATION = 873,
    PS_INFORMATION = 874,
    IMS_INFORMATION = 876,
    MMS_INFORMATION = 877,
    LCS_INFORMATION = 878,
    POC_INFORMATION = 879,
    MBMS_INFORMATION = 880,

    // 3GPP PS Information
    TGPP_CHARGING_ID = 2,
    TGPP_PDP_TYPE = 3,
    TGPP_CG_ADDRESS = 4,
    TGPP_GPRS_NEGOTIATED_QOS_PROFILE = 5,
    TGPP_SGSN_ADDRESS = 6,
    TGPP_GGSN_ADDRESS = 7,
    TGPP_IMSI_MCC_MNC = 8,
    TGPP_GGSN_MCC_MNC = 9,
    TGPP_NSAPI = 10,
    TGPP_SESSION_STOP_INDICATOR = 11,
    TGPP_SELECTION_MODE = 12,
    TGPP_CHARGING_CHARACTERISTICS = 13,
    TGPP_SGSN_MCC_MNC = 18,
    TGPP_MS_TIMEZONE = 23,
    TGPP_USER_LOCATION_INFO = 22,
    TGPP_RAT_TYPE = 21,

    // Called/Calling station
    CALLED_STATION_ID = 30,
    CALLING_STATION_ID = 31,

    // Tariff
    TARIFF_CHANGE_USAGE = 452,
    TARIFF_TIME_CHANGE = 451,

    // Reporting
    REPORTING_REASON = 872,

    // Trigger
    TRIGGER_TYPE = 870,
    TRIGGER = 1264,

    // QoS
    QOS_INFORMATION = 1016,
    QOS_CLASS_IDENTIFIER = 1028,
    MAX_REQUESTED_BANDWIDTH_UL = 516,
    MAX_REQUESTED_BANDWIDTH_DL = 515,
    GUARANTEED_BITRATE_UL = 1025,
    GUARANTEED_BITRATE_DL = 1026,
    BEARER_IDENTIFIER = 1020,
    ALLOCATION_RETENTION_PRIORITY = 1034,

    // Time stamps
    EVENT_TIMESTAMP = 55,

    // Supported features
    SUPPORTED_FEATURES = 628
};

/**
 * Reporting Reason
 */
enum class ReportingReason : uint32_t {
    THRESHOLD = 0,
    QHT = 1,  // Quota Holding Time
    FINAL = 2,
    QUOTA_EXHAUSTED = 3,
    VALIDITY_TIME = 4,
    OTHER_QUOTA_TYPE = 5,
    RATING_CONDITION_CHANGE = 6,
    FORCED_REAUTHORISATION = 7,
    POOL_EXHAUSTED = 8
};

/**
 * Trigger Type
 */
enum class TriggerType : uint32_t {
    CHANGE_IN_SGSN_IP_ADDRESS = 1,
    CHANGE_IN_QOS = 2,
    CHANGE_IN_LOCATION = 3,
    CHANGE_IN_RAT = 4,
    CHANGEINQOS_TRAFFIC_CLASS = 10,
    CHANGEINQOS_RELIABILITY_CLASS = 11,
    CHANGEINQOS_DELAY_CLASS = 12,
    CHANGEINQOS_PEAK_THROUGHPUT = 13,
    CHANGEINQOS_PRECEDENCE_CLASS = 14,
    CHANGEINQOS_MEAN_THROUGHPUT = 15,
    CHANGEINQOS_MAXIMUM_BIT_RATE_DOWNLINK = 16,
    CHANGEINQOS_MAXIMUM_BIT_RATE_UPLINK = 17,
    CHANGEINQOS_GUARANTEED_BIT_RATE_DOWNLINK = 18,
    CHANGEINQOS_GUARANTEED_BIT_RATE_UPLINK = 19,
    CHANGEINLOCATION_MCC = 20,
    CHANGEINLOCATION_MNC = 21,
    CHANGEINLOCATION_RAC = 22,
    CHANGEINLOCATION_LAC = 23,
    CHANGEINLOCATION_CellId = 24,
    CHANGEINLOCATION_TAC = 25,
    CHANGEINLOCATION_ECGI = 26
};

// ============================================================================
// Gy-specific Structures
// ============================================================================

/**
 * Multiple Services Credit Control (MSCC)
 */
struct MultipleServicesCreditControl {
    std::optional<GrantedServiceUnit> granted_service_unit;
    std::optional<RequestedServiceUnit> requested_service_unit;
    std::optional<UsedServiceUnit> used_service_unit;
    std::optional<uint32_t> rating_group;
    std::optional<uint32_t> service_identifier;
    std::optional<uint32_t> validity_time;
    std::optional<uint32_t> result_code;
    std::optional<FinalUnitIndication> final_unit_indication;
    std::optional<std::chrono::system_clock::time_point> time_of_first_usage;
    std::optional<std::chrono::system_clock::time_point> time_of_last_usage;
    std::vector<TriggerType> triggers;
    std::optional<ReportingReason> reporting_reason;

    nlohmann::json toJson() const;
};

/**
 * Cost Information
 */
struct CostInformation {
    uint32_t unit_value;
    uint32_t currency_code;
    std::optional<std::string> cost_unit;

    nlohmann::json toJson() const;
};

/**
 * PS (Packet Switched) Information
 */
struct PSInformation {
    std::optional<uint32_t> tgpp_charging_id;
    std::optional<uint32_t> tgpp_pdp_type;
    std::optional<std::string> tgpp_sgsn_address;
    std::optional<std::string> tgpp_ggsn_address;
    std::optional<std::string> called_station_id;  // APN
    std::optional<uint32_t> tgpp_nsapi;
    std::optional<std::string> tgpp_selection_mode;
    std::optional<std::string> tgpp_charging_characteristics;
    std::optional<uint32_t> tgpp_rat_type;
    std::optional<std::vector<uint8_t>> tgpp_user_location_info;

    nlohmann::json toJson() const;
};

/**
 * IMS Information
 */
struct IMSInformation {
    std::optional<std::string> calling_party_address;
    std::optional<std::string> called_party_address;
    std::optional<std::string> event_type;
    std::optional<uint32_t> role_of_node;
    std::optional<std::string> node_functionality;

    nlohmann::json toJson() const;
};

/**
 * Service Information
 */
struct ServiceInformation {
    std::optional<PSInformation> ps_information;
    std::optional<IMSInformation> ims_information;

    nlohmann::json toJson() const;
};

// ============================================================================
// Gy Messages
// ============================================================================

/**
 * Credit Control Request (CCR) - Gy specific fields
 */
struct GyCreditControlRequest {
    CCRequestType cc_request_type;
    uint32_t cc_request_number;

    // Service context
    std::optional<std::string> service_context_id;

    // Subscription ID
    std::vector<SubscriptionId> subscription_ids;

    // Multiple services credit control
    std::vector<MultipleServicesCreditControl> mscc;

    // User equipment info
    std::optional<UserEquipmentInfo> user_equipment_info;

    // Service information
    std::optional<ServiceInformation> service_information;

    // Event timestamp
    std::optional<std::chrono::system_clock::time_point> event_timestamp;

    nlohmann::json toJson() const;
};

/**
 * Credit Control Answer (CCA) - Gy specific fields
 */
struct GyCreditControlAnswer {
    uint32_t result_code;
    CCRequestType cc_request_type;
    uint32_t cc_request_number;

    // Multiple services credit control
    std::vector<MultipleServicesCreditControl> mscc;

    // Cost information
    std::optional<CostInformation> cost_information;

    // Credit control failure handling
    std::optional<uint32_t> cc_session_failover;

    nlohmann::json toJson() const;
};

/**
 * Gy Message (extends Diameter base message)
 */
struct DiameterGyMessage {
    DiameterMessage base;

    // Parsed message-specific data
    std::optional<GyCreditControlRequest> ccr;
    std::optional<GyCreditControlAnswer> cca;

    // Common extracted fields
    std::optional<CCRequestType> cc_request_type;
    std::optional<std::string> called_station_id;  // APN

    nlohmann::json toJson() const;
};

/**
 * Diameter Gy Parser
 *
 * Parses Gy-specific Diameter messages for online charging (P-GW/GGSN to OCS).
 */
class DiameterGyParser {
public:
    DiameterGyParser() = default;
    ~DiameterGyParser() = default;

    /**
     * Parse Gy message from Diameter base message
     * @param msg Diameter base message
     * @return Parsed Gy message or nullopt if not Gy
     */
    std::optional<DiameterGyMessage> parse(const DiameterMessage& msg);

    /**
     * Check if message is Gy
     */
    static bool isGyMessage(const DiameterMessage& msg);

private:
    // Message-specific parsers
    GyCreditControlRequest parseCCR(const DiameterMessage& msg);
    GyCreditControlAnswer parseCCA(const DiameterMessage& msg);

    // AVP parsers
    std::optional<MultipleServicesCreditControl> parseMSCC(std::shared_ptr<DiameterAVP> avp);
    std::optional<SubscriptionId> parseSubscriptionId(std::shared_ptr<DiameterAVP> avp);
    std::optional<ServiceUnit> parseServiceUnit(std::shared_ptr<DiameterAVP> avp);
    std::optional<UsedServiceUnit> parseUsedServiceUnit(std::shared_ptr<DiameterAVP> avp);
    std::optional<FinalUnitIndication> parseFinalUnitIndication(std::shared_ptr<DiameterAVP> avp);
    std::optional<RedirectServer> parseRedirectServer(std::shared_ptr<DiameterAVP> avp);
    std::optional<UserEquipmentInfo> parseUserEquipmentInfo(std::shared_ptr<DiameterAVP> avp);
    std::optional<ServiceInformation> parseServiceInformation(std::shared_ptr<DiameterAVP> avp);
    std::optional<PSInformation> parsePSInformation(std::shared_ptr<DiameterAVP> avp);
    std::optional<IMSInformation> parseIMSInformation(std::shared_ptr<DiameterAVP> avp);
    std::optional<CostInformation> parseCostInformation(std::shared_ptr<DiameterAVP> avp);
};

}  // namespace diameter
}  // namespace callflow
