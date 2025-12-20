#include "protocol_parsers/diameter/diameter_policy_types.h"

namespace callflow {
namespace diameter {

// ============================================================================
// Structure toJson() Methods
// ============================================================================

nlohmann::json AllocationRetentionPriority::toJson() const {
    nlohmann::json j;
    j["priority_level"] = priority_level;
    j["pre_emption_capability"] = static_cast<uint32_t>(pre_emption_capability);
    j["pre_emption_vulnerability"] = static_cast<uint32_t>(pre_emption_vulnerability);
    return j;
}

nlohmann::json QoSInformation::toJson() const {
    nlohmann::json j;
    if (qos_class_identifier.has_value()) {
        j["qos_class_identifier"] = qos_class_identifier.value();
    }
    if (max_requested_bandwidth_ul.has_value()) {
        j["max_requested_bandwidth_ul"] = max_requested_bandwidth_ul.value();
    }
    if (max_requested_bandwidth_dl.has_value()) {
        j["max_requested_bandwidth_dl"] = max_requested_bandwidth_dl.value();
    }
    if (guaranteed_bitrate_ul.has_value()) {
        j["guaranteed_bitrate_ul"] = guaranteed_bitrate_ul.value();
    }
    if (guaranteed_bitrate_dl.has_value()) {
        j["guaranteed_bitrate_dl"] = guaranteed_bitrate_dl.value();
    }
    if (bearer_identifier.has_value()) {
        j["bearer_identifier"] = bearer_identifier.value();
    }
    if (allocation_retention_priority.has_value()) {
        j["allocation_retention_priority"] = allocation_retention_priority->toJson();
    }
    if (apn_aggregate_max_bitrate_ul.has_value()) {
        j["apn_aggregate_max_bitrate_ul"] = apn_aggregate_max_bitrate_ul.value();
    }
    if (apn_aggregate_max_bitrate_dl.has_value()) {
        j["apn_aggregate_max_bitrate_dl"] = apn_aggregate_max_bitrate_dl.value();
    }
    return j;
}

nlohmann::json DefaultEPSBearerQoS::toJson() const {
    nlohmann::json j;
    j["qos_class_identifier"] = qos_class_identifier;
    j["allocation_retention_priority"] = allocation_retention_priority.toJson();
    return j;
}

nlohmann::json FlowInformation::toJson() const {
    nlohmann::json j;
    j["flow_direction"] = static_cast<uint32_t>(flow_direction);
    j["flow_description"] = flow_description;
    if (tos_traffic_class.has_value()) {
        j["tos_traffic_class"] = tos_traffic_class.value();
    }
    return j;
}

nlohmann::json ServiceUnit::toJson() const {
    nlohmann::json j;
    if (cc_time.has_value()) {
        j["cc_time"] = cc_time.value();
    }
    if (cc_total_octets.has_value()) {
        j["cc_total_octets"] = cc_total_octets.value();
    }
    if (cc_input_octets.has_value()) {
        j["cc_input_octets"] = cc_input_octets.value();
    }
    if (cc_output_octets.has_value()) {
        j["cc_output_octets"] = cc_output_octets.value();
    }
    if (cc_service_specific_units.has_value()) {
        j["cc_service_specific_units"] = cc_service_specific_units.value();
    }
    return j;
}

nlohmann::json UsedServiceUnit::toJson() const {
    nlohmann::json j;
    if (cc_time.has_value()) {
        j["cc_time"] = cc_time.value();
    }
    if (cc_total_octets.has_value()) {
        j["cc_total_octets"] = cc_total_octets.value();
    }
    if (cc_input_octets.has_value()) {
        j["cc_input_octets"] = cc_input_octets.value();
    }
    if (cc_output_octets.has_value()) {
        j["cc_output_octets"] = cc_output_octets.value();
    }
    if (cc_service_specific_units.has_value()) {
        j["cc_service_specific_units"] = cc_service_specific_units.value();
    }
    if (tariff_change_usage.has_value()) {
        j["tariff_change_usage"] = static_cast<uint32_t>(tariff_change_usage.value());
    }
    if (reporting_reason.has_value()) {
        j["reporting_reason"] = reporting_reason.value();
    }
    return j;
}

nlohmann::json RedirectServer::toJson() const {
    nlohmann::json j;
    j["redirect_address_type"] = static_cast<uint32_t>(redirect_address_type);
    j["redirect_server_address"] = redirect_server_address;
    return j;
}

nlohmann::json FinalUnitIndication::toJson() const {
    nlohmann::json j;
    j["final_unit_action"] = static_cast<uint32_t>(final_unit_action);
    if (!restriction_filter_rule.empty()) {
        j["restriction_filter_rule"] = restriction_filter_rule;
    }
    if (!filter_id.empty()) {
        j["filter_id"] = filter_id;
    }
    if (redirect_server.has_value()) {
        j["redirect_server"] = redirect_server->toJson();
    }
    return j;
}

nlohmann::json SubscriptionId::toJson() const {
    nlohmann::json j;
    j["subscription_id_type"] = static_cast<uint32_t>(subscription_id_type);
    j["subscription_id_data"] = subscription_id_data;
    return j;
}

nlohmann::json UserEquipmentInfo::toJson() const {
    nlohmann::json j;
    j["user_equipment_info_type"] = static_cast<uint32_t>(user_equipment_info_type);
    j["user_equipment_info_value"] = user_equipment_info_value;
    return j;
}

// ============================================================================
// Helper Functions
// ============================================================================

std::string getFlowDirectionName(FlowDirection direction) {
    switch (direction) {
        case FlowDirection::UNSPECIFIED:    return "Unspecified";
        case FlowDirection::DOWNLINK:       return "Downlink";
        case FlowDirection::UPLINK:         return "Uplink";
        case FlowDirection::BIDIRECTIONAL:  return "Bidirectional";
        default:                            return "Unknown";
    }
}

std::string getFlowStatusName(FlowStatus status) {
    switch (status) {
        case FlowStatus::ENABLED_UPLINK:    return "Enabled-Uplink";
        case FlowStatus::ENABLED_DOWNLINK:  return "Enabled-Downlink";
        case FlowStatus::ENABLED:           return "Enabled";
        case FlowStatus::DISABLED:          return "Disabled";
        case FlowStatus::REMOVED:           return "Removed";
        default:                            return "Unknown";
    }
}

std::string getFlowUsageName(FlowUsage usage) {
    switch (usage) {
        case FlowUsage::NO_INFORMATION:     return "No-Information";
        case FlowUsage::RTCP:               return "RTCP";
        case FlowUsage::AF_SIGNALLING:      return "AF-Signalling";
        default:                            return "Unknown";
    }
}

std::string getMediaTypeName(MediaType type) {
    switch (type) {
        case MediaType::AUDIO:              return "Audio";
        case MediaType::VIDEO:              return "Video";
        case MediaType::DATA:               return "Data";
        case MediaType::APPLICATION:        return "Application";
        case MediaType::CONTROL:            return "Control";
        case MediaType::TEXT:               return "Text";
        case MediaType::MESSAGE:            return "Message";
        case MediaType::OTHER:              return "Other";
        default:                            return "Unknown";
    }
}

std::string getCCRequestTypeName(CCRequestType type) {
    switch (type) {
        case CCRequestType::INITIAL_REQUEST:      return "Initial-Request";
        case CCRequestType::UPDATE_REQUEST:       return "Update-Request";
        case CCRequestType::TERMINATION_REQUEST:  return "Termination-Request";
        case CCRequestType::EVENT_REQUEST:        return "Event-Request";
        default:                                  return "Unknown";
    }
}

std::string getIPCANTypeName(IPCANType type) {
    switch (type) {
        case IPCANType::TGPP_GPRS:      return "3GPP-GPRS";
        case IPCANType::DOCSIS:         return "DOCSIS";
        case IPCANType::XDSL:           return "xDSL";
        case IPCANType::WIMAX:          return "WiMAX";
        case IPCANType::TGPP2:          return "3GPP2";
        case IPCANType::TGPP_EPS:       return "3GPP-EPS";
        case IPCANType::NON_3GPP_EPS:   return "Non-3GPP-EPS";
        case IPCANType::FBA:            return "FBA";
        case IPCANType::TGPP_5GS:       return "3GPP-5GS";
        case IPCANType::NON_3GPP_5GS:   return "Non-3GPP-5GS";
        default:                        return "Unknown";
    }
}

std::string getFinalUnitActionName(FinalUnitAction action) {
    switch (action) {
        case FinalUnitAction::TERMINATE:        return "Terminate";
        case FinalUnitAction::REDIRECT:         return "Redirect";
        case FinalUnitAction::RESTRICT_ACCESS:  return "Restrict-Access";
        default:                                return "Unknown";
    }
}

}  // namespace diameter
}  // namespace callflow
