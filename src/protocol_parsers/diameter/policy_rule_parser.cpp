#include "protocol_parsers/diameter/diameter_gx.h"
#include "protocol_parsers/diameter/diameter_rx.h"
#include "protocol_parsers/diameter/diameter_gy.h"
#include "common/logger.h"

namespace callflow {
namespace diameter {

/**
 * Policy Rule Parser
 *
 * This file contains common parsing logic shared across Gx, Rx, and Gy parsers.
 * The actual parsing is done in the individual parser implementations.
 */

// ============================================================================
// Common Helper Functions
// ============================================================================

/**
 * Validate IP filter rule format (used in flow descriptions)
 */
bool validateIPFilterRule(const std::string& rule) {
    if (rule.empty()) {
        return false;
    }

    // Basic validation - should start with "permit" or "deny"
    if (rule.find("permit") != 0 && rule.find("deny") != 0) {
        return false;
    }

    return true;
}

/**
 * Parse flow direction from string
 */
std::optional<FlowDirection> parseFlowDirectionFromString(const std::string& direction) {
    if (direction == "in") {
        return FlowDirection::UPLINK;
    } else if (direction == "out") {
        return FlowDirection::DOWNLINK;
    } else if (direction == "both") {
        return FlowDirection::BIDIRECTIONAL;
    }
    return std::nullopt;
}

/**
 * Validate QCI value (1-9 are standardized, 128-254 are operator-specific)
 */
bool validateQCI(uint32_t qci) {
    return (qci >= 1 && qci <= 9) || (qci >= 128 && qci <= 254);
}

/**
 * Validate priority level (1-15, where 1 is highest)
 */
bool validatePriorityLevel(uint32_t priority) {
    return priority >= 1 && priority <= 15;
}

/**
 * Validate service identifier
 */
bool validateServiceIdentifier(uint32_t service_id) {
    // Service identifiers can be any 32-bit value
    // No specific validation needed
    return true;
}

/**
 * Validate rating group
 */
bool validateRatingGroup(uint32_t rating_group) {
    // Rating groups can be any 32-bit value
    // No specific validation needed
    return true;
}

/**
 * Convert octets to human-readable bandwidth string
 */
std::string formatBandwidth(uint64_t octets_per_second) {
    if (octets_per_second == 0) {
        return "0 bps";
    }

    uint64_t bits_per_second = octets_per_second * 8;

    if (bits_per_second < 1000) {
        return std::to_string(bits_per_second) + " bps";
    } else if (bits_per_second < 1000000) {
        return std::to_string(bits_per_second / 1000) + " Kbps";
    } else if (bits_per_second < 1000000000) {
        return std::to_string(bits_per_second / 1000000) + " Mbps";
    } else {
        return std::to_string(bits_per_second / 1000000000) + " Gbps";
    }
}

/**
 * Format service unit for logging
 */
std::string formatServiceUnit(const ServiceUnit& su) {
    std::string result;

    if (su.cc_time.has_value()) {
        result += "Time: " + std::to_string(su.cc_time.value()) + "s ";
    }
    if (su.cc_total_octets.has_value()) {
        result += "Octets: " + std::to_string(su.cc_total_octets.value()) + " ";
    }
    if (su.cc_input_octets.has_value()) {
        result += "Input: " + std::to_string(su.cc_input_octets.value()) + " ";
    }
    if (su.cc_output_octets.has_value()) {
        result += "Output: " + std::to_string(su.cc_output_octets.value()) + " ";
    }
    if (su.cc_service_specific_units.has_value()) {
        result += "SSU: " + std::to_string(su.cc_service_specific_units.value()) + " ";
    }

    return result.empty() ? "None" : result;
}

/**
 * Calculate total data usage from used service units
 */
uint64_t calculateTotalDataUsage(const std::vector<UsedServiceUnit>& used_units) {
    uint64_t total = 0;

    for (const auto& unit : used_units) {
        if (unit.cc_total_octets.has_value()) {
            total += unit.cc_total_octets.value();
        } else {
            if (unit.cc_input_octets.has_value()) {
                total += unit.cc_input_octets.value();
            }
            if (unit.cc_output_octets.has_value()) {
                total += unit.cc_output_octets.value();
            }
        }
    }

    return total;
}

/**
 * Check if QoS information is valid
 */
bool isValidQoSInformation(const QoSInformation& qos) {
    // Must have at least QCI
    if (!qos.qos_class_identifier.has_value()) {
        return false;
    }

    // Validate QCI
    if (!validateQCI(qos.qos_class_identifier.value())) {
        return false;
    }

    // If ARP is present, validate priority level
    if (qos.allocation_retention_priority.has_value()) {
        if (!validatePriorityLevel(qos.allocation_retention_priority->priority_level)) {
            return false;
        }
    }

    return true;
}

/**
 * Check if charging rule definition is valid
 */
bool isValidChargingRuleDefinition(const ChargingRuleDefinition& rule) {
    // Must have a rule name
    if (rule.charging_rule_name.empty()) {
        Logger::warning("Charging rule has no name");
        return false;
    }

    // Should have either service identifier or rating group
    if (!rule.service_identifier.has_value() && !rule.rating_group.has_value()) {
        Logger::warning("Charging rule " + rule.charging_rule_name +
                       " has no service identifier or rating group");
        return false;
    }

    // If QoS is present, validate it
    if (rule.qos_information.has_value()) {
        if (!isValidQoSInformation(rule.qos_information.value())) {
            Logger::warning("Charging rule " + rule.charging_rule_name +
                           " has invalid QoS information");
            return false;
        }
    }

    // If flow information is present, validate it
    for (const auto& flow : rule.flow_information) {
        if (!validateIPFilterRule(flow.flow_description)) {
            Logger::warning("Charging rule " + rule.charging_rule_name +
                           " has invalid flow description");
            return false;
        }
    }

    return true;
}

/**
 * Check if media component description is valid
 */
bool isValidMediaComponentDescription(const MediaComponentDescription& media) {
    // Must have a media component number
    if (media.media_component_number == 0) {
        Logger::warning("Media component has no number");
        return false;
    }

    // Should have at least one media sub-component
    if (media.media_sub_components.empty()) {
        Logger::warning("Media component " +
                       std::to_string(media.media_component_number) +
                       " has no sub-components");
        return false;
    }

    // Validate sub-components
    for (const auto& sub : media.media_sub_components) {
        if (sub.flow_descriptions.empty()) {
            Logger::warning("Media sub-component " +
                           std::to_string(sub.flow_number) +
                           " has no flow descriptions");
            return false;
        }
    }

    return true;
}

/**
 * Log policy rule installation
 */
void logChargingRuleInstall(const ChargingRuleInstall& install) {
    Logger::info("Installing charging rules:");

    if (!install.charging_rule_definition.empty()) {
        Logger::info("  Dynamic rules: " +
                    std::to_string(install.charging_rule_definition.size()));
        for (const auto& rule : install.charging_rule_definition) {
            Logger::info("    - " + rule.charging_rule_name);
        }
    }

    if (!install.charging_rule_name.empty()) {
        Logger::info("  Predefined rules: " +
                    std::to_string(install.charging_rule_name.size()));
        for (const auto& name : install.charging_rule_name) {
            Logger::info("    - " + name);
        }
    }

    if (!install.charging_rule_base_name.empty()) {
        Logger::info("  Base rule names: " +
                    std::to_string(install.charging_rule_base_name.size()));
        for (const auto& name : install.charging_rule_base_name) {
            Logger::info("    - " + name);
        }
    }

    if (install.bearer_identifier.has_value()) {
        Logger::info("  Bearer ID: " +
                    std::to_string(install.bearer_identifier.value()));
    }
}

/**
 * Log credit control usage
 */
void logCreditControlUsage(const MultipleServicesCreditControl& mscc) {
    std::string log_msg = "Credit control - ";

    if (mscc.rating_group.has_value()) {
        log_msg += "RG: " + std::to_string(mscc.rating_group.value()) + " ";
    }

    if (mscc.service_identifier.has_value()) {
        log_msg += "SI: " + std::to_string(mscc.service_identifier.value()) + " ";
    }

    if (mscc.used_service_unit.has_value()) {
        log_msg += "Used: " + formatServiceUnit(*reinterpret_cast<const ServiceUnit*>(&mscc.used_service_unit.value())) + " ";
    }

    if (mscc.granted_service_unit.has_value()) {
        log_msg += "Granted: " + formatServiceUnit(mscc.granted_service_unit.value()) + " ";
    }

    Logger::info(log_msg);
}

}  // namespace diameter
}  // namespace callflow
