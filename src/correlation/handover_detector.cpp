#include "correlation/tunnel_types.h"
#include "session/session_types.h"
#include "common/logger.h"
#include "common/types.h"
#include <string>

namespace callflow {

/**
 * Utility functions for advanced handover detection and classification
 */

/**
 * Determine handover type from message context
 */
std::string detectHandoverType(const SessionMessageRef& msg,
                                const SessionMessageRef* /*prev_msg*/ = nullptr) {
    // Check protocol type
    if (msg.protocol == ProtocolType::X2AP) {
        return "X2";
    }

    if (msg.protocol == ProtocolType::S1AP) {
        // Could be S1 handover if we see specific S1AP messages
        if (msg.message_type == MessageType::S1AP_HANDOVER_REQUEST ||
            msg.message_type == MessageType::S1AP_PATH_SWITCH_REQUEST) {
            return "S1";
        }
    }

    if (msg.protocol == ProtocolType::NGAP) {
        // 5G handover
        if (msg.message_type == MessageType::NGAP_HANDOVER_REQUEST ||
            msg.message_type == MessageType::NGAP_PATH_SWITCH_REQUEST) {
            return "N2";
        }
    }

    // Check parsed data for handover indicators
    if (msg.parsed_data.contains("handover_type")) {
        std::string ho_type = msg.parsed_data["handover_type"].get<std::string>();
        if (!ho_type.empty()) {
            return ho_type;
        }
    }

    // Default to X2 for GTP modify bearer with TEID change
    if (msg.message_type == MessageType::GTP_MODIFY_BEARER_RESP) {
        return "X2";
    }

    return "UNKNOWN";
}

/**
 * Extract source eNB/gNB IP from handover message
 */
std::string extractSourceEnbIp(const SessionMessageRef& msg) {
    if (msg.parsed_data.contains("source_enb_ip")) {
        return msg.parsed_data["source_enb_ip"].get<std::string>();
    }

    if (msg.parsed_data.contains("source_gnb_ip")) {
        return msg.parsed_data["source_gnb_ip"].get<std::string>();
    }

    // Try to extract from bearer contexts
    if (msg.parsed_data.contains("bearer_contexts") &&
        msg.parsed_data["bearer_contexts"].is_array() &&
        !msg.parsed_data["bearer_contexts"].empty()) {

        auto& bearer = msg.parsed_data["bearer_contexts"][0];

        if (bearer.contains("s1u_enb_fteid") &&
            bearer["s1u_enb_fteid"].contains("ipv4")) {
            return bearer["s1u_enb_fteid"]["ipv4"].get<std::string>();
        }
    }

    // Fallback to message source IP
    return msg.src_ip;
}

/**
 * Extract target eNB/gNB IP from handover message
 */
std::string extractTargetEnbIp(const SessionMessageRef& msg) {
    if (msg.parsed_data.contains("target_enb_ip")) {
        return msg.parsed_data["target_enb_ip"].get<std::string>();
    }

    if (msg.parsed_data.contains("target_gnb_ip")) {
        return msg.parsed_data["target_gnb_ip"].get<std::string>();
    }

    // Try to extract from bearer contexts in response
    if (msg.parsed_data.contains("bearer_contexts") &&
        msg.parsed_data["bearer_contexts"].is_array() &&
        !msg.parsed_data["bearer_contexts"].empty()) {

        auto& bearer = msg.parsed_data["bearer_contexts"][0];

        if (bearer.contains("s1u_enb_fteid") &&
            bearer["s1u_enb_fteid"].contains("ipv4")) {
            return bearer["s1u_enb_fteid"]["ipv4"].get<std::string>();
        }
    }

    // Fallback to message destination IP
    return msg.dst_ip;
}

/**
 * Check if handover was successful
 */
bool isHandoverSuccessful(const SessionMessageRef& msg) {
    // Check for success indicators in parsed data
    if (msg.parsed_data.contains("cause")) {
        auto& cause = msg.parsed_data["cause"];

        if (cause.is_object() && cause.contains("value")) {
            int cause_value = cause["value"].get<int>();
            // Cause value 16 = "Request accepted" in GTP
            return cause_value == 16;
        }

        if (cause.is_number()) {
            return cause.get<int>() == 16;
        }
    }

    // For GTP Modify Bearer Response, absence of error is success
    if (msg.message_type == MessageType::GTP_MODIFY_BEARER_RESP) {
        if (!msg.parsed_data.contains("error") &&
            !msg.parsed_data.contains("failure")) {
            return true;
        }
    }

    // For X2AP/S1AP handover complete
    if (msg.message_type == MessageType::S1AP_HANDOVER_NOTIFY ||
        msg.message_type == MessageType::NGAP_HANDOVER_NOTIFY) {
        return true;
    }

    return false;
}

/**
 * Estimate handover preparation time from message sequence
 */
std::chrono::milliseconds estimatePreparationTime(
    const std::vector<SessionMessageRef>& messages) {

    if (messages.size() < 2) {
        return std::chrono::milliseconds{0};
    }

    // Find handover request and response
    std::optional<std::chrono::system_clock::time_point> request_time;
    std::optional<std::chrono::system_clock::time_point> response_time;

    for (const auto& msg : messages) {
        if (msg.message_type == MessageType::S1AP_HANDOVER_REQUEST ||
            msg.message_type == MessageType::NGAP_HANDOVER_REQUEST) {
            if (!request_time.has_value()) {
                request_time = msg.timestamp;
            }
        }

        if (msg.message_type == MessageType::S1AP_HANDOVER_REQUEST_ACK ||
            msg.message_type == MessageType::NGAP_HANDOVER_REQUEST_ACK) {
            if (!response_time.has_value()) {
                response_time = msg.timestamp;
            }
        }
    }

    if (request_time.has_value() && response_time.has_value()) {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            *response_time - *request_time);
    }

    return std::chrono::milliseconds{0};
}

/**
 * Classify handover quality based on interruption time
 */
std::string classifyHandoverQuality(std::chrono::milliseconds interruption_time) {
    auto ms = interruption_time.count();

    if (ms < 0) {
        return "INVALID";  // Negative interruption indicates timing issue
    } else if (ms == 0) {
        return "SEAMLESS";  // No interruption
    } else if (ms < 50) {
        return "EXCELLENT";  // < 50ms
    } else if (ms < 100) {
        return "GOOD";  // 50-100ms
    } else if (ms < 300) {
        return "ACCEPTABLE";  // 100-300ms
    } else if (ms < 1000) {
        return "POOR";  // 300ms-1s
    } else {
        return "FAILED";  // > 1s indicates likely failure
    }
}

/**
 * Calculate handover success rate for a set of handover events
 */
struct HandoverStatistics {
    uint32_t total_handovers = 0;
    uint32_t successful_handovers = 0;
    uint32_t failed_handovers = 0;
    std::chrono::milliseconds avg_interruption_time{0};
    std::chrono::milliseconds min_interruption_time{999999};
    std::chrono::milliseconds max_interruption_time{0};

    double getSuccessRate() const {
        if (total_handovers == 0) {
            return 0.0;
        }
        return (static_cast<double>(successful_handovers) / total_handovers) * 100.0;
    }

    nlohmann::json toJson() const {
        return nlohmann::json{
            {"total_handovers", total_handovers},
            {"successful_handovers", successful_handovers},
            {"failed_handovers", failed_handovers},
            {"success_rate_percent", getSuccessRate()},
            {"avg_interruption_ms", avg_interruption_time.count()},
            {"min_interruption_ms", min_interruption_time.count()},
            {"max_interruption_ms", max_interruption_time.count()}
        };
    }
};

HandoverStatistics calculateHandoverStatistics(const std::vector<HandoverEvent>& handovers) {
    HandoverStatistics stats;
    stats.total_handovers = handovers.size();

    if (handovers.empty()) {
        return stats;
    }

    int64_t total_interruption = 0;

    for (const auto& ho : handovers) {
        auto quality = classifyHandoverQuality(ho.interruption_time);

        if (quality != "FAILED" && quality != "INVALID") {
            stats.successful_handovers++;
        } else {
            stats.failed_handovers++;
        }

        total_interruption += ho.interruption_time.count();

        if (ho.interruption_time < stats.min_interruption_time) {
            stats.min_interruption_time = ho.interruption_time;
        }

        if (ho.interruption_time > stats.max_interruption_time) {
            stats.max_interruption_time = ho.interruption_time;
        }
    }

    stats.avg_interruption_time = std::chrono::milliseconds{
        total_interruption / static_cast<int64_t>(handovers.size())};

    return stats;
}

} // namespace callflow
