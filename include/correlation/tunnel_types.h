#ifndef TUNNEL_TYPES_H
#define TUNNEL_TYPES_H

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace callflow {

/**
 * GTP tunnel lifecycle states
 */
enum class TunnelState {
    INACTIVE,      // Tunnel exists but no recent activity
    CREATING,      // Create Session Request sent, awaiting Response
    ACTIVE,        // Create Session Response received, tunnel operational
    MODIFYING,     // Modify Bearer in progress (handover, QoS change)
    DELETING,      // Delete Session Request sent
    DELETED        // Delete Session Response received or timeout
};

/**
 * Convert TunnelState to string for logging and JSON
 */
inline std::string tunnelStateToString(TunnelState state) {
    switch (state) {
        case TunnelState::INACTIVE: return "INACTIVE";
        case TunnelState::CREATING: return "CREATING";
        case TunnelState::ACTIVE: return "ACTIVE";
        case TunnelState::MODIFYING: return "MODIFYING";
        case TunnelState::DELETING: return "DELETING";
        case TunnelState::DELETED: return "DELETED";
        default: return "UNKNOWN";
    }
}

/**
 * Represents a GTP handover event (TEID change due to mobility)
 */
struct HandoverEvent {
    std::chrono::system_clock::time_point timestamp;
    uint32_t old_teid_uplink;
    uint32_t new_teid_uplink;
    std::string old_enb_ip;
    std::string new_enb_ip;
    std::string handover_type;  // "X2", "S1", "N2"
    std::chrono::milliseconds interruption_time;

    nlohmann::json toJson() const {
        return nlohmann::json{
            {"timestamp", std::chrono::duration_cast<std::chrono::milliseconds>(
                timestamp.time_since_epoch()).count()},
            {"old_teid", old_teid_uplink},
            {"new_teid", new_teid_uplink},
            {"old_enb_ip", old_enb_ip},
            {"new_enb_ip", new_enb_ip},
            {"handover_type", handover_type},
            {"interruption_ms", interruption_time.count()}
        };
    }
};

/**
 * Complete GTP tunnel (bearer) with lifecycle tracking, metrics, and handover history
 */
struct GtpTunnel {
    // Tunnel identifiers
    uint32_t teid_uplink;      // S1-U/N3 uplink (UE → Network)
    uint32_t teid_downlink;    // S1-U/N3 downlink (Network → UE)
    std::string imsi;
    std::string ue_ip_v4;
    std::string ue_ip_v6;
    std::string apn;  // Access Point Name
    uint8_t eps_bearer_id = 0;
    uint8_t qci = 0;  // QoS Class Identifier

    // Lifecycle state
    TunnelState state = TunnelState::INACTIVE;

    // Lifecycle timestamps
    std::chrono::system_clock::time_point created;
    std::optional<std::chrono::system_clock::time_point> deleted;
    std::chrono::system_clock::time_point last_activity;

    // Keep-alive tracking
    uint32_t echo_request_count = 0;
    uint32_t echo_response_count = 0;
    std::chrono::system_clock::time_point last_echo_request;
    std::chrono::system_clock::time_point last_echo_response;
    std::chrono::seconds echo_interval{0};

    // Data metrics
    uint64_t uplink_packets = 0;
    uint64_t downlink_packets = 0;
    uint64_t uplink_bytes = 0;
    uint64_t downlink_bytes = 0;

    // Handover tracking
    std::vector<HandoverEvent> handovers;

    // Visualization control
    enum class VisualizationMode {
        FULL,        // Show all messages including echo
        AGGREGATED,  // Show setup/teardown + "N keep-alives over M hours"
        MINIMAL      // Show only setup/teardown
    };
    VisualizationMode viz_mode = VisualizationMode::AGGREGATED;

    /**
     * Calculate tunnel duration in hours
     */
    double getDurationHours() const {
        auto end = deleted.has_value() ? *deleted : std::chrono::system_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(end - created);
        return duration.count() / 3600.0;
    }

    /**
     * Check if tunnel is currently active
     */
    bool isActive() const {
        return state == TunnelState::ACTIVE || state == TunnelState::MODIFYING;
    }

    /**
     * Get tunnel ID as hex string
     */
    std::string getTunnelId() const {
        char buf[32];
        snprintf(buf, sizeof(buf), "teid_0x%08x", teid_uplink);
        return std::string(buf);
    }

    /**
     * Export to JSON for visualization
     */
    nlohmann::json toJson() const {
        nlohmann::json j = {
            {"tunnel_id", getTunnelId()},
            {"teid_uplink", teid_uplink},
            {"teid_downlink", teid_downlink},
            {"imsi", imsi},
            {"apn", apn},
            {"state", tunnelStateToString(state)},
            {"created", std::chrono::duration_cast<std::chrono::milliseconds>(
                created.time_since_epoch()).count()},
            {"duration_hours", getDurationHours()},
            {"viz_mode", static_cast<int>(viz_mode)},
            {"metrics", {
                {"uplink_bytes", uplink_bytes},
                {"downlink_bytes", downlink_bytes},
                {"uplink_packets", uplink_packets},
                {"downlink_packets", downlink_packets},
                {"echo_request_count", echo_request_count},
                {"echo_response_count", echo_response_count},
                {"handover_count", handovers.size()}
            }}
        };

        // Add optional fields
        if (!ue_ip_v4.empty()) {
            j["ue_ip"] = ue_ip_v4;
        } else if (!ue_ip_v6.empty()) {
            j["ue_ip"] = ue_ip_v6;
        }

        if (deleted.has_value()) {
            j["deleted"] = std::chrono::duration_cast<std::chrono::milliseconds>(
                deleted->time_since_epoch()).count();
        }

        if (eps_bearer_id > 0) {
            j["eps_bearer_id"] = eps_bearer_id;
        }

        if (qci > 0) {
            j["qci"] = qci;
        }

        if (echo_interval.count() > 0) {
            j["echo_interval_sec"] = echo_interval.count();
        }

        // Add handover events
        if (!handovers.empty()) {
            nlohmann::json handover_array = nlohmann::json::array();
            for (const auto& ho : handovers) {
                handover_array.push_back(ho.toJson());
            }
            j["handovers"] = handover_array;
        }

        return j;
    }
};

/**
 * Aggregated keep-alive summary for visualization
 */
struct AggregatedKeepalive {
    std::chrono::system_clock::time_point start_time;
    std::chrono::system_clock::time_point end_time;
    uint32_t echo_count = 0;
    std::chrono::seconds avg_interval{0};
    bool all_successful = true;  // All echoes got responses

    /**
     * Get duration in hours
     */
    double getDurationHours() const {
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time);
        return duration.count() / 3600.0;
    }

    /**
     * Export to JSON for visualization
     */
    nlohmann::json toJson() const {
        return nlohmann::json{
            {"type", "KEEPALIVE_AGGREGATED"},
            {"timestamp_start", std::chrono::duration_cast<std::chrono::milliseconds>(
                start_time.time_since_epoch()).count()},
            {"timestamp_end", std::chrono::duration_cast<std::chrono::milliseconds>(
                end_time.time_since_epoch()).count()},
            {"echo_count", echo_count},
            {"interval_sec", avg_interval.count()},
            {"all_successful", all_successful},
            {"message", "Session active (" + std::to_string(echo_count) +
                       " keep-alives over " +
                       std::to_string(getDurationHours()) + " hours)"}
        };
    }
};

/**
 * Tunnel event for visualization timeline
 */
struct TunnelEvent {
    enum class Type {
        CREATE,
        KEEPALIVE,
        KEEPALIVE_AGGREGATED,
        HANDOVER,
        MODIFY_BEARER,
        DELETE,
        TIMEOUT
    };

    Type type;
    std::chrono::system_clock::time_point timestamp;
    std::string message;
    nlohmann::json details;

    nlohmann::json toJson() const {
        std::string type_str;
        switch (type) {
            case Type::CREATE: type_str = "CREATE"; break;
            case Type::KEEPALIVE: type_str = "KEEPALIVE"; break;
            case Type::KEEPALIVE_AGGREGATED: type_str = "KEEPALIVE_AGGREGATED"; break;
            case Type::HANDOVER: type_str = "HANDOVER"; break;
            case Type::MODIFY_BEARER: type_str = "MODIFY_BEARER"; break;
            case Type::DELETE: type_str = "DELETE"; break;
            case Type::TIMEOUT: type_str = "TIMEOUT"; break;
            default: type_str = "UNKNOWN"; break;
        }

        nlohmann::json j = {
            {"type", type_str},
            {"timestamp", std::chrono::duration_cast<std::chrono::milliseconds>(
                timestamp.time_since_epoch()).count()},
            {"message", message}
        };

        if (!details.empty()) {
            j["details"] = details;
        }

        return j;
    }
};

} // namespace callflow

#endif // TUNNEL_TYPES_H
