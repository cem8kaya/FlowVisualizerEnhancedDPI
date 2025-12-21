#ifndef TUNNEL_MANAGER_H
#define TUNNEL_MANAGER_H

#include "tunnel_types.h"
#include "keepalive_aggregator.h"
#include "session/session_types.h"
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace callflow {

/**
 * TunnelManager tracks GTP tunnel lifecycle, aggregates keep-alive messages,
 * detects handovers, and provides visualization-friendly output.
 *
 * Features:
 * - Track tunnel creation, modification, deletion
 * - Aggregate Echo Request/Response messages
 * - Detect handovers via TEID changes
 * - Calculate interruption times
 * - Timeout detection and cleanup
 * - Generate visualization JSON
 *
 * Performance targets:
 * - Tunnel lookup: < 100ns (hash table)
 * - Memory: < 2KB per active tunnel
 * - Support: 100,000+ concurrent tunnels
 */
class TunnelManager {
public:
    /**
     * Configuration for tunnel management
     */
    struct Config {
        std::chrono::seconds activity_timeout{7200};      // 2 hours
        std::chrono::seconds echo_timeout_multiplier{3};  // 3x interval
        std::chrono::seconds stale_timeout_multiplier{5}; // 5x interval
        bool enable_handover_detection = true;
        bool enable_auto_cleanup = true;
        uint32_t max_tunnels = 100000;
    };

    explicit TunnelManager(const Config& config = Config{});

    /**
     * Process a session message to update tunnel state
     */
    void processMessage(const SessionMessageRef& msg);

    /**
     * Create a new tunnel from Create Session Request
     */
    void createTunnel(const SessionMessageRef& msg);

    /**
     * Update tunnel from Create Session Response
     */
    void activateTunnel(const SessionMessageRef& msg);

    /**
     * Delete tunnel from Delete Session Request/Response
     */
    void deleteTunnel(const SessionMessageRef& msg);

    /**
     * Modify tunnel (QoS change, handover, etc.)
     */
    void modifyTunnel(const SessionMessageRef& msg);

    /**
     * Track Echo Request
     */
    void handleEchoRequest(const SessionMessageRef& msg);

    /**
     * Track Echo Response
     */
    void handleEchoResponse(const SessionMessageRef& msg);

    /**
     * Track user data packet
     */
    void handleUserData(uint32_t teid, bool is_uplink, uint32_t bytes,
                        const std::chrono::system_clock::time_point& ts);

    /**
     * Get tunnel by TEID
     */
    std::optional<GtpTunnel> getTunnel(uint32_t teid) const;

    /**
     * Get tunnels by IMSI
     */
    std::vector<GtpTunnel> getTunnelsByImsi(const std::string& imsi) const;

    /**
     * Get tunnels by UE IP
     */
    std::vector<GtpTunnel> getTunnelsByUeIp(const std::string& ue_ip) const;

    /**
     * Get all active tunnels
     */
    std::vector<GtpTunnel> getActiveTunnels() const;

    /**
     * Get all tunnels (active and inactive)
     */
    std::vector<GtpTunnel> getAllTunnels() const;

    /**
     * Check for timeouts and cleanup stale tunnels
     */
    void checkTimeouts();

    /**
     * Generate visualization JSON for a tunnel with events timeline
     */
    nlohmann::json getTunnelVisualization(uint32_t teid) const;

    /**
     * Generate visualization JSON for all tunnels of an IMSI
     */
    nlohmann::json getImsiVisualization(const std::string& imsi) const;

    /**
     * Get statistics
     */
    struct Statistics {
        uint32_t total_tunnels = 0;
        uint32_t active_tunnels = 0;
        uint32_t deleted_tunnels = 0;
        uint32_t handovers_detected = 0;
        uint32_t echo_requests = 0;
        uint32_t echo_responses = 0;
        uint64_t total_uplink_bytes = 0;
        uint64_t total_downlink_bytes = 0;
    };

    Statistics getStatistics() const;

    /**
     * Clear all tunnels
     */
    void clear();

    /**
     * Set handover callback (called when handover detected)
     */
    using HandoverCallback = std::function<void(const HandoverEvent&, const GtpTunnel&)>;
    void setHandoverCallback(HandoverCallback callback);

private:
    Config config_;
    KeepAliveAggregator keepalive_aggregator_;

    // TEID -> Tunnel
    std::unordered_map<uint32_t, GtpTunnel> tunnels_;

    // Indices for fast lookup
    std::unordered_map<std::string, std::vector<uint32_t>> imsi_index_;
    std::unordered_map<std::string, std::vector<uint32_t>> ue_ip_index_;

    mutable std::mutex mutex_;

    HandoverCallback handover_callback_;

    /**
     * Extract TEID from message
     */
    std::optional<uint32_t> extractTeid(const SessionMessageRef& msg) const;

    /**
     * Extract TEID pair (uplink/downlink) from message
     */
    struct TeidPair {
        uint32_t uplink;
        uint32_t downlink;
    };
    std::optional<TeidPair> extractTeidPair(const SessionMessageRef& msg) const;

    /**
     * Extract IMSI from message
     */
    std::optional<std::string> extractImsi(const SessionMessageRef& msg) const;

    /**
     * Find existing tunnel by IMSI (for handover detection)
     */
    std::optional<uint32_t> findTunnelByImsi(const std::string& imsi) const;

    /**
     * Detect and handle handover
     */
    void detectHandover(const SessionMessageRef& msg);

    /**
     * Calculate interruption time between old and new TEID
     */
    std::chrono::milliseconds calculateInterruptionTime(uint32_t old_teid,
                                                         uint32_t new_teid) const;

    /**
     * Create tunnel entry from handover
     */
    void createTunnelFromHandover(const GtpTunnel& old_tunnel, uint32_t new_teid,
                                   const HandoverEvent& handover);

    /**
     * Update indices when tunnel created
     */
    void updateIndices(uint32_t teid, const GtpTunnel& tunnel);

    /**
     * Remove from indices when tunnel deleted
     */
    void removeFromIndices(uint32_t teid, const GtpTunnel& tunnel);

    /**
     * Generate event timeline for a tunnel
     */
    std::vector<TunnelEvent> generateEventTimeline(const GtpTunnel& tunnel) const;
};

} // namespace callflow

#endif // TUNNEL_MANAGER_H
