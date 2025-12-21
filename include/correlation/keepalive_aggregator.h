#ifndef KEEPALIVE_AGGREGATOR_H
#define KEEPALIVE_AGGREGATOR_H

#include "tunnel_types.h"
#include <chrono>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <vector>

namespace callflow {

/**
 * KeepAliveAggregator manages GTP Echo Request/Response pairs and determines
 * when to show individual echoes vs aggregated summaries for visualization.
 *
 * Rules for showing individual echo messages:
 * - First echo after tunnel creation
 * - Last echo before tunnel deletion
 * - Echo timeout (missing response)
 * - Interval changes significantly (> 20%)
 *
 * All other echoes are aggregated into "Session Active" indicators.
 */
class KeepAliveAggregator {
public:
    /**
     * Track an Echo Request for a tunnel
     */
    void addEchoRequest(uint32_t teid, const std::chrono::system_clock::time_point& ts);

    /**
     * Track an Echo Response for a tunnel
     */
    void addEchoResponse(uint32_t teid, const std::chrono::system_clock::time_point& ts);

    /**
     * Get aggregated keep-alive summaries for a tunnel
     */
    std::vector<AggregatedKeepalive> getAggregatedKeepalives(uint32_t teid) const;

    /**
     * Determine if an echo should be shown individually in visualization
     */
    bool shouldShowEcho(uint32_t teid, const std::chrono::system_clock::time_point& ts) const;

    /**
     * Finalize aggregation for a tunnel (call when tunnel is deleted)
     */
    void finalizeTunnel(uint32_t teid);

    /**
     * Get echo statistics for a tunnel
     */
    struct EchoStats {
        uint32_t request_count = 0;
        uint32_t response_count = 0;
        uint32_t timeout_count = 0;
        std::chrono::seconds avg_interval{0};
        std::optional<std::chrono::system_clock::time_point> last_request;
        std::optional<std::chrono::system_clock::time_point> last_response;
    };

    EchoStats getEchoStats(uint32_t teid) const;

    /**
     * Clear all data for a tunnel
     */
    void clearTunnel(uint32_t teid);

    /**
     * Clear all data
     */
    void clear();

private:
    struct EchoRecord {
        std::chrono::system_clock::time_point request_time;
        std::optional<std::chrono::system_clock::time_point> response_time;
        bool is_timeout = false;
        bool show_individually = false;  // Flag for visualization
    };

    struct TunnelEchoData {
        std::vector<EchoRecord> echoes;
        std::chrono::seconds current_interval{0};
        bool is_finalized = false;
        std::vector<AggregatedKeepalive> aggregated_cache;
    };

    // TEID -> echo tracking data
    std::map<uint32_t, TunnelEchoData> tunnel_data_;

    mutable std::mutex mutex_;

    /**
     * Calculate average interval between echoes
     */
    std::chrono::seconds calculateAverageInterval(const std::vector<EchoRecord>& echoes) const;

    /**
     * Detect significant interval change (> 20%)
     */
    bool isSignificantIntervalChange(std::chrono::seconds old_interval,
                                      std::chrono::seconds new_interval) const;

    /**
     * Generate aggregated summaries from echo records
     */
    std::vector<AggregatedKeepalive> generateAggregations(
        const std::vector<EchoRecord>& echoes) const;

    /**
     * Mark echoes that should be shown individually
     */
    void markEchoesForVisualization(TunnelEchoData& data);
};

} // namespace callflow

#endif // KEEPALIVE_AGGREGATOR_H
