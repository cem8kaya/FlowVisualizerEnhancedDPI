#pragma once

#include "common/types.h"
#include "persistence/database.h"
#include <string>
#include <vector>
#include <map>
#include <optional>

namespace callflow {

// Forward declaration
class DatabaseManager;

/**
 * Summary statistics
 */
struct AnalyticsSummary {
    int total_jobs = 0;
    int completed_jobs = 0;
    int failed_jobs = 0;
    int active_jobs = 0;
    int total_sessions = 0;
    int64_t total_packets = 0;
    int64_t total_bytes = 0;
    double avg_session_duration_ms = 0.0;
    double avg_packets_per_session = 0.0;
    std::map<std::string, double> protocol_distribution;  // protocol -> percentage
};

/**
 * Protocol statistics
 */
struct ProtocolStats {
    std::string protocol;
    int session_count = 0;
    int64_t packet_count = 0;
    int64_t byte_count = 0;
    double percentage = 0.0;
};

/**
 * Top talker statistics
 */
struct TalkerStats {
    std::string ip_address;
    int64_t packet_count = 0;
    int64_t byte_count = 0;
    int session_count = 0;
};

/**
 * Performance metrics
 */
struct PerformanceMetrics {
    double avg_parsing_throughput_mbps = 0.0;
    double avg_job_completion_time_sec = 0.0;
    double cache_hit_rate = 0.0;
    size_t memory_usage_mb = 0;
    int active_jobs = 0;
    int queued_jobs = 0;
    int total_api_requests = 0;
    double avg_api_response_time_ms = 0.0;
};

/**
 * Time series data point
 */
struct TimeSeriesPoint {
    int64_t timestamp;
    int64_t value;
};

/**
 * AnalyticsManager - Provides analytics and monitoring data
 */
class AnalyticsManager {
public:
    /**
     * Constructor
     * @param db Database manager for data queries
     */
    explicit AnalyticsManager(DatabaseManager* db);

    /**
     * Destructor
     */
    ~AnalyticsManager();

    // ========================================================================
    // Summary Statistics
    // ========================================================================

    /**
     * Get overall summary statistics
     * @param start_date Optional start date filter (Unix timestamp seconds)
     * @param end_date Optional end date filter (Unix timestamp seconds)
     * @return Summary statistics
     */
    AnalyticsSummary getSummary(
        std::optional<int64_t> start_date = std::nullopt,
        std::optional<int64_t> end_date = std::nullopt
    );

    // ========================================================================
    // Protocol Analytics
    // ========================================================================

    /**
     * Get protocol statistics
     * @param job_id Optional job ID filter
     * @return List of protocol statistics
     */
    std::vector<ProtocolStats> getProtocolStats(
        const std::optional<std::string>& job_id = std::nullopt
    );

    /**
     * Get protocol distribution (for pie chart)
     * @param job_id Optional job ID filter
     * @return Map of protocol name to percentage
     */
    std::map<std::string, double> getProtocolDistribution(
        const std::optional<std::string>& job_id = std::nullopt
    );

    // ========================================================================
    // Traffic Analytics
    // ========================================================================

    /**
     * Get top talkers by packet count
     * @param limit Maximum number of results
     * @param job_id Optional job ID filter
     * @return List of top talker statistics
     */
    std::vector<TalkerStats> getTopTalkers(
        int limit = 10,
        const std::optional<std::string>& job_id = std::nullopt
    );

    /**
     * Get top talkers by byte count
     * @param limit Maximum number of results
     * @param job_id Optional job ID filter
     * @return List of top talker statistics
     */
    std::vector<TalkerStats> getTopTalkersByBytes(
        int limit = 10,
        const std::optional<std::string>& job_id = std::nullopt
    );

    // ========================================================================
    // Performance Metrics
    // ========================================================================

    /**
     * Get current performance metrics
     * @return Performance metrics
     */
    PerformanceMetrics getPerformanceMetrics();

    /**
     * Update API request metrics (call after each API request)
     * @param response_time_ms Response time in milliseconds
     */
    void recordApiRequest(double response_time_ms);

    /**
     * Update job metrics (call when job completes)
     * @param job_id Job ID
     * @param completion_time_sec Time taken to complete job
     */
    void recordJobCompletion(const std::string& job_id, double completion_time_sec);

    // ========================================================================
    // Time Series Data
    // ========================================================================

    /**
     * Get jobs over time
     * @param start Start timestamp (Unix seconds)
     * @param end End timestamp (Unix seconds)
     * @param interval Interval size ("1h", "1d", "1w")
     * @return Time series data points
     */
    std::vector<TimeSeriesPoint> getJobsOverTime(
        int64_t start,
        int64_t end,
        const std::string& interval = "1h"
    );

    /**
     * Get sessions over time
     * @param start Start timestamp (Unix seconds)
     * @param end End timestamp (Unix seconds)
     * @param interval Interval size ("1h", "1d", "1w")
     * @return Time series data points
     */
    std::vector<TimeSeriesPoint> getSessionsOverTime(
        int64_t start,
        int64_t end,
        const std::string& interval = "1h"
    );

    // ========================================================================
    // Prometheus Metrics Export
    // ========================================================================

    /**
     * Export metrics in Prometheus text format
     * @return Prometheus metrics text
     */
    std::string exportPrometheusMetrics();

    // ========================================================================
    // Cache Management
    // ========================================================================

    /**
     * Clear analytics cache (force recalculation)
     */
    void clearCache();

    /**
     * Enable/disable caching
     * @param enabled Enable caching
     */
    void setCachingEnabled(bool enabled);

private:
    DatabaseManager* db_;
    bool caching_enabled_;

    // Performance tracking
    struct {
        int64_t total_api_requests = 0;
        double total_api_response_time_ms = 0.0;
        int64_t total_jobs_completed = 0;
        double total_job_completion_time_sec = 0.0;
    } metrics_;

    // Cache
    struct {
        std::optional<AnalyticsSummary> summary;
        std::optional<std::vector<ProtocolStats>> protocol_stats;
        std::optional<PerformanceMetrics> performance;
        int64_t last_update = 0;
        int ttl_seconds = 60;  // Cache TTL
    } cache_;

    /**
     * Check if cache is valid
     * @return true if cache can be used
     */
    bool isCacheValid() const;

    /**
     * Update cache timestamp
     */
    void updateCacheTimestamp();

    /**
     * Parse interval string to seconds
     * @param interval Interval string ("1h", "1d", "1w")
     * @return Interval in seconds
     */
    int64_t parseInterval(const std::string& interval) const;

    /**
     * Round timestamp to interval boundary
     * @param timestamp Unix timestamp
     * @param interval_seconds Interval size in seconds
     * @return Rounded timestamp
     */
    int64_t roundToInterval(int64_t timestamp, int64_t interval_seconds) const;
};

}  // namespace callflow
