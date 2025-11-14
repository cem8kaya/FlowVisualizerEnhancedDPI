#include "api_server/analytics_manager.h"
#include "common/logger.h"
#include <sstream>
#include <iomanip>
#include <chrono>
#include <cmath>
#include <sys/resource.h>
#include <unistd.h>

namespace callflow {

// ============================================================================
// Constructor / Destructor
// ============================================================================

AnalyticsManager::AnalyticsManager(DatabaseManager* db)
    : db_(db), caching_enabled_(true) {
    if (!db_) {
        throw std::runtime_error("DatabaseManager cannot be null");
    }

    LOG_INFO("AnalyticsManager initialized");
}

AnalyticsManager::~AnalyticsManager() = default;

// ============================================================================
// Summary Statistics
// ============================================================================

AnalyticsSummary AnalyticsManager::getSummary(
    std::optional<int64_t> start_date,
    std::optional<int64_t> end_date
) {
    // Check cache
    if (caching_enabled_ && isCacheValid() && cache_.summary && !start_date && !end_date) {
        return *cache_.summary;
    }

    AnalyticsSummary summary;

    // Build WHERE clause for date filtering
    std::string where_clause;
    if (start_date || end_date) {
        where_clause = " WHERE ";
        if (start_date && end_date) {
            where_clause += "created_at >= " + std::to_string(*start_date) +
                          " AND created_at <= " + std::to_string(*end_date);
        } else if (start_date) {
            where_clause += "created_at >= " + std::to_string(*start_date);
        } else {
            where_clause += "created_at <= " + std::to_string(*end_date);
        }
    }

    // Job statistics
    std::string job_sql = "SELECT status, COUNT(*) FROM jobs" + where_clause + " GROUP BY status";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(
            static_cast<sqlite3*>(db_->getHandle()),
            job_sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            std::string status = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            int count = sqlite3_column_int(stmt, 1);

            summary.total_jobs += count;
            if (status == "completed") {
                summary.completed_jobs = count;
            } else if (status == "failed") {
                summary.failed_jobs = count;
            } else if (status == "running" || status == "queued") {
                summary.active_jobs += count;
            }
        }
        sqlite3_finalize(stmt);
    }

    // Session statistics
    std::string session_where = where_clause.empty() ? "" :
        " WHERE session_id IN (SELECT session_id FROM sessions s JOIN jobs j ON s.job_id = j.job_id" + where_clause + ")";

    std::string session_sql = "SELECT COUNT(*), SUM(packet_count), SUM(byte_count), AVG(duration_ms) "
                             "FROM sessions" + session_where;

    if (sqlite3_prepare_v2(
            static_cast<sqlite3*>(db_->getHandle()),
            session_sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {

        if (sqlite3_step(stmt) == SQLITE_ROW) {
            summary.total_sessions = sqlite3_column_int(stmt, 0);
            summary.total_packets = sqlite3_column_int64(stmt, 1);
            summary.total_bytes = sqlite3_column_int64(stmt, 2);
            summary.avg_session_duration_ms = sqlite3_column_double(stmt, 3);
        }
        sqlite3_finalize(stmt);
    }

    // Calculate average packets per session
    if (summary.total_sessions > 0) {
        summary.avg_packets_per_session =
            static_cast<double>(summary.total_packets) / summary.total_sessions;
    }

    // Protocol distribution
    std::string proto_sql = "SELECT session_type, COUNT(*) FROM sessions" + session_where +
                           " GROUP BY session_type";

    if (sqlite3_prepare_v2(
            static_cast<sqlite3*>(db_->getHandle()),
            proto_sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            std::string protocol = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            int count = sqlite3_column_int(stmt, 1);

            if (summary.total_sessions > 0) {
                double percentage = (static_cast<double>(count) / summary.total_sessions) * 100.0;
                summary.protocol_distribution[protocol] = percentage;
            }
        }
        sqlite3_finalize(stmt);
    }

    // Update cache
    if (caching_enabled_ && !start_date && !end_date) {
        cache_.summary = summary;
        updateCacheTimestamp();
    }

    return summary;
}

// ============================================================================
// Protocol Analytics
// ============================================================================

std::vector<ProtocolStats> AnalyticsManager::getProtocolStats(
    const std::optional<std::string>& job_id
) {
    std::vector<ProtocolStats> stats;

    std::string where_clause;
    if (job_id) {
        where_clause = " WHERE job_id = '" + *job_id + "'";
    }

    std::string sql = R"(
        SELECT
            session_type,
            COUNT(*) as session_count,
            SUM(packet_count) as packet_count,
            SUM(byte_count) as byte_count
        FROM sessions
    )" + where_clause + " GROUP BY session_type ORDER BY session_count DESC";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(
            static_cast<sqlite3*>(db_->getHandle()),
            sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        return stats;
    }

    int64_t total_sessions = 0;

    // First pass: calculate total
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        total_sessions += sqlite3_column_int(stmt, 1);
    }
    sqlite3_reset(stmt);

    // Second pass: build stats with percentages
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        ProtocolStats ps;
        ps.protocol = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        ps.session_count = sqlite3_column_int(stmt, 1);
        ps.packet_count = sqlite3_column_int64(stmt, 2);
        ps.byte_count = sqlite3_column_int64(stmt, 3);

        if (total_sessions > 0) {
            ps.percentage = (static_cast<double>(ps.session_count) / total_sessions) * 100.0;
        }

        stats.push_back(ps);
    }

    sqlite3_finalize(stmt);
    return stats;
}

std::map<std::string, double> AnalyticsManager::getProtocolDistribution(
    const std::optional<std::string>& job_id
) {
    std::map<std::string, double> distribution;

    auto stats = getProtocolStats(job_id);
    for (const auto& s : stats) {
        distribution[s.protocol] = s.percentage;
    }

    return distribution;
}

// ============================================================================
// Traffic Analytics
// ============================================================================

std::vector<TalkerStats> AnalyticsManager::getTopTalkers(
    int limit,
    const std::optional<std::string>& job_id
) {
    std::vector<TalkerStats> talkers;

    std::string where_clause;
    if (job_id) {
        where_clause = " WHERE e.session_id IN (SELECT session_id FROM sessions WHERE job_id = '" + *job_id + "')";
    }

    // Extract IPs from events table (source and destination)
    std::string sql = R"(
        SELECT
            ip,
            COUNT(*) as packet_count,
            COUNT(DISTINCT session_id) as session_count
        FROM (
            SELECT src_ip as ip, session_id FROM events )" + where_clause + R"(
            UNION ALL
            SELECT dst_ip as ip, session_id FROM events )" + where_clause + R"(
        ) combined
        GROUP BY ip
        ORDER BY packet_count DESC
        LIMIT ?
    )";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(
            static_cast<sqlite3*>(db_->getHandle()),
            sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        return talkers;
    }

    sqlite3_bind_int(stmt, 1, limit);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        TalkerStats ts;
        ts.ip_address = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        ts.packet_count = sqlite3_column_int64(stmt, 1);
        ts.session_count = sqlite3_column_int(stmt, 2);
        ts.byte_count = 0;  // Would need payload size tracking

        talkers.push_back(ts);
    }

    sqlite3_finalize(stmt);
    return talkers;
}

std::vector<TalkerStats> AnalyticsManager::getTopTalkersByBytes(
    int limit,
    const std::optional<std::string>& job_id
) {
    // For byte-based top talkers, we need to track byte counts per IP
    // This would require additional event metadata
    // For now, return packet-based talkers
    return getTopTalkers(limit, job_id);
}

// ============================================================================
// Performance Metrics
// ============================================================================

PerformanceMetrics AnalyticsManager::getPerformanceMetrics() {
    // Check cache
    if (caching_enabled_ && isCacheValid() && cache_.performance) {
        return *cache_.performance;
    }

    PerformanceMetrics metrics;

    // Calculate parsing throughput from recent jobs
    std::string sql = R"(
        SELECT
            AVG(total_bytes / NULLIF((completed_at - started_at), 0)) as avg_bytes_per_sec,
            AVG((completed_at - started_at) / 1000.0) as avg_completion_time_sec
        FROM jobs
        WHERE status = 'completed' AND started_at > 0 AND completed_at > started_at
    )";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(
            static_cast<sqlite3*>(db_->getHandle()),
            sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {

        if (sqlite3_step(stmt) == SQLITE_ROW) {
            double bytes_per_sec = sqlite3_column_double(stmt, 0);
            metrics.avg_parsing_throughput_mbps = (bytes_per_sec * 8.0) / (1024.0 * 1024.0);
            metrics.avg_job_completion_time_sec = sqlite3_column_double(stmt, 1);
        }
        sqlite3_finalize(stmt);
    }

    // Active and queued jobs
    sql = "SELECT status, COUNT(*) FROM jobs WHERE status IN ('running', 'queued') GROUP BY status";

    if (sqlite3_prepare_v2(
            static_cast<sqlite3*>(db_->getHandle()),
            sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            std::string status = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            int count = sqlite3_column_int(stmt, 1);

            if (status == "running") {
                metrics.active_jobs = count;
            } else if (status == "queued") {
                metrics.queued_jobs = count;
            }
        }
        sqlite3_finalize(stmt);
    }

    // Cache hit rate (placeholder - would need caching implementation)
    metrics.cache_hit_rate = 0.0;

    // Memory usage
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
        metrics.memory_usage_mb = usage.ru_maxrss / 1024;  // KB to MB
    }

    // API metrics
    if (metrics_.total_api_requests > 0) {
        metrics.total_api_requests = metrics_.total_api_requests;
        metrics.avg_api_response_time_ms =
            metrics_.total_api_response_time_ms / metrics_.total_api_requests;
    }

    // Update cached metrics from our internal tracking
    if (metrics_.total_jobs_completed > 0) {
        metrics.avg_job_completion_time_sec =
            metrics_.total_job_completion_time_sec / metrics_.total_jobs_completed;
    }

    // Update cache
    if (caching_enabled_) {
        cache_.performance = metrics;
        updateCacheTimestamp();
    }

    return metrics;
}

void AnalyticsManager::recordApiRequest(double response_time_ms) {
    metrics_.total_api_requests++;
    metrics_.total_api_response_time_ms += response_time_ms;
}

void AnalyticsManager::recordJobCompletion(const std::string& job_id, double completion_time_sec) {
    metrics_.total_jobs_completed++;
    metrics_.total_job_completion_time_sec += completion_time_sec;

    LOG_DEBUG("Job {} completed in {:.2f}s", job_id, completion_time_sec);
}

// ============================================================================
// Time Series Data
// ============================================================================

std::vector<TimeSeriesPoint> AnalyticsManager::getJobsOverTime(
    int64_t start,
    int64_t end,
    const std::string& interval
) {
    std::vector<TimeSeriesPoint> points;

    int64_t interval_sec = parseInterval(interval);

    // Group jobs by time intervals
    std::string sql = R"(
        SELECT
            ? * (created_at / ?) as bucket,
            COUNT(*) as count
        FROM jobs
        WHERE created_at >= ? AND created_at <= ?
        GROUP BY bucket
        ORDER BY bucket
    )";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(
            static_cast<sqlite3*>(db_->getHandle()),
            sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        return points;
    }

    sqlite3_bind_int64(stmt, 1, interval_sec);
    sqlite3_bind_int64(stmt, 2, interval_sec);
    sqlite3_bind_int64(stmt, 3, start);
    sqlite3_bind_int64(stmt, 4, end);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        TimeSeriesPoint point;
        point.timestamp = sqlite3_column_int64(stmt, 0);
        point.value = sqlite3_column_int64(stmt, 1);
        points.push_back(point);
    }

    sqlite3_finalize(stmt);
    return points;
}

std::vector<TimeSeriesPoint> AnalyticsManager::getSessionsOverTime(
    int64_t start,
    int64_t end,
    const std::string& interval
) {
    std::vector<TimeSeriesPoint> points;

    int64_t interval_sec = parseInterval(interval);

    // Group sessions by time intervals
    std::string sql = R"(
        SELECT
            ? * (start_time / ?) as bucket,
            COUNT(*) as count
        FROM sessions
        WHERE start_time >= ? AND start_time <= ?
        GROUP BY bucket
        ORDER BY bucket
    )";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(
            static_cast<sqlite3*>(db_->getHandle()),
            sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        return points;
    }

    sqlite3_bind_int64(stmt, 1, interval_sec);
    sqlite3_bind_int64(stmt, 2, interval_sec);
    sqlite3_bind_int64(stmt, 3, start);
    sqlite3_bind_int64(stmt, 4, end);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        TimeSeriesPoint point;
        point.timestamp = sqlite3_column_int64(stmt, 0);
        point.value = sqlite3_column_int64(stmt, 1);
        points.push_back(point);
    }

    sqlite3_finalize(stmt);
    return points;
}

// ============================================================================
// Prometheus Metrics Export
// ============================================================================

std::string AnalyticsManager::exportPrometheusMetrics() {
    std::ostringstream oss;

    auto summary = getSummary();
    auto perf = getPerformanceMetrics();

    // Jobs metrics
    oss << "# HELP callflowd_jobs_total Total jobs processed\n";
    oss << "# TYPE callflowd_jobs_total counter\n";
    oss << "callflowd_jobs_total{status=\"completed\"} " << summary.completed_jobs << "\n";
    oss << "callflowd_jobs_total{status=\"failed\"} " << summary.failed_jobs << "\n";
    oss << "callflowd_jobs_total{status=\"active\"} " << summary.active_jobs << "\n";
    oss << "\n";

    // Sessions metrics
    oss << "# HELP callflowd_sessions_total Total sessions processed\n";
    oss << "# TYPE callflowd_sessions_total counter\n";
    oss << "callflowd_sessions_total " << summary.total_sessions << "\n";
    oss << "\n";

    // Sessions by protocol
    oss << "# HELP callflowd_sessions_by_protocol Sessions grouped by protocol\n";
    oss << "# TYPE callflowd_sessions_by_protocol gauge\n";
    for (const auto& [protocol, percentage] : summary.protocol_distribution) {
        int count = static_cast<int>(summary.total_sessions * percentage / 100.0);
        oss << "callflowd_sessions_by_protocol{protocol=\"" << protocol
            << "\"} " << count << "\n";
    }
    oss << "\n";

    // Packets and bytes
    oss << "# HELP callflowd_packets_total Total packets processed\n";
    oss << "# TYPE callflowd_packets_total counter\n";
    oss << "callflowd_packets_total " << summary.total_packets << "\n";
    oss << "\n";

    oss << "# HELP callflowd_bytes_total Total bytes processed\n";
    oss << "# TYPE callflowd_bytes_total counter\n";
    oss << "callflowd_bytes_total " << summary.total_bytes << "\n";
    oss << "\n";

    // Performance metrics
    oss << "# HELP callflowd_parsing_throughput_mbps Parsing throughput in Mbps\n";
    oss << "# TYPE callflowd_parsing_throughput_mbps gauge\n";
    oss << "callflowd_parsing_throughput_mbps " << perf.avg_parsing_throughput_mbps << "\n";
    oss << "\n";

    oss << "# HELP callflowd_job_completion_time_seconds Average job completion time\n";
    oss << "# TYPE callflowd_job_completion_time_seconds gauge\n";
    oss << "callflowd_job_completion_time_seconds " << perf.avg_job_completion_time_sec << "\n";
    oss << "\n";

    oss << "# HELP callflowd_active_jobs Number of active jobs\n";
    oss << "# TYPE callflowd_active_jobs gauge\n";
    oss << "callflowd_active_jobs " << perf.active_jobs << "\n";
    oss << "\n";

    oss << "# HELP callflowd_queued_jobs Number of queued jobs\n";
    oss << "# TYPE callflowd_queued_jobs gauge\n";
    oss << "callflowd_queued_jobs " << perf.queued_jobs << "\n";
    oss << "\n";

    oss << "# HELP callflowd_memory_usage_bytes Memory usage in bytes\n";
    oss << "# TYPE callflowd_memory_usage_bytes gauge\n";
    oss << "callflowd_memory_usage_bytes " << (perf.memory_usage_mb * 1024 * 1024) << "\n";
    oss << "\n";

    oss << "# HELP callflowd_api_requests_total Total API requests\n";
    oss << "# TYPE callflowd_api_requests_total counter\n";
    oss << "callflowd_api_requests_total " << perf.total_api_requests << "\n";
    oss << "\n";

    oss << "# HELP callflowd_api_response_time_milliseconds Average API response time\n";
    oss << "# TYPE callflowd_api_response_time_milliseconds gauge\n";
    oss << "callflowd_api_response_time_milliseconds " << perf.avg_api_response_time_ms << "\n";
    oss << "\n";

    // Session metrics
    oss << "# HELP callflowd_session_duration_milliseconds Average session duration\n";
    oss << "# TYPE callflowd_session_duration_milliseconds gauge\n";
    oss << "callflowd_session_duration_milliseconds " << summary.avg_session_duration_ms << "\n";
    oss << "\n";

    oss << "# HELP callflowd_packets_per_session Average packets per session\n";
    oss << "# TYPE callflowd_packets_per_session gauge\n";
    oss << "callflowd_packets_per_session " << summary.avg_packets_per_session << "\n";
    oss << "\n";

    return oss.str();
}

// ============================================================================
// Cache Management
// ============================================================================

void AnalyticsManager::clearCache() {
    cache_.summary = std::nullopt;
    cache_.protocol_stats = std::nullopt;
    cache_.performance = std::nullopt;
    cache_.last_update = 0;

    LOG_DEBUG("Analytics cache cleared");
}

void AnalyticsManager::setCachingEnabled(bool enabled) {
    caching_enabled_ = enabled;
    if (!enabled) {
        clearCache();
    }

    LOG_INFO("Analytics caching {}", enabled ? "enabled" : "disabled");
}

// ============================================================================
// Private Helper Methods
// ============================================================================

bool AnalyticsManager::isCacheValid() const {
    auto now = std::chrono::system_clock::now();
    auto now_sec = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count();

    return (now_sec - cache_.last_update) < cache_.ttl_seconds;
}

void AnalyticsManager::updateCacheTimestamp() {
    auto now = std::chrono::system_clock::now();
    cache_.last_update = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count();
}

int64_t AnalyticsManager::parseInterval(const std::string& interval) const {
    // Parse interval string (e.g., "1h", "1d", "1w")
    if (interval.empty()) {
        return 3600;  // Default: 1 hour
    }

    size_t num_end = 0;
    int value = std::stoi(interval, &num_end);

    if (num_end >= interval.length()) {
        return value;  // Just a number in seconds
    }

    char unit = interval[num_end];
    switch (unit) {
        case 's': return value;
        case 'm': return value * 60;
        case 'h': return value * 3600;
        case 'd': return value * 86400;
        case 'w': return value * 604800;
        default: return 3600;  // Default: 1 hour
    }
}

int64_t AnalyticsManager::roundToInterval(int64_t timestamp, int64_t interval_seconds) const {
    return (timestamp / interval_seconds) * interval_seconds;
}

}  // namespace callflow
