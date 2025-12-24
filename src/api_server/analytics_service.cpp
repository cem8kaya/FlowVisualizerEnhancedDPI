#include "api_server/analytics_service.h"

#include <sqlite3.h>

#include <algorithm>
#include <iostream>

#include "api_server/job_manager.h"
#include "common/logger.h"
#include "common/utils.h"
#include "persistence/database.h"

namespace callflow {

AnalyticsService::AnalyticsService(std::shared_ptr<JobManager> job_mgr,
                                   std::shared_ptr<DatabaseManager> db_mgr)
    : job_manager_(job_mgr), db_manager_(db_mgr) {}

AnalyticsService::Summary AnalyticsService::getSummary() const {
    Summary summary{};

    // Get job stats from JobManager (in-memory + DB loaded)
    auto jobs = job_manager_->getAllJobs();
    summary.total_jobs = jobs.size();

    for (const auto& job : jobs) {
        if (job->status == JobStatus::RUNNING || job->status == JobStatus::QUEUED) {
            summary.active_jobs++;
        } else if (job->status == JobStatus::COMPLETED) {
            summary.completed_jobs++;
            summary.bytes_processed += job->total_bytes;
        } else if (job->status == JobStatus::FAILED) {
            summary.failed_jobs++;
        }
    }

    // Get session stats from Database
    // We use raw queries for efficiency and aggregation
    sqlite3* db = static_cast<sqlite3*>(db_manager_->getHandle());
    sqlite3_stmt* stmt;

    // Total sessions
    const char* sql_sessions = "SELECT COUNT(*) FROM sessions";
    if (sqlite3_prepare_v2(db, sql_sessions, -1, &stmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            summary.total_sessions = sqlite3_column_int64(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }

    // VoLTE calls
    const char* sql_volte = "SELECT COUNT(*) FROM sessions WHERE session_type = 'VOLTE'";
    if (sqlite3_prepare_v2(db, sql_volte, -1, &stmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            summary.volte_calls = sqlite3_column_int64(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }

    // Failed sessions (incomplete or error)
    // Assuming 'incomplete' logic or specific error flags. For now, we can check for incomplete
    // sessions. OR we can look for specific types if defined. Let's use is_complete logic if mapped
    // to DB or just 0 for now if not tracked. SessionRecord doesn't explicitly store 'failed' but
    // 'is_complete' might be relevant if stored. Let's count sessions where end_time is 0 or
    // duration is 0 for 'failed/incomplete' rough proxy, or rely on future schema. For now, let's
    // query for sessions with no end_time as 'active/incomplete/failed' Actually, let's assume
    // 'failed_sessions' are those with error metadata or explicitly marked. Given the schema in
    // database.h, we don't have a 'failed' column. Let's return 0 or a placeholder.
    summary.failed_sessions = 0;

    // VoLTE Trend (Today vs Yesterday)
    // Get count for last 24h
    auto now = std::chrono::system_clock::now();
    auto yesterday = now - std::chrono::hours(24);
    auto two_days_ago = now - std::chrono::hours(48);

    long long now_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    long long yesterday_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(yesterday.time_since_epoch()).count();
    long long two_days_ago_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(two_days_ago.time_since_epoch())
            .count();

    size_t today_count = 0;
    size_t yesterday_count = 0;

    std::string sql_trend =
        "SELECT COUNT(*) FROM sessions WHERE session_type = 'VOLTE' AND start_time >= ? AND "
        "start_time < ?";

    // Today
    if (sqlite3_prepare_v2(db, sql_trend.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int64(stmt, 1, yesterday_ms);
        sqlite3_bind_int64(stmt, 2, now_ms);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            today_count = sqlite3_column_int64(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }

    // Yesterday
    if (sqlite3_prepare_v2(db, sql_trend.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int64(stmt, 1, two_days_ago_ms);
        sqlite3_bind_int64(stmt, 2, yesterday_ms);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            yesterday_count = sqlite3_column_int64(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }

    if (yesterday_count > 0) {
        summary.volte_trend_percent =
            ((double)today_count - (double)yesterday_count) / (double)yesterday_count * 100.0;
    } else {
        summary.volte_trend_percent = today_count > 0 ? 100.0 : 0.0;
    }

    return summary;
}

nlohmann::json AnalyticsService::getSummaryJson() const {
    Summary s = getSummary();
    return {{"total_jobs", s.total_jobs},
            {"active_jobs", s.active_jobs},
            {"completed_jobs", s.completed_jobs},
            {"failed_jobs", s.failed_jobs},
            {"total_sessions", s.total_sessions},
            {"volte_calls", s.volte_calls},
            {"failed_sessions", s.failed_sessions},
            {"bytes_processed", s.bytes_processed},
            {"volte_trend_percent", s.volte_trend_percent}};
}

std::vector<AnalyticsService::ProtocolStat> AnalyticsService::getProtocolDistribution(
    const std::string& job_id, std::chrono::hours timeframe) const {
    std::vector<ProtocolStat> stats;
    sqlite3* db = static_cast<sqlite3*>(db_manager_->getHandle());
    sqlite3_stmt* stmt;

    std::string sql = "SELECT session_type, COUNT(*) FROM sessions WHERE 1=1";
    if (!job_id.empty()) {
        sql += " AND job_id = ?";
    }

    // Apply timeframe only if job_id is empty (global stats), otherwise full job stats
    if (job_id.empty()) {
        auto now = std::chrono::system_clock::now();
        long long since_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                 (now - timeframe).time_since_epoch())
                                 .count();
        sql += " AND start_time >= " + std::to_string(since_ms);
    }

    sql += " GROUP BY session_type";

    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        LOG_ERROR("Failed to prepare protocol distribution query");
        return stats;
    }

    if (!job_id.empty()) {
        sqlite3_bind_text(stmt, 1, job_id.c_str(), -1, SQLITE_STATIC);
    }

    size_t total = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        std::string proto = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        size_t count = sqlite3_column_int64(stmt, 1);

        ProtocolStat stat;
        stat.protocol = proto;
        stat.count = count;
        stats.push_back(stat);
        total += count;
    }
    sqlite3_finalize(stmt);

    for (auto& stat : stats) {
        if (total > 0) {
            stat.percentage = (double)stat.count / total * 100.0;
        } else {
            stat.percentage = 0.0;
        }
    }

    return stats;
}

nlohmann::json AnalyticsService::getProtocolDistributionJson(
    const std::string& job_id, const std::string& timeframe_str) const {
    std::chrono::hours timeframe(24);
    if (timeframe_str == "1h")
        timeframe = std::chrono::hours(1);
    else if (timeframe_str == "7d")
        timeframe = std::chrono::hours(24 * 7);
    else if (timeframe_str == "30d")
        timeframe = std::chrono::hours(24 * 30);

    auto stats = getProtocolDistribution(job_id, timeframe);
    nlohmann::json result = nlohmann::json::array();
    for (const auto& stat : stats) {
        result.push_back(
            {{"protocol", stat.protocol}, {"count", stat.count}, {"percentage", stat.percentage}});
    }
    return result;
}

std::vector<AnalyticsService::VolteTrendPoint> AnalyticsService::getVolteTrend(
    std::chrono::hours duration, std::chrono::minutes interval) const {
    std::vector<VolteTrendPoint> points;
    sqlite3* db = static_cast<sqlite3*>(db_manager_->getHandle());
    sqlite3_stmt* stmt;

    auto now = std::chrono::system_clock::now();
    long long start_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>((now - duration).time_since_epoch())
            .count();
    long long interval_ms = std::chrono::duration_cast<std::chrono::milliseconds>(interval).count();

    // Group by time bucket
    // Note: This query uses SQLite integer division for bucketing
    std::string sql = R"(
        SELECT 
            (start_time / ?) * ? as bucket,
            COUNT(*) as count,
            AVG(duration_ms) as avg_duration 
        FROM sessions 
        WHERE session_type = 'VOLTE' AND start_time >= ?
        GROUP BY bucket 
        ORDER BY bucket
    )";

    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        LOG_ERROR("Failed to prepare trend query");
        return points;
    }

    sqlite3_bind_int64(stmt, 1, interval_ms);
    sqlite3_bind_int64(stmt, 2, interval_ms);
    sqlite3_bind_int64(stmt, 3, start_ms);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        long long bucket_ms = sqlite3_column_int64(stmt, 0);
        size_t count = sqlite3_column_int64(stmt, 1);
        double avg_duration = sqlite3_column_double(stmt, 2);

        VolteTrendPoint point;
        point.timestamp = utils::timestampToIso8601(
            std::chrono::system_clock::time_point(std::chrono::milliseconds(bucket_ms)));
        point.call_count = count;
        // Placeholder values for columns we might not track yet
        point.avg_mos = 4.0;              // Mock or need MOS column
        point.success_rate = 100.0;       // Mock or need status check
        point.avg_setup_time_ms = 500.0;  // Mock or need setup_time column

        points.push_back(point);
    }
    sqlite3_finalize(stmt);

    return points;
}

nlohmann::json AnalyticsService::getVolteTrendJson(const std::string& duration_str) const {
    std::chrono::hours duration(24);
    std::chrono::minutes interval(60);

    if (duration_str == "1h") {
        duration = std::chrono::hours(1);
        interval = std::chrono::minutes(5);
    } else if (duration_str == "7d") {
        duration = std::chrono::hours(168);
        interval = std::chrono::hours(6);
    }

    auto trend = getVolteTrend(duration, interval);
    nlohmann::json result = nlohmann::json::array();
    for (const auto& p : trend) {
        result.push_back({{"timestamp", p.timestamp},
                          {"call_count", p.call_count},
                          {"avg_mos", p.avg_mos},
                          {"success_rate", p.success_rate},
                          {"avg_setup_time", p.avg_setup_time_ms}});
    }
    return result;
}

nlohmann::json AnalyticsService::getJobStats(const std::string& job_id) const {
    auto job = job_manager_->getJobInfo(job_id);
    if (!job)
        return nullptr;

    return {{"job_id", job->job_id},
            {"status", jobStatusToString(job->status)},
            {"sessions", job->session_count},
            {"packets", job->total_packets},
            {"bytes", job->total_bytes}};
}

}  // namespace callflow
