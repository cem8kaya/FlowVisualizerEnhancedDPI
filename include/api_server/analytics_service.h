#pragma once
#include <chrono>
#include <map>
#include <memory>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

namespace callflow {

class JobManager;
class DatabaseManager;

class AnalyticsService {
public:
    AnalyticsService(std::shared_ptr<JobManager> job_mgr, std::shared_ptr<DatabaseManager> db_mgr);

    // Dashboard summary
    struct Summary {
        size_t total_jobs;
        size_t active_jobs;
        size_t completed_jobs;
        size_t failed_jobs;
        size_t total_sessions;
        size_t volte_calls;
        size_t failed_sessions;
        uint64_t bytes_processed;
        double volte_trend_percent;  // vs yesterday
    };
    Summary getSummary() const;
    nlohmann::json getSummaryJson() const;

    // Protocol distribution
    struct ProtocolStat {
        std::string protocol;
        size_t count;
        double percentage;
    };
    std::vector<ProtocolStat> getProtocolDistribution(
        const std::string& job_id = "",  // Empty = all jobs
        std::chrono::hours timeframe = std::chrono::hours(24)) const;
    nlohmann::json getProtocolDistributionJson(const std::string& job_id,
                                               const std::string& timeframe) const;

    // VoLTE metrics trend
    struct VolteTrendPoint {
        std::string timestamp;
        size_t call_count;
        double avg_mos;
        double success_rate;
        double avg_setup_time_ms;
    };
    std::vector<VolteTrendPoint> getVolteTrend(
        std::chrono::hours duration = std::chrono::hours(24),
        std::chrono::minutes interval = std::chrono::minutes(60)) const;
    nlohmann::json getVolteTrendJson(const std::string& duration) const;

    // Job-specific stats
    nlohmann::json getJobStats(const std::string& job_id) const;

private:
    std::shared_ptr<JobManager> job_manager_;
    std::shared_ptr<DatabaseManager> db_manager_;
};

}  // namespace callflow
