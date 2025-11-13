#pragma once

#include "common/types.h"
#include <sqlite3.h>
#include <string>
#include <vector>
#include <optional>
#include <mutex>
#include <nlohmann/json.hpp>

namespace callflow {

/**
 * Event data for database storage
 */
struct Event {
    int64_t event_id;
    std::string session_id;
    int64_t timestamp;         // Microseconds since epoch
    std::string event_type;
    std::string protocol;
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    std::string message_type;
    nlohmann::json payload;
    std::string direction;

    nlohmann::json toJson() const;
};

/**
 * Session data for database storage
 */
struct Session {
    std::string session_id;
    std::string job_id;
    std::string session_type;  // VOLTE, GTP, DIAMETER, HTTP2, etc.
    std::string session_key;   // Call-ID, Session-ID, TEID, etc.
    int64_t start_time;
    int64_t end_time;
    int32_t duration_ms;
    int32_t packet_count;
    int64_t byte_count;
    std::vector<std::string> participant_ips;
    nlohmann::json metadata;

    nlohmann::json toJson() const;
};

/**
 * Metric data for analytics
 */
struct Metric {
    int64_t metric_id;
    std::string job_id;
    std::string session_id;
    std::string metric_type;
    double metric_value;
    int64_t timestamp;
    nlohmann::json metadata;
};

/**
 * Query filters for sessions
 */
struct SessionFilter {
    std::string job_id;
    std::string protocol_filter;
    std::string session_key_search;
    int64_t start_time_min = 0;
    int64_t start_time_max = 0;
    int page = 1;
    int limit = 20;
    std::string sort_by = "start_time";  // start_time, duration_ms, packet_count
    bool sort_desc = true;
};

/**
 * Database statistics
 */
struct DatabaseStats {
    size_t total_jobs;
    size_t total_sessions;
    size_t total_events;
    size_t total_metrics;
    int64_t db_size_bytes;
};

/**
 * Database manager for SQLite3 persistence
 * Thread-safe operations for job, session, and event storage
 */
class DatabaseManager {
public:
    /**
     * Constructor
     * @param db_path Path to SQLite database file
     * @throws std::runtime_error if database cannot be opened
     */
    explicit DatabaseManager(const std::string& db_path);

    /**
     * Destructor - closes database connection
     */
    ~DatabaseManager();

    // Disable copy and move
    DatabaseManager(const DatabaseManager&) = delete;
    DatabaseManager& operator=(const DatabaseManager&) = delete;

    // ===== Job Operations =====

    /**
     * Insert a new job
     * @param job Job information
     * @return true on success, false on failure
     */
    bool insertJob(const JobInfo& job);

    /**
     * Update an existing job
     * @param job_id Job ID to update
     * @param job Updated job information
     * @return true on success, false on failure
     */
    bool updateJob(const std::string& job_id, const JobInfo& job);

    /**
     * Get job by ID
     * @param job_id Job ID
     * @return Job information or nullopt if not found
     */
    std::optional<JobInfo> getJob(const std::string& job_id);

    /**
     * Get all jobs with optional status filter
     * @param status_filter Filter by status (empty = all)
     * @return Vector of jobs
     */
    std::vector<JobInfo> getAllJobs(const std::string& status_filter = "");

    /**
     * Delete a job and all associated data
     * @param job_id Job ID
     * @return true on success, false on failure
     */
    bool deleteJob(const std::string& job_id);

    /**
     * Delete old jobs based on retention policy
     * @param retention_days Number of days to retain
     * @return Number of jobs deleted
     */
    int deleteOldJobs(int retention_days = 7);

    // ===== Session Operations =====

    /**
     * Insert a new session
     * @param session Session data
     * @return true on success, false on failure
     */
    bool insertSession(const Session& session);

    /**
     * Update an existing session
     * @param session Session data
     * @return true on success, false on failure
     */
    bool updateSession(const Session& session);

    /**
     * Get session by ID
     * @param session_id Session ID
     * @return Session data or nullopt if not found
     */
    std::optional<Session> getSession(const std::string& session_id);

    /**
     * Get sessions by job with filtering and pagination
     * @param filter Query filters
     * @return Vector of sessions
     */
    std::vector<Session> getSessionsByFilter(const SessionFilter& filter);

    /**
     * Get session count for a job
     * @param job_id Job ID
     * @return Number of sessions
     */
    int getSessionCount(const std::string& job_id);

    // ===== Event Operations =====

    /**
     * Insert a new event
     * @param event Event data
     * @return true on success, false on failure
     */
    bool insertEvent(const Event& event);

    /**
     * Insert multiple events in a transaction
     * @param events Vector of events
     * @return true on success, false on failure
     */
    bool insertEvents(const std::vector<Event>& events);

    /**
     * Get all events for a session
     * @param session_id Session ID
     * @return Vector of events
     */
    std::vector<Event> getEventsBySession(const std::string& session_id);

    /**
     * Get event count for a session
     * @param session_id Session ID
     * @return Number of events
     */
    int getEventCount(const std::string& session_id);

    // ===== Metrics Operations =====

    /**
     * Insert a metric
     * @param metric Metric data
     * @return true on success, false on failure
     */
    bool insertMetric(const Metric& metric);

    /**
     * Get metrics for a job
     * @param job_id Job ID
     * @param metric_type Optional filter by metric type
     * @return Vector of metrics
     */
    std::vector<Metric> getMetrics(const std::string& job_id,
                                   const std::string& metric_type = "");

    // ===== Utility Operations =====

    /**
     * Get database statistics
     * @return Database stats
     */
    DatabaseStats getStats();

    /**
     * Execute VACUUM to reclaim space
     * @return true on success
     */
    bool vacuum();

    /**
     * Begin a transaction
     * @return true on success
     */
    bool beginTransaction();

    /**
     * Commit a transaction
     * @return true on success
     */
    bool commitTransaction();

    /**
     * Rollback a transaction
     * @return true on success
     */
    bool rollbackTransaction();

    /**
     * Check if database is healthy
     * @return true if database is accessible
     */
    bool isHealthy();

private:
    sqlite3* db_;
    std::string db_path_;
    std::mutex db_mutex_;
    bool in_transaction_;

    // Helper methods
    bool executeStatement(const std::string& sql);
    bool prepareStatement(const std::string& sql, sqlite3_stmt** stmt);
    bool initializeSchema();
    int64_t getLastInsertRowId();

    // Conversion helpers
    static int64_t timestampToUnix(const Timestamp& ts);
    static Timestamp unixToTimestamp(int64_t unix_time);
};

}  // namespace callflow
