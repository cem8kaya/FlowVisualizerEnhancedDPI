#pragma once

#include "common/types.h"
#include <string>
#include <vector>
#include <optional>
#include <mutex>
#include <sqlite3.h>

namespace callflow {

/**
 * Database configuration
 */
struct DatabaseConfig {
    bool enabled = true;
    std::string path = "./callflowd.db";
    int retention_days = 7;
    bool auto_vacuum = true;
    int busy_timeout_ms = 5000;
};

/**
 * Session record for database storage
 */
struct SessionRecord {
    SessionId session_id;
    JobId job_id;
    std::string session_type;      // SIP, DIAMETER, GTP, HTTP2
    std::string session_key;       // Call-ID, Session-ID, TEID, etc.
    int64_t start_time;            // Unix timestamp (milliseconds)
    int64_t end_time = 0;          // Unix timestamp (milliseconds)
    int64_t duration_ms = 0;
    uint64_t packet_count = 0;
    uint64_t byte_count = 0;
    std::string participant_ips;  // JSON array string
    std::string metadata;          // JSON object string
};

/**
 * Event record for database storage
 */
struct EventRecord {
    int64_t event_id = 0;          // Auto-increment
    SessionId session_id;
    int64_t timestamp;             // Unix timestamp (milliseconds)
    std::string event_type;
    std::string protocol;
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    std::string message_type;
    std::string payload;           // JSON object string
};

/**
 * Query filters for sessions
 */
struct SessionFilter {
    std::optional<std::string> job_id;
    std::optional<std::string> session_type;
    std::optional<std::string> session_key;
    std::optional<int64_t> start_time_min;
    std::optional<int64_t> start_time_max;
    int page = 1;
    int limit = 20;
    std::string order_by = "start_time";  // start_time, duration_ms, packet_count
    bool descending = true;
};

/**
 * Database manager for persistent storage
 */
class DatabaseManager {
public:
    /**
     * Constructor
     * @param config Database configuration
     */
    explicit DatabaseManager(const DatabaseConfig& config);

    /**
     * Destructor - closes database connection
     */
    ~DatabaseManager();

    /**
     * Initialize database (create tables if not exist)
     * @return true on success
     */
    bool initialize();

    /**
     * Close database connection
     */
    void close();

    // ========================================================================
    // Job Operations
    // ========================================================================

    /**
     * Insert new job record
     * @param job Job information
     * @return true on success
     */
    bool insertJob(const JobInfo& job);

    /**
     * Update existing job record
     * @param job_id Job ID
     * @param job Updated job information
     * @return true on success
     */
    bool updateJob(const std::string& job_id, const JobInfo& job);

    /**
     * Get job by ID
     * @param job_id Job ID
     * @return Job info or nullopt if not found
     */
    std::optional<JobInfo> getJob(const std::string& job_id);

    /**
     * Get all jobs with optional status filter
     * @param status_filter Filter by status (empty for all)
     * @return List of jobs
     */
    std::vector<JobInfo> getAllJobs(const std::string& status_filter = "");

    /**
     * Delete job and associated data
     * @param job_id Job ID
     * @return true on success
     */
    bool deleteJob(const std::string& job_id);

    /**
     * Delete old jobs beyond retention period
     * @param retention_days Number of days to retain
     * @return Number of jobs deleted
     */
    int deleteOldJobs(int retention_days);

    // ========================================================================
    // Session Operations
    // ========================================================================

    /**
     * Insert session record
     * @param session Session data
     * @return true on success
     */
    bool insertSession(const SessionRecord& session);

    /**
     * Update session record
     * @param session_id Session ID
     * @param session Updated session data
     * @return true on success
     */
    bool updateSession(const std::string& session_id, const SessionRecord& session);

    /**
     * Get session by ID
     * @param session_id Session ID
     * @return Session record or nullopt if not found
     */
    std::optional<SessionRecord> getSession(const std::string& session_id);

    /**
     * Get sessions with filters and pagination
     * @param filter Query filters
     * @return List of sessions
     */
    std::vector<SessionRecord> getSessions(const SessionFilter& filter);

    /**
     * Get total session count matching filter
     * @param filter Query filters (page/limit ignored)
     * @return Total count
     */
    int getSessionCount(const SessionFilter& filter);

    /**
     * Get sessions by job ID (paginated)
     * @param job_id Job ID
     * @param page Page number (1-based)
     * @param limit Records per page
     * @param protocol_filter Protocol type filter (empty for all)
     * @return List of sessions
     */
    std::vector<SessionRecord> getSessionsByJob(
        const std::string& job_id,
        int page = 1,
        int limit = 20,
        const std::string& protocol_filter = ""
    );

    // ========================================================================
    // Event Operations
    // ========================================================================

    /**
     * Insert event record
     * @param event Event data
     * @return true on success, event_id set on insert
     */
    bool insertEvent(EventRecord& event);

    /**
     * Get events for a session
     * @param session_id Session ID
     * @return List of events
     */
    std::vector<EventRecord> getEventsBySession(const std::string& session_id);

    /**
     * Get events count for a session
     * @param session_id Session ID
     * @return Event count
     */
    int getEventCount(const std::string& session_id);

    // ========================================================================
    // Utility Operations
    // ========================================================================

    /**
     * Execute raw SQL query (for maintenance)
     * @param sql SQL statement
     * @return true on success
     */
    bool execute(const std::string& sql);

    /**
     * Get database statistics
     * @return JSON object with stats
     */
    nlohmann::json getStatistics();

    /**
     * Vacuum database (reclaim space)
     * @return true on success
     */
    bool vacuum();

    /**
     * Check if database is open
     */
    bool isOpen() const { return db_ != nullptr; }

    /**
     * Get raw SQLite3 handle (for internal use only)
     * @return SQLite3 database handle
     */
    void* getHandle() { return db_; }

private:
    DatabaseConfig config_;
    sqlite3* db_;
    std::mutex db_mutex_;

    /**
     * Prepare SQL statement
     * @param sql SQL query
     * @param stmt Statement handle (output)
     * @return true on success
     */
    bool prepareStatement(const std::string& sql, sqlite3_stmt** stmt);

    /**
     * Finalize statement
     */
    void finalizeStatement(sqlite3_stmt* stmt);

    /**
     * Convert timestamp to Unix milliseconds
     */
    int64_t timestampToUnix(const Timestamp& ts);

    /**
     * Convert Unix milliseconds to timestamp
     */
    Timestamp unixToTimestamp(int64_t unix_ms);

    /**
     * Build WHERE clause from session filter
     */
    std::string buildSessionWhereClause(const SessionFilter& filter,
                                        std::vector<std::string>& params);
};

}  // namespace callflow
