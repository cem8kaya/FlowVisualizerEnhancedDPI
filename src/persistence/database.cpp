#include "persistence/database.h"
#include "common/logger.h"
#include <chrono>
#include <sstream>
#include <nlohmann/json.hpp>

namespace callflow {

// SQL schema for database tables
static const char* SCHEMA_SQL = R"(
CREATE TABLE IF NOT EXISTS jobs (
    job_id TEXT PRIMARY KEY,
    input_file TEXT NOT NULL,
    output_file TEXT,
    status TEXT NOT NULL,
    progress INTEGER DEFAULT 0,
    created_at INTEGER NOT NULL,
    started_at INTEGER,
    completed_at INTEGER,
    total_packets INTEGER DEFAULT 0,
    total_bytes INTEGER DEFAULT 0,
    session_count INTEGER DEFAULT 0,
    error_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
CREATE INDEX IF NOT EXISTS idx_jobs_created_at ON jobs(created_at);

CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL,
    session_type TEXT NOT NULL,
    session_key TEXT NOT NULL,
    start_time INTEGER NOT NULL,
    end_time INTEGER,
    duration_ms INTEGER,
    packet_count INTEGER DEFAULT 0,
    byte_count INTEGER DEFAULT 0,
    participant_ips TEXT,
    metadata TEXT,
    FOREIGN KEY (job_id) REFERENCES jobs(job_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_sessions_job_id ON sessions(job_id);
CREATE INDEX IF NOT EXISTS idx_sessions_type ON sessions(session_type);
CREATE INDEX IF NOT EXISTS idx_sessions_start_time ON sessions(start_time);
CREATE INDEX IF NOT EXISTS idx_sessions_key ON sessions(session_key);

CREATE TABLE IF NOT EXISTS events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    protocol TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    message_type TEXT,
    payload TEXT,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_events_session_id ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
)";

// ============================================================================
// Constructor / Destructor
// ============================================================================

DatabaseManager::DatabaseManager(const DatabaseConfig& config)
    : config_(config), db_(nullptr) {
}

DatabaseManager::~DatabaseManager() {
    close();
}

// ============================================================================
// Initialization
// ============================================================================

bool DatabaseManager::initialize() {
    std::lock_guard<std::mutex> lock(db_mutex_);

    if (!config_.enabled) {
        LOG_INFO("Database persistence disabled in configuration");
        return true;
    }

    // Open database
    int rc = sqlite3_open(config_.path.c_str(), &db_);
    if (rc != SQLITE_OK) {
        LOG_ERROR("Failed to open database {}: {}", config_.path, sqlite3_errmsg(db_));
        return false;
    }

    LOG_INFO("Opened database: {}", config_.path);

    // Set busy timeout
    sqlite3_busy_timeout(db_, config_.busy_timeout_ms);

    // Enable foreign keys
    execute("PRAGMA foreign_keys = ON");

    // Set journal mode to WAL for better concurrency
    execute("PRAGMA journal_mode = WAL");

    // Auto vacuum if enabled
    if (config_.auto_vacuum) {
        execute("PRAGMA auto_vacuum = FULL");
    }

    // Create tables
    char* err_msg = nullptr;
    rc = sqlite3_exec(db_, SCHEMA_SQL, nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        LOG_ERROR("Failed to create tables: {}", err_msg);
        sqlite3_free(err_msg);
        return false;
    }

    LOG_INFO("Database initialized successfully");
    return true;
}

void DatabaseManager::close() {
    std::lock_guard<std::mutex> lock(db_mutex_);

    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
        LOG_INFO("Database closed");
    }
}

// ============================================================================
// Job Operations
// ============================================================================

bool DatabaseManager::insertJob(const JobInfo& job) {
    std::lock_guard<std::mutex> lock(db_mutex_);

    if (!db_) return false;

    const char* sql = R"(
        INSERT INTO jobs (
            job_id, input_file, output_file, status, progress,
            created_at, started_at, completed_at,
            total_packets, total_bytes, session_count, error_message
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    )";

    sqlite3_stmt* stmt;
    if (!prepareStatement(sql, &stmt)) {
        return false;
    }

    sqlite3_bind_text(stmt, 1, job.job_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, job.input_filename.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, job.output_filename.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, jobStatusToString(job.status).c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 5, job.progress);
    sqlite3_bind_int64(stmt, 6, timestampToUnix(job.created_at));
    sqlite3_bind_int64(stmt, 7, timestampToUnix(job.started_at));
    sqlite3_bind_int64(stmt, 8, timestampToUnix(job.completed_at));
    sqlite3_bind_int64(stmt, 9, job.total_packets);
    sqlite3_bind_int64(stmt, 10, job.total_bytes);
    sqlite3_bind_int(stmt, 11, job.session_ids.size());
    sqlite3_bind_text(stmt, 12, job.error_message.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    finalizeStatement(stmt);

    if (rc != SQLITE_DONE) {
        LOG_ERROR("Failed to insert job: {}", sqlite3_errmsg(db_));
        return false;
    }

    LOG_DEBUG("Inserted job: {}", job.job_id);
    return true;
}

bool DatabaseManager::updateJob(const std::string& job_id, const JobInfo& job) {
    std::lock_guard<std::mutex> lock(db_mutex_);

    if (!db_) return false;

    const char* sql = R"(
        UPDATE jobs SET
            status = ?, progress = ?, started_at = ?, completed_at = ?,
            total_packets = ?, total_bytes = ?, session_count = ?, error_message = ?
        WHERE job_id = ?
    )";

    sqlite3_stmt* stmt;
    if (!prepareStatement(sql, &stmt)) {
        return false;
    }

    sqlite3_bind_text(stmt, 1, jobStatusToString(job.status).c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, job.progress);
    sqlite3_bind_int64(stmt, 3, timestampToUnix(job.started_at));
    sqlite3_bind_int64(stmt, 4, timestampToUnix(job.completed_at));
    sqlite3_bind_int64(stmt, 5, job.total_packets);
    sqlite3_bind_int64(stmt, 6, job.total_bytes);
    sqlite3_bind_int(stmt, 7, job.session_ids.size());
    sqlite3_bind_text(stmt, 8, job.error_message.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 9, job_id.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    finalizeStatement(stmt);

    if (rc != SQLITE_DONE) {
        LOG_ERROR("Failed to update job: {}", sqlite3_errmsg(db_));
        return false;
    }

    LOG_DEBUG("Updated job: {}", job_id);
    return true;
}

std::optional<JobInfo> DatabaseManager::getJob(const std::string& job_id) {
    std::lock_guard<std::mutex> lock(db_mutex_);

    if (!db_) return std::nullopt;

    const char* sql = R"(
        SELECT job_id, input_file, output_file, status, progress,
               created_at, started_at, completed_at,
               total_packets, total_bytes, session_count, error_message
        FROM jobs WHERE job_id = ?
    )";

    sqlite3_stmt* stmt;
    if (!prepareStatement(sql, &stmt)) {
        return std::nullopt;
    }

    sqlite3_bind_text(stmt, 1, job_id.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        finalizeStatement(stmt);
        return std::nullopt;
    }

    JobInfo job;
    job.job_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
    job.input_filename = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
    job.output_filename = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
    job.status = stringToJobStatus(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3)));
    job.progress = sqlite3_column_int(stmt, 4);
    job.created_at = unixToTimestamp(sqlite3_column_int64(stmt, 5));
    job.started_at = unixToTimestamp(sqlite3_column_int64(stmt, 6));
    job.completed_at = unixToTimestamp(sqlite3_column_int64(stmt, 7));
    job.total_packets = sqlite3_column_int64(stmt, 8);
    job.total_bytes = sqlite3_column_int64(stmt, 9);
    const char* error_msg = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 11));
    if (error_msg) {
        job.error_message = error_msg;
    }

    finalizeStatement(stmt);
    return job;
}

std::vector<JobInfo> DatabaseManager::getAllJobs(const std::string& status_filter) {
    std::lock_guard<std::mutex> lock(db_mutex_);

    std::vector<JobInfo> jobs;
    if (!db_) return jobs;

    std::string sql = R"(
        SELECT job_id, input_file, output_file, status, progress,
               created_at, started_at, completed_at,
               total_packets, total_bytes, session_count, error_message
        FROM jobs
    )";

    if (!status_filter.empty()) {
        sql += " WHERE status = ?";
    }
    sql += " ORDER BY created_at DESC";

    sqlite3_stmt* stmt;
    if (!prepareStatement(sql, &stmt)) {
        return jobs;
    }

    if (!status_filter.empty()) {
        sqlite3_bind_text(stmt, 1, status_filter.c_str(), -1, SQLITE_TRANSIENT);
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        JobInfo job;
        job.job_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        job.input_filename = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        job.output_filename = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        job.status = stringToJobStatus(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3)));
        job.progress = sqlite3_column_int(stmt, 4);
        job.created_at = unixToTimestamp(sqlite3_column_int64(stmt, 5));
        job.started_at = unixToTimestamp(sqlite3_column_int64(stmt, 6));
        job.completed_at = unixToTimestamp(sqlite3_column_int64(stmt, 7));
        job.total_packets = sqlite3_column_int64(stmt, 8);
        job.total_bytes = sqlite3_column_int64(stmt, 9);
        const char* error_msg = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 11));
        if (error_msg) {
            job.error_message = error_msg;
        }
        jobs.push_back(job);
    }

    finalizeStatement(stmt);
    return jobs;
}

bool DatabaseManager::deleteJob(const std::string& job_id) {
    std::lock_guard<std::mutex> lock(db_mutex_);

    if (!db_) return false;

    const char* sql = "DELETE FROM jobs WHERE job_id = ?";

    sqlite3_stmt* stmt;
    if (!prepareStatement(sql, &stmt)) {
        return false;
    }

    sqlite3_bind_text(stmt, 1, job_id.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    finalizeStatement(stmt);

    if (rc != SQLITE_DONE) {
        LOG_ERROR("Failed to delete job: {}", sqlite3_errmsg(db_));
        return false;
    }

    LOG_INFO("Deleted job: {}", job_id);
    return true;
}

int DatabaseManager::deleteOldJobs(int retention_days) {
    std::lock_guard<std::mutex> lock(db_mutex_);

    if (!db_) return 0;

    auto now = std::chrono::system_clock::now();
    auto cutoff = now - std::chrono::hours(24 * retention_days);
    int64_t cutoff_unix = timestampToUnix(cutoff);

    const char* sql = "DELETE FROM jobs WHERE created_at < ?";

    sqlite3_stmt* stmt;
    if (!prepareStatement(sql, &stmt)) {
        return 0;
    }

    sqlite3_bind_int64(stmt, 1, cutoff_unix);

    int rc = sqlite3_step(stmt);
    int deleted = sqlite3_changes(db_);
    finalizeStatement(stmt);

    if (rc != SQLITE_DONE) {
        LOG_ERROR("Failed to delete old jobs: {}", sqlite3_errmsg(db_));
        return 0;
    }

    LOG_INFO("Deleted {} old jobs (retention {} days)", deleted, retention_days);
    return deleted;
}

// ============================================================================
// Session Operations
// ============================================================================

bool DatabaseManager::insertSession(const SessionRecord& session) {
    std::lock_guard<std::mutex> lock(db_mutex_);

    if (!db_) return false;

    const char* sql = R"(
        INSERT INTO sessions (
            session_id, job_id, session_type, session_key,
            start_time, end_time, duration_ms,
            packet_count, byte_count, participant_ips, metadata
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    )";

    sqlite3_stmt* stmt;
    if (!prepareStatement(sql, &stmt)) {
        return false;
    }

    sqlite3_bind_text(stmt, 1, session.session_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, session.job_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, session.session_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, session.session_key.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 5, session.start_time);
    sqlite3_bind_int64(stmt, 6, session.end_time);
    sqlite3_bind_int64(stmt, 7, session.duration_ms);
    sqlite3_bind_int64(stmt, 8, session.packet_count);
    sqlite3_bind_int64(stmt, 9, session.byte_count);
    sqlite3_bind_text(stmt, 10, session.participant_ips.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 11, session.metadata.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    finalizeStatement(stmt);

    if (rc != SQLITE_DONE) {
        LOG_ERROR("Failed to insert session: {}", sqlite3_errmsg(db_));
        return false;
    }

    LOG_TRACE("Inserted session: {}", session.session_id);
    return true;
}

bool DatabaseManager::updateSession(const std::string& session_id, const SessionRecord& session) {
    std::lock_guard<std::mutex> lock(db_mutex_);

    if (!db_) return false;

    const char* sql = R"(
        UPDATE sessions SET
            end_time = ?, duration_ms = ?, packet_count = ?, byte_count = ?, metadata = ?
        WHERE session_id = ?
    )";

    sqlite3_stmt* stmt;
    if (!prepareStatement(sql, &stmt)) {
        return false;
    }

    sqlite3_bind_int64(stmt, 1, session.end_time);
    sqlite3_bind_int64(stmt, 2, session.duration_ms);
    sqlite3_bind_int64(stmt, 3, session.packet_count);
    sqlite3_bind_int64(stmt, 4, session.byte_count);
    sqlite3_bind_text(stmt, 5, session.metadata.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, session_id.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    finalizeStatement(stmt);

    if (rc != SQLITE_DONE) {
        LOG_ERROR("Failed to update session: {}", sqlite3_errmsg(db_));
        return false;
    }

    return true;
}

std::optional<SessionRecord> DatabaseManager::getSession(const std::string& session_id) {
    std::lock_guard<std::mutex> lock(db_mutex_);

    if (!db_) return std::nullopt;

    const char* sql = R"(
        SELECT session_id, job_id, session_type, session_key,
               start_time, end_time, duration_ms,
               packet_count, byte_count, participant_ips, metadata
        FROM sessions WHERE session_id = ?
    )";

    sqlite3_stmt* stmt;
    if (!prepareStatement(sql, &stmt)) {
        return std::nullopt;
    }

    sqlite3_bind_text(stmt, 1, session_id.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        finalizeStatement(stmt);
        return std::nullopt;
    }

    SessionRecord session;
    session.session_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
    session.job_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
    session.session_type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
    session.session_key = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
    session.start_time = sqlite3_column_int64(stmt, 4);
    session.end_time = sqlite3_column_int64(stmt, 5);
    session.duration_ms = sqlite3_column_int64(stmt, 6);
    session.packet_count = sqlite3_column_int64(stmt, 7);
    session.byte_count = sqlite3_column_int64(stmt, 8);
    const char* ips = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 9));
    const char* meta = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 10));
    if (ips) session.participant_ips = ips;
    if (meta) session.metadata = meta;

    finalizeStatement(stmt);
    return session;
}

std::vector<SessionRecord> DatabaseManager::getSessions(const SessionFilter& filter) {
    std::lock_guard<std::mutex> lock(db_mutex_);

    std::vector<SessionRecord> sessions;
    if (!db_) return sessions;

    std::vector<std::string> params;
    std::string where_clause = buildSessionWhereClause(filter, params);

    std::ostringstream sql;
    sql << "SELECT session_id, job_id, session_type, session_key, "
        << "start_time, end_time, duration_ms, packet_count, byte_count, "
        << "participant_ips, metadata FROM sessions";

    if (!where_clause.empty()) {
        sql << " WHERE " << where_clause;
    }

    sql << " ORDER BY " << filter.order_by;
    if (filter.descending) {
        sql << " DESC";
    }

    sql << " LIMIT ? OFFSET ?";

    sqlite3_stmt* stmt;
    if (!prepareStatement(sql.str(), &stmt)) {
        return sessions;
    }

    // Bind parameters (simplified - in production use proper binding)
    int offset = (filter.page - 1) * filter.limit;
    sqlite3_bind_int(stmt, 1, filter.limit);
    sqlite3_bind_int(stmt, 2, offset);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        SessionRecord session;
        session.session_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        session.job_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        session.session_type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        session.session_key = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        session.start_time = sqlite3_column_int64(stmt, 4);
        session.end_time = sqlite3_column_int64(stmt, 5);
        session.duration_ms = sqlite3_column_int64(stmt, 6);
        session.packet_count = sqlite3_column_int64(stmt, 7);
        session.byte_count = sqlite3_column_int64(stmt, 8);
        const char* ips = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 9));
        const char* meta = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 10));
        if (ips) session.participant_ips = ips;
        if (meta) session.metadata = meta;
        sessions.push_back(session);
    }

    finalizeStatement(stmt);
    return sessions;
}

int DatabaseManager::getSessionCount(const SessionFilter& filter) {
    std::lock_guard<std::mutex> lock(db_mutex_);

    if (!db_) return 0;

    std::vector<std::string> params;
    std::string where_clause = buildSessionWhereClause(filter, params);

    std::ostringstream sql;
    sql << "SELECT COUNT(*) FROM sessions";
    if (!where_clause.empty()) {
        sql << " WHERE " << where_clause;
    }

    sqlite3_stmt* stmt;
    if (!prepareStatement(sql.str(), &stmt)) {
        return 0;
    }

    int count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
    }

    finalizeStatement(stmt);
    return count;
}

std::vector<SessionRecord> DatabaseManager::getSessionsByJob(
    const std::string& job_id,
    int page,
    int limit,
    const std::string& protocol_filter) {

    SessionFilter filter;
    filter.job_id = job_id;
    if (!protocol_filter.empty()) {
        filter.session_type = protocol_filter;
    }
    filter.page = page;
    filter.limit = limit;

    return getSessions(filter);
}

// ============================================================================
// Event Operations
// ============================================================================

bool DatabaseManager::insertEvent(EventRecord& event) {
    std::lock_guard<std::mutex> lock(db_mutex_);

    if (!db_) return false;

    const char* sql = R"(
        INSERT INTO events (
            session_id, timestamp, event_type, protocol,
            src_ip, dst_ip, src_port, dst_port, message_type, payload
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    )";

    sqlite3_stmt* stmt;
    if (!prepareStatement(sql, &stmt)) {
        return false;
    }

    sqlite3_bind_text(stmt, 1, event.session_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, event.timestamp);
    sqlite3_bind_text(stmt, 3, event.event_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, event.protocol.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, event.src_ip.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, event.dst_ip.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 7, event.src_port);
    sqlite3_bind_int(stmt, 8, event.dst_port);
    sqlite3_bind_text(stmt, 9, event.message_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 10, event.payload.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_DONE) {
        event.event_id = sqlite3_last_insert_rowid(db_);
    }

    finalizeStatement(stmt);

    if (rc != SQLITE_DONE) {
        LOG_ERROR("Failed to insert event: {}", sqlite3_errmsg(db_));
        return false;
    }

    return true;
}

std::vector<EventRecord> DatabaseManager::getEventsBySession(const std::string& session_id) {
    std::lock_guard<std::mutex> lock(db_mutex_);

    std::vector<EventRecord> events;
    if (!db_) return events;

    const char* sql = R"(
        SELECT event_id, session_id, timestamp, event_type, protocol,
               src_ip, dst_ip, src_port, dst_port, message_type, payload
        FROM events WHERE session_id = ? ORDER BY timestamp ASC
    )";

    sqlite3_stmt* stmt;
    if (!prepareStatement(sql, &stmt)) {
        return events;
    }

    sqlite3_bind_text(stmt, 1, session_id.c_str(), -1, SQLITE_TRANSIENT);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        EventRecord event;
        event.event_id = sqlite3_column_int64(stmt, 0);
        event.session_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        event.timestamp = sqlite3_column_int64(stmt, 2);
        event.event_type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        event.protocol = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        event.src_ip = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        event.dst_ip = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
        event.src_port = sqlite3_column_int(stmt, 7);
        event.dst_port = sqlite3_column_int(stmt, 8);
        const char* msg_type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 9));
        const char* payload = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 10));
        if (msg_type) event.message_type = msg_type;
        if (payload) event.payload = payload;
        events.push_back(event);
    }

    finalizeStatement(stmt);
    return events;
}

int DatabaseManager::getEventCount(const std::string& session_id) {
    std::lock_guard<std::mutex> lock(db_mutex_);

    if (!db_) return 0;

    const char* sql = "SELECT COUNT(*) FROM events WHERE session_id = ?";

    sqlite3_stmt* stmt;
    if (!prepareStatement(sql, &stmt)) {
        return 0;
    }

    sqlite3_bind_text(stmt, 1, session_id.c_str(), -1, SQLITE_TRANSIENT);

    int count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
    }

    finalizeStatement(stmt);
    return count;
}

// ============================================================================
// Utility Operations
// ============================================================================

bool DatabaseManager::execute(const std::string& sql) {
    if (!db_) return false;

    char* err_msg = nullptr;
    int rc = sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        LOG_ERROR("SQL error: {}", err_msg);
        sqlite3_free(err_msg);
        return false;
    }

    return true;
}

nlohmann::json DatabaseManager::getStatistics() {
    nlohmann::json stats;

    if (!db_) {
        stats["error"] = "Database not open";
        return stats;
    }

    std::lock_guard<std::mutex> lock(db_mutex_);

    // Get job counts
    sqlite3_stmt* stmt;
    if (prepareStatement("SELECT COUNT(*) FROM jobs", &stmt)) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            stats["total_jobs"] = sqlite3_column_int(stmt, 0);
        }
        finalizeStatement(stmt);
    }

    // Get session counts
    if (prepareStatement("SELECT COUNT(*) FROM sessions", &stmt)) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            stats["total_sessions"] = sqlite3_column_int(stmt, 0);
        }
        finalizeStatement(stmt);
    }

    // Get event counts
    if (prepareStatement("SELECT COUNT(*) FROM events", &stmt)) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            stats["total_events"] = sqlite3_column_int(stmt, 0);
        }
        finalizeStatement(stmt);
    }

    // Database file size
    stats["database_path"] = config_.path;

    return stats;
}

bool DatabaseManager::vacuum() {
    std::lock_guard<std::mutex> lock(db_mutex_);

    if (!db_) return false;

    LOG_INFO("Running VACUUM on database...");
    return execute("VACUUM");
}

// ============================================================================
// Private Helper Methods
// ============================================================================

bool DatabaseManager::prepareStatement(const std::string& sql, sqlite3_stmt** stmt) {
    int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, stmt, nullptr);
    if (rc != SQLITE_OK) {
        LOG_ERROR("Failed to prepare statement: {}", sqlite3_errmsg(db_));
        return false;
    }
    return true;
}

void DatabaseManager::finalizeStatement(sqlite3_stmt* stmt) {
    if (stmt) {
        sqlite3_finalize(stmt);
    }
}

int64_t DatabaseManager::timestampToUnix(const Timestamp& ts) {
    auto duration = ts.time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
}

Timestamp DatabaseManager::unixToTimestamp(int64_t unix_ms) {
    return Timestamp(std::chrono::milliseconds(unix_ms));
}

std::string DatabaseManager::buildSessionWhereClause(
    const SessionFilter& filter,
    std::vector<std::string>& params) {

    std::vector<std::string> conditions;

    if (filter.job_id) {
        conditions.push_back("job_id = '" + *filter.job_id + "'");
    }

    if (filter.session_type) {
        conditions.push_back("session_type = '" + *filter.session_type + "'");
    }

    if (filter.session_key) {
        conditions.push_back("session_key = '" + *filter.session_key + "'");
    }

    if (filter.start_time_min) {
        conditions.push_back("start_time >= " + std::to_string(*filter.start_time_min));
    }

    if (filter.start_time_max) {
        conditions.push_back("start_time <= " + std::to_string(*filter.start_time_max));
    }

    if (conditions.empty()) {
        return "";
    }

    std::ostringstream oss;
    for (size_t i = 0; i < conditions.size(); ++i) {
        if (i > 0) oss << " AND ";
        oss << conditions[i];
    }

    return oss.str();
}

}  // namespace callflow
