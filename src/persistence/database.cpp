#include "persistence/database.h"
#include "common/logger.h"
#include <fstream>
#include <sstream>
#include <chrono>
#include <cstring>

namespace callflow {

// ============================================================================
// Helper Functions
// ============================================================================

int64_t DatabaseManager::timestampToUnix(const Timestamp& ts) {
    return std::chrono::duration_cast<std::chrono::microseconds>(
        ts.time_since_epoch()).count();
}

Timestamp DatabaseManager::unixToTimestamp(int64_t unix_time) {
    return Timestamp(std::chrono::microseconds(unix_time));
}

// ============================================================================
// Event/Session JSON Conversion
// ============================================================================

nlohmann::json Event::toJson() const {
    nlohmann::json j;
    j["event_id"] = event_id;
    j["session_id"] = session_id;
    j["timestamp"] = timestamp;
    j["event_type"] = event_type;
    j["protocol"] = protocol;
    j["src_ip"] = src_ip;
    j["dst_ip"] = dst_ip;
    j["src_port"] = src_port;
    j["dst_port"] = dst_port;
    j["message_type"] = message_type;
    j["payload"] = payload;
    j["direction"] = direction;
    return j;
}

nlohmann::json Session::toJson() const {
    nlohmann::json j;
    j["session_id"] = session_id;
    j["job_id"] = job_id;
    j["session_type"] = session_type;
    j["session_key"] = session_key;
    j["start_time"] = start_time;
    j["end_time"] = end_time;
    j["duration_ms"] = duration_ms;
    j["packet_count"] = packet_count;
    j["byte_count"] = byte_count;
    j["participant_ips"] = participant_ips;
    j["metadata"] = metadata;
    return j;
}

// ============================================================================
// DatabaseManager Implementation
// ============================================================================

DatabaseManager::DatabaseManager(const std::string& db_path)
    : db_(nullptr), db_path_(db_path), in_transaction_(false) {

    int rc = sqlite3_open(db_path.c_str(), &db_);
    if (rc != SQLITE_OK) {
        std::string error = sqlite3_errmsg(db_);
        LOG_ERROR("Failed to open database at " << db_path << ": " << error);
        throw std::runtime_error("Failed to open database: " + error);
    }

    LOG_INFO("Database opened: " << db_path);

    // Enable foreign keys
    executeStatement("PRAGMA foreign_keys = ON");

    // Set journal mode to WAL for better concurrency
    executeStatement("PRAGMA journal_mode = WAL");

    // Initialize schema
    if (!initializeSchema()) {
        LOG_ERROR("Failed to initialize database schema");
        sqlite3_close(db_);
        throw std::runtime_error("Failed to initialize database schema");
    }
}

DatabaseManager::~DatabaseManager() {
    if (db_) {
        sqlite3_close(db_);
        LOG_INFO("Database closed: " << db_path_);
    }
}

bool DatabaseManager::initializeSchema() {
    std::lock_guard<std::mutex> lock(db_mutex_);

    // Read schema from file if it exists, otherwise use embedded version
    std::ifstream schema_file("schema.sql");
    std::string schema;

    if (schema_file.is_open()) {
        std::stringstream buffer;
        buffer << schema_file.rdbuf();
        schema = buffer.str();
        LOG_INFO("Loaded schema from schema.sql");
    } else {
        // Embedded minimal schema (fallback)
        schema = R"(
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
                error_message TEXT,
                metadata TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);

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
                direction TEXT,
                FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_events_session_id ON events(session_id);
        )";
        LOG_WARN("schema.sql not found, using embedded schema");
    }

    // Execute schema (split by semicolon for multiple statements)
    size_t pos = 0;
    while (pos < schema.length()) {
        size_t next = schema.find(';', pos);
        if (next == std::string::npos) break;

        std::string statement = schema.substr(pos, next - pos + 1);

        // Skip empty statements and comments
        if (statement.find_first_not_of(" \t\n\r;") != std::string::npos &&
            statement.find("--") != 0) {

            char* err_msg = nullptr;
            int rc = sqlite3_exec(db_, statement.c_str(), nullptr, nullptr, &err_msg);
            if (rc != SQLITE_OK) {
                std::string error = err_msg ? err_msg : "Unknown error";
                sqlite3_free(err_msg);
                LOG_ERROR("Schema execution error: " << error);
                return false;
            }
        }
        pos = next + 1;
    }

    LOG_INFO("Database schema initialized successfully");
    return true;
}

bool DatabaseManager::executeStatement(const std::string& sql) {
    char* err_msg = nullptr;
    int rc = sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        std::string error = err_msg ? err_msg : "Unknown error";
        sqlite3_free(err_msg);
        LOG_ERROR("SQL execution error: " << error << " (SQL: " << sql << ")");
        return false;
    }
    return true;
}

bool DatabaseManager::prepareStatement(const std::string& sql, sqlite3_stmt** stmt) {
    int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, stmt, nullptr);
    if (rc != SQLITE_OK) {
        LOG_ERROR("Failed to prepare statement: " << sqlite3_errmsg(db_));
        return false;
    }
    return true;
}

int64_t DatabaseManager::getLastInsertRowId() {
    return sqlite3_last_insert_rowid(db_);
}

// ============================================================================
// Job Operations
// ============================================================================

bool DatabaseManager::insertJob(const JobInfo& job) {
    std::lock_guard<std::mutex> lock(db_mutex_);

    const char* sql = R"(
        INSERT INTO jobs (job_id, input_file, output_file, status, progress,
                         created_at, started_at, completed_at, total_packets,
                         total_bytes, session_count, error_message)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    )";

    sqlite3_stmt* stmt = nullptr;
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
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        LOG_ERROR("Failed to insert job: " << sqlite3_errmsg(db_));
        return false;
    }

    LOG_INFO("Inserted job: " << job.job_id);
    return true;
}

bool DatabaseManager::updateJob(const std::string& job_id, const JobInfo& job) {
    std::lock_guard<std::mutex> lock(db_mutex_);

    const char* sql = R"(
        UPDATE jobs SET
            output_file = ?, status = ?, progress = ?,
            started_at = ?, completed_at = ?,
            total_packets = ?, total_bytes = ?, session_count = ?,
            error_message = ?
        WHERE job_id = ?
    )";

    sqlite3_stmt* stmt = nullptr;
    if (!prepareStatement(sql, &stmt)) {
        return false;
    }

    sqlite3_bind_text(stmt, 1, job.output_filename.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, jobStatusToString(job.status).c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, job.progress);
    sqlite3_bind_int64(stmt, 4, timestampToUnix(job.started_at));
    sqlite3_bind_int64(stmt, 5, timestampToUnix(job.completed_at));
    sqlite3_bind_int64(stmt, 6, job.total_packets);
    sqlite3_bind_int64(stmt, 7, job.total_bytes);
    sqlite3_bind_int(stmt, 8, job.session_ids.size());
    sqlite3_bind_text(stmt, 9, job.error_message.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 10, job_id.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        LOG_ERROR("Failed to update job: " << sqlite3_errmsg(db_));
        return false;
    }

    return true;
}

std::optional<JobInfo> DatabaseManager::getJob(const std::string& job_id) {
    std::lock_guard<std::mutex> lock(db_mutex_);

    const char* sql = R"(
        SELECT job_id, input_file, output_file, status, progress,
               created_at, started_at, completed_at, total_packets,
               total_bytes, session_count, error_message
        FROM jobs WHERE job_id = ?
    )";

    sqlite3_stmt* stmt = nullptr;
    if (!prepareStatement(sql, &stmt)) {
        return std::nullopt;
    }

    sqlite3_bind_text(stmt, 1, job_id.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return std::nullopt;
    }

    JobInfo job;
    job.job_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
    job.input_filename = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));

    if (sqlite3_column_type(stmt, 2) != SQLITE_NULL) {
        job.output_filename = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
    }

    std::string status_str = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
    job.status = stringToJobStatus(status_str);
    job.progress = sqlite3_column_int(stmt, 4);
    job.created_at = unixToTimestamp(sqlite3_column_int64(stmt, 5));
    job.started_at = unixToTimestamp(sqlite3_column_int64(stmt, 6));
    job.completed_at = unixToTimestamp(sqlite3_column_int64(stmt, 7));
    job.total_packets = sqlite3_column_int64(stmt, 8);
    job.total_bytes = sqlite3_column_int64(stmt, 9);

    if (sqlite3_column_type(stmt, 11) != SQLITE_NULL) {
        job.error_message = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 11));
    }

    sqlite3_finalize(stmt);
    return job;
}

std::vector<JobInfo> DatabaseManager::getAllJobs(const std::string& status_filter) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    std::vector<JobInfo> jobs;

    std::string sql = R"(
        SELECT job_id, input_file, output_file, status, progress,
               created_at, started_at, completed_at, total_packets,
               total_bytes, session_count, error_message
        FROM jobs
    )";

    if (!status_filter.empty()) {
        sql += " WHERE status = ?";
    }
    sql += " ORDER BY created_at DESC";

    sqlite3_stmt* stmt = nullptr;
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

        if (sqlite3_column_type(stmt, 2) != SQLITE_NULL) {
            job.output_filename = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        }

        std::string status_str = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        job.status = stringToJobStatus(status_str);
        job.progress = sqlite3_column_int(stmt, 4);
        job.created_at = unixToTimestamp(sqlite3_column_int64(stmt, 5));
        job.started_at = unixToTimestamp(sqlite3_column_int64(stmt, 6));
        job.completed_at = unixToTimestamp(sqlite3_column_int64(stmt, 7));
        job.total_packets = sqlite3_column_int64(stmt, 8);
        job.total_bytes = sqlite3_column_int64(stmt, 9);

        if (sqlite3_column_type(stmt, 11) != SQLITE_NULL) {
            job.error_message = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 11));
        }

        jobs.push_back(job);
    }

    sqlite3_finalize(stmt);
    return jobs;
}

bool DatabaseManager::deleteJob(const std::string& job_id) {
    std::lock_guard<std::mutex> lock(db_mutex_);

    const char* sql = "DELETE FROM jobs WHERE job_id = ?";

    sqlite3_stmt* stmt = nullptr;
    if (!prepareStatement(sql, &stmt)) {
        return false;
    }

    sqlite3_bind_text(stmt, 1, job_id.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        LOG_ERROR("Failed to delete job: " << sqlite3_errmsg(db_));
        return false;
    }

    LOG_INFO("Deleted job: " << job_id);
    return true;
}

int DatabaseManager::deleteOldJobs(int retention_days) {
    std::lock_guard<std::mutex> lock(db_mutex_);

    auto now = std::chrono::system_clock::now();
    auto retention = now - std::chrono::hours(24 * retention_days);
    int64_t retention_unix = timestampToUnix(retention);

    const char* sql = "DELETE FROM jobs WHERE created_at < ?";

    sqlite3_stmt* stmt = nullptr;
    if (!prepareStatement(sql, &stmt)) {
        return 0;
    }

    sqlite3_bind_int64(stmt, 1, retention_unix);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        LOG_ERROR("Failed to delete old jobs: " << sqlite3_errmsg(db_));
        return 0;
    }

    int deleted = sqlite3_changes(db_);
    LOG_INFO("Deleted " << deleted << " old jobs (retention: " << retention_days << " days)");
    return deleted;
}

// ============================================================================
// Session Operations
// ============================================================================

bool DatabaseManager::insertSession(const Session& session) {
    std::lock_guard<std::mutex> lock(db_mutex_);

    const char* sql = R"(
        INSERT INTO sessions (session_id, job_id, session_type, session_key,
                             start_time, end_time, duration_ms, packet_count,
                             byte_count, participant_ips, metadata)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    )";

    sqlite3_stmt* stmt = nullptr;
    if (!prepareStatement(sql, &stmt)) {
        return false;
    }

    nlohmann::json participants_json = session.participant_ips;
    std::string participants_str = participants_json.dump();
    std::string metadata_str = session.metadata.dump();

    sqlite3_bind_text(stmt, 1, session.session_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, session.job_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, session.session_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, session.session_key.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 5, session.start_time);
    sqlite3_bind_int64(stmt, 6, session.end_time);
    sqlite3_bind_int(stmt, 7, session.duration_ms);
    sqlite3_bind_int(stmt, 8, session.packet_count);
    sqlite3_bind_int64(stmt, 9, session.byte_count);
    sqlite3_bind_text(stmt, 10, participants_str.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 11, metadata_str.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        LOG_ERROR("Failed to insert session: " << sqlite3_errmsg(db_));
        return false;
    }

    return true;
}

bool DatabaseManager::updateSession(const Session& session) {
    std::lock_guard<std::mutex> lock(db_mutex_);

    const char* sql = R"(
        UPDATE sessions SET
            end_time = ?, duration_ms = ?, packet_count = ?,
            byte_count = ?, metadata = ?
        WHERE session_id = ?
    )";

    sqlite3_stmt* stmt = nullptr;
    if (!prepareStatement(sql, &stmt)) {
        return false;
    }

    std::string metadata_str = session.metadata.dump();

    sqlite3_bind_int64(stmt, 1, session.end_time);
    sqlite3_bind_int(stmt, 2, session.duration_ms);
    sqlite3_bind_int(stmt, 3, session.packet_count);
    sqlite3_bind_int64(stmt, 4, session.byte_count);
    sqlite3_bind_text(stmt, 5, metadata_str.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, session.session_id.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        LOG_ERROR("Failed to update session: " << sqlite3_errmsg(db_));
        return false;
    }

    return true;
}

std::optional<Session> DatabaseManager::getSession(const std::string& session_id) {
    std::lock_guard<std::mutex> lock(db_mutex_);

    const char* sql = R"(
        SELECT session_id, job_id, session_type, session_key,
               start_time, end_time, duration_ms, packet_count,
               byte_count, participant_ips, metadata
        FROM sessions WHERE session_id = ?
    )";

    sqlite3_stmt* stmt = nullptr;
    if (!prepareStatement(sql, &stmt)) {
        return std::nullopt;
    }

    sqlite3_bind_text(stmt, 1, session_id.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return std::nullopt;
    }

    Session session;
    session.session_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
    session.job_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
    session.session_type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
    session.session_key = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
    session.start_time = sqlite3_column_int64(stmt, 4);
    session.end_time = sqlite3_column_int64(stmt, 5);
    session.duration_ms = sqlite3_column_int(stmt, 6);
    session.packet_count = sqlite3_column_int(stmt, 7);
    session.byte_count = sqlite3_column_int64(stmt, 8);

    if (sqlite3_column_type(stmt, 9) != SQLITE_NULL) {
        std::string participants_str = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 9));
        try {
            auto j = nlohmann::json::parse(participants_str);
            session.participant_ips = j.get<std::vector<std::string>>();
        } catch (...) {
            // Ignore parse errors
        }
    }

    if (sqlite3_column_type(stmt, 10) != SQLITE_NULL) {
        std::string metadata_str = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 10));
        try {
            session.metadata = nlohmann::json::parse(metadata_str);
        } catch (...) {
            session.metadata = nlohmann::json::object();
        }
    }

    sqlite3_finalize(stmt);
    return session;
}

std::vector<Session> DatabaseManager::getSessionsByFilter(const SessionFilter& filter) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    std::vector<Session> sessions;

    std::ostringstream sql;
    sql << "SELECT session_id, job_id, session_type, session_key, "
        << "start_time, end_time, duration_ms, packet_count, "
        << "byte_count, participant_ips, metadata FROM sessions WHERE 1=1";

    if (!filter.job_id.empty()) {
        sql << " AND job_id = ?";
    }
    if (!filter.protocol_filter.empty()) {
        sql << " AND session_type = ?";
    }
    if (!filter.session_key_search.empty()) {
        sql << " AND session_key LIKE ?";
    }
    if (filter.start_time_min > 0) {
        sql << " AND start_time >= ?";
    }
    if (filter.start_time_max > 0) {
        sql << " AND start_time <= ?";
    }

    sql << " ORDER BY " << filter.sort_by;
    if (filter.sort_desc) {
        sql << " DESC";
    }
    sql << " LIMIT ? OFFSET ?";

    sqlite3_stmt* stmt = nullptr;
    if (!prepareStatement(sql.str(), &stmt)) {
        return sessions;
    }

    int param_idx = 1;
    if (!filter.job_id.empty()) {
        sqlite3_bind_text(stmt, param_idx++, filter.job_id.c_str(), -1, SQLITE_TRANSIENT);
    }
    if (!filter.protocol_filter.empty()) {
        sqlite3_bind_text(stmt, param_idx++, filter.protocol_filter.c_str(), -1, SQLITE_TRANSIENT);
    }
    if (!filter.session_key_search.empty()) {
        std::string search = "%" + filter.session_key_search + "%";
        sqlite3_bind_text(stmt, param_idx++, search.c_str(), -1, SQLITE_TRANSIENT);
    }
    if (filter.start_time_min > 0) {
        sqlite3_bind_int64(stmt, param_idx++, filter.start_time_min);
    }
    if (filter.start_time_max > 0) {
        sqlite3_bind_int64(stmt, param_idx++, filter.start_time_max);
    }
    sqlite3_bind_int(stmt, param_idx++, filter.limit);
    sqlite3_bind_int(stmt, param_idx++, (filter.page - 1) * filter.limit);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        Session session;
        session.session_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        session.job_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        session.session_type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        session.session_key = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        session.start_time = sqlite3_column_int64(stmt, 4);
        session.end_time = sqlite3_column_int64(stmt, 5);
        session.duration_ms = sqlite3_column_int(stmt, 6);
        session.packet_count = sqlite3_column_int(stmt, 7);
        session.byte_count = sqlite3_column_int64(stmt, 8);

        if (sqlite3_column_type(stmt, 9) != SQLITE_NULL) {
            std::string participants_str = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 9));
            try {
                auto j = nlohmann::json::parse(participants_str);
                session.participant_ips = j.get<std::vector<std::string>>();
            } catch (...) {}
        }

        if (sqlite3_column_type(stmt, 10) != SQLITE_NULL) {
            std::string metadata_str = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 10));
            try {
                session.metadata = nlohmann::json::parse(metadata_str);
            } catch (...) {
                session.metadata = nlohmann::json::object();
            }
        }

        sessions.push_back(session);
    }

    sqlite3_finalize(stmt);
    return sessions;
}

int DatabaseManager::getSessionCount(const std::string& job_id) {
    std::lock_guard<std::mutex> lock(db_mutex_);

    const char* sql = "SELECT COUNT(*) FROM sessions WHERE job_id = ?";

    sqlite3_stmt* stmt = nullptr;
    if (!prepareStatement(sql, &stmt)) {
        return 0;
    }

    sqlite3_bind_text(stmt, 1, job_id.c_str(), -1, SQLITE_TRANSIENT);

    int count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
    }

    sqlite3_finalize(stmt);
    return count;
}

// ============================================================================
// Event Operations
// ============================================================================

bool DatabaseManager::insertEvent(const Event& event) {
    std::lock_guard<std::mutex> lock(db_mutex_);

    const char* sql = R"(
        INSERT INTO events (session_id, timestamp, event_type, protocol,
                           src_ip, dst_ip, src_port, dst_port,
                           message_type, payload, direction)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    )";

    sqlite3_stmt* stmt = nullptr;
    if (!prepareStatement(sql, &stmt)) {
        return false;
    }

    std::string payload_str = event.payload.dump();

    sqlite3_bind_text(stmt, 1, event.session_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, event.timestamp);
    sqlite3_bind_text(stmt, 3, event.event_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, event.protocol.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, event.src_ip.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, event.dst_ip.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 7, event.src_port);
    sqlite3_bind_int(stmt, 8, event.dst_port);
    sqlite3_bind_text(stmt, 9, event.message_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 10, payload_str.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 11, event.direction.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        LOG_ERROR("Failed to insert event: " << sqlite3_errmsg(db_));
        return false;
    }

    return true;
}

bool DatabaseManager::insertEvents(const std::vector<Event>& events) {
    if (events.empty()) {
        return true;
    }

    std::lock_guard<std::mutex> lock(db_mutex_);

    if (!beginTransaction()) {
        return false;
    }

    const char* sql = R"(
        INSERT INTO events (session_id, timestamp, event_type, protocol,
                           src_ip, dst_ip, src_port, dst_port,
                           message_type, payload, direction)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    )";

    sqlite3_stmt* stmt = nullptr;
    if (!prepareStatement(sql, &stmt)) {
        rollbackTransaction();
        return false;
    }

    for (const auto& event : events) {
        std::string payload_str = event.payload.dump();

        sqlite3_bind_text(stmt, 1, event.session_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 2, event.timestamp);
        sqlite3_bind_text(stmt, 3, event.event_type.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, event.protocol.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 5, event.src_ip.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 6, event.dst_ip.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 7, event.src_port);
        sqlite3_bind_int(stmt, 8, event.dst_port);
        sqlite3_bind_text(stmt, 9, event.message_type.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 10, payload_str.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 11, event.direction.c_str(), -1, SQLITE_TRANSIENT);

        if (sqlite3_step(stmt) != SQLITE_DONE) {
            LOG_ERROR("Failed to insert event: " << sqlite3_errmsg(db_));
            sqlite3_finalize(stmt);
            rollbackTransaction();
            return false;
        }

        sqlite3_reset(stmt);
    }

    sqlite3_finalize(stmt);

    if (!commitTransaction()) {
        return false;
    }

    return true;
}

std::vector<Event> DatabaseManager::getEventsBySession(const std::string& session_id) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    std::vector<Event> events;

    const char* sql = R"(
        SELECT event_id, session_id, timestamp, event_type, protocol,
               src_ip, dst_ip, src_port, dst_port, message_type, payload, direction
        FROM events WHERE session_id = ? ORDER BY timestamp ASC
    )";

    sqlite3_stmt* stmt = nullptr;
    if (!prepareStatement(sql, &stmt)) {
        return events;
    }

    sqlite3_bind_text(stmt, 1, session_id.c_str(), -1, SQLITE_TRANSIENT);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        Event event;
        event.event_id = sqlite3_column_int64(stmt, 0);
        event.session_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        event.timestamp = sqlite3_column_int64(stmt, 2);
        event.event_type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        event.protocol = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        event.src_ip = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        event.dst_ip = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
        event.src_port = sqlite3_column_int(stmt, 7);
        event.dst_port = sqlite3_column_int(stmt, 8);
        event.message_type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 9));

        if (sqlite3_column_type(stmt, 10) != SQLITE_NULL) {
            std::string payload_str = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 10));
            try {
                event.payload = nlohmann::json::parse(payload_str);
            } catch (...) {
                event.payload = nlohmann::json::object();
            }
        }

        event.direction = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 11));

        events.push_back(event);
    }

    sqlite3_finalize(stmt);
    return events;
}

int DatabaseManager::getEventCount(const std::string& session_id) {
    std::lock_guard<std::mutex> lock(db_mutex_);

    const char* sql = "SELECT COUNT(*) FROM events WHERE session_id = ?";

    sqlite3_stmt* stmt = nullptr;
    if (!prepareStatement(sql, &stmt)) {
        return 0;
    }

    sqlite3_bind_text(stmt, 1, session_id.c_str(), -1, SQLITE_TRANSIENT);

    int count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
    }

    sqlite3_finalize(stmt);
    return count;
}

// ============================================================================
// Metrics Operations
// ============================================================================

bool DatabaseManager::insertMetric(const Metric& metric) {
    std::lock_guard<std::mutex> lock(db_mutex_);

    const char* sql = R"(
        INSERT INTO metrics (job_id, session_id, metric_type, metric_value,
                            timestamp, metadata)
        VALUES (?, ?, ?, ?, ?, ?)
    )";

    sqlite3_stmt* stmt = nullptr;
    if (!prepareStatement(sql, &stmt)) {
        return false;
    }

    std::string metadata_str = metric.metadata.dump();

    if (metric.job_id.empty()) {
        sqlite3_bind_null(stmt, 1);
    } else {
        sqlite3_bind_text(stmt, 1, metric.job_id.c_str(), -1, SQLITE_TRANSIENT);
    }

    if (metric.session_id.empty()) {
        sqlite3_bind_null(stmt, 2);
    } else {
        sqlite3_bind_text(stmt, 2, metric.session_id.c_str(), -1, SQLITE_TRANSIENT);
    }

    sqlite3_bind_text(stmt, 3, metric.metric_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_double(stmt, 4, metric.metric_value);
    sqlite3_bind_int64(stmt, 5, metric.timestamp);
    sqlite3_bind_text(stmt, 6, metadata_str.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        LOG_ERROR("Failed to insert metric: " << sqlite3_errmsg(db_));
        return false;
    }

    return true;
}

std::vector<Metric> DatabaseManager::getMetrics(const std::string& job_id,
                                                const std::string& metric_type) {
    std::lock_guard<std::mutex> lock(db_mutex_);
    std::vector<Metric> metrics;

    std::string sql = R"(
        SELECT metric_id, job_id, session_id, metric_type, metric_value,
               timestamp, metadata
        FROM metrics WHERE job_id = ?
    )";

    if (!metric_type.empty()) {
        sql += " AND metric_type = ?";
    }

    sqlite3_stmt* stmt = nullptr;
    if (!prepareStatement(sql, &stmt)) {
        return metrics;
    }

    sqlite3_bind_text(stmt, 1, job_id.c_str(), -1, SQLITE_TRANSIENT);
    if (!metric_type.empty()) {
        sqlite3_bind_text(stmt, 2, metric_type.c_str(), -1, SQLITE_TRANSIENT);
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        Metric metric;
        metric.metric_id = sqlite3_column_int64(stmt, 0);
        if (sqlite3_column_type(stmt, 1) != SQLITE_NULL) {
            metric.job_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        }
        if (sqlite3_column_type(stmt, 2) != SQLITE_NULL) {
            metric.session_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        }
        metric.metric_type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        metric.metric_value = sqlite3_column_double(stmt, 4);
        metric.timestamp = sqlite3_column_int64(stmt, 5);

        if (sqlite3_column_type(stmt, 6) != SQLITE_NULL) {
            std::string metadata_str = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
            try {
                metric.metadata = nlohmann::json::parse(metadata_str);
            } catch (...) {
                metric.metadata = nlohmann::json::object();
            }
        }

        metrics.push_back(metric);
    }

    sqlite3_finalize(stmt);
    return metrics;
}

// ============================================================================
// Utility Operations
// ============================================================================

DatabaseStats DatabaseManager::getStats() {
    std::lock_guard<std::mutex> lock(db_mutex_);
    DatabaseStats stats;

    const char* sql_jobs = "SELECT COUNT(*) FROM jobs";
    const char* sql_sessions = "SELECT COUNT(*) FROM sessions";
    const char* sql_events = "SELECT COUNT(*) FROM events";
    const char* sql_metrics = "SELECT COUNT(*) FROM metrics";

    sqlite3_stmt* stmt = nullptr;

    if (prepareStatement(sql_jobs, &stmt)) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            stats.total_jobs = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }

    if (prepareStatement(sql_sessions, &stmt)) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            stats.total_sessions = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }

    if (prepareStatement(sql_events, &stmt)) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            stats.total_events = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }

    if (prepareStatement(sql_metrics, &stmt)) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            stats.total_metrics = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }

    // Get database file size
    const char* sql_size = "SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()";
    if (prepareStatement(sql_size, &stmt)) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            stats.db_size_bytes = sqlite3_column_int64(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }

    return stats;
}

bool DatabaseManager::vacuum() {
    std::lock_guard<std::mutex> lock(db_mutex_);
    return executeStatement("VACUUM");
}

bool DatabaseManager::beginTransaction() {
    if (in_transaction_) {
        LOG_WARN("Transaction already in progress");
        return false;
    }

    if (!executeStatement("BEGIN TRANSACTION")) {
        return false;
    }

    in_transaction_ = true;
    return true;
}

bool DatabaseManager::commitTransaction() {
    if (!in_transaction_) {
        LOG_WARN("No transaction in progress");
        return false;
    }

    if (!executeStatement("COMMIT")) {
        return false;
    }

    in_transaction_ = false;
    return true;
}

bool DatabaseManager::rollbackTransaction() {
    if (!in_transaction_) {
        LOG_WARN("No transaction in progress");
        return false;
    }

    if (!executeStatement("ROLLBACK")) {
        return false;
    }

    in_transaction_ = false;
    return true;
}

bool DatabaseManager::isHealthy() {
    std::lock_guard<std::mutex> lock(db_mutex_);

    const char* sql = "SELECT 1";
    sqlite3_stmt* stmt = nullptr;

    if (!prepareStatement(sql, &stmt)) {
        return false;
    }

    bool healthy = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);

    return healthy;
}

}  // namespace callflow
