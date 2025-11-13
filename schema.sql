-- nDPI Callflow Visualizer Database Schema
-- SQLite3 database for job, session, and event persistence
-- Version: 1.0 (Milestone 4)

-- Jobs table: Stores PCAP processing jobs
CREATE TABLE IF NOT EXISTS jobs (
    job_id TEXT PRIMARY KEY,
    input_file TEXT NOT NULL,
    output_file TEXT,
    status TEXT NOT NULL CHECK(status IN ('QUEUED', 'RUNNING', 'COMPLETED', 'FAILED')),
    progress INTEGER DEFAULT 0 CHECK(progress >= 0 AND progress <= 100),
    created_at INTEGER NOT NULL,  -- Unix timestamp
    started_at INTEGER,
    completed_at INTEGER,
    total_packets INTEGER DEFAULT 0,
    total_bytes INTEGER DEFAULT 0,
    session_count INTEGER DEFAULT 0,
    error_message TEXT,
    metadata TEXT  -- JSON object for additional data
);

CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
CREATE INDEX IF NOT EXISTS idx_jobs_created_at ON jobs(created_at);

-- Sessions table: Stores call flow sessions
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL,
    session_type TEXT NOT NULL CHECK(session_type IN ('VOLTE', 'GTP', 'DIAMETER', 'HTTP2', 'MIXED', 'UNKNOWN')),
    session_key TEXT NOT NULL,   -- Call-ID, Session-ID, TEID, etc.
    start_time INTEGER NOT NULL,  -- Unix timestamp
    end_time INTEGER,
    duration_ms INTEGER,
    packet_count INTEGER DEFAULT 0,
    byte_count INTEGER DEFAULT 0,
    participant_ips TEXT,  -- JSON array of IP addresses
    metadata TEXT,         -- JSON object for protocol-specific data
    FOREIGN KEY (job_id) REFERENCES jobs(job_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_sessions_job_id ON sessions(job_id);
CREATE INDEX IF NOT EXISTS idx_sessions_type ON sessions(session_type);
CREATE INDEX IF NOT EXISTS idx_sessions_start_time ON sessions(start_time);
CREATE INDEX IF NOT EXISTS idx_sessions_session_key ON sessions(session_key);

-- Events table: Stores individual protocol events within sessions
CREATE TABLE IF NOT EXISTS events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    timestamp INTEGER NOT NULL,  -- Unix timestamp (microseconds)
    event_type TEXT NOT NULL,    -- Message type (INVITE, CCR, etc.)
    protocol TEXT NOT NULL CHECK(protocol IN ('SIP', 'RTP', 'RTCP', 'GTP-C', 'GTP-U', 'DIAMETER', 'HTTP2', 'UNKNOWN')),
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    message_type TEXT,           -- User-friendly message description
    payload TEXT,                -- JSON object with parsed protocol data
    direction TEXT,              -- 'client->server', 'server->client', etc.
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_events_session_id ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_protocol ON events(protocol);

-- Metrics table: Stores aggregated metrics for analytics
CREATE TABLE IF NOT EXISTS metrics (
    metric_id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT,
    session_id TEXT,
    metric_type TEXT NOT NULL,   -- 'throughput', 'packet_rate', 'jitter', etc.
    metric_value REAL NOT NULL,
    timestamp INTEGER NOT NULL,
    metadata TEXT,               -- JSON for additional metric data
    FOREIGN KEY (job_id) REFERENCES jobs(job_id) ON DELETE CASCADE,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_metrics_type ON metrics(metric_type);
CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON metrics(timestamp);

-- Database version tracking
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at INTEGER NOT NULL,
    description TEXT
);

INSERT OR IGNORE INTO schema_version (version, applied_at, description)
VALUES (1, strftime('%s', 'now'), 'Initial schema for M4');
