-- Migration: Session Correlation Tables
-- Version: 006
-- Description: Add tables for enhanced session correlation across 3GPP interfaces
-- Author: Claude Code
-- Date: 2025

-- ============================================================================
-- Sessions Table
-- ============================================================================
-- Stores correlated sessions across multiple interfaces
CREATE TABLE IF NOT EXISTS sessions (
    -- Primary key
    session_id TEXT PRIMARY KEY,

    -- Session metadata
    session_type TEXT NOT NULL,                 -- EnhancedSessionType enum value
    start_time INTEGER NOT NULL,                -- Unix timestamp (milliseconds)
    end_time INTEGER NOT NULL,                  -- Unix timestamp (milliseconds)
    duration_ms INTEGER NOT NULL,               -- Duration in milliseconds
    is_complete BOOLEAN NOT NULL DEFAULT 0,     -- Whether session has proper start/end

    -- Correlation keys (JSON)
    correlation_key TEXT NOT NULL,              -- JSON object with all correlation identifiers

    -- Primary identifiers (indexed for fast lookup)
    imsi TEXT,                                  -- LTE subscriber identifier
    supi TEXT,                                  -- 5G subscriber identifier
    msisdn TEXT,                                -- Phone number
    ue_ipv4 TEXT,                               -- UE IPv4 address
    ue_ipv6 TEXT,                               -- UE IPv6 address

    -- Session identifiers
    teid_s1u INTEGER,                           -- TEID for S1-U interface
    teid_s5u INTEGER,                           -- TEID for S5/S8-U interface
    seid_n4 INTEGER,                            -- SEID for N4 PFCP interface
    pdu_session_id INTEGER,                     -- PDU Session ID (5G)
    eps_bearer_id INTEGER,                      -- EPS Bearer ID (LTE)

    -- UE context identifiers
    enb_ue_s1ap_id INTEGER,                     -- eNodeB UE S1AP ID
    mme_ue_s1ap_id INTEGER,                     -- MME UE S1AP ID
    ran_ue_ngap_id INTEGER,                     -- RAN UE NGAP ID
    amf_ue_ngap_id INTEGER,                     -- AMF UE NGAP ID

    -- Network identifiers
    apn TEXT,                                   -- Access Point Name (LTE)
    dnn TEXT,                                   -- Data Network Name (5G)
    network_instance TEXT,                      -- Network instance

    -- Application identifiers
    sip_call_id TEXT,                           -- SIP Call-ID for VoLTE
    rtp_ssrc INTEGER,                           -- RTP SSRC

    -- Statistics
    total_packets INTEGER NOT NULL DEFAULT 0,
    total_bytes INTEGER NOT NULL DEFAULT 0,
    setup_time_ms INTEGER,                      -- Time to establish session

    -- Interfaces involved (JSON array)
    interfaces_involved TEXT NOT NULL,          -- JSON array of interface types

    -- Additional metadata (JSON)
    metadata TEXT,                              -- JSON object with additional metadata

    -- Timestamps
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000)
);

-- Indices for fast lookup
CREATE INDEX IF NOT EXISTS idx_sessions_imsi ON sessions(imsi) WHERE imsi IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_sessions_supi ON sessions(supi) WHERE supi IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_sessions_msisdn ON sessions(msisdn) WHERE msisdn IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_sessions_ue_ipv4 ON sessions(ue_ipv4) WHERE ue_ipv4 IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_sessions_ue_ipv6 ON sessions(ue_ipv6) WHERE ue_ipv6 IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_sessions_teid_s1u ON sessions(teid_s1u) WHERE teid_s1u IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_sessions_teid_s5u ON sessions(teid_s5u) WHERE teid_s5u IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_sessions_seid_n4 ON sessions(seid_n4) WHERE seid_n4 IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_sessions_mme_ue_id ON sessions(mme_ue_s1ap_id) WHERE mme_ue_s1ap_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_sessions_amf_ue_id ON sessions(amf_ue_ngap_id) WHERE amf_ue_ngap_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_sessions_session_type ON sessions(session_type);
CREATE INDEX IF NOT EXISTS idx_sessions_start_time ON sessions(start_time);
CREATE INDEX IF NOT EXISTS idx_sessions_sip_call_id ON sessions(sip_call_id) WHERE sip_call_id IS NOT NULL;

-- ============================================================================
-- Session Messages Table (Junction Table)
-- ============================================================================
-- Links protocol messages to sessions
CREATE TABLE IF NOT EXISTS session_messages (
    -- Primary key
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Foreign keys
    session_id TEXT NOT NULL,                   -- References sessions(session_id)
    message_id TEXT NOT NULL,                   -- Unique message identifier
    packet_id TEXT NOT NULL,                    -- Packet identifier

    -- Message metadata
    interface_type TEXT NOT NULL,               -- InterfaceType enum value
    protocol_type TEXT NOT NULL,                -- ProtocolType enum value
    message_type TEXT NOT NULL,                 -- MessageType enum value
    timestamp INTEGER NOT NULL,                 -- Unix timestamp (milliseconds)
    sequence_in_session INTEGER NOT NULL,       -- Sequence number within session

    -- Correlation key for this message (JSON)
    correlation_key TEXT NOT NULL,              -- JSON object with correlation identifiers

    -- Timestamps
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),

    -- Foreign key constraint
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE,

    -- Unique constraint
    UNIQUE(session_id, message_id)
);

-- Indices for fast lookup
CREATE INDEX IF NOT EXISTS idx_session_messages_session_id ON session_messages(session_id);
CREATE INDEX IF NOT EXISTS idx_session_messages_message_id ON session_messages(message_id);
CREATE INDEX IF NOT EXISTS idx_session_messages_packet_id ON session_messages(packet_id);
CREATE INDEX IF NOT EXISTS idx_session_messages_interface ON session_messages(interface_type);
CREATE INDEX IF NOT EXISTS idx_session_messages_timestamp ON session_messages(timestamp);
CREATE INDEX IF NOT EXISTS idx_session_messages_protocol ON session_messages(protocol_type);

-- ============================================================================
-- Session Legs Table
-- ============================================================================
-- Groups messages by interface for each session
CREATE TABLE IF NOT EXISTS session_legs (
    -- Primary key
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Foreign keys
    session_id TEXT NOT NULL,                   -- References sessions(session_id)

    -- Leg metadata
    interface_type TEXT NOT NULL,               -- InterfaceType enum value
    start_time INTEGER NOT NULL,                -- Unix timestamp (milliseconds)
    end_time INTEGER NOT NULL,                  -- Unix timestamp (milliseconds)
    duration_ms INTEGER NOT NULL,               -- Duration in milliseconds
    message_count INTEGER NOT NULL DEFAULT 0,   -- Number of messages in this leg
    total_bytes INTEGER NOT NULL DEFAULT 0,     -- Total bytes in this leg

    -- Timestamps
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),

    -- Foreign key constraint
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE,

    -- Unique constraint
    UNIQUE(session_id, interface_type)
);

-- Indices for fast lookup
CREATE INDEX IF NOT EXISTS idx_session_legs_session_id ON session_legs(session_id);
CREATE INDEX IF NOT EXISTS idx_session_legs_interface ON session_legs(interface_type);

-- ============================================================================
-- Session Statistics Table
-- ============================================================================
-- Aggregate statistics for session analysis
CREATE TABLE IF NOT EXISTS session_statistics (
    -- Primary key (singleton table)
    id INTEGER PRIMARY KEY CHECK (id = 1),

    -- Aggregate statistics
    total_sessions INTEGER NOT NULL DEFAULT 0,
    total_messages INTEGER NOT NULL DEFAULT 0,
    total_bytes INTEGER NOT NULL DEFAULT 0,

    -- Averages
    average_session_duration_ms REAL NOT NULL DEFAULT 0.0,
    average_setup_time_ms REAL NOT NULL DEFAULT 0.0,

    -- Session type counts (JSON)
    sessions_by_type TEXT,                      -- JSON object with counts per type

    -- Interface message counts (JSON)
    messages_by_interface TEXT,                 -- JSON object with counts per interface

    -- Timestamps
    last_updated INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000)
);

-- Initialize statistics table with default values
INSERT OR IGNORE INTO session_statistics (id) VALUES (1);

-- ============================================================================
-- PFCP Messages Table
-- ============================================================================
-- Store parsed PFCP messages for session analysis
CREATE TABLE IF NOT EXISTS pfcp_messages (
    -- Primary key
    message_id TEXT PRIMARY KEY,

    -- Packet metadata
    packet_id TEXT NOT NULL,
    timestamp INTEGER NOT NULL,                 -- Unix timestamp (milliseconds)
    frame_number INTEGER NOT NULL,

    -- Network 5-tuple
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    src_port INTEGER NOT NULL,
    dst_port INTEGER NOT NULL,
    protocol INTEGER NOT NULL,

    -- PFCP header
    version INTEGER NOT NULL,
    message_type INTEGER NOT NULL,
    message_type_name TEXT NOT NULL,
    message_length INTEGER NOT NULL,
    seid INTEGER,                               -- Session Endpoint Identifier
    sequence_number INTEGER NOT NULL,
    is_session_message BOOLEAN NOT NULL,

    -- Extracted fields
    node_id TEXT,
    f_seid TEXT,                                -- F-SEID (JSON)

    -- Rules (JSON arrays)
    pdrs TEXT,                                  -- PDR rules (JSON array)
    fars TEXT,                                  -- FAR rules (JSON array)
    urrs TEXT,                                  -- URR rules (JSON array)
    qers TEXT,                                  -- QER rules (JSON array)

    -- Full parsed message (JSON)
    parsed_message TEXT NOT NULL,

    -- Timestamps
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000)
);

-- Indices for fast lookup
CREATE INDEX IF NOT EXISTS idx_pfcp_messages_timestamp ON pfcp_messages(timestamp);
CREATE INDEX IF NOT EXISTS idx_pfcp_messages_seid ON pfcp_messages(seid) WHERE seid IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_pfcp_messages_message_type ON pfcp_messages(message_type);
CREATE INDEX IF NOT EXISTS idx_pfcp_messages_node_id ON pfcp_messages(node_id) WHERE node_id IS NOT NULL;

-- ============================================================================
-- Triggers for maintaining statistics
-- ============================================================================

-- Trigger to update session statistics on new session
CREATE TRIGGER IF NOT EXISTS update_stats_on_session_insert
AFTER INSERT ON sessions
BEGIN
    UPDATE session_statistics
    SET total_sessions = total_sessions + 1,
        last_updated = strftime('%s', 'now') * 1000
    WHERE id = 1;
END;

-- Trigger to update session statistics on session delete
CREATE TRIGGER IF NOT EXISTS update_stats_on_session_delete
AFTER DELETE ON sessions
BEGIN
    UPDATE session_statistics
    SET total_sessions = total_sessions - 1,
        last_updated = strftime('%s', 'now') * 1000
    WHERE id = 1;
END;

-- Trigger to update session updated_at timestamp
CREATE TRIGGER IF NOT EXISTS update_session_timestamp
AFTER UPDATE ON sessions
FOR EACH ROW
BEGIN
    UPDATE sessions
    SET updated_at = strftime('%s', 'now') * 1000
    WHERE session_id = NEW.session_id;
END;

-- ============================================================================
-- Views for convenient querying
-- ============================================================================

-- View: Complete session information with message counts
CREATE VIEW IF NOT EXISTS v_sessions_summary AS
SELECT
    s.session_id,
    s.session_type,
    s.imsi,
    s.supi,
    s.ue_ipv4,
    s.start_time,
    s.end_time,
    s.duration_ms,
    s.total_packets,
    s.total_bytes,
    s.is_complete,
    s.interfaces_involved,
    COUNT(sm.id) AS message_count,
    COUNT(DISTINCT sl.interface_type) AS interface_count
FROM sessions s
LEFT JOIN session_messages sm ON s.session_id = sm.session_id
LEFT JOIN session_legs sl ON s.session_id = sl.session_id
GROUP BY s.session_id;

-- View: Session messages with interface information
CREATE VIEW IF NOT EXISTS v_session_messages_detail AS
SELECT
    sm.session_id,
    sm.message_id,
    sm.packet_id,
    sm.interface_type,
    sm.protocol_type,
    sm.message_type,
    sm.timestamp,
    sm.sequence_in_session,
    s.session_type,
    s.imsi,
    s.supi
FROM session_messages sm
JOIN sessions s ON sm.session_id = s.session_id
ORDER BY sm.timestamp;

-- View: PFCP session establishment messages
CREATE VIEW IF NOT EXISTS v_pfcp_session_establishments AS
SELECT
    message_id,
    packet_id,
    timestamp,
    message_type_name,
    seid,
    node_id,
    f_seid,
    pdrs,
    fars
FROM pfcp_messages
WHERE message_type IN (50, 51)  -- SESSION_ESTABLISHMENT_REQUEST/RESPONSE
ORDER BY timestamp;

-- ============================================================================
-- Comments
-- ============================================================================

-- The sessions table stores correlated sessions across multiple 3GPP interfaces
-- It includes all correlation keys (IMSI, SUPI, TEID, SEID, etc.) for fast lookup
--
-- The session_messages table creates the link between protocol messages and sessions
-- This allows for efficient querying of all messages in a session
--
-- The session_legs table groups messages by interface within each session
-- This provides a view of the session across different network interfaces
--
-- The pfcp_messages table stores parsed PFCP messages with extracted rules
-- This enables detailed analysis of user plane session setup and modification
--
-- All timestamps are stored as Unix timestamps in milliseconds for consistency
