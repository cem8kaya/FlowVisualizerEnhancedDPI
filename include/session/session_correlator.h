#pragma once

#include <memory>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <vector>

#include "common/types.h"
#include "session/session_types.h"

namespace callflow {

/**
 * Enhanced Session Correlator
 *
 * Correlates protocol messages across multiple 3GPP interfaces to reconstruct
 * complete end-to-end sessions. Supports both LTE and 5G networks.
 *
 * Key capabilities:
 * - Cross-interface correlation using IMSI, TEID, SEID, UE IDs
 * - Session type detection (attach, handover, VoLTE call, etc.)
 * - Support for incomplete sessions (missing packets)
 * - Real-time correlation as messages are processed
 * - Query interface for session retrieval
 */
class EnhancedSessionCorrelator {
public:
    EnhancedSessionCorrelator() = default;
    ~EnhancedSessionCorrelator() = default;

    /**
     * Add a message to the correlator
     * The message will be correlated with existing sessions or create a new session
     *
     * @param msg Message reference with correlation keys
     */
    void addMessage(const SessionMessageRef& msg);

    /**
     * Find sessions by IMSI
     *
     * @param imsi IMSI to search for
     * @return Vector of sessions containing this IMSI
     */
    std::vector<Session> correlateByImsi(const std::string& imsi) const;

    /**
     * Find sessions by SUPI (5G identifier)
     *
     * @param supi SUPI to search for
     * @return Vector of sessions containing this SUPI
     */
    std::vector<Session> correlateBySupi(const std::string& supi) const;

    /**
     * Find sessions by TEID (GTP-U tunnel identifier)
     *
     * @param teid TEID to search for
     * @return Vector of sessions containing this TEID
     */
    std::vector<Session> correlateByTeid(uint32_t teid) const;

    /**
     * Find sessions by SEID (PFCP session identifier)
     *
     * @param seid SEID to search for
     * @return Vector of sessions containing this SEID
     */
    std::vector<Session> correlateBySeid(uint64_t seid) const;

    /**
     * Find sessions by UE IP address
     *
     * @param ue_ip UE IP address to search for
     * @return Vector of sessions containing this UE IP
     */
    std::vector<Session> correlateByUeIp(const std::string& ue_ip) const;

    /**
     * Find sessions by correlation key (any matching identifier)
     *
     * @param key Correlation key to search for
     * @return Vector of sessions matching this key
     */
    std::vector<Session> correlateByKey(const SessionCorrelationKey& key) const;

    /**
     * Get a specific session by ID
     *
     * @param session_id Session ID to retrieve
     * @return Session if found, nullopt otherwise
     */
    std::optional<Session> getSession(const std::string& session_id) const;

    /**
     * Get all sessions
     */
    std::vector<std::shared_ptr<Session>> getAllSessions() const;

    /**
     * Get sessions by type
     *
     * @param type Session type to filter by
     * @return Vector of sessions of the specified type
     */
    std::vector<Session> getSessionsByType(EnhancedSessionType type) const;

    /**
     * Get sessions involving a specific interface
     *
     * @param interface Interface type to filter by
     * @return Vector of sessions involving this interface
     */
    std::vector<Session> getSessionsByInterface(InterfaceType interface) const;

    /**
     * Get all session legs for a primary identifier (IMSI/SUPI)
     * Returns all messages across all interfaces for this subscriber
     *
     * @param identifier Primary identifier (IMSI or SUPI)
     * @return Vector of all messages for this identifier
     */
    std::vector<SessionMessageRef> getSessionLegs(const std::string& identifier) const;

    /**
     * Get session statistics
     *
     * @return Aggregated statistics for all sessions
     */
    SessionStatistics getStatistics() const;

    /**
     * Clear all sessions
     */
    void clear();

    /**
     * Finalize all sessions
     * Should be called after all messages have been added
     */
    void finalize();

    /**
     * Get number of active sessions
     */
    size_t getSessionCount() const;

    /**
     * Export sessions to JSON
     *
     * @return JSON array of all sessions
     */
    nlohmann::json exportToJson() const;

    /**
     * Process a packet and correlate it to a session
     */
    void processPacket(const PacketMetadata& packet, ProtocolType protocol,
                       const nlohmann::json& parsed_data);

    /**
     * Finalize all sessions (timeout logic, etc.)
     */
    void finalizeSessions();

private:
    // Session storage
    std::unordered_map<std::string, Session> sessions_;  // session_id -> Session

    // Correlation indices for fast lookup
    std::unordered_map<std::string, std::vector<std::string>> imsi_index_;   // IMSI -> session_ids
    std::unordered_map<std::string, std::vector<std::string>> supi_index_;   // SUPI -> session_ids
    std::unordered_map<uint32_t, std::vector<std::string>> teid_index_;      // TEID -> session_ids
    std::unordered_map<uint64_t, std::vector<std::string>> seid_index_;      // SEID -> session_ids
    std::unordered_map<std::string, std::vector<std::string>> ue_ip_index_;  // UE IP -> session_ids
    std::unordered_map<uint32_t, std::vector<std::string>>
        mme_ue_id_index_;  // MME UE ID -> session_ids
    std::unordered_map<uint64_t, std::vector<std::string>>
        amf_ue_id_index_;  // AMF UE ID -> session_ids

    // Thread safety
    mutable std::mutex mutex_;

    /**
     * Find existing session that matches the correlation key
     *
     * @param key Correlation key from new message
     * @return Session ID if found, nullopt otherwise
     */
    std::optional<std::string> findMatchingSession(const SessionCorrelationKey& key) const;

    /**
     * Create a new session for a message
     *
     * @param msg First message of the session
     * @return New session ID
     */
    std::string createNewSession(const SessionMessageRef& msg);

    /**
     * Add message to an existing session
     *
     * @param session_id Session to add message to
     * @param msg Message to add
     */
    void addMessageToSession(const std::string& session_id, const SessionMessageRef& msg);

    /**
     * Update correlation indices for a session
     *
     * @param session_id Session ID
     * @param key Correlation key to index
     */
    void updateIndices(const std::string& session_id, const SessionCorrelationKey& key);

    /**
     * Detect session type based on message sequence
     *
     * @param session Session to analyze
     * @return Detected session type
     */
    EnhancedSessionType detectSessionType(const Session& session) const;

    /**
     * Check if message is a session start message
     *
     * @param msg Message to check
     * @return True if this is a session start message
     */
    bool isSessionStartMessage(const SessionMessageRef& msg) const;

    /**
     * Check if message is a session end message
     *
     * @param msg Message to check
     * @return True if this is a session end message
     */
    bool isSessionEndMessage(const SessionMessageRef& msg) const;

    /**
     * Generate unique session ID
     *
     * @return New unique session ID (UUID v4)
     */
    std::string generateSessionId() const;

    /**
     * Merge two sessions if they are determined to be the same
     * This can happen when correlation keys are discovered later
     *
     * @param session_id1 First session ID
     * @param session_id2 Second session ID
     */
    void mergeSessions(const std::string& session_id1, const std::string& session_id2);

    /**
     * Extract correlation key from various protocol message types
     */
    SessionCorrelationKey extractCorrelationKey(const nlohmann::json& parsed_message,
                                                ProtocolType protocol) const;
};

}  // namespace callflow
