#pragma once

#include "diameter_base.h"
#include "diameter_types.h"
#include <chrono>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace callflow {
namespace diameter {

// ============================================================================
// Diameter Session Structures
// ============================================================================

/**
 * Represents a request-answer pair in a Diameter session
 */
struct DiameterMessagePair {
    std::shared_ptr<DiameterMessage> request;
    std::shared_ptr<DiameterMessage> answer;
    std::chrono::milliseconds latency{0};
    std::chrono::system_clock::time_point request_time;
    std::optional<std::chrono::system_clock::time_point> answer_time;

    DiameterMessagePair() = default;
    explicit DiameterMessagePair(std::shared_ptr<DiameterMessage> req);

    /**
     * Set answer and calculate latency
     */
    void setAnswer(std::shared_ptr<DiameterMessage> ans, std::chrono::system_clock::time_point time);

    /**
     * Check if answer has been received
     */
    bool isComplete() const { return answer != nullptr; }

    /**
     * Convert to JSON
     */
    nlohmann::json toJson() const;
};

/**
 * Represents a complete Diameter session
 */
struct DiameterSession {
    std::string session_id;
    std::string origin_host;
    std::string origin_realm;
    DiameterInterface interface;
    uint32_t application_id;

    // Message pairs (request-answer)
    std::vector<DiameterMessagePair> message_pairs;

    // Session timing
    std::chrono::system_clock::time_point start_time;
    std::optional<std::chrono::system_clock::time_point> end_time;

    // For subscriber sessions (3GPP)
    std::optional<std::string> imsi;
    std::optional<std::string> msisdn;

    // Session state
    bool active;

    DiameterSession();
    explicit DiameterSession(const std::string& sid);

    /**
     * Add message pair to session
     */
    void addMessagePair(const DiameterMessagePair& pair);

    /**
     * Get session duration
     */
    std::chrono::milliseconds getDuration() const;

    /**
     * Get total number of messages
     */
    size_t getMessageCount() const;

    /**
     * Get number of completed message pairs
     */
    size_t getCompletedPairCount() const;

    /**
     * Get average latency across all completed pairs
     */
    std::chrono::milliseconds getAverageLatency() const;

    /**
     * Check if session has ended
     */
    bool hasEnded() const { return end_time.has_value(); }

    /**
     * Mark session as ended
     */
    void markEnded();

    /**
     * Convert to JSON
     */
    nlohmann::json toJson() const;
};

// ============================================================================
// Diameter Session Manager
// ============================================================================

class DiameterSessionManager {
public:
    DiameterSessionManager() = default;
    ~DiameterSessionManager() = default;

    /**
     * Process a Diameter message and update sessions
     * @param msg Diameter message to process
     * @param timestamp Message timestamp
     * @return Session ID if message was successfully processed
     */
    std::optional<std::string> processMessage(
        std::shared_ptr<DiameterMessage> msg,
        std::chrono::system_clock::time_point timestamp
    );

    /**
     * Find session by session ID
     * @param session_id Session ID to find
     * @return Session if found
     */
    std::optional<DiameterSession> findSession(const std::string& session_id) const;

    /**
     * Get all active sessions
     * @return Vector of active sessions
     */
    std::vector<DiameterSession> getActiveSessions() const;

    /**
     * Get all sessions (active and inactive)
     * @return Vector of all sessions
     */
    std::vector<DiameterSession> getAllSessions() const;

    /**
     * Correlate request and answer messages by hop-by-hop ID
     * @param request Request message
     * @param answer Answer message
     * @param request_time Time request was sent
     * @param answer_time Time answer was received
     * @return true if correlation succeeded
     */
    bool correlateRequestResponse(
        std::shared_ptr<DiameterMessage> request,
        std::shared_ptr<DiameterMessage> answer,
        std::chrono::system_clock::time_point request_time,
        std::chrono::system_clock::time_point answer_time
    );

    /**
     * Clean up old inactive sessions
     * @param max_age Maximum age for inactive sessions
     * @return Number of sessions cleaned up
     */
    size_t cleanupOldSessions(std::chrono::seconds max_age);

    /**
     * Get session count
     */
    size_t getSessionCount() const;

    /**
     * Get active session count
     */
    size_t getActiveSessionCount() const;

    /**
     * Clear all sessions
     */
    void clear();

    /**
     * Get statistics
     */
    struct Statistics {
        size_t total_sessions;
        size_t active_sessions;
        size_t total_messages;
        size_t completed_pairs;
        std::chrono::milliseconds avg_latency;

        nlohmann::json toJson() const;
    };

    Statistics getStatistics() const;

private:
    /**
     * Create new session from message
     */
    DiameterSession createSession(std::shared_ptr<DiameterMessage> msg);

    /**
     * Update existing session with message
     */
    void updateSession(DiameterSession& session, std::shared_ptr<DiameterMessage> msg, std::chrono::system_clock::time_point timestamp);

    /**
     * Find pending request by hop-by-hop ID
     */
    std::optional<std::string> findRequestByHopByHop(uint32_t hop_by_hop_id) const;

    /**
     * Extract subscriber info from message (IMSI, MSISDN)
     */
    void extractSubscriberInfo(DiameterSession& session, std::shared_ptr<DiameterMessage> msg);

    // Session storage
    std::unordered_map<std::string, DiameterSession> sessions_;

    // Hop-by-hop to session mapping (for correlation)
    std::unordered_map<uint32_t, std::string> hop_to_session_;

    // Pending requests (hop-by-hop ID to {session_id, timestamp})
    struct PendingRequest {
        std::string session_id;
        std::chrono::system_clock::time_point timestamp;
    };
    std::unordered_map<uint32_t, PendingRequest> pending_requests_;

    // Thread safety
    mutable std::mutex mutex_;
};

}  // namespace diameter
}  // namespace callflow
