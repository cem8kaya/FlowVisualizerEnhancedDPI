#pragma once

#include "correlation/diameter/diameter_session.h"
#include "correlation/identity/subscriber_context_manager.h"
#include <unordered_map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace callflow {
namespace correlation {

/**
 * @brief Diameter intra-protocol correlator
 *
 * Groups Diameter messages into sessions based on Session-ID,
 * links requests to answers by Hop-by-Hop-ID, detects interfaces,
 * and extracts subscriber information.
 *
 * Key responsibilities:
 * - Session tracking by Session-ID
 * - Request/Answer correlation by Hop-by-Hop-ID
 * - Interface detection (S6a, Gx, Rx, Cx, Sh, Gy, etc.)
 * - Subscriber identity extraction (IMSI, MSISDN, Framed-IP)
 * - Integration with SubscriberContextManager
 */
class DiameterCorrelator {
public:
    DiameterCorrelator();
    explicit DiameterCorrelator(SubscriberContextManager* ctx_manager);
    ~DiameterCorrelator() = default;

    /**
     * @brief Add a Diameter message to correlation
     *
     * This will:
     * - Find or create a session based on Session-ID
     * - Add the message to the session
     * - Link request/answer pairs by Hop-by-Hop-ID
     * - Extract subscriber information
     * - Update SubscriberContextManager if configured
     */
    void addMessage(const DiameterMessage& msg);

    /**
     * @brief Finalize all sessions
     *
     * Extracts all remaining information and marks sessions as complete.
     * Should be called after all messages have been processed.
     */
    void finalize();

    // ========================================================================
    // Session Access
    // ========================================================================

    /**
     * @brief Get all sessions
     */
    std::vector<DiameterSession*> getSessions();

    /**
     * @brief Get sessions by interface type
     */
    std::vector<DiameterSession*> getSessionsByInterface(DiameterInterface iface);

    /**
     * @brief Get Gx sessions (for VoLTE/PDN correlation)
     */
    std::vector<DiameterSession*> getGxSessions() {
        return getSessionsByInterface(DiameterInterface::GX);
    }

    /**
     * @brief Get Rx sessions (for VoLTE correlation)
     */
    std::vector<DiameterSession*> getRxSessions() {
        return getSessionsByInterface(DiameterInterface::RX);
    }

    /**
     * @brief Get S6a sessions (for mobility correlation)
     */
    std::vector<DiameterSession*> getS6aSessions() {
        return getSessionsByInterface(DiameterInterface::S6A);
    }

    /**
     * @brief Get Cx sessions (for IMS registration correlation)
     */
    std::vector<DiameterSession*> getCxSessions() {
        return getSessionsByInterface(DiameterInterface::CX);
    }

    /**
     * @brief Get Sh sessions (for IMS user data correlation)
     */
    std::vector<DiameterSession*> getShSessions() {
        return getSessionsByInterface(DiameterInterface::SH);
    }

    // ========================================================================
    // Session Lookup
    // ========================================================================

    /**
     * @brief Find session by Session-ID
     */
    DiameterSession* findBySessionId(const std::string& session_id);

    /**
     * @brief Find sessions by IMSI
     */
    std::vector<DiameterSession*> findByImsi(const std::string& imsi);

    /**
     * @brief Find sessions by MSISDN
     */
    std::vector<DiameterSession*> findByMsisdn(const std::string& msisdn);

    /**
     * @brief Find sessions by Framed-IP-Address
     */
    std::vector<DiameterSession*> findByFramedIp(const std::string& ip);

    /**
     * @brief Find sessions by Framed-IPv6-Prefix
     */
    std::vector<DiameterSession*> findByFramedIpv6Prefix(const std::string& prefix);

    /**
     * @brief Find session by Hop-by-Hop-ID (for request/answer correlation)
     */
    DiameterSession* findByHopByHopId(uint32_t hop_by_hop_id);

    // ========================================================================
    // Statistics
    // ========================================================================

    struct Stats {
        size_t total_messages = 0;
        size_t total_sessions = 0;
        std::unordered_map<DiameterInterface, size_t> sessions_by_interface;
        size_t error_responses = 0;
        size_t request_count = 0;
        size_t answer_count = 0;
        size_t linked_pairs = 0;
    };

    /**
     * @brief Get correlation statistics
     */
    Stats getStats() const;

    /**
     * @brief Clear all sessions and reset state
     */
    void clear();

    /**
     * @brief Get session count
     */
    size_t getSessionCount() const;

private:
    std::mutex mutex_;
    std::unordered_map<std::string, std::unique_ptr<DiameterSession>> sessions_;

    // Hop-by-Hop to Session-ID mapping for request/answer correlation
    std::unordered_map<uint32_t, std::string> hop_to_session_;

    // Subscriber identity to Session-IDs mapping
    std::unordered_map<std::string, std::vector<std::string>> imsi_to_sessions_;
    std::unordered_map<std::string, std::vector<std::string>> msisdn_to_sessions_;
    std::unordered_map<std::string, std::vector<std::string>> framed_ip_to_sessions_;

    SubscriberContextManager* ctx_manager_ = nullptr;

    int session_sequence_ = 0;
    Stats stats_;

    // Internal methods
    std::string generateSessionId(double timestamp);
    void updateSubscriberContext(const DiameterSession& session);
    void updateLookupMaps(const std::string& session_id, const DiameterSession& session);
    void trackHopByHop(uint32_t hop_by_hop_id, const std::string& session_id);
};

} // namespace correlation
} // namespace callflow
