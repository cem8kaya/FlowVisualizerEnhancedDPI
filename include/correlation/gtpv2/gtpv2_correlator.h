#pragma once

#include "correlation/gtpv2/gtpv2_session.h"
#include "correlation/gtpv2/gtpv2_message.h"
#include "correlation/gtpv2/gtpv2_fteid_manager.h"
#include "correlation/identity/subscriber_context_manager.h"
#include <unordered_map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace callflow {
namespace correlation {

/**
 * @brief GTPv2 intra-protocol correlator
 *
 * Groups GTPv2-C messages into sessions, tracks bearers,
 * and maintains F-TEID mappings for GTP-U correlation.
 *
 * Key responsibilities:
 * - Session tracking by Control TEID
 * - Request/Response correlation by Sequence Number
 * - Bearer lifecycle management (default + dedicated)
 * - F-TEID extraction and indexing for GTP-U linking
 * - Subscriber identity extraction (IMSI, MSISDN, MEI)
 * - Integration with SubscriberContextManager
 */
class Gtpv2Correlator {
public:
    Gtpv2Correlator();
    explicit Gtpv2Correlator(SubscriberContextManager* ctx_manager);
    ~Gtpv2Correlator() = default;

    /**
     * @brief Add a GTPv2 message to correlation
     *
     * This will:
     * - Find or create a session based on Control TEID
     * - Add the message to the session
     * - Extract bearer information
     * - Register F-TEIDs for GTP-U correlation
     * - Update SubscriberContextManager if configured
     */
    void addMessage(const Gtpv2Message& msg);

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
    std::vector<Gtpv2Session*> getSessions();

    /**
     * @brief Get IMS sessions only (for VoLTE correlation)
     */
    std::vector<Gtpv2Session*> getImsSessions();

    /**
     * @brief Get sessions with dedicated bearers (active VoLTE calls)
     */
    std::vector<Gtpv2Session*> getSessionsWithDedicatedBearers();

    /**
     * @brief Get internet sessions
     */
    std::vector<Gtpv2Session*> getInternetSessions();

    /**
     * @brief Get emergency sessions
     */
    std::vector<Gtpv2Session*> getEmergencySessions();

    // ========================================================================
    // Session Lookup
    // ========================================================================

    /**
     * @brief Find session by Control TEID
     */
    Gtpv2Session* findByControlTeid(uint32_t teid);

    /**
     * @brief Find sessions by IMSI
     */
    std::vector<Gtpv2Session*> findByImsi(const std::string& imsi);

    /**
     * @brief Find sessions by MSISDN
     */
    std::vector<Gtpv2Session*> findByMsisdn(const std::string& msisdn);

    /**
     * @brief Find session by PDN address (UE IP)
     */
    Gtpv2Session* findByPdnAddress(const std::string& ip);

    /**
     * @brief Find session by F-TEID
     */
    Gtpv2Session* findByFteid(const std::string& ip, uint32_t teid);

    /**
     * @brief Find session by GTP-U packet
     */
    Gtpv2Session* findByGtpuPacket(const std::string& src_ip,
                                    const std::string& dst_ip,
                                    uint32_t teid);

    // ========================================================================
    // F-TEID Manager Access
    // ========================================================================

    /**
     * @brief Get F-TEID manager for GTP-U linking
     */
    Gtpv2FteidManager& getFteidManager() { return fteid_manager_; }
    const Gtpv2FteidManager& getFteidManager() const { return fteid_manager_; }

    // ========================================================================
    // Statistics
    // ========================================================================

    struct Stats {
        size_t total_messages = 0;
        size_t total_sessions = 0;
        size_t ims_sessions = 0;
        size_t internet_sessions = 0;
        size_t emergency_sessions = 0;
        size_t sessions_with_dedicated_bearers = 0;
        size_t total_bearers = 0;
        size_t default_bearers = 0;
        size_t dedicated_bearers = 0;
        size_t session_errors = 0;
        size_t active_sessions = 0;
        size_t deleted_sessions = 0;
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
    std::unordered_map<std::string, std::unique_ptr<Gtpv2Session>> sessions_;
    // Key: Session key from Control TEID + Sequence

    Gtpv2FteidManager fteid_manager_;
    SubscriberContextManager* ctx_manager_ = nullptr;

    int session_sequence_ = 0;
    Stats stats_;

    // Lookup indices for fast access
    std::unordered_map<uint32_t, Gtpv2Session*> teid_to_session_;
    std::unordered_map<std::string, std::vector<Gtpv2Session*>> imsi_to_sessions_;
    std::unordered_map<std::string, std::vector<Gtpv2Session*>> msisdn_to_sessions_;
    std::unordered_map<std::string, Gtpv2Session*> pdn_address_to_session_;

    // Internal methods
    std::string generateSessionKey(uint32_t teid, uint32_t sequence);
    std::string generateIntraCorrelator(double timestamp, int seq);
    void updateSubscriberContext(const Gtpv2Session& session);
    void updateLookupIndices(Gtpv2Session* session);
    void registerSessionFteids(Gtpv2Session* session);
    Gtpv2Session* findOrCreateSession(const Gtpv2Message& msg);
};

} // namespace correlation
} // namespace callflow
