#pragma once

#include "correlation/sip/sip_session.h"
#include "correlation/identity/subscriber_context_manager.h"
#include <unordered_map>
#include <memory>
#include <mutex>

namespace callflow {
namespace correlation {

/**
 * @brief SIP intra-protocol correlator
 *
 * Groups SIP messages into sessions based on Call-ID,
 * detects session types, and extracts call party information.
 */
class SipCorrelator {
public:
    SipCorrelator();
    explicit SipCorrelator(SubscriberContextManager* ctx_manager);
    ~SipCorrelator() = default;

    /**
     * @brief Add a parsed SIP message
     */
    void addMessage(const SipMessage& msg);

    /**
     * @brief Finalize all sessions (call after all messages added)
     */
    void finalize();

    /**
     * @brief Get all sessions
     */
    std::vector<SipSession*> getSessions();

    /**
     * @brief Get sessions of specific type
     */
    std::vector<SipSession*> getSessionsByType(SipSessionType type);

    /**
     * @brief Get voice/video call sessions only
     */
    std::vector<SipSession*> getCallSessions();

    /**
     * @brief Find session by Call-ID
     */
    SipSession* findByCallId(const std::string& call_id);

    /**
     * @brief Find sessions by MSISDN (caller or callee)
     */
    std::vector<SipSession*> findByMsisdn(const std::string& msisdn);

    /**
     * @brief Get session by frame number
     */
    SipSession* findByFrame(uint32_t frame_number);

    /**
     * @brief Get statistics
     */
    struct Stats {
        size_t total_messages = 0;
        size_t total_sessions = 0;
        size_t registration_sessions = 0;
        size_t voice_call_sessions = 0;
        size_t video_call_sessions = 0;
        size_t sms_sessions = 0;
        size_t other_sessions = 0;
    };
    Stats getStats() const;

    /**
     * @brief Clear all sessions
     */
    void clear();

private:
    mutable std::mutex mutex_;
    std::unordered_map<std::string, std::unique_ptr<SipSession>> sessions_;
    // Key: Call-ID

    SubscriberContextManager* ctx_manager_ = nullptr;

    int session_sequence_ = 0;
    Stats stats_;

    std::string generateSessionId(double timestamp);
    void updateSubscriberContext(const SipSession& session);
};

} // namespace correlation
} // namespace callflow
