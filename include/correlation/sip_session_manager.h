#pragma once

#include "correlation/sip/sip_session.h"
#include "correlation/sip_dialog_tracker.h"
#include "common/types.h"
#include "protocol_parsers/sip_parser.h"
#include "session/session_types.h"
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>
#include <nlohmann/json.hpp>

namespace callflow {
namespace correlation {

/**
 * Manages standalone SIP sessions when no cross-protocol correlation exists
 * Creates self-contained sessions with diagram-ready data structures
 */
class SipSessionManager {
public:
    SipSessionManager();
    ~SipSessionManager() = default;

    // Process SIP message and create/update session
    void processSipMessage(const SipMessage& msg, const PacketMetadata& metadata);

    // Get all standalone SIP sessions
    std::vector<std::shared_ptr<SipSession>> getSessions() const;

    // Get session by Call-ID
    std::shared_ptr<SipSession> getSessionByCallId(const std::string& call_id) const;

    // Export sessions in format compatible with UI
    nlohmann::json exportSessions() const;

    // Statistics
    struct Stats {
        size_t total_sessions = 0;
        size_t active_sessions = 0;
        size_t completed_sessions = 0;
        size_t total_messages = 0;
        size_t total_dialogs = 0;
    };
    Stats getStats() const;

    // Cleanup old sessions
    void cleanup(std::chrono::seconds max_age = std::chrono::hours(24));

private:
    mutable std::mutex mutex_;

    // Call-ID -> SipSession
    std::unordered_map<std::string, std::shared_ptr<SipSession>> sessions_;

    // Dialog tracker for transaction management
    std::unique_ptr<SipDialogTracker> dialog_tracker_;

    // Create session from first message
    std::shared_ptr<SipSession> createSession(const SipMessage& msg,
                                               const PacketMetadata& metadata);

    // Convert SIP session to generic Session format for UI
    Session toGenericSession(const SipSession& sip_session) const;
};

}} // namespace callflow::correlation
