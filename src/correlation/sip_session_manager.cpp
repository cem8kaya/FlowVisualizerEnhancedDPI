#include "correlation/sip_session_manager.h"

#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

#include "common/logger.h"
#include "common/utils.h"

namespace callflow {
namespace correlation {

SipSessionManager::SipSessionManager() {
    dialog_tracker_ = std::make_unique<SipDialogTracker>();
}

void SipSessionManager::processSipMessage(const SipMessage& msg, const PacketMetadata& metadata) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (msg.getCallId().empty()) {
        LOG_WARN("SIP message without Call-ID, skipping");
        return;
    }

    // Get or create session
    auto& session = sessions_[msg.getCallId()];
    if (!session) {
        session = createSession(msg, metadata);
        LOG_INFO("Created standalone SIP session: " << msg.getCallId());
    }

    // Add message to session
    session->addMessage(msg);

    // Update dialog tracker
    // Create struct SipMessage from Class SipMessage for dialog tracker
    ::callflow::SipMessage struct_msg;
    struct_msg.is_request = msg.isRequest();

    if (msg.isRequest()) {
        struct_msg.method = msg.getMethod();
        struct_msg.request_uri = msg.getRequestUri();
    } else {
        struct_msg.status_code = msg.getStatusCode();
        struct_msg.reason_phrase = msg.getReasonPhrase();
        // Response CSeq method is needed for transaction matching
        struct_msg.method = msg.getCSeqMethod();
    }

    struct_msg.call_id = msg.getCallId();
    struct_msg.from_tag = msg.getFromTag();
    struct_msg.to_tag = msg.getToTag();

    // Use stringstream to convert CSeq to string (safer than to_string in some contexts)
    std::ostringstream oss;
    oss << msg.getCSeq();
    struct_msg.cseq = oss.str();

    // Copy Via branch for transaction matching
    auto top_via = msg.getTopVia();
    if (top_via.has_value()) {
        struct_msg.via_branch = top_via->branch;
    }

    dialog_tracker_->processMessage(struct_msg, metadata.five_tuple.src_ip,
                                    metadata.five_tuple.dst_ip, metadata.timestamp);
}

std::shared_ptr<SipSession> SipSessionManager::createSession(const SipMessage& msg,
                                                             const PacketMetadata& metadata) {
    auto session = std::make_shared<SipSession>(msg.getCallId());

    // Session will auto-populate during addMessage()
    return session;
}

std::vector<std::shared_ptr<SipSession>> SipSessionManager::getSessions() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<std::shared_ptr<SipSession>> result;
    result.reserve(sessions_.size());

    for (const auto& [call_id, session] : sessions_) {
        result.push_back(session);
    }

    return result;
}

std::shared_ptr<SipSession> SipSessionManager::getSessionByCallId(
    const std::string& call_id) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = sessions_.find(call_id);
    if (it != sessions_.end()) {
        return it->second;
    }

    return nullptr;
}

nlohmann::json SipSessionManager::exportSessions() const {
    std::lock_guard<std::mutex> lock(mutex_);

    nlohmann::json result = nlohmann::json::array();

    for (const auto& [call_id, sip_session] : sessions_) {
        // Convert to generic Session format
        Session generic_session = toGenericSession(*sip_session);

        // Export to JSON
        nlohmann::json session_json;
        session_json["session_id"] = generic_session.session_id;
        session_json["session_type"] = "SIP_ONLY";
        session_json["call_id"] = call_id;
        session_json["start_time"] = sip_session->getStartTime();
        session_json["end_time"] = sip_session->getEndTime();
        session_json["message_count"] = sip_session->getMessageCount();
        session_json["dialog_count"] = sip_session->getDialogs().size();

        // Add call party information
        session_json["caller_msisdn"] = sip_session->getCallerMsisdn();
        session_json["callee_msisdn"] = sip_session->getCalleeMsisdn();
        session_json["caller_ip"] = sip_session->getCallerIp();
        session_json["callee_ip"] = sip_session->getCalleeIp();

        // Add messages
        nlohmann::json messages_json = nlohmann::json::array();
        for (const auto& msg : sip_session->getMessages()) {
            messages_json.push_back(msg.toJson());
        }
        session_json["messages"] = messages_json;

        // Add events (for timeline visualization)
        nlohmann::json events_json = nlohmann::json::array();
        if (!generic_session.legs.empty()) {
            for (const auto& msg_ref : generic_session.legs[0].messages) {
                nlohmann::json event;
                event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
                                         msg_ref.timestamp.time_since_epoch())
                                         .count();
                event["protocol"] = protocolTypeToString(msg_ref.protocol);
                event["message_type"] = msg_ref.message_type;
                event["data"] = msg_ref.parsed_data;
                events_json.push_back(event);
            }
        }
        session_json["events"] = events_json;

        result.push_back(session_json);
    }

    return result;
}

Session SipSessionManager::toGenericSession(const SipSession& sip_session) const {
    Session session;
    session.session_id = sip_session.getSessionId();
    session.session_type = EnhancedSessionType::SIP_SESSION;

    // Create single leg with all SIP messages
    SessionLeg leg;
    leg.interface_type = "SIP";

    for (const auto& sip_msg : sip_session.getMessages()) {
        SessionMessageRef msg_ref;
        msg_ref.protocol = ProtocolType::SIP;

        // Determine message type
        if (sip_msg.isRequest()) {
            msg_ref.message_type = sip_msg.getMethod();
        } else {
            msg_ref.message_type = std::to_string(sip_msg.getStatusCode());
        }

        // Set timestamp (use session start time + offset for now)
        msg_ref.timestamp =
            std::chrono::system_clock::from_time_t(static_cast<time_t>(sip_session.getStartTime()));

        // Store parsed data as JSON
        msg_ref.parsed_data = sip_msg.toJson();

        leg.messages.push_back(msg_ref);
    }

    session.legs.push_back(leg);
    return session;
}

SipSessionManager::Stats SipSessionManager::getStats() const {
    std::lock_guard<std::mutex> lock(mutex_);

    Stats stats;
    stats.total_sessions = sessions_.size();

    for (const auto& [call_id, session] : sessions_) {
        stats.total_messages += session->getMessageCount();
        stats.total_dialogs += session->getDialogs().size();

        // Consider session completed if it has a BYE message
        const auto& messages = session->getMessages();
        bool completed = false;
        for (const auto& msg : messages) {
            if (msg.isRequest() && msg.getMethod() == "BYE") {
                completed = true;
                break;
            }
        }

        if (completed) {
            stats.completed_sessions++;
        } else {
            stats.active_sessions++;
        }
    }

    return stats;
}

void SipSessionManager::cleanup(std::chrono::seconds max_age) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto now = std::chrono::system_clock::now();
    auto it = sessions_.begin();

    while (it != sessions_.end()) {
        const auto& session = it->second;
        auto session_end =
            std::chrono::system_clock::from_time_t(static_cast<time_t>(session->getEndTime()));

        auto age = std::chrono::duration_cast<std::chrono::seconds>(now - session_end);

        if (age > max_age) {
            LOG_DEBUG("Removing old SIP session: " << it->first << " (age: " << age.count()
                                                   << "s)");
            it = sessions_.erase(it);
        } else {
            ++it;
        }
    }
}

}  // namespace correlation
}  // namespace callflow
