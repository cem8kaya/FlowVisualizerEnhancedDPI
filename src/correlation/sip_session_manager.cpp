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
                                                             const PacketMetadata& /* metadata */) {
    LOG_INFO("SipSessionManager: Creating new session for Call-ID: "
             << msg.getCallId() << " Initial TS: " << std::fixed << msg.getTimestamp());
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
        // Finalize session to extract call parties and session type
        sip_session->finalize();

        // Convert to generic Session format
        Session generic_session = toGenericSession(*sip_session);

        // Export to JSON
        nlohmann::json session_json;
        session_json["session_id"] = generic_session.session_id;
        session_json["session_type"] = sipSessionTypeToString(sip_session->getType());
        session_json["call_id"] = call_id;
        // Convert timestamps from seconds to milliseconds
        double start_time_sec = sip_session->getStartTime();
        double end_time_sec = sip_session->getEndTime();

        // Validate timestamps (should be after year 2000: 946684800 seconds)
        if (start_time_sec < 946684800.0 || end_time_sec < 946684800.0) {
            LOG_WARN("Invalid timestamp detected for SIP session "
                     << call_id << ": start=" << start_time_sec << ", end=" << end_time_sec);
        }

        // Explicitly use int64_t to avoid potential 32-bit truncation or uint64 interpretation
        // issues
        int64_t start_time_ms = static_cast<int64_t>(start_time_sec * 1000.0);
        int64_t end_time_ms = static_cast<int64_t>(end_time_sec * 1000.0);

        // Debug logging for timestamp truncation investigation
        if (start_time_ms > 4294967296LL || start_time_ms < 0) {
            // Log only if it looks large enough or negative (which shouldn't happen for valid
            // dates)
            LOG_DEBUG("Exporting SIP Session " << call_id << ": start_sec=" << start_time_sec
                                               << ", start_ms=" << start_time_ms
                                               << ", end_ms=" << end_time_ms);
        }

        session_json["start_time"] = start_time_ms;
        session_json["end_time"] = end_time_ms;

        // Debug fields to diagnose 1970/2004 issues
        session_json["debug_start_time_sec"] = start_time_sec;
        session_json["debug_end_time_sec"] = end_time_sec;

        session_json["message_count"] = sip_session->getMessageCount();
        session_json["dialog_count"] = sip_session->getDialogs().size();

        // Add call party information
        session_json["caller_msisdn"] = sip_session->getCallerMsisdn();
        session_json["callee_msisdn"] = sip_session->getCalleeMsisdn();
        session_json["caller_imsi"] = sip_session->getCallerImsi();
        session_json["callee_imsi"] = sip_session->getCalleeImsi();
        // Fallback for UI 'imsi' column if needed
        session_json["imsi"] = sip_session->getCallerImsi().empty() ? sip_session->getCalleeImsi()
                                                                    : sip_session->getCallerImsi();
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
                if (msg_ref.timestamp.time_since_epoch().count() > 0) {
                    event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
                                             msg_ref.timestamp.time_since_epoch())
                                             .count();
                } else {
                    event["timestamp"] = 0;
                }
                event["protocol"] = protocolTypeToString(msg_ref.protocol);

                // Convert MessageType to string for UI
                std::string type_str;
                switch (msg_ref.message_type) {
                    case MessageType::SIP_INVITE:
                        type_str = "INVITE";
                        break;
                    case MessageType::SIP_ACK:
                        type_str = "ACK";
                        break;
                    case MessageType::SIP_BYE:
                        type_str = "BYE";
                        break;
                    case MessageType::SIP_REGISTER:
                        type_str = "REGISTER";
                        break;
                    case MessageType::SIP_OPTIONS:
                        type_str = "OPTIONS";
                        break;
                    case MessageType::SIP_PRACK:
                        type_str = "PRACK";
                        break;
                    case MessageType::SIP_UPDATE:
                        type_str = "UPDATE";
                        break;
                    case MessageType::SIP_CANCEL:
                        type_str = "CANCEL";
                        break;
                    case MessageType::SIP_TRYING:
                        type_str = "100 Trying";
                        break;
                    case MessageType::SIP_RINGING:
                        type_str = "180 Ringing";
                        break;
                    case MessageType::SIP_SESSION_PROGRESS:
                        type_str = "183 Progress";
                        break;
                    case MessageType::SIP_OK:
                        type_str = "200 OK";
                        break;
                    default:
                        // Fallback for responses that don't have a specific MessageType
                        if (msg_ref.message_type == MessageType::UNKNOWN &&
                            msg_ref.parsed_data.contains("status_code")) {
                            int code = msg_ref.parsed_data["status_code"];
                            std::string phrase = msg_ref.parsed_data.value("reason_phrase", "");
                            type_str = std::to_string(code) + (phrase.empty() ? "" : " " + phrase);
                        } else {
                            type_str = std::to_string(static_cast<int>(msg_ref.message_type));
                        }
                        break;
                }
                event["message_type"] = type_str;

                // Add IPs for direction arrow
                event["src_ip"] = msg_ref.src_ip;
                event["dst_ip"] = msg_ref.dst_ip;

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
    leg.interface = InterfaceType::IMS_SIP;

    for (const auto& sip_msg : sip_session.getMessages()) {
        SessionMessageRef msg_ref;
        msg_ref.protocol = ProtocolType::SIP;

        // Determine message type
        if (sip_msg.isRequest()) {
            std::string method = sip_msg.getMethod();
            if (method == "INVITE")
                msg_ref.message_type = MessageType::SIP_INVITE;
            else if (method == "ACK")
                msg_ref.message_type = MessageType::SIP_ACK;
            else if (method == "BYE")
                msg_ref.message_type = MessageType::SIP_BYE;
            else if (method == "REGISTER")
                msg_ref.message_type = MessageType::SIP_REGISTER;
            else if (method == "OPTIONS")
                msg_ref.message_type = MessageType::SIP_OPTIONS;
            else if (method == "PRACK")
                msg_ref.message_type = MessageType::SIP_PRACK;
            else if (method == "UPDATE")
                msg_ref.message_type = MessageType::SIP_UPDATE;
            else if (method == "CANCEL")
                msg_ref.message_type = MessageType::SIP_CANCEL;
            else
                msg_ref.message_type = MessageType::UNKNOWN;
        } else {
            int status_code = sip_msg.getStatusCode();
            if (status_code == 100)
                msg_ref.message_type = MessageType::SIP_TRYING;
            else if (status_code == 180)
                msg_ref.message_type = MessageType::SIP_RINGING;
            else if (status_code == 183)
                msg_ref.message_type = MessageType::SIP_SESSION_PROGRESS;
            else if (status_code == 200)
                msg_ref.message_type = MessageType::SIP_OK;
            else
                msg_ref.message_type = MessageType::UNKNOWN;
        }

        // Set timestamp from specific message
        double ts = sip_msg.getTimestamp();
        if (ts > 0) {
            msg_ref.timestamp = std::chrono::system_clock::time_point(
                std::chrono::duration_cast<std::chrono::system_clock::duration>(
                    std::chrono::duration<double>(ts)));
        } else {
            // Fallback to session start if message has no timestamp (shouldn't happen with fix)
            msg_ref.timestamp = std::chrono::system_clock::from_time_t(
                static_cast<time_t>(sip_session.getStartTime()));
        }

        // Populate IPs/Ports
        msg_ref.src_ip = sip_msg.getSourceIp();
        msg_ref.dst_ip = sip_msg.getDestIp();
        msg_ref.src_port = sip_msg.getSourcePort();
        msg_ref.dst_port = sip_msg.getDestPort();

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
