#include "common/logger.h"
#include "protocol_parsers/diameter/diameter_session.h"

namespace callflow {
namespace diameter {

// ============================================================================
// DiameterMessagePair Implementation
// ============================================================================

DiameterMessagePair::DiameterMessagePair(std::shared_ptr<DiameterMessage> req)
    : request(std::move(req)), request_time(std::chrono::system_clock::now()) {}

void DiameterMessagePair::setAnswer(std::shared_ptr<DiameterMessage> ans,
                                    std::chrono::system_clock::time_point time) {
    answer = std::move(ans);
    answer_time = time;

    // Calculate latency
    latency = std::chrono::duration_cast<std::chrono::milliseconds>(time - request_time);
}

nlohmann::json DiameterMessagePair::toJson() const {
    nlohmann::json j;

    if (request) {
        j["request"] = request->toJson();
    }

    if (answer) {
        j["answer"] = answer->toJson();
    }

    j["latency_ms"] = latency.count();
    j["complete"] = isComplete();

    return j;
}

// ============================================================================
// DiameterSession Implementation
// ============================================================================

DiameterSession::DiameterSession()
    : interface(DiameterInterface::UNKNOWN),
      application_id(0),
      start_time(std::chrono::system_clock::now()),
      active(true) {}

DiameterSession::DiameterSession(const std::string& sid)
    : session_id(sid),
      interface(DiameterInterface::UNKNOWN),
      application_id(0),
      start_time(std::chrono::system_clock::now()),
      active(true) {}

void DiameterSession::addMessagePair(const DiameterMessagePair& pair) {
    message_pairs.push_back(pair);
}

std::chrono::milliseconds DiameterSession::getDuration() const {
    auto end = end_time.value_or(std::chrono::system_clock::now());
    return std::chrono::duration_cast<std::chrono::milliseconds>(end - start_time);
}

size_t DiameterSession::getMessageCount() const {
    size_t count = 0;
    for (const auto& pair : message_pairs) {
        count++;  // Request
        if (pair.answer) {
            count++;  // Answer
        }
    }
    return count;
}

size_t DiameterSession::getCompletedPairCount() const {
    size_t count = 0;
    for (const auto& pair : message_pairs) {
        if (pair.isComplete()) {
            count++;
        }
    }
    return count;
}

std::chrono::milliseconds DiameterSession::getAverageLatency() const {
    if (message_pairs.empty()) {
        return std::chrono::milliseconds(0);
    }

    std::chrono::milliseconds total(0);
    size_t count = 0;

    for (const auto& pair : message_pairs) {
        if (pair.isComplete()) {
            total += pair.latency;
            count++;
        }
    }

    return count > 0 ? std::chrono::duration_cast<std::chrono::milliseconds>(total / count)
                     : std::chrono::milliseconds(0);
}

void DiameterSession::markEnded() {
    end_time = std::chrono::system_clock::now();
    active = false;
}

nlohmann::json DiameterSession::toJson() const {
    nlohmann::json j;

    j["session_id"] = session_id;
    j["origin_host"] = origin_host;
    j["origin_realm"] = origin_realm;
    j["interface"] = getInterfaceName(interface);
    j["application_id"] = application_id;
    j["application_name"] = getApplicationIDName(application_id);
    j["active"] = active;

    if (imsi.has_value()) {
        j["imsi"] = imsi.value();
    }
    if (msisdn.has_value()) {
        j["msisdn"] = msisdn.value();
    }

    // Statistics
    j["message_count"] = getMessageCount();
    j["completed_pairs"] = getCompletedPairCount();
    j["duration_ms"] = getDuration().count();
    j["average_latency_ms"] = getAverageLatency().count();

    // Message pairs
    nlohmann::json pairs_json = nlohmann::json::array();
    for (const auto& pair : message_pairs) {
        pairs_json.push_back(pair.toJson());
    }
    j["message_pairs"] = pairs_json;

    return j;
}

// ============================================================================
// DiameterSessionManager Implementation
// ============================================================================

std::optional<std::string> DiameterSessionManager::processMessage(
    std::shared_ptr<DiameterMessage> msg, std::chrono::system_clock::time_point timestamp) {
    if (!msg) {
        return std::nullopt;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    // Extract or generate session ID
    std::string session_id;
    if (msg->session_id.has_value() && !msg->session_id.value().empty()) {
        session_id = msg->session_id.value();
    } else {
        // For messages without Session-Id (like CER/CEA, DWR/DWA), use hop-by-hop ID
        session_id = "hop-" + std::to_string(msg->header.hop_by_hop_id);
    }

    // Find or create session
    auto it = sessions_.find(session_id);
    if (it == sessions_.end()) {
        // Create new session
        DiameterSession session = createSession(msg);
        sessions_[session_id] = session;
        it = sessions_.find(session_id);
    }

    DiameterSession& session = it->second;

    // Update session with message
    updateSession(session, msg, timestamp);

    // Store hop-by-hop mapping for correlation
    hop_to_session_[msg->header.hop_by_hop_id] = session_id;

    // If this is a request, store it as pending
    if (msg->header.request) {
        pending_requests_[msg->header.hop_by_hop_id] = {session_id, timestamp};
    } else {
        // This is an answer, try to correlate with request
        auto pending_it = pending_requests_.find(msg->header.hop_by_hop_id);
        if (pending_it != pending_requests_.end()) {
            // Found matching request
            auto req_session_it = sessions_.find(pending_it->second.session_id);
            if (req_session_it != sessions_.end()) {
                // Find the request message pair and add the answer
                for (auto& pair : req_session_it->second.message_pairs) {
                    if (pair.request &&
                        pair.request->header.hop_by_hop_id == msg->header.hop_by_hop_id &&
                        !pair.isComplete()) {
                        pair.setAnswer(msg, timestamp);
                        break;
                    }
                }
            }
            // Remove from pending
            pending_requests_.erase(pending_it);
        }
    }

    return session_id;
}

std::optional<DiameterSession> DiameterSessionManager::findSession(
    const std::string& session_id) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = sessions_.find(session_id);
    if (it != sessions_.end()) {
        return it->second;
    }

    return std::nullopt;
}

std::vector<DiameterSession> DiameterSessionManager::getActiveSessions() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<DiameterSession> active_sessions;
    for (const auto& [session_id, session] : sessions_) {
        if (session.active) {
            active_sessions.push_back(session);
        }
    }

    return active_sessions;
}

std::vector<DiameterSession> DiameterSessionManager::getAllSessions() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<DiameterSession> all_sessions;
    for (const auto& [session_id, session] : sessions_) {
        all_sessions.push_back(session);
    }

    return all_sessions;
}

bool DiameterSessionManager::correlateRequestResponse(
    std::shared_ptr<DiameterMessage> request, std::shared_ptr<DiameterMessage> answer,
    std::chrono::system_clock::time_point request_time,
    std::chrono::system_clock::time_point answer_time) {
    (void)request_time;  // Used for interface consistency, timing tracked internally
    (void)answer_time;   // Used for interface consistency, timing tracked internally
    if (!request || !answer) {
        return false;
    }

    // Check if hop-by-hop IDs match
    if (request->header.hop_by_hop_id != answer->header.hop_by_hop_id) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    // Find session
    std::string session_id;
    if (request->session_id.has_value()) {
        session_id = request->session_id.value();
    } else {
        session_id = "hop-" + std::to_string(request->header.hop_by_hop_id);
    }

    auto it = sessions_.find(session_id);
    if (it == sessions_.end()) {
        return false;
    }

    // Find the message pair and update it
    for (auto& pair : it->second.message_pairs) {
        if (pair.request && pair.request->header.hop_by_hop_id == request->header.hop_by_hop_id &&
            !pair.isComplete()) {
            pair.setAnswer(answer, answer_time);
            return true;
        }
    }

    return false;
}

size_t DiameterSessionManager::cleanupOldSessions(std::chrono::seconds max_age) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto now = std::chrono::system_clock::now();
    size_t cleaned = 0;

    auto it = sessions_.begin();
    while (it != sessions_.end()) {
        const auto& session = it->second;

        // Only clean up inactive sessions
        if (!session.active) {
            auto age = now - (session.end_time.value_or(session.start_time));
            if (age > max_age) {
                it = sessions_.erase(it);
                cleaned++;
                continue;
            }
        }

        ++it;
    }

    return cleaned;
}

size_t DiameterSessionManager::getSessionCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return sessions_.size();
}

size_t DiameterSessionManager::getActiveSessionCount() const {
    std::lock_guard<std::mutex> lock(mutex_);

    size_t count = 0;
    for (const auto& [session_id, session] : sessions_) {
        if (session.active) {
            count++;
        }
    }

    return count;
}

void DiameterSessionManager::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    sessions_.clear();
    hop_to_session_.clear();
    pending_requests_.clear();
}

DiameterSessionManager::Statistics DiameterSessionManager::getStatistics() const {
    std::lock_guard<std::mutex> lock(mutex_);

    Statistics stats;
    stats.total_sessions = sessions_.size();
    stats.active_sessions = 0;
    stats.total_messages = 0;
    stats.completed_pairs = 0;

    std::chrono::milliseconds total_latency(0);
    size_t latency_count = 0;

    for (const auto& [session_id, session] : sessions_) {
        if (session.active) {
            stats.active_sessions++;
        }

        stats.total_messages += session.getMessageCount();
        stats.completed_pairs += session.getCompletedPairCount();

        for (const auto& pair : session.message_pairs) {
            if (pair.isComplete()) {
                total_latency += pair.latency;
                latency_count++;
            }
        }
    }

    stats.avg_latency =
        latency_count > 0
            ? std::chrono::duration_cast<std::chrono::milliseconds>(total_latency / latency_count)
            : std::chrono::milliseconds(0);

    return stats;
}

nlohmann::json DiameterSessionManager::Statistics::toJson() const {
    nlohmann::json j;
    j["total_sessions"] = total_sessions;
    j["active_sessions"] = active_sessions;
    j["total_messages"] = total_messages;
    j["completed_pairs"] = completed_pairs;
    j["avg_latency_ms"] = avg_latency.count();
    return j;
}

// ============================================================================
// Private Helper Methods
// ============================================================================

DiameterSession DiameterSessionManager::createSession(std::shared_ptr<DiameterMessage> msg) {
    DiameterSession session;

    if (msg->session_id.has_value()) {
        session.session_id = msg->session_id.value();
    } else {
        session.session_id = "hop-" + std::to_string(msg->header.hop_by_hop_id);
    }

    session.origin_host = msg->origin_host.value_or("");
    session.origin_realm = msg->origin_realm.value_or("");
    session.application_id = msg->header.application_id;
    session.interface = msg->getInterface();
    session.start_time = std::chrono::system_clock::now();
    session.active = true;

    // Extract subscriber info
    extractSubscriberInfo(session, msg);

    return session;
}

void DiameterSessionManager::updateSession(DiameterSession& session,
                                           std::shared_ptr<DiameterMessage> msg,
                                           std::chrono::system_clock::time_point timestamp) {
    // Update session fields if not set
    if (session.origin_host.empty() && msg->origin_host.has_value()) {
        session.origin_host = msg->origin_host.value();
    }
    if (session.origin_realm.empty() && msg->origin_realm.has_value()) {
        session.origin_realm = msg->origin_realm.value();
    }

    // Extract subscriber info
    extractSubscriberInfo(session, msg);

    // Add message to session
    if (msg->header.request) {
        // This is a request, create a new message pair
        DiameterMessagePair pair(msg);
        pair.request_time = timestamp;
        session.message_pairs.push_back(pair);
    }

    // Check for session termination
    if (msg->header.command_code ==
            static_cast<uint32_t>(DiameterCommandCode::SESSION_TERMINATION) ||
        msg->header.command_code == static_cast<uint32_t>(DiameterCommandCode::ABORT_SESSION) ||
        msg->header.command_code == static_cast<uint32_t>(DiameterCommandCode::DISCONNECT_PEER)) {
        if (!msg->header.request) {  // Answer
            session.markEnded();
        }
    }
}

std::optional<std::string> DiameterSessionManager::findRequestByHopByHop(
    uint32_t hop_by_hop_id) const {
    auto it = hop_to_session_.find(hop_by_hop_id);
    if (it != hop_to_session_.end()) {
        return it->second;
    }
    return std::nullopt;
}

void DiameterSessionManager::extractSubscriberInfo(DiameterSession& session,
                                                   std::shared_ptr<DiameterMessage> msg) {
    // Look for IMSI and MSISDN in User-Name AVP (common in 3GPP)
    if (msg->session_id.has_value()) {
        const std::string& sid = msg->session_id.value();

        // IMSI is often in the session ID for 3GPP sessions
        size_t imsi_pos = sid.find("imsi-");
        if (imsi_pos != std::string::npos && !session.imsi.has_value()) {
            size_t start = imsi_pos + 5;
            size_t end = sid.find_first_not_of("0123456789", start);
            if (end == std::string::npos) {
                end = sid.length();
            }
            session.imsi = sid.substr(start, end - start);
        }
    }

    // Check User-Name AVP
    auto user_name_avp = msg->findAVP(static_cast<uint32_t>(DiameterAVPCode::USER_NAME));
    if (user_name_avp && !session.imsi.has_value()) {
        std::string user_name = user_name_avp->getDataAsString();
        // IMSI format: digits only, 15 digits
        if (user_name.length() == 15 &&
            user_name.find_first_not_of("0123456789") == std::string::npos) {
            session.imsi = user_name;
        }
    }
}

}  // namespace diameter
}  // namespace callflow
