#include "flow_manager/session_correlator.h"
#include "common/logger.h"
#include "common/utils.h"

namespace callflow {

nlohmann::json Session::toJson(bool include_events) const {
    nlohmann::json j;

    j["session_id"] = session_id;
    j["type"] = sessionTypeToString(type);
    j["session_key"] = session_key;
    j["start_time"] = utils::timestampToIso8601(start_time);
    j["end_time"] = utils::timestampToIso8601(end_time);

    // Participants
    nlohmann::json participants_json = nlohmann::json::array();
    for (const auto& p : participants) {
        participants_json.push_back(p.toString());
    }
    j["participants"] = participants_json;

    // Metrics
    nlohmann::json metrics_json;
    metrics_json["packets"] = metrics.total_packets;
    metrics_json["bytes"] = metrics.total_bytes;
    metrics_json["rtp_loss"] = metrics.rtp_packet_loss;
    metrics_json["rtp_jitter_ms"] = metrics.rtp_jitter_ms;
    metrics_json["setup_time_ms"] = metrics.setup_time_ms;
    if (metrics.duration_ms.has_value()) {
        metrics_json["duration_ms"] = metrics.duration_ms.value();
    }
    j["metrics"] = metrics_json;

    j["events_count"] = events.size();

    // Include events if requested
    if (include_events) {
        nlohmann::json events_json = nlohmann::json::array();
        for (const auto& event : events) {
            nlohmann::json event_json;
            event_json["event_id"] = event.event_id;
            event_json["timestamp"] = utils::timestampToIso8601(event.timestamp);
            event_json["direction"] = directionToString(event.direction);
            event_json["protocol"] = protocolTypeToString(event.protocol);
            event_json["message_type"] = messageTypeToString(event.message_type);
            event_json["short"] = event.short_description;
            event_json["details"] = event.details;
            event_json["packet_ref"] = event.packet_ref;
            events_json.push_back(event_json);
        }
        j["events"] = events_json;
    }

    return j;
}

nlohmann::json Session::toSummaryJson() const {
    return toJson(false);
}

SessionCorrelator::SessionCorrelator(const Config& config) : config_(config) {
    LOG_INFO("SessionCorrelator initialized");
}

void SessionCorrelator::processPacket(const PacketMetadata& packet,
                                     ProtocolType protocol,
                                     const nlohmann::json& parsed_data) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Extract session key from parsed data
    std::string session_key;

    if (protocol == ProtocolType::SIP && parsed_data.contains("call_id")) {
        session_key = parsed_data["call_id"].get<std::string>();
    } else if (protocol == ProtocolType::DIAMETER && parsed_data.contains("session_id")) {
        session_key = parsed_data["session_id"].get<std::string>();
    } else if (protocol == ProtocolType::GTP_C && parsed_data.contains("teid")) {
        session_key = "GTP-" + std::to_string(parsed_data["teid"].get<uint32_t>());
    } else if (protocol == ProtocolType::HTTP2 && parsed_data.contains("stream_id")) {
        session_key = "HTTP2-" + packet.five_tuple.toString() + "-" +
                     std::to_string(parsed_data["stream_id"].get<uint32_t>());
    } else {
        // Fallback to 5-tuple
        session_key = "FLOW-" + packet.five_tuple.toString();
    }

    if (session_key.empty()) {
        return;
    }

    // Get or create session
    SessionType type = determineSessionType(protocol);
    auto session = getOrCreateSession(session_key, type, packet.timestamp);

    // Add event
    addEventToSession(session, packet, protocol, parsed_data);

    // Update metrics
    updateMetrics(session, packet);

    // Update end time
    session->end_time = packet.timestamp;
}

std::shared_ptr<Session> SessionCorrelator::getSession(const SessionId& session_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    for (const auto& [key, session] : sessions_) {
        if (session->session_id == session_id) {
            return session;
        }
    }

    return nullptr;
}

std::vector<std::shared_ptr<Session>> SessionCorrelator::getAllSessions() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<std::shared_ptr<Session>> result;
    result.reserve(sessions_.size());

    for (const auto& [key, session] : sessions_) {
        result.push_back(session);
    }

    return result;
}

void SessionCorrelator::finalizeSessions() {
    std::lock_guard<std::mutex> lock(mutex_);

    for (auto& [key, session] : sessions_) {
        // Calculate duration
        auto duration_ms = utils::timeDiffMs(session->start_time, session->end_time);
        session->metrics.duration_ms = duration_ms;

        LOG_DEBUG("Finalized session " << session->session_id
                  << " (" << session->events.size() << " events, "
                  << duration_ms << "ms duration)");
    }
}

size_t SessionCorrelator::getSessionCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return sessions_.size();
}

std::shared_ptr<Session> SessionCorrelator::getOrCreateSession(const std::string& session_key,
                                                               SessionType type,
                                                               Timestamp ts) {
    auto it = sessions_.find(session_key);

    if (it != sessions_.end()) {
        return it->second;
    }

    // Create new session
    auto session = std::make_shared<Session>();
    session->session_id = utils::generateUuid();
    session->type = type;
    session->session_key = session_key;
    session->start_time = ts;
    session->end_time = ts;

    sessions_[session_key] = session;

    LOG_INFO("Created new session: " << session->session_id
             << " type=" << sessionTypeToString(type)
             << " key=" << session_key);

    return session;
}

SessionType SessionCorrelator::determineSessionType(ProtocolType protocol) {
    switch (protocol) {
        case ProtocolType::SIP:
        case ProtocolType::RTP:
            return SessionType::VOLTE;
        case ProtocolType::GTP_C:
        case ProtocolType::GTP_U:
            return SessionType::GTP;
        case ProtocolType::DIAMETER:
            return SessionType::DIAMETER;
        case ProtocolType::HTTP2:
            return SessionType::HTTP2;
        default:
            return SessionType::UNKNOWN;
    }
}

void SessionCorrelator::addEventToSession(std::shared_ptr<Session> session,
                                         const PacketMetadata& packet,
                                         ProtocolType protocol,
                                         const nlohmann::json& parsed_data) {
    SessionEvent event;
    event.event_id = utils::generateUuid();
    event.timestamp = packet.timestamp;
    event.protocol = protocol;
    event.packet_ref = packet.packet_id;

    // Determine direction (simplified)
    event.direction = Direction::CLIENT_TO_SERVER;

    // Extract message type and description from parsed data
    if (protocol == ProtocolType::SIP) {
        if (parsed_data.contains("is_request") && parsed_data["is_request"].get<bool>()) {
            std::string method = parsed_data.value("method", "UNKNOWN");
            event.short_description = "SIP " + method;
            if (method == "INVITE") event.message_type = MessageType::SIP_INVITE;
            else if (method == "ACK") event.message_type = MessageType::SIP_ACK;
            else if (method == "BYE") event.message_type = MessageType::SIP_BYE;
        } else {
            int status_code = parsed_data.value("status_code", 0);
            std::string reason = parsed_data.value("reason_phrase", "");
            event.short_description = "SIP " + std::to_string(status_code) + " " + reason;
            if (status_code == 100) event.message_type = MessageType::SIP_TRYING;
            else if (status_code == 180) event.message_type = MessageType::SIP_RINGING;
            else if (status_code == 200) event.message_type = MessageType::SIP_OK;
        }
    } else if (protocol == ProtocolType::RTP) {
        event.short_description = "RTP packet";
        event.message_type = MessageType::UNKNOWN;
    }

    event.details = parsed_data;

    // Add participants if not already in list
    Participant src{packet.five_tuple.src_ip, packet.five_tuple.src_port};
    Participant dst{packet.five_tuple.dst_ip, packet.five_tuple.dst_port};

    if (std::find(session->participants.begin(), session->participants.end(), src) ==
        session->participants.end()) {
        session->participants.push_back(src);
    }

    if (std::find(session->participants.begin(), session->participants.end(), dst) ==
        session->participants.end()) {
        session->participants.push_back(dst);
    }

    session->events.push_back(event);
}

void SessionCorrelator::updateMetrics(std::shared_ptr<Session> session,
                                     const PacketMetadata& packet) {
    session->metrics.total_packets++;
    session->metrics.total_bytes += packet.packet_length;
}

}  // namespace callflow
