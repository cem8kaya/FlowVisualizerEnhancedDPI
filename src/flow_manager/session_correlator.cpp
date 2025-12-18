#include "flow_manager/session_correlator.h"

#include "common/logger.h"
#include "common/utils.h"

namespace callflow {

nlohmann::json FlowSession::toJson(bool include_events) const {
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

    // Frontend compatibility fields (flattened metrics)
    j["packet_count"] = metrics.total_packets;
    j["byte_count"] = metrics.total_bytes;
    j["session_type"] = sessionTypeToString(type);  // Ensure type is available as session_type

    if (metrics.duration_ms.has_value()) {
        j["duration_ms"] = metrics.duration_ms.value();
    } else {
        j["duration_ms"] = 0;
    }

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

nlohmann::json FlowSession::toSummaryJson() const {
    return toJson(false);
}

SessionCorrelator::SessionCorrelator(const Config& config) : config_(config) {
    LOG_INFO("SessionCorrelator initialized");
}

void SessionCorrelator::processPacket(const PacketMetadata& packet, ProtocolType protocol,
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
    } else if (protocol == ProtocolType::PFCP) {
        // PFCP can use F-SEID or SEID from header
        if (parsed_data.contains("f_seid")) {
            session_key = "PFCP-" + std::to_string(parsed_data["f_seid"].get<uint64_t>());
        } else if (parsed_data.contains("header") && parsed_data["header"].contains("seid")) {
            session_key = "PFCP-" + std::to_string(parsed_data["header"]["seid"].get<uint64_t>());
        } else {
            // Fallback to 5-tuple for node management messages
            session_key = "PFCP-" + packet.five_tuple.toString();
        }
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

std::shared_ptr<FlowSession> SessionCorrelator::getSession(const SessionId& session_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    for (const auto& [key, session] : sessions_) {
        if (session->session_id == session_id) {
            return session;
        }
    }

    return nullptr;
}

std::vector<std::shared_ptr<FlowSession>> SessionCorrelator::getAllSessions() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<std::shared_ptr<FlowSession>> result;
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

        LOG_DEBUG("Finalized session " << session->session_id << " (" << session->events.size()
                                       << " events, " << duration_ms << "ms duration)");
    }
}

size_t SessionCorrelator::getSessionCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return sessions_.size();
}

std::shared_ptr<FlowSession> SessionCorrelator::getOrCreateSession(const std::string& session_key,
                                                                   SessionType type, Timestamp ts) {
    auto it = sessions_.find(session_key);

    if (it != sessions_.end()) {
        return it->second;
    }

    // Create new session
    auto session = std::make_shared<FlowSession>();
    session->session_id = utils::generateUuid();
    session->type = type;
    session->session_key = session_key;
    session->start_time = ts;
    session->end_time = ts;

    sessions_[session_key] = session;

    LOG_INFO("Created new session: " << session->session_id << " type=" << sessionTypeToString(type)
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
        case ProtocolType::PFCP:
            return SessionType::PFCP;
        case ProtocolType::DIAMETER:
            return SessionType::DIAMETER;
        case ProtocolType::HTTP2:
            return SessionType::HTTP2;
        default:
            return SessionType::UNKNOWN;
    }
}

void SessionCorrelator::addEventToSession(std::shared_ptr<FlowSession> session,
                                          const PacketMetadata& packet, ProtocolType protocol,
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
            if (method == "INVITE")
                event.message_type = MessageType::SIP_INVITE;
            else if (method == "ACK")
                event.message_type = MessageType::SIP_ACK;
            else if (method == "BYE")
                event.message_type = MessageType::SIP_BYE;
        } else {
            int status_code = parsed_data.value("status_code", 0);
            std::string reason = parsed_data.value("reason_phrase", "");
            event.short_description = "SIP " + std::to_string(status_code) + " " + reason;
            if (status_code == 100)
                event.message_type = MessageType::SIP_TRYING;
            else if (status_code == 180)
                event.message_type = MessageType::SIP_RINGING;
            else if (status_code == 200)
                event.message_type = MessageType::SIP_OK;
        }
    } else if (protocol == ProtocolType::RTP) {
        event.short_description = "RTP packet";
        event.message_type = MessageType::UNKNOWN;
    } else if (protocol == ProtocolType::DIAMETER) {
        std::string command_name = parsed_data.value("command_name", "DIAMETER");
        event.short_description = "DIAMETER " + command_name;

        // Extract message type from header
        if (parsed_data.contains("header") && parsed_data["header"].contains("command_code")) {
            uint32_t cmd_code = parsed_data["header"]["command_code"].get<uint32_t>();
            bool is_request = parsed_data["header"].value("request_flag", false);

            if (cmd_code == 272) {  // Credit-Control
                event.message_type =
                    is_request ? MessageType::DIAMETER_CCR : MessageType::DIAMETER_CCA;
            } else if (cmd_code == 265) {  // AA-Request
                event.message_type =
                    is_request ? MessageType::DIAMETER_AAR : MessageType::DIAMETER_AAA;
            }
        }
    } else if (protocol == ProtocolType::GTP_C) {
        std::string msg_name = parsed_data.value("message_type_name", "GTP");
        event.short_description = "GTP " + msg_name;

        // Extract message type from header
        if (parsed_data.contains("header") && parsed_data["header"].contains("message_type")) {
            uint8_t msg_type = parsed_data["header"]["message_type"].get<uint8_t>();

            switch (msg_type) {
                case 32:
                    event.message_type = MessageType::GTP_CREATE_SESSION_REQ;
                    break;
                case 33:
                    event.message_type = MessageType::GTP_CREATE_SESSION_RESP;
                    break;
                case 36:
                    event.message_type = MessageType::GTP_DELETE_SESSION_REQ;
                    break;
                case 37:
                    event.message_type = MessageType::GTP_DELETE_SESSION_RESP;
                    break;
                case 1:
                    event.message_type = MessageType::GTP_ECHO_REQ;
                    break;
                case 2:
                    event.message_type = MessageType::GTP_ECHO_RESP;
                    break;
                default:
                    event.message_type = MessageType::UNKNOWN;
                    break;
            }
        }
    } else if (protocol == ProtocolType::PFCP) {
        std::string msg_name = parsed_data.value("message_type_name", "PFCP");
        event.short_description = "PFCP " + msg_name;

        // Extract message type from header
        if (parsed_data.contains("header") && parsed_data["header"].contains("message_type")) {
            uint8_t msg_type = parsed_data["header"]["message_type"].get<uint8_t>();

            switch (msg_type) {
                case 1:
                    event.message_type = MessageType::PFCP_HEARTBEAT_REQ;
                    break;
                case 2:
                    event.message_type = MessageType::PFCP_HEARTBEAT_RESP;
                    break;
                case 5:
                    event.message_type = MessageType::PFCP_ASSOCIATION_SETUP_REQ;
                    break;
                case 6:
                    event.message_type = MessageType::PFCP_ASSOCIATION_SETUP_RESP;
                    break;
                case 50:
                    event.message_type = MessageType::PFCP_SESSION_ESTABLISHMENT_REQ;
                    break;
                case 51:
                    event.message_type = MessageType::PFCP_SESSION_ESTABLISHMENT_RESP;
                    break;
                case 52:
                    event.message_type = MessageType::PFCP_SESSION_MODIFICATION_REQ;
                    break;
                case 53:
                    event.message_type = MessageType::PFCP_SESSION_MODIFICATION_RESP;
                    break;
                case 54:
                    event.message_type = MessageType::PFCP_SESSION_DELETION_REQ;
                    break;
                case 55:
                    event.message_type = MessageType::PFCP_SESSION_DELETION_RESP;
                    break;
                case 56:
                    event.message_type = MessageType::PFCP_SESSION_REPORT_REQ;
                    break;
                case 57:
                    event.message_type = MessageType::PFCP_SESSION_REPORT_RESP;
                    break;
                default:
                    event.message_type = MessageType::UNKNOWN;
                    break;
            }
        }
    }

    event.details = parsed_data;

    // Simplified participant tracking
    bool src_found = false;
    bool dst_found = false;

    // Use string representation for simple matching
    std::string src_str =
        packet.five_tuple.src_ip + ":" + std::to_string(packet.five_tuple.src_port);
    std::string dst_str =
        packet.five_tuple.dst_ip + ":" + std::to_string(packet.five_tuple.dst_port);

    for (const auto& p : session->participants) {
        if (p.toString() == src_str)
            src_found = true;
        if (p.toString() == dst_str)
            dst_found = true;
    }

    if (!src_found) {
        Participant p;
        p.ip = packet.five_tuple.src_ip;
        p.port = packet.five_tuple.src_port;
        session->participants.push_back(p);
    }

    if (!dst_found) {
        Participant p;
        p.ip = packet.five_tuple.dst_ip;
        p.port = packet.five_tuple.dst_port;
        session->participants.push_back(p);
    }

    session->events.push_back(event);
}

void SessionCorrelator::updateMetrics(std::shared_ptr<FlowSession> session,
                                      const PacketMetadata& packet) {
    session->metrics.total_packets++;
    session->metrics.total_bytes += packet.packet_length;

    // Simple duration update
    if (session->metrics.total_packets == 1) {
        session->metrics.setup_time_ms = 0;  // First packet
    } else {
        auto duration = utils::timeDiffMs(session->start_time, packet.timestamp);
        session->metrics.duration_ms = duration;
    }
}

}  // namespace callflow
