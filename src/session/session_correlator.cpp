#include "session/session_correlator.h"

#include <algorithm>
#include <iomanip>
#include <random>
#include <sstream>
#include <unordered_set>

#include "common/logger.h"
#include "common/utils.h"

namespace callflow {

// ============================================================================
// EnhancedSessionCorrelator Public Methods
// ============================================================================

void EnhancedSessionCorrelator::addMessage(const SessionMessageRef& msg) {
    std::lock_guard<std::mutex> lock(mutex_);

    LOG_DEBUG("Adding message to correlator: " << protocolTypeToString(msg.protocol) << " on "
                                               << interfaceTypeToString(msg.interface));

    // Try to find existing session that matches
    auto existing_session_id = findMatchingSession(msg.correlation_key);

    if (existing_session_id.has_value()) {
        // Add to existing session
        LOG_DEBUG("Found matching session: " << existing_session_id.value());
        addMessageToSession(existing_session_id.value(), msg);
    } else {
        // Create new session
        std::string new_session_id = createNewSession(msg);
        LOG_DEBUG("Created new session: " << new_session_id);
    }
}

std::vector<Session> EnhancedSessionCorrelator::correlateByImsi(const std::string& imsi) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Session> result;

    auto it = imsi_index_.find(imsi);
    if (it != imsi_index_.end()) {
        for (const auto& session_id : it->second) {
            auto session_it = sessions_.find(session_id);
            if (session_it != sessions_.end()) {
                result.push_back(session_it->second);
            }
        }
    }

    return result;
}

std::vector<Session> EnhancedSessionCorrelator::correlateBySupi(const std::string& supi) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Session> result;

    auto it = supi_index_.find(supi);
    if (it != supi_index_.end()) {
        for (const auto& session_id : it->second) {
            auto session_it = sessions_.find(session_id);
            if (session_it != sessions_.end()) {
                result.push_back(session_it->second);
            }
        }
    }

    return result;
}

std::vector<Session> EnhancedSessionCorrelator::correlateByTeid(uint32_t teid) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Session> result;

    auto it = teid_index_.find(teid);
    if (it != teid_index_.end()) {
        for (const auto& session_id : it->second) {
            auto session_it = sessions_.find(session_id);
            if (session_it != sessions_.end()) {
                result.push_back(session_it->second);
            }
        }
    }

    return result;
}

std::vector<Session> EnhancedSessionCorrelator::correlateBySeid(uint64_t seid) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Session> result;

    auto it = seid_index_.find(seid);
    if (it != seid_index_.end()) {
        for (const auto& session_id : it->second) {
            auto session_it = sessions_.find(session_id);
            if (session_it != sessions_.end()) {
                result.push_back(session_it->second);
            }
        }
    }

    return result;
}

std::vector<Session> EnhancedSessionCorrelator::correlateByUeIp(const std::string& ue_ip) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Session> result;

    auto it = ue_ip_index_.find(ue_ip);
    if (it != ue_ip_index_.end()) {
        for (const auto& session_id : it->second) {
            auto session_it = sessions_.find(session_id);
            if (session_it != sessions_.end()) {
                result.push_back(session_it->second);
            }
        }
    }

    return result;
}

std::vector<Session> EnhancedSessionCorrelator::correlateByKey(
    const SessionCorrelationKey& key) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Session> result;
    std::unordered_set<std::string> found_session_ids;

    // Search all indices
    if (key.imsi.has_value()) {
        auto it = imsi_index_.find(key.imsi.value());
        if (it != imsi_index_.end()) {
            found_session_ids.insert(it->second.begin(), it->second.end());
        }
    }

    if (key.supi.has_value()) {
        auto it = supi_index_.find(key.supi.value());
        if (it != supi_index_.end()) {
            found_session_ids.insert(it->second.begin(), it->second.end());
        }
    }

    if (key.teid_s1u.has_value()) {
        auto it = teid_index_.find(key.teid_s1u.value());
        if (it != teid_index_.end()) {
            found_session_ids.insert(it->second.begin(), it->second.end());
        }
    }

    if (key.seid_n4.has_value()) {
        auto it = seid_index_.find(key.seid_n4.value());
        if (it != seid_index_.end()) {
            found_session_ids.insert(it->second.begin(), it->second.end());
        }
    }

    if (key.ue_ipv4.has_value()) {
        auto it = ue_ip_index_.find(key.ue_ipv4.value());
        if (it != ue_ip_index_.end()) {
            found_session_ids.insert(it->second.begin(), it->second.end());
        }
    }

    // Collect sessions
    for (const auto& session_id : found_session_ids) {
        auto session_it = sessions_.find(session_id);
        if (session_it != sessions_.end()) {
            result.push_back(session_it->second);
        }
    }

    return result;
}

std::optional<Session> EnhancedSessionCorrelator::getSession(const std::string& session_id) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = sessions_.find(session_id);
    if (it != sessions_.end()) {
        return it->second;
    }

    return std::nullopt;
}

std::vector<Session> EnhancedSessionCorrelator::getSessionsByType(EnhancedSessionType type) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Session> result;

    for (const auto& [session_id, session] : sessions_) {
        if (session.session_type == type) {
            result.push_back(session);
        }
    }

    return result;
}

std::vector<Session> EnhancedSessionCorrelator::getSessionsByInterface(
    InterfaceType interface) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Session> result;

    for (const auto& [session_id, session] : sessions_) {
        if (std::find(session.interfaces_involved.begin(), session.interfaces_involved.end(),
                      interface) != session.interfaces_involved.end()) {
            result.push_back(session);
        }
    }

    return result;
}

std::vector<SessionMessageRef> EnhancedSessionCorrelator::getSessionLegs(
    const std::string& identifier) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<SessionMessageRef> result;

    // Search by IMSI
    auto imsi_it = imsi_index_.find(identifier);
    if (imsi_it != imsi_index_.end()) {
        for (const auto& session_id : imsi_it->second) {
            auto session_it = sessions_.find(session_id);
            if (session_it != sessions_.end()) {
                auto msgs = session_it->second.getAllMessages();
                result.insert(result.end(), msgs.begin(), msgs.end());
            }
        }
    }

    // Search by SUPI
    auto supi_it = supi_index_.find(identifier);
    if (supi_it != supi_index_.end()) {
        for (const auto& session_id : supi_it->second) {
            auto session_it = sessions_.find(session_id);
            if (session_it != sessions_.end()) {
                auto msgs = session_it->second.getAllMessages();
                result.insert(result.end(), msgs.begin(), msgs.end());
            }
        }
    }

    // Sort by timestamp
    std::sort(result.begin(), result.end(),
              [](const SessionMessageRef& a, const SessionMessageRef& b) {
                  return a.timestamp < b.timestamp;
              });

    return result;
}

SessionStatistics EnhancedSessionCorrelator::getStatistics() const {
    std::lock_guard<std::mutex> lock(mutex_);

    SessionStatistics stats;
    stats.total_sessions = sessions_.size();
    stats.total_messages = 0;
    stats.total_bytes = 0;
    stats.average_session_duration_ms = 0.0;
    stats.average_setup_time_ms = 0.0;

    uint32_t sessions_with_setup_time = 0;
    double total_duration_ms = 0.0;
    double total_setup_time_ms = 0.0;

    for (const auto& [session_id, session] : sessions_) {
        // Count by type
        stats.sessions_by_type[session.session_type]++;

        // Count messages and bytes
        stats.total_messages += session.total_packets;
        stats.total_bytes += session.total_bytes;

        // Sum duration
        total_duration_ms += session.getDurationMs();

        // Sum setup time
        if (session.setup_time_ms.has_value()) {
            total_setup_time_ms += session.setup_time_ms.value();
            sessions_with_setup_time++;
        }

        // Count messages by interface
        for (const auto& leg : session.legs) {
            stats.messages_by_interface[leg.interface] += leg.messages.size();
        }
    }

    // Calculate averages
    if (stats.total_sessions > 0) {
        stats.average_session_duration_ms = total_duration_ms / stats.total_sessions;
    }
    if (sessions_with_setup_time > 0) {
        stats.average_setup_time_ms = total_setup_time_ms / sessions_with_setup_time;
    }

    return stats;
}

void EnhancedSessionCorrelator::clear() {
    std::lock_guard<std::mutex> lock(mutex_);

    sessions_.clear();
    imsi_index_.clear();
    supi_index_.clear();
    teid_index_.clear();
    seid_index_.clear();
    ue_ip_index_.clear();
    mme_ue_id_index_.clear();
    amf_ue_id_index_.clear();

    LOG_INFO("Session correlator cleared");
}

void EnhancedSessionCorrelator::finalize() {
    std::lock_guard<std::mutex> lock(mutex_);

    LOG_INFO("Finalizing " << sessions_.size() << " sessions");

    for (auto& [session_id, session] : sessions_) {
        session.finalize();

        // Detect session type
        session.session_type = detectSessionType(session);
    }

    LOG_INFO("Session finalization complete");
}

size_t EnhancedSessionCorrelator::getSessionCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return sessions_.size();
}

nlohmann::json EnhancedSessionCorrelator::exportToJson() const {
    std::lock_guard<std::mutex> lock(mutex_);

    nlohmann::json j = nlohmann::json::array();

    for (const auto& [session_id, session] : sessions_) {
        j.push_back(session.toJson());
    }

    return j;
}

// ============================================================================
// EnhancedSessionCorrelator Private Methods
// ============================================================================

std::optional<std::string> EnhancedSessionCorrelator::findMatchingSession(
    const SessionCorrelationKey& key) const {
    // Check if any existing session matches this correlation key
    for (const auto& [session_id, session] : sessions_) {
        if (session.correlation_key.matches(key)) {
            return session_id;
        }
    }

    return std::nullopt;
}

std::string EnhancedSessionCorrelator::createNewSession(const SessionMessageRef& msg) {
    Session new_session;
    new_session.session_id = generateSessionId();
    new_session.session_type = EnhancedSessionType::UNKNOWN;
    new_session.correlation_key = msg.correlation_key;
    new_session.start_time = msg.timestamp;
    new_session.end_time = msg.timestamp;
    new_session.total_packets = 0;
    new_session.total_bytes = 0;
    new_session.is_complete = false;

    // Add first message
    new_session.addMessage(msg);

    // Update indices
    updateIndices(new_session.session_id, msg.correlation_key);

    // Store session
    sessions_[new_session.session_id] = new_session;

    return new_session.session_id;
}

void EnhancedSessionCorrelator::addMessageToSession(const std::string& session_id,
                                                    const SessionMessageRef& msg) {
    auto it = sessions_.find(session_id);
    if (it == sessions_.end()) {
        LOG_ERROR("Session not found: " << session_id);
        return;
    }

    Session& session = it->second;
    session.addMessage(msg);

    // Update indices with new correlation keys
    updateIndices(session_id, msg.correlation_key);
}

void EnhancedSessionCorrelator::updateIndices(const std::string& session_id,
                                              const SessionCorrelationKey& key) {
    // Update IMSI index
    if (key.imsi.has_value()) {
        auto& sessions = imsi_index_[key.imsi.value()];
        if (std::find(sessions.begin(), sessions.end(), session_id) == sessions.end()) {
            sessions.push_back(session_id);
        }
    }

    // Update SUPI index
    if (key.supi.has_value()) {
        auto& sessions = supi_index_[key.supi.value()];
        if (std::find(sessions.begin(), sessions.end(), session_id) == sessions.end()) {
            sessions.push_back(session_id);
        }
    }

    // Update TEID indices
    if (key.teid_s1u.has_value()) {
        auto& sessions = teid_index_[key.teid_s1u.value()];
        if (std::find(sessions.begin(), sessions.end(), session_id) == sessions.end()) {
            sessions.push_back(session_id);
        }
    }
    if (key.teid_s5u.has_value()) {
        auto& sessions = teid_index_[key.teid_s5u.value()];
        if (std::find(sessions.begin(), sessions.end(), session_id) == sessions.end()) {
            sessions.push_back(session_id);
        }
    }

    // Update SEID index
    if (key.seid_n4.has_value()) {
        auto& sessions = seid_index_[key.seid_n4.value()];
        if (std::find(sessions.begin(), sessions.end(), session_id) == sessions.end()) {
            sessions.push_back(session_id);
        }
    }

    // Update UE IP indices
    if (key.ue_ipv4.has_value()) {
        auto& sessions = ue_ip_index_[key.ue_ipv4.value()];
        if (std::find(sessions.begin(), sessions.end(), session_id) == sessions.end()) {
            sessions.push_back(session_id);
        }
    }
    if (key.ue_ipv6.has_value()) {
        auto& sessions = ue_ip_index_[key.ue_ipv6.value()];
        if (std::find(sessions.begin(), sessions.end(), session_id) == sessions.end()) {
            sessions.push_back(session_id);
        }
    }

    // Update UE context ID indices
    if (key.mme_ue_s1ap_id.has_value()) {
        auto& sessions = mme_ue_id_index_[key.mme_ue_s1ap_id.value()];
        if (std::find(sessions.begin(), sessions.end(), session_id) == sessions.end()) {
            sessions.push_back(session_id);
        }
    }
    if (key.amf_ue_ngap_id.has_value()) {
        auto& sessions = amf_ue_id_index_[key.amf_ue_ngap_id.value()];
        if (std::find(sessions.begin(), sessions.end(), session_id) == sessions.end()) {
            sessions.push_back(session_id);
        }
    }
}

EnhancedSessionType EnhancedSessionCorrelator::detectSessionType(const Session& session) const {
    // Analyze message sequence to determine session type
    auto all_messages = session.getAllMessages();

    if (all_messages.empty()) {
        return EnhancedSessionType::UNKNOWN;
    }

    // Count message types
    bool has_s1ap = false;
    bool has_ngap = false;
    bool has_x2ap = false;
    bool has_gtp = false;
    bool has_pfcp = false;
    bool has_sip = false;
    bool has_rtp = false;

    bool has_attach_request = false;
    bool has_registration_request = false;
    bool has_pdu_session_establish = false;
    bool has_handover_request = false;

    for (const auto& msg : all_messages) {
        // Check protocols
        if (msg.interface == InterfaceType::S1_MME)
            has_s1ap = true;
        if (msg.interface == InterfaceType::N2)
            has_ngap = true;
        if (msg.interface == InterfaceType::X2)
            has_x2ap = true;
        if (msg.interface == InterfaceType::S1_U || msg.interface == InterfaceType::S11)
            has_gtp = true;
        if (msg.interface == InterfaceType::N4)
            has_pfcp = true;
        if (msg.interface == InterfaceType::IMS_SIP)
            has_sip = true;
        if (msg.interface == InterfaceType::IMS_RTP)
            has_rtp = true;

        // Check specific message types (would need proper message type enum extensions)
        // For now, use simplified detection
    }

    // Detect session type based on protocol combination
    if (has_sip && has_rtp) {
        return EnhancedSessionType::VOLTE_CALL;
    }

    if (has_x2ap) {
        return EnhancedSessionType::LTE_HANDOVER_X2;
    }

    if (has_ngap && has_pfcp) {
        if (session.legs.size() >= 2) {
            return EnhancedSessionType::G5_PDU_SESSION;
        }
        return EnhancedSessionType::G5_REGISTRATION;
    }

    if (has_s1ap && has_gtp) {
        if (session.legs.size() >= 3) {
            return EnhancedSessionType::LTE_ATTACH;
        }
        return EnhancedSessionType::LTE_PDN_CONNECT;
    }

    if (session.legs.size() > 1) {
        return EnhancedSessionType::MIXED;
    }

    return EnhancedSessionType::INCOMPLETE;
}

bool EnhancedSessionCorrelator::isSessionStartMessage(const SessionMessageRef& msg) const {
    // Check if this is a session start message
    switch (msg.message_type) {
        case MessageType::SIP_INVITE:
        case MessageType::NGAP_INITIAL_UE_MESSAGE:
        case MessageType::NAS5G_REGISTRATION_REQUEST:
        case MessageType::NAS5G_PDU_SESSION_ESTABLISHMENT_REQUEST:
        case MessageType::X2AP_HANDOVER_PREPARATION:
        case MessageType::NGAP_PDU_SESSION_RESOURCE_SETUP:
            return true;
        default:
            return false;
    }
}

bool EnhancedSessionCorrelator::isSessionEndMessage(const SessionMessageRef& msg) const {
    // Check if this is a session end message
    switch (msg.message_type) {
        case MessageType::SIP_BYE:
        case MessageType::NAS5G_DEREGISTRATION_REQUEST:
        case MessageType::NGAP_PDU_SESSION_RESOURCE_RELEASE:
        case MessageType::X2AP_UE_CONTEXT_RELEASE:
            return true;
        default:
            return false;
    }
}

std::string EnhancedSessionCorrelator::generateSessionId() const {
    // Generate UUID v4
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);
    std::uniform_int_distribution<> dis2(8, 11);

    std::stringstream ss;
    ss << std::hex;

    for (int i = 0; i < 8; i++) {
        ss << dis(gen);
    }
    ss << "-";
    for (int i = 0; i < 4; i++) {
        ss << dis(gen);
    }
    ss << "-4";
    for (int i = 0; i < 3; i++) {
        ss << dis(gen);
    }
    ss << "-";
    ss << dis2(gen);
    for (int i = 0; i < 3; i++) {
        ss << dis(gen);
    }
    ss << "-";
    for (int i = 0; i < 12; i++) {
        ss << dis(gen);
    }

    return ss.str();
}

void EnhancedSessionCorrelator::mergeSessions(const std::string& session_id1,
                                              const std::string& session_id2) {
    auto it1 = sessions_.find(session_id1);
    auto it2 = sessions_.find(session_id2);

    if (it1 == sessions_.end() || it2 == sessions_.end()) {
        LOG_ERROR("Cannot merge sessions: one or both not found");
        return;
    }

    Session& session1 = it1->second;
    Session& session2 = it2->second;

    // Merge session2 into session1
    for (const auto& leg : session2.legs) {
        for (const auto& msg : leg.messages) {
            session1.addMessage(msg);
        }
    }

    // Merge correlation keys
    session1.correlation_key.merge(session2.correlation_key);

    // Update indices
    updateIndices(session_id1, session2.correlation_key);

    // Remove session2
    sessions_.erase(session_id2);

    // TODO: Clean up indices that point to session_id2

    LOG_INFO("Merged session " << session_id2 << " into " << session_id1);
}

}  // namespace callflow

void callflow::EnhancedSessionCorrelator::processPacket(const PacketMetadata& packet,
                                                        ProtocolType protocol,
                                                        const nlohmann::json& parsed_data) {
    // 1. Extract correlation key
    // 1. Extract correlation key
    SessionCorrelationKey key = extractCorrelationKey(parsed_data, protocol);

    // 2. Identify interface type
    InterfaceType interface =
        detectInterfaceType(protocol, packet.five_tuple.src_port, packet.five_tuple.dst_port);
    if (interface == InterfaceType::UNKNOWN) {
        // Fallback or log?
        // Let's assume some default or skip if critical?
        // For now, proceed.
    }

    // 3. Determine message type
    MessageType message_type = MessageType::UNKNOWN;

    if (protocol == ProtocolType::SIP) {
        if (parsed_data.contains("is_request") && parsed_data["is_request"].get<bool>()) {
            std::string method = parsed_data.value("method", "UNKNOWN");
            if (method == "INVITE")
                message_type = MessageType::SIP_INVITE;
            else if (method == "ACK")
                message_type = MessageType::SIP_ACK;
            else if (method == "BYE")
                message_type = MessageType::SIP_BYE;
            else if (method == "REGISTER")
                message_type = MessageType::SIP_REGISTER;
            else if (method == "OPTIONS")
                message_type = MessageType::SIP_OPTIONS;
            else if (method == "PRACK")
                message_type = MessageType::SIP_PRACK;
            else if (method == "UPDATE")
                message_type = MessageType::SIP_UPDATE;
        } else {
            int status_code = parsed_data.value("status_code", 0);
            if (status_code == 100)
                message_type = MessageType::SIP_TRYING;
            else if (status_code == 180)
                message_type = MessageType::SIP_RINGING;
            else if (status_code == 200)
                message_type = MessageType::SIP_OK;
        }
    } else if (protocol == ProtocolType::DIAMETER) {
        if (parsed_data.contains("header") && parsed_data["header"].contains("command_code")) {
            uint32_t cmd_code = parsed_data["header"]["command_code"].get<uint32_t>();
            bool is_request = parsed_data["header"].value("request_flag", false);
            if (cmd_code == 272)
                message_type = is_request ? MessageType::DIAMETER_CCR : MessageType::DIAMETER_CCA;
            else if (cmd_code == 265)
                message_type = is_request ? MessageType::DIAMETER_AAR : MessageType::DIAMETER_AAA;
        }
    } else if (protocol == ProtocolType::GTP_C) {
        if (parsed_data.contains("header") && parsed_data["header"].contains("message_type")) {
            uint8_t msg_type = parsed_data["header"]["message_type"].get<uint8_t>();
            switch (msg_type) {
                case 32:
                    message_type = MessageType::GTP_CREATE_SESSION_REQ;
                    break;
                case 33:
                    message_type = MessageType::GTP_CREATE_SESSION_RESP;
                    break;
                case 36:
                    message_type = MessageType::GTP_DELETE_SESSION_REQ;
                    break;
                case 37:
                    message_type = MessageType::GTP_DELETE_SESSION_RESP;
                    break;
                case 1:
                    message_type = MessageType::GTP_ECHO_REQ;
                    break;
                case 2:
                    message_type = MessageType::GTP_ECHO_RESP;
                    break;
            }
        }
    } else if (protocol == ProtocolType::PFCP) {
        if (parsed_data.contains("header") && parsed_data["header"].contains("message_type")) {
            uint8_t msg_type = parsed_data["header"]["message_type"].get<uint8_t>();
            switch (msg_type) {
                case 50:
                    message_type = MessageType::PFCP_SESSION_ESTABLISHMENT_REQ;
                    break;
                case 51:
                    message_type = MessageType::PFCP_SESSION_ESTABLISHMENT_RESP;
                    break;
                case 52:
                    message_type = MessageType::PFCP_SESSION_MODIFICATION_REQ;
                    break;
                case 53:
                    message_type = MessageType::PFCP_SESSION_MODIFICATION_RESP;
                    break;
                case 54:
                    message_type = MessageType::PFCP_SESSION_DELETION_REQ;
                    break;
                case 55:
                    message_type = MessageType::PFCP_SESSION_DELETION_RESP;
                    break;
            }
        }
    }

    // 4. Create SessionMessageRef
    SessionMessageRef msg;
    msg.message_id = utils::generateUuid();
    msg.packet_id = packet.packet_id;
    msg.timestamp = packet.timestamp;
    msg.interface = interface;
    msg.protocol = protocol;
    msg.message_type = message_type;
    msg.correlation_key = key;
    msg.src_ip = packet.five_tuple.src_ip;
    msg.dst_ip = packet.five_tuple.dst_ip;
    msg.src_port = packet.five_tuple.src_port;
    msg.dst_port = packet.five_tuple.dst_port;

    // 5. Correlate to Session
    // 5. Correlate to Session
    addMessage(msg);
}

void callflow::EnhancedSessionCorrelator::finalizeSessions() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [id, session] : sessions_) {
        session.finalize();
    }
}

std::vector<std::shared_ptr<callflow::Session>>
callflow::EnhancedSessionCorrelator::getAllSessions() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::shared_ptr<Session>> result;
    result.reserve(sessions_.size());
    for (const auto& [id, session] : sessions_) {
        result.push_back(std::make_shared<Session>(session));
    }
    return result;
}
