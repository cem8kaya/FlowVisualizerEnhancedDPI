#include "correlation/tunnel_manager.h"
#include "common/logger.h"
#include "common/types.h"
#include <algorithm>

namespace callflow {

TunnelManager::TunnelManager(const Config& config)
    : config_(config) {
}

void TunnelManager::processMessage(const SessionMessageRef& msg) {
    switch (msg.message_type) {
        case MessageType::GTP_CREATE_SESSION_REQ:
            createTunnel(msg);
            break;

        case MessageType::GTP_CREATE_SESSION_RESP:
            activateTunnel(msg);
            break;

        case MessageType::GTP_DELETE_SESSION_REQ:
        case MessageType::GTP_DELETE_SESSION_RESP:
            deleteTunnel(msg);
            break;

        case MessageType::GTP_MODIFY_BEARER_REQ:
        case MessageType::GTP_MODIFY_BEARER_RESP:
            modifyTunnel(msg);
            if (config_.enable_handover_detection) {
                detectHandover(msg);
            }
            break;

        case MessageType::GTP_ECHO_REQ:
            handleEchoRequest(msg);
            break;

        case MessageType::GTP_ECHO_RESP:
            handleEchoResponse(msg);
            break;

        default:
            // Not a GTP control message we care about
            break;
    }
}

void TunnelManager::createTunnel(const SessionMessageRef& msg) {
    auto teid_opt = extractTeid(msg);
    if (!teid_opt.has_value()) {
        LOG_WARN("Create Session Request without TEID");
        return;
    }

    uint32_t teid = *teid_opt;

    std::lock_guard<std::mutex> lock(mutex_);

    // Check if tunnel already exists
    if (tunnels_.find(teid) != tunnels_.end()) {
        LOG_WARN("Tunnel 0x{:08x} already exists", teid);
        return;
    }

    // Check max tunnels limit
    if (tunnels_.size() >= config_.max_tunnels) {
        LOG_ERROR("Max tunnels limit reached: {}", config_.max_tunnels);
        return;
    }

    GtpTunnel tunnel;
    tunnel.teid_uplink = teid;
    tunnel.state = TunnelState::CREATING;
    tunnel.created = msg.timestamp;
    tunnel.last_activity = msg.timestamp;

    // Extract identifiers
    if (msg.correlation_key.imsi.has_value()) {
        tunnel.imsi = *msg.correlation_key.imsi;
    }

    if (msg.correlation_key.apn.has_value()) {
        tunnel.apn = *msg.correlation_key.apn;
    }

    if (msg.correlation_key.ue_ipv4.has_value()) {
        tunnel.ue_ip_v4 = *msg.correlation_key.ue_ipv4;
    }

    if (msg.correlation_key.ue_ipv6.has_value()) {
        tunnel.ue_ip_v6 = *msg.correlation_key.ue_ipv6;
    }

    if (msg.correlation_key.eps_bearer_id.has_value()) {
        tunnel.eps_bearer_id = *msg.correlation_key.eps_bearer_id;
    }

    // Extract QCI from parsed data
    if (msg.parsed_data.contains("bearer_contexts") &&
        msg.parsed_data["bearer_contexts"].is_array() &&
        !msg.parsed_data["bearer_contexts"].empty()) {

        auto& bearer = msg.parsed_data["bearer_contexts"][0];
        if (bearer.contains("qci")) {
            tunnel.qci = bearer["qci"].get<uint8_t>();
        }
    }

    tunnels_[teid] = tunnel;
    updateIndices(teid, tunnel);

    LOG_INFO("Tunnel created: 0x{:08x}, IMSI={}, APN={}",
             teid, tunnel.imsi, tunnel.apn);
}

void TunnelManager::activateTunnel(const SessionMessageRef& msg) {
    auto teid_pair_opt = extractTeidPair(msg);
    if (!teid_pair_opt.has_value()) {
        LOG_WARN("Create Session Response without TEID pair");
        return;
    }

    uint32_t teid_uplink = teid_pair_opt->uplink;
    uint32_t teid_downlink = teid_pair_opt->downlink;

    std::lock_guard<std::mutex> lock(mutex_);

    auto it = tunnels_.find(teid_uplink);
    if (it == tunnels_.end()) {
        LOG_WARN("Tunnel 0x{:08x} not found for activation", teid_uplink);
        return;
    }

    auto& tunnel = it->second;
    tunnel.teid_downlink = teid_downlink;
    tunnel.state = TunnelState::ACTIVE;
    tunnel.last_activity = msg.timestamp;

    // Update UE IP if not already set
    if (tunnel.ue_ip_v4.empty() && msg.correlation_key.ue_ipv4.has_value()) {
        tunnel.ue_ip_v4 = *msg.correlation_key.ue_ipv4;
        // Update IP index
        ue_ip_index_[tunnel.ue_ip_v4].push_back(teid_uplink);
    }

    if (tunnel.ue_ip_v6.empty() && msg.correlation_key.ue_ipv6.has_value()) {
        tunnel.ue_ip_v6 = *msg.correlation_key.ue_ipv6;
        ue_ip_index_[tunnel.ue_ip_v6].push_back(teid_uplink);
    }

    LOG_INFO("Tunnel activated: 0x{:08x}, downlink=0x{:08x}, UE IP={}",
             teid_uplink, teid_downlink,
             !tunnel.ue_ip_v4.empty() ? tunnel.ue_ip_v4 : tunnel.ue_ip_v6);
}

void TunnelManager::deleteTunnel(const SessionMessageRef& msg) {
    auto teid_opt = extractTeid(msg);
    if (!teid_opt.has_value()) {
        LOG_WARN("Delete Session without TEID");
        return;
    }

    uint32_t teid = *teid_opt;

    std::lock_guard<std::mutex> lock(mutex_);

    auto it = tunnels_.find(teid);
    if (it == tunnels_.end()) {
        LOG_WARN("Tunnel 0x{:08x} not found for deletion", teid);
        return;
    }

    auto& tunnel = it->second;

    if (msg.message_type == MessageType::GTP_DELETE_SESSION_REQ) {
        tunnel.state = TunnelState::DELETING;
    } else {
        tunnel.state = TunnelState::DELETED;
        tunnel.deleted = msg.timestamp;

        // Finalize keep-alive aggregation
        keepalive_aggregator_.finalizeTunnel(teid);

        LOG_INFO("Tunnel deleted: 0x{:08x}, duration={:.2f}h",
                 teid, tunnel.getDurationHours());
    }

    tunnel.last_activity = msg.timestamp;
}

void TunnelManager::modifyTunnel(const SessionMessageRef& msg) {
    auto teid_opt = extractTeid(msg);
    if (!teid_opt.has_value()) {
        return;
    }

    uint32_t teid = *teid_opt;

    std::lock_guard<std::mutex> lock(mutex_);

    auto it = tunnels_.find(teid);
    if (it == tunnels_.end()) {
        return;
    }

    auto& tunnel = it->second;

    if (msg.message_type == MessageType::GTP_MODIFY_BEARER_REQ) {
        tunnel.state = TunnelState::MODIFYING;
    } else {
        tunnel.state = TunnelState::ACTIVE;
    }

    tunnel.last_activity = msg.timestamp;
}

void TunnelManager::handleEchoRequest(const SessionMessageRef& msg) {
    auto teid_opt = extractTeid(msg);
    if (!teid_opt.has_value()) {
        return;
    }

    uint32_t teid = *teid_opt;

    keepalive_aggregator_.addEchoRequest(teid, msg.timestamp);

    std::lock_guard<std::mutex> lock(mutex_);

    auto it = tunnels_.find(teid);
    if (it != tunnels_.end()) {
        auto& tunnel = it->second;
        tunnel.echo_request_count++;
        tunnel.last_echo_request = msg.timestamp;
        tunnel.last_activity = msg.timestamp;

        // Calculate interval
        if (tunnel.echo_request_count > 1) {
            auto interval = std::chrono::duration_cast<std::chrono::seconds>(
                msg.timestamp - tunnel.last_echo_request);
            tunnel.echo_interval = interval;
        }
    }
}

void TunnelManager::handleEchoResponse(const SessionMessageRef& msg) {
    auto teid_opt = extractTeid(msg);
    if (!teid_opt.has_value()) {
        return;
    }

    uint32_t teid = *teid_opt;

    keepalive_aggregator_.addEchoResponse(teid, msg.timestamp);

    std::lock_guard<std::mutex> lock(mutex_);

    auto it = tunnels_.find(teid);
    if (it != tunnels_.end()) {
        auto& tunnel = it->second;
        tunnel.echo_response_count++;
        tunnel.last_echo_response = msg.timestamp;
        tunnel.last_activity = msg.timestamp;
    }
}

void TunnelManager::handleUserData(uint32_t teid, bool is_uplink, uint32_t bytes,
                                    const std::chrono::system_clock::time_point& ts) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = tunnels_.find(teid);
    if (it == tunnels_.end()) {
        return;
    }

    auto& tunnel = it->second;

    if (is_uplink) {
        tunnel.uplink_packets++;
        tunnel.uplink_bytes += bytes;
    } else {
        tunnel.downlink_packets++;
        tunnel.downlink_bytes += bytes;
    }

    tunnel.last_activity = ts;
}

std::optional<GtpTunnel> TunnelManager::getTunnel(uint32_t teid) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = tunnels_.find(teid);
    if (it == tunnels_.end()) {
        return std::nullopt;
    }

    return it->second;
}

std::vector<GtpTunnel> TunnelManager::getTunnelsByImsi(const std::string& imsi) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<GtpTunnel> result;

    auto it = imsi_index_.find(imsi);
    if (it != imsi_index_.end()) {
        for (uint32_t teid : it->second) {
            auto tunnel_it = tunnels_.find(teid);
            if (tunnel_it != tunnels_.end()) {
                result.push_back(tunnel_it->second);
            }
        }
    }

    return result;
}

std::vector<GtpTunnel> TunnelManager::getTunnelsByUeIp(const std::string& ue_ip) const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<GtpTunnel> result;

    auto it = ue_ip_index_.find(ue_ip);
    if (it != ue_ip_index_.end()) {
        for (uint32_t teid : it->second) {
            auto tunnel_it = tunnels_.find(teid);
            if (tunnel_it != tunnels_.end()) {
                result.push_back(tunnel_it->second);
            }
        }
    }

    return result;
}

std::vector<GtpTunnel> TunnelManager::getActiveTunnels() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<GtpTunnel> result;

    for (const auto& [teid, tunnel] : tunnels_) {
        if (tunnel.isActive()) {
            result.push_back(tunnel);
        }
    }

    return result;
}

std::vector<GtpTunnel> TunnelManager::getAllTunnels() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<GtpTunnel> result;

    for (const auto& [teid, tunnel] : tunnels_) {
        result.push_back(tunnel);
    }

    return result;
}

void TunnelManager::checkTimeouts() {
    std::lock_guard<std::mutex> lock(mutex_);

    auto now = std::chrono::system_clock::now();

    for (auto& [teid, tunnel] : tunnels_) {
        if (tunnel.state == TunnelState::ACTIVE ||
            tunnel.state == TunnelState::MODIFYING) {

            // Check activity timeout
            auto idle_time = std::chrono::duration_cast<std::chrono::seconds>(
                now - tunnel.last_activity);

            if (idle_time > config_.activity_timeout) {
                LOG_INFO("Tunnel 0x{:08x} idle for {}s, marking inactive",
                        teid, idle_time.count());
                tunnel.state = TunnelState::INACTIVE;
            }

            // Check echo timeout
            if (tunnel.echo_interval.count() > 0 &&
                tunnel.last_echo_response.time_since_epoch().count() > 0) {

                auto echo_idle = std::chrono::duration_cast<std::chrono::seconds>(
                    now - tunnel.last_echo_response);

                auto echo_timeout = tunnel.echo_interval * config_.echo_timeout_multiplier.count();

                if (echo_idle > echo_timeout) {
                    LOG_WARN("Tunnel 0x{:08x} echo timeout: {}s since last response",
                            teid, echo_idle.count());
                }
            }
        }
    }
}

nlohmann::json TunnelManager::getTunnelVisualization(uint32_t teid) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = tunnels_.find(teid);
    if (it == tunnels_.end()) {
        return nlohmann::json::object();
    }

    const auto& tunnel = it->second;

    auto j = tunnel.toJson();

    // Add event timeline
    auto events = generateEventTimeline(tunnel);
    nlohmann::json events_array = nlohmann::json::array();

    for (const auto& event : events) {
        events_array.push_back(event.toJson());
    }

    j["events"] = events_array;

    return j;
}

nlohmann::json TunnelManager::getImsiVisualization(const std::string& imsi) const {
    std::lock_guard<std::mutex> lock(mutex_);

    nlohmann::json result = nlohmann::json::array();

    auto it = imsi_index_.find(imsi);
    if (it != imsi_index_.end()) {
        for (uint32_t teid : it->second) {
            auto tunnel_it = tunnels_.find(teid);
            if (tunnel_it != tunnels_.end()) {
                const auto& tunnel = tunnel_it->second;
                auto j = tunnel.toJson();

                // Add event timeline
                auto events = generateEventTimeline(tunnel);
                nlohmann::json events_array = nlohmann::json::array();

                for (const auto& event : events) {
                    events_array.push_back(event.toJson());
                }

                j["events"] = events_array;
                result.push_back(j);
            }
        }
    }

    return result;
}

TunnelManager::Statistics TunnelManager::getStatistics() const {
    std::lock_guard<std::mutex> lock(mutex_);

    Statistics stats;
    stats.total_tunnels = tunnels_.size();

    for (const auto& [teid, tunnel] : tunnels_) {
        if (tunnel.isActive()) {
            stats.active_tunnels++;
        }
        if (tunnel.state == TunnelState::DELETED) {
            stats.deleted_tunnels++;
        }
        stats.handovers_detected += tunnel.handovers.size();
        stats.echo_requests += tunnel.echo_request_count;
        stats.echo_responses += tunnel.echo_response_count;
        stats.total_uplink_bytes += tunnel.uplink_bytes;
        stats.total_downlink_bytes += tunnel.downlink_bytes;
    }

    return stats;
}

void TunnelManager::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    tunnels_.clear();
    imsi_index_.clear();
    ue_ip_index_.clear();
    keepalive_aggregator_.clear();
}

void TunnelManager::setHandoverCallback(HandoverCallback callback) {
    handover_callback_ = std::move(callback);
}

std::optional<uint32_t> TunnelManager::extractTeid(const SessionMessageRef& msg) const {
    // Try correlation key first
    if (msg.correlation_key.teid_s1u.has_value()) {
        return *msg.correlation_key.teid_s1u;
    }

    // Try parsed data
    if (msg.parsed_data.contains("teid")) {
        return msg.parsed_data["teid"].get<uint32_t>();
    }

    if (msg.parsed_data.contains("teid_c")) {
        return msg.parsed_data["teid_c"].get<uint32_t>();
    }

    return std::nullopt;
}

std::optional<TunnelManager::TeidPair> TunnelManager::extractTeidPair(
    const SessionMessageRef& msg) const {

    TeidPair pair{0, 0};
    bool found_uplink = false;
    bool found_downlink = false;

    // Extract from bearer contexts
    if (msg.parsed_data.contains("bearer_contexts") &&
        msg.parsed_data["bearer_contexts"].is_array() &&
        !msg.parsed_data["bearer_contexts"].empty()) {

        auto& bearer = msg.parsed_data["bearer_contexts"][0];

        if (bearer.contains("s1u_enb_fteid")) {
            auto& fteid = bearer["s1u_enb_fteid"];
            if (fteid.contains("teid")) {
                pair.uplink = fteid["teid"].get<uint32_t>();
                found_uplink = true;
            }
        }

        if (bearer.contains("s1u_sgw_fteid")) {
            auto& fteid = bearer["s1u_sgw_fteid"];
            if (fteid.contains("teid")) {
                pair.downlink = fteid["teid"].get<uint32_t>();
                found_downlink = true;
            }
        }
    }

    if (found_uplink && found_downlink) {
        return pair;
    }

    return std::nullopt;
}

std::optional<std::string> TunnelManager::extractImsi(const SessionMessageRef& msg) const {
    if (msg.correlation_key.imsi.has_value()) {
        return *msg.correlation_key.imsi;
    }

    if (msg.parsed_data.contains("imsi")) {
        return msg.parsed_data["imsi"].get<std::string>();
    }

    return std::nullopt;
}

std::optional<uint32_t> TunnelManager::findTunnelByImsi(const std::string& imsi) const {
    auto it = imsi_index_.find(imsi);
    if (it != imsi_index_.end() && !it->second.empty()) {
        // Return the most recent (last) tunnel
        return it->second.back();
    }
    return std::nullopt;
}

void TunnelManager::detectHandover(const SessionMessageRef& msg) {
    if (msg.message_type != MessageType::GTP_MODIFY_BEARER_RESP) {
        return;
    }

    auto new_teid_pair = extractTeidPair(msg);
    auto imsi_opt = extractImsi(msg);

    if (!new_teid_pair.has_value() || !imsi_opt.has_value()) {
        return;
    }

    uint32_t new_teid = new_teid_pair->uplink;
    std::string imsi = *imsi_opt;

    std::lock_guard<std::mutex> lock(mutex_);

    // Find existing tunnel with same IMSI
    auto old_teid_opt = findTunnelByImsi(imsi);
    if (!old_teid_opt.has_value()) {
        return;
    }

    uint32_t old_teid = *old_teid_opt;

    // Check if TEID actually changed
    if (old_teid == new_teid) {
        return;  // Not a handover, just a modify
    }

    auto old_tunnel_it = tunnels_.find(old_teid);
    if (old_tunnel_it == tunnels_.end()) {
        return;
    }

    auto& old_tunnel = old_tunnel_it->second;

    // Handover detected!
    HandoverEvent handover;
    handover.timestamp = msg.timestamp;
    handover.old_teid_uplink = old_teid;
    handover.new_teid_uplink = new_teid;
    handover.handover_type = "X2";  // Default, could be refined

    // Extract eNB IPs if available
    if (msg.parsed_data.contains("bearer_contexts") &&
        msg.parsed_data["bearer_contexts"].is_array() &&
        !msg.parsed_data["bearer_contexts"].empty()) {

        auto& bearer = msg.parsed_data["bearer_contexts"][0];

        if (bearer.contains("s1u_enb_fteid") &&
            bearer["s1u_enb_fteid"].contains("ipv4")) {
            handover.new_enb_ip = bearer["s1u_enb_fteid"]["ipv4"].get<std::string>();
        }
    }

    // Calculate interruption time
    handover.interruption_time = calculateInterruptionTime(old_teid, new_teid);

    old_tunnel.handovers.push_back(handover);

    LOG_INFO("Handover detected: 0x{:08x} -> 0x{:08x}, IMSI={}, interruption={}ms",
             old_teid, new_teid, imsi, handover.interruption_time.count());

    // Create new tunnel from handover
    createTunnelFromHandover(old_tunnel, new_teid, handover);

    // Invoke callback if set
    if (handover_callback_) {
        handover_callback_(handover, old_tunnel);
    }
}

std::chrono::milliseconds TunnelManager::calculateInterruptionTime(
    uint32_t old_teid, uint32_t new_teid) const {

    // Find last activity on old TEID and first activity on new TEID
    auto old_it = tunnels_.find(old_teid);
    auto new_it = tunnels_.find(new_teid);

    if (old_it == tunnels_.end() || new_it == tunnels_.end()) {
        return std::chrono::milliseconds{0};
    }

    auto& old_tunnel = old_it->second;
    auto& new_tunnel = new_it->second;

    // Calculate interruption
    auto interruption = std::chrono::duration_cast<std::chrono::milliseconds>(
        new_tunnel.created - old_tunnel.last_activity);

    return interruption;
}

void TunnelManager::createTunnelFromHandover(const GtpTunnel& old_tunnel,
                                              uint32_t new_teid,
                                              const HandoverEvent& handover) {
    GtpTunnel new_tunnel;
    new_tunnel.teid_uplink = new_teid;
    new_tunnel.imsi = old_tunnel.imsi;
    new_tunnel.ue_ip_v4 = old_tunnel.ue_ip_v4;
    new_tunnel.ue_ip_v6 = old_tunnel.ue_ip_v6;
    new_tunnel.apn = old_tunnel.apn;
    new_tunnel.eps_bearer_id = old_tunnel.eps_bearer_id;
    new_tunnel.qci = old_tunnel.qci;
    new_tunnel.state = TunnelState::ACTIVE;
    new_tunnel.created = handover.timestamp;
    new_tunnel.last_activity = handover.timestamp;
    new_tunnel.viz_mode = old_tunnel.viz_mode;

    tunnels_[new_teid] = new_tunnel;
    updateIndices(new_teid, new_tunnel);

    LOG_DEBUG("Created new tunnel from handover: 0x{:08x}", new_teid);
}

void TunnelManager::updateIndices(uint32_t teid, const GtpTunnel& tunnel) {
    if (!tunnel.imsi.empty()) {
        imsi_index_[tunnel.imsi].push_back(teid);
    }

    if (!tunnel.ue_ip_v4.empty()) {
        ue_ip_index_[tunnel.ue_ip_v4].push_back(teid);
    }

    if (!tunnel.ue_ip_v6.empty()) {
        ue_ip_index_[tunnel.ue_ip_v6].push_back(teid);
    }
}

void TunnelManager::removeFromIndices(uint32_t teid, const GtpTunnel& tunnel) {
    auto remove_from_vector = [teid](std::vector<uint32_t>& vec) {
        vec.erase(std::remove(vec.begin(), vec.end(), teid), vec.end());
    };

    if (!tunnel.imsi.empty()) {
        auto it = imsi_index_.find(tunnel.imsi);
        if (it != imsi_index_.end()) {
            remove_from_vector(it->second);
        }
    }

    if (!tunnel.ue_ip_v4.empty()) {
        auto it = ue_ip_index_.find(tunnel.ue_ip_v4);
        if (it != ue_ip_index_.end()) {
            remove_from_vector(it->second);
        }
    }

    if (!tunnel.ue_ip_v6.empty()) {
        auto it = ue_ip_index_.find(tunnel.ue_ip_v6);
        if (it != ue_ip_index_.end()) {
            remove_from_vector(it->second);
        }
    }
}

std::vector<TunnelEvent> TunnelManager::generateEventTimeline(const GtpTunnel& tunnel) const {
    std::vector<TunnelEvent> events;

    // Create event
    TunnelEvent create_event;
    create_event.type = TunnelEvent::Type::CREATE;
    create_event.timestamp = tunnel.created;
    create_event.message = "GTP Create Session";
    events.push_back(create_event);

    // Keep-alive aggregations
    if (tunnel.viz_mode == GtpTunnel::VisualizationMode::AGGREGATED ||
        tunnel.viz_mode == GtpTunnel::VisualizationMode::FULL) {

        auto aggregations = keepalive_aggregator_.getAggregatedKeepalives(tunnel.teid_uplink);
        for (const auto& agg : aggregations) {
            TunnelEvent ka_event;
            ka_event.type = TunnelEvent::Type::KEEPALIVE_AGGREGATED;
            ka_event.timestamp = agg.start_time;
            ka_event.message = "Session active (" + std::to_string(agg.echo_count) +
                              " keep-alives over " + std::to_string(agg.getDurationHours()) + " hours)";
            ka_event.details = agg.toJson();
            events.push_back(ka_event);
        }
    }

    // Handover events
    for (const auto& handover : tunnel.handovers) {
        TunnelEvent ho_event;
        ho_event.type = TunnelEvent::Type::HANDOVER;
        ho_event.timestamp = handover.timestamp;
        ho_event.message = handover.handover_type + " Handover";
        ho_event.details = handover.toJson();
        events.push_back(ho_event);
    }

    // Delete event
    if (tunnel.deleted.has_value()) {
        TunnelEvent delete_event;
        delete_event.type = TunnelEvent::Type::DELETE;
        delete_event.timestamp = *tunnel.deleted;
        delete_event.message = "GTP Delete Session";
        events.push_back(delete_event);
    }

    // Sort events by timestamp
    std::sort(events.begin(), events.end(),
              [](const TunnelEvent& a, const TunnelEvent& b) {
                  return a.timestamp < b.timestamp;
              });

    return events;
}

} // namespace callflow
