#include "protocol_parsers/gtp/gtp_teid_manager.h"
#include "common/logger.h"
#include <chrono>

namespace callflow {
namespace gtp {

// ============================================================================
// GtpTunnel Methods
// ============================================================================

nlohmann::json GtpTunnel::toJson() const {
    nlohmann::json j;

    // TEID information
    j["teid_uplink"] = teid_uplink;
    j["teid_downlink"] = teid_downlink;
    j["teid_s5_sgw"] = teid_s5_sgw;
    j["teid_s5_pgw"] = teid_s5_pgw;

    // Subscriber information
    j["imsi"] = imsi;
    j["ue_ip"] = ue_ip;
    j["apn"] = apn;
    if (!msisdn.empty()) {
        j["msisdn"] = msisdn;
    }

    // Session information
    j["session_id"] = session_id;
    j["eps_bearer_id"] = eps_bearer_id;
    j["qci"] = qci;

    // Network information
    if (!serving_network.empty()) {
        j["serving_network"] = serving_network;
    }
    if (!rat_type.empty()) {
        j["rat_type"] = rat_type;
    }

    // Timestamps
    j["created_timestamp"] = created_timestamp;
    j["last_activity_timestamp"] = last_activity_timestamp;

    return j;
}

// ============================================================================
// GtpTEIDManager Methods
// ============================================================================

void GtpTEIDManager::registerTunnel(const GtpTunnel& tunnel) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Use uplink TEID as primary key (most common for GTP-U correlation)
    uint32_t primary_teid = tunnel.teid_uplink;
    if (primary_teid == 0) {
        primary_teid = tunnel.teid_downlink;
    }

    if (primary_teid == 0) {
        LOG_WARNING("Cannot register tunnel with zero TEID");
        return;
    }

    // Check if tunnel already exists
    auto it = teid_to_tunnel_.find(primary_teid);
    if (it != teid_to_tunnel_.end()) {
        LOG_DEBUG("Updating existing tunnel for TEID 0x" << std::hex << primary_teid << std::dec);
    } else {
        LOG_DEBUG("Registering new tunnel for TEID 0x" << std::hex << primary_teid << std::dec
                  << ", IMSI=" << tunnel.imsi
                  << ", UE IP=" << tunnel.ue_ip
                  << ", APN=" << tunnel.apn);
        total_tunnels_created_++;
    }

    // Store tunnel
    teid_to_tunnel_[primary_teid] = tunnel;

    // Also store downlink TEID if different
    if (tunnel.teid_downlink != 0 && tunnel.teid_downlink != primary_teid) {
        teid_to_tunnel_[tunnel.teid_downlink] = tunnel;
    }

    // Store S5/S8 TEIDs
    if (tunnel.teid_s5_sgw != 0 && tunnel.teid_s5_sgw != primary_teid) {
        teid_to_tunnel_[tunnel.teid_s5_sgw] = tunnel;
    }
    if (tunnel.teid_s5_pgw != 0 && tunnel.teid_s5_pgw != primary_teid) {
        teid_to_tunnel_[tunnel.teid_s5_pgw] = tunnel;
    }

    // Update secondary indexes
    if (!tunnel.imsi.empty()) {
        imsi_to_teid_[tunnel.imsi] = primary_teid;
    }
    if (!tunnel.ue_ip.empty()) {
        ue_ip_to_teid_[tunnel.ue_ip] = primary_teid;
    }
    if (!tunnel.session_id.empty()) {
        session_id_to_teid_[tunnel.session_id] = primary_teid;
    }
}

void GtpTEIDManager::updateTunnel(uint32_t teid, const GtpTunnel& tunnel) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = teid_to_tunnel_.find(teid);
    if (it == teid_to_tunnel_.end()) {
        LOG_WARNING("Cannot update non-existent tunnel for TEID 0x" << std::hex << teid << std::dec);
        return;
    }

    LOG_DEBUG("Updating tunnel for TEID 0x" << std::hex << teid << std::dec);
    it->second = tunnel;

    // Update secondary indexes
    if (!tunnel.imsi.empty()) {
        imsi_to_teid_[tunnel.imsi] = teid;
    }
    if (!tunnel.ue_ip.empty()) {
        ue_ip_to_teid_[tunnel.ue_ip] = teid;
    }
    if (!tunnel.session_id.empty()) {
        session_id_to_teid_[tunnel.session_id] = teid;
    }
}

void GtpTEIDManager::deleteTunnel(uint32_t teid) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = teid_to_tunnel_.find(teid);
    if (it == teid_to_tunnel_.end()) {
        LOG_DEBUG("Tunnel for TEID 0x" << std::hex << teid << std::dec << " not found");
        return;
    }

    LOG_DEBUG("Deleting tunnel for TEID 0x" << std::hex << teid << std::dec);

    const GtpTunnel& tunnel = it->second;

    // Remove from secondary indexes
    if (!tunnel.imsi.empty()) {
        imsi_to_teid_.erase(tunnel.imsi);
    }
    if (!tunnel.ue_ip.empty()) {
        ue_ip_to_teid_.erase(tunnel.ue_ip);
    }
    if (!tunnel.session_id.empty()) {
        session_id_to_teid_.erase(tunnel.session_id);
    }

    // Remove all TEID entries for this tunnel
    teid_to_tunnel_.erase(tunnel.teid_uplink);
    teid_to_tunnel_.erase(tunnel.teid_downlink);
    teid_to_tunnel_.erase(tunnel.teid_s5_sgw);
    teid_to_tunnel_.erase(tunnel.teid_s5_pgw);

    total_tunnels_deleted_++;
}

std::optional<GtpTunnel> GtpTEIDManager::findByTEID(uint32_t teid) const {
    std::lock_guard<std::mutex> lock(mutex_);
    total_lookups_++;

    auto it = teid_to_tunnel_.find(teid);
    if (it != teid_to_tunnel_.end()) {
        total_lookup_hits_++;
        return it->second;
    }

    return std::nullopt;
}

std::optional<GtpTunnel> GtpTEIDManager::findByIMSI(const std::string& imsi) const {
    std::lock_guard<std::mutex> lock(mutex_);
    total_lookups_++;

    auto it = imsi_to_teid_.find(imsi);
    if (it != imsi_to_teid_.end()) {
        auto tunnel_it = teid_to_tunnel_.find(it->second);
        if (tunnel_it != teid_to_tunnel_.end()) {
            total_lookup_hits_++;
            return tunnel_it->second;
        }
    }

    return std::nullopt;
}

std::optional<GtpTunnel> GtpTEIDManager::findByUEIP(const std::string& ue_ip) const {
    std::lock_guard<std::mutex> lock(mutex_);
    total_lookups_++;

    auto it = ue_ip_to_teid_.find(ue_ip);
    if (it != ue_ip_to_teid_.end()) {
        auto tunnel_it = teid_to_tunnel_.find(it->second);
        if (tunnel_it != teid_to_tunnel_.end()) {
            total_lookup_hits_++;
            return tunnel_it->second;
        }
    }

    return std::nullopt;
}

std::optional<GtpTunnel> GtpTEIDManager::findBySessionID(const std::string& session_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    total_lookups_++;

    auto it = session_id_to_teid_.find(session_id);
    if (it != session_id_to_teid_.end()) {
        auto tunnel_it = teid_to_tunnel_.find(it->second);
        if (tunnel_it != teid_to_tunnel_.end()) {
            total_lookup_hits_++;
            return tunnel_it->second;
        }
    }

    return std::nullopt;
}

std::vector<GtpTunnel> GtpTEIDManager::getAllTunnels() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<GtpTunnel> tunnels;
    tunnels.reserve(teid_to_tunnel_.size());

    for (const auto& [teid, tunnel] : teid_to_tunnel_) {
        tunnels.push_back(tunnel);
    }

    return tunnels;
}

size_t GtpTEIDManager::getTunnelCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return teid_to_tunnel_.size();
}

void GtpTEIDManager::clear() {
    std::lock_guard<std::mutex> lock(mutex_);

    LOG_INFO("Clearing all GTP tunnels (count=" << teid_to_tunnel_.size() << ")");

    teid_to_tunnel_.clear();
    imsi_to_teid_.clear();
    ue_ip_to_teid_.clear();
    session_id_to_teid_.clear();
}

nlohmann::json GtpTEIDManager::getStatistics() const {
    std::lock_guard<std::mutex> lock(mutex_);

    nlohmann::json j;
    j["active_tunnels"] = teid_to_tunnel_.size();
    j["total_tunnels_created"] = total_tunnels_created_;
    j["total_tunnels_deleted"] = total_tunnels_deleted_;
    j["total_lookups"] = total_lookups_;
    j["total_lookup_hits"] = total_lookup_hits_;

    if (total_lookups_ > 0) {
        j["lookup_hit_rate"] = static_cast<double>(total_lookup_hits_) / static_cast<double>(total_lookups_);
    } else {
        j["lookup_hit_rate"] = 0.0;
    }

    return j;
}

}  // namespace gtp
}  // namespace callflow
