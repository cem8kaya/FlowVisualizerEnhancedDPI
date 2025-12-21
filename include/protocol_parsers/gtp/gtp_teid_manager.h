#pragma once

#include <cstdint>
#include <string>
#include <optional>
#include <unordered_map>
#include <mutex>
#include <nlohmann/json.hpp>

namespace callflow {
namespace gtp {

/**
 * GTP Tunnel information for correlation between control and user plane
 */
struct GtpTunnel {
    // TEID values for correlation
    uint32_t teid_uplink;      // S1-U S-GW TEID (UE → Network)
    uint32_t teid_downlink;    // S1-U eNodeB TEID (Network → UE)
    uint32_t teid_s5_sgw;      // S5/S8 S-GW TEID
    uint32_t teid_s5_pgw;      // S5/S8 P-GW TEID

    // Subscriber information
    std::string imsi;
    std::string ue_ip;
    std::string apn;
    std::string msisdn;

    // Session information
    std::string session_id;
    uint8_t eps_bearer_id;
    uint8_t qci;

    // Network information
    std::string serving_network;  // PLMN ID
    std::string rat_type;

    // Timestamp
    uint64_t created_timestamp;
    uint64_t last_activity_timestamp;

    nlohmann::json toJson() const;
};

/**
 * GTP TEID Manager
 * Manages TEID-to-session correlation for GTPv2-C and GTP-U
 * Thread-safe for concurrent access
 */
class GtpTEIDManager {
public:
    GtpTEIDManager() = default;
    ~GtpTEIDManager() = default;

    /**
     * Register a new GTP tunnel
     * Called when processing Create Session Response
     * @param tunnel Tunnel information
     */
    void registerTunnel(const GtpTunnel& tunnel);

    /**
     * Update tunnel information
     * Called when processing Modify Bearer Request/Response
     * @param teid TEID to update
     * @param tunnel Updated tunnel information
     */
    void updateTunnel(uint32_t teid, const GtpTunnel& tunnel);

    /**
     * Delete a tunnel
     * Called when processing Delete Session Request/Response
     * @param teid TEID to delete
     */
    void deleteTunnel(uint32_t teid);

    /**
     * Find tunnel by TEID
     * Used for correlating GTP-U packets
     * @param teid TEID value
     * @return Tunnel information or nullopt if not found
     */
    std::optional<GtpTunnel> findByTEID(uint32_t teid) const;

    /**
     * Find tunnel by IMSI
     * @param imsi IMSI value
     * @return Tunnel information or nullopt if not found
     */
    std::optional<GtpTunnel> findByIMSI(const std::string& imsi) const;

    /**
     * Find tunnel by UE IP address
     * @param ue_ip UE IP address
     * @return Tunnel information or nullopt if not found
     */
    std::optional<GtpTunnel> findByUEIP(const std::string& ue_ip) const;

    /**
     * Find tunnel by session ID
     * @param session_id Session ID
     * @return Tunnel information or nullopt if not found
     */
    std::optional<GtpTunnel> findBySessionID(const std::string& session_id) const;

    /**
     * Get all active tunnels
     * @return Vector of all tunnel information
     */
    std::vector<GtpTunnel> getAllTunnels() const;

    /**
     * Get number of active tunnels
     * @return Count of active tunnels
     */
    size_t getTunnelCount() const;

    /**
     * Clear all tunnels
     */
    void clear();

    /**
     * Get statistics
     * @return JSON object with statistics
     */
    nlohmann::json getStatistics() const;

private:
    // Main TEID lookup table (most common case for GTP-U correlation)
    mutable std::mutex mutex_;
    std::unordered_map<uint32_t, GtpTunnel> teid_to_tunnel_;

    // Secondary indexes for lookups
    std::unordered_map<std::string, uint32_t> imsi_to_teid_;
    std::unordered_map<std::string, uint32_t> ue_ip_to_teid_;
    std::unordered_map<std::string, uint32_t> session_id_to_teid_;

    // Statistics
    mutable uint64_t total_tunnels_created_ = 0;
    mutable uint64_t total_tunnels_deleted_ = 0;
    mutable uint64_t total_lookups_ = 0;
    mutable uint64_t total_lookup_hits_ = 0;
};

}  // namespace gtp
}  // namespace callflow
