#pragma once

#include <chrono>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include <nlohmann/json.hpp>

namespace callflow {
namespace correlation {

/**
 * VolteSubscriberContext - Unified view of all identifiers for a single subscriber in VoLTE correlation
 *
 * This structure maintains the complete identity profile of a subscriber across
 * all network layers (radio, core, IMS) and tracks the evolution of identifiers
 * as they change during mobility events and service establishment.
 */
struct VolteSubscriberContext {
    std::string context_id;

    // ========================================================================
    // Primary Permanent Identifiers
    // ========================================================================
    std::optional<std::string> imsi;    // International Mobile Subscriber Identity (LTE)
    std::optional<std::string> supi;    // Subscription Permanent Identifier (5G)
    std::optional<std::string> msisdn;  // Phone number
    std::optional<std::string> imei;    // International Mobile Equipment Identity
    std::optional<std::string> imeisv;  // IMEI Software Version

    // ========================================================================
    // Temporary Identifiers
    // ========================================================================

    /**
     * GUTI - Globally Unique Temporary Identifier (LTE)
     * Used to protect IMSI privacy over the air interface
     */
    struct GUTI {
        std::string mcc_mnc;      // PLMN ID (e.g., "310410")
        uint16_t mme_group_id;    // MME Group ID
        uint8_t mme_code;         // MME Code
        uint32_t m_tmsi;          // M-TMSI (main temporary identifier)

        std::string toString() const;
        bool operator==(const GUTI& other) const;
        bool operator!=(const GUTI& other) const { return !(*this == other); }
    };

    std::optional<GUTI> current_guti;
    std::vector<GUTI> guti_history;  // Track GUTI changes during TAU, handovers

    /**
     * 5G-GUTI - 5G Globally Unique Temporary Identifier
     */
    struct GUTI5G {
        std::string mcc_mnc;      // PLMN ID
        uint16_t amf_region_id;   // AMF Region ID
        uint16_t amf_set_id;      // AMF Set ID
        uint8_t amf_pointer;      // AMF Pointer
        uint32_t tmsi_5g;         // 5G-TMSI

        std::string toString() const;
        bool operator==(const GUTI5G& other) const;
        bool operator!=(const GUTI5G& other) const { return !(*this == other); }
    };

    std::optional<GUTI5G> current_5g_guti;
    std::vector<GUTI5G> guti_5g_history;

    // ========================================================================
    // Network-Assigned Identifiers
    // ========================================================================

    std::set<std::string> ue_ipv4_addresses;  // All IPv4 addresses ever assigned
    std::set<std::string> ue_ipv6_addresses;  // All IPv6 addresses ever assigned
    std::string current_ue_ipv4;              // Most recent IPv4
    std::string current_ue_ipv6;              // Most recent IPv6

    // ========================================================================
    // Bearer/Tunnel Identifiers
    // ========================================================================

    /**
     * Bearer Information - Tracks EPS bearers and their associated tunnels
     */
    struct BearerInfo {
        uint32_t teid;                // Tunnel Endpoint Identifier
        uint8_t eps_bearer_id;        // EPS Bearer ID (5-15)
        std::string interface;        // Interface name (e.g., "S1-U", "S5-U")
        std::string pgw_ip;           // P-GW IP address
        uint8_t qci;                  // QoS Class Identifier
        uint64_t uplink_teid;         // Uplink TEID (optional)
        uint64_t downlink_teid;       // Downlink TEID (optional)
        std::chrono::system_clock::time_point created;
        std::optional<std::chrono::system_clock::time_point> deleted;

        bool is_active() const { return !deleted.has_value(); }
    };

    std::vector<BearerInfo> bearers;

    /**
     * PDU Session Information - Tracks 5G PDU sessions
     */
    struct PduSessionInfo {
        uint8_t pdu_session_id;       // PDU Session ID
        uint64_t uplink_teid;         // N3 uplink TEID
        uint64_t downlink_teid;       // N3 downlink TEID
        std::string dnn;              // Data Network Name
        uint8_t sst;                  // Slice/Service Type
        std::optional<uint32_t> sd;   // Slice Differentiator
        std::chrono::system_clock::time_point created;
        std::optional<std::chrono::system_clock::time_point> deleted;

        bool is_active() const { return !deleted.has_value(); }
    };

    std::vector<PduSessionInfo> pdu_sessions;

    std::set<uint64_t> seids;  // PFCP Session Endpoint Identifiers (N4 interface)

    // ========================================================================
    // Control Plane Context IDs
    // ========================================================================

    // LTE S1AP Context IDs
    std::optional<uint32_t> mme_ue_s1ap_id;  // MME-side UE context ID
    std::optional<uint32_t> enb_ue_s1ap_id;  // eNodeB-side UE context ID

    // 5G NGAP Context IDs
    std::optional<uint64_t> amf_ue_ngap_id;  // AMF-side UE context ID
    std::optional<uint64_t> ran_ue_ngap_id;  // gNB/RAN-side UE context ID

    // ========================================================================
    // IMS/VoLTE Identifiers
    // ========================================================================

    std::set<std::string> sip_uris;         // All SIP URIs (sip:user@domain)
    std::string current_sip_uri;            // Currently registered SIP URI
    std::set<std::string> sip_call_ids;     // All SIP Call-IDs seen
    std::set<std::string> icids;            // IMS Charging Identifiers

    // ========================================================================
    // Session References
    // ========================================================================

    std::set<std::string> session_ids;  // References to correlated sessions

    // ========================================================================
    // Lifecycle Tracking
    // ========================================================================

    std::chrono::system_clock::time_point first_seen;
    std::chrono::system_clock::time_point last_updated;

    // ========================================================================
    // Helper Methods
    // ========================================================================

    /**
     * Check if this context contains a specific identifier
     */
    bool hasIdentifier(const std::string& id) const;

    /**
     * Get the primary identifier for this subscriber (preference: IMSI > SUPI > MSISDN)
     */
    std::string getPrimaryIdentifier() const;

    /**
     * Get the best available subscriber identifier for display
     */
    std::string getDisplayName() const;

    /**
     * Get count of active bearers
     */
    size_t getActiveBearerCount() const;

    /**
     * Get count of active PDU sessions
     */
    size_t getActivePduSessionCount() const;

    /**
     * Serialize to JSON for debugging/export
     */
    nlohmann::json toJson() const;
};

/**
 * VolteSubscriberContextManager
 *
 * Central registry and lookup service for subscriber contexts for VoLTE correlation.
 * Provides fast O(1) lookups by any identifier type and maintains
 * consistency across identifier updates and context merges.
 *
 * Thread-safe for concurrent access from multiple packet processing threads.
 */
class VolteSubscriberContextManager {
public:
    /**
     * Construct a subscriber context manager
     * @param max_contexts Maximum number of contexts to track (LRU eviction beyond this)
     */
    explicit VolteSubscriberContextManager(size_t max_contexts = 1000000);
    ~VolteSubscriberContextManager();

    // ========================================================================
    // Lookup Methods - All return nullptr if not found
    // ========================================================================

    std::shared_ptr<VolteSubscriberContext> findByImsi(const std::string& imsi);
    std::shared_ptr<VolteSubscriberContext> findBySupi(const std::string& supi);
    std::shared_ptr<VolteSubscriberContext> findByMsisdn(const std::string& msisdn);
    std::shared_ptr<VolteSubscriberContext> findByGuti(const VolteSubscriberContext::GUTI& guti);
    std::shared_ptr<VolteSubscriberContext> findByGuti5G(const VolteSubscriberContext::GUTI5G& guti);
    std::shared_ptr<VolteSubscriberContext> findByUeIp(const std::string& ip);
    std::shared_ptr<VolteSubscriberContext> findByTeid(uint32_t teid);
    std::shared_ptr<VolteSubscriberContext> findBySeid(uint64_t seid);
    std::shared_ptr<VolteSubscriberContext> findBySipUri(const std::string& uri);
    std::shared_ptr<VolteSubscriberContext> findBySipCallId(const std::string& call_id);
    std::shared_ptr<VolteSubscriberContext> findByMmeUeId(uint32_t mme_ue_s1ap_id);
    std::shared_ptr<VolteSubscriberContext> findByEnbUeId(uint32_t enb_ue_s1ap_id);
    std::shared_ptr<VolteSubscriberContext> findByAmfUeId(uint64_t amf_ue_ngap_id);
    std::shared_ptr<VolteSubscriberContext> findByRanUeId(uint64_t ran_ue_ngap_id);
    std::shared_ptr<VolteSubscriberContext> findByContextId(const std::string& context_id);

    // ========================================================================
    // Registration Methods
    // ========================================================================

    /**
     * Get existing context or create new one identified by IMSI
     */
    std::shared_ptr<VolteSubscriberContext> getOrCreate(const std::string& imsi);

    /**
     * Get existing context or create new one identified by SUPI
     */
    std::shared_ptr<VolteSubscriberContext> getOrCreateBySupi(const std::string& supi);

    /**
     * Create a new context without a permanent identifier (will be linked later)
     */
    std::shared_ptr<VolteSubscriberContext> createTemporaryContext();

    // ========================================================================
    // Update Methods - All update indices atomically
    // ========================================================================

    void updateImsi(const std::string& context_id, const std::string& imsi);
    void updateSupi(const std::string& context_id, const std::string& supi);
    void updateMsisdn(const std::string& context_id, const std::string& msisdn);
    void updateImei(const std::string& context_id, const std::string& imei);
    void updateGuti(const std::string& context_id, const VolteSubscriberContext::GUTI& guti);
    void updateGuti5G(const std::string& context_id, const VolteSubscriberContext::GUTI5G& guti);
    void updateUeIp(const std::string& context_id, const std::string& ipv4,
                    const std::string& ipv6 = "");
    void addBearer(const std::string& context_id, const VolteSubscriberContext::BearerInfo& bearer);
    void removeBearer(const std::string& context_id, uint32_t teid);
    void addPduSession(const std::string& context_id, const VolteSubscriberContext::PduSessionInfo& session);
    void removePduSession(const std::string& context_id, uint8_t pdu_session_id);
    void addSeid(const std::string& context_id, uint64_t seid);
    void updateMmeUeId(const std::string& context_id, uint32_t mme_ue_s1ap_id);
    void updateEnbUeId(const std::string& context_id, uint32_t enb_ue_s1ap_id);
    void updateAmfUeId(const std::string& context_id, uint64_t amf_ue_ngap_id);
    void updateRanUeId(const std::string& context_id, uint64_t ran_ue_ngap_id);
    void updateSipUri(const std::string& context_id, const std::string& uri);
    void addSipCallId(const std::string& context_id, const std::string& call_id);
    void addIcid(const std::string& context_id, const std::string& icid);
    void addSessionId(const std::string& context_id, const std::string& session_id);

    // ========================================================================
    // Context Merge
    // ========================================================================

    /**
     * Merge two contexts, keeping all identifiers and updating all indices
     * @param context_id_keep The context to keep (destination)
     * @param context_id_merge The context to merge and remove (source)
     * @return true if merge succeeded, false if either context not found
     */
    bool mergeContexts(const std::string& context_id_keep, const std::string& context_id_merge);

    // ========================================================================
    // Cleanup
    // ========================================================================

    /**
     * Remove contexts that haven't been updated since cutoff time
     * @param cutoff Time threshold
     * @return Number of contexts removed
     */
    size_t cleanupStaleContexts(std::chrono::system_clock::time_point cutoff);

    /**
     * Remove a specific context and all its index entries
     */
    bool removeContext(const std::string& context_id);

    // ========================================================================
    // Statistics
    // ========================================================================

    struct Stats {
        size_t total_contexts = 0;
        size_t with_imsi = 0;
        size_t with_supi = 0;
        size_t with_msisdn = 0;
        size_t with_ue_ip = 0;
        size_t with_active_bearers = 0;
        size_t with_active_pdu_sessions = 0;
        size_t with_sip_sessions = 0;
        size_t lookups_total = 0;
        size_t lookups_hit = 0;
        size_t merges_total = 0;
        size_t cleanups_total = 0;

        double getHitRate() const {
            return lookups_total > 0 ? (double)lookups_hit / lookups_total : 0.0;
        }

        nlohmann::json toJson() const;
    };

    Stats getStats() const;
    void resetStats();

private:
    // ========================================================================
    // Internal State
    // ========================================================================

    mutable std::shared_mutex mutex_;  // Readers-writer lock for thread-safety

    // Main context storage
    std::unordered_map<std::string, std::shared_ptr<VolteSubscriberContext>> contexts_;

    // Lookup indices - all map identifier -> context_id
    std::unordered_map<std::string, std::string> imsi_index_;
    std::unordered_map<std::string, std::string> supi_index_;
    std::unordered_map<std::string, std::string> msisdn_index_;
    std::unordered_map<std::string, std::string> guti_index_;
    std::unordered_map<std::string, std::string> guti_5g_index_;
    std::unordered_map<std::string, std::string> ue_ip_index_;
    std::unordered_map<uint32_t, std::string> teid_index_;
    std::unordered_map<uint64_t, std::string> seid_index_;
    std::unordered_map<std::string, std::string> sip_uri_index_;
    std::unordered_map<std::string, std::string> sip_call_id_index_;
    std::unordered_map<std::string, std::string> icid_index_;
    std::unordered_map<uint32_t, std::string> mme_ue_id_index_;
    std::unordered_map<uint32_t, std::string> enb_ue_id_index_;
    std::unordered_map<uint64_t, std::string> amf_ue_id_index_;
    std::unordered_map<uint64_t, std::string> ran_ue_id_index_;

    size_t max_contexts_;
    mutable Stats stats_;

    // ========================================================================
    // Internal Helper Methods
    // ========================================================================

    std::string generateContextId();
    void updateLastModified(const std::string& context_id);
    void removeFromAllIndices(const std::shared_ptr<VolteSubscriberContext>& context);

    // Index update helpers
    void addToImsiIndex(const std::string& context_id, const std::string& imsi);
    void removeFromImsiIndex(const std::string& imsi);
    void addToTeidIndex(const std::string& context_id, uint32_t teid);
    void removeFromTeidIndex(uint32_t teid);

    // Generic lookup helper
    template<typename KeyType>
    std::shared_ptr<VolteSubscriberContext> lookupInIndex(
        const std::unordered_map<KeyType, std::string>& index,
        const KeyType& key) const;
};

}  // namespace correlation
}  // namespace callflow
