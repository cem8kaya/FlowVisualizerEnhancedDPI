#pragma once

#include "correlation/identity/subscriber_identity.h"
#include <memory>
#include <vector>
#include <unordered_map>
#include <shared_mutex>
#include <functional>

namespace callflow {
namespace correlation {

/**
 * @brief Manages subscriber contexts across all protocols
 *
 * Maintains a unified view of subscriber identities, handling:
 * - Multi-key lookup (IMSI, MSISDN, IMEI, IP)
 * - Context merging when new links discovered
 * - Identity propagation across protocols
 *
 * Thread-safe for concurrent access from multiple protocol parsers.
 */
class SubscriberContextManager {
public:
    using ContextPtr = std::shared_ptr<SubscriberIdentity>;
    using ContextCallback = std::function<void(ContextPtr)>;

    SubscriberContextManager() = default;
    ~SubscriberContextManager() = default;

    // Non-copyable
    SubscriberContextManager(const SubscriberContextManager&) = delete;
    SubscriberContextManager& operator=(const SubscriberContextManager&) = delete;

    /**
     * @brief Get or create subscriber context by IMSI
     * @param imsi Raw IMSI string
     * @return Shared pointer to subscriber context
     */
    ContextPtr getOrCreateByImsi(const std::string& imsi);

    /**
     * @brief Get or create subscriber context by MSISDN
     * @param msisdn Raw MSISDN string
     * @return Shared pointer to subscriber context
     */
    ContextPtr getOrCreateByMsisdn(const std::string& msisdn);

    /**
     * @brief Get or create subscriber context by IMEI
     * @param imei Raw IMEI string
     * @return Shared pointer to subscriber context
     */
    ContextPtr getOrCreateByImei(const std::string& imei);

    /**
     * @brief Get or create subscriber context by UE IP address
     * @param ip IPv4 or IPv6 address
     * @return Shared pointer to subscriber context
     */
    ContextPtr getOrCreateByUeIp(const std::string& ip);

    /**
     * @brief Find subscriber context by IMSI
     * @return Context pointer or nullptr if not found
     */
    ContextPtr findByImsi(const std::string& imsi) const;

    /**
     * @brief Find subscriber context by MSISDN
     * @return Context pointer or nullptr if not found
     */
    ContextPtr findByMsisdn(const std::string& msisdn) const;

    /**
     * @brief Find subscriber context by IMEI
     * @return Context pointer or nullptr if not found
     */
    ContextPtr findByImei(const std::string& imei) const;

    /**
     * @brief Find subscriber context by UE IP address
     * @return Context pointer or nullptr if not found
     */
    ContextPtr findByUeIp(const std::string& ip) const;

    /**
     * @brief Find subscriber context by 4G GUTI
     * @return Context pointer or nullptr if not found
     */
    ContextPtr findByGuti(const Guti4G& guti) const;

    /**
     * @brief Find subscriber context by TMSI
     * @return Context pointer or nullptr if not found
     */
    ContextPtr findByTmsi(uint32_t tmsi) const;

    /**
     * @brief Link IMSI and MSISDN together
     *
     * If both identifiers exist in different contexts, the contexts are merged.
     * This is a key operation for identity propagation.
     *
     * @param imsi Raw IMSI string
     * @param msisdn Raw MSISDN string
     */
    void linkImsiMsisdn(const std::string& imsi, const std::string& msisdn);

    /**
     * @brief Link IMSI and IMEI together
     */
    void linkImsiImei(const std::string& imsi, const std::string& imei);

    /**
     * @brief Link MSISDN and UE IP address
     */
    void linkMsisdnUeIp(const std::string& msisdn, const std::string& ip);

    /**
     * @brief Link IMSI and UE IP address
     */
    void linkImsiUeIp(const std::string& imsi, const std::string& ip);

    /**
     * @brief Link IMSI and 4G GUTI
     */
    void linkImsiGuti(const std::string& imsi, const Guti4G& guti);

    /**
     * @brief Link IMSI and TMSI
     */
    void linkImsiTmsi(const std::string& imsi, uint32_t tmsi);

    /**
     * @brief Add GTP-U tunnel information to subscriber context
     *
     * @param imsi_or_msisdn Subscriber identifier (IMSI or MSISDN)
     * @param peer_ip GTP-U peer endpoint IP
     * @param teid Tunnel Endpoint Identifier
     */
    void addGtpuTunnel(const std::string& imsi_or_msisdn,
                       const std::string& peer_ip,
                       uint32_t teid);

    /**
     * @brief Run identity propagation algorithm
     *
     * Propagates identifiers across linked contexts based on:
     * - Shared IP addresses (default bearer + IMS bearer)
     * - GTP tunnel correlations
     * - GUTI/TMSI mappings
     *
     * This implements the "forward-fill/backward-fill" approach from
     * the production Python correlator.
     */
    void propagateIdentities();

    /**
     * @brief Get all subscriber contexts
     * @return Vector of all active contexts
     */
    std::vector<ContextPtr> getAllContexts() const;

    /**
     * @brief Get statistics about managed contexts
     */
    struct Stats {
        size_t total_contexts = 0;
        size_t contexts_with_imsi = 0;
        size_t contexts_with_msisdn = 0;
        size_t contexts_with_imei = 0;
        size_t contexts_with_ue_ip = 0;
        size_t merge_operations = 0;
    };
    Stats getStats() const;

    /**
     * @brief Clear all contexts and reset state
     */
    void clear();

private:
    mutable std::shared_mutex mutex_;

    // Primary storage - all contexts
    std::vector<ContextPtr> contexts_;

    // Index maps for fast O(1) lookup
    std::unordered_map<std::string, ContextPtr> imsi_index_;      // IMSI digits -> Context
    std::unordered_map<std::string, ContextPtr> msisdn_index_;    // Normalized MSISDN -> Context
    std::unordered_map<std::string, ContextPtr> imei_index_;      // IMEI digits -> Context
    std::unordered_map<std::string, ContextPtr> ip_index_;        // UE IP -> Context
    std::unordered_map<uint32_t, ContextPtr> tmsi_index_;         // TMSI -> Context
    std::unordered_map<std::string, ContextPtr> guti_index_;      // GUTI string -> Context

    // Statistics
    mutable Stats stats_{};

    // Internal helper methods
    ContextPtr createContext();
    void mergeContexts(ContextPtr primary, ContextPtr secondary);
    void updateIndices(ContextPtr context);
    void removeFromIndices(ContextPtr context);

    std::string normalizeForIndex(const std::string& msisdn) const;
    std::string normalizeImsiForIndex(const std::string& imsi) const;
    std::string normalizeImeiForIndex(const std::string& imei) const;

    // Helper for IP-based correlation
    void correlateByIpAddress();
    void correlateByGuti();
};

/**
 * @brief Builder for updating subscriber context from protocol messages
 *
 * Provides a fluent interface for building subscriber contexts from
 * various protocol message types. Automatically handles normalization
 * and linking.
 *
 * Example usage:
 *   SubscriberContextBuilder(manager)
 *       .fromGtpImsi("460001234567890")
 *       .fromGtpMsisdn("+8613800138000")
 *       .fromGtpPdnAddress("10.1.2.3")
 *       .build();
 */
class SubscriberContextBuilder {
public:
    explicit SubscriberContextBuilder(SubscriberContextManager& manager);

    // From SIP message headers
    SubscriberContextBuilder& fromSipFrom(const std::string& from_uri);
    SubscriberContextBuilder& fromSipTo(const std::string& to_uri);
    SubscriberContextBuilder& fromSipPai(const std::string& pai);
    SubscriberContextBuilder& fromSipContact(const std::string& contact,
                                              const std::string& ip);

    // From Diameter AVPs
    SubscriberContextBuilder& fromDiameterImsi(const std::string& imsi);
    SubscriberContextBuilder& fromDiameterMsisdn(const std::string& msisdn);
    SubscriberContextBuilder& fromDiameterFramedIp(const std::string& ip);
    SubscriberContextBuilder& fromDiameterPublicIdentity(const std::string& pub_id);

    // From GTPv2 Information Elements
    SubscriberContextBuilder& fromGtpImsi(const std::string& imsi);
    SubscriberContextBuilder& fromGtpMsisdn(const std::string& msisdn);
    SubscriberContextBuilder& fromGtpMei(const std::string& mei);
    SubscriberContextBuilder& fromGtpPdnAddress(const std::string& ip);
    SubscriberContextBuilder& fromGtpFteid(const std::string& ip, uint32_t teid);
    SubscriberContextBuilder& fromGtpApn(const std::string& apn);

    // From NAS/S1AP messages
    SubscriberContextBuilder& fromNasImsi(const std::string& imsi);
    SubscriberContextBuilder& fromNasImei(const std::string& imei);
    SubscriberContextBuilder& fromNasGuti(const Guti4G& guti);
    SubscriberContextBuilder& fromNasTmsi(uint32_t tmsi);

    /**
     * @brief Build and return the subscriber context
     *
     * Performs all necessary linking operations and returns the
     * unified context for this subscriber.
     */
    SubscriberContextManager::ContextPtr build();

private:
    SubscriberContextManager& manager_;

    // Accumulated identifiers
    std::optional<std::string> imsi_;
    std::optional<std::string> msisdn_;
    std::optional<std::string> imei_;
    std::optional<std::string> ue_ip_;
    std::optional<Guti4G> guti_;
    std::optional<uint32_t> tmsi_;
    std::optional<std::string> apn_;
    std::vector<std::pair<std::string, uint32_t>> gtp_tunnels_;  // (peer_ip, teid)
};

} // namespace correlation
} // namespace callflow
