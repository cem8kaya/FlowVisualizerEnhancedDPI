#include "correlation/identity/subscriber_context_manager.h"

#include <algorithm>
#include <mutex>
#include <sstream>

#include "correlation/identity/imei_normalizer.h"
#include "correlation/identity/imsi_normalizer.h"
#include "correlation/identity/msisdn_normalizer.h"

namespace callflow {
namespace correlation {

// ============================================================================
// SubscriberContextManager - Core Methods
// ============================================================================

SubscriberContextManager::ContextPtr SubscriberContextManager::createContext() {
    auto context = std::make_shared<SubscriberIdentity>();
    context->first_seen = std::chrono::steady_clock::now();
    context->last_seen = context->first_seen;
    contexts_.push_back(context);
    stats_.total_contexts++;
    return context;
}

std::string SubscriberContextManager::normalizeForIndex(const std::string& msisdn) const {
    auto normalized = MsisdnNormalizer::normalize(msisdn);
    return normalized.national;  // Use national form for consistent indexing
}

std::string SubscriberContextManager::normalizeImsiForIndex(const std::string& imsi) const {
    auto normalized = ImsiNormalizer::normalize(imsi);
    if (normalized) {
        return normalized->digits;
    }
    // Fallback to extracting digits
    std::string digits;
    for (char c : imsi) {
        if (std::isdigit(c)) {
            digits += c;
        }
    }
    return digits;
}

std::string SubscriberContextManager::normalizeImeiForIndex(const std::string& imei) const {
    auto normalized = ImeiNormalizer::normalize(imei);
    if (normalized) {
        return normalized->imei;
    }
    // Fallback to extracting digits
    std::string digits;
    for (char c : imei) {
        if (std::isdigit(c)) {
            digits += c;
        }
    }
    return digits;
}

void SubscriberContextManager::updateIndices(ContextPtr context) {
    if (context->imsi) {
        imsi_index_[context->imsi->digits] = context;
        stats_.contexts_with_imsi++;
    }
    if (context->msisdn) {
        msisdn_index_[context->msisdn->national] = context;
        stats_.contexts_with_msisdn++;
    }
    if (context->imei) {
        imei_index_[context->imei->imei] = context;
        stats_.contexts_with_imei++;
    }
    if (context->tmsi) {
        tmsi_index_[*context->tmsi] = context;
    }
    if (context->guti) {
        guti_index_[context->guti->toString()] = context;
    }
    for (const auto& ep : context->endpoints) {
        if (!ep.ipv4.empty()) {
            ip_index_[ep.ipv4] = context;
            stats_.contexts_with_ue_ip++;
        }
        if (!ep.ipv6.empty()) {
            ip_index_[ep.ipv6] = context;
            stats_.contexts_with_ue_ip++;
        }
    }
}

void SubscriberContextManager::removeFromIndices(ContextPtr context) {
    if (context->imsi) {
        imsi_index_.erase(context->imsi->digits);
    }
    if (context->msisdn) {
        msisdn_index_.erase(context->msisdn->national);
    }
    if (context->imei) {
        imei_index_.erase(context->imei->imei);
    }
    if (context->tmsi) {
        tmsi_index_.erase(*context->tmsi);
    }
    if (context->guti) {
        guti_index_.erase(context->guti->toString());
    }
    for (const auto& ep : context->endpoints) {
        if (!ep.ipv4.empty()) {
            ip_index_.erase(ep.ipv4);
        }
        if (!ep.ipv6.empty()) {
            ip_index_.erase(ep.ipv6);
        }
    }
}

// ============================================================================
// SubscriberContextManager - Get or Create Methods
// ============================================================================

SubscriberContextManager::ContextPtr SubscriberContextManager::getOrCreateByImsi(
    const std::string& imsi) {
    std::unique_lock lock(mutex_);

    std::string normalized = normalizeImsiForIndex(imsi);
    auto it = imsi_index_.find(normalized);
    if (it != imsi_index_.end()) {
        return it->second;
    }

    auto context = createContext();
    auto normalized_imsi = ImsiNormalizer::normalize(imsi);
    if (normalized_imsi) {
        context->imsi = *normalized_imsi;
    } else {
        // Create minimal IMSI structure
        context->imsi = NormalizedImsi{imsi, normalized, "", "", ""};
    }
    imsi_index_[normalized] = context;
    stats_.contexts_with_imsi++;
    return context;
}

SubscriberContextManager::ContextPtr SubscriberContextManager::getOrCreateByMsisdn(
    const std::string& msisdn) {
    std::unique_lock lock(mutex_);

    std::string normalized = normalizeForIndex(msisdn);
    auto it = msisdn_index_.find(normalized);
    if (it != msisdn_index_.end()) {
        return it->second;
    }

    auto context = createContext();
    context->msisdn = MsisdnNormalizer::normalize(msisdn);
    msisdn_index_[normalized] = context;
    stats_.contexts_with_msisdn++;
    return context;
}

SubscriberContextManager::ContextPtr SubscriberContextManager::getOrCreateByImei(
    const std::string& imei) {
    std::unique_lock lock(mutex_);

    std::string normalized = normalizeImeiForIndex(imei);
    auto it = imei_index_.find(normalized);
    if (it != imei_index_.end()) {
        return it->second;
    }

    auto context = createContext();
    auto normalized_imei = ImeiNormalizer::normalize(imei);
    if (normalized_imei) {
        context->imei = *normalized_imei;
    } else {
        // Create minimal IMEI structure
        context->imei = NormalizedImei{imei, normalized, std::nullopt, "", ""};
    }
    imei_index_[normalized] = context;
    stats_.contexts_with_imei++;
    return context;
}

SubscriberContextManager::ContextPtr SubscriberContextManager::getOrCreateByUeIp(
    const std::string& ip) {
    std::unique_lock lock(mutex_);

    auto it = ip_index_.find(ip);
    if (it != ip_index_.end()) {
        return it->second;
    }

    auto context = createContext();
    NetworkEndpoint endpoint;
    if (ip.find(':') != std::string::npos) {
        endpoint.ipv6 = ip;
    } else {
        endpoint.ipv4 = ip;
    }
    context->endpoints.push_back(endpoint);
    ip_index_[ip] = context;
    stats_.contexts_with_ue_ip++;
    return context;
}

// ============================================================================
// SubscriberContextManager - Find Methods
// ============================================================================

SubscriberContextManager::ContextPtr SubscriberContextManager::findByImsi(
    const std::string& imsi) const {
    std::shared_lock lock(mutex_);

    std::string normalized = normalizeImsiForIndex(imsi);
    auto it = imsi_index_.find(normalized);
    return (it != imsi_index_.end()) ? it->second : nullptr;
}

SubscriberContextManager::ContextPtr SubscriberContextManager::findByMsisdn(
    const std::string& msisdn) const {
    std::shared_lock lock(mutex_);

    std::string normalized = normalizeForIndex(msisdn);
    auto it = msisdn_index_.find(normalized);
    return (it != msisdn_index_.end()) ? it->second : nullptr;
}

SubscriberContextManager::ContextPtr SubscriberContextManager::findByImei(
    const std::string& imei) const {
    std::shared_lock lock(mutex_);

    std::string normalized = normalizeImeiForIndex(imei);
    auto it = imei_index_.find(normalized);
    return (it != imei_index_.end()) ? it->second : nullptr;
}

SubscriberContextManager::ContextPtr SubscriberContextManager::findByUeIp(
    const std::string& ip) const {
    std::shared_lock lock(mutex_);

    auto it = ip_index_.find(ip);
    return (it != ip_index_.end()) ? it->second : nullptr;
}

SubscriberContextManager::ContextPtr SubscriberContextManager::findByGuti(
    const Guti4G& guti) const {
    std::shared_lock lock(mutex_);

    auto it = guti_index_.find(guti.toString());
    return (it != guti_index_.end()) ? it->second : nullptr;
}

SubscriberContextManager::ContextPtr SubscriberContextManager::findByTmsi(uint32_t tmsi) const {
    std::shared_lock lock(mutex_);

    auto it = tmsi_index_.find(tmsi);
    return (it != tmsi_index_.end()) ? it->second : nullptr;
}

// ============================================================================
// SubscriberContextManager - Linking Methods
// ============================================================================

void SubscriberContextManager::mergeContexts(ContextPtr primary, ContextPtr secondary) {
    // Remove secondary from indices first to avoid conflicts
    removeFromIndices(secondary);

    // Merge identifiers from secondary into primary
    if (!primary->imsi && secondary->imsi) {
        primary->imsi = secondary->imsi;
    }
    if (!primary->msisdn && secondary->msisdn) {
        primary->msisdn = secondary->msisdn;
    }
    if (!primary->imei && secondary->imei) {
        primary->imei = secondary->imei;
    }
    if (!primary->guti && secondary->guti) {
        primary->guti = secondary->guti;
    }
    if (!primary->tmsi && secondary->tmsi) {
        primary->tmsi = secondary->tmsi;
    }
    if (!primary->p_tmsi && secondary->p_tmsi) {
        primary->p_tmsi = secondary->p_tmsi;
    }
    if (!primary->guti_5g && secondary->guti_5g) {
        primary->guti_5g = secondary->guti_5g;
    }
    if (!primary->tmsi_5g && secondary->tmsi_5g) {
        primary->tmsi_5g = secondary->tmsi_5g;
    }

    // Merge APN information
    if (primary->apn.empty() && !secondary->apn.empty()) {
        primary->apn = secondary->apn;
    }
    if (primary->pdn_type.empty() && !secondary->pdn_type.empty()) {
        primary->pdn_type = secondary->pdn_type;
    }

    // Merge endpoints (avoid duplicates)
    for (const auto& ep : secondary->endpoints) {
        bool duplicate = false;
        for (const auto& existing_ep : primary->endpoints) {
            if ((ep.ipv4 == existing_ep.ipv4 && !ep.ipv4.empty()) ||
                (ep.ipv6 == existing_ep.ipv6 && !ep.ipv6.empty())) {
                duplicate = true;
                break;
            }
        }
        if (!duplicate) {
            primary->endpoints.push_back(ep);
        }
    }

    // Merge confidence scores (keep highest)
    for (const auto& [key, score] : secondary->confidence) {
        if (primary->confidence.find(key) == primary->confidence.end() ||
            primary->confidence[key] < score) {
            primary->confidence[key] = score;
        }
    }

    // Update timestamps
    if (secondary->first_seen < primary->first_seen) {
        primary->first_seen = secondary->first_seen;
    }
    if (secondary->last_seen > primary->last_seen) {
        primary->last_seen = secondary->last_seen;
    }

    // Update all indices to point to primary
    updateIndices(primary);

    // Remove secondary from contexts list
    contexts_.erase(std::remove(contexts_.begin(), contexts_.end(), secondary), contexts_.end());

    stats_.merge_operations++;
}

void SubscriberContextManager::linkImsiMsisdn(const std::string& imsi, const std::string& msisdn) {
    std::unique_lock lock(mutex_);

    std::string norm_imsi = normalizeImsiForIndex(imsi);
    std::string norm_msisdn = normalizeForIndex(msisdn);

    auto imsi_it = imsi_index_.find(norm_imsi);
    auto msisdn_it = msisdn_index_.find(norm_msisdn);

    ContextPtr imsi_ctx = (imsi_it != imsi_index_.end()) ? imsi_it->second : nullptr;
    ContextPtr msisdn_ctx = (msisdn_it != msisdn_index_.end()) ? msisdn_it->second : nullptr;

    if (imsi_ctx && msisdn_ctx) {
        if (imsi_ctx != msisdn_ctx) {
            // Different contexts - merge them
            mergeContexts(imsi_ctx, msisdn_ctx);
        }
        // Same context - nothing to do
    } else if (imsi_ctx && !msisdn_ctx) {
        // Add MSISDN to existing IMSI context
        removeFromIndices(imsi_ctx);  // Temporarily remove to update
        imsi_ctx->msisdn = MsisdnNormalizer::normalize(msisdn);
        updateIndices(imsi_ctx);
    } else if (!imsi_ctx && msisdn_ctx) {
        // Add IMSI to existing MSISDN context
        removeFromIndices(msisdn_ctx);
        auto normalized_imsi = ImsiNormalizer::normalize(imsi);
        if (normalized_imsi) {
            msisdn_ctx->imsi = *normalized_imsi;
        } else {
            msisdn_ctx->imsi = NormalizedImsi{imsi, norm_imsi, "", "", ""};
        }
        updateIndices(msisdn_ctx);
    } else {
        // Create new context with both identifiers
        auto context = createContext();
        auto normalized_imsi = ImsiNormalizer::normalize(imsi);
        if (normalized_imsi) {
            context->imsi = *normalized_imsi;
        } else {
            context->imsi = NormalizedImsi{imsi, norm_imsi, "", "", ""};
        }
        context->msisdn = MsisdnNormalizer::normalize(msisdn);
        updateIndices(context);
    }
}

void SubscriberContextManager::linkImsiImei(const std::string& imsi, const std::string& imei) {
    std::unique_lock lock(mutex_);

    std::string norm_imsi = normalizeImsiForIndex(imsi);
    std::string norm_imei = normalizeImeiForIndex(imei);

    auto imsi_it = imsi_index_.find(norm_imsi);
    auto imei_it = imei_index_.find(norm_imei);

    ContextPtr imsi_ctx = (imsi_it != imsi_index_.end()) ? imsi_it->second : nullptr;
    ContextPtr imei_ctx = (imei_it != imei_index_.end()) ? imei_it->second : nullptr;

    if (imsi_ctx && imei_ctx) {
        if (imsi_ctx != imei_ctx) {
            mergeContexts(imsi_ctx, imei_ctx);
        }
    } else if (imsi_ctx && !imei_ctx) {
        removeFromIndices(imsi_ctx);
        auto normalized_imei = ImeiNormalizer::normalize(imei);
        if (normalized_imei) {
            imsi_ctx->imei = *normalized_imei;
        } else {
            imsi_ctx->imei = NormalizedImei{imei, norm_imei, std::nullopt, "", ""};
        }
        updateIndices(imsi_ctx);
    } else if (!imsi_ctx && imei_ctx) {
        removeFromIndices(imei_ctx);
        auto normalized_imsi = ImsiNormalizer::normalize(imsi);
        if (normalized_imsi) {
            imei_ctx->imsi = *normalized_imsi;
        } else {
            imei_ctx->imsi = NormalizedImsi{imsi, norm_imsi, "", "", ""};
        }
        updateIndices(imei_ctx);
    } else {
        auto context = createContext();
        auto normalized_imsi = ImsiNormalizer::normalize(imsi);
        auto normalized_imei = ImeiNormalizer::normalize(imei);
        if (normalized_imsi) {
            context->imsi = *normalized_imsi;
        } else {
            context->imsi = NormalizedImsi{imsi, norm_imsi, "", "", ""};
        }
        if (normalized_imei) {
            context->imei = *normalized_imei;
        } else {
            context->imei = NormalizedImei{imei, norm_imei, std::nullopt, "", ""};
        }
        updateIndices(context);
    }
}

void SubscriberContextManager::linkMsisdnUeIp(const std::string& msisdn, const std::string& ip) {
    std::unique_lock lock(mutex_);

    std::string norm_msisdn = normalizeForIndex(msisdn);

    auto msisdn_it = msisdn_index_.find(norm_msisdn);
    auto ip_it = ip_index_.find(ip);

    ContextPtr msisdn_ctx = (msisdn_it != msisdn_index_.end()) ? msisdn_it->second : nullptr;
    ContextPtr ip_ctx = (ip_it != ip_index_.end()) ? ip_it->second : nullptr;

    if (msisdn_ctx && ip_ctx) {
        if (msisdn_ctx != ip_ctx) {
            mergeContexts(msisdn_ctx, ip_ctx);
        }
    } else if (msisdn_ctx && !ip_ctx) {
        NetworkEndpoint endpoint;
        if (ip.find(':') != std::string::npos) {
            endpoint.ipv6 = ip;
        } else {
            endpoint.ipv4 = ip;
        }
        msisdn_ctx->endpoints.push_back(endpoint);
        ip_index_[ip] = msisdn_ctx;
    } else if (!msisdn_ctx && ip_ctx) {
        removeFromIndices(ip_ctx);
        ip_ctx->msisdn = MsisdnNormalizer::normalize(msisdn);
        updateIndices(ip_ctx);
    } else {
        auto context = createContext();
        context->msisdn = MsisdnNormalizer::normalize(msisdn);
        NetworkEndpoint endpoint;
        if (ip.find(':') != std::string::npos) {
            endpoint.ipv6 = ip;
        } else {
            endpoint.ipv4 = ip;
        }
        context->endpoints.push_back(endpoint);
        updateIndices(context);
    }
}

void SubscriberContextManager::linkImsiUeIp(const std::string& imsi, const std::string& ip) {
    std::unique_lock lock(mutex_);

    std::string norm_imsi = normalizeImsiForIndex(imsi);

    auto imsi_it = imsi_index_.find(norm_imsi);
    auto ip_it = ip_index_.find(ip);

    ContextPtr imsi_ctx = (imsi_it != imsi_index_.end()) ? imsi_it->second : nullptr;
    ContextPtr ip_ctx = (ip_it != ip_index_.end()) ? ip_it->second : nullptr;

    if (imsi_ctx && ip_ctx) {
        if (imsi_ctx != ip_ctx) {
            mergeContexts(imsi_ctx, ip_ctx);
        }
    } else if (imsi_ctx && !ip_ctx) {
        NetworkEndpoint endpoint;
        if (ip.find(':') != std::string::npos) {
            endpoint.ipv6 = ip;
        } else {
            endpoint.ipv4 = ip;
        }
        imsi_ctx->endpoints.push_back(endpoint);
        ip_index_[ip] = imsi_ctx;
    } else if (!imsi_ctx && ip_ctx) {
        removeFromIndices(ip_ctx);
        auto normalized_imsi = ImsiNormalizer::normalize(imsi);
        if (normalized_imsi) {
            ip_ctx->imsi = *normalized_imsi;
        } else {
            ip_ctx->imsi = NormalizedImsi{imsi, norm_imsi, "", "", ""};
        }
        updateIndices(ip_ctx);
    } else {
        auto context = createContext();
        auto normalized_imsi = ImsiNormalizer::normalize(imsi);
        if (normalized_imsi) {
            context->imsi = *normalized_imsi;
        } else {
            context->imsi = NormalizedImsi{imsi, norm_imsi, "", "", ""};
        }
        NetworkEndpoint endpoint;
        if (ip.find(':') != std::string::npos) {
            endpoint.ipv6 = ip;
        } else {
            endpoint.ipv4 = ip;
        }
        context->endpoints.push_back(endpoint);
        updateIndices(context);
    }
}

void SubscriberContextManager::linkImsiGuti(const std::string& imsi, const Guti4G& guti) {
    std::unique_lock lock(mutex_);

    std::string norm_imsi = normalizeImsiForIndex(imsi);
    std::string guti_str = guti.toString();

    auto imsi_it = imsi_index_.find(norm_imsi);
    auto guti_it = guti_index_.find(guti_str);

    ContextPtr imsi_ctx = (imsi_it != imsi_index_.end()) ? imsi_it->second : nullptr;
    ContextPtr guti_ctx = (guti_it != guti_index_.end()) ? guti_it->second : nullptr;

    if (imsi_ctx && guti_ctx) {
        if (imsi_ctx != guti_ctx) {
            mergeContexts(imsi_ctx, guti_ctx);
        }
    } else if (imsi_ctx && !guti_ctx) {
        imsi_ctx->guti = guti;
        guti_index_[guti_str] = imsi_ctx;
    } else if (!imsi_ctx && guti_ctx) {
        removeFromIndices(guti_ctx);
        auto normalized_imsi = ImsiNormalizer::normalize(imsi);
        if (normalized_imsi) {
            guti_ctx->imsi = *normalized_imsi;
        } else {
            guti_ctx->imsi = NormalizedImsi{imsi, norm_imsi, "", "", ""};
        }
        updateIndices(guti_ctx);
    } else {
        auto context = createContext();
        auto normalized_imsi = ImsiNormalizer::normalize(imsi);
        if (normalized_imsi) {
            context->imsi = *normalized_imsi;
        } else {
            context->imsi = NormalizedImsi{imsi, norm_imsi, "", "", ""};
        }
        context->guti = guti;
        updateIndices(context);
    }
}

void SubscriberContextManager::linkImsiTmsi(const std::string& imsi, uint32_t tmsi) {
    std::unique_lock lock(mutex_);

    std::string norm_imsi = normalizeImsiForIndex(imsi);

    auto imsi_it = imsi_index_.find(norm_imsi);
    auto tmsi_it = tmsi_index_.find(tmsi);

    ContextPtr imsi_ctx = (imsi_it != imsi_index_.end()) ? imsi_it->second : nullptr;
    ContextPtr tmsi_ctx = (tmsi_it != tmsi_index_.end()) ? tmsi_it->second : nullptr;

    if (imsi_ctx && tmsi_ctx) {
        if (imsi_ctx != tmsi_ctx) {
            mergeContexts(imsi_ctx, tmsi_ctx);
        }
    } else if (imsi_ctx && !tmsi_ctx) {
        imsi_ctx->tmsi = tmsi;
        tmsi_index_[tmsi] = imsi_ctx;
    } else if (!imsi_ctx && tmsi_ctx) {
        removeFromIndices(tmsi_ctx);
        auto normalized_imsi = ImsiNormalizer::normalize(imsi);
        if (normalized_imsi) {
            tmsi_ctx->imsi = *normalized_imsi;
        } else {
            tmsi_ctx->imsi = NormalizedImsi{imsi, norm_imsi, "", "", ""};
        }
        updateIndices(tmsi_ctx);
    } else {
        auto context = createContext();
        auto normalized_imsi = ImsiNormalizer::normalize(imsi);
        if (normalized_imsi) {
            context->imsi = *normalized_imsi;
        } else {
            context->imsi = NormalizedImsi{imsi, norm_imsi, "", "", ""};
        }
        context->tmsi = tmsi;
        updateIndices(context);
    }
}

void SubscriberContextManager::addGtpuTunnel(const std::string& imsi_or_msisdn,
                                             const std::string& peer_ip, uint32_t teid) {
    std::unique_lock lock(mutex_);

    // Try to find context by IMSI first
    std::string norm_imsi = normalizeImsiForIndex(imsi_or_msisdn);
    auto imsi_it = imsi_index_.find(norm_imsi);

    ContextPtr context = nullptr;
    if (imsi_it != imsi_index_.end()) {
        context = imsi_it->second;
    } else {
        // Try MSISDN
        std::string norm_msisdn = normalizeForIndex(imsi_or_msisdn);
        auto msisdn_it = msisdn_index_.find(norm_msisdn);
        if (msisdn_it != msisdn_index_.end()) {
            context = msisdn_it->second;
        }
    }

    if (context) {
        // Add GTP-U tunnel info to endpoints
        bool found = false;
        for (auto& ep : context->endpoints) {
            if (!ep.gtpu_peer_ip || !ep.gtpu_teid) {
                ep.gtpu_peer_ip = peer_ip;
                ep.gtpu_teid = teid;
                found = true;
                break;
            }
        }
        if (!found) {
            // Create new endpoint with tunnel info
            NetworkEndpoint ep;
            ep.gtpu_peer_ip = peer_ip;
            ep.gtpu_teid = teid;
            context->endpoints.push_back(ep);
        }
    }
}

// ============================================================================
// SubscriberContextManager - Identity Propagation
// ============================================================================

void SubscriberContextManager::correlateByIpAddress() {
    // Build IP to contexts mapping
    std::unordered_map<std::string, std::vector<ContextPtr>> ip_to_contexts;

    for (const auto& ctx : contexts_) {
        for (const auto& ep : ctx->endpoints) {
            if (!ep.ipv4.empty()) {
                ip_to_contexts[ep.ipv4].push_back(ctx);
            }
            if (!ep.ipv6.empty()) {
                ip_to_contexts[ep.ipv6].push_back(ctx);
                // Also index by /64 prefix for IPv6
                std::string prefix = ep.getIpv6Prefix(64);
                if (!prefix.empty()) {
                    ip_to_contexts[prefix].push_back(ctx);
                }
            }
        }
    }

    // Merge contexts that share IP addresses
    for (const auto& [ip, ctxs] : ip_to_contexts) {
        if (ctxs.size() > 1) {
            auto primary = ctxs[0];
            for (size_t i = 1; i < ctxs.size(); i++) {
                if (primary != ctxs[i]) {
                    mergeContexts(primary, ctxs[i]);
                }
            }
        }
    }
}

void SubscriberContextManager::correlateByGuti() {
    // GUTI-based correlation: if GUTI m-TMSI matches TMSI, link them
    for (const auto& ctx : contexts_) {
        if (ctx->guti && ctx->guti->m_tmsi) {
            auto tmsi_it = tmsi_index_.find(ctx->guti->m_tmsi);
            if (tmsi_it != tmsi_index_.end() && tmsi_it->second != ctx) {
                mergeContexts(ctx, tmsi_it->second);
            }
        }
    }
}

void SubscriberContextManager::propagateIdentities() {
    std::unique_lock lock(mutex_);

    // Phase 1: IP-based correlation
    correlateByIpAddress();

    // Phase 2: GUTI/TMSI correlation
    correlateByGuti();

    // Phase 3: Propagate missing identifiers within contexts
    // This handles cases where we have IMSI but not MSISDN, etc.
    for (auto& ctx : contexts_) {
        // Update last_seen timestamp
        ctx->last_seen = std::chrono::steady_clock::now();

        // Calculate confidence scores based on completeness
        float completeness = 0.0f;
        if (ctx->imsi)
            completeness += 0.3f;
        if (ctx->msisdn)
            completeness += 0.3f;
        if (ctx->imei)
            completeness += 0.2f;
        if (!ctx->endpoints.empty())
            completeness += 0.2f;

        ctx->confidence["identity_completeness"] = completeness;
    }
}

// ============================================================================
// SubscriberContextManager - Query Methods
// ============================================================================

std::vector<SubscriberContextManager::ContextPtr> SubscriberContextManager::getAllContexts() const {
    std::shared_lock lock(mutex_);
    return contexts_;
}

SubscriberContextManager::Stats SubscriberContextManager::getStats() const {
    std::shared_lock lock(mutex_);
    return stats_;
}

void SubscriberContextManager::clear() {
    std::unique_lock lock(mutex_);

    contexts_.clear();
    imsi_index_.clear();
    msisdn_index_.clear();
    imei_index_.clear();
    ip_index_.clear();
    tmsi_index_.clear();
    guti_index_.clear();

    stats_ = Stats{};
}

// ============================================================================
// SubscriberContextBuilder Implementation
// ============================================================================

SubscriberContextBuilder::SubscriberContextBuilder(SubscriberContextManager& manager)
    : manager_(manager) {}

SubscriberContextBuilder& SubscriberContextBuilder::fromSipFrom(const std::string& from_uri) {
    auto msisdn = MsisdnNormalizer::fromSipUri(from_uri);
    if (msisdn) {
        msisdn_ = msisdn->national;
    }
    return *this;
}

SubscriberContextBuilder& SubscriberContextBuilder::fromSipTo(const std::string& to_uri) {
    auto msisdn = MsisdnNormalizer::fromSipUri(to_uri);
    if (msisdn) {
        msisdn_ = msisdn->national;
    }
    return *this;
}

SubscriberContextBuilder& SubscriberContextBuilder::fromSipPai(const std::string& pai) {
    auto msisdn = MsisdnNormalizer::fromSipUri(pai);
    if (msisdn) {
        msisdn_ = msisdn->national;
    }
    return *this;
}

SubscriberContextBuilder& SubscriberContextBuilder::fromSipContact(const std::string& contact,
                                                                   const std::string& ip) {
    auto msisdn = MsisdnNormalizer::fromSipUri(contact);
    if (msisdn) {
        msisdn_ = msisdn->national;
    }
    if (!ip.empty()) {
        ue_ip_ = ip;
    }
    return *this;
}

SubscriberContextBuilder& SubscriberContextBuilder::fromDiameterImsi(const std::string& imsi) {
    imsi_ = imsi;
    return *this;
}

SubscriberContextBuilder& SubscriberContextBuilder::fromDiameterMsisdn(const std::string& msisdn) {
    msisdn_ = msisdn;
    return *this;
}

SubscriberContextBuilder& SubscriberContextBuilder::fromDiameterFramedIp(const std::string& ip) {
    ue_ip_ = ip;
    return *this;
}

SubscriberContextBuilder& SubscriberContextBuilder::fromDiameterPublicIdentity(
    const std::string& pub_id) {
    auto msisdn = MsisdnNormalizer::fromSipUri(pub_id);
    if (msisdn) {
        msisdn_ = msisdn->national;
    }
    return *this;
}

SubscriberContextBuilder& SubscriberContextBuilder::fromGtpImsi(const std::string& imsi) {
    imsi_ = imsi;
    return *this;
}

SubscriberContextBuilder& SubscriberContextBuilder::fromGtpMsisdn(const std::string& msisdn) {
    msisdn_ = msisdn;
    return *this;
}

SubscriberContextBuilder& SubscriberContextBuilder::fromGtpMei(const std::string& mei) {
    imei_ = mei;
    return *this;
}

SubscriberContextBuilder& SubscriberContextBuilder::fromGtpPdnAddress(const std::string& ip) {
    ue_ip_ = ip;
    return *this;
}

SubscriberContextBuilder& SubscriberContextBuilder::fromGtpFteid(const std::string& ip,
                                                                 uint32_t teid) {
    gtp_tunnels_.push_back({ip, teid});
    return *this;
}

SubscriberContextBuilder& SubscriberContextBuilder::fromGtpApn(const std::string& apn) {
    apn_ = apn;
    return *this;
}

SubscriberContextBuilder& SubscriberContextBuilder::fromNasImsi(const std::string& imsi) {
    imsi_ = imsi;
    return *this;
}

SubscriberContextBuilder& SubscriberContextBuilder::fromNasImei(const std::string& imei) {
    imei_ = imei;
    return *this;
}

SubscriberContextBuilder& SubscriberContextBuilder::fromNasGuti(const Guti4G& guti) {
    guti_ = guti;
    return *this;
}

SubscriberContextBuilder& SubscriberContextBuilder::fromNasTmsi(uint32_t tmsi) {
    tmsi_ = tmsi;
    return *this;
}

SubscriberContextManager::ContextPtr SubscriberContextBuilder::build() {
    // Determine primary identifier for lookup
    SubscriberContextManager::ContextPtr context = nullptr;

    if (imsi_) {
        context = manager_.getOrCreateByImsi(*imsi_);
    } else if (msisdn_) {
        context = manager_.getOrCreateByMsisdn(*msisdn_);
    } else if (ue_ip_) {
        context = manager_.getOrCreateByUeIp(*ue_ip_);
    } else if (imei_) {
        context = manager_.getOrCreateByImei(*imei_);
    }

    if (!context) {
        // No identifiers provided, return nullptr
        return nullptr;
    }

    // Now link all identifiers together
    if (imsi_ && msisdn_) {
        manager_.linkImsiMsisdn(*imsi_, *msisdn_);
    }
    if (imsi_ && imei_) {
        manager_.linkImsiImei(*imsi_, *imei_);
    }
    if (imsi_ && ue_ip_) {
        manager_.linkImsiUeIp(*imsi_, *ue_ip_);
    }
    if (msisdn_ && ue_ip_) {
        manager_.linkMsisdnUeIp(*msisdn_, *ue_ip_);
    }
    if (imsi_ && guti_) {
        manager_.linkImsiGuti(*imsi_, *guti_);
    }
    if (imsi_ && tmsi_) {
        manager_.linkImsiTmsi(*imsi_, *tmsi_);
    }

    // Add GTP-U tunnel information
    for (const auto& [peer_ip, teid] : gtp_tunnels_) {
        if (imsi_) {
            manager_.addGtpuTunnel(*imsi_, peer_ip, teid);
        } else if (msisdn_) {
            manager_.addGtpuTunnel(*msisdn_, peer_ip, teid);
        }
    }

    // Add APN if provided
    if (apn_ && !apn_->empty()) {
        context->apn = *apn_;
    }

    return context;
}

}  // namespace correlation
}  // namespace callflow
