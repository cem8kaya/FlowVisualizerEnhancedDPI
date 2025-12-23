#include "correlation/subscriber_context.h"

#include <algorithm>
#include <iomanip>
#include <random>
#include <sstream>

#include "common/logger.h"

namespace callflow {
namespace correlation {

// ============================================================================
// SubscriberContext::GUTI Implementation
// ============================================================================

std::string SubscriberContext::GUTI::toString() const {
    std::ostringstream oss;
    oss << "GUTI{" << mcc_mnc << ":"
        << std::hex << std::setfill('0')
        << std::setw(4) << mme_group_id << ":"
        << std::setw(2) << static_cast<int>(mme_code) << ":"
        << std::setw(8) << m_tmsi << "}";
    return oss.str();
}

bool SubscriberContext::GUTI::operator==(const GUTI& other) const {
    return mcc_mnc == other.mcc_mnc &&
           mme_group_id == other.mme_group_id &&
           mme_code == other.mme_code &&
           m_tmsi == other.m_tmsi;
}

// ============================================================================
// SubscriberContext::GUTI5G Implementation
// ============================================================================

std::string SubscriberContext::GUTI5G::toString() const {
    std::ostringstream oss;
    oss << "5G-GUTI{" << mcc_mnc << ":"
        << std::hex << std::setfill('0')
        << std::setw(2) << amf_region_id << ":"
        << std::setw(4) << amf_set_id << ":"
        << std::setw(2) << static_cast<int>(amf_pointer) << ":"
        << std::setw(8) << tmsi_5g << "}";
    return oss.str();
}

bool SubscriberContext::GUTI5G::operator==(const GUTI5G& other) const {
    return mcc_mnc == other.mcc_mnc &&
           amf_region_id == other.amf_region_id &&
           amf_set_id == other.amf_set_id &&
           amf_pointer == other.amf_pointer &&
           tmsi_5g == other.tmsi_5g;
}

// ============================================================================
// SubscriberContext Implementation
// ============================================================================

bool SubscriberContext::hasIdentifier(const std::string& id) const {
    if (imsi && *imsi == id) return true;
    if (supi && *supi == id) return true;
    if (msisdn && *msisdn == id) return true;
    if (imei && *imei == id) return true;
    if (imeisv && *imeisv == id) return true;

    if (ue_ipv4_addresses.count(id)) return true;
    if (ue_ipv6_addresses.count(id)) return true;
    if (sip_uris.count(id)) return true;
    if (sip_call_ids.count(id)) return true;
    if (icids.count(id)) return true;

    return false;
}

std::string SubscriberContext::getPrimaryIdentifier() const {
    if (imsi) return *imsi;
    if (supi) return *supi;
    if (msisdn) return *msisdn;
    if (!current_ue_ipv4.empty()) return current_ue_ipv4;
    if (!current_ue_ipv6.empty()) return current_ue_ipv6;
    if (!current_sip_uri.empty()) return current_sip_uri;
    if (current_guti) return current_guti->toString();
    if (current_5g_guti) return current_5g_guti->toString();
    return context_id;
}

std::string SubscriberContext::getDisplayName() const {
    if (msisdn) return *msisdn;
    if (imsi) return *imsi;
    if (supi) return *supi;
    if (!current_sip_uri.empty()) return current_sip_uri;
    return getPrimaryIdentifier();
}

size_t SubscriberContext::getActiveBearerCount() const {
    return std::count_if(bearers.begin(), bearers.end(),
                        [](const BearerInfo& b) { return b.is_active(); });
}

size_t SubscriberContext::getActivePduSessionCount() const {
    return std::count_if(pdu_sessions.begin(), pdu_sessions.end(),
                        [](const PduSessionInfo& p) { return p.is_active(); });
}

nlohmann::json SubscriberContext::toJson() const {
    nlohmann::json j;

    j["context_id"] = context_id;

    // Primary identifiers
    if (imsi) j["imsi"] = *imsi;
    if (supi) j["supi"] = *supi;
    if (msisdn) j["msisdn"] = *msisdn;
    if (imei) j["imei"] = *imei;
    if (imeisv) j["imeisv"] = *imeisv;

    // Temporary identifiers
    if (current_guti) {
        j["current_guti"] = current_guti->toString();
    }
    if (!guti_history.empty()) {
        j["guti_history"] = nlohmann::json::array();
        for (const auto& guti : guti_history) {
            j["guti_history"].push_back(guti.toString());
        }
    }

    if (current_5g_guti) {
        j["current_5g_guti"] = current_5g_guti->toString();
    }
    if (!guti_5g_history.empty()) {
        j["guti_5g_history"] = nlohmann::json::array();
        for (const auto& guti : guti_5g_history) {
            j["guti_5g_history"].push_back(guti.toString());
        }
    }

    // Network-assigned identifiers
    if (!current_ue_ipv4.empty()) j["current_ue_ipv4"] = current_ue_ipv4;
    if (!current_ue_ipv6.empty()) j["current_ue_ipv6"] = current_ue_ipv6;
    if (!ue_ipv4_addresses.empty()) {
        j["ue_ipv4_addresses"] = nlohmann::json::array();
        for (const auto& ip : ue_ipv4_addresses) {
            j["ue_ipv4_addresses"].push_back(ip);
        }
    }
    if (!ue_ipv6_addresses.empty()) {
        j["ue_ipv6_addresses"] = nlohmann::json::array();
        for (const auto& ip : ue_ipv6_addresses) {
            j["ue_ipv6_addresses"].push_back(ip);
        }
    }

    // Bearers
    if (!bearers.empty()) {
        j["bearers"] = nlohmann::json::array();
        for (const auto& bearer : bearers) {
            nlohmann::json b;
            b["teid"] = bearer.teid;
            b["eps_bearer_id"] = bearer.eps_bearer_id;
            b["interface"] = bearer.interface;
            b["pgw_ip"] = bearer.pgw_ip;
            b["qci"] = bearer.qci;
            b["active"] = bearer.is_active();
            if (bearer.uplink_teid > 0) b["uplink_teid"] = bearer.uplink_teid;
            if (bearer.downlink_teid > 0) b["downlink_teid"] = bearer.downlink_teid;
            j["bearers"].push_back(b);
        }
    }

    // PDU Sessions
    if (!pdu_sessions.empty()) {
        j["pdu_sessions"] = nlohmann::json::array();
        for (const auto& session : pdu_sessions) {
            nlohmann::json s;
            s["pdu_session_id"] = session.pdu_session_id;
            s["uplink_teid"] = session.uplink_teid;
            s["downlink_teid"] = session.downlink_teid;
            s["dnn"] = session.dnn;
            s["sst"] = session.sst;
            if (session.sd) s["sd"] = *session.sd;
            s["active"] = session.is_active();
            j["pdu_sessions"].push_back(s);
        }
    }

    // PFCP SEIDs
    if (!seids.empty()) {
        j["seids"] = nlohmann::json::array();
        for (const auto& seid : seids) {
            j["seids"].push_back(seid);
        }
    }

    // Control plane context IDs
    if (mme_ue_s1ap_id) j["mme_ue_s1ap_id"] = *mme_ue_s1ap_id;
    if (enb_ue_s1ap_id) j["enb_ue_s1ap_id"] = *enb_ue_s1ap_id;
    if (amf_ue_ngap_id) j["amf_ue_ngap_id"] = *amf_ue_ngap_id;
    if (ran_ue_ngap_id) j["ran_ue_ngap_id"] = *ran_ue_ngap_id;

    // IMS/VoLTE identifiers
    if (!current_sip_uri.empty()) j["current_sip_uri"] = current_sip_uri;
    if (!sip_uris.empty()) {
        j["sip_uris"] = nlohmann::json::array();
        for (const auto& uri : sip_uris) {
            j["sip_uris"].push_back(uri);
        }
    }
    if (!sip_call_ids.empty()) {
        j["sip_call_ids"] = nlohmann::json::array();
        for (const auto& call_id : sip_call_ids) {
            j["sip_call_ids"].push_back(call_id);
        }
    }
    if (!icids.empty()) {
        j["icids"] = nlohmann::json::array();
        for (const auto& icid : icids) {
            j["icids"].push_back(icid);
        }
    }

    // Session references
    if (!session_ids.empty()) {
        j["session_ids"] = nlohmann::json::array();
        for (const auto& sid : session_ids) {
            j["session_ids"].push_back(sid);
        }
    }

    // Lifecycle
    j["first_seen"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        first_seen.time_since_epoch()).count();
    j["last_updated"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        last_updated.time_since_epoch()).count();

    // Statistics
    j["active_bearer_count"] = getActiveBearerCount();
    j["active_pdu_session_count"] = getActivePduSessionCount();

    return j;
}

// ============================================================================
// SubscriberContextManager Implementation
// ============================================================================

SubscriberContextManager::SubscriberContextManager(size_t max_contexts)
    : max_contexts_(max_contexts) {
    LOG_INFO("SubscriberContextManager initialized with max_contexts=" << max_contexts);
}

SubscriberContextManager::~SubscriberContextManager() {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    LOG_INFO("SubscriberContextManager destroyed. Total contexts tracked: " << contexts_.size());
}

// ============================================================================
// Lookup Methods
// ============================================================================

template<typename KeyType>
std::shared_ptr<SubscriberContext> SubscriberContextManager::lookupInIndex(
    const std::unordered_map<KeyType, std::string>& index,
    const KeyType& key) const {

    std::shared_lock<std::shared_mutex> lock(mutex_);
    stats_.lookups_total++;

    auto it = index.find(key);
    if (it == index.end()) {
        return nullptr;
    }

    auto ctx_it = contexts_.find(it->second);
    if (ctx_it == contexts_.end()) {
        // Stale index entry - should not happen with proper maintenance
        LOG_WARN("Stale index entry detected");
        return nullptr;
    }

    stats_.lookups_hit++;
    return ctx_it->second;
}

std::shared_ptr<SubscriberContext> SubscriberContextManager::findByImsi(const std::string& imsi) {
    return lookupInIndex(imsi_index_, imsi);
}

std::shared_ptr<SubscriberContext> SubscriberContextManager::findBySupi(const std::string& supi) {
    return lookupInIndex(supi_index_, supi);
}

std::shared_ptr<SubscriberContext> SubscriberContextManager::findByMsisdn(const std::string& msisdn) {
    return lookupInIndex(msisdn_index_, msisdn);
}

std::shared_ptr<SubscriberContext> SubscriberContextManager::findByGuti(
    const SubscriberContext::GUTI& guti) {
    return lookupInIndex(guti_index_, guti.toString());
}

std::shared_ptr<SubscriberContext> SubscriberContextManager::findByGuti5G(
    const SubscriberContext::GUTI5G& guti) {
    return lookupInIndex(guti_5g_index_, guti.toString());
}

std::shared_ptr<SubscriberContext> SubscriberContextManager::findByUeIp(const std::string& ip) {
    return lookupInIndex(ue_ip_index_, ip);
}

std::shared_ptr<SubscriberContext> SubscriberContextManager::findByTeid(uint32_t teid) {
    return lookupInIndex(teid_index_, teid);
}

std::shared_ptr<SubscriberContext> SubscriberContextManager::findBySeid(uint64_t seid) {
    return lookupInIndex(seid_index_, seid);
}

std::shared_ptr<SubscriberContext> SubscriberContextManager::findBySipUri(const std::string& uri) {
    return lookupInIndex(sip_uri_index_, uri);
}

std::shared_ptr<SubscriberContext> SubscriberContextManager::findBySipCallId(const std::string& call_id) {
    return lookupInIndex(sip_call_id_index_, call_id);
}

std::shared_ptr<SubscriberContext> SubscriberContextManager::findByMmeUeId(uint32_t mme_ue_s1ap_id) {
    return lookupInIndex(mme_ue_id_index_, mme_ue_s1ap_id);
}

std::shared_ptr<SubscriberContext> SubscriberContextManager::findByEnbUeId(uint32_t enb_ue_s1ap_id) {
    return lookupInIndex(enb_ue_id_index_, enb_ue_s1ap_id);
}

std::shared_ptr<SubscriberContext> SubscriberContextManager::findByAmfUeId(uint64_t amf_ue_ngap_id) {
    return lookupInIndex(amf_ue_id_index_, amf_ue_ngap_id);
}

std::shared_ptr<SubscriberContext> SubscriberContextManager::findByRanUeId(uint64_t ran_ue_ngap_id) {
    return lookupInIndex(ran_ue_id_index_, ran_ue_ngap_id);
}

std::shared_ptr<SubscriberContext> SubscriberContextManager::findByContextId(
    const std::string& context_id) {
    std::shared_lock<std::shared_mutex> lock(mutex_);

    auto it = contexts_.find(context_id);
    return it != contexts_.end() ? it->second : nullptr;
}

// ============================================================================
// Registration Methods
// ============================================================================

std::shared_ptr<SubscriberContext> SubscriberContextManager::getOrCreate(const std::string& imsi) {
    // Try read lock first (fast path)
    {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        auto it = imsi_index_.find(imsi);
        if (it != imsi_index_.end()) {
            auto ctx_it = contexts_.find(it->second);
            if (ctx_it != contexts_.end()) {
                return ctx_it->second;
            }
        }
    }

    // Need to create - upgrade to write lock
    std::unique_lock<std::shared_mutex> lock(mutex_);

    // Double-check after acquiring write lock
    auto it = imsi_index_.find(imsi);
    if (it != imsi_index_.end()) {
        auto ctx_it = contexts_.find(it->second);
        if (ctx_it != contexts_.end()) {
            return ctx_it->second;
        }
    }

    // Create new context
    auto context = std::make_shared<SubscriberContext>();
    context->context_id = generateContextId();
    context->imsi = imsi;
    context->first_seen = std::chrono::system_clock::now();
    context->last_updated = context->first_seen;

    contexts_[context->context_id] = context;
    imsi_index_[imsi] = context->context_id;

    stats_.total_contexts++;
    stats_.with_imsi++;

    LOG_DEBUG("Created new subscriber context: " << context->context_id << " for IMSI: " << imsi);

    return context;
}

std::shared_ptr<SubscriberContext> SubscriberContextManager::getOrCreateBySupi(
    const std::string& supi) {
    // Try read lock first (fast path)
    {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        auto it = supi_index_.find(supi);
        if (it != supi_index_.end()) {
            auto ctx_it = contexts_.find(it->second);
            if (ctx_it != contexts_.end()) {
                return ctx_it->second;
            }
        }
    }

    // Need to create - upgrade to write lock
    std::unique_lock<std::shared_mutex> lock(mutex_);

    // Double-check
    auto it = supi_index_.find(supi);
    if (it != supi_index_.end()) {
        auto ctx_it = contexts_.find(it->second);
        if (ctx_it != contexts_.end()) {
            return ctx_it->second;
        }
    }

    // Create new context
    auto context = std::make_shared<SubscriberContext>();
    context->context_id = generateContextId();
    context->supi = supi;
    context->first_seen = std::chrono::system_clock::now();
    context->last_updated = context->first_seen;

    contexts_[context->context_id] = context;
    supi_index_[supi] = context->context_id;

    stats_.total_contexts++;
    stats_.with_supi++;

    LOG_DEBUG("Created new subscriber context: " << context->context_id << " for SUPI: " << supi);

    return context;
}

std::shared_ptr<SubscriberContext> SubscriberContextManager::createTemporaryContext() {
    std::unique_lock<std::shared_mutex> lock(mutex_);

    auto context = std::make_shared<SubscriberContext>();
    context->context_id = generateContextId();
    context->first_seen = std::chrono::system_clock::now();
    context->last_updated = context->first_seen;

    contexts_[context->context_id] = context;
    stats_.total_contexts++;

    LOG_DEBUG("Created temporary subscriber context: " << context->context_id);

    return context;
}

// ============================================================================
// Update Methods
// ============================================================================

void SubscriberContextManager::updateImsi(const std::string& context_id,
                                         const std::string& imsi) {
    std::unique_lock<std::shared_mutex> lock(mutex_);

    auto it = contexts_.find(context_id);
    if (it == contexts_.end()) {
        LOG_WARN("Cannot update IMSI: context " << context_id << " not found");
        return;
    }

    auto& context = it->second;

    // Remove old index entry if it exists
    if (context->imsi) {
        imsi_index_.erase(*context->imsi);
    } else {
        stats_.with_imsi++;
    }

    context->imsi = imsi;
    context->last_updated = std::chrono::system_clock::now();
    imsi_index_[imsi] = context_id;

    LOG_DEBUG("Updated IMSI for context " << context_id << ": " << imsi);
}

void SubscriberContextManager::updateSupi(const std::string& context_id,
                                         const std::string& supi) {
    std::unique_lock<std::shared_mutex> lock(mutex_);

    auto it = contexts_.find(context_id);
    if (it == contexts_.end()) {
        LOG_WARN("Cannot update SUPI: context " << context_id << " not found");
        return;
    }

    auto& context = it->second;

    if (context->supi) {
        supi_index_.erase(*context->supi);
    } else {
        stats_.with_supi++;
    }

    context->supi = supi;
    context->last_updated = std::chrono::system_clock::now();
    supi_index_[supi] = context_id;

    LOG_DEBUG("Updated SUPI for context " << context_id << ": " << supi);
}

void SubscriberContextManager::updateMsisdn(const std::string& context_id,
                                           const std::string& msisdn) {
    std::unique_lock<std::shared_mutex> lock(mutex_);

    auto it = contexts_.find(context_id);
    if (it == contexts_.end()) {
        LOG_WARN("Cannot update MSISDN: context " << context_id << " not found");
        return;
    }

    auto& context = it->second;

    if (context->msisdn) {
        msisdn_index_.erase(*context->msisdn);
    } else {
        stats_.with_msisdn++;
    }

    context->msisdn = msisdn;
    context->last_updated = std::chrono::system_clock::now();
    msisdn_index_[msisdn] = context_id;

    LOG_DEBUG("Updated MSISDN for context " << context_id << ": " << msisdn);
}

void SubscriberContextManager::updateImei(const std::string& context_id,
                                         const std::string& imei) {
    std::unique_lock<std::shared_mutex> lock(mutex_);

    auto it = contexts_.find(context_id);
    if (it == contexts_.end()) {
        LOG_WARN("Cannot update IMEI: context " << context_id << " not found");
        return;
    }

    auto& context = it->second;
    context->imei = imei;
    context->last_updated = std::chrono::system_clock::now();

    LOG_DEBUG("Updated IMEI for context " << context_id << ": " << imei);
}

void SubscriberContextManager::updateGuti(const std::string& context_id,
                                         const SubscriberContext::GUTI& guti) {
    std::unique_lock<std::shared_mutex> lock(mutex_);

    auto it = contexts_.find(context_id);
    if (it == contexts_.end()) {
        LOG_WARN("Cannot update GUTI: context " << context_id << " not found");
        return;
    }

    auto& context = it->second;

    // Remove old GUTI from index
    if (context->current_guti) {
        guti_index_.erase(context->current_guti->toString());
    }

    // Add old GUTI to history if it's different
    if (context->current_guti && *context->current_guti != guti) {
        context->guti_history.push_back(*context->current_guti);
    }

    context->current_guti = guti;
    context->last_updated = std::chrono::system_clock::now();
    guti_index_[guti.toString()] = context_id;

    LOG_DEBUG("Updated GUTI for context " << context_id << ": " << guti.toString());
}

void SubscriberContextManager::updateGuti5G(const std::string& context_id,
                                           const SubscriberContext::GUTI5G& guti) {
    std::unique_lock<std::shared_mutex> lock(mutex_);

    auto it = contexts_.find(context_id);
    if (it == contexts_.end()) {
        LOG_WARN("Cannot update 5G-GUTI: context " << context_id << " not found");
        return;
    }

    auto& context = it->second;

    if (context->current_5g_guti) {
        guti_5g_index_.erase(context->current_5g_guti->toString());
    }

    if (context->current_5g_guti && *context->current_5g_guti != guti) {
        context->guti_5g_history.push_back(*context->current_5g_guti);
    }

    context->current_5g_guti = guti;
    context->last_updated = std::chrono::system_clock::now();
    guti_5g_index_[guti.toString()] = context_id;

    LOG_DEBUG("Updated 5G-GUTI for context " << context_id << ": " << guti.toString());
}

void SubscriberContextManager::updateUeIp(const std::string& context_id,
                                         const std::string& ipv4,
                                         const std::string& ipv6) {
    std::unique_lock<std::shared_mutex> lock(mutex_);

    auto it = contexts_.find(context_id);
    if (it == contexts_.end()) {
        LOG_WARN("Cannot update UE IP: context " << context_id << " not found");
        return;
    }

    auto& context = it->second;
    bool was_empty = context->ue_ipv4_addresses.empty() && context->ue_ipv6_addresses.empty();

    if (!ipv4.empty()) {
        // Remove old current IPv4 from index if different
        if (!context->current_ue_ipv4.empty() && context->current_ue_ipv4 != ipv4) {
            // Keep in history but update current
        }

        context->ue_ipv4_addresses.insert(ipv4);
        context->current_ue_ipv4 = ipv4;
        ue_ip_index_[ipv4] = context_id;
        LOG_DEBUG("Updated UE IPv4 for context " << context_id << ": " << ipv4);
    }

    if (!ipv6.empty()) {
        if (!context->current_ue_ipv6.empty() && context->current_ue_ipv6 != ipv6) {
            // Keep in history but update current
        }

        context->ue_ipv6_addresses.insert(ipv6);
        context->current_ue_ipv6 = ipv6;
        ue_ip_index_[ipv6] = context_id;
        LOG_DEBUG("Updated UE IPv6 for context " << context_id << ": " << ipv6);
    }

    if (was_empty && (!context->ue_ipv4_addresses.empty() || !context->ue_ipv6_addresses.empty())) {
        stats_.with_ue_ip++;
    }

    context->last_updated = std::chrono::system_clock::now();
}

void SubscriberContextManager::addBearer(const std::string& context_id,
                                        const SubscriberContext::BearerInfo& bearer) {
    std::unique_lock<std::shared_mutex> lock(mutex_);

    auto it = contexts_.find(context_id);
    if (it == contexts_.end()) {
        LOG_WARN("Cannot add bearer: context " << context_id << " not found");
        return;
    }

    auto& context = it->second;
    bool had_active_bearers = context->getActiveBearerCount() > 0;

    context->bearers.push_back(bearer);
    teid_index_[bearer.teid] = context_id;
    if (bearer.uplink_teid > 0) {
        teid_index_[static_cast<uint32_t>(bearer.uplink_teid)] = context_id;
    }
    if (bearer.downlink_teid > 0) {
        teid_index_[static_cast<uint32_t>(bearer.downlink_teid)] = context_id;
    }

    if (!had_active_bearers && context->getActiveBearerCount() > 0) {
        stats_.with_active_bearers++;
    }

    context->last_updated = std::chrono::system_clock::now();

    LOG_DEBUG("Added bearer to context " << context_id << ": TEID=" << bearer.teid
              << " bearer_id=" << static_cast<int>(bearer.eps_bearer_id));
}

void SubscriberContextManager::removeBearer(const std::string& context_id, uint32_t teid) {
    std::unique_lock<std::shared_mutex> lock(mutex_);

    auto it = contexts_.find(context_id);
    if (it == contexts_.end()) {
        LOG_WARN("Cannot remove bearer: context " << context_id << " not found");
        return;
    }

    auto& context = it->second;

    for (auto& bearer : context->bearers) {
        if (bearer.teid == teid && bearer.is_active()) {
            bearer.deleted = std::chrono::system_clock::now();
            context->last_updated = bearer.deleted.value();

            // Remove from index
            teid_index_.erase(teid);

            if (context->getActiveBearerCount() == 0) {
                stats_.with_active_bearers--;
            }

            LOG_DEBUG("Removed bearer from context " << context_id << ": TEID=" << teid);
            return;
        }
    }

    LOG_WARN("Bearer with TEID " << teid << " not found in context " << context_id);
}

void SubscriberContextManager::addPduSession(const std::string& context_id,
                                            const SubscriberContext::PduSessionInfo& session) {
    std::unique_lock<std::shared_mutex> lock(mutex_);

    auto it = contexts_.find(context_id);
    if (it == contexts_.end()) {
        LOG_WARN("Cannot add PDU session: context " << context_id << " not found");
        return;
    }

    auto& context = it->second;
    bool had_active_sessions = context->getActivePduSessionCount() > 0;

    context->pdu_sessions.push_back(session);

    if (!had_active_sessions && context->getActivePduSessionCount() > 0) {
        stats_.with_active_pdu_sessions++;
    }

    context->last_updated = std::chrono::system_clock::now();

    LOG_DEBUG("Added PDU session to context " << context_id
              << ": session_id=" << static_cast<int>(session.pdu_session_id));
}

void SubscriberContextManager::removePduSession(const std::string& context_id,
                                               uint8_t pdu_session_id) {
    std::unique_lock<std::shared_mutex> lock(mutex_);

    auto it = contexts_.find(context_id);
    if (it == contexts_.end()) {
        LOG_WARN("Cannot remove PDU session: context " << context_id << " not found");
        return;
    }

    auto& context = it->second;

    for (auto& session : context->pdu_sessions) {
        if (session.pdu_session_id == pdu_session_id && session.is_active()) {
            session.deleted = std::chrono::system_clock::now();
            context->last_updated = session.deleted.value();

            if (context->getActivePduSessionCount() == 0) {
                stats_.with_active_pdu_sessions--;
            }

            LOG_DEBUG("Removed PDU session from context " << context_id
                      << ": session_id=" << static_cast<int>(pdu_session_id));
            return;
        }
    }

    LOG_WARN("PDU session " << static_cast<int>(pdu_session_id)
             << " not found in context " << context_id);
}

void SubscriberContextManager::addSeid(const std::string& context_id, uint64_t seid) {
    std::unique_lock<std::shared_mutex> lock(mutex_);

    auto it = contexts_.find(context_id);
    if (it == contexts_.end()) {
        LOG_WARN("Cannot add SEID: context " << context_id << " not found");
        return;
    }

    auto& context = it->second;
    context->seids.insert(seid);
    seid_index_[seid] = context_id;
    context->last_updated = std::chrono::system_clock::now();

    LOG_DEBUG("Added SEID to context " << context_id << ": " << seid);
}

void SubscriberContextManager::updateMmeUeId(const std::string& context_id,
                                            uint32_t mme_ue_s1ap_id) {
    std::unique_lock<std::shared_mutex> lock(mutex_);

    auto it = contexts_.find(context_id);
    if (it == contexts_.end()) {
        LOG_WARN("Cannot update MME UE S1AP ID: context " << context_id << " not found");
        return;
    }

    auto& context = it->second;

    if (context->mme_ue_s1ap_id) {
        mme_ue_id_index_.erase(*context->mme_ue_s1ap_id);
    }

    context->mme_ue_s1ap_id = mme_ue_s1ap_id;
    mme_ue_id_index_[mme_ue_s1ap_id] = context_id;
    context->last_updated = std::chrono::system_clock::now();

    LOG_DEBUG("Updated MME UE S1AP ID for context " << context_id << ": " << mme_ue_s1ap_id);
}

void SubscriberContextManager::updateEnbUeId(const std::string& context_id,
                                            uint32_t enb_ue_s1ap_id) {
    std::unique_lock<std::shared_mutex> lock(mutex_);

    auto it = contexts_.find(context_id);
    if (it == contexts_.end()) {
        LOG_WARN("Cannot update eNB UE S1AP ID: context " << context_id << " not found");
        return;
    }

    auto& context = it->second;

    if (context->enb_ue_s1ap_id) {
        enb_ue_id_index_.erase(*context->enb_ue_s1ap_id);
    }

    context->enb_ue_s1ap_id = enb_ue_s1ap_id;
    enb_ue_id_index_[enb_ue_s1ap_id] = context_id;
    context->last_updated = std::chrono::system_clock::now();

    LOG_DEBUG("Updated eNB UE S1AP ID for context " << context_id << ": " << enb_ue_s1ap_id);
}

void SubscriberContextManager::updateAmfUeId(const std::string& context_id,
                                            uint64_t amf_ue_ngap_id) {
    std::unique_lock<std::shared_mutex> lock(mutex_);

    auto it = contexts_.find(context_id);
    if (it == contexts_.end()) {
        LOG_WARN("Cannot update AMF UE NGAP ID: context " << context_id << " not found");
        return;
    }

    auto& context = it->second;

    if (context->amf_ue_ngap_id) {
        amf_ue_id_index_.erase(*context->amf_ue_ngap_id);
    }

    context->amf_ue_ngap_id = amf_ue_ngap_id;
    amf_ue_id_index_[amf_ue_ngap_id] = context_id;
    context->last_updated = std::chrono::system_clock::now();

    LOG_DEBUG("Updated AMF UE NGAP ID for context " << context_id << ": " << amf_ue_ngap_id);
}

void SubscriberContextManager::updateRanUeId(const std::string& context_id,
                                            uint64_t ran_ue_ngap_id) {
    std::unique_lock<std::shared_mutex> lock(mutex_);

    auto it = contexts_.find(context_id);
    if (it == contexts_.end()) {
        LOG_WARN("Cannot update RAN UE NGAP ID: context " << context_id << " not found");
        return;
    }

    auto& context = it->second;

    if (context->ran_ue_ngap_id) {
        ran_ue_id_index_.erase(*context->ran_ue_ngap_id);
    }

    context->ran_ue_ngap_id = ran_ue_ngap_id;
    ran_ue_id_index_[ran_ue_ngap_id] = context_id;
    context->last_updated = std::chrono::system_clock::now();

    LOG_DEBUG("Updated RAN UE NGAP ID for context " << context_id << ": " << ran_ue_ngap_id);
}

void SubscriberContextManager::updateSipUri(const std::string& context_id,
                                           const std::string& uri) {
    std::unique_lock<std::shared_mutex> lock(mutex_);

    auto it = contexts_.find(context_id);
    if (it == contexts_.end()) {
        LOG_WARN("Cannot update SIP URI: context " << context_id << " not found");
        return;
    }

    auto& context = it->second;
    bool was_empty = context->sip_uris.empty();

    context->sip_uris.insert(uri);
    context->current_sip_uri = uri;
    sip_uri_index_[uri] = context_id;
    context->last_updated = std::chrono::system_clock::now();

    if (was_empty) {
        stats_.with_sip_sessions++;
    }

    LOG_DEBUG("Updated SIP URI for context " << context_id << ": " << uri);
}

void SubscriberContextManager::addSipCallId(const std::string& context_id,
                                           const std::string& call_id) {
    std::unique_lock<std::shared_mutex> lock(mutex_);

    auto it = contexts_.find(context_id);
    if (it == contexts_.end()) {
        LOG_WARN("Cannot add SIP Call-ID: context " << context_id << " not found");
        return;
    }

    auto& context = it->second;
    context->sip_call_ids.insert(call_id);
    sip_call_id_index_[call_id] = context_id;
    context->last_updated = std::chrono::system_clock::now();

    LOG_DEBUG("Added SIP Call-ID to context " << context_id << ": " << call_id);
}

void SubscriberContextManager::addIcid(const std::string& context_id,
                                      const std::string& icid) {
    std::unique_lock<std::shared_mutex> lock(mutex_);

    auto it = contexts_.find(context_id);
    if (it == contexts_.end()) {
        LOG_WARN("Cannot add ICID: context " << context_id << " not found");
        return;
    }

    auto& context = it->second;
    context->icids.insert(icid);
    icid_index_[icid] = context_id;
    context->last_updated = std::chrono::system_clock::now();

    LOG_DEBUG("Added ICID to context " << context_id << ": " << icid);
}

void SubscriberContextManager::addSessionId(const std::string& context_id,
                                           const std::string& session_id) {
    std::unique_lock<std::shared_mutex> lock(mutex_);

    auto it = contexts_.find(context_id);
    if (it == contexts_.end()) {
        LOG_WARN("Cannot add session ID: context " << context_id << " not found");
        return;
    }

    auto& context = it->second;
    context->session_ids.insert(session_id);
    context->last_updated = std::chrono::system_clock::now();

    LOG_DEBUG("Added session ID to context " << context_id << ": " << session_id);
}

// ============================================================================
// Context Merge
// ============================================================================

bool SubscriberContextManager::mergeContexts(const std::string& context_id_keep,
                                            const std::string& context_id_merge) {
    std::unique_lock<std::shared_mutex> lock(mutex_);

    auto it_keep = contexts_.find(context_id_keep);
    auto it_merge = contexts_.find(context_id_merge);

    if (it_keep == contexts_.end() || it_merge == contexts_.end()) {
        LOG_WARN("Cannot merge contexts: one or both not found");
        return false;
    }

    auto& ctx_keep = it_keep->second;
    auto& ctx_merge = it_merge->second;

    LOG_INFO("Merging context " << context_id_merge << " into " << context_id_keep);

    // Merge primary identifiers
    if (!ctx_keep->imsi && ctx_merge->imsi) {
        ctx_keep->imsi = ctx_merge->imsi;
        imsi_index_[*ctx_merge->imsi] = context_id_keep;
    }
    if (!ctx_keep->supi && ctx_merge->supi) {
        ctx_keep->supi = ctx_merge->supi;
        supi_index_[*ctx_merge->supi] = context_id_keep;
    }
    if (!ctx_keep->msisdn && ctx_merge->msisdn) {
        ctx_keep->msisdn = ctx_merge->msisdn;
        msisdn_index_[*ctx_merge->msisdn] = context_id_keep;
    }
    if (!ctx_keep->imei && ctx_merge->imei) {
        ctx_keep->imei = ctx_merge->imei;
    }
    if (!ctx_keep->imeisv && ctx_merge->imeisv) {
        ctx_keep->imeisv = ctx_merge->imeisv;
    }

    // Merge GUTI
    if (!ctx_keep->current_guti && ctx_merge->current_guti) {
        ctx_keep->current_guti = ctx_merge->current_guti;
        guti_index_[ctx_merge->current_guti->toString()] = context_id_keep;
    }
    ctx_keep->guti_history.insert(ctx_keep->guti_history.end(),
                                  ctx_merge->guti_history.begin(),
                                  ctx_merge->guti_history.end());

    // Merge 5G-GUTI
    if (!ctx_keep->current_5g_guti && ctx_merge->current_5g_guti) {
        ctx_keep->current_5g_guti = ctx_merge->current_5g_guti;
        guti_5g_index_[ctx_merge->current_5g_guti->toString()] = context_id_keep;
    }
    ctx_keep->guti_5g_history.insert(ctx_keep->guti_5g_history.end(),
                                     ctx_merge->guti_5g_history.begin(),
                                     ctx_merge->guti_5g_history.end());

    // Merge UE IPs
    for (const auto& ip : ctx_merge->ue_ipv4_addresses) {
        ctx_keep->ue_ipv4_addresses.insert(ip);
        ue_ip_index_[ip] = context_id_keep;
    }
    for (const auto& ip : ctx_merge->ue_ipv6_addresses) {
        ctx_keep->ue_ipv6_addresses.insert(ip);
        ue_ip_index_[ip] = context_id_keep;
    }
    if (ctx_keep->current_ue_ipv4.empty() && !ctx_merge->current_ue_ipv4.empty()) {
        ctx_keep->current_ue_ipv4 = ctx_merge->current_ue_ipv4;
    }
    if (ctx_keep->current_ue_ipv6.empty() && !ctx_merge->current_ue_ipv6.empty()) {
        ctx_keep->current_ue_ipv6 = ctx_merge->current_ue_ipv6;
    }

    // Merge bearers
    for (const auto& bearer : ctx_merge->bearers) {
        ctx_keep->bearers.push_back(bearer);
        teid_index_[bearer.teid] = context_id_keep;
    }

    // Merge PDU sessions
    for (const auto& session : ctx_merge->pdu_sessions) {
        ctx_keep->pdu_sessions.push_back(session);
    }

    // Merge SEIDs
    for (const auto& seid : ctx_merge->seids) {
        ctx_keep->seids.insert(seid);
        seid_index_[seid] = context_id_keep;
    }

    // Merge control plane IDs
    if (!ctx_keep->mme_ue_s1ap_id && ctx_merge->mme_ue_s1ap_id) {
        ctx_keep->mme_ue_s1ap_id = ctx_merge->mme_ue_s1ap_id;
        mme_ue_id_index_[*ctx_merge->mme_ue_s1ap_id] = context_id_keep;
    }
    if (!ctx_keep->enb_ue_s1ap_id && ctx_merge->enb_ue_s1ap_id) {
        ctx_keep->enb_ue_s1ap_id = ctx_merge->enb_ue_s1ap_id;
        enb_ue_id_index_[*ctx_merge->enb_ue_s1ap_id] = context_id_keep;
    }
    if (!ctx_keep->amf_ue_ngap_id && ctx_merge->amf_ue_ngap_id) {
        ctx_keep->amf_ue_ngap_id = ctx_merge->amf_ue_ngap_id;
        amf_ue_id_index_[*ctx_merge->amf_ue_ngap_id] = context_id_keep;
    }
    if (!ctx_keep->ran_ue_ngap_id && ctx_merge->ran_ue_ngap_id) {
        ctx_keep->ran_ue_ngap_id = ctx_merge->ran_ue_ngap_id;
        ran_ue_id_index_[*ctx_merge->ran_ue_ngap_id] = context_id_keep;
    }

    // Merge IMS/VoLTE identifiers
    for (const auto& uri : ctx_merge->sip_uris) {
        ctx_keep->sip_uris.insert(uri);
        sip_uri_index_[uri] = context_id_keep;
    }
    if (ctx_keep->current_sip_uri.empty() && !ctx_merge->current_sip_uri.empty()) {
        ctx_keep->current_sip_uri = ctx_merge->current_sip_uri;
    }
    for (const auto& call_id : ctx_merge->sip_call_ids) {
        ctx_keep->sip_call_ids.insert(call_id);
        sip_call_id_index_[call_id] = context_id_keep;
    }
    for (const auto& icid : ctx_merge->icids) {
        ctx_keep->icids.insert(icid);
        icid_index_[icid] = context_id_keep;
    }

    // Merge session IDs
    for (const auto& sid : ctx_merge->session_ids) {
        ctx_keep->session_ids.insert(sid);
    }

    // Update lifecycle
    if (ctx_merge->first_seen < ctx_keep->first_seen) {
        ctx_keep->first_seen = ctx_merge->first_seen;
    }
    ctx_keep->last_updated = std::chrono::system_clock::now();

    // Remove merged context
    contexts_.erase(context_id_merge);
    stats_.total_contexts--;
    stats_.merges_total++;

    LOG_INFO("Successfully merged contexts. Resulting context has "
             << ctx_keep->bearers.size() << " bearers, "
             << ctx_keep->sip_call_ids.size() << " SIP calls");

    return true;
}

// ============================================================================
// Cleanup
// ============================================================================

size_t SubscriberContextManager::cleanupStaleContexts(
    std::chrono::system_clock::time_point cutoff) {
    std::unique_lock<std::shared_mutex> lock(mutex_);

    std::vector<std::string> to_remove;

    for (const auto& [context_id, context] : contexts_) {
        if (context->last_updated < cutoff) {
            to_remove.push_back(context_id);
        }
    }

    for (const auto& context_id : to_remove) {
        auto it = contexts_.find(context_id);
        if (it != contexts_.end()) {
            removeFromAllIndices(it->second);
            contexts_.erase(it);
            stats_.total_contexts--;
        }
    }

    stats_.cleanups_total += to_remove.size();

    if (!to_remove.empty()) {
        LOG_INFO("Cleaned up " << to_remove.size() << " stale subscriber contexts");
    }

    return to_remove.size();
}

bool SubscriberContextManager::removeContext(const std::string& context_id) {
    std::unique_lock<std::shared_mutex> lock(mutex_);

    auto it = contexts_.find(context_id);
    if (it == contexts_.end()) {
        return false;
    }

    removeFromAllIndices(it->second);
    contexts_.erase(it);
    stats_.total_contexts--;

    LOG_DEBUG("Removed context: " << context_id);

    return true;
}

void SubscriberContextManager::removeFromAllIndices(
    const std::shared_ptr<SubscriberContext>& context) {

    if (context->imsi) {
        imsi_index_.erase(*context->imsi);
        stats_.with_imsi--;
    }
    if (context->supi) {
        supi_index_.erase(*context->supi);
        stats_.with_supi--;
    }
    if (context->msisdn) {
        msisdn_index_.erase(*context->msisdn);
        stats_.with_msisdn--;
    }
    if (context->current_guti) {
        guti_index_.erase(context->current_guti->toString());
    }
    if (context->current_5g_guti) {
        guti_5g_index_.erase(context->current_5g_guti->toString());
    }

    for (const auto& ip : context->ue_ipv4_addresses) {
        ue_ip_index_.erase(ip);
    }
    for (const auto& ip : context->ue_ipv6_addresses) {
        ue_ip_index_.erase(ip);
    }
    if (!context->ue_ipv4_addresses.empty() || !context->ue_ipv6_addresses.empty()) {
        stats_.with_ue_ip--;
    }

    for (const auto& bearer : context->bearers) {
        teid_index_.erase(bearer.teid);
    }
    if (context->getActiveBearerCount() > 0) {
        stats_.with_active_bearers--;
    }

    if (context->getActivePduSessionCount() > 0) {
        stats_.with_active_pdu_sessions--;
    }

    for (const auto& seid : context->seids) {
        seid_index_.erase(seid);
    }

    if (context->mme_ue_s1ap_id) {
        mme_ue_id_index_.erase(*context->mme_ue_s1ap_id);
    }
    if (context->enb_ue_s1ap_id) {
        enb_ue_id_index_.erase(*context->enb_ue_s1ap_id);
    }
    if (context->amf_ue_ngap_id) {
        amf_ue_id_index_.erase(*context->amf_ue_ngap_id);
    }
    if (context->ran_ue_ngap_id) {
        ran_ue_id_index_.erase(*context->ran_ue_ngap_id);
    }

    for (const auto& uri : context->sip_uris) {
        sip_uri_index_.erase(uri);
    }
    for (const auto& call_id : context->sip_call_ids) {
        sip_call_id_index_.erase(call_id);
    }
    for (const auto& icid : context->icids) {
        icid_index_.erase(icid);
    }
    if (!context->sip_uris.empty()) {
        stats_.with_sip_sessions--;
    }
}

// ============================================================================
// Statistics
// ============================================================================

nlohmann::json SubscriberContextManager::Stats::toJson() const {
    nlohmann::json j;
    j["total_contexts"] = total_contexts;
    j["with_imsi"] = with_imsi;
    j["with_supi"] = with_supi;
    j["with_msisdn"] = with_msisdn;
    j["with_ue_ip"] = with_ue_ip;
    j["with_active_bearers"] = with_active_bearers;
    j["with_active_pdu_sessions"] = with_active_pdu_sessions;
    j["with_sip_sessions"] = with_sip_sessions;
    j["lookups_total"] = lookups_total;
    j["lookups_hit"] = lookups_hit;
    j["hit_rate"] = getHitRate();
    j["merges_total"] = merges_total;
    j["cleanups_total"] = cleanups_total;
    return j;
}

SubscriberContextManager::Stats SubscriberContextManager::getStats() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return stats_;
}

void SubscriberContextManager::resetStats() {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    stats_.lookups_total = 0;
    stats_.lookups_hit = 0;
    stats_.merges_total = 0;
    stats_.cleanups_total = 0;
}

// ============================================================================
// Internal Helper Methods
// ============================================================================

std::string SubscriberContextManager::generateContextId() {
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    static std::uniform_int_distribution<uint64_t> dis;

    std::ostringstream oss;
    oss << "ctx_" << std::hex << std::setfill('0') << std::setw(16) << dis(gen);
    return oss.str();
}

}  // namespace correlation
}  // namespace callflow
