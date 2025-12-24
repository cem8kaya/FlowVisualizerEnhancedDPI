#include "correlation/gtpv2/gtpv2_correlator.h"

#include <algorithm>
#include <iomanip>
#include <sstream>

namespace callflow {
namespace correlation {

Gtpv2Correlator::Gtpv2Correlator() : ctx_manager_(nullptr) {}

Gtpv2Correlator::Gtpv2Correlator(SubscriberContextManager* ctx_manager)
    : ctx_manager_(ctx_manager) {}

std::string Gtpv2Correlator::generateSessionKey(uint32_t teid, uint32_t sequence) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(8) << teid << "_" << std::setw(8) << sequence;
    return ss.str();
}

std::string Gtpv2Correlator::generateIntraCorrelator(double timestamp, int seq) {
    std::stringstream ss;
    ss << "gtpv2_" << std::fixed << std::setprecision(6) << timestamp << "_" << seq;
    return ss.str();
}

Gtpv2Session* Gtpv2Correlator::findOrCreateSession(const Gtpv2Message& msg) {
    uint32_t teid = msg.getTeid();
    uint32_t sequence = msg.getSequence();

    // For session establishment messages, use sequence to create new session
    if (isSessionEstablishment(msg.getMessageType())) {
        std::string key = generateSessionKey(teid, sequence);

        auto it = sessions_.find(key);
        if (it != sessions_.end()) {
            return it->second.get();
        }

        // Create new session
        auto session = std::make_unique<Gtpv2Session>(teid, sequence);
        session->setIntraCorrelator(
            generateIntraCorrelator(msg.getTimestamp(), session_sequence_++));

        Gtpv2Session* session_ptr = session.get();
        sessions_[key] = std::move(session);
        stats_.total_sessions++;

        return session_ptr;
    }

    // For other messages, try to find existing session by TEID
    Gtpv2Session* session = findByControlTeid(teid);
    if (session) {
        return session;
    }

    // If not found and this is a response, create session anyway
    // (sometimes we miss the request)
    if (isResponse(msg.getMessageType())) {
        std::string key = generateSessionKey(teid, sequence);

        auto session_obj = std::make_unique<Gtpv2Session>(teid, sequence);
        session_obj->setIntraCorrelator(
            generateIntraCorrelator(msg.getTimestamp(), session_sequence_++));

        session = session_obj.get();
        sessions_[key] = std::move(session_obj);
        stats_.total_sessions++;
    }

    return session;
}

void Gtpv2Correlator::addMessage(const Gtpv2Message& msg) {
    std::lock_guard<std::mutex> lock(mutex_);

    stats_.total_messages++;

    // Find or create session
    Gtpv2Session* session = findOrCreateSession(msg);
    if (!session) {
        stats_.session_errors++;
        return;
    }

    // Add message to session
    session->addMessage(msg);

    // Update lookup indices
    updateLookupIndices(session);

    // Register F-TEIDs
    registerSessionFteids(session);

    // Update subscriber context
    if (ctx_manager_) {
        updateSubscriberContext(*session);
    }

    // Track errors
    if (msg.isError()) {
        stats_.session_errors++;
    }
}

void Gtpv2Correlator::finalize() {
    std::lock_guard<std::mutex> lock(mutex_);

    // Reset stats
    stats_.ims_sessions = 0;
    stats_.internet_sessions = 0;
    stats_.emergency_sessions = 0;
    stats_.sessions_with_dedicated_bearers = 0;
    stats_.total_bearers = 0;
    stats_.default_bearers = 0;
    stats_.dedicated_bearers = 0;
    stats_.active_sessions = 0;
    stats_.deleted_sessions = 0;

    for (auto& [key, session] : sessions_) {
        session->finalize();

        // Update statistics
        if (session->isIms()) {
            stats_.ims_sessions++;
        }
        if (session->getPdnClass() == PdnClass::INTERNET) {
            stats_.internet_sessions++;
        }
        if (session->isEmergency()) {
            stats_.emergency_sessions++;
        }
        if (session->hasDedicatedBearers()) {
            stats_.sessions_with_dedicated_bearers++;
        }

        auto bearers = session->getBearers();
        stats_.total_bearers += bearers.size();
        for (const auto* bearer : bearers) {
            if (bearer->isDefault()) {
                stats_.default_bearers++;
            } else {
                stats_.dedicated_bearers++;
            }
        }

        if (session->isActive()) {
            stats_.active_sessions++;
        }
        if (session->getState() == Gtpv2Session::State::DELETED) {
            stats_.deleted_sessions++;
        }

        // Final subscriber context update
        if (ctx_manager_) {
            updateSubscriberContext(*session);
        }
    }
}

std::vector<Gtpv2Session*> Gtpv2Correlator::getSessions() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Gtpv2Session*> result;
    for (auto& [key, session] : sessions_) {
        result.push_back(session.get());
    }
    return result;
}

std::vector<Gtpv2Session*> Gtpv2Correlator::getImsSessions() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Gtpv2Session*> result;
    for (auto& [key, session] : sessions_) {
        if (session->isIms()) {
            result.push_back(session.get());
        }
    }
    return result;
}

std::vector<Gtpv2Session*> Gtpv2Correlator::getSessionsWithDedicatedBearers() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Gtpv2Session*> result;
    for (auto& [key, session] : sessions_) {
        if (session->hasDedicatedBearers()) {
            result.push_back(session.get());
        }
    }
    return result;
}

std::vector<Gtpv2Session*> Gtpv2Correlator::getInternetSessions() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Gtpv2Session*> result;
    for (auto& [key, session] : sessions_) {
        if (session->getPdnClass() == PdnClass::INTERNET) {
            result.push_back(session.get());
        }
    }
    return result;
}

std::vector<Gtpv2Session*> Gtpv2Correlator::getEmergencySessions() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Gtpv2Session*> result;
    for (auto& [key, session] : sessions_) {
        if (session->isEmergency()) {
            result.push_back(session.get());
        }
    }
    return result;
}

Gtpv2Session* Gtpv2Correlator::findByControlTeid(uint32_t teid) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = teid_to_session_.find(teid);
    if (it != teid_to_session_.end()) {
        return it->second;
    }
    return nullptr;
}

std::vector<Gtpv2Session*> Gtpv2Correlator::findByImsi(const std::string& imsi) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = imsi_to_sessions_.find(imsi);
    if (it != imsi_to_sessions_.end()) {
        return it->second;
    }
    return {};
}

std::vector<Gtpv2Session*> Gtpv2Correlator::findByMsisdn(const std::string& msisdn) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = msisdn_to_sessions_.find(msisdn);
    if (it != msisdn_to_sessions_.end()) {
        return it->second;
    }
    return {};
}

Gtpv2Session* Gtpv2Correlator::findByPdnAddress(const std::string& ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = pdn_address_to_session_.find(ip);
    if (it != pdn_address_to_session_.end()) {
        return it->second;
    }
    return nullptr;
}

Gtpv2Session* Gtpv2Correlator::findByFteid(const std::string& ip, uint32_t teid) {
    // No lock needed - fteid_manager has its own locking if needed
    return fteid_manager_.findSessionByFteid(ip, teid);
}

Gtpv2Session* Gtpv2Correlator::findByGtpuPacket(const std::string& src_ip,
                                                const std::string& dst_ip, uint32_t teid) {
    return fteid_manager_.findSessionByGtpuPacket(src_ip, dst_ip, teid);
}

Gtpv2Correlator::Stats Gtpv2Correlator::getStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

void Gtpv2Correlator::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    sessions_.clear();
    teid_to_session_.clear();
    imsi_to_sessions_.clear();
    msisdn_to_sessions_.clear();
    pdn_address_to_session_.clear();
    fteid_manager_.clear();
    stats_ = Stats();
    session_sequence_ = 0;
}

size_t Gtpv2Correlator::getSessionCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return sessions_.size();
}

void Gtpv2Correlator::updateSubscriberContext(const Gtpv2Session& session) {
    if (!ctx_manager_) {
        return;
    }

    SubscriberContextBuilder builder(*ctx_manager_);

    // Add IMSI
    auto imsi = session.getImsi();
    if (imsi.has_value()) {
        builder.fromGtpImsi(imsi.value());
    }

    // Add MSISDN if available
    auto msisdn = session.getMsisdn();
    if (msisdn.has_value()) {
        builder.fromGtpMsisdn(msisdn.value());
    }

    // Add MEI if available
    auto mei = session.getMei();
    if (mei.has_value()) {
        builder.fromGtpMei(mei.value());
    }

    // Add PDN addresses if available
    auto pdn_v4 = session.getPdnAddressV4();
    if (pdn_v4.has_value()) {
        builder.fromGtpPdnAddress(pdn_v4.value());
    }

    auto pdn_v6 = session.getPdnAddressV6();
    if (pdn_v6.has_value()) {
        builder.fromGtpPdnAddress(pdn_v6.value());
    }

    // Add Access Point Name
    auto apn = session.getApn();
    if (!apn.empty()) {
        builder.fromGtpApn(apn);
    }

    // Build context
    builder.build();
}

void Gtpv2Correlator::updateLookupIndices(Gtpv2Session* session) {
    if (!session) {
        return;
    }

    // Update TEID index
    teid_to_session_[session->getControlTeid()] = session;

    // Update IMSI index
    auto imsi = session->getImsi();
    if (imsi.has_value()) {
        auto& sessions = imsi_to_sessions_[imsi.value()];
        if (std::find(sessions.begin(), sessions.end(), session) == sessions.end()) {
            sessions.push_back(session);
        }
    }

    // Update MSISDN index
    auto msisdn = session->getMsisdn();
    if (msisdn.has_value()) {
        auto& sessions = msisdn_to_sessions_[msisdn.value()];
        if (std::find(sessions.begin(), sessions.end(), session) == sessions.end()) {
            sessions.push_back(session);
        }
    }

    // Update PDN address index
    auto pdn_v4 = session->getPdnAddressV4();
    if (pdn_v4.has_value()) {
        pdn_address_to_session_[pdn_v4.value()] = session;
    }

    auto pdn_v6 = session->getPdnAddressV6();
    if (pdn_v6.has_value()) {
        pdn_address_to_session_[pdn_v6.value()] = session;
    }
}

void Gtpv2Correlator::registerSessionFteids(Gtpv2Session* session) {
    if (!session) {
        return;
    }

    // Register all F-TEIDs from session with F-TEID manager
    const auto& fteids = session->getFteids();
    for (const auto& fteid : fteids) {
        fteid_manager_.registerFteid(fteid, session);
    }

    // Also register F-TEIDs from bearers
    auto bearers = session->getBearers();
    for (const auto* bearer : bearers) {
        // Create F-TEIDs from bearer endpoints and register them
        if (bearer->getS1uEnbIp().has_value() && bearer->getS1uEnbTeid().has_value()) {
            GtpV2FTEID fteid;
            fteid.interface_type = FTEIDInterfaceType::S1_U_ENODEB_GTP_U;
            fteid.ipv4_address = bearer->getS1uEnbIp().value();
            fteid.teid = bearer->getS1uEnbTeid().value();
            fteid_manager_.registerFteid(fteid, session);
        }

        if (bearer->getS1uSgwIp().has_value() && bearer->getS1uSgwTeid().has_value()) {
            GtpV2FTEID fteid;
            fteid.interface_type = FTEIDInterfaceType::S1_U_SGW_GTP_U;
            fteid.ipv4_address = bearer->getS1uSgwIp().value();
            fteid.teid = bearer->getS1uSgwTeid().value();
            fteid_manager_.registerFteid(fteid, session);
        }

        if (bearer->getS5PgwIp().has_value() && bearer->getS5PgwTeid().has_value()) {
            GtpV2FTEID fteid;
            fteid.interface_type = FTEIDInterfaceType::S5_S8_PGW_GTP_U;
            fteid.ipv4_address = bearer->getS5PgwIp().value();
            fteid.teid = bearer->getS5PgwTeid().value();
            fteid_manager_.registerFteid(fteid, session);
        }

        if (bearer->getS5SgwIp().has_value() && bearer->getS5SgwTeid().has_value()) {
            GtpV2FTEID fteid;
            fteid.interface_type = FTEIDInterfaceType::S5_S8_SGW_GTP_U;
            fteid.ipv4_address = bearer->getS5SgwIp().value();
            fteid.teid = bearer->getS5SgwTeid().value();
            fteid_manager_.registerFteid(fteid, session);
        }
    }
}

}  // namespace correlation
}  // namespace callflow
