#include "correlation/nas/nas_correlator.h"
#include <sstream>

namespace callflow {
namespace correlation {

NasCorrelator::NasCorrelator() = default;

NasCorrelator::NasCorrelator(SubscriberContextManager* ctx_manager)
    : ctx_manager_(ctx_manager) {}

void NasCorrelator::addMessage(const NasMessage& msg,
                                std::optional<uint32_t> mme_ue_id,
                                std::optional<uint32_t> enb_ue_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    stats_.total_messages++;

    // Find or create session for this message
    NasSession* session = findOrCreateSession(msg, mme_ue_id, enb_ue_id);
    if (session) {
        session->addMessage(msg);

        // Update stats based on message type
        if (msg.getEmmMessageType()) {
            auto emm_type = *msg.getEmmMessageType();
            if (emm_type == NasEmmMessageType::ATTACH_REQUEST) {
                stats_.attach_procedures++;
            } else if (emm_type == NasEmmMessageType::TAU_REQUEST) {
                stats_.tau_procedures++;
            } else if (emm_type == NasEmmMessageType::DETACH_REQUEST) {
                stats_.detach_procedures++;
            }
        }
    }
}

void NasCorrelator::finalize() {
    std::lock_guard<std::mutex> lock(mutex_);

    for (auto& session : sessions_) {
        session->finalize();
        updateSubscriberContext(*session);
    }

    // Update statistics
    stats_.total_sessions = sessions_.size();
    stats_.emm_sessions = 0;
    stats_.esm_sessions = 0;
    stats_.ims_esm_sessions = 0;

    for (const auto& session : sessions_) {
        if (session->getType() == NasSessionType::EMM) {
            stats_.emm_sessions++;
        } else if (session->getType() == NasSessionType::ESM) {
            stats_.esm_sessions++;
            if (session->isIms()) {
                stats_.ims_esm_sessions++;
            }
        }
    }
}

std::vector<NasSession*> NasCorrelator::getSessions() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<NasSession*> result;
    result.reserve(sessions_.size());
    for (auto& session : sessions_) {
        result.push_back(session.get());
    }
    return result;
}

std::vector<NasSession*> NasCorrelator::getEmmSessions() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<NasSession*> result;
    for (auto& session : sessions_) {
        if (session->getType() == NasSessionType::EMM) {
            result.push_back(session.get());
        }
    }
    return result;
}

std::vector<NasSession*> NasCorrelator::getEsmSessions() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<NasSession*> result;
    for (auto& session : sessions_) {
        if (session->getType() == NasSessionType::ESM) {
            result.push_back(session.get());
        }
    }
    return result;
}

std::vector<NasSession*> NasCorrelator::getImsEsmSessions() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<NasSession*> result;
    for (auto& session : sessions_) {
        if (session->getType() == NasSessionType::ESM && session->isIms()) {
            result.push_back(session.get());
        }
    }
    return result;
}

std::vector<NasSession*> NasCorrelator::findByImsi(const std::string& imsi) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<NasSession*> result;

    auto range = imsi_index_.equal_range(imsi);
    for (auto it = range.first; it != range.second; ++it) {
        result.push_back(it->second);
    }

    return result;
}

NasSession* NasCorrelator::findByTmsi(uint32_t tmsi) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = tmsi_index_.find(tmsi);
    return (it != tmsi_index_.end()) ? it->second : nullptr;
}

NasSession* NasCorrelator::findByS1apContext(uint32_t mme_ue_id, uint32_t enb_ue_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string key = makeS1apContextKey(mme_ue_id, enb_ue_id);
    auto it = s1ap_context_index_.find(key);
    return (it != s1ap_context_index_.end()) ? it->second : nullptr;
}

NasCorrelator::Stats NasCorrelator::getStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

NasSession* NasCorrelator::findOrCreateSession(const NasMessage& msg,
                                                std::optional<uint32_t> mme_ue_id,
                                                std::optional<uint32_t> enb_ue_id) {
    // Try to find existing session by S1AP context
    if (mme_ue_id && enb_ue_id) {
        std::string s1ap_key = makeS1apContextKey(*mme_ue_id, *enb_ue_id);
        auto it = s1ap_context_index_.find(s1ap_key);
        if (it != s1ap_context_index_.end()) {
            return it->second;
        }
    }

    // Try to find by IMSI
    if (auto imsi = msg.getImsi()) {
        auto it = imsi_index_.find(*imsi);
        if (it != imsi_index_.end()) {
            return it->second;
        }
    }

    // Try to find by TMSI
    if (auto tmsi = msg.getTmsi()) {
        auto it = tmsi_index_.find(*tmsi);
        if (it != tmsi_index_.end()) {
            return it->second;
        }
    }

    // Create new session
    auto session = std::make_unique<NasSession>();
    NasSession* session_ptr = session.get();

    // Link to S1AP context if available
    if (mme_ue_id && enb_ue_id) {
        session->setS1apContext(*mme_ue_id, *enb_ue_id);
        std::string s1ap_key = makeS1apContextKey(*mme_ue_id, *enb_ue_id);
        s1ap_context_index_[s1ap_key] = session_ptr;
    }

    // Index by identifiers (if present)
    if (auto imsi = msg.getImsi()) {
        imsi_index_.emplace(*imsi, session_ptr);
    }
    if (auto tmsi = msg.getTmsi()) {
        tmsi_index_[*tmsi] = session_ptr;
    }

    sessions_.push_back(std::move(session));
    return session_ptr;
}

std::string NasCorrelator::makeS1apContextKey(uint32_t mme_ue_id, uint32_t enb_ue_id) {
    std::ostringstream oss;
    oss << mme_ue_id << ":" << enb_ue_id;
    return oss.str();
}

void NasCorrelator::updateSubscriberContext(const NasSession& session) {
    if (!ctx_manager_) {
        return;
    }

    // Create or update subscriber context
    if (auto imsi = session.getImsi()) {
        auto ctx = ctx_manager_->getOrCreateByImsi(*imsi);

        // Link identifiers
        if (auto imei = session.getImei()) {
            ctx_manager_->linkImsiImei(*imsi, *imei);
        }

        if (auto guti = session.getGuti()) {
            ctx_manager_->linkImsiGuti(*imsi, *guti);
        }

        if (auto tmsi = session.getTmsi()) {
            ctx_manager_->linkImsiTmsi(*imsi, *tmsi);
        }

        if (auto pdn_addr = session.getPdnAddress()) {
            ctx_manager_->linkImsiUeIp(*imsi, *pdn_addr);
        }

        // Update APN
        if (auto apn = session.getApn()) {
            ctx->apn = *apn;
        }
    }
}

} // namespace correlation
} // namespace callflow
