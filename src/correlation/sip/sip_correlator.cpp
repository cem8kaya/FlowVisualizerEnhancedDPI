#include "correlation/sip/sip_correlator.h"
#include "correlation/identity/msisdn_normalizer.h"
#include <algorithm>

namespace callflow {
namespace correlation {

SipCorrelator::SipCorrelator() = default;

SipCorrelator::SipCorrelator(SubscriberContextManager* ctx_manager)
    : ctx_manager_(ctx_manager) {}

void SipCorrelator::addMessage(const SipMessage& msg) {
    std::lock_guard<std::mutex> lock(mutex_);

    const std::string& call_id = msg.getCallId();
    if (call_id.empty()) {
        return;  // Invalid SIP message
    }

    // Get or create session
    auto it = sessions_.find(call_id);
    if (it == sessions_.end()) {
        auto session = std::make_unique<SipSession>(call_id);
        session->setIntraCorrelator(generateSessionId(msg.getTimestamp()));
        sessions_[call_id] = std::move(session);
        it = sessions_.find(call_id);
    }

    it->second->addMessage(msg);
    stats_.total_messages++;
}

void SipCorrelator::finalize() {
    std::lock_guard<std::mutex> lock(mutex_);

    for (auto& [call_id, session] : sessions_) {
        session->finalize();

        // Update statistics
        stats_.total_sessions++;
        switch (session->getType()) {
            case SipSessionType::REGISTRATION:
            case SipSessionType::DEREGISTRATION:
            case SipSessionType::THIRD_PARTY_REG:
                stats_.registration_sessions++;
                break;
            case SipSessionType::VOICE_CALL:
                stats_.voice_call_sessions++;
                break;
            case SipSessionType::VIDEO_CALL:
                stats_.video_call_sessions++;
                break;
            case SipSessionType::SMS_MESSAGE:
                stats_.sms_sessions++;
                break;
            default:
                stats_.other_sessions++;
                break;
        }

        // Update subscriber context if available
        if (ctx_manager_) {
            updateSubscriberContext(*session);
        }
    }
}

std::vector<SipSession*> SipCorrelator::getSessions() {
    std::vector<SipSession*> result;

    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [call_id, session] : sessions_) {
        result.push_back(session.get());
    }

    // Sort by start time
    std::sort(result.begin(), result.end(),
        [](SipSession* a, SipSession* b) {
            return a->getStartTime() < b->getStartTime();
        });

    return result;
}

std::vector<SipSession*> SipCorrelator::getSessionsByType(SipSessionType type) {
    std::vector<SipSession*> result;

    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [call_id, session] : sessions_) {
        if (session->getType() == type) {
            result.push_back(session.get());
        }
    }

    // Sort by start time
    std::sort(result.begin(), result.end(),
        [](SipSession* a, SipSession* b) {
            return a->getStartTime() < b->getStartTime();
        });

    return result;
}

std::vector<SipSession*> SipCorrelator::getCallSessions() {
    std::vector<SipSession*> result;

    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [call_id, session] : sessions_) {
        SipSessionType type = session->getType();
        if (type == SipSessionType::VOICE_CALL ||
            type == SipSessionType::VIDEO_CALL ||
            type == SipSessionType::EMERGENCY_CALL) {
            result.push_back(session.get());
        }
    }

    // Sort by start time
    std::sort(result.begin(), result.end(),
        [](SipSession* a, SipSession* b) {
            return a->getStartTime() < b->getStartTime();
        });

    return result;
}

SipSession* SipCorrelator::findByCallId(const std::string& call_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = sessions_.find(call_id);
    if (it != sessions_.end()) {
        return it->second.get();
    }

    return nullptr;
}

std::vector<SipSession*> SipCorrelator::findByMsisdn(const std::string& msisdn) {
    std::vector<SipSession*> result;
    auto normalized = MsisdnNormalizer::normalize(msisdn);

    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [call_id, session] : sessions_) {
        auto caller = MsisdnNormalizer::normalize(session->getCallerMsisdn());
        auto callee = MsisdnNormalizer::normalize(session->getCalleeMsisdn());

        if (MsisdnNormalizer::matches(normalized, caller) ||
            MsisdnNormalizer::matches(normalized, callee)) {
            result.push_back(session.get());
        }
    }

    return result;
}

SipSession* SipCorrelator::findByFrame(uint32_t frame_number) {
    std::lock_guard<std::mutex> lock(mutex_);

    for (auto& [call_id, session] : sessions_) {
        if (frame_number >= session->getStartFrame() &&
            frame_number <= session->getEndFrame()) {
            return session.get();
        }
    }

    return nullptr;
}

SipCorrelator::Stats SipCorrelator::getStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

void SipCorrelator::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    sessions_.clear();
    session_sequence_ = 0;
    stats_ = Stats();
}

std::string SipCorrelator::generateSessionId(double timestamp) {
    // Format: timestamp_S_sequence (e.g., "1702396800.123_S_1")
    session_sequence_++;
    return std::to_string(timestamp) + "_S_" + std::to_string(session_sequence_);
}

void SipCorrelator::updateSubscriberContext(const SipSession& session) {
    // Update caller context
    if (!session.getCallerMsisdn().empty()) {
        auto ctx = ctx_manager_->getOrCreateByMsisdn(session.getCallerMsisdn());
        if (!session.getCallerIp().empty()) {
            NetworkEndpoint ep;
            ep.ipv4 = session.getCallerIp();
            ctx->endpoints.push_back(ep);
        }
    }

    // Update callee context
    if (!session.getCalleeMsisdn().empty()) {
        auto ctx = ctx_manager_->getOrCreateByMsisdn(session.getCalleeMsisdn());
        if (!session.getCalleeIp().empty()) {
            NetworkEndpoint ep;
            ep.ipv4 = session.getCalleeIp();
            ctx->endpoints.push_back(ep);
        }
    }
}

} // namespace correlation
} // namespace callflow
