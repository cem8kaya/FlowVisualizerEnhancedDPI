#include "correlation/diameter/diameter_correlator.h"

#include <algorithm>
#include <iomanip>
#include <sstream>

namespace callflow {
namespace correlation {

DiameterCorrelator::DiameterCorrelator() : ctx_manager_(nullptr) {}

DiameterCorrelator::DiameterCorrelator(SubscriberContextManager* ctx_manager)
    : ctx_manager_(ctx_manager) {}

// ============================================================================
// Message Processing
// ============================================================================

void DiameterCorrelator::addMessage(const DiameterMessage& msg) {
    std::lock_guard<std::mutex> lock(mutex_);

    stats_.total_messages++;
    if (msg.isRequest()) {
        stats_.request_count++;
    } else {
        stats_.answer_count++;
    }

    // Get Session-ID
    std::string session_id = msg.getSessionId();
    if (session_id.empty()) {
        // Generate a synthetic Session-ID if missing
        session_id = generateSessionId(msg.getTimestamp());
    }

    // Find or create session
    auto it = sessions_.find(session_id);
    if (it == sessions_.end()) {
        // Create new session
        auto session = std::make_unique<DiameterSession>(session_id);
        it = sessions_.insert({session_id, std::move(session)}).first;
        stats_.total_sessions++;

        // Update interface statistics
        DiameterInterface iface = msg.getInterface();
        stats_.sessions_by_interface[iface]++;
    }

    DiameterSession* session = it->second.get();

    // Track Hop-by-Hop-ID for request/answer correlation
    trackHopByHop(msg.getHopByHopId(), session_id);

    // Add message to session
    session->addMessage(msg);

    // Update lookup maps with subscriber identities
    updateLookupMaps(session_id, *session);

    // Track errors
    if (msg.isAnswer() && msg.isError()) {
        stats_.error_responses++;
    }

    // Update SubscriberContextManager if configured
    if (ctx_manager_) {
        updateSubscriberContext(*session);
    }
}

void DiameterCorrelator::finalize() {
    std::lock_guard<std::mutex> lock(mutex_);

    for (auto& pair : sessions_) {
        pair.second->finalize();

        // Final update to SubscriberContextManager
        if (ctx_manager_) {
            updateSubscriberContext(*pair.second);
        }
    }

    // Count linked request/answer pairs
    stats_.linked_pairs = 0;
    for (const auto& pair : sessions_) {
        const auto& session = pair.second;
        for (const auto& msg : session->getMessages()) {
            if (msg.isRequest()) {
                if (session->findAnswer(msg) != nullptr) {
                    stats_.linked_pairs++;
                }
            }
        }
    }
}

// ============================================================================
// Session Access
// ============================================================================

std::vector<DiameterSession*> DiameterCorrelator::getSessions() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<DiameterSession*> result;
    result.reserve(sessions_.size());

    for (auto& pair : sessions_) {
        result.push_back(pair.second.get());
    }

    return result;
}

std::vector<DiameterSession*> DiameterCorrelator::getSessionsByInterface(DiameterInterface iface) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<DiameterSession*> result;

    for (auto& pair : sessions_) {
        if (pair.second->getInterface() == iface) {
            result.push_back(pair.second.get());
        }
    }

    return result;
}

// ============================================================================
// Session Lookup
// ============================================================================

DiameterSession* DiameterCorrelator::findBySessionId(const std::string& session_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = sessions_.find(session_id);
    if (it != sessions_.end()) {
        return it->second.get();
    }
    return nullptr;
}

std::vector<DiameterSession*> DiameterCorrelator::findByImsi(const std::string& imsi) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<DiameterSession*> result;

    auto it = imsi_to_sessions_.find(imsi);
    if (it != imsi_to_sessions_.end()) {
        for (const auto& session_id : it->second) {
            auto session_it = sessions_.find(session_id);
            if (session_it != sessions_.end()) {
                result.push_back(session_it->second.get());
            }
        }
    }

    return result;
}

std::vector<DiameterSession*> DiameterCorrelator::findByMsisdn(const std::string& msisdn) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<DiameterSession*> result;

    auto it = msisdn_to_sessions_.find(msisdn);
    if (it != msisdn_to_sessions_.end()) {
        for (const auto& session_id : it->second) {
            auto session_it = sessions_.find(session_id);
            if (session_it != sessions_.end()) {
                result.push_back(session_it->second.get());
            }
        }
    }

    return result;
}

std::vector<DiameterSession*> DiameterCorrelator::findByFramedIp(const std::string& ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<DiameterSession*> result;

    auto it = framed_ip_to_sessions_.find(ip);
    if (it != framed_ip_to_sessions_.end()) {
        for (const auto& session_id : it->second) {
            auto session_it = sessions_.find(session_id);
            if (session_it != sessions_.end()) {
                result.push_back(session_it->second.get());
            }
        }
    }

    return result;
}

std::vector<DiameterSession*> DiameterCorrelator::findByFramedIpv6Prefix(
    const std::string& prefix) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<DiameterSession*> result;

    // Search through all sessions for matching IPv6 prefix
    for (auto& pair : sessions_) {
        auto session_prefix = pair.second->getFramedIpv6Prefix();
        if (session_prefix && *session_prefix == prefix) {
            result.push_back(pair.second.get());
        }
    }

    return result;
}

DiameterSession* DiameterCorrelator::findByHopByHopId(uint32_t hop_by_hop_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = hop_to_session_.find(hop_by_hop_id);
    if (it != hop_to_session_.end()) {
        auto session_it = sessions_.find(it->second);
        if (session_it != sessions_.end()) {
            return session_it->second.get();
        }
    }

    return nullptr;
}

// ============================================================================
// Statistics
// ============================================================================

DiameterCorrelator::Stats DiameterCorrelator::getStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

void DiameterCorrelator::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    sessions_.clear();
    hop_to_session_.clear();
    imsi_to_sessions_.clear();
    msisdn_to_sessions_.clear();
    framed_ip_to_sessions_.clear();
    session_sequence_ = 0;
    stats_ = Stats();
}

size_t DiameterCorrelator::getSessionCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return sessions_.size();
}

// ============================================================================
// Internal Methods
// ============================================================================

std::string DiameterCorrelator::generateSessionId(double timestamp) {
    // Generate a synthetic Session-ID for messages without one
    std::ostringstream oss;
    oss << "synthetic-diameter-session-" << std::fixed << std::setprecision(6) << timestamp << "-"
        << (++session_sequence_);
    return oss.str();
}

void DiameterCorrelator::updateSubscriberContext(const DiameterSession& session) {
    if (!ctx_manager_) {
        return;
    }

    SubscriberContextBuilder builder(*ctx_manager_);

    // Set IMSI
    auto imsi = session.getImsi();
    if (imsi) {
        builder.fromDiameterImsi(*imsi);
    }

    // Set MSISDN
    auto msisdn = session.getMsisdn();
    if (msisdn) {
        builder.fromDiameterMsisdn(*msisdn);
    }

    // Set Framed-IP
    auto framed_ip = session.getFramedIpAddress();
    if (framed_ip) {
        builder.fromDiameterFramedIp(*framed_ip);
    }

    // Set Public Identity
    // Note: session doesn't explicitly expose public identity getter in previous view,
    // but typically it's User-Name or Public-Identity AVP.
    // Assuming simplistic mapping for now based on what we have.

    builder.build();
}

void DiameterCorrelator::updateLookupMaps(const std::string& session_id,
                                          const DiameterSession& session) {
    // Update IMSI lookup
    auto imsi = session.getImsi();
    if (imsi) {
        auto& sessions = imsi_to_sessions_[*imsi];
        if (std::find(sessions.begin(), sessions.end(), session_id) == sessions.end()) {
            sessions.push_back(session_id);
        }
    }

    // Update MSISDN lookup
    auto msisdn = session.getMsisdn();
    if (msisdn) {
        auto& sessions = msisdn_to_sessions_[*msisdn];
        if (std::find(sessions.begin(), sessions.end(), session_id) == sessions.end()) {
            sessions.push_back(session_id);
        }
    }

    // Update Framed-IP lookup
    auto framed_ip = session.getFramedIpAddress();
    if (framed_ip) {
        auto& sessions = framed_ip_to_sessions_[*framed_ip];
        if (std::find(sessions.begin(), sessions.end(), session_id) == sessions.end()) {
            sessions.push_back(session_id);
        }
    }
}

void DiameterCorrelator::trackHopByHop(uint32_t hop_by_hop_id, const std::string& session_id) {
    hop_to_session_[hop_by_hop_id] = session_id;
}

}  // namespace correlation
}  // namespace callflow
