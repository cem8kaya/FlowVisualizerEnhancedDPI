#include "correlation/diameter/diameter_session.h"
#include <algorithm>

namespace callflow {
namespace correlation {

DiameterSession::DiameterSession(const std::string& session_id)
    : session_id_(session_id) {
    intra_correlator_ = session_id;  // Default intra-correlator is Session-ID
}

// ============================================================================
// Session Identification
// ============================================================================

std::string DiameterSession::getInterfaceName() const {
    return interfaceToString(interface_);
}

// ============================================================================
// Message Management
// ============================================================================

void DiameterSession::addMessage(const DiameterMessage& msg) {
    messages_.push_back(msg);
    updateTimeWindow(msg);
    updateFromMessage(msg);

    // Detect interface from first message
    if (messages_.size() == 1) {
        detectInterface();
    }
}

// ============================================================================
// Request/Answer Linking
// ============================================================================

const DiameterMessage* DiameterSession::findAnswer(const DiameterMessage& request) const {
    if (!request.isRequest()) {
        return nullptr;
    }

    uint32_t hop_by_hop = request.getHopByHopId();

    for (const auto& msg : messages_) {
        if (msg.isAnswer() && msg.getHopByHopId() == hop_by_hop) {
            return &msg;
        }
    }

    return nullptr;
}

const DiameterMessage* DiameterSession::findRequest(const DiameterMessage& answer) const {
    if (!answer.isAnswer()) {
        return nullptr;
    }

    uint32_t hop_by_hop = answer.getHopByHopId();

    for (const auto& msg : messages_) {
        if (msg.isRequest() && msg.getHopByHopId() == hop_by_hop) {
            return &msg;
        }
    }

    return nullptr;
}

const DiameterMessage* DiameterSession::findByHopByHop(uint32_t hop_by_hop_id) const {
    for (const auto& msg : messages_) {
        if (msg.getHopByHopId() == hop_by_hop_id) {
            return &msg;
        }
    }
    return nullptr;
}

// ============================================================================
// Gx-Specific Information
// ============================================================================

void DiameterSession::addChargingRule(const std::string& rule) {
    // Check if rule already exists
    if (std::find(charging_rules_.begin(), charging_rules_.end(), rule) == charging_rules_.end()) {
        charging_rules_.push_back(rule);
    }
}

// ============================================================================
// Time Window
// ============================================================================

double DiameterSession::getDuration() const {
    if (end_time_ > start_time_) {
        return end_time_ - start_time_;
    }
    return 0.0;
}

// ============================================================================
// Result Tracking
// ============================================================================

void DiameterSession::addResultCode(const DiameterResultCode& rc) {
    result_codes_.push_back(rc);
    if (!rc.is_success) {
        has_errors_ = true;
    }
}

// ========================================================================
// Session State
// ========================================================================

void DiameterSession::finalize() {
    if (finalized_) {
        return;
    }

    // Extract all information from messages
    detectInterface();
    extractSubscriberInfo();
    extractNetworkInfo();
    extractGxInfo();
    extractRxInfo();

    finalized_ = true;
}

// ============================================================================
// Internal Methods
// ============================================================================

void DiameterSession::detectInterface() {
    if (messages_.empty()) {
        return;
    }

    // Get interface from first message
    interface_ = messages_[0].getInterface();
    application_id_ = messages_[0].getApplicationId();
}

void DiameterSession::extractSubscriberInfo() {
    // Extract subscriber information from all messages
    for (const auto& msg : messages_) {
        if (!imsi_) {
            imsi_ = msg.extractImsi();
        }
        if (!msisdn_) {
            msisdn_ = msg.extractMsisdn();
        }
        if (!public_identity_) {
            public_identity_ = msg.extractPublicIdentity();
        }

        // Stop if we have all subscriber identities
        if (imsi_ && msisdn_ && public_identity_) {
            break;
        }
    }
}

void DiameterSession::extractNetworkInfo() {
    // Extract network information from all messages
    for (const auto& msg : messages_) {
        if (!framed_ip_) {
            framed_ip_ = msg.extractFramedIp();
        }
        if (!framed_ipv6_prefix_) {
            framed_ipv6_prefix_ = msg.extractFramedIpv6Prefix();
        }
        if (!called_station_id_) {
            called_station_id_ = msg.extractApn();
        }
        if (!rat_type_) {
            rat_type_ = msg.extractRatType();
        }

        // Stop if we have all network info
        if (framed_ip_ && framed_ipv6_prefix_ && called_station_id_ && rat_type_) {
            break;
        }
    }
}

void DiameterSession::extractGxInfo() {
    if (interface_ != DiameterInterface::GX &&
        interface_ != DiameterInterface::GY &&
        interface_ != DiameterInterface::RO) {
        return;
    }

    // Extract Gx-specific information
    for (const auto& msg : messages_) {
        // Get CC-Request-Type from first request
        if (!ccr_type_ && msg.isRequest()) {
            ccr_type_ = msg.extractCCRequestType();
        }

        // Get QCI
        if (!qci_) {
            qci_ = msg.extractQci();
        }

        // Get Bearer ID
        if (!bearer_id_) {
            bearer_id_ = msg.extractBearerIdentifier();
        }

        // Collect all charging rules
        auto rules = msg.extractChargingRuleNames();
        for (const auto& rule : rules) {
            addChargingRule(rule);
        }
    }
}

void DiameterSession::extractRxInfo() {
    if (interface_ != DiameterInterface::RX) {
        return;
    }

    // Extract Rx-specific information
    for (const auto& msg : messages_) {
        if (!af_application_id_) {
            af_application_id_ = msg.extractAfApplicationId();
        }
        if (!media_type_) {
            media_type_ = msg.extractMediaType();
        }

        if (af_application_id_ && media_type_) {
            break;
        }
    }
}

void DiameterSession::updateTimeWindow(const DiameterMessage& msg) {
    double timestamp = msg.getTimestamp();
    uint32_t frame = msg.getFrameNumber();

    if (start_time_ == 0.0 || timestamp < start_time_) {
        start_time_ = timestamp;
        start_frame_ = frame;
    }

    if (timestamp > end_time_) {
        end_time_ = timestamp;
        end_frame_ = frame;
    }
}

void DiameterSession::updateFromMessage(const DiameterMessage& msg) {
    // Update subscriber info if not already set
    if (!imsi_) {
        imsi_ = msg.extractImsi();
    }
    if (!msisdn_) {
        msisdn_ = msg.extractMsisdn();
    }

    // Update network info if not already set
    if (!framed_ip_) {
        framed_ip_ = msg.extractFramedIp();
    }
    if (!framed_ipv6_prefix_) {
        framed_ipv6_prefix_ = msg.extractFramedIpv6Prefix();
    }
    if (!called_station_id_) {
        called_station_id_ = msg.extractApn();
    }

    // For Gx sessions, get CC-Request-Type from first request
    if (interface_ == DiameterInterface::GX && !ccr_type_ && msg.isRequest()) {
        ccr_type_ = msg.extractCCRequestType();
    }

    // Track result codes from answers
    if (msg.isAnswer()) {
        auto rc = msg.getParsedResultCode();
        if (rc) {
            addResultCode(*rc);
        }
    }
}

} // namespace correlation
} // namespace callflow
