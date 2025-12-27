#include "correlation/sip/sip_session.h"

#include <algorithm>

#include "common/utils.h"
#include "correlation/sip/sip_call_detector.h"

namespace callflow {
namespace correlation {

SipSession::SipSession(const std::string& call_id)
    : call_id_(call_id),
      session_id_(utils::generateUuid()),
      type_(SipSessionType::UNKNOWN),
      start_time_(0.0),
      end_time_(0.0),
      start_frame_(0),
      end_frame_(0) {}

void SipSession::addMessage(const SipMessage& msg) {
    messages_.push_back(msg);
    updateTimeWindow(msg);

    // Add to appropriate dialog
    std::string from_tag = msg.getFromTag();
    std::string to_tag = msg.getToTag();

    SipDialog* dialog = getOrCreateDialog(from_tag, to_tag);
    if (dialog) {
        dialog->addMessage(msg);

        // If this is a response with a new To-tag, update the dialog
        if (msg.isResponse() && msg.hasToTag() && dialog->isEarly()) {
            dialog->setToTag(to_tag);
        }
    }
}

void SipSession::updateTimeWindow(const SipMessage& msg) {
    double timestamp = msg.getTimestamp();
    uint32_t frame = msg.getFrameNumber();

    if (messages_.size() == 1) {
        // First message
        start_time_ = timestamp;
        end_time_ = timestamp;
        start_frame_ = frame;
        end_frame_ = frame;
    } else {
        if (timestamp < start_time_) {
            start_time_ = timestamp;
            start_frame_ = frame;
        }
        if (timestamp > end_time_) {
            end_time_ = timestamp;
            end_frame_ = frame;
        }
    }
}

void SipSession::recalculateTimeWindow() {
    if (messages_.empty()) {
        return;
    }

    // Reset loop
    start_time_ = 0.0;
    end_time_ = 0.0;
    start_frame_ = 0;
    end_frame_ = 0;

    for (const auto& msg : messages_) {
        double ts = msg.getTimestamp();
        uint32_t fr = msg.getFrameNumber();

        if (start_time_ == 0.0 || ts < start_time_) {
            start_time_ = ts;
            start_frame_ = fr;
        }
        if (end_time_ == 0.0 || ts > end_time_) {
            end_time_ = ts;
            end_frame_ = fr;
        }
    }
}

SipDialog* SipSession::getOrCreateDialog(const std::string& from_tag, const std::string& to_tag) {
    // Create dialog key
    std::string dialog_key = call_id_ + ":" + from_tag;
    if (!to_tag.empty()) {
        dialog_key += ":" + to_tag;
    }

    // Check if dialog exists
    auto it = dialog_map_.find(dialog_key);
    if (it != dialog_map_.end()) {
        return it->second;
    }

    // Check if we have an early dialog that matches
    std::string early_key = call_id_ + ":" + from_tag;
    auto early_it = dialog_map_.find(early_key);
    if (early_it != dialog_map_.end() && !to_tag.empty()) {
        // Update the dialog map with the confirmed dialog ID
        SipDialog* dialog = early_it->second;
        dialog_map_.erase(early_it);
        dialog_map_[dialog_key] = dialog;
        return dialog;
    }

    // Create new dialog
    auto dialog = std::make_unique<SipDialog>(dialog_key, from_tag, to_tag);
    SipDialog* ptr = dialog.get();
    dialogs_.push_back(std::move(dialog));
    dialog_map_[dialog_key] = ptr;

    return ptr;
}

SipDialog* SipSession::findDialog(const std::string& from_tag, const std::string& to_tag) const {
    std::string dialog_key = call_id_ + ":" + from_tag;
    if (!to_tag.empty()) {
        dialog_key += ":" + to_tag;
    }

    auto it = dialog_map_.find(dialog_key);
    if (it != dialog_map_.end()) {
        return it->second;
    }

    return nullptr;
}

void SipSession::finalize() {
    recalculateTimeWindow();  // Ensure timestamps are correct before export
    detectSessionType();
    extractCallParties();
    extractMediaInfo();
    extractUeIpAddresses();
}

void SipSession::detectSessionType() {
    type_ = SipCallDetector::detectSessionType(messages_);
}

void SipSession::extractCallParties() {
    auto party_info = SipCallDetector::extractCallParties(messages_);

    caller_msisdn_ = party_info.caller_msisdn;
    callee_msisdn_ = party_info.callee_msisdn;
    if (party_info.forward_target_msisdn.has_value()) {
        forward_target_msisdn_ = party_info.forward_target_msisdn;
    }
}

void SipSession::extractMediaInfo() {
    media_ = SipCallDetector::extractMediaInfo(messages_);
}

void SipSession::extractUeIpAddresses() {
    auto party_info = SipCallDetector::extractCallParties(messages_);

    caller_ip_ = party_info.caller_ip;
    callee_ip_ = party_info.callee_ip;
    caller_ipv6_prefix_ = party_info.caller_ipv6_prefix;
    callee_ipv6_prefix_ = party_info.callee_ipv6_prefix;
}

bool SipSession::hasAudio() const {
    return std::any_of(media_.begin(), media_.end(),
                       [](const SipMediaInfo& m) { return m.media_type == "audio"; });
}

bool SipSession::hasVideo() const {
    return std::any_of(media_.begin(), media_.end(),
                       [](const SipMediaInfo& m) { return m.media_type == "video"; });
}

std::string SipSession::extractMsisdnFromHeader(const std::string& header_value) {
    return SipCallDetector::extractMsisdn(header_value);
}

}  // namespace correlation
}  // namespace callflow
