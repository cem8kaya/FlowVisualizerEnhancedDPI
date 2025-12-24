#include "correlation/sip/sip_dialog.h"
#include <algorithm>

namespace callflow {
namespace correlation {

SipDialog::SipDialog(const std::string& dialog_id,
                     const std::string& from_tag,
                     const std::string& to_tag)
    : dialog_id_(dialog_id),
      from_tag_(from_tag),
      to_tag_(to_tag) {
}

void SipDialog::addMessage(const SipMessage& msg) {
    messages_.push_back(msg);
    updateTimeWindow(msg);
    updateState(msg);

    // If this is a response and we don't have a To-tag yet, set it
    if (to_tag_.empty() && msg.isResponse() && msg.hasToTag()) {
        setToTag(msg.getToTag());
    }
}

void SipDialog::updateTimeWindow(const SipMessage& msg) {
    double timestamp = msg.getTimestamp();
    uint32_t frame = msg.getFrameNumber();

    if (messages_.size() == 1) {
        // First message
        start_time_ = timestamp;
        end_time_ = timestamp;
        start_frame_ = frame;
        end_frame_ = frame;
    } else {
        if (timestamp > end_time_) {
            end_time_ = timestamp;
            end_frame_ = frame;
        }
    }
}

void SipDialog::updateState(const SipMessage& msg) {
    if (msg.isRequest()) {
        // Request messages
        if (msg.isInvite()) {
            if (state_ == SipDialogState::INIT) {
                state_ = SipDialogState::CALLING;
            }
        } else if (msg.isBye()) {
            state_ = SipDialogState::TERMINATED;
        } else if (msg.isCancel()) {
            state_ = SipDialogState::TERMINATED;
        }
    } else {
        // Response messages
        int status_code = msg.getStatusCode();

        if (msg.isProvisional()) {
            // 1xx response
            if (state_ == SipDialogState::CALLING) {
                if (msg.hasToTag()) {
                    // Early dialog established
                    state_ = SipDialogState::EARLY;
                } else {
                    state_ = SipDialogState::PROCEEDING;
                }
            }
        } else if (msg.isSuccess()) {
            // 2xx response
            if (msg.getCSeqMethod() == "INVITE") {
                state_ = SipDialogState::CONFIRMED;
            }
        } else if (msg.isError()) {
            // 3xx, 4xx, 5xx, 6xx
            if (msg.getCSeqMethod() == "INVITE") {
                state_ = SipDialogState::TERMINATED;
            }
        }
    }
}

void SipDialog::setToTag(const std::string& to_tag) {
    to_tag_ = to_tag;
    // Update dialog ID
    dialog_id_ = dialog_id_ + ":" + to_tag_;
}

SipTransaction* SipDialog::getOrCreateTransaction(const std::string& transaction_id,
                                                   const SipMessage& request) {
    auto it = transaction_map_.find(transaction_id);
    if (it != transaction_map_.end()) {
        return it->second;
    }

    // Create new transaction
    auto transaction = std::make_unique<SipTransaction>(transaction_id, request);
    SipTransaction* ptr = transaction.get();
    transactions_.push_back(std::move(transaction));
    transaction_map_[transaction_id] = ptr;

    return ptr;
}

SipTransaction* SipDialog::findTransaction(const std::string& transaction_id) {
    auto it = transaction_map_.find(transaction_id);
    if (it != transaction_map_.end()) {
        return it->second;
    }
    return nullptr;
}

const SipMessage* SipDialog::getInitialRequest() const {
    // Return the first INVITE or other dialog-creating request
    for (const auto& msg : messages_) {
        if (msg.isRequest() && (msg.isInvite() || msg.getMethod() == "SUBSCRIBE")) {
            return &msg;
        }
    }
    return nullptr;
}

const SipMessage* SipDialog::getDialogEstablishingResponse() const {
    // Return the first 2xx response that establishes the dialog
    for (const auto& msg : messages_) {
        if (msg.isResponse() && msg.isSuccess() &&
            (msg.getCSeqMethod() == "INVITE" || msg.getCSeqMethod() == "SUBSCRIBE")) {
            return &msg;
        }
    }
    return nullptr;
}

double SipDialog::getDuration() const {
    return end_time_ - start_time_;
}

} // namespace correlation
} // namespace callflow
