#pragma once

#include "correlation/sip/sip_message.h"
#include "correlation/sip/sip_transaction.h"
#include <memory>
#include <vector>
#include <unordered_map>
#include <string>

namespace callflow {
namespace correlation {

/**
 * @brief Represents a SIP dialog
 *
 * A dialog is a peer-to-peer SIP relationship between two user agents
 * that persists for some time. Identified by Call-ID, From-tag, and To-tag.
 *
 * RFC 3261:
 * - Dialog ID = Call-ID + local-tag + remote-tag
 * - Dialog begins with a request that creates a dialog (INVITE, SUBSCRIBE)
 * - Dialog confirmed when 2xx response contains To-tag
 */
class SipDialog {
public:
    SipDialog(const std::string& dialog_id,
              const std::string& from_tag,
              const std::string& to_tag);
    ~SipDialog() = default;

    // Dialog identification
    std::string getDialogId() const { return dialog_id_; }
    std::string getFromTag() const { return from_tag_; }
    std::string getToTag() const { return to_tag_; }

    // State
    SipDialogState getState() const { return state_; }
    void setState(SipDialogState state) { state_ = state; }

    // Is this an early dialog (no To-tag yet)?
    bool isEarly() const { return to_tag_.empty(); }
    bool isConfirmed() const { return state_ == SipDialogState::CONFIRMED; }
    bool isTerminated() const { return state_ == SipDialogState::TERMINATED; }

    // Messages
    void addMessage(const SipMessage& msg);
    const std::vector<SipMessage>& getMessages() const { return messages_; }

    // Transactions
    SipTransaction* getOrCreateTransaction(const std::string& transaction_id,
                                           const SipMessage& request);
    SipTransaction* findTransaction(const std::string& transaction_id);
    const std::vector<std::unique_ptr<SipTransaction>>& getTransactions() const {
        return transactions_;
    }

    // Dialog establishment
    const SipMessage* getInitialRequest() const;
    const SipMessage* getDialogEstablishingResponse() const;

    // Timing
    double getStartTime() const { return start_time_; }
    double getEndTime() const { return end_time_; }
    double getDuration() const;

    // Frame range
    uint32_t getStartFrame() const { return start_frame_; }
    uint32_t getEndFrame() const { return end_frame_; }

    // Update dialog state based on message
    void updateState(const SipMessage& msg);

    // Set To-tag when received (for early dialogs)
    void setToTag(const std::string& to_tag);

private:
    std::string dialog_id_;
    std::string from_tag_;
    std::string to_tag_;

    SipDialogState state_ = SipDialogState::INIT;

    std::vector<SipMessage> messages_;
    std::vector<std::unique_ptr<SipTransaction>> transactions_;
    std::unordered_map<std::string, SipTransaction*> transaction_map_;

    double start_time_ = 0.0;
    double end_time_ = 0.0;
    uint32_t start_frame_ = 0;
    uint32_t end_frame_ = 0;

    void updateTimeWindow(const SipMessage& msg);
};

} // namespace correlation
} // namespace callflow
