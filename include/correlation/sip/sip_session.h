#pragma once

#include <memory>
#include <unordered_map>
#include <vector>

#include "correlation/sip/sip_dialog.h"
#include "correlation/sip/sip_message.h"
#include "correlation/sip/sip_types.h"

namespace callflow {
namespace correlation {

/**
 * @brief Represents a complete SIP session
 *
 * A session is identified by Call-ID and contains:
 * - One or more dialogs (for forking scenarios)
 * - Transactions within each dialog
 * - Extracted call party information
 */
class SipSession {
public:
    SipSession(const std::string& call_id);
    ~SipSession() = default;

    // Session identification
    std::string getCallId() const { return call_id_; }
    std::string getSessionId() const { return session_id_; }
    SipSessionType getType() const { return type_; }

    // Add message to session
    void addMessage(const SipMessage& msg);

    // Get messages
    const std::vector<SipMessage>& getMessages() const { return messages_; }
    size_t getMessageCount() const { return messages_.size(); }

    // Dialog management
    SipDialog* getOrCreateDialog(const std::string& from_tag, const std::string& to_tag);
    SipDialog* findDialog(const std::string& from_tag, const std::string& to_tag) const;
    const std::vector<std::unique_ptr<SipDialog>>& getDialogs() const { return dialogs_; }

    // Call party information
    std::string getCallerMsisdn() const { return caller_msisdn_; }
    std::string getCallerImsi() const { return caller_imsi_; }  // Added getter
    std::string getCalleeMsisdn() const { return callee_msisdn_; }
    std::string getCalleeImsi() const { return callee_imsi_; }  // Added getter
    std::optional<std::string> getForwardTargetMsisdn() const { return forward_target_msisdn_; }
    std::optional<std::string> getForwardTargetImsi() const {
        return forward_target_imsi_;
    }  // Added getter

    std::string getCallerIp() const { return caller_ip_; }
    std::string getCalleeIp() const { return callee_ip_; }

    // Time window
    double getStartTime() const { return start_time_; }
    double getEndTime() const { return end_time_; }
    uint32_t getStartFrame() const { return start_frame_; }
    uint32_t getEndFrame() const { return end_frame_; }

    // Media information
    const std::vector<SipMediaInfo>& getMediaInfo() const { return media_; }
    bool hasAudio() const;
    bool hasVideo() const;

    // Correlation IDs
    void setIntraCorrelator(const std::string& id) { intra_correlator_ = id; }
    std::string getIntraCorrelator() const { return intra_correlator_; }

    void setInterCorrelator(const std::string& id) { inter_correlator_ = id; }
    std::string getInterCorrelator() const { return inter_correlator_; }

    // Finalize session (detect type, extract parties, etc.)
    void finalize();

private:
    std::string call_id_;
    std::string session_id_;  // Generated: timestamp_S_sequence
    SipSessionType type_ = SipSessionType::UNKNOWN;

    std::vector<SipMessage> messages_;
    std::vector<std::unique_ptr<SipDialog>> dialogs_;
    std::unordered_map<std::string, SipDialog*> dialog_map_;

    // Call parties (normalized MSISDNs)
    // Call parties (normalized MSISDNs)
    std::string caller_msisdn_;
    std::string caller_imsi_;  // Added IMSI member
    std::string callee_msisdn_;
    std::string callee_imsi_;  // Added IMSI member
    std::optional<std::string> forward_target_msisdn_;
    std::optional<std::string> forward_target_imsi_;  // Added IMSI member

    // UE IP addresses (for cross-protocol correlation)
    std::string caller_ip_;
    std::string caller_ipv6_prefix_;
    std::string callee_ip_;
    std::string callee_ipv6_prefix_;

    // Time window
    double start_time_ = 0.0;
    double end_time_ = 0.0;
    uint32_t start_frame_ = 0;
    uint32_t end_frame_ = 0;

    // Media
    std::vector<SipMediaInfo> media_;

    // Time window

    // Correlation IDs
    std::string intra_correlator_;
    std::string inter_correlator_;

    // Internal methods
    void detectSessionType();
    void extractCallParties();
    void extractMediaInfo();
    void extractUeIpAddresses();
    void updateTimeWindow(const SipMessage& msg);
    void recalculateTimeWindow();

    std::string extractMsisdnFromHeader(const std::string& header_value);
};

}  // namespace correlation
}  // namespace callflow
