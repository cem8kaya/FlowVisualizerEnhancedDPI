#pragma once
#include <chrono>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "protocol_parsers/sip_parser.h"

namespace callflow {

// SIP Transaction (RFC 3261 Section 17)
struct SipTransaction {
    std::string branch;  // Via branch parameter (unique per transaction)
    std::string method;  // INVITE, BYE, etc.
    uint32_t cseq_number;

    std::chrono::system_clock::time_point request_time;
    std::optional<std::chrono::system_clock::time_point> response_time;

    std::optional<int> final_response_code;
    std::vector<int> provisional_responses;  // 100, 180, 183, etc.

    enum class State {
        CALLING,     // INVITE sent, waiting for response
        PROCEEDING,  // 1xx received
        COMPLETED,   // Final response received
        CONFIRMED,   // ACK sent (for INVITE only)
        TERMINATED
    };
    State state = State::CALLING;

    // Calculate response time
    std::optional<std::chrono::milliseconds> getResponseLatency() const {
        if (response_time) {
            return std::chrono::duration_cast<std::chrono::milliseconds>(*response_time -
                                                                         request_time);
        }
        return std::nullopt;
    }
};

// SIP Dialog (RFC 3261 Section 12)
struct SipDialog {
    std::string dialog_id;  // Computed: call_id + from_tag + to_tag
    std::string call_id;
    std::string from_tag;
    std::string to_tag;
    std::string local_uri;
    std::string remote_uri;

    // Dialog state
    enum class State {
        EARLY,      // 1xx received, no To-tag or provisional To-tag
        CONFIRMED,  // 2xx received with To-tag
        TERMINATED
    };
    State state = State::EARLY;

    // Route set and contact
    std::vector<std::string> route_set;
    std::string local_contact;
    std::string remote_contact;
    uint32_t local_cseq = 0;
    uint32_t remote_cseq = 0;

    // Transactions within this dialog
    std::vector<std::shared_ptr<SipTransaction>> transactions;

    // Timing
    std::chrono::system_clock::time_point created_at;
    std::optional<std::chrono::system_clock::time_point> confirmed_at;
    std::optional<std::chrono::system_clock::time_point> terminated_at;

    // Media info (from SDP)
    struct MediaInfo {
        std::string audio_ip;
        uint16_t audio_port = 0;
        std::string audio_codec;
        std::string video_ip;
        uint16_t video_port = 0;
        std::string video_codec;
    };
    std::optional<MediaInfo> local_media;
    std::optional<MediaInfo> remote_media;

    // Helper to check if this is a forked dialog
    // In strict SIP terms, if a fork happens, we get multiple dialogs from one request.
    // We can track related dialogs.
    bool isForked() const { return !forked_dialogs.empty(); }
    std::vector<std::string> forked_dialogs;  // Other dialog IDs from same INVITE

    std::string computeDialogId() const {
        if (to_tag.empty())
            return call_id + ":" + from_tag;
        return call_id + ":" + from_tag + ":" + to_tag;
    }
};

class SipDialogTracker {
public:
    SipDialogTracker() = default;

    // Process incoming SIP message
    void processMessage(const SipMessage& msg, const std::string& src_ip, const std::string& dst_ip,
                        std::chrono::system_clock::time_point timestamp);

    // Get dialog by various keys
    std::shared_ptr<SipDialog> getDialogByCallId(const std::string& call_id) const;
    std::shared_ptr<SipDialog> getDialogById(const std::string& dialog_id) const;
    std::vector<std::shared_ptr<SipDialog>> getDialogsByUri(const std::string& uri) const;

    // Get active dialogs (for correlation)
    std::vector<std::shared_ptr<SipDialog>> getActiveDialogs() const;

    // Get all dialogs including terminated
    std::vector<std::shared_ptr<SipDialog>> getAllDialogs() const;

    // Statistics
    struct Stats {
        size_t total_dialogs = 0;
        size_t active_dialogs = 0;
        size_t early_dialogs = 0;
        size_t forked_dialogs = 0;
        size_t completed_transactions = 0;
        double avg_setup_time_ms = 0.0;
    };
    Stats getStats() const;

    // Cleanup expired dialogs
    void cleanup(std::chrono::seconds max_age = std::chrono::seconds(3600));

private:
    mutable std::mutex mutex_;

    // Primary storage: dialog_id -> SipDialog
    std::unordered_map<std::string, std::shared_ptr<SipDialog>> dialogs_;

    // Indexes for fast lookup
    std::unordered_multimap<std::string, std::shared_ptr<SipDialog>> call_id_index_;
    std::unordered_multimap<std::string, std::shared_ptr<SipDialog>> uri_index_;

    // Transaction tracking: branch -> Transaction
    std::unordered_map<std::string, std::shared_ptr<SipTransaction>> transactions_;

    // Handle specific message types
    void handleRequest(const SipMessage& msg, const std::string& src_ip, const std::string& dst_ip,
                       std::chrono::system_clock::time_point timestamp);

    void handleResponse(const SipMessage& msg, const std::string& src_ip, const std::string& dst_ip,
                        std::chrono::system_clock::time_point timestamp);

    // Create or find dialog
    std::shared_ptr<SipDialog> findOrCreateDialog(const SipMessage& msg,
                                                  std::chrono::system_clock::time_point timestamp);

    // Create transaction
    std::shared_ptr<SipTransaction> getOrCreateTransaction(
        const SipMessage& msg, std::chrono::system_clock::time_point timestamp);

    // Helper to update media info from SDP
    void updateMediaInfo(SipDialog& dialog, const SipMessage::SdpInfo& sdp, bool is_local);
};

}  // namespace callflow
