#include "correlation/sip_dialog_tracker.h"

#include <algorithm>

#include "common/logger.h"

namespace callflow {

void SipDialogTracker::processMessage(const SipMessage& msg, const std::string& src_ip,
                                      const std::string& dst_ip,
                                      std::chrono::system_clock::time_point timestamp) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (msg.is_request) {
        handleRequest(msg, src_ip, dst_ip, timestamp);
    } else {
        handleResponse(msg, src_ip, dst_ip, timestamp);
    }
}

void SipDialogTracker::handleRequest(const SipMessage& msg, const std::string& src_ip,
                                     const std::string& dst_ip,
                                     std::chrono::system_clock::time_point timestamp) {
    // 1. Transaction Handling
    auto tx = getOrCreateTransaction(msg, timestamp);
    if (!tx)
        return;

    // Update transaction state
    if (msg.method == "ACK") {
        if (tx->state == SipTransaction::State::COMPLETED) {
            tx->state = SipTransaction::State::CONFIRMED;
        }
    } else if (msg.method == "BYE" || msg.method == "CANCEL") {
        // modifying existing transaction or creating new one?
        // BYE and CANCEL are separate transactions but relate to existing dialogs
        tx->state = SipTransaction::State::CALLING;
    }

    // 2. Dialog Handling
    auto dialog = findOrCreateDialog(msg, timestamp);
    if (!dialog)
        return;  // Could be stateless request or error

    // Link transaction to dialog if not already linked
    bool tx_exists = false;
    for (const auto& existing_tx : dialog->transactions) {
        if (existing_tx->branch == tx->branch) {
            tx_exists = true;
            break;
        }
    }
    if (!tx_exists) {
        dialog->transactions.push_back(tx);
    }

    // Update Dialog State
    if (msg.method == "BYE") {
        // We don't terminate immediately on BYE request, wait for 200 OK
        // But we can mark it as terminating if we wanted
    } else if (msg.method == "INVITE") {
        // Re-INVITE?
        if (dialog->state == SipDialog::State::CONFIRMED) {
            // This is a re-INVITE
            // Update media if SDP present
            if (msg.sdp) {
                updateMediaInfo(*dialog, *msg.sdp, true);  // Assuming request is local->remote?
                // Actually we need to know direction relative to dialog creation
                // For simplified tracking:
                if (src_ip == dialog->local_uri ||
                    msg.from.find(dialog->local_uri) != std::string::npos) {
                    updateMediaInfo(*dialog, *msg.sdp, true);
                } else {
                    updateMediaInfo(*dialog, *msg.sdp, false);
                }
            }
        }
    }
}

void SipDialogTracker::handleResponse(const SipMessage& msg, const std::string& src_ip,
                                      const std::string& dst_ip,
                                      std::chrono::system_clock::time_point timestamp) {
    // Find transaction
    std::string branch = msg.via_branch;
    if (branch.empty())
        return;

    auto it = transactions_.find(branch);
    if (it == transactions_.end()) {
        // Stray response or transaction cleaned up
        return;
    }

    auto tx = it->second;
    tx->response_time = timestamp;  // Update last response time? Or first? usually first final
                                    // response matters for latency

    if (msg.status_code >= 100 && msg.status_code < 200) {
        tx->provisional_responses.push_back(msg.status_code);
        tx->state = SipTransaction::State::PROCEEDING;
    } else if (msg.status_code >= 200) {
        tx->final_response_code = msg.status_code;
        tx->state = SipTransaction::State::COMPLETED;
    }

    // Update Dialog
    // Find dialog - Note: Response might create a dialog (e.g. 180 Ringing with To-tag)
    // or update existing one (200 OK)

    // We try to find the dialog again because tags might have updated (To-tag in response)
    // The key in map might need to be updated or we search by Call-ID and check tags

    std::shared_ptr<SipDialog> dialog = nullptr;

    // Search by Call-ID and From-tag
    // The response has same From-tag as request.
    // It has To-tag.

    std::string call_id = msg.call_id;
    std::string from_tag = msg.from_tag;
    std::string to_tag = msg.to_tag;

    // Search in call_id_index
    auto range = call_id_index_.equal_range(call_id);
    for (auto i = range.first; i != range.second; ++i) {
        auto d = i->second;
        // Check if this dialog matches
        if (d->from_tag == from_tag) {
            // If dialog has no to_tag (EARLY), and this response has to_tag
            // We might need to split (forking) or update
            if (d->to_tag.empty() && !to_tag.empty()) {
                // First response with tag? Update this dialog
                // OR if this is a second response with diff tag -> Fork!

                // Check if we already have a focused dialog for this call_id/from/to
                // If d is the only one and has empty to_tag, we claim it.
                // Otherwise we might need to create a new one.

                // BUT, wait, if we have multiple forks, we should have multiple dialogs.
                // Ideally we should have created an EARLY dialog without To-tag?
                // Actually RFC says dialog is identified by Call-ID + From-tag + To-tag.
                // An early dialog (100 Trying) might not have To-tag.

                d->to_tag = to_tag;
                d->dialog_id = d->computeDialogId();
                // Re-insert into map with new ID?
                // This is tricky with pointers in maps.
                // Since we use shared_ptr, we can update the object.
                // But we need to update the main map `dialogs_` key.

                // Remove old key
                // Note: This logic is simplified. Real SIP stack is more complex.
                // For visualization, we treat the first To-tag as the "main" one usually unless
                // forked.

                dialog = d;

            } else if (d->to_tag == to_tag) {
                dialog = d;
            }
        }
    }

    // If no dialog found and it's a 1xx or 2xx to INVITE, handle forking
    if (!dialog && (msg.status_code < 300) && !msg.to_tag.empty()) {
        if (tx && tx->method == "INVITE") {
            // FORKING: Create new dialog from this response
            auto new_dialog = std::make_shared<SipDialog>();
            new_dialog->call_id = call_id;
            new_dialog->from_tag = from_tag;
            new_dialog->to_tag = to_tag;
            new_dialog->dialog_id = new_dialog->computeDialogId();
            new_dialog->created_at = timestamp;
            new_dialog->state =
                (msg.status_code < 200) ? SipDialog::State::EARLY : SipDialog::State::CONFIRMED;

            if (new_dialog->state == SipDialog::State::CONFIRMED) {
                new_dialog->confirmed_at = timestamp;
            }

            // Parse URIs (copy from findOrCreateDialog logic)
            size_t sip_pos = msg.from.find("sip:");
            size_t end_pos = msg.from.find_first_of(";>", sip_pos);
            if (sip_pos != std::string::npos) {
                new_dialog->local_uri = msg.from.substr(sip_pos, end_pos - sip_pos);
            } else {
                new_dialog->local_uri = msg.from;
            }

            sip_pos = msg.to.find("sip:");
            end_pos = msg.to.find_first_of(";>", sip_pos);
            if (sip_pos != std::string::npos) {
                new_dialog->remote_uri = msg.to.substr(sip_pos, end_pos - sip_pos);
            } else {
                new_dialog->remote_uri = msg.to;
            }

            // Handle Media
            if (msg.sdp) {
                updateMediaInfo(*new_dialog, *msg.sdp, false);  // Response usually from remote
            }

            // Store and Index
            dialogs_[new_dialog->dialog_id] = new_dialog;
            call_id_index_.insert({new_dialog->call_id, new_dialog});
            uri_index_.insert({new_dialog->local_uri, new_dialog});

            dialog = new_dialog;

            // Mark forking
            auto range_fork = call_id_index_.equal_range(call_id);
            for (auto i = range_fork.first; i != range_fork.second; ++i) {
                if (i->second != new_dialog) {
                    new_dialog->forked_dialogs.push_back(i->second->dialog_id);
                    i->second->forked_dialogs.push_back(new_dialog->dialog_id);
                }
            }
        }
    }

    if (dialog) {
        // Update dialog state
        if (msg.status_code >= 200 && msg.status_code < 300) {
            if (tx->method == "INVITE") {
                dialog->state = SipDialog::State::CONFIRMED;
                if (!dialog->confirmed_at)
                    dialog->confirmed_at = timestamp;

                // Update media
                if (msg.sdp) {
                    updateMediaInfo(*dialog, *msg.sdp, false);
                }
            } else if (tx->method == "BYE") {
                dialog->state = SipDialog::State::TERMINATED;
                dialog->terminated_at = timestamp;
            }
        } else if (msg.status_code >= 300) {
            // Failure
            if (tx->method == "INVITE" && dialog->state == SipDialog::State::EARLY) {
                dialog->state = SipDialog::State::TERMINATED;
                dialog->terminated_at = timestamp;
            }
        }
    }
}

std::shared_ptr<SipTransaction> SipDialogTracker::getOrCreateTransaction(
    const SipMessage& msg, std::chrono::system_clock::time_point timestamp) {
    if (msg.via_branch.empty())
        return nullptr;

    auto it = transactions_.find(msg.via_branch);
    if (it != transactions_.end()) {
        return it->second;
    }

    // Create new transaction
    auto tx = std::make_shared<SipTransaction>();
    tx->branch = msg.via_branch;
    tx->method = msg.method;
    // Extract CSeq number
    try {
        size_t space = msg.cseq.find(' ');
        if (space != std::string::npos) {
            tx->cseq_number = std::stoul(msg.cseq.substr(0, space));
        } else {
            tx->cseq_number = std::stoul(msg.cseq);
        }
    } catch (...) {
        tx->cseq_number = 0;
    }

    tx->request_time = timestamp;
    tx->state = SipTransaction::State::CALLING;

    transactions_[msg.via_branch] = tx;
    return tx;
}

std::shared_ptr<SipDialog> SipDialogTracker::findOrCreateDialog(
    const SipMessage& msg, std::chrono::system_clock::time_point timestamp) {
    // Only INVITE, SUBSCRIBE, REFER create dialogs
    // But we might start tracking mid-stream

    std::string call_id = msg.call_id;
    if (call_id.empty())
        return nullptr;

    std::string from_tag = msg.from_tag;
    std::string to_tag = msg.to_tag;

    // Try exact match first
    std::string dialog_id = call_id + ":" + from_tag + ":" + to_tag;

    if (to_tag.empty()) {
        // Initial request usually has no To-tag
        // Dialog ID is just Call-ID + From-tag
        dialog_id = call_id + ":" + from_tag;
    }

    auto it = dialogs_.find(dialog_id);
    if (it != dialogs_.end()) {
        return it->second;
    }

    // Create new dialog if it's a dialog-creating method
    if (msg.isDialogCreating()) {
        auto dialog = std::make_shared<SipDialog>();
        dialog->call_id = call_id;
        dialog->from_tag = from_tag;
        dialog->to_tag = to_tag;        // might be empty
        dialog->dialog_id = dialog_id;  // Store key

        // URIs
        size_t sip_pos = msg.from.find("sip:");
        size_t end_pos = msg.from.find_first_of(";>", sip_pos);
        if (sip_pos != std::string::npos) {
            dialog->local_uri = msg.from.substr(sip_pos, end_pos - sip_pos);
        } else {
            dialog->local_uri = msg.from;
        }

        sip_pos = msg.to.find("sip:");
        end_pos = msg.to.find_first_of(";>", sip_pos);
        if (sip_pos != std::string::npos) {
            dialog->remote_uri = msg.to.substr(sip_pos, end_pos - sip_pos);
        } else {
            dialog->remote_uri = msg.to;
        }

        dialog->created_at = timestamp;
        dialog->state = SipDialog::State::EARLY;

        // Initial Media
        if (msg.sdp) {
            updateMediaInfo(*dialog, *msg.sdp, true);  // Local media
        }

        // Store
        dialogs_[dialog_id] = dialog;
        call_id_index_.insert({call_id, dialog});
        uri_index_.insert({dialog->local_uri, dialog});

        return dialog;
    }

    return nullptr;
}

std::shared_ptr<SipDialog> SipDialogTracker::getDialogByCallId(const std::string& call_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = call_id_index_.find(call_id);
    if (it != call_id_index_.end()) {
        return it->second;
    }
    return nullptr;
}

std::shared_ptr<SipDialog> SipDialogTracker::getDialogById(const std::string& dialog_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = dialogs_.find(dialog_id);
    if (it != dialogs_.end()) {
        return it->second;
    }
    return nullptr;
}

std::vector<std::shared_ptr<SipDialog>> SipDialogTracker::getDialogsByUri(
    const std::string& uri) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::shared_ptr<SipDialog>> results;
    auto range = uri_index_.equal_range(uri);
    for (auto i = range.first; i != range.second; ++i) {
        results.push_back(i->second);
    }
    return results;
}

std::vector<std::shared_ptr<SipDialog>> SipDialogTracker::getActiveDialogs() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::shared_ptr<SipDialog>> results;
    for (const auto& [id, dialog] : dialogs_) {
        if (dialog->state != SipDialog::State::TERMINATED) {
            results.push_back(dialog);
        }
    }
    return results;
}

std::vector<std::shared_ptr<SipDialog>> SipDialogTracker::getAllDialogs() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::shared_ptr<SipDialog>> results;
    results.reserve(dialogs_.size());
    for (const auto& [id, dialog] : dialogs_) {
        results.push_back(dialog);
    }
    return results;
}

SipDialogTracker::Stats SipDialogTracker::getStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    Stats stats;
    stats.total_dialogs = dialogs_.size();

    double total_setup = 0;
    int setup_counts = 0;

    for (const auto& [id, dialog] : dialogs_) {
        if (dialog->state != SipDialog::State::TERMINATED) {
            stats.active_dialogs++;
        }
        if (dialog->state == SipDialog::State::EARLY) {
            stats.early_dialogs++;
        }
        if (dialog->isForked()) {
            stats.forked_dialogs++;
        }

        if (dialog->confirmed_at) {
            auto diff = std::chrono::duration_cast<std::chrono::milliseconds>(
                            *dialog->confirmed_at - dialog->created_at)
                            .count();
            total_setup += diff;
            setup_counts++;
        }
    }

    stats.completed_transactions = 0;
    for (const auto& [id, tx] : transactions_) {
        if (tx->state == SipTransaction::State::COMPLETED ||
            tx->state == SipTransaction::State::CONFIRMED ||
            tx->state == SipTransaction::State::TERMINATED) {
            stats.completed_transactions++;
        }
    }

    if (setup_counts > 0) {
        stats.avg_setup_time_ms = total_setup / setup_counts;
    }

    return stats;
}

void SipDialogTracker::cleanup(std::chrono::seconds max_age) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto now = std::chrono::system_clock::now();

    // Cleanup transactions
    for (auto it = transactions_.begin(); it != transactions_.end();) {
        // Simple age check: request_time
        if (now - it->second->request_time >
            max_age) {  // Using max_age for transactions too for now, or maybe shorter? 60s for
                        // transactions is usually enough
            // RFC 3261 says 32s for Timer F (Non-INVITE)
            // Let's use 5 min for safety
            it = transactions_.erase(it);
        } else {
            ++it;
        }
    }

    // Cleanup dialogs
    for (auto it = dialogs_.begin(); it != dialogs_.end();) {
        bool stale = false;
        if (it->second->state == SipDialog::State::TERMINATED) {
            if (it->second->terminated_at && (now - *it->second->terminated_at > max_age)) {
                stale = true;
            }
        } else {
            // Keep active dialogs... but what if they are zombies?
            // Use active check?
            if (now - it->second->created_at > std::chrono::hours(24)) {  // Hard limit
                stale = true;
            }
        }

        if (stale) {
            // Remove from indexes
            // This is slow: O(N) scan of multimap ranges?
            // Better to cleanup indexes efficiently or rebuild them
            // For now, accept slight inefficiency or leak in indexes (pointers)
            // Ideally we need to find iterators in multimaps

            // NOTE: To properly remove from multimap, we need to search
            // But since we are removing shared_ptr, we can check equality

            // Remove from call_id_index_
            auto range = call_id_index_.equal_range(it->second->call_id);
            for (auto i = range.first; i != range.second;) {
                if (i->second == it->second) {
                    i = call_id_index_.erase(i);
                } else {
                    ++i;
                }
            }

            // Remove from uri_index_
            auto range2 = uri_index_.equal_range(it->second->local_uri);
            for (auto i = range2.first; i != range2.second;) {
                if (i->second == it->second) {
                    i = uri_index_.erase(i);
                } else {
                    ++i;
                }
            }

            it = dialogs_.erase(it);
        } else {
            ++it;
        }
    }
}

void SipDialogTracker::updateMediaInfo(SipDialog& dialog, const SipMessage::SdpInfo& sdp,
                                       bool is_local) {
    SipDialog::MediaInfo info;
    info.audio_ip = sdp.connection_address;
    info.audio_port = sdp.rtp_port;
    if (!sdp.codecs.empty()) {
        info.audio_codec = sdp.codecs[0].encoding_name;  // just take first
    }

    if (is_local) {
        dialog.local_media = info;
    } else {
        dialog.remote_media = info;
    }
}

}  // namespace callflow
