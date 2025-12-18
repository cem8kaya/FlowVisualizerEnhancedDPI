#include "transport/sctp_reassembler.h"
#include <algorithm>

namespace callflow {

// ============================================================================
// SctpDataFragment Methods
// ============================================================================

nlohmann::json SctpDataFragment::toJson() const {
    nlohmann::json j;
    j["stream_id"] = stream_id;
    j["tsn"] = tsn;
    j["stream_sequence"] = stream_sequence;
    j["payload_protocol"] = payload_protocol;
    j["unordered"] = unordered;
    j["beginning"] = beginning;
    j["ending"] = ending;
    j["data_length"] = data.size();
    return j;
}

// ============================================================================
// SctpReassembledMessage Methods
// ============================================================================

nlohmann::json SctpReassembledMessage::toJson() const {
    nlohmann::json j;
    j["stream_id"] = stream_id;
    j["stream_sequence"] = stream_sequence;
    j["payload_protocol"] = payload_protocol;
    j["data_length"] = data.size();
    j["start_tsn"] = start_tsn;
    j["end_tsn"] = end_tsn;
    j["fragment_count"] = fragment_count;
    return j;
}

// ============================================================================
// SctpStreamContext Methods
// ============================================================================

nlohmann::json SctpStreamContext::toJson() const {
    nlohmann::json j;
    j["stream_id"] = stream_id;
    j["next_expected_ssn"] = next_expected_ssn;
    j["state"] = static_cast<int>(state);
    j["messages_received"] = messages_received;
    j["bytes_received"] = bytes_received;
    j["fragments_received"] = fragments_received;
    j["out_of_order_count"] = out_of_order_count;
    j["pending_fragments_count"] = pending_fragments.size();
    j["unordered_buffer_count"] = unordered_buffer.size();
    return j;
}

// ============================================================================
// SctpStreamReassembler Methods
// ============================================================================

std::optional<SctpReassembledMessage> SctpStreamReassembler::addFragment(
    const SctpDataFragment& fragment) {

    total_fragments_++;

    auto& stream = getOrCreateStream(fragment.stream_id);
    stream.fragments_received++;
    stream.bytes_received += fragment.data.size();

    // Handle unordered vs ordered fragments
    if (fragment.unordered) {
        return handleUnorderedFragment(stream, fragment);
    } else {
        return handleOrderedFragment(stream, fragment);
    }
}

bool SctpStreamReassembler::hasCompleteMessages() const {
    return !complete_messages_.empty();
}

std::optional<SctpReassembledMessage> SctpStreamReassembler::getCompleteMessage() {
    if (complete_messages_.empty()) {
        return std::nullopt;
    }

    auto msg = complete_messages_.front();
    complete_messages_.pop();
    return msg;
}

void SctpStreamReassembler::handleGap(uint16_t stream_id, uint32_t gap_start, uint32_t gap_end) {
    total_gaps_++;

    auto it = streams_.find(stream_id);
    if (it == streams_.end()) {
        return;
    }

    auto& stream = it->second;

    // Remove any fragments in the gap range from unordered buffer
    auto buf_it = stream.unordered_buffer.begin();
    while (buf_it != stream.unordered_buffer.end()) {
        if (buf_it->first >= gap_start && buf_it->first <= gap_end) {
            buf_it = stream.unordered_buffer.erase(buf_it);
        } else {
            ++buf_it;
        }
    }

    // Note: For ordered fragments in pending_fragments, we may need to skip
    // the affected SSNs if they were part of the gap. This is application-specific.
}

void SctpStreamReassembler::resetStream(uint16_t stream_id) {
    auto it = streams_.find(stream_id);
    if (it != streams_.end()) {
        it->second.state = SctpStreamState::RESET_PENDING;
        it->second.pending_fragments.clear();
        it->second.unordered_buffer.clear();
    }
}

std::optional<SctpStreamContext> SctpStreamReassembler::getStreamContext(uint16_t stream_id) const {
    auto it = streams_.find(stream_id);
    if (it == streams_.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::vector<uint16_t> SctpStreamReassembler::getStreamIds() const {
    std::vector<uint16_t> ids;
    ids.reserve(streams_.size());
    for (const auto& pair : streams_) {
        ids.push_back(pair.first);
    }
    return ids;
}

nlohmann::json SctpStreamReassembler::getStatistics() const {
    nlohmann::json j;
    j["total_fragments"] = total_fragments_;
    j["total_messages"] = total_messages_;
    j["total_bytes"] = total_bytes_;
    j["total_gaps"] = total_gaps_;
    j["stream_count"] = streams_.size();
    j["pending_messages"] = complete_messages_.size();

    // Per-stream statistics
    nlohmann::json streams_json = nlohmann::json::array();
    for (const auto& pair : streams_) {
        streams_json.push_back(pair.second.toJson());
    }
    j["streams"] = streams_json;

    return j;
}

void SctpStreamReassembler::clear() {
    streams_.clear();
    while (!complete_messages_.empty()) {
        complete_messages_.pop();
    }
    total_fragments_ = 0;
    total_messages_ = 0;
    total_bytes_ = 0;
    total_gaps_ = 0;
}

// ============================================================================
// Private Methods
// ============================================================================

SctpStreamContext& SctpStreamReassembler::getOrCreateStream(uint16_t stream_id) {
    auto it = streams_.find(stream_id);
    if (it == streams_.end()) {
        auto result = streams_.emplace(stream_id, SctpStreamContext(stream_id));
        return result.first->second;
    }
    return it->second;
}

std::optional<SctpReassembledMessage> SctpStreamReassembler::handleUnorderedFragment(
    SctpStreamContext& stream, const SctpDataFragment& fragment) {

    // For unordered delivery, we can process fragments immediately
    // if they form a complete message (B and E flags both set)

    if (fragment.beginning && fragment.ending) {
        // Single-fragment message
        SctpReassembledMessage msg;
        msg.stream_id = fragment.stream_id;
        msg.stream_sequence = fragment.stream_sequence;
        msg.payload_protocol = fragment.payload_protocol;
        msg.data = fragment.data;
        msg.start_tsn = fragment.tsn;
        msg.end_tsn = fragment.tsn;
        msg.fragment_count = 1;

        stream.messages_received++;
        total_messages_++;
        total_bytes_ += msg.data.size();

        complete_messages_.push(msg);
        return msg;
    }

    // Multi-fragment unordered message
    // Store in unordered buffer and try to reassemble by TSN sequence
    stream.unordered_buffer[fragment.tsn] = fragment;

    // Try to find a complete sequence
    // Look for B flag fragment, then consecutive TSNs until E flag
    for (const auto& pair : stream.unordered_buffer) {
        const auto& start_frag = pair.second;

        if (!start_frag.beginning) {
            continue;  // Not a start fragment
        }

        // Try to build a complete message from this start
        std::vector<SctpDataFragment> fragments;
        fragments.push_back(start_frag);

        uint32_t expected_tsn = start_frag.tsn + 1;
        bool complete = start_frag.ending;

        while (!complete) {
            auto next_it = stream.unordered_buffer.find(expected_tsn);
            if (next_it == stream.unordered_buffer.end()) {
                break;  // Missing fragment
            }

            fragments.push_back(next_it->second);
            complete = next_it->second.ending;
            expected_tsn++;
        }

        if (complete) {
            // We have a complete message
            auto msg = assembleFragments(fragments);

            // Remove fragments from buffer
            for (const auto& frag : fragments) {
                stream.unordered_buffer.erase(frag.tsn);
            }

            stream.messages_received++;
            total_messages_++;
            total_bytes_ += msg.data.size();

            complete_messages_.push(msg);
            return msg;
        }
    }

    return std::nullopt;
}

std::optional<SctpReassembledMessage> SctpStreamReassembler::handleOrderedFragment(
    SctpStreamContext& stream, const SctpDataFragment& fragment) {

    // For ordered delivery, we must respect the Stream Sequence Number (SSN)

    // Check if this is the next expected SSN
    if (fragment.stream_sequence < stream.next_expected_ssn) {
        // Out-of-order or duplicate, ignore
        stream.out_of_order_count++;
        return std::nullopt;
    }

    // Add fragment to pending list for this SSN
    auto& fragments = stream.pending_fragments[fragment.stream_sequence];
    fragments.push_back(fragment);

    // Sort fragments by TSN to ensure correct order
    std::sort(fragments.begin(), fragments.end(),
              [](const SctpDataFragment& a, const SctpDataFragment& b) {
                  return a.tsn < b.tsn;
              });

    // Check if we can reassemble the message at the next expected SSN
    while (true) {
        auto it = stream.pending_fragments.find(stream.next_expected_ssn);
        if (it == stream.pending_fragments.end()) {
            break;  // No fragments for next expected SSN
        }

        auto& frags = it->second;
        if (!isMessageComplete(frags)) {
            break;  // Message not complete yet
        }

        // Reassemble and deliver
        auto msg = assembleFragments(frags);

        stream.pending_fragments.erase(it);
        stream.next_expected_ssn++;
        stream.messages_received++;
        total_messages_++;
        total_bytes_ += msg.data.size();

        complete_messages_.push(msg);

        // Continue checking for next SSN
    }

    // Return the first complete message if available
    if (hasCompleteMessages()) {
        return getCompleteMessage();
    }

    return std::nullopt;
}

bool SctpStreamReassembler::isMessageComplete(const std::vector<SctpDataFragment>& fragments) const {
    if (fragments.empty()) {
        return false;
    }

    // Check for B flag in first fragment and E flag in last fragment
    bool has_beginning = false;
    bool has_ending = false;

    for (const auto& frag : fragments) {
        if (frag.beginning) {
            has_beginning = true;
        }
        if (frag.ending) {
            has_ending = true;
        }
    }

    if (!has_beginning || !has_ending) {
        return false;
    }

    // Check that fragments form a contiguous sequence
    // Note: Fragments should already be sorted by TSN
    for (size_t i = 1; i < fragments.size(); ++i) {
        if (fragments[i].tsn != fragments[i-1].tsn + 1) {
            return false;  // Gap in sequence
        }
    }

    return true;
}

SctpReassembledMessage SctpStreamReassembler::assembleFragments(
    const std::vector<SctpDataFragment>& fragments) {

    SctpReassembledMessage msg;

    if (fragments.empty()) {
        return msg;
    }

    const auto& first = fragments.front();
    const auto& last = fragments.back();

    msg.stream_id = first.stream_id;
    msg.stream_sequence = first.stream_sequence;
    msg.payload_protocol = first.payload_protocol;
    msg.start_tsn = first.tsn;
    msg.end_tsn = last.tsn;
    msg.fragment_count = fragments.size();

    // Concatenate fragment data
    size_t total_size = 0;
    for (const auto& frag : fragments) {
        total_size += frag.data.size();
    }

    msg.data.reserve(total_size);
    for (const auto& frag : fragments) {
        msg.data.insert(msg.data.end(), frag.data.begin(), frag.data.end());
    }

    return msg;
}

}  // namespace callflow
