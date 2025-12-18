#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <queue>
#include <vector>
#include <nlohmann/json.hpp>

namespace callflow {

/**
 * SCTP stream state
 */
enum class SctpStreamState {
    ACTIVE,
    RESET_PENDING,
    CLOSED
};

/**
 * SCTP chunk data fragment
 */
struct SctpDataFragment {
    uint16_t stream_id;
    uint32_t tsn;              // Transmission Sequence Number
    uint16_t stream_sequence;   // Stream Sequence Number
    uint32_t payload_protocol;  // Payload Protocol Identifier
    bool unordered;             // U flag - unordered delivery
    bool beginning;             // B flag - beginning of message
    bool ending;                // E flag - ending of message
    std::vector<uint8_t> data;  // Fragment payload

    nlohmann::json toJson() const;
};

/**
 * Reassembled SCTP message
 */
struct SctpReassembledMessage {
    uint16_t stream_id;
    uint16_t stream_sequence;
    uint32_t payload_protocol;
    std::vector<uint8_t> data;  // Complete reassembled message
    uint32_t start_tsn;         // TSN of first fragment
    uint32_t end_tsn;           // TSN of last fragment
    size_t fragment_count;      // Number of fragments

    nlohmann::json toJson() const;
};

/**
 * Stream reassembly context
 */
struct SctpStreamContext {
    uint16_t stream_id;
    uint32_t next_expected_ssn;  // Next expected Stream Sequence Number
    SctpStreamState state;

    // Fragmented message reassembly
    std::map<uint16_t, std::vector<SctpDataFragment>> pending_fragments;  // SSN -> fragments

    // Out-of-order delivery for unordered streams
    std::map<uint32_t, SctpDataFragment> unordered_buffer;  // TSN -> fragment

    // Statistics
    uint64_t messages_received;
    uint64_t bytes_received;
    uint64_t fragments_received;
    uint64_t out_of_order_count;

    SctpStreamContext(uint16_t id)
        : stream_id(id),
          next_expected_ssn(0),
          state(SctpStreamState::ACTIVE),
          messages_received(0),
          bytes_received(0),
          fragments_received(0),
          out_of_order_count(0) {}

    nlohmann::json toJson() const;
};

/**
 * SCTP Stream Reassembler
 *
 * Handles per-stream sequence tracking, fragment reassembly,
 * and out-of-order delivery for SCTP multi-streaming.
 */
class SctpStreamReassembler {
public:
    SctpStreamReassembler() = default;
    ~SctpStreamReassembler() = default;

    /**
     * Add a data chunk fragment to the reassembler
     * @param fragment Data fragment to add
     * @return Reassembled message if complete, nullopt otherwise
     */
    std::optional<SctpReassembledMessage> addFragment(const SctpDataFragment& fragment);

    /**
     * Check if there are complete messages available
     * @return True if messages are ready to be retrieved
     */
    bool hasCompleteMessages() const;

    /**
     * Get the next complete message
     * @return Complete message or nullopt if none available
     */
    std::optional<SctpReassembledMessage> getCompleteMessage();

    /**
     * Handle a gap in the sequence (e.g., packet loss detected)
     * @param stream_id Stream ID
     * @param gap_start Start TSN of the gap
     * @param gap_end End TSN of the gap
     */
    void handleGap(uint16_t stream_id, uint32_t gap_start, uint32_t gap_end);

    /**
     * Reset a stream
     * @param stream_id Stream ID to reset
     */
    void resetStream(uint16_t stream_id);

    /**
     * Get stream context
     * @param stream_id Stream ID
     * @return Stream context or nullopt if not found
     */
    std::optional<SctpStreamContext> getStreamContext(uint16_t stream_id) const;

    /**
     * Get all stream IDs
     * @return Vector of active stream IDs
     */
    std::vector<uint16_t> getStreamIds() const;

    /**
     * Get reassembler statistics as JSON
     */
    nlohmann::json getStatistics() const;

    /**
     * Clear all stream state
     */
    void clear();

private:
    /**
     * Get or create stream context
     */
    SctpStreamContext& getOrCreateStream(uint16_t stream_id);

    /**
     * Try to reassemble fragments for a given stream and SSN
     * @param stream Stream context
     * @param ssn Stream Sequence Number
     * @return Reassembled message if complete, nullopt otherwise
     */
    std::optional<SctpReassembledMessage> tryReassemble(SctpStreamContext& stream, uint16_t ssn);

    /**
     * Check if all fragments for a message are available
     * @param fragments Vector of fragments
     * @return True if message is complete
     */
    bool isMessageComplete(const std::vector<SctpDataFragment>& fragments) const;

    /**
     * Assemble fragments into a complete message
     * @param fragments Vector of fragments (must be complete)
     * @return Reassembled message
     */
    SctpReassembledMessage assembleFragments(const std::vector<SctpDataFragment>& fragments);

    /**
     * Handle unordered fragment
     * @param stream Stream context
     * @param fragment Data fragment
     * @return Reassembled message if complete, nullopt otherwise
     */
    std::optional<SctpReassembledMessage> handleUnorderedFragment(
        SctpStreamContext& stream, const SctpDataFragment& fragment);

    /**
     * Handle ordered fragment
     * @param stream Stream context
     * @param fragment Data fragment
     * @return Reassembled message if complete, nullopt otherwise
     */
    std::optional<SctpReassembledMessage> handleOrderedFragment(
        SctpStreamContext& stream, const SctpDataFragment& fragment);

    // Stream contexts indexed by stream ID
    std::map<uint16_t, SctpStreamContext> streams_;

    // Queue of complete messages ready for retrieval
    std::queue<SctpReassembledMessage> complete_messages_;

    // Global statistics
    uint64_t total_fragments_;
    uint64_t total_messages_;
    uint64_t total_bytes_;
    uint64_t total_gaps_;
};

}  // namespace callflow
