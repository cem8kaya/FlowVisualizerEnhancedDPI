#include "pcap_ingest/tcp_reassembler.h"

#include "common/logger.h"

namespace callflow {

TcpReassembler::TcpReassembler() {}

void TcpReassembler::cleanup() {
    auto now = std::chrono::steady_clock::now();
    for (auto it = streams_.begin(); it != streams_.end();) {
        if (std::chrono::duration_cast<std::chrono::seconds>(now - it->second.last_update).count() >
            timeout_sec_) {
            it = streams_.erase(it);
        } else {
            ++it;
        }
    }
}

std::vector<uint8_t> TcpReassembler::processSegment(const FiveTuple& flow_id, uint32_t seq,
                                                    const std::vector<uint8_t>& payload,
                                                    bool is_syn, bool is_fin) {
    auto& state = streams_[flow_id];
    state.last_update = std::chrono::steady_clock::now();

    // Handle SYN
    if (is_syn) {
        state.syn_seen = true;
        state.next_seq = seq + 1;

        // If there is payload in SYN, process it? (Allowed but rare, TFO)
        if (!payload.empty()) {
            // Treat payload as starting at seq+1
            // But usually SYN consumes 1 seq, payload starts at seq+1? No.
            // SYN consumes 1. Data starts at (seq of SYN) + 1.
            // So if payload is attached to SYN packet, it starts at seq+1.
            // We adjust `seq` to `seq + 1` for payload processing?
            // Logic below:
            // If payload non-empty, handle it.
        }
    } else if (!state.syn_seen) {
        // Mid-stream pickup?
        // We can either drop until we see SYN, or assume we start here if it looks reasonable.
        // For DPI, we often want to parse what we can.
        // Strategy: If first packet we see for this flow, assume it's next.
        if (state.next_seq == 0) {
            state.next_seq = seq;
            state.syn_seen = true;  // Pretend we are synced
        }
    }

    std::vector<uint8_t> reassembled;

    // effective_seq is where the data starts
    uint32_t effective_seq = seq;
    if (is_syn) {
        effective_seq++;
    }

    if (payload.empty()) {
        // Just an ACK or control packet.
        // FIN handling
        if (is_fin) {
            // FIN consumes 1 seq
            // If we were waiting for this seq, advance.
            if (effective_seq == state.next_seq) {
                state.next_seq++;
            }
        }
        return reassembled;
    }

    // Check if this is the expected sequence
    // Using wrapping arithmetic logic: overflow safe difference
    int32_t diff = static_cast<int32_t>(effective_seq - state.next_seq);

    if (diff == 0) {
        // Expected segment
        reassembled.insert(reassembled.end(), payload.begin(), payload.end());
        state.next_seq += payload.size();

        // Check for FIN processing (FIN is usually at end of payload)
        if (is_fin) {
            state.next_seq++;
        }

        // Check buffer for subsequent segments
        while (!state.out_of_order_segments.empty()) {
            auto it = state.out_of_order_segments.begin();
            uint32_t buffered_seq = it->first;

            if (buffered_seq == state.next_seq) {
                // Next contiguous block
                reassembled.insert(reassembled.end(), it->second.begin(), it->second.end());
                state.next_seq += it->second.size();
                state.out_of_order_segments.erase(it);
            } else {
                // Check if buffered packet is now overlap/old (should have been handled)
                // or just still ahead.
                int32_t buf_diff = static_cast<int32_t>(buffered_seq - state.next_seq);
                if (buf_diff < 0) {
                    // Old data, remove
                    state.out_of_order_segments.erase(it);
                } else {
                    // Gap, stop
                    break;
                }
            }
        }
    } else if (diff > 0) {
        // Gap, buffer it
        // Only buffer if reasonable size to avoid DoS
        if (state.out_of_order_segments.size() < 100) {
            state.out_of_order_segments[effective_seq] = payload;
        }
    } else {
        // Duplicate or retransmission (diff < 0)
        // Ignore
    }

    return reassembled;
}

}  // namespace callflow
