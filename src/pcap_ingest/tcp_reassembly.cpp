#include "pcap_ingest/tcp_reassembly.h"

#include "common/logger.h"
#include "pcap_ingest/tcp_state_machine.h"

namespace callflow {

const char* tcpStateToString(TcpStreamState::State state) {
    switch (state) {
        case TcpStreamState::State::CLOSED:
            return "CLOSED";
        case TcpStreamState::State::SYN_SENT:
            return "SYN_SENT";
        case TcpStreamState::State::SYN_RECEIVED:
            return "SYN_RECEIVED";
        case TcpStreamState::State::ESTABLISHED:
            return "ESTABLISHED";
        case TcpStreamState::State::FIN_WAIT_1:
            return "FIN_WAIT_1";
        case TcpStreamState::State::FIN_WAIT_2:
            return "FIN_WAIT_2";
        case TcpStreamState::State::CLOSE_WAIT:
            return "CLOSE_WAIT";
        case TcpStreamState::State::CLOSING:
            return "CLOSING";
        case TcpStreamState::State::LAST_ACK:
            return "LAST_ACK";
        case TcpStreamState::State::TIME_WAIT:
            return "TIME_WAIT";
        default:
            return "UNKNOWN";
    }
}

TcpReassembler::TcpReassembler(size_t max_streams, size_t max_buffer_per_stream)
    : max_streams_(max_streams), max_buffer_per_stream_(max_buffer_per_stream) {
    LOG_DEBUG("TcpReassembler initialized with max_streams=" << max_streams
                                                              << " max_buffer=" << max_buffer_per_stream);
}

TcpReassembler::~TcpReassembler() {
    LOG_DEBUG("TcpReassembler destroyed. Final stats: total_streams=" << stats_.total_streams
                                                                       << " bytes_reassembled=" << stats_.bytes_reassembled);
}

void TcpReassembler::processPacket(const FiveTuple& ft, const TcpSegment& segment) {
    // Check stream limit
    if (streams_.size() >= max_streams_ && streams_.find(ft) == streams_.end()) {
        LOG_WARN("Maximum stream limit reached (" << max_streams_ << "), dropping new stream");
        return;
    }

    auto& state = streams_[ft];

    // Initialize new stream
    if (state.state == TcpStreamState::State::CLOSED && state.first_seen.time_since_epoch().count() == 0) {
        state.first_seen = segment.timestamp;
        stats_.total_streams++;
        stats_.active_streams++;
        LOG_DEBUG("New TCP stream: " << ft.toString());
    }

    state.last_seen = segment.timestamp;

    // Determine direction (client/server)
    // We use a canonical form: the endpoint that sends the first SYN is the "client"
    // For mid-stream pickups, we use the first packet's direction
    bool is_client = isClient(ft, ft);

    // Handle RST
    if (segment.flags & TCP_FLAG_RST) {
        handleRst(ft, state);
        return;
    }

    // Handle SYN
    if (segment.flags & TCP_FLAG_SYN) {
        handleSyn(ft, state, segment, is_client);
        return;
    }

    // Handle FIN
    if (segment.flags & TCP_FLAG_FIN) {
        handleFin(ft, state, segment, is_client);
    }

    // Handle data
    if (!segment.payload.empty()) {
        handleData(ft, state, segment, is_client);
    }

    // Process state machine
    TcpStateMachine::processFlags(state, segment.flags, is_client);
}

void TcpReassembler::handleSyn(const FiveTuple& ft, TcpStreamState& state,
                                const TcpSegment& seg, bool is_client) {
    if (is_client) {
        if (state.state == TcpStreamState::State::CLOSED) {
            state.isn_client = seg.seq_num;
            state.next_seq_client = seg.seq_num + 1;
            state.state = TcpStreamState::State::SYN_SENT;
            LOG_DEBUG("TCP SYN from client: " << ft.toString() << " ISN=" << seg.seq_num);
        }
    } else {
        // SYN-ACK from server
        if (state.state == TcpStreamState::State::SYN_SENT ||
            state.state == TcpStreamState::State::CLOSED) {
            state.isn_server = seg.seq_num;
            state.next_seq_server = seg.seq_num + 1;
            state.state = TcpStreamState::State::SYN_RECEIVED;
            LOG_DEBUG("TCP SYN-ACK from server: " << ft.toString() << " ISN=" << seg.seq_num);
        }
    }

    // Handle TCP Fast Open (TFO) - SYN with data
    if (!seg.payload.empty()) {
        LOG_DEBUG("TCP Fast Open detected with " << seg.payload.size() << " bytes");
        // Process payload starting at ISN + 1
        TcpSegment data_seg = seg;
        data_seg.seq_num = seg.seq_num + 1;
        data_seg.flags &= ~TCP_FLAG_SYN;
        handleData(ft, state, data_seg, is_client);
    }
}

void TcpReassembler::handleData(const FiveTuple& ft, TcpStreamState& state,
                                 const TcpSegment& seg, bool is_client) {
    if (state.state != TcpStreamState::State::ESTABLISHED &&
        state.state != TcpStreamState::State::FIN_WAIT_1 &&
        state.state != TcpStreamState::State::FIN_WAIT_2 &&
        state.state != TcpStreamState::State::CLOSE_WAIT) {
        // Data before connection established - mid-stream pickup
        if (state.state == TcpStreamState::State::CLOSED ||
            state.state == TcpStreamState::State::SYN_SENT) {
            LOG_DEBUG("Mid-stream TCP pickup: " << ft.toString());
            state.state = TcpStreamState::State::ESTABLISHED;
            if (is_client) {
                state.next_seq_client = seg.seq_num;
            } else {
                state.next_seq_server = seg.seq_num;
            }
        }
    }

    // Check for retransmission
    if (isRetransmission(state, seg, is_client)) {
        LOG_DEBUG("TCP retransmission detected: seq=" << seg.seq_num << " len=" << seg.payload.size());
        stats_.retransmissions++;
        state.retransmissions++;
        return;
    }

    uint32_t& next_seq = is_client ? state.next_seq_client : state.next_seq_server;
    auto& ooo_buffer = is_client ? state.ooo_buffer_client : state.ooo_buffer_server;
    auto& buffer = is_client ? state.buffer_client : state.buffer_server;
    uint64_t& byte_count = is_client ? state.bytes_client : state.bytes_server;

    // Sequence number arithmetic (handles wraparound)
    int32_t diff = static_cast<int32_t>(seg.seq_num - next_seq);

    if (diff == 0) {
        // Expected sequence - in order
        buffer.insert(buffer.end(), seg.payload.begin(), seg.payload.end());
        next_seq += seg.payload.size();
        byte_count += seg.payload.size();
        stats_.bytes_reassembled += seg.payload.size();

        // Check buffer size limit
        if (buffer.size() > max_buffer_per_stream_) {
            LOG_WARN("TCP stream buffer overflow: " << ft.toString() << " size=" << buffer.size());
            stats_.truncated_streams++;
            buffer.erase(buffer.begin(), buffer.begin() + (buffer.size() - max_buffer_per_stream_));
        }

        // Deliver data via callback
        if (data_callback_ && !buffer.empty()) {
            Direction dir = is_client ? Direction::CLIENT_TO_SERVER : Direction::SERVER_TO_CLIENT;
            data_callback_(ft, dir, buffer.data(), buffer.size(), seg.timestamp);
        }

        // Check for contiguous out-of-order segments
        deliverInOrderData(ft, state, is_client);

    } else if (diff > 0) {
        // Future segment - out of order (gap exists)
        LOG_DEBUG("Out-of-order TCP segment: expected=" << next_seq << " got=" << seg.seq_num
                                                        << " gap=" << diff);
        stats_.out_of_order_handled++;
        state.out_of_order++;

        // Buffer it if reasonable
        if (ooo_buffer.size() < 100 && static_cast<uint32_t>(diff) < max_buffer_per_stream_) {
            ooo_buffer[seg.seq_num] = seg;
        } else {
            LOG_WARN("Out-of-order buffer limit reached, dropping segment");
        }

    } else {
        // Old segment (diff < 0) - likely duplicate/overlap
        // Check if it's a partial retransmission with new data
        uint32_t seg_end = seg.seq_num + seg.payload.size();
        if (static_cast<int32_t>(seg_end - next_seq) > 0) {
            // Partial overlap with new data
            uint32_t overlap = next_seq - seg.seq_num;
            if (overlap < seg.payload.size()) {
                LOG_DEBUG("Partial overlap with new data: overlap=" << overlap);
                buffer.insert(buffer.end(), seg.payload.begin() + overlap, seg.payload.end());
                next_seq += (seg.payload.size() - overlap);
                byte_count += (seg.payload.size() - overlap);
                stats_.bytes_reassembled += (seg.payload.size() - overlap);

                deliverInOrderData(ft, state, is_client);
            }
        }
    }
}

void TcpReassembler::deliverInOrderData(const FiveTuple& ft, TcpStreamState& state,
                                        bool is_client) {
    uint32_t& next_seq = is_client ? state.next_seq_client : state.next_seq_server;
    auto& ooo_buffer = is_client ? state.ooo_buffer_client : state.ooo_buffer_server;
    auto& buffer = is_client ? state.buffer_client : state.buffer_server;
    uint64_t& byte_count = is_client ? state.bytes_client : state.bytes_server;

    while (!ooo_buffer.empty()) {
        auto it = ooo_buffer.begin();

        if (it->first == next_seq) {
            // Next contiguous segment
            const auto& payload = it->second.payload;
            buffer.insert(buffer.end(), payload.begin(), payload.end());
            next_seq += payload.size();
            byte_count += payload.size();
            stats_.bytes_reassembled += payload.size();

            // Deliver data
            if (data_callback_ && !buffer.empty()) {
                Direction dir = is_client ? Direction::CLIENT_TO_SERVER : Direction::SERVER_TO_CLIENT;
                data_callback_(ft, dir, buffer.data(), buffer.size(), it->second.timestamp);
            }

            ooo_buffer.erase(it);
        } else if (static_cast<int32_t>(it->first - next_seq) < 0) {
            // Old segment, remove
            ooo_buffer.erase(it);
        } else {
            // Still have gap
            break;
        }
    }
}

void TcpReassembler::handleFin(const FiveTuple& ft, TcpStreamState& state,
                                const TcpSegment& seg, bool is_client) {
    LOG_DEBUG("TCP FIN: " << ft.toString() << " from " << (is_client ? "client" : "server"));

    // Process any remaining data in this segment first
    if (!seg.payload.empty()) {
        TcpSegment data_seg = seg;
        data_seg.flags &= ~TCP_FLAG_FIN;
        handleData(ft, state, data_seg, is_client);
    }

    // Flush buffer for this direction
    flushBuffer(ft, state, is_client);

    // Update sequence for FIN (consumes 1 byte)
    uint32_t& next_seq = is_client ? state.next_seq_client : state.next_seq_server;
    if (seg.seq_num + (seg.payload.empty() ? 0 : seg.payload.size()) == next_seq) {
        next_seq++;
    }

    // State machine will handle FIN state transitions
}

void TcpReassembler::handleRst(const FiveTuple& ft, TcpStreamState& state) {
    LOG_DEBUG("TCP RST: " << ft.toString());

    // Flush both directions
    flushBuffer(ft, state, true);
    flushBuffer(ft, state, false);

    // Notify close
    if (close_callback_) {
        close_callback_(ft);
    }

    // Clean up stream
    streams_.erase(ft);
    stats_.active_streams--;
}

void TcpReassembler::flushBuffer(const FiveTuple& ft, TcpStreamState& state, bool is_client) {
    auto& buffer = is_client ? state.buffer_client : state.buffer_server;

    if (!buffer.empty() && data_callback_) {
        Direction dir = is_client ? Direction::CLIENT_TO_SERVER : Direction::SERVER_TO_CLIENT;
        data_callback_(ft, dir, buffer.data(), buffer.size(), state.last_seen);
        LOG_DEBUG("Flushed " << buffer.size() << " bytes from TCP stream: " << ft.toString());
    }

    buffer.clear();
}

bool TcpReassembler::isRetransmission(const TcpStreamState& state, const TcpSegment& seg,
                                       bool is_client) {
    uint32_t next_seq = is_client ? state.next_seq_client : state.next_seq_server;

    // Retransmission if sequence number is before expected
    int32_t diff = static_cast<int32_t>(seg.seq_num - next_seq);
    if (diff < 0) {
        // Check if entire segment is old data
        uint32_t seg_end = seg.seq_num + seg.payload.size();
        if (static_cast<int32_t>(seg_end - next_seq) <= 0) {
            return true;  // Pure retransmission
        }
    }

    return false;
}

bool TcpReassembler::isClient(const FiveTuple& ft, const FiveTuple& canonical_ft) {
    // Simple heuristic: lower IP/port combination is "client"
    // In practice, we'd track which side sent the first SYN
    // For now, use lexicographic comparison
    return ft.src_ip < ft.dst_ip || (ft.src_ip == ft.dst_ip && ft.src_port < ft.dst_port);
}

size_t TcpReassembler::cleanupStaleStreams(Timestamp now, std::chrono::seconds timeout) {
    size_t cleaned = 0;

    for (auto it = streams_.begin(); it != streams_.end();) {
        const auto& state = it->second;
        auto age = std::chrono::duration_cast<std::chrono::seconds>(now - state.last_seen);

        if (age > timeout) {
            LOG_DEBUG("Cleaning up stale TCP stream: " << it->first.toString()
                                                       << " age=" << age.count() << "s");

            // Flush any remaining data
            const_cast<TcpReassembler*>(this)->flushBuffer(it->first,
                                                           const_cast<TcpStreamState&>(state), true);
            const_cast<TcpReassembler*>(this)->flushBuffer(it->first,
                                                           const_cast<TcpStreamState&>(state), false);

            // Notify close
            if (close_callback_) {
                close_callback_(it->first);
            }

            it = streams_.erase(it);
            stats_.active_streams--;
            cleaned++;
        } else {
            ++it;
        }
    }

    return cleaned;
}

void TcpReassembler::cleanup() {
    auto now = std::chrono::system_clock::now();
    cleanupStaleStreams(now, std::chrono::seconds(300));
}

TcpReassembler::Stats TcpReassembler::getStats() const {
    auto stats = stats_;
    stats.active_streams = streams_.size();
    return stats;
}

// Legacy interface for backward compatibility
std::vector<uint8_t> TcpReassembler::processSegment(const FiveTuple& flow_id, uint32_t seq,
                                                     const std::vector<uint8_t>& payload,
                                                     bool is_syn, bool is_fin) {
    // Create TcpSegment from legacy parameters
    TcpSegment segment;
    segment.seq_num = seq;
    segment.ack_num = 0;
    segment.flags = 0;
    if (is_syn)
        segment.flags |= TCP_FLAG_SYN;
    if (is_fin)
        segment.flags |= TCP_FLAG_FIN;
    segment.payload = payload;
    segment.timestamp = std::chrono::system_clock::now();

    // For legacy mode, we'll just accumulate and return when we have contiguous data
    auto& state = streams_[flow_id];

    // Initialize if needed
    if (state.state == TcpStreamState::State::CLOSED &&
        state.first_seen.time_since_epoch().count() == 0) {
        state.first_seen = segment.timestamp;
        state.next_seq_client = is_syn ? seq + 1 : seq;
        state.state = is_syn ? TcpStreamState::State::ESTABLISHED : TcpStreamState::State::ESTABLISHED;
        stats_.total_streams++;
    }

    state.last_seen = segment.timestamp;

    std::vector<uint8_t> result;

    if (is_syn) {
        state.next_seq_client = seq + 1;
        if (!payload.empty()) {
            state.buffer_client.insert(state.buffer_client.end(), payload.begin(), payload.end());
            state.next_seq_client += payload.size();
            result = state.buffer_client;
            state.buffer_client.clear();
        }
        return result;
    }

    int32_t diff = static_cast<int32_t>(seq - state.next_seq_client);

    if (diff == 0) {
        // Expected sequence
        state.buffer_client.insert(state.buffer_client.end(), payload.begin(), payload.end());
        state.next_seq_client += payload.size();

        if (is_fin) {
            state.next_seq_client++;
        }

        // Check for buffered segments
        while (!state.ooo_buffer_client.empty()) {
            auto it = state.ooo_buffer_client.begin();
            if (it->first == state.next_seq_client) {
                state.buffer_client.insert(state.buffer_client.end(), it->second.payload.begin(),
                                           it->second.payload.end());
                state.next_seq_client += it->second.payload.size();
                state.ooo_buffer_client.erase(it);
            } else {
                break;
            }
        }

        result = state.buffer_client;
        state.buffer_client.clear();

    } else if (diff > 0) {
        // Out of order - buffer it
        if (state.ooo_buffer_client.size() < 100) {
            state.ooo_buffer_client[seq] = segment;
        }
    }

    return result;
}

}  // namespace callflow
