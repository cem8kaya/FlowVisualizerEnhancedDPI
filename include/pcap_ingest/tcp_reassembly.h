#pragma once

#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <optional>
#include <vector>

#include "common/types.h"

namespace callflow {

// TCP flags
constexpr uint8_t TCP_FLAG_FIN = 0x01;
constexpr uint8_t TCP_FLAG_SYN = 0x02;
constexpr uint8_t TCP_FLAG_RST = 0x04;
constexpr uint8_t TCP_FLAG_PSH = 0x08;
constexpr uint8_t TCP_FLAG_ACK = 0x10;
constexpr uint8_t TCP_FLAG_URG = 0x20;

struct TcpSegment {
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t flags;  // SYN, ACK, FIN, RST, PSH
    std::vector<uint8_t> payload;
    Timestamp timestamp;
    bool retransmission = false;
};

struct TcpStreamState {
    enum class State {
        CLOSED,
        SYN_SENT,
        SYN_RECEIVED,
        ESTABLISHED,
        FIN_WAIT_1,
        FIN_WAIT_2,
        CLOSE_WAIT,
        CLOSING,
        LAST_ACK,
        TIME_WAIT
    };

    State state = State::CLOSED;
    uint32_t isn_client = 0;  // Initial sequence number from client
    uint32_t isn_server = 0;  // Initial sequence number from server
    uint32_t next_seq_client = 0;
    uint32_t next_seq_server = 0;

    // Out-of-order segment buffers (seq -> segment)
    std::map<uint32_t, TcpSegment> ooo_buffer_client;
    std::map<uint32_t, TcpSegment> ooo_buffer_server;

    // Reassembled stream buffers
    std::vector<uint8_t> buffer_client;
    std::vector<uint8_t> buffer_server;

    // Statistics
    uint64_t bytes_client = 0;
    uint64_t bytes_server = 0;
    uint32_t retransmissions = 0;
    uint32_t out_of_order = 0;

    Timestamp first_seen;
    Timestamp last_seen;
};

const char* tcpStateToString(TcpStreamState::State state);

class TcpReassembler {
public:
    using DataCallback = std::function<void(const FiveTuple&, Direction, const uint8_t*, size_t,
                                            Timestamp)>;
    using StreamCloseCallback = std::function<void(const FiveTuple&)>;

    TcpReassembler(size_t max_streams = 100000, size_t max_buffer_per_stream = 1024 * 1024);
    ~TcpReassembler();

    /**
     * Process a TCP packet segment
     * @param ft Five-tuple identifying the flow
     * @param segment TCP segment data
     */
    void processPacket(const FiveTuple& ft, const TcpSegment& segment);

    /**
     * Legacy interface for backward compatibility
     * @param flow_id The 5-tuple identifying the flow
     * @param seq The sequence number of the segment
     * @param payload TCP payload data
     * @param is_syn True if SYN flag is set
     * @param is_fin True if FIN flag is set
     * @return Contiguous payload data if available, otherwise empty.
     */
    std::vector<uint8_t> processSegment(const FiveTuple& flow_id, uint32_t seq,
                                        const std::vector<uint8_t>& payload, bool is_syn,
                                        bool is_fin);

    /**
     * Set callback for reassembled data delivery
     */
    void setDataCallback(DataCallback cb) { data_callback_ = std::move(cb); }

    /**
     * Set callback for stream close events
     */
    void setCloseCallback(StreamCloseCallback cb) { close_callback_ = std::move(cb); }

    /**
     * Clean up stale streams based on timeout
     * @param now Current timestamp
     * @param timeout Timeout duration (default 300 seconds)
     * @return Number of streams cleaned up
     */
    size_t cleanupStaleStreams(Timestamp now,
                               std::chrono::seconds timeout = std::chrono::seconds(300));

    /**
     * Legacy cleanup interface
     */
    void cleanup();

    struct Stats {
        uint64_t total_streams = 0;
        uint64_t active_streams = 0;
        uint64_t bytes_reassembled = 0;
        uint64_t retransmissions = 0;
        uint64_t out_of_order_handled = 0;
        uint64_t truncated_streams = 0;
    };

    Stats getStats() const;

private:
    std::map<FiveTuple, TcpStreamState> streams_;
    DataCallback data_callback_;
    StreamCloseCallback close_callback_;
    size_t max_streams_;
    size_t max_buffer_per_stream_;
    Stats stats_;

    void handleSyn(const FiveTuple& ft, TcpStreamState& state, const TcpSegment& seg,
                   bool is_client);
    void handleData(const FiveTuple& ft, TcpStreamState& state, const TcpSegment& seg,
                    bool is_client);
    void handleFin(const FiveTuple& ft, TcpStreamState& state, const TcpSegment& seg,
                   bool is_client);
    void handleRst(const FiveTuple& ft, TcpStreamState& state);

    void deliverInOrderData(const FiveTuple& ft, TcpStreamState& state, bool is_client);
    bool isRetransmission(const TcpStreamState& state, const TcpSegment& seg, bool is_client);
    void flushBuffer(const FiveTuple& ft, TcpStreamState& state, bool is_client);
    bool isClient(const FiveTuple& ft, const FiveTuple& canonical_ft);
};

}  // namespace callflow
