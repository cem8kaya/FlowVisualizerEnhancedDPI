#pragma once

#include <map>
#include <optional>
#include <vector>

#include "common/types.h"

namespace callflow {

/**
 * Tracks a TCP stream state
 */
struct TcpStreamState {
    uint32_t next_seq = 0;
    bool syn_seen = false;
    std::map<uint32_t, std::vector<uint8_t>> out_of_order_segments;
    std::chrono::steady_clock::time_point last_update;
};

class TcpReassembler {
public:
    TcpReassembler();

    /**
     * Process a TCP segment.
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
     * Clean up old streams
     */
    void cleanup();

private:
    std::map<FiveTuple, TcpStreamState> streams_;
    uint32_t timeout_sec_ = 120;
};

}  // namespace callflow
