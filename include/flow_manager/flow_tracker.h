#pragma once

#include "common/types.h"
#include "protocol_parsers/rtp_parser.h"
#include <unordered_map>
#include <memory>
#include <mutex>

namespace callflow {

/**
 * Flow state information
 */
struct FlowInfo {
    FiveTuple five_tuple;
    ProtocolType protocol;
    Timestamp first_seen;
    Timestamp last_seen;
    uint64_t packet_count;
    uint64_t byte_count;
    Direction direction;

    // Protocol-specific state
    std::string session_key;  // Call-ID, Session-ID, TEID, etc.

    // RTP stream tracking
    std::unique_ptr<RtpStreamTracker> rtp_tracker;
};

/**
 * Flow tracker - maintains state for network flows
 */
class FlowTracker {
public:
    explicit FlowTracker(const Config& config);
    ~FlowTracker() = default;

    /**
     * Update or create flow for a packet
     */
    void updateFlow(const PacketMetadata& packet, ProtocolType protocol);

    /**
     * Get flow information
     */
    std::shared_ptr<FlowInfo> getFlow(const FiveTuple& ft);

    /**
     * Associate a session key (Call-ID, etc.) with a flow
     */
    void setSessionKey(const FiveTuple& ft, const std::string& session_key);

    /**
     * Get all flows for a session key
     */
    std::vector<std::shared_ptr<FlowInfo>> getFlowsBySessionKey(const std::string& session_key);

    /**
     * Clean up expired flows
     */
    size_t cleanupExpiredFlows();

    /**
     * Get total number of active flows
     */
    size_t getFlowCount() const;

    /**
     * Get all flows
     */
    std::vector<std::shared_ptr<FlowInfo>> getAllFlows() const;

private:
    Config config_;
    mutable std::mutex mutex_;

    std::unordered_map<FiveTuple, std::shared_ptr<FlowInfo>> flows_;
    std::unordered_map<std::string, std::vector<FiveTuple>> session_to_flows_;

    bool isFlowExpired(const FlowInfo& flow) const;
};

}  // namespace callflow
