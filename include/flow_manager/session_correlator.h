#pragma once

#include <map>
#include <memory>
#include <nlohmann/json.hpp>
#include <vector>

#include "common/types.h"
#include "flow_manager/flow_tracker.h"

namespace callflow {

/**
 * Session event
 */
struct SessionEvent {
    EventId event_id;
    Timestamp timestamp;
    Direction direction;
    ProtocolType protocol;
    MessageType message_type;
    std::string short_description;
    nlohmann::json details;
    PacketId packet_ref;
};

/**
 * Session information
 */
/**
 * Session information (Flow-based)
 */
struct FlowSession {
    SessionId session_id;
    SessionType type;
    std::string session_key;  // Call-ID, DIAMETER Session-ID, GTP TEID, etc.

    Timestamp start_time;
    Timestamp end_time;

    std::vector<Participant> participants;
    std::vector<SessionEvent> events;

    SessionMetrics metrics;

    // Convert to JSON
    nlohmann::json toJson(bool include_events = true) const;
    nlohmann::json toSummaryJson() const;
};

/**
 * Session correlator - groups packets into sessions
 */
class SessionCorrelator {
public:
    explicit SessionCorrelator(const Config& config);
    ~SessionCorrelator() = default;

    /**
     * Process a packet and correlate it to a session
     */
    void processPacket(const PacketMetadata& packet, ProtocolType protocol,
                       const nlohmann::json& parsed_data);

    /**
     * Get session by ID
     */
    std::shared_ptr<FlowSession> getSession(const SessionId& session_id);

    /**
     * Get all sessions
     */
    std::vector<std::shared_ptr<FlowSession>> getAllSessions() const;

    /**
     * Finalize all sessions (calculate final metrics)
     */
    void finalizeSessions();

    /**
     * Get number of sessions
     */
    size_t getSessionCount() const;

private:
    Config config_;
    mutable std::mutex mutex_;

    std::map<std::string, std::shared_ptr<FlowSession>> sessions_;  // Key: session_key

    std::shared_ptr<FlowSession> getOrCreateSession(const std::string& session_key,
                                                    SessionType type, Timestamp ts);

    SessionType determineSessionType(ProtocolType protocol);
    void addEventToSession(std::shared_ptr<FlowSession> session, const PacketMetadata& packet,
                           ProtocolType protocol, const nlohmann::json& parsed_data);
    void updateMetrics(std::shared_ptr<FlowSession> session, const PacketMetadata& packet);
};

}  // namespace callflow
