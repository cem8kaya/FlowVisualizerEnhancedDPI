#ifndef LADDER_DIAGRAM_GENERATOR_H
#define LADDER_DIAGRAM_GENERATOR_H

#include <vector>
#include <memory>
#include <string>
#include <unordered_map>
#include "ladder_types.h"
#include "participant_detector.h"
#include "../session/session_types.h"

namespace flowviz {

/**
 * Generates ladder diagrams from session messages
 *
 * Creates strictly time-ordered, multi-participant visualizations that show
 * message flows across ALL protocols and interfaces.
 *
 * Features:
 * - Global timestamp ordering (microsecond precision)
 * - Auto-detect participants from IP addresses and protocols
 * - Identify 3GPP interfaces (S1-MME, S11, S6a, etc.)
 * - Calculate request-response latencies
 * - Group events by procedure
 * - Generate JSON for D3.js visualization
 */
class LadderDiagramGenerator {
public:
    LadderDiagramGenerator();

    /**
     * Generate ladder diagram from session messages
     * @param messages Vector of session messages (will be sorted by timestamp)
     * @param session_id Optional session ID
     * @param title Optional diagram title
     * @return Complete ladder diagram
     */
    LadderDiagram generate(
        std::vector<callflow::SessionMessageRef> messages,
        const std::string& session_id = "",
        const std::string& title = ""
    );

    /**
     * Generate ladder diagram from a Session object
     * @param session Session object containing all messages
     * @param title Optional diagram title (defaults to session type)
     * @return Complete ladder diagram
     */
    LadderDiagram generateFromSession(
        const callflow::Session& session,
        const std::string& title = ""
    );

    /**
     * Add explicit participant mapping
     */
    void addParticipantMapping(
        const std::string& ip,
        const std::string& name,
        ParticipantType type
    );

    /**
     * Set whether to calculate latencies
     */
    void setCalculateLatencies(bool calculate) {
        calculate_latencies_ = calculate;
    }

    /**
     * Set whether to group by procedures
     */
    void setGroupByProcedures(bool group) {
        group_by_procedures_ = group;
    }

private:
    std::unique_ptr<ParticipantDetector> participant_detector_;
    bool calculate_latencies_ = true;
    bool group_by_procedures_ = true;

    // Convert SessionMessageRef to LadderEvent
    LadderEvent createLadderEvent(
        const callflow::SessionMessageRef& msg,
        const std::string& from_participant,
        const std::string& to_participant
    );

    // Identify 3GPP interface from message
    std::string identifyInterface(const callflow::SessionMessageRef& msg);

    // Identify interface from GTP message
    std::string identifyGtpInterface(
        const callflow::SessionMessageRef& msg,
        ParticipantType src_type,
        ParticipantType dst_type
    );

    // Identify interface from Diameter message
    std::string identifyDiameterInterface(const callflow::SessionMessageRef& msg);

    // Determine message direction
    MessageDirection determineDirection(const callflow::SessionMessageRef& msg);

    // Check if message is a request
    bool isRequest(callflow::MessageType msg_type);

    // Check if message is a response
    bool isResponse(callflow::MessageType msg_type);

    // Get request type for a response
    std::optional<callflow::MessageType> getRequestForResponse(callflow::MessageType response_type);

    // Calculate latencies between request-response pairs
    void calculateLatencies(std::vector<LadderEvent>& events);

    // Group events by procedure
    std::vector<ProcedureGroup> groupEventsByProcedure(
        const std::vector<LadderEvent>& events
    );

    // Calculate metrics
    LadderMetrics calculateMetrics(
        const std::vector<LadderEvent>& events,
        const std::vector<ProcedureGroup>& procedures
    );

    // Generate UUID
    std::string generateUuid();

    // Extract details from message for JSON
    nlohmann::json extractMessageDetails(const callflow::SessionMessageRef& msg);

    // Get human-readable message name
    std::string getMessageName(callflow::MessageType msg_type);

    // Get human-readable protocol name
    std::string getProtocolName(callflow::ProtocolType protocol);

    // Counter for event IDs
    uint64_t event_counter_ = 0;
};

} // namespace flowviz

#endif // LADDER_DIAGRAM_GENERATOR_H
