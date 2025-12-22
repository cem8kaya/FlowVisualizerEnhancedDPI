#ifndef PARTICIPANT_DETECTOR_H
#define PARTICIPANT_DETECTOR_H

#include <string>
#include <unordered_map>
#include <memory>
#include <optional>
#include "ladder_types.h"
#include "../session/session_types.h"
#include "../common/types.h"

namespace flowviz {

/**
 * Detects network participants from IP addresses and protocol patterns
 *
 * Uses heuristics to identify network entities:
 * - UE: Source of S1AP Initial UE Message, SIP REGISTER from device
 * - eNodeB: S1AP connection on port 36412
 * - gNodeB: NGAP connection on port 38412
 * - MME: Receives S1AP, sends GTPv2-C on S11
 * - AMF: Receives NGAP, makes HTTP/2 SBI calls
 * - S-GW: GTPv2-C on S11 and S5/S8
 * - P-GW: GTPv2-C on S5/S8, Diameter Gx to PCRF
 * - HSS: Diameter S6a responder
 * - PCRF: Diameter Gx responder
 * - P-CSCF: First SIP hop from UE
 */
class ParticipantDetector {
public:
    ParticipantDetector();

    /**
     * Detect participant from a message
     * @param msg Session message
     * @param is_source True if detecting source participant, false for destination
     * @return Detected participant info
     */
    ParticipantInfo detectParticipant(
        const SessionMessageRef& msg,
        bool is_source
    );

    /**
     * Add explicit IP-to-participant mapping
     * @param ip IP address
     * @param name Friendly name
     * @param type Participant type
     */
    void addExplicitMapping(
        const std::string& ip,
        const std::string& name,
        ParticipantType type
    );

    /**
     * Add explicit IP-to-participant mapping with port
     * @param ip IP address
     * @param port Port number
     * @param name Friendly name
     * @param type Participant type
     */
    void addExplicitMappingWithPort(
        const std::string& ip,
        uint16_t port,
        const std::string& name,
        ParticipantType type
    );

    /**
     * Get participant by IP address (if already detected)
     */
    std::optional<ParticipantInfo> getParticipant(const std::string& ip) const;

    /**
     * Get all detected participants
     */
    std::vector<ParticipantInfo> getAllParticipants() const;

    /**
     * Clear all detected participants
     */
    void clear();

private:
    // IP address -> ParticipantInfo mapping
    std::unordered_map<std::string, ParticipantInfo> ip_to_participant_;

    // IP:Port -> ParticipantInfo mapping (for cases where port matters)
    std::unordered_map<std::string, ParticipantInfo> ip_port_to_participant_;

    // Detect participant type from protocol and port
    ParticipantType detectTypeFromProtocol(
        const SessionMessageRef& msg,
        bool is_source
    );

    // Detect participant type from message type
    ParticipantType detectTypeFromMessageType(
        const SessionMessageRef& msg,
        bool is_source
    );

    // Detect participant type from Diameter Application-ID
    ParticipantType detectTypeFromDiameter(
        const SessionMessageRef& msg,
        bool is_source
    );

    // Generate participant ID
    std::string generateParticipantId(
        ParticipantType type,
        const std::string& ip,
        uint16_t port
    );

    // Create key for IP:port combination
    std::string makeIpPortKey(const std::string& ip, uint16_t port) const {
        return ip + ":" + std::to_string(port);
    }

    // Extract Diameter Application-ID from message details
    std::optional<uint32_t> extractDiameterAppId(const SessionMessageRef& msg) const;

    // Counters for generating unique IDs
    std::unordered_map<ParticipantType, uint32_t> type_counters_;
};

} // namespace flowviz

#endif // PARTICIPANT_DETECTOR_H
