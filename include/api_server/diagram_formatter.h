#pragma once
#include <nlohmann/json.hpp>
#include <string>
#include <unordered_map>
#include <vector>

#include "correlation/volte_call.h"
#include "session/session_types.h"

namespace callflow {

class DiagramFormatter {
public:
    // Convert session events to ladder diagram format
    static nlohmann::json toLadderDiagram(const Session& session);

    // Convert session events to timeline format
    static nlohmann::json toTimeline(const Session& session);

    // Convert VoLTE call flow to MSC format
    static nlohmann::json toMscDiagram(const correlation::VolteCall& flow);

private:
    // Extract unique participants from events
    static std::vector<nlohmann::json> extractParticipants(
        const std::vector<SessionMessageRef>& messages);

    // Determine participant type (UE, P-CSCF, S-CSCF, HSS, etc.)
    static std::string determineParticipantType(const std::string& ip, uint16_t port,
                                                const std::string& protocol);

    // Generate participant label
    static std::string generateParticipantLabel(const std::string& ip, uint16_t port,
                                                const std::string& type);

    // Convert event to message
    static nlohmann::json messageToEvent(
        const SessionMessageRef& msg,
        const std::unordered_map<std::string, std::string>& ip_to_participant);

    // Generate SIP-only diagram
    static nlohmann::json generateSipOnlyDiagram(const Session& session);

    // Determine SIP participant label
    static std::string determineSipParticipantLabel(const std::string& ip, uint16_t port);

    // Determine SIP participant type
    static std::string determineSipParticipantType(const std::string& ip, uint16_t port);

    // Generate SIP message label
    static std::string generateSipMessageLabel(const nlohmann::json& sip_msg);

    // Port to network element mapping
    static const std::unordered_map<uint16_t, std::string> PORT_TO_ELEMENT;
};

}  // namespace callflow
