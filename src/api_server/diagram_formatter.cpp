#include "api_server/diagram_formatter.h"

#include <algorithm>
#include <iostream>

#include "common/utils.h"

namespace callflow {

const std::unordered_map<uint16_t, std::string> DiagramFormatter::PORT_TO_ELEMENT = {
    {5060, "SIP-Proxy"},     {5061, "SIP-TLS-Proxy"}, {3868, "Diameter-Server"},
    {2123, "GTP-C-Gateway"}, {2152, "GTP-U-Gateway"}, {8805, "PFCP-Function"}};

nlohmann::json DiagramFormatter::toLadderDiagram(const Session& session) {
    nlohmann::json result;

    // Check if SIP-only session
    if (session.session_type == EnhancedSessionType::SIP_SESSION) {
        return generateSipOnlyDiagram(session);
    }

    auto messages = session.getAllMessages();

    // Extract participants
    // result["participants"] is assigned the result of extractParticipants
    auto participants_json = extractParticipants(messages);
    result["participants"] = participants_json;

    // Build IP to participant ID mapping
    std::unordered_map<std::string, std::string> ip_to_id;
    for (const auto& p : participants_json) {
        // Use IP:Port or just IP depending on how we want to match.
        // In extractParticipants I use "ip" and "port" fields.
        // Let's use the same key logic as in extractParticipants: src_ip + ":" + src_port
        std::string key =
            p["ip"].get<std::string>() + ":" + std::to_string(p["port"].get<uint16_t>());
        ip_to_id[key] = p["id"].get<std::string>();
    }

    // Convert events to messages
    nlohmann::json diagram_messages = nlohmann::json::array();
    for (size_t i = 0; i < messages.size(); ++i) {
        auto msg = messageToEvent(messages[i], ip_to_id);
        msg["id"] = "msg" + std::to_string(i);
        diagram_messages.push_back(msg);
    }
    result["messages"] = diagram_messages;

    // Add metadata
    result["metadata"] = {{"session_id", session.session_id},
                          {"type", enhancedSessionTypeToString(session.session_type)},
                          {"start_time", utils::timestampToIso8601(session.start_time)},
                          {"end_time", utils::timestampToIso8601(session.end_time)}};

    return result;
}

nlohmann::json DiagramFormatter::toTimeline(const Session& session) {
    nlohmann::json items = nlohmann::json::array();
    auto messages = session.getAllMessages();

    for (size_t i = 0; i < messages.size(); ++i) {
        const auto& msg = messages[i];
        items.push_back({{"id", i},
                         {"content", messageTypeToString(msg.message_type)},
                         {"start", utils::timestampToIso8601(msg.timestamp)},
                         {"group", interfaceTypeToString(msg.interface)}});
    }
    return {{"items", items}};
}

nlohmann::json DiagramFormatter::toMscDiagram(const correlation::VolteCall& flow) {
    return nlohmann::json::object();
}

std::vector<nlohmann::json> DiagramFormatter::extractParticipants(
    const std::vector<SessionMessageRef>& messages) {
    std::unordered_map<std::string, nlohmann::json> participants;
    int order = 0;

    for (const auto& msg : messages) {
        // Process source
        std::string src_key = msg.src_ip + ":" + std::to_string(msg.src_port);

        if (participants.find(src_key) == participants.end()) {
            std::string type = determineParticipantType(msg.src_ip, msg.src_port,
                                                        protocolTypeToString(msg.protocol));
            std::string label = generateParticipantLabel(msg.src_ip, msg.src_port, type);

            participants[src_key] = {{"id", "p" + std::to_string(order++)},
                                     {"ip", msg.src_ip},
                                     {"port", msg.src_port},
                                     {"label", label},
                                     {"type", type}};
        }

        // Process destination
        std::string dst_key = msg.dst_ip + ":" + std::to_string(msg.dst_port);
        if (participants.find(dst_key) == participants.end()) {
            std::string type = determineParticipantType(msg.dst_ip, msg.dst_port,
                                                        protocolTypeToString(msg.protocol));
            std::string label = generateParticipantLabel(msg.dst_ip, msg.dst_port, type);

            participants[dst_key] = {{"id", "p" + std::to_string(order++)},
                                     {"ip", msg.dst_ip},
                                     {"port", msg.dst_port},
                                     {"label", label},
                                     {"type", type}};
        }
    }

    std::vector<nlohmann::json> result;
    for (auto& [key, p] : participants) {
        result.push_back(p);
    }
    std::sort(result.begin(), result.end(),
              [](const nlohmann::json& a, const nlohmann::json& b) { return a["id"] < b["id"]; });

    return result;
}

std::string DiagramFormatter::determineParticipantType(const std::string& ip, uint16_t port,
                                                       const std::string& protocol) {
    auto it = PORT_TO_ELEMENT.find(port);
    if (it != PORT_TO_ELEMENT.end()) {
        return it->second;
    }

    if (protocol == "SIP") {
        if (port > 10000)
            return "UE";
        return "SIP-Server";
    }

    if (protocol == "RTP" || protocol == "RTCP") {
        return "Media-Endpoint";
    }

    if (protocol == "DIAMETER") {
        return "Diameter-Node";
    }

    if (protocol == "GTP-C" || protocol == "GTP-U") {
        return "GTP-Gateway";
    }

    return "Unknown";
}

std::string DiagramFormatter::generateParticipantLabel(const std::string& ip, uint16_t port,
                                                       const std::string& type) {
    return type + "\\n" + ip;
}

nlohmann::json DiagramFormatter::messageToEvent(
    const SessionMessageRef& msg,
    const std::unordered_map<std::string, std::string>& ip_to_participant) {
    std::string src_key = msg.src_ip + ":" + std::to_string(msg.src_port);
    std::string dst_key = msg.dst_ip + ":" + std::to_string(msg.dst_port);

    std::string from_id = (ip_to_participant.count(src_key)) ? ip_to_participant.at(src_key) : "?";
    std::string to_id = (ip_to_participant.count(dst_key)) ? ip_to_participant.at(dst_key) : "?";

    // Use message type string or protocol
    std::string label = messageTypeToString(msg.message_type);
    if (label == "UNKNOWN" || label.empty()) {
        label = protocolTypeToString(msg.protocol);
    }

    return {{"from", from_id},
            {"to", to_id},
            {"label", label},
            {"protocol", protocolTypeToString(msg.protocol)},
            {"timestamp", utils::timestampToIso8601(msg.timestamp)},
            {"details", msg.parsed_data},
            {"direction", "uni"}};
}

nlohmann::json DiagramFormatter::generateSipOnlyDiagram(const Session& session) {
    nlohmann::json diagram;
    diagram["title"] = "SIP Call Flow";
    diagram["session_id"] = session.session_id;

    // Get all messages (should be SIP messages only)
    auto messages = session.getAllMessages();

    // Extract participants from SIP messages
    std::set<std::pair<std::string, uint16_t>> endpoints;
    for (const auto& msg_ref : messages) {
        endpoints.insert({msg_ref.src_ip, msg_ref.src_port});
        endpoints.insert({msg_ref.dst_ip, msg_ref.dst_port});
    }

    // Create participants
    nlohmann::json participants = nlohmann::json::array();
    int participant_id = 0;
    std::map<std::string, std::string> ip_to_id;

    for (const auto& [ip, port] : endpoints) {
        std::string pid = "p" + std::to_string(participant_id++);
        std::string key = ip + ":" + std::to_string(port);
        ip_to_id[key] = pid;

        nlohmann::json p;
        p["id"] = pid;
        p["label"] = determineSipParticipantLabel(ip, port);
        p["ip"] = ip;
        p["port"] = port;
        p["type"] = determineSipParticipantType(ip, port);
        participants.push_back(p);
    }
    diagram["participants"] = participants;

    // Create messages
    nlohmann::json diagram_messages = nlohmann::json::array();
    for (size_t i = 0; i < messages.size(); ++i) {
        const auto& msg_ref = messages[i];
        auto sip_msg = msg_ref.parsed_data;

        std::string src_key = msg_ref.src_ip + ":" + std::to_string(msg_ref.src_port);
        std::string dst_key = msg_ref.dst_ip + ":" + std::to_string(msg_ref.dst_port);

        nlohmann::json m;
        m["id"] = "msg" + std::to_string(i);
        m["timestamp"] =
            std::chrono::duration_cast<std::chrono::milliseconds>(msg_ref.timestamp.time_since_epoch())
                .count();
        m["from"] = ip_to_id[src_key];
        m["to"] = ip_to_id[dst_key];
        m["protocol"] = "SIP";
        m["type"] = sip_msg.value("method", sip_msg.value("status_code", ""));
        m["label"] = generateSipMessageLabel(sip_msg);
        m["details"] = sip_msg;

        diagram_messages.push_back(m);
    }
    diagram["messages"] = diagram_messages;

    // Add metadata
    if (session.correlation_key.sip_call_id.has_value()) {
        diagram["metadata"] = {{"session_id", session.session_id},
                               {"call_id", session.correlation_key.sip_call_id.value()},
                               {"type", "SIP-Session"},
                               {"start_time", utils::timestampToIso8601(session.start_time)},
                               {"end_time", utils::timestampToIso8601(session.end_time)}};
    } else {
        diagram["metadata"] = {{"session_id", session.session_id},
                               {"type", "SIP-Session"},
                               {"start_time", utils::timestampToIso8601(session.start_time)},
                               {"end_time", utils::timestampToIso8601(session.end_time)}};
    }

    return diagram;
}

std::string DiagramFormatter::determineSipParticipantLabel(const std::string& ip, uint16_t port) {
    // Try to determine role from port or IP pattern
    if (port == 5060 || port == 5061) {
        // Could be proxy, UAC, or UAS
        return "SIP-" + ip.substr(ip.find_last_of('.') + 1);
    }

    // Use last octet of IP
    return "UE-" + ip.substr(ip.find_last_of('.') + 1);
}

std::string DiagramFormatter::determineSipParticipantType(const std::string& ip, uint16_t port) {
    if (port == 5060 || port == 5061) {
        return "proxy";
    }
    return "endpoint";
}

std::string DiagramFormatter::generateSipMessageLabel(const nlohmann::json& sip_msg) {
    if (sip_msg.contains("method")) {
        return sip_msg["method"].get<std::string>();
    } else if (sip_msg.contains("status_code")) {
        std::string label = std::to_string(sip_msg["status_code"].get<int>());
        if (sip_msg.contains("reason_phrase")) {
            label += " " + sip_msg["reason_phrase"].get<std::string>();
        }
        return label;
    }
    return "SIP";
}

}  // namespace callflow
