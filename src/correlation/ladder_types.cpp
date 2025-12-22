#include "../../include/correlation/ladder_types.h"
#include <sstream>
#include <iomanip>

namespace flowviz {

// Convert ParticipantType to string
std::string toString(ParticipantType type) {
    switch (type) {
        case ParticipantType::UE: return "UE";
        case ParticipantType::ENODEB: return "ENODEB";
        case ParticipantType::GNODEB: return "GNODEB";
        case ParticipantType::MME: return "MME";
        case ParticipantType::AMF: return "AMF";
        case ParticipantType::SGW: return "SGW";
        case ParticipantType::PGW: return "PGW";
        case ParticipantType::UPF: return "UPF";
        case ParticipantType::SMF: return "SMF";
        case ParticipantType::HSS: return "HSS";
        case ParticipantType::UDM: return "UDM";
        case ParticipantType::PCRF: return "PCRF";
        case ParticipantType::PCF: return "PCF";
        case ParticipantType::P_CSCF: return "P_CSCF";
        case ParticipantType::I_CSCF: return "I_CSCF";
        case ParticipantType::S_CSCF: return "S_CSCF";
        case ParticipantType::AS: return "AS";
        case ParticipantType::OCS: return "OCS";
        case ParticipantType::DNS: return "DNS";
        case ParticipantType::DHCP: return "DHCP";
        case ParticipantType::UNKNOWN: return "UNKNOWN";
        default: return "UNKNOWN";
    }
}

std::string participantTypeToString(ParticipantType type) {
    return toString(type);
}

ParticipantType stringToParticipantType(const std::string& str) {
    if (str == "UE") return ParticipantType::UE;
    if (str == "ENODEB") return ParticipantType::ENODEB;
    if (str == "GNODEB") return ParticipantType::GNODEB;
    if (str == "MME") return ParticipantType::MME;
    if (str == "AMF") return ParticipantType::AMF;
    if (str == "SGW") return ParticipantType::SGW;
    if (str == "PGW") return ParticipantType::PGW;
    if (str == "UPF") return ParticipantType::UPF;
    if (str == "SMF") return ParticipantType::SMF;
    if (str == "HSS") return ParticipantType::HSS;
    if (str == "UDM") return ParticipantType::UDM;
    if (str == "PCRF") return ParticipantType::PCRF;
    if (str == "PCF") return ParticipantType::PCF;
    if (str == "P_CSCF") return ParticipantType::P_CSCF;
    if (str == "I_CSCF") return ParticipantType::I_CSCF;
    if (str == "S_CSCF") return ParticipantType::S_CSCF;
    if (str == "AS") return ParticipantType::AS;
    if (str == "OCS") return ParticipantType::OCS;
    if (str == "DNS") return ParticipantType::DNS;
    if (str == "DHCP") return ParticipantType::DHCP;
    return ParticipantType::UNKNOWN;
}

// Convert MessageDirection to string
std::string toString(MessageDirection direction) {
    switch (direction) {
        case MessageDirection::REQUEST: return "REQUEST";
        case MessageDirection::RESPONSE: return "RESPONSE";
        case MessageDirection::INDICATION: return "INDICATION";
        case MessageDirection::BIDIRECTIONAL: return "BIDIRECTIONAL";
        default: return "BIDIRECTIONAL";
    }
}

// Helper to convert timestamp to ISO8601 string
static std::string timestampToIso8601(const std::chrono::system_clock::time_point& tp) {
    auto time_t = std::chrono::system_clock::to_time_t(tp);
    auto microseconds = std::chrono::duration_cast<std::chrono::microseconds>(
        tp.time_since_epoch()) % 1000000;

    std::stringstream ss;
    ss << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%S");
    ss << '.' << std::setfill('0') << std::setw(6) << microseconds.count() << 'Z';
    return ss.str();
}

// ParticipantInfo JSON serialization
nlohmann::json ParticipantInfo::toJson() const {
    nlohmann::json j;
    j["id"] = id;
    j["type"] = toString(type);
    j["ip"] = ip_address;

    if (friendly_name.has_value()) {
        j["friendly_name"] = friendly_name.value();
    }

    if (port.has_value()) {
        j["port"] = port.value();
    }

    return j;
}

// LadderEvent JSON serialization
nlohmann::json LadderEvent::toJson() const {
    nlohmann::json j;
    j["event_id"] = event_id;
    j["timestamp"] = timestampToIso8601(timestamp);
    j["timestamp_us"] = timestamp_us;
    j["from"] = from_participant;
    j["to"] = to_participant;
    j["interface"] = interface;
    j["protocol"] = protocol_name;
    j["message"] = message;
    j["direction"] = toString(direction);

    if (details.has_value()) {
        j["details"] = details.value();
    }

    if (procedure.has_value()) {
        j["procedure"] = procedure.value();
    }

    if (procedure_step.has_value()) {
        j["procedure_step"] = procedure_step.value();
    }

    if (correlation_id.has_value()) {
        j["correlation_id"] = correlation_id.value();
    }

    if (latency_us.has_value()) {
        j["latency_us"] = latency_us.value();
    }

    if (message_id.has_value()) {
        j["message_id"] = message_id.value();
    }

    return j;
}

// ProcedureGroup JSON serialization
nlohmann::json ProcedureGroup::toJson() const {
    nlohmann::json j;
    j["procedure_id"] = procedure_id;
    j["procedure_name"] = procedure_name;
    j["start_event"] = start_event_id;

    if (end_event_id.has_value()) {
        j["end_event"] = end_event_id.value();
    }

    j["start_time"] = timestampToIso8601(start_time);

    if (end_time.has_value()) {
        j["end_time"] = timestampToIso8601(end_time.value());
    }

    j["duration_ms"] = duration.count();
    j["success"] = success;
    j["total_events"] = total_events;

    if (!child_procedure_ids.empty()) {
        j["child_procedures"] = child_procedure_ids;
    }

    return j;
}

// LadderMetrics JSON serialization
nlohmann::json LadderMetrics::toJson() const {
    nlohmann::json j;
    j["total_events"] = total_events;
    j["total_duration_ms"] = total_duration.count();
    j["average_inter_event_ms"] = average_inter_event.count();

    if (!latencies.empty()) {
        nlohmann::json latencies_json;
        for (const auto& [name, value] : latencies) {
            latencies_json[name] = value;
        }
        j["latencies"] = latencies_json;
    }

    return j;
}

// LadderDiagram JSON serialization
nlohmann::json LadderDiagram::toJson() const {
    nlohmann::json j;
    j["diagram_type"] = diagram_type;
    j["title"] = title;
    j["session_id"] = session_id;
    j["start_time"] = timestampToIso8601(start_time);

    if (end_time.has_value()) {
        j["end_time"] = timestampToIso8601(end_time.value());
    }

    j["duration_ms"] = duration_ms.count();

    // Participants
    nlohmann::json participants_json = nlohmann::json::array();
    for (const auto& participant : participants) {
        participants_json.push_back(participant.toJson());
    }
    j["participants"] = participants_json;

    // Events
    nlohmann::json events_json = nlohmann::json::array();
    for (const auto& event : events) {
        events_json.push_back(event.toJson());
    }
    j["events"] = events_json;

    // Procedures
    nlohmann::json procedures_json = nlohmann::json::array();
    for (const auto& procedure : procedures) {
        procedures_json.push_back(procedure.toJson());
    }
    j["procedures"] = procedures_json;

    // Metrics
    j["metrics"] = metrics.toJson();

    return j;
}

} // namespace flowviz
