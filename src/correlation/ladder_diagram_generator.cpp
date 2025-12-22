#include "../../include/correlation/ladder_diagram_generator.h"
#include "../../include/common/types.h"
#include "../../include/correlation/procedure_state_machine.h"
#include <algorithm>
#include <random>
#include <sstream>
#include <iomanip>
#include <unordered_set>

namespace flowviz {

LadderDiagramGenerator::LadderDiagramGenerator() {
    participant_detector_ = std::make_unique<ParticipantDetector>();
}

LadderDiagram LadderDiagramGenerator::generate(
    std::vector<callflow::SessionMessageRef> messages,
    const std::string& session_id,
    const std::string& title
) {
    LadderDiagram diagram;
    diagram.session_id = session_id.empty() ? generateUuid() : session_id;
    diagram.title = title.empty() ? "Network Flow Diagram" : title;

    if (messages.empty()) {
        diagram.duration_ms = std::chrono::milliseconds(0);
        return diagram;
    }

    // Sort messages by timestamp
    std::sort(messages.begin(), messages.end(),
        [](const callflow::SessionMessageRef& a, const callflow::SessionMessageRef& b) {
            return a.timestamp < b.timestamp;
        });

    // Set time range
    diagram.start_time = messages.front().timestamp;
    diagram.end_time = messages.back().timestamp;
    diagram.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        messages.back().timestamp - messages.front().timestamp
    );

    // Convert messages to ladder events
    std::vector<LadderEvent> events;
    events.reserve(messages.size());

    for (const auto& msg : messages) {
        // Detect participants
        auto src_participant = participant_detector_->detectParticipant(msg, true);
        auto dst_participant = participant_detector_->detectParticipant(msg, false);

        // Create ladder event
        auto event = createLadderEvent(msg, src_participant.id, dst_participant.id);
        events.push_back(event);
    }

    // Calculate latencies if enabled
    if (calculate_latencies_) {
        calculateLatencies(events);
    }

    // Get unique participants
    auto all_participants = participant_detector_->getAllParticipants();
    diagram.participants = all_participants;

    // Group by procedures if enabled
    if (group_by_procedures_) {
        diagram.procedures = groupEventsByProcedure(events);
    }

    // Calculate metrics
    diagram.metrics = calculateMetrics(events, diagram.procedures);

    diagram.events = std::move(events);

    return diagram;
}

LadderDiagram LadderDiagramGenerator::generateFromSession(
    const callflow::Session& session,
    const std::string& title
) {
    // Get all messages from the session
    std::vector<callflow::SessionMessageRef> messages = session.getAllMessages();

    // Generate title from session type if not provided
    std::string diagram_title = title;
    if (diagram_title.empty()) {
        diagram_title = callflow::enhancedSessionTypeToString(session.session_type);

        // Add IMSI if available
        if (session.correlation_key.imsi.has_value()) {
            diagram_title += " - IMSI: " + session.correlation_key.imsi.value();
        }
    }

    return generate(messages, session.session_id, diagram_title);
}

void LadderDiagramGenerator::addParticipantMapping(
    const std::string& ip,
    const std::string& name,
    ParticipantType type
) {
    participant_detector_->addExplicitMapping(ip, name, type);
}

LadderEvent LadderDiagramGenerator::createLadderEvent(
    const callflow::SessionMessageRef& msg,
    const std::string& from_participant,
    const std::string& to_participant
) {
    LadderEvent event;

    // Generate event ID
    event.event_id = "evt_" + std::to_string(++event_counter_);

    // Set timestamps
    event.timestamp = msg.timestamp;
    event.timestamp_us = std::chrono::duration_cast<std::chrono::microseconds>(
        msg.timestamp.time_since_epoch()
    ).count();

    // Set participants
    event.from_participant = from_participant;
    event.to_participant = to_participant;

    // Set protocol
    event.protocol = msg.protocol;
    event.protocol_name = getProtocolName(msg.protocol);

    // Set message type and name
    event.message_type = msg.message_type;
    event.message = getMessageName(msg.message_type);

    // Identify interface
    event.interface = identifyInterface(msg);

    // Determine direction
    event.direction = determineDirection(msg);

    // Extract details
    if (!msg.parsed_data.empty()) {
        event.details = extractMessageDetails(msg);
    }

    // Set correlation ID
    if (msg.correlation_key.imsi.has_value()) {
        event.correlation_id = msg.correlation_key.imsi.value();
    } else if (msg.correlation_key.sip_call_id.has_value()) {
        event.correlation_id = msg.correlation_key.sip_call_id.value();
    }

    // Store original message ID
    event.message_id = msg.message_id;

    return event;
}

std::string LadderDiagramGenerator::identifyInterface(const callflow::SessionMessageRef& msg) {
    // Get participant types for source and destination
    auto src_info = participant_detector_->getParticipant(msg.src_ip);
    auto dst_info = participant_detector_->getParticipant(msg.dst_ip);

    ParticipantType src_type = src_info.has_value() ? src_info->type : ParticipantType::UNKNOWN;
    ParticipantType dst_type = dst_info.has_value() ? dst_info->type : ParticipantType::UNKNOWN;

    // Check protocol-specific interfaces
    switch (msg.protocol) {
        case callflow::ProtocolType::S1AP:
            return "S1-MME";

        case callflow::ProtocolType::GTP_U:
            if (src_type == ParticipantType::ENODEB || dst_type == ParticipantType::ENODEB) {
                return "S1-U";
            } else if (src_type == ParticipantType::SGW || dst_type == ParticipantType::SGW) {
                return "S5/S8-U";
            }
            return "GTP-U";

        case callflow::ProtocolType::GTP_C:
            return identifyGtpInterface(msg, src_type, dst_type);

        case callflow::ProtocolType::NGAP:
            return "N2";

        case callflow::ProtocolType::PFCP:
            return "N4";

        case callflow::ProtocolType::DIAMETER:
            return identifyDiameterInterface(msg);

        case callflow::ProtocolType::SIP:
        case callflow::ProtocolType::RTP:
        case callflow::ProtocolType::RTCP:
            return "IMS";

        case callflow::ProtocolType::HTTP2:
            // 5G Service Based Architecture
            return "SBI";

        case callflow::ProtocolType::DNS:
            return "DNS";

        case callflow::ProtocolType::DHCP:
            return "DHCP";

        default:
            return "UNKNOWN";
    }
}

std::string LadderDiagramGenerator::identifyGtpInterface(
    const callflow::SessionMessageRef& msg,
    ParticipantType src_type,
    ParticipantType dst_type
) {
    (void)msg; // Suppress unused parameter warning

    // S11: MME <-> S-GW
    if ((src_type == ParticipantType::MME && dst_type == ParticipantType::SGW) ||
        (src_type == ParticipantType::SGW && dst_type == ParticipantType::MME)) {
        return "S11";
    }

    // S5/S8: S-GW <-> P-GW
    if ((src_type == ParticipantType::SGW && dst_type == ParticipantType::PGW) ||
        (src_type == ParticipantType::PGW && dst_type == ParticipantType::SGW)) {
        return "S5/S8";
    }

    // S4: SGSN <-> S-GW (for 2G/3G interworking)
    // Not commonly seen in modern networks

    return "GTP-C";
}

std::string LadderDiagramGenerator::identifyDiameterInterface(const callflow::SessionMessageRef& msg) {
    // Try to extract Application-ID from parsed data
    if (msg.parsed_data.contains("application_id")) {
        uint32_t app_id = msg.parsed_data["application_id"].get<uint32_t>();

        switch (app_id) {
            case 16777251:
                return "S6a";  // MME <-> HSS

            case 16777238:
                return "Gx";   // PCRF <-> P-GW

            case 16777236:
                return "Rx";   // P-CSCF <-> PCRF

            case 16777217:
                return "Sh";   // AS <-> HSS

            case 16777250:
                return "S6d";  // MME <-> HSS (SMS)

            case 16777252:
                return "S13";  // MME <-> EIR

            case 16777272:
                return "Sy";   // PCRF <-> OCS

            default:
                return "DIAMETER";
        }
    }

    return "DIAMETER";
}

MessageDirection LadderDiagramGenerator::determineDirection(const callflow::SessionMessageRef& msg) {
    if (isRequest(msg.message_type)) {
        return MessageDirection::REQUEST;
    } else if (isResponse(msg.message_type)) {
        return MessageDirection::RESPONSE;
    }

    // For indication messages or unknown
    return MessageDirection::INDICATION;
}

bool LadderDiagramGenerator::isRequest(callflow::MessageType msg_type) {
    // List of request message types
    switch (msg_type) {
        // GTP-C Requests
        case callflow::MessageType::GTP_CREATE_SESSION_REQ:
        case callflow::MessageType::GTP_MODIFY_BEARER_REQ:
        case callflow::MessageType::GTP_DELETE_SESSION_REQ:
        case callflow::MessageType::GTP_CREATE_BEARER_REQ:
        case callflow::MessageType::GTP_DELETE_BEARER_REQ:
        case callflow::MessageType::GTP_ECHO_REQ:

        // PFCP Requests
        case callflow::MessageType::PFCP_HEARTBEAT_REQ:
        case callflow::MessageType::PFCP_ASSOCIATION_SETUP_REQ:
        case callflow::MessageType::PFCP_SESSION_ESTABLISHMENT_REQ:
        case callflow::MessageType::PFCP_SESSION_MODIFICATION_REQ:
        case callflow::MessageType::PFCP_SESSION_DELETION_REQ:
        case callflow::MessageType::PFCP_SESSION_REPORT_REQ:

        // Diameter Requests (Command Code with Request bit set)
        case callflow::MessageType::DIAMETER_CCR:
        case callflow::MessageType::DIAMETER_AAR:
        case callflow::MessageType::DIAMETER_RAR:

        // SIP Requests
        case callflow::MessageType::SIP_INVITE:
        case callflow::MessageType::SIP_ACK:
        case callflow::MessageType::SIP_BYE:
        case callflow::MessageType::SIP_CANCEL:
        case callflow::MessageType::SIP_REGISTER:
        case callflow::MessageType::SIP_OPTIONS:
        case callflow::MessageType::SIP_UPDATE:
        case callflow::MessageType::SIP_PRACK:

        // S1AP/NGAP Requests (most are indications, but some are request-like)
        case callflow::MessageType::S1AP_INITIAL_UE_MESSAGE:
        case callflow::MessageType::NGAP_INITIAL_UE_MESSAGE:
            return true;

        default:
            return false;
    }
}

bool LadderDiagramGenerator::isResponse(callflow::MessageType msg_type) {
    // List of response message types
    switch (msg_type) {
        // GTP-C Responses
        case callflow::MessageType::GTP_CREATE_SESSION_RESP:
        case callflow::MessageType::GTP_MODIFY_BEARER_RESP:
        case callflow::MessageType::GTP_DELETE_SESSION_RESP:
        case callflow::MessageType::GTP_CREATE_BEARER_RESP:
        case callflow::MessageType::GTP_DELETE_BEARER_RESP:
        case callflow::MessageType::GTP_ECHO_RESP:

        // PFCP Responses
        case callflow::MessageType::PFCP_HEARTBEAT_RESP:
        case callflow::MessageType::PFCP_ASSOCIATION_SETUP_RESP:
        case callflow::MessageType::PFCP_SESSION_ESTABLISHMENT_RESP:
        case callflow::MessageType::PFCP_SESSION_MODIFICATION_RESP:
        case callflow::MessageType::PFCP_SESSION_DELETION_RESP:
        case callflow::MessageType::PFCP_SESSION_REPORT_RESP:

        // Diameter Responses
        case callflow::MessageType::DIAMETER_CCA:
        case callflow::MessageType::DIAMETER_AAA:
        case callflow::MessageType::DIAMETER_RAA:

        // SIP Responses
        case callflow::MessageType::SIP_TRYING:
        case callflow::MessageType::SIP_RINGING:
            return true;

        default:
            return false;
    }
}

std::optional<callflow::MessageType> LadderDiagramGenerator::getRequestForResponse(callflow::MessageType response_type) {
    // Map responses to their corresponding requests
    switch (response_type) {
        case callflow::MessageType::GTP_CREATE_SESSION_RESP:
            return callflow::MessageType::GTP_CREATE_SESSION_REQ;
        case callflow::MessageType::GTP_MODIFY_BEARER_RESP:
            return callflow::MessageType::GTP_MODIFY_BEARER_REQ;
        case callflow::MessageType::GTP_DELETE_SESSION_RESP:
            return callflow::MessageType::GTP_DELETE_SESSION_REQ;
        case callflow::MessageType::GTP_ECHO_RESP:
            return callflow::MessageType::GTP_ECHO_REQ;

        case callflow::MessageType::PFCP_HEARTBEAT_RESP:
            return callflow::MessageType::PFCP_HEARTBEAT_REQ;
        case callflow::MessageType::PFCP_SESSION_ESTABLISHMENT_RESP:
            return callflow::MessageType::PFCP_SESSION_ESTABLISHMENT_REQ;

        case callflow::MessageType::DIAMETER_CCA:
            return callflow::MessageType::DIAMETER_CCR;
        case callflow::MessageType::DIAMETER_AAA:
            return callflow::MessageType::DIAMETER_AAR;

        case callflow::MessageType::SIP_TRYING:
        case callflow::MessageType::SIP_RINGING:
            // SIP responses can be for multiple request types
            // Would need more context to determine exact request
            return callflow::MessageType::SIP_INVITE;

        default:
            return std::nullopt;
    }
}

void LadderDiagramGenerator::calculateLatencies(std::vector<LadderEvent>& events) {
    // Map to store pending requests: key = correlation_id + message_type
    std::unordered_map<std::string, LadderEvent*> pending_requests;

    for (auto& event : events) {
        if (event.direction == MessageDirection::REQUEST) {
            // Store request for later matching
            std::string key = event.protocol_name + ":" + event.message;
            if (event.correlation_id.has_value()) {
                key = event.correlation_id.value() + ":" + key;
            }
            pending_requests[key] = &event;
        } else if (event.direction == MessageDirection::RESPONSE) {
            // Find matching request
            auto req_type = getRequestForResponse(event.message_type);
            if (req_type.has_value()) {
                std::string req_msg = getMessageName(req_type.value());
                std::string key = event.protocol_name + ":" + req_msg;

                if (event.correlation_id.has_value()) {
                    key = event.correlation_id.value() + ":" + key;
                }

                auto it = pending_requests.find(key);
                if (it != pending_requests.end()) {
                    // Calculate latency
                    auto latency = std::chrono::duration_cast<std::chrono::microseconds>(
                        event.timestamp - it->second->timestamp
                    );
                    event.latency_us = latency.count();

                    // Remove matched request
                    pending_requests.erase(it);
                }
            }
        }
    }
}

std::vector<ProcedureGroup> LadderDiagramGenerator::groupEventsByProcedure(
    const std::vector<LadderEvent>& events
) {
    std::vector<ProcedureGroup> procedures;
    std::unordered_map<std::string, size_t> procedure_map;  // procedure_name -> index

    for (const auto& event : events) {
        if (!event.procedure.has_value()) {
            continue;
        }

        std::string proc_name = event.procedure.value();
        auto it = procedure_map.find(proc_name);

        if (it == procedure_map.end()) {
            // Create new procedure group
            ProcedureGroup proc;
            proc.procedure_id = "proc_" + std::to_string(procedures.size() + 1);
            proc.procedure_name = proc_name;
            proc.start_event_id = event.event_id;
            proc.start_time = event.timestamp;
            proc.total_events = 1;
            proc.success = true;  // Assume success unless we detect failure

            procedures.push_back(proc);
            procedure_map[proc_name] = procedures.size() - 1;
        } else {
            // Update existing procedure
            ProcedureGroup& proc = procedures[it->second];
            proc.end_event_id = event.event_id;
            proc.end_time = event.timestamp;
            proc.total_events++;

            // Calculate duration
            if (proc.end_time.has_value()) {
                proc.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                    proc.end_time.value() - proc.start_time
                );
            }
        }
    }

    return procedures;
}

LadderMetrics LadderDiagramGenerator::calculateMetrics(
    const std::vector<LadderEvent>& events,
    const std::vector<ProcedureGroup>& procedures
) {
    (void)procedures;  // Suppress unused parameter warning

    LadderMetrics metrics;
    metrics.total_events = static_cast<uint32_t>(events.size());

    if (events.empty()) {
        metrics.total_duration = std::chrono::milliseconds(0);
        metrics.average_inter_event = std::chrono::milliseconds(0);
        return metrics;
    }

    // Calculate total duration
    metrics.total_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        events.back().timestamp - events.front().timestamp
    );

    // Calculate average inter-event time
    if (events.size() > 1) {
        uint64_t total_inter_event_us = 0;
        for (size_t i = 1; i < events.size(); ++i) {
            auto diff = std::chrono::duration_cast<std::chrono::microseconds>(
                events[i].timestamp - events[i-1].timestamp
            );
            total_inter_event_us += diff.count();
        }
        uint64_t avg_us = total_inter_event_us / (events.size() - 1);
        metrics.average_inter_event = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::microseconds(avg_us)
        );
    }

    // Collect named latencies
    for (const auto& event : events) {
        if (event.latency_us.has_value()) {
            std::string latency_name = event.protocol_name + "_" + event.message;
            metrics.latencies[latency_name] = event.latency_us.value();
        }
    }

    return metrics;
}

std::string LadderDiagramGenerator::generateUuid() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, 15);
    static std::uniform_int_distribution<> dis2(8, 11);

    std::stringstream ss;
    ss << std::hex;

    for (int i = 0; i < 8; i++) {
        ss << dis(gen);
    }
    ss << "-";

    for (int i = 0; i < 4; i++) {
        ss << dis(gen);
    }
    ss << "-4";  // UUID version 4

    for (int i = 0; i < 3; i++) {
        ss << dis(gen);
    }
    ss << "-";

    ss << dis2(gen);  // UUID variant

    for (int i = 0; i < 3; i++) {
        ss << dis(gen);
    }
    ss << "-";

    for (int i = 0; i < 12; i++) {
        ss << dis(gen);
    }

    return ss.str();
}

nlohmann::json LadderDiagramGenerator::extractMessageDetails(const callflow::SessionMessageRef& msg) {
    // Return a subset of parsed_data that's relevant for the ladder diagram
    nlohmann::json details;

    // Copy relevant fields
    if (msg.parsed_data.contains("imsi")) {
        details["imsi"] = msg.parsed_data["imsi"];
    }
    if (msg.parsed_data.contains("teid")) {
        details["teid"] = msg.parsed_data["teid"];
    }
    if (msg.parsed_data.contains("sequence_number")) {
        details["sequence_number"] = msg.parsed_data["sequence_number"];
    }
    if (msg.parsed_data.contains("apn")) {
        details["apn"] = msg.parsed_data["apn"];
    }
    if (msg.parsed_data.contains("result_code")) {
        details["result_code"] = msg.parsed_data["result_code"];
    }
    if (msg.parsed_data.contains("cause")) {
        details["cause"] = msg.parsed_data["cause"];
    }

    // Include NAS message if present (embedded in S1AP/NGAP)
    if (msg.parsed_data.contains("nas_pdu")) {
        details["nas_pdu"] = msg.parsed_data["nas_pdu"];
    }

    return details.empty() ? msg.parsed_data : details;
}

std::string LadderDiagramGenerator::getMessageName(callflow::MessageType msg_type) {
    return messageTypeToString(msg_type);
}

std::string LadderDiagramGenerator::getProtocolName(callflow::ProtocolType protocol) {
    return protocolTypeToString(protocol);
}

} // namespace flowviz
