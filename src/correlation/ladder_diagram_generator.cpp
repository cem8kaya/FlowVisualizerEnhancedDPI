#include "../../include/correlation/ladder_diagram_generator.h"
#include "../../include/common/message_type_names.h"
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
    std::vector<SessionMessageRef> messages,
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
        [](const SessionMessageRef& a, const SessionMessageRef& b) {
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
    const Session& session,
    const std::string& title
) {
    // Get all messages from the session
    std::vector<SessionMessageRef> messages = session.getAllMessages();

    // Generate title from session type if not provided
    std::string diagram_title = title;
    if (diagram_title.empty()) {
        diagram_title = sessionTypeToString(session.session_type);

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
    const SessionMessageRef& msg,
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

    // Set procedure information from correlation key
    if (msg.correlation_key.procedure_type.has_value()) {
        event.procedure = procedureTypeToString(msg.correlation_key.procedure_type.value());
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

std::string LadderDiagramGenerator::identifyInterface(const SessionMessageRef& msg) {
    // Get participant types for source and destination
    auto src_info = participant_detector_->getParticipant(msg.src_ip);
    auto dst_info = participant_detector_->getParticipant(msg.dst_ip);

    ParticipantType src_type = src_info.has_value() ? src_info->type : ParticipantType::UNKNOWN;
    ParticipantType dst_type = dst_info.has_value() ? dst_info->type : ParticipantType::UNKNOWN;

    // Check protocol-specific interfaces
    switch (msg.protocol) {
        case ProtocolType::S1AP:
            return "S1-MME";

        case ProtocolType::GTP_U:
            if (src_type == ParticipantType::ENODEB || dst_type == ParticipantType::ENODEB) {
                return "S1-U";
            } else if (src_type == ParticipantType::SGW || dst_type == ParticipantType::SGW) {
                return "S5/S8-U";
            }
            return "GTP-U";

        case ProtocolType::GTP_C:
            return identifyGtpInterface(msg, src_type, dst_type);

        case ProtocolType::NGAP:
            return "N2";

        case ProtocolType::PFCP:
            return "N4";

        case ProtocolType::DIAMETER:
            return identifyDiameterInterface(msg);

        case ProtocolType::SIP:
        case ProtocolType::RTP:
        case ProtocolType::RTCP:
            return "IMS";

        case ProtocolType::HTTP2:
            // 5G Service Based Architecture
            return "SBI";

        case ProtocolType::DNS:
            return "DNS";

        case ProtocolType::DHCP:
            return "DHCP";

        default:
            return "UNKNOWN";
    }
}

std::string LadderDiagramGenerator::identifyGtpInterface(
    const SessionMessageRef& msg,
    ParticipantType src_type,
    ParticipantType dst_type
) {
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

std::string LadderDiagramGenerator::identifyDiameterInterface(const SessionMessageRef& msg) {
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

MessageDirection LadderDiagramGenerator::determineDirection(const SessionMessageRef& msg) {
    if (isRequest(msg.message_type)) {
        return MessageDirection::REQUEST;
    } else if (isResponse(msg.message_type)) {
        return MessageDirection::RESPONSE;
    }

    // For indication messages or unknown
    return MessageDirection::INDICATION;
}

bool LadderDiagramGenerator::isRequest(MessageType msg_type) {
    // List of request message types
    switch (msg_type) {
        // GTP-C Requests
        case MessageType::GTP_CREATE_SESSION_REQUEST:
        case MessageType::GTP_MODIFY_BEARER_REQUEST:
        case MessageType::GTP_DELETE_SESSION_REQUEST:
        case MessageType::GTP_CREATE_BEARER_REQUEST:
        case MessageType::GTP_DELETE_BEARER_REQUEST:
        case MessageType::GTP_ECHO_REQUEST:

        // PFCP Requests
        case MessageType::PFCP_HEARTBEAT_REQUEST:
        case MessageType::PFCP_ASSOCIATION_SETUP_REQUEST:
        case MessageType::PFCP_ASSOCIATION_UPDATE_REQUEST:
        case MessageType::PFCP_ASSOCIATION_RELEASE_REQUEST:
        case MessageType::PFCP_SESSION_ESTABLISHMENT_REQUEST:
        case MessageType::PFCP_SESSION_MODIFICATION_REQUEST:
        case MessageType::PFCP_SESSION_DELETION_REQUEST:
        case MessageType::PFCP_SESSION_REPORT_REQUEST:

        // Diameter Requests (Command Code with Request bit set)
        case MessageType::DIAMETER_CCR:
        case MessageType::DIAMETER_AAR:
        case MessageType::DIAMETER_RAR:

        // SIP Requests
        case MessageType::SIP_INVITE:
        case MessageType::SIP_ACK:
        case MessageType::SIP_BYE:
        case MessageType::SIP_CANCEL:
        case MessageType::SIP_REGISTER:
        case MessageType::SIP_OPTIONS:
        case MessageType::SIP_UPDATE:
        case MessageType::SIP_PRACK:
        case MessageType::SIP_INFO:
        case MessageType::SIP_SUBSCRIBE:
        case MessageType::SIP_NOTIFY:

        // S1AP/NGAP Requests (most are indications, but some are request-like)
        case MessageType::S1AP_INITIAL_UE_MESSAGE:
        case MessageType::NGAP_INITIAL_UE_MESSAGE:
            return true;

        default:
            return false;
    }
}

bool LadderDiagramGenerator::isResponse(MessageType msg_type) {
    // List of response message types
    switch (msg_type) {
        // GTP-C Responses
        case MessageType::GTP_CREATE_SESSION_RESPONSE:
        case MessageType::GTP_MODIFY_BEARER_RESPONSE:
        case MessageType::GTP_DELETE_SESSION_RESPONSE:
        case MessageType::GTP_CREATE_BEARER_RESPONSE:
        case MessageType::GTP_DELETE_BEARER_RESPONSE:
        case MessageType::GTP_ECHO_RESPONSE:

        // PFCP Responses
        case MessageType::PFCP_HEARTBEAT_RESPONSE:
        case MessageType::PFCP_ASSOCIATION_SETUP_RESPONSE:
        case MessageType::PFCP_ASSOCIATION_UPDATE_RESPONSE:
        case MessageType::PFCP_ASSOCIATION_RELEASE_RESPONSE:
        case MessageType::PFCP_SESSION_ESTABLISHMENT_RESPONSE:
        case MessageType::PFCP_SESSION_MODIFICATION_RESPONSE:
        case MessageType::PFCP_SESSION_DELETION_RESPONSE:
        case MessageType::PFCP_SESSION_REPORT_RESPONSE:

        // Diameter Responses
        case MessageType::DIAMETER_CCA:
        case MessageType::DIAMETER_AAA:
        case MessageType::DIAMETER_RAA:

        // SIP Responses
        case MessageType::SIP_100_TRYING:
        case MessageType::SIP_180_RINGING:
        case MessageType::SIP_183_SESSION_PROGRESS:
        case MessageType::SIP_200_OK:
        case MessageType::SIP_486_BUSY_HERE:
        case MessageType::SIP_487_REQUEST_TERMINATED:
        case MessageType::SIP_603_DECLINE:
            return true;

        default:
            return false;
    }
}

std::optional<MessageType> LadderDiagramGenerator::getRequestForResponse(MessageType response_type) {
    // Map responses to their corresponding requests
    switch (response_type) {
        case MessageType::GTP_CREATE_SESSION_RESPONSE:
            return MessageType::GTP_CREATE_SESSION_REQUEST;
        case MessageType::GTP_MODIFY_BEARER_RESPONSE:
            return MessageType::GTP_MODIFY_BEARER_REQUEST;
        case MessageType::GTP_DELETE_SESSION_RESPONSE:
            return MessageType::GTP_DELETE_SESSION_REQUEST;
        case MessageType::GTP_ECHO_RESPONSE:
            return MessageType::GTP_ECHO_REQUEST;

        case MessageType::PFCP_HEARTBEAT_RESPONSE:
            return MessageType::PFCP_HEARTBEAT_REQUEST;
        case MessageType::PFCP_SESSION_ESTABLISHMENT_RESPONSE:
            return MessageType::PFCP_SESSION_ESTABLISHMENT_REQUEST;

        case MessageType::DIAMETER_CCA:
            return MessageType::DIAMETER_CCR;
        case MessageType::DIAMETER_AAA:
            return MessageType::DIAMETER_AAR;

        case MessageType::SIP_200_OK:
        case MessageType::SIP_100_TRYING:
        case MessageType::SIP_180_RINGING:
        case MessageType::SIP_183_SESSION_PROGRESS:
            // SIP responses can be for multiple request types
            // Would need more context to determine exact request
            return MessageType::SIP_INVITE;

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

nlohmann::json LadderDiagramGenerator::extractMessageDetails(const SessionMessageRef& msg) {
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

std::string LadderDiagramGenerator::getMessageName(MessageType msg_type) {
    return messageTypeToString(msg_type);
}

std::string LadderDiagramGenerator::getProtocolName(ProtocolType protocol) {
    return protocolTypeToString(protocol);
}

} // namespace flowviz
