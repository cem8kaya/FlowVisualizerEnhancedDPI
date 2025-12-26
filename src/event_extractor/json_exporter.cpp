#include "event_extractor/json_exporter.h"

#include <fstream>
#include <numeric>
#include <set>

#include "common/logger.h"
#include "common/types.h"
#include "common/utils.h"
#include "session/session_correlator.h"

namespace callflow {

std::string JsonExporter::exportSession(const Session& session, bool include_events) {
    (void)include_events;  // Currently unused, reserved for future use
    nlohmann::json j = session.toJson();
    return formatJson(j, true);
}

std::string JsonExporter::exportSessions(const std::vector<std::shared_ptr<Session>>& sessions,
                                         bool include_events) {
    (void)include_events;  // Currently unused, reserved for future use
    nlohmann::json j = nlohmann::json::array();

    for (const auto& session : sessions) {
        if (session) {
            j.push_back(session->toJson());
        }
    }

    return formatJson(j, true);
}

std::string JsonExporter::exportSessionSummary(const Session& session) {
    nlohmann::json j = session.toJson();
    return formatJson(j, true);
}

bool JsonExporter::exportToFile(const std::string& filename,
                                const std::vector<std::shared_ptr<Session>>& sessions,
                                bool pretty_print) {
    try {
        nlohmann::json j = nlohmann::json::array();

        for (const auto& session : sessions) {
            if (session) {
                j.push_back(session->toJson());
            }
        }

        std::ofstream file(filename);
        if (!file.is_open()) {
            LOG_ERROR("Failed to open file for writing: " << filename);
            return false;
        }

        nlohmann::json root;
        root["sessions"] = j;

        if (pretty_print) {
            file << root.dump(2);
        } else {
            file << root.dump();
        }

        file.close();

        LOG_INFO("Exported " << sessions.size() << " sessions to " << filename);
        return true;

    } catch (const std::exception& e) {
        LOG_ERROR("Failed to export sessions to file: " << e.what());
        return false;
    }
}

std::string JsonExporter::exportJobResult(const JobId& job_id,
                                          const std::vector<std::shared_ptr<Session>>& sessions,
                                          const nlohmann::json& metadata) {
    nlohmann::json result;

    result["job_id"] = job_id;
    result["status"] = "completed";
    result["timestamp"] = utils::timestampToIso8601(utils::now());
    result["metadata"] = metadata;

    // Session summaries
    nlohmann::json sessions_json = nlohmann::json::array();
    for (const auto& session : sessions) {
        if (session) {
            sessions_json.push_back(session->toJson());
        }
    }
    result["sessions"] = sessions_json;

    result["summary"] = {
        {"total_sessions", sessions.size()},
        {"total_events",
         std::accumulate(sessions.begin(), sessions.end(), 0ULL, [](size_t sum, const auto& s) {
             return sum + (s ? s->total_packets : 0);
         })}};

    return formatJson(result, true);
}

std::string JsonExporter::formatJson(const nlohmann::json& j, bool pretty_print) {
    if (pretty_print) {
        return j.dump(2);
    } else {
        return j.dump();
    }
}

std::string JsonExporter::exportMasterSessions(const EnhancedSessionCorrelator& correlator,
                                               const std::vector<std::string>& /*export_fields*/) {
    auto master_sessions = correlator.getAllMasterSessions();
    nlohmann::json root = nlohmann::json::array();

    for (const auto& [imsi, master] : master_sessions) {
        nlohmann::json j_master;
        j_master["master_id"] = master.master_uuid;
        j_master["session_id"] = master.master_uuid;  // Alias for UI compatibility
        j_master["imsi"] = master.imsi;
        j_master["msisdn"] = master.msisdn;
        j_master["start_time"] = std::chrono::duration_cast<std::chrono::milliseconds>(
                                     master.start_time.time_since_epoch())
                                     .count();

        // Collect Protocols
        std::vector<std::string> protocols;
        if (master.gtp_session_id.has_value())
            protocols.push_back("GTPv2");
        if (!master.sip_session_ids.empty())
            protocols.push_back("SIP");
        if (!master.diameter_session_ids.empty())
            protocols.push_back("DIAMETER");
        j_master["protocols"] = protocols;

        // Collect and Aggregate Events
        std::vector<SessionMessageRef> all_messages;
        std::set<std::string> processed_sessions;

        // Helper to collect messages from a session ID
        auto collect_msgs = [&](const std::string& sid) {
            if (processed_sessions.count(sid))
                return;
            processed_sessions.insert(sid);

            auto session_opt = correlator.getSession(sid);
            if (session_opt) {
                auto msgs = session_opt->getAllMessages();
                all_messages.insert(all_messages.end(), msgs.begin(), msgs.end());
            }
        };

        if (master.gtp_session_id.has_value())
            collect_msgs(master.gtp_session_id.value());
        for (const auto& sid : master.sip_session_ids)
            collect_msgs(sid);
        for (const auto& sid : master.diameter_session_ids)
            collect_msgs(sid);

        // Sort by timestamp
        std::sort(all_messages.begin(), all_messages.end(),
                  [](const SessionMessageRef& a, const SessionMessageRef& b) {
                      return a.timestamp < b.timestamp;
                  });

        // Calculate metrics and participants
        uint64_t total_packets = all_messages.size();
        uint64_t total_bytes = 0;
        std::set<std::string> participants;

        // Convert to JSON
        nlohmann::json j_events = nlohmann::json::array();
        for (const auto& msg : all_messages) {
            total_bytes += msg.payload_length;
            participants.insert(msg.src_ip + ":" + std::to_string(msg.src_port));
            participants.insert(msg.dst_ip + ":" + std::to_string(msg.dst_port));

            nlohmann::json j_event;
            // Basic fields
            j_event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
                                       msg.timestamp.time_since_epoch())
                                       .count();
            j_event["src_ip"] = msg.src_ip;
            j_event["dst_ip"] = msg.dst_ip;
            j_event["src_port"] = msg.src_port;
            j_event["dst_port"] = msg.dst_port;

            // Map Protocol Type to String
            std::string protocol_str;
            switch (msg.protocol) {
                case ProtocolType::GTP_C:
                    protocol_str = "GTPv2-C";
                    break;
                case ProtocolType::GTP_U:
                    protocol_str = "GTPv2-U";
                    break;
                case ProtocolType::SIP:
                    protocol_str = "SIP";
                    break;
                case ProtocolType::DIAMETER:
                    protocol_str = "DIAMETER";
                    break;
                default:
                    protocol_str = "UNKNOWN";
            }
            j_event["proto"] = protocol_str;
            j_event["protocol"] = protocol_str;  // Alias for UI compatibility

            // Message Type
            j_event["type_id"] = static_cast<int>(msg.message_type);
            j_event["message_type"] = messageTypeToString(msg.message_type);
            j_event["short"] = messageTypeToString(msg.message_type);  // Short description

            // Add details
            j_event["details"] = {{"src_ip", msg.src_ip},
                                  {"dst_ip", msg.dst_ip},
                                  {"src_port", msg.src_port},
                                  {"dst_port", msg.dst_port},
                                  {"payload_len", msg.payload_length}};

            j_events.push_back(j_event);
        }

        j_master["events"] = j_events;

        // Add metrics
        // Add metrics
        uint64_t start_time = j_master["start_time"].get<uint64_t>();

        // Calculate end_time
        uint64_t end_time = start_time;
        if (!all_messages.empty()) {
            end_time = std::chrono::duration_cast<std::chrono::milliseconds>(
                           all_messages.back().timestamp.time_since_epoch())
                           .count();
        }

        j_master["end_time"] = end_time;

        // Add duration_ms at top level for UI compatibility
        j_master["duration_ms"] = end_time - start_time;

        j_master["metrics"] = {{"packets", total_packets},
                               {"bytes", total_bytes},
                               {"duration_ms", end_time - start_time}};

        // Add participants
        j_master["participants"] = nlohmann::json::array();
        for (const auto& p : participants) {
            j_master["participants"].push_back(p);
        }

        root.push_back(j_master);
    }

    return formatJson(root, true);
}

std::string JsonExporter::exportAllSessionsWithSipOnly(const EnhancedSessionCorrelator& correlator) {
    LOG_INFO("exportAllSessionsWithSipOnly: START");
    nlohmann::json root = nlohmann::json::array();

    // First, export all master sessions (correlated VoLTE calls)
    LOG_INFO("exportAllSessionsWithSipOnly: Calling getAllMasterSessions()");
    auto master_sessions = correlator.getAllMasterSessions();
    LOG_INFO("exportAllSessionsWithSipOnly: Got " << master_sessions.size() << " master sessions");
    for (const auto& [imsi, master] : master_sessions) {
        nlohmann::json j_master;
        j_master["master_id"] = master.master_uuid;
        j_master["session_id"] = master.master_uuid;
        j_master["imsi"] = master.imsi;
        j_master["msisdn"] = master.msisdn;
        j_master["start_time"] = std::chrono::duration_cast<std::chrono::milliseconds>(
                                     master.start_time.time_since_epoch())
                                     .count();

        // Collect Protocols
        std::vector<std::string> protocols;
        if (master.gtp_session_id.has_value())
            protocols.push_back("GTPV2");
        if (!master.sip_session_ids.empty())
            protocols.push_back("SIP");
        if (!master.diameter_session_ids.empty())
            protocols.push_back("DIAMETER");
        j_master["protocols"] = protocols;

        // Collect and Aggregate Events
        std::vector<SessionMessageRef> all_messages;
        std::set<std::string> processed_sessions;

        auto collect_msgs = [&](const std::string& sid) {
            if (processed_sessions.count(sid))
                return;
            processed_sessions.insert(sid);

            LOG_DEBUG("exportAllSessionsWithSipOnly: collect_msgs calling getSession(" << sid << ")");
            auto session_opt = correlator.getSession(sid);
            if (session_opt) {
                auto msgs = session_opt->getAllMessages();
                all_messages.insert(all_messages.end(), msgs.begin(), msgs.end());
                LOG_DEBUG("exportAllSessionsWithSipOnly: Got " << msgs.size() << " messages from session " << sid);
            }
        };

        LOG_DEBUG("exportAllSessionsWithSipOnly: Processing master session for IMSI " << imsi);
        if (master.gtp_session_id.has_value())
            collect_msgs(master.gtp_session_id.value());
        for (const auto& sid : master.sip_session_ids)
            collect_msgs(sid);
        for (const auto& sid : master.diameter_session_ids)
            collect_msgs(sid);
        LOG_DEBUG("exportAllSessionsWithSipOnly: Finished collecting messages for IMSI " << imsi);

        // Sort by timestamp
        std::sort(all_messages.begin(), all_messages.end(),
                  [](const SessionMessageRef& a, const SessionMessageRef& b) {
                      return a.timestamp < b.timestamp;
                  });

        // Calculate metrics
        uint64_t total_packets = all_messages.size();
        uint64_t total_bytes = 0;
        std::set<std::string> participants;

        nlohmann::json j_events = nlohmann::json::array();
        for (const auto& msg : all_messages) {
            total_bytes += msg.payload_length;
            participants.insert(msg.src_ip + ":" + std::to_string(msg.src_port));
            participants.insert(msg.dst_ip + ":" + std::to_string(msg.dst_port));

            nlohmann::json j_event;
            j_event["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
                                       msg.timestamp.time_since_epoch())
                                       .count();
            j_event["src_ip"] = msg.src_ip;
            j_event["dst_ip"] = msg.dst_ip;
            j_event["src_port"] = msg.src_port;
            j_event["dst_port"] = msg.dst_port;

            std::string protocol_str;
            switch (msg.protocol) {
                case ProtocolType::GTP_C:
                    protocol_str = "GTPv2-C";
                    break;
                case ProtocolType::GTP_U:
                    protocol_str = "GTPv2-U";
                    break;
                case ProtocolType::SIP:
                    protocol_str = "SIP";
                    break;
                case ProtocolType::DIAMETER:
                    protocol_str = "DIAMETER";
                    break;
                default:
                    protocol_str = "UNKNOWN";
            }
            j_event["proto"] = protocol_str;
            j_event["protocol"] = protocol_str;
            j_event["type_id"] = static_cast<int>(msg.message_type);
            j_event["message_type"] = messageTypeToString(msg.message_type);
            j_event["short"] = messageTypeToString(msg.message_type);
            j_event["details"] = {{"src_ip", msg.src_ip},
                                  {"dst_ip", msg.dst_ip},
                                  {"src_port", msg.src_port},
                                  {"dst_port", msg.dst_port},
                                  {"payload_len", msg.payload_length}};
            j_events.push_back(j_event);
        }

        j_master["events"] = j_events;

        uint64_t start_time = j_master["start_time"].get<uint64_t>();
        uint64_t end_time = start_time;
        if (!all_messages.empty()) {
            end_time = std::chrono::duration_cast<std::chrono::milliseconds>(
                           all_messages.back().timestamp.time_since_epoch())
                           .count();
        }

        j_master["end_time"] = end_time;
        j_master["duration_ms"] = end_time - start_time;
        j_master["metrics"] = {{"packets", total_packets},
                               {"bytes", total_bytes},
                               {"duration_ms", end_time - start_time}};

        j_master["participants"] = nlohmann::json::array();
        for (const auto& p : participants) {
            j_master["participants"].push_back(p);
        }

        root.push_back(j_master);
    }

    LOG_INFO("exportAllSessionsWithSipOnly: Finished processing " << master_sessions.size() << " master sessions");
    // Now export SIP-only sessions (standalone SIP without GTP correlation)
    LOG_INFO("exportAllSessionsWithSipOnly: Calling exportAllSessions() - THIS MAY DEADLOCK!");
    auto all_sessions_json = correlator.exportAllSessions();
    LOG_INFO("exportAllSessionsWithSipOnly: exportAllSessions() completed successfully");
    if (all_sessions_json.contains("sip_only") && all_sessions_json["sip_only"].is_array()) {
        for (const auto& sip_session : all_sessions_json["sip_only"]) {
            nlohmann::json j_sip;

            // Use call_id as session identifier
            std::string call_id = sip_session.value("call_id", "");
            std::string session_id = sip_session.value("session_id", call_id);

            j_sip["session_id"] = session_id;
            j_sip["master_id"] = session_id;  // For compatibility
            j_sip["imsi"] = "";  // SIP-only sessions don't have IMSI
            j_sip["msisdn"] = sip_session.value("caller_msisdn", "");
            j_sip["call_id"] = call_id;
            j_sip["session_type"] = "SIP_ONLY";

            // Protocols - SIP only
            j_sip["protocols"] = nlohmann::json::array({"SIP"});

            // Timestamps
            j_sip["start_time"] = sip_session.value("start_time", 0);
            j_sip["end_time"] = sip_session.value("end_time", 0);

            uint64_t start_ms = j_sip["start_time"].get<uint64_t>();
            uint64_t end_ms = j_sip["end_time"].get<uint64_t>();
            j_sip["duration_ms"] = (end_ms > start_ms) ? (end_ms - start_ms) : 0;

            // Copy events if available
            if (sip_session.contains("events")) {
                j_sip["events"] = sip_session["events"];
            } else if (sip_session.contains("messages")) {
                // Convert messages to events format
                nlohmann::json events = nlohmann::json::array();
                for (const auto& msg : sip_session["messages"]) {
                    nlohmann::json event;
                    event["timestamp"] = msg.value("timestamp", 0);
                    event["proto"] = "SIP";
                    event["protocol"] = "SIP";

                    // Determine message type
                    if (msg.value("is_request", true)) {
                        event["message_type"] = "SIP_" + msg.value("method", "UNKNOWN");
                        event["short"] = msg.value("method", "UNKNOWN");
                    } else {
                        int status = msg.value("status_code", 0);
                        event["message_type"] = "SIP_" + std::to_string(status);
                        event["short"] = std::to_string(status) + " " + msg.value("reason_phrase", "");
                    }

                    events.push_back(event);
                }
                j_sip["events"] = events;
            } else {
                j_sip["events"] = nlohmann::json::array();
            }

            // Metrics
            size_t event_count = j_sip["events"].size();
            j_sip["metrics"] = {{"packets", event_count},
                                {"bytes", 0},
                                {"duration_ms", j_sip["duration_ms"]}};

            // Participants from caller/callee
            j_sip["participants"] = nlohmann::json::array();
            if (sip_session.contains("caller_ip") && !sip_session["caller_ip"].get<std::string>().empty()) {
                j_sip["participants"].push_back(sip_session["caller_ip"].get<std::string>());
            }
            if (sip_session.contains("callee_ip") && !sip_session["callee_ip"].get<std::string>().empty()) {
                j_sip["participants"].push_back(sip_session["callee_ip"].get<std::string>());
            }

            root.push_back(j_sip);
        }
    }

    return formatJson(root, true);
}

}  // namespace callflow
