#include "correlation/volte/volte_json.h"

#include <algorithm>
#include <chrono>
#include <string>
#include <vector>

#include "common/utils.h"

namespace callflow {
namespace correlation {

nlohmann::json VolteJsonSerializer::partyToJson(const VolteParty& party) {
    nlohmann::json j;

    j["role"] = party.role;

    if (!party.msisdn.empty()) {
        j["msisdn"] = party.msisdn;
    }

    if (party.imsi.has_value() && !party.imsi->empty()) {
        j["imsi"] = *party.imsi;
    }

    if (party.imei.has_value() && !party.imei->empty()) {
        j["imei"] = *party.imei;
    }

    if (!party.ip_v4.empty()) {
        j["ip_v4"] = party.ip_v4;
    }

    if (!party.ip_v6_prefix.empty()) {
        j["ip_v6_prefix"] = party.ip_v6_prefix;
    }

    return j;
}

nlohmann::json VolteJsonSerializer::callFlowToJson(const VolteCallFlow& flow) {
    nlohmann::json j;

    // Basic metadata
    j["flow_id"] = flow.flow_id;
    j["type"] = toString(flow.type);

    // Call parties
    nlohmann::json parties;
    parties["caller"] = partyToJson(flow.caller);
    parties["callee"] = partyToJson(flow.callee);

    if (flow.forward_target.has_value()) {
        parties["forward_target"] = partyToJson(*flow.forward_target);
    }

    j["parties"] = parties;

    auto toTimePoint = [](double ts) {
        return std::chrono::system_clock::time_point(
            std::chrono::duration_cast<std::chrono::system_clock::duration>(
                std::chrono::duration<double>(ts)));
    };

    // Time window
    nlohmann::json time_window;
    time_window["start_time"] = utils::timestampToIso8601(toTimePoint(flow.start_time));
    time_window["end_time"] = utils::timestampToIso8601(toTimePoint(flow.end_time));
    time_window["start_frame"] = flow.start_frame;
    time_window["end_frame"] = flow.end_frame;
    j["time_window"] = time_window;

    // Protocol sessions
    nlohmann::json protocol_sessions;

    if (!flow.sip_sessions.empty()) {
        protocol_sessions["sip"] = flow.sip_sessions;
    }

    nlohmann::json diameter;
    if (!flow.diameter_sessions.empty()) {
        // Separate Diameter sessions by interface type
        std::vector<std::string> gx_sessions;
        std::vector<std::string> rx_sessions;
        std::vector<std::string> cx_sessions;
        std::vector<std::string> sh_sessions;
        std::vector<std::string> other_sessions;

        for (const auto& session_id : flow.diameter_sessions) {
            // Simple heuristic: check if session_id contains interface type
            if (session_id.find("gx") != std::string::npos ||
                session_id.find("Gx") != std::string::npos) {
                gx_sessions.push_back(session_id);
            } else if (session_id.find("rx") != std::string::npos ||
                       session_id.find("Rx") != std::string::npos) {
                rx_sessions.push_back(session_id);
            } else if (session_id.find("cx") != std::string::npos ||
                       session_id.find("Cx") != std::string::npos) {
                cx_sessions.push_back(session_id);
            } else if (session_id.find("sh") != std::string::npos ||
                       session_id.find("Sh") != std::string::npos) {
                sh_sessions.push_back(session_id);
            } else {
                other_sessions.push_back(session_id);
            }
        }

        if (!gx_sessions.empty())
            diameter["gx"] = gx_sessions;
        if (!rx_sessions.empty())
            diameter["rx"] = rx_sessions;
        if (!cx_sessions.empty())
            diameter["cx"] = cx_sessions;
        if (!sh_sessions.empty())
            diameter["sh"] = sh_sessions;
        if (!other_sessions.empty())
            diameter["other"] = other_sessions;

        protocol_sessions["diameter"] = diameter;
    }

    if (!flow.gtpv2_sessions.empty()) {
        protocol_sessions["gtpv2"] = flow.gtpv2_sessions;
    }

    if (!flow.nas_sessions.empty()) {
        protocol_sessions["nas"] = flow.nas_sessions;
    }

    if (!flow.rtp_ssrcs.empty()) {
        protocol_sessions["rtp_ssrcs"] = flow.rtp_ssrcs;
    }

    j["protocol_sessions"] = protocol_sessions;

    // Statistics
    nlohmann::json stats;

    nlohmann::json message_counts;
    message_counts["sip"] = flow.stats.sip_messages;
    message_counts["diameter"] = flow.stats.diameter_messages;
    message_counts["gtp"] = flow.stats.gtp_messages;
    message_counts["nas"] = flow.stats.nas_messages;
    message_counts["rtp"] = flow.stats.rtp_packets;
    stats["message_counts"] = message_counts;

    nlohmann::json timing;
    if (flow.stats.setup_time_ms.has_value()) {
        timing["setup_time_ms"] = *flow.stats.setup_time_ms;
    }
    if (flow.stats.ring_time_ms.has_value()) {
        timing["ring_time_ms"] = *flow.stats.ring_time_ms;
    }
    if (flow.stats.call_duration_ms.has_value()) {
        timing["call_duration_ms"] = *flow.stats.call_duration_ms;
    }
    stats["timing"] = timing;

    nlohmann::json quality;
    if (flow.stats.rtp_jitter_ms.has_value()) {
        quality["rtp_jitter_ms"] = *flow.stats.rtp_jitter_ms;
    }
    if (flow.stats.rtp_packet_loss.has_value()) {
        quality["rtp_packet_loss_percent"] = *flow.stats.rtp_packet_loss;
    }
    if (flow.stats.estimated_mos.has_value()) {
        quality["estimated_mos"] = *flow.stats.estimated_mos;
    }
    stats["quality"] = quality;

    j["statistics"] = stats;

    // Network path
    if (!flow.network_path.empty()) {
        j["network_path"] = flow.network_path;
    }

    // Frame list (can be large, optionally include)
    j["total_frames"] = flow.frame_numbers.size();

    return j;
}

nlohmann::json VolteJsonSerializer::callFlowToTimelineJson(const VolteCallFlow& flow) {
    nlohmann::json timeline;
    timeline["flow_id"] = flow.flow_id;
    timeline["type"] = toString(flow.type);

    // For now, return a placeholder timeline
    // This would require access to the actual protocol message details
    // which are stored in the individual correlators
    nlohmann::json events = nlohmann::json::array();

    auto toTimePoint = [](double ts) {
        return std::chrono::system_clock::time_point(
            std::chrono::duration_cast<std::chrono::system_clock::duration>(
                std::chrono::duration<double>(ts)));
    };

    // Add time window markers
    events.push_back({{"timestamp", utils::timestampToIso8601(toTimePoint(flow.start_time))},
                      {"frame", flow.start_frame},
                      {"event_type", "FLOW_START"},
                      {"description", "VoLTE call flow started"}});

    events.push_back({{"timestamp", utils::timestampToIso8601(toTimePoint(flow.end_time))},
                      {"frame", flow.end_frame},
                      {"event_type", "FLOW_END"},
                      {"description", "VoLTE call flow ended"}});

    timeline["events"] = events;
    timeline["total_events"] = events.size();

    return timeline;
}

nlohmann::json VolteJsonSerializer::callFlowsSummaryToJson(
    const std::vector<VolteCallFlow*>& flows) {
    nlohmann::json summary;

    // Overall counts
    summary["total_flows"] = flows.size();

    // Count by type
    std::map<VolteFlowType, size_t> type_counts;
    for (const auto* flow : flows) {
        type_counts[flow->type]++;
    }

    nlohmann::json by_type;
    for (const auto& [type, count] : type_counts) {
        by_type[toString(type)] = count;
    }
    summary["flows_by_type"] = by_type;

    // Aggregate statistics
    size_t total_sip_messages = 0;
    size_t total_diameter_messages = 0;
    size_t total_gtp_messages = 0;
    size_t total_nas_messages = 0;
    size_t total_rtp_packets = 0;

    double avg_setup_time_ms = 0.0;
    size_t setup_time_count = 0;

    double avg_call_duration_ms = 0.0;
    size_t duration_count = 0;

    double avg_jitter_ms = 0.0;
    size_t jitter_count = 0;

    double avg_packet_loss = 0.0;
    size_t packet_loss_count = 0;

    double avg_mos = 0.0;
    size_t mos_count = 0;

    for (const auto* flow : flows) {
        total_sip_messages += flow->stats.sip_messages;
        total_diameter_messages += flow->stats.diameter_messages;
        total_gtp_messages += flow->stats.gtp_messages;
        total_nas_messages += flow->stats.nas_messages;
        total_rtp_packets += flow->stats.rtp_packets;

        if (flow->stats.setup_time_ms.has_value()) {
            avg_setup_time_ms += *flow->stats.setup_time_ms;
            setup_time_count++;
        }

        if (flow->stats.call_duration_ms.has_value()) {
            avg_call_duration_ms += *flow->stats.call_duration_ms;
            duration_count++;
        }

        if (flow->stats.rtp_jitter_ms.has_value()) {
            avg_jitter_ms += *flow->stats.rtp_jitter_ms;
            jitter_count++;
        }

        if (flow->stats.rtp_packet_loss.has_value()) {
            avg_packet_loss += *flow->stats.rtp_packet_loss;
            packet_loss_count++;
        }

        if (flow->stats.estimated_mos.has_value()) {
            avg_mos += *flow->stats.estimated_mos;
            mos_count++;
        }
    }

    // Calculate averages
    if (setup_time_count > 0) {
        avg_setup_time_ms /= setup_time_count;
    }
    if (duration_count > 0) {
        avg_call_duration_ms /= duration_count;
    }
    if (jitter_count > 0) {
        avg_jitter_ms /= jitter_count;
    }
    if (packet_loss_count > 0) {
        avg_packet_loss /= packet_loss_count;
    }
    if (mos_count > 0) {
        avg_mos /= mos_count;
    }

    nlohmann::json aggregate_stats;
    aggregate_stats["total_sip_messages"] = total_sip_messages;
    aggregate_stats["total_diameter_messages"] = total_diameter_messages;
    aggregate_stats["total_gtp_messages"] = total_gtp_messages;
    aggregate_stats["total_nas_messages"] = total_nas_messages;
    aggregate_stats["total_rtp_packets"] = total_rtp_packets;

    nlohmann::json average_metrics;
    if (setup_time_count > 0) {
        average_metrics["avg_setup_time_ms"] = avg_setup_time_ms;
    }
    if (duration_count > 0) {
        average_metrics["avg_call_duration_ms"] = avg_call_duration_ms;
    }
    if (jitter_count > 0) {
        average_metrics["avg_jitter_ms"] = avg_jitter_ms;
    }
    if (packet_loss_count > 0) {
        average_metrics["avg_packet_loss_percent"] = avg_packet_loss;
    }
    if (mos_count > 0) {
        average_metrics["avg_mos"] = avg_mos;
    }

    summary["aggregate_statistics"] = aggregate_stats;
    summary["average_metrics"] = average_metrics;

    // Time range
    if (!flows.empty()) {
        double earliest = flows[0]->start_time;
        double latest = flows[0]->end_time;

        for (const auto* flow : flows) {
            earliest = std::min(earliest, flow->start_time);
            latest = std::max(latest, flow->end_time);
        }

        auto toTimePoint = [](double ts) {
            return std::chrono::system_clock::time_point(
                std::chrono::duration_cast<std::chrono::system_clock::duration>(
                    std::chrono::duration<double>(ts)));
        };

        summary["time_range"] = {{"start", utils::timestampToIso8601(toTimePoint(earliest))},
                                 {"end", utils::timestampToIso8601(toTimePoint(latest))},
                                 {"duration_seconds", latest - earliest}};
    }

    return summary;
}

}  // namespace correlation
}  // namespace callflow
