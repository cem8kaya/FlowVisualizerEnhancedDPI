#pragma once

#include "correlation/volte/volte_types.h"
#include <nlohmann/json.hpp>

namespace callflow {
namespace correlation {

/**
 * @brief JSON serialization utilities for VoLTE call flows
 */
class VolteJsonSerializer {
public:
    /**
     * @brief Convert VolteParty to JSON
     */
    static nlohmann::json partyToJson(const VolteParty& party);

    /**
     * @brief Convert VolteCallFlow to JSON
     *
     * Generates the complete JSON representation including:
     * - Flow metadata (ID, type, time window)
     * - Call parties (caller, callee, forward target)
     * - Protocol sessions (SIP, Diameter, GTPv2, NAS, RTP)
     * - Statistics and quality metrics
     */
    static nlohmann::json callFlowToJson(const VolteCallFlow& flow);

    /**
     * @brief Convert VolteCallFlow to timeline JSON
     *
     * Generates a chronological timeline of all events in the call flow.
     * Useful for visualizing the sequence of protocol messages.
     */
    static nlohmann::json callFlowToTimelineJson(const VolteCallFlow& flow);

    /**
     * @brief Convert multiple call flows to summary JSON
     *
     * Generates aggregate statistics for a collection of call flows.
     */
    static nlohmann::json callFlowsSummaryToJson(
        const std::vector<VolteCallFlow*>& flows);

    /**
     * @brief Convert correlation statistics to JSON
     */
    template<typename Stats>
    static nlohmann::json statsToJson(const Stats& stats) {
        nlohmann::json j;
        j["total_call_flows"] = stats.total_call_flows;
        j["voice_calls"] = stats.voice_calls;
        j["video_calls"] = stats.video_calls;
        j["sms_sessions"] = stats.sms_sessions;
        j["registrations"] = stats.registrations;
        j["data_sessions"] = stats.data_sessions;

        j["uncorrelated"] = {
            {"sip_sessions", stats.uncorrelated_sip_sessions},
            {"diameter_sessions", stats.uncorrelated_diameter_sessions},
            {"gtp_sessions", stats.uncorrelated_gtp_sessions},
            {"nas_sessions", stats.uncorrelated_nas_sessions},
            {"rtp_streams", stats.uncorrelated_rtp_streams}
        };

        return j;
    }
};

} // namespace correlation
} // namespace callflow
