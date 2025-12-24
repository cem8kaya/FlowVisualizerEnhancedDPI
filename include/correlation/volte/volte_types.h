#pragma once

#include <string>
#include <vector>
#include <optional>
#include <cstdint>

namespace callflow {
namespace correlation {

/**
 * @brief VoLTE flow type classification
 */
enum class VolteFlowType {
    MO_VOICE_CALL,        // Mobile Originated voice
    MT_VOICE_CALL,        // Mobile Terminated voice
    MO_VIDEO_CALL,        // Mobile Originated video
    MT_VIDEO_CALL,        // Mobile Terminated video
    VOICE_CALL_FORWARDING, // Call with CFU/CFB/CFNR
    CONFERENCE_CALL,      // 3-way conference
    MO_SMS,               // Mobile Originated SMS
    MT_SMS,               // Mobile Terminated SMS
    IMS_REGISTRATION,     // IMS registration
    SUPPLEMENTARY_SERVICE, // USSD, etc.
    DATA_SESSION,         // Non-IMS data (when no SIP)
    UNKNOWN
};

/**
 * @brief Convert VolteFlowType to string
 */
inline const char* toString(VolteFlowType type) {
    switch (type) {
        case VolteFlowType::MO_VOICE_CALL: return "MO_VOICE_CALL";
        case VolteFlowType::MT_VOICE_CALL: return "MT_VOICE_CALL";
        case VolteFlowType::MO_VIDEO_CALL: return "MO_VIDEO_CALL";
        case VolteFlowType::MT_VIDEO_CALL: return "MT_VIDEO_CALL";
        case VolteFlowType::VOICE_CALL_FORWARDING: return "VOICE_CALL_FORWARDING";
        case VolteFlowType::CONFERENCE_CALL: return "CONFERENCE_CALL";
        case VolteFlowType::MO_SMS: return "MO_SMS";
        case VolteFlowType::MT_SMS: return "MT_SMS";
        case VolteFlowType::IMS_REGISTRATION: return "IMS_REGISTRATION";
        case VolteFlowType::SUPPLEMENTARY_SERVICE: return "SUPPLEMENTARY_SERVICE";
        case VolteFlowType::DATA_SESSION: return "DATA_SESSION";
        case VolteFlowType::UNKNOWN: return "UNKNOWN";
        default: return "UNKNOWN";
    }
}

/**
 * @brief Call party in a VoLTE flow
 */
struct VolteParty {
    std::string msisdn;
    std::optional<std::string> imsi;
    std::optional<std::string> imei;
    std::string ip_v4;
    std::string ip_v6_prefix;
    std::string role;  // "UEa", "UEb", "UEc"

    VolteParty() = default;

    VolteParty(const std::string& role_) : role(role_) {}
};

/**
 * @brief Complete VoLTE call flow
 *
 * Represents a correlated VoLTE session that spans multiple protocols:
 * - SIP signaling
 * - Diameter interfaces (Gx, Rx, Cx, Sh)
 * - GTPv2 bearer management
 * - NAS ESM procedures
 * - RTP media streams
 */
struct VolteCallFlow {
    std::string flow_id;
    VolteFlowType type;

    // Call parties
    VolteParty caller;   // UEa
    VolteParty callee;   // UEb
    std::optional<VolteParty> forward_target;  // UEc (for call forwarding)

    // Time window
    double start_time = 0.0;
    double end_time = 0.0;
    uint32_t start_frame = 0;
    uint32_t end_frame = 0;

    // Protocol sessions (intra-correlator IDs)
    std::vector<std::string> sip_sessions;
    std::vector<std::string> diameter_sessions;
    std::vector<std::string> gtpv2_sessions;
    std::vector<std::string> nas_sessions;
    std::vector<uint32_t> rtp_ssrcs;

    // All frames in this flow
    std::vector<uint32_t> frame_numbers;

    // Quality metrics
    struct Stats {
        uint32_t sip_messages = 0;
        uint32_t diameter_messages = 0;
        uint32_t gtp_messages = 0;
        uint32_t nas_messages = 0;
        uint32_t rtp_packets = 0;

        std::optional<double> setup_time_ms;
        std::optional<double> ring_time_ms;
        std::optional<double> call_duration_ms;

        std::optional<double> rtp_jitter_ms;
        std::optional<double> rtp_packet_loss;
        std::optional<double> estimated_mos;
    } stats;

    // Network elements traversed
    std::vector<std::string> network_path;

    VolteCallFlow() : caller("UEa"), callee("UEb") {}
};

} // namespace correlation
} // namespace callflow
