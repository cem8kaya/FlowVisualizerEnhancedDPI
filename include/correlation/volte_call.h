#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "correlation/volte_subscriber_context.h"
#include "protocol_parsers/diameter_parser.h"
#include "protocol_parsers/gtp_parser.h"
#include "protocol_parsers/rtp_parser.h"
#include "protocol_parsers/sip_parser.h"
#include "session/session_types.h"

namespace callflow {
namespace correlation {

/**
 * @brief Represents a complete VoLTE call with all protocol legs correlated
 *
 * A VoLTE call involves multiple protocol interactions:
 * - SIP signaling (INVITE/200 OK/ACK/BYE) via P-CSCF
 * - DIAMETER Rx (P-CSCF → PCRF for QoS authorization)
 * - DIAMETER Gx (PCRF → PGW for policy control)
 * - GTP-C bearer management (dedicated QCI-1 bearer for voice)
 * - RTP media streams (audio over dedicated bearer)
 *
 * This structure correlates all these legs into a unified call view.
 */
struct VolteCall {
    // Primary identifiers
    std::string call_id;  ///< SIP Call-ID (primary key)
    std::string icid;     ///< IMS Charging ID (from P-Charging-Vector)

    // Subscriber identifiers
    std::string imsi;            ///< International Mobile Subscriber Identity
    std::string msisdn;          ///< Mobile phone number
    std::string calling_number;  ///< Calling party (from P-Asserted-Identity)
    std::string called_number;   ///< Called party (from Request-URI or To header)

    /**
     * @brief Call state tracking
     */
    enum class State {
        INITIATING,    ///< SIP INVITE sent
        TRYING,        ///< SIP 100 Trying received
        RINGING,       ///< SIP 180 Ringing received
        ANSWERED,      ///< SIP 200 OK received
        CONFIRMED,     ///< SIP ACK sent
        MEDIA_ACTIVE,  ///< RTP packets detected
        TERMINATING,   ///< SIP BYE sent/received
        COMPLETED,     ///< Call successfully completed
        FAILED,        ///< Call failed (4xx/5xx/6xx response)
        CANCELLED      ///< Call cancelled (CANCEL)
    };
    State state = State::INITIATING;
    std::string state_reason;  ///< Human-readable state reason (e.g., "486 Busy Here")

    /**
     * @brief SIP signaling leg
     */
    struct SipLeg {
        std::string session_id;  ///< Internal session ID
        std::string call_id;     ///< SIP Call-ID
        std::string from_uri;    ///< From header URI
        std::string to_uri;      ///< To header URI
        std::string p_cscf_ip;   ///< P-CSCF address

        // Timing milestones
        std::chrono::system_clock::time_point invite_time;
        std::optional<std::chrono::system_clock::time_point> trying_time;
        std::optional<std::chrono::system_clock::time_point> ringing_time;
        std::optional<std::chrono::system_clock::time_point> answer_time;
        std::optional<std::chrono::system_clock::time_point> ack_time;
        std::optional<std::chrono::system_clock::time_point> bye_time;

        // Media parameters (from SDP)
        std::string audio_codec;       ///< Codec name (e.g., "AMR", "AMR-WB")
        uint16_t rtp_port_local = 0;   ///< UE RTP port
        uint16_t rtp_port_remote = 0;  ///< Remote RTP port
        std::string remote_ip;         ///< Remote media IP

        nlohmann::json toJson() const;
    };
    SipLeg sip_leg;

    /**
     * @brief DIAMETER Rx leg (P-CSCF → PCRF media authorization)
     */
    struct RxLeg {
        std::string session_id;  ///< Diameter Session-Id AVP
        std::string af_app_id;   ///< AF-Application-Identifier (IMS signaling)
        std::string framed_ip;   ///< UE IP address (Framed-IP-Address AVP)

        std::chrono::system_clock::time_point aar_time;
        std::optional<std::chrono::system_clock::time_point> aaa_time;

        uint32_t result_code = 0;  ///< Diameter Result-Code (2001 = success)

        /**
         * @brief Media component description from Rx AAR
         */
        struct MediaComponent {
            uint32_t flow_number;          ///< Media-Component-Number
            std::string media_type;        ///< Audio, Video, etc.
            uint32_t max_bandwidth_ul;     ///< Max-Requested-Bandwidth-UL
            uint32_t max_bandwidth_dl;     ///< Max-Requested-Bandwidth-DL
            std::string flow_description;  ///< IP filter rules
        };
        std::vector<MediaComponent> media_components;

        nlohmann::json toJson() const;
    };
    std::optional<RxLeg> rx_leg;

    /**
     * @brief DIAMETER Gx leg (PCRF → PGW policy control)
     */
    struct GxLeg {
        std::string session_id;  ///< Diameter Session-Id AVP
        std::string framed_ip;   ///< UE IP address

        std::chrono::system_clock::time_point rar_time;
        std::optional<std::chrono::system_clock::time_point> raa_time;

        /**
         * @brief Charging rule installed for voice bearer
         */
        struct ChargingRule {
            std::string rule_name;                 ///< Charging-Rule-Name
            uint8_t qci = 0;                       ///< QoS Class Identifier (1 for voice)
            uint32_t guaranteed_bandwidth_ul = 0;  ///< GBR uplink
            uint32_t guaranteed_bandwidth_dl = 0;  ///< GBR downlink
        };
        std::vector<ChargingRule> charging_rules;

        nlohmann::json toJson() const;
    };
    std::optional<GxLeg> gx_leg;

    /**
     * @brief GTP-C bearer leg (dedicated bearer creation)
     */
    struct BearerLeg {
        std::string session_id;      ///< Internal session ID
        uint32_t teid_uplink = 0;    ///< S5/S8 uplink TEID
        uint32_t teid_downlink = 0;  ///< S5/S8 downlink TEID
        uint8_t eps_bearer_id = 0;   ///< EPS Bearer ID (5-15)
        uint8_t qci = 0;             ///< QCI (1 for voice)
        uint32_t gbr_ul = 0;         ///< Guaranteed Bit Rate uplink (bps)
        uint32_t gbr_dl = 0;         ///< Guaranteed Bit Rate downlink (bps)

        std::chrono::system_clock::time_point request_time;
        std::optional<std::chrono::system_clock::time_point> response_time;

        uint32_t cause = 0;  ///< GTP Cause (16 = Request accepted)

        nlohmann::json toJson() const;
    };
    std::optional<BearerLeg> bearer_leg;

    /**
     * @brief RTP media leg (voice packets)
     */
    struct RtpLeg {
        uint32_t ssrc = 0;         ///< Synchronization Source ID
        std::string local_ip;      ///< UE IP address
        uint16_t local_port = 0;   ///< UE RTP port
        std::string remote_ip;     ///< Remote media gateway IP
        uint16_t remote_port = 0;  ///< Remote RTP port

        /**
         * @brief Per-direction RTP statistics
         */
        struct Direction {
            uint64_t packets = 0;
            uint64_t bytes = 0;
            double packet_loss_rate = 0.0;  ///< Percentage
            double jitter_ms = 0.0;         ///< Average jitter in milliseconds
            double mos_estimate = 0.0;      ///< Mean Opinion Score estimate (1-5)
            std::chrono::system_clock::time_point first_packet;
            std::chrono::system_clock::time_point last_packet;
        };
        Direction uplink;    ///< UE → Network
        Direction downlink;  ///< Network → UE

        nlohmann::json toJson() const;
    };
    std::optional<RtpLeg> rtp_leg;

    /**
     * @brief Computed call quality metrics
     */
    struct Metrics {
        std::chrono::milliseconds setup_time{0};             ///< INVITE → 200 OK
        std::chrono::milliseconds post_dial_delay{0};        ///< INVITE → 180 Ringing
        std::chrono::milliseconds answer_delay{0};           ///< 180 → 200 OK
        std::chrono::milliseconds bearer_setup_time{0};      ///< Bearer Req → Resp
        std::chrono::milliseconds rx_authorization_time{0};  ///< AAR → AAA
        std::chrono::milliseconds total_call_duration{0};    ///< INVITE → BYE
        std::chrono::milliseconds media_duration{0};         ///< First RTP → Last RTP
        double avg_mos = 0.0;                                ///< Average MOS (both directions)
        double packet_loss_rate = 0.0;                       ///< Average packet loss
        double jitter_ms = 0.0;                              ///< Average jitter

        nlohmann::json toJson() const;
    };
    Metrics metrics;

    std::chrono::system_clock::time_point start_time;
    std::chrono::system_clock::time_point end_time;

    /**
     * @brief Check if call has completed all signaling
     */
    bool isComplete() const;

    /**
     * @brief Check if call failed
     */
    bool isFailed() const;

    /**
     * @brief Check if call has active media
     */
    bool hasMedia() const;

    /**
     * @brief Serialize to JSON
     */
    nlohmann::json toJson() const;

    /**
     * @brief Generate ladder diagram JSON for visualization
     */
    nlohmann::json toLadderDiagramJson() const;
};

/**
 * @brief Correlator for VoLTE calls across multiple protocol legs
 *
 * This class maintains a registry of active and completed VoLTE calls,
 * correlating messages from different protocols into unified call records.
 *
 * Correlation strategy:
 * 1. SIP INVITE → Create new call with Call-ID as primary key
 * 2. Extract IMSI from P-Asserted-Identity or via IP lookup in VolteSubscriberContextManager
 * 3. DIAMETER Rx AAR with matching ICID → Link to call
 * 4. DIAMETER Gx RAR with same UE IP → Link to call
 * 5. GTP Create Bearer with same IMSI + QCI=1 → Link to call
 * 6. RTP packets to SDP-negotiated ports → Link to call
 *
 * Thread-safety: This class is NOT thread-safe. Caller must synchronize.
 */
class VolteCallCorrelator {
public:
    /**
     * @brief Construct correlator with subscriber context manager
     */
    explicit VolteCallCorrelator(std::shared_ptr<VolteSubscriberContextManager> context_mgr);

    /**
     * @brief Process a SIP message and correlate to call
     *
     * @param msg Message reference with packet metadata
     * @param sip Parsed SIP message
     */
    void processSipMessage(const SessionMessageRef& msg, const SipMessage& sip);

    /**
     * @brief Process a DIAMETER Rx message (P-CSCF ↔ PCRF)
     *
     * @param msg Message reference
     * @param dia Parsed DIAMETER message
     */
    void processDiameterRx(const SessionMessageRef& msg, const DiameterMessage& dia);

    /**
     * @brief Process a DIAMETER Gx message (PGW ↔ PCRF)
     *
     * @param msg Message reference
     * @param dia Parsed DIAMETER message
     */
    void processDiameterGx(const SessionMessageRef& msg, const DiameterMessage& dia);

    /**
     * @brief Process a GTP bearer message
     *
     * @param msg Message reference
     * @param gtp Parsed GTP message
     */
    void processGtpBearer(const SessionMessageRef& msg, const GtpMessage& gtp);

    /**
     * @brief Process an RTP packet
     *
     * @param msg Message reference
     * @param rtp Parsed RTP header
     */
    void processRtpPacket(const SessionMessageRef& msg, const RtpHeader& rtp);

    /**
     * @brief Find call by SIP Call-ID
     */
    std::shared_ptr<VolteCall> findByCallId(const std::string& call_id);

    /**
     * @brief Find call by IMS Charging ID (ICID)
     */
    std::shared_ptr<VolteCall> findByIcid(const std::string& icid);

    /**
     * @brief Find call by DIAMETER Rx Session-Id
     */
    std::shared_ptr<VolteCall> findByRxSessionId(const std::string& session_id);

    /**
     * @brief Find call by GTP TEID
     */
    std::shared_ptr<VolteCall> findByTeid(uint32_t teid);

    /**
     * @brief Find all calls for a subscriber (by IMSI)
     */
    std::vector<std::shared_ptr<VolteCall>> findByImsi(const std::string& imsi);

    /**
     * @brief Get all calls (active and completed)
     */
    std::vector<std::shared_ptr<VolteCall>> getAllCalls() const;

    /**
     * @brief Get only active calls (not completed/failed)
     */
    std::vector<std::shared_ptr<VolteCall>> getActiveCalls() const;

    /**
     * @brief Clean up completed calls older than retention period
     *
     * @param retention Minimum age for cleanup
     * @return Number of calls removed
     */
    size_t cleanupCompletedCalls(std::chrono::seconds retention);

    /**
     * @brief Statistics about tracked calls
     */
    struct Stats {
        uint64_t total_calls = 0;
        uint64_t successful_calls = 0;
        uint64_t failed_calls = 0;
        uint64_t active_calls = 0;
        double avg_setup_time_ms = 0.0;
        double avg_mos = 0.0;
    };

    /**
     * @brief Get aggregate statistics
     */
    Stats getStats() const;

private:
    std::shared_ptr<VolteSubscriberContextManager> context_mgr_;

    // Primary index: Call-ID → Call
    std::unordered_map<std::string, std::shared_ptr<VolteCall>> calls_by_call_id_;

    // Secondary indices for correlation
    std::unordered_map<std::string, std::string> icid_to_call_id_;
    std::unordered_map<std::string, std::string> rx_session_to_call_id_;
    std::unordered_map<uint32_t, std::string> teid_to_call_id_;
    std::unordered_multimap<std::string, std::string> imsi_to_call_ids_;

    /**
     * @brief Correlate DIAMETER Rx to call by ICID or UE IP
     */
    void correlateRxToCall(std::shared_ptr<VolteCall> call, const std::string& framed_ip);

    /**
     * @brief Correlate GTP bearer to call by IMSI and QCI
     */
    void correlateBearerToCall(std::shared_ptr<VolteCall> call, const std::string& ue_ip);

    /**
     * @brief Correlate RTP to call by UE IP and port
     */
    void correlateRtpToCall(std::shared_ptr<VolteCall> call, const std::string& ue_ip,
                            uint16_t port);

    /**
     * @brief Update call state and trigger metric calculation
     */
    void updateCallState(std::shared_ptr<VolteCall> call, VolteCall::State new_state,
                         const std::string& reason = "");

    /**
     * @brief Calculate timing and quality metrics
     */
    void calculateMetrics(std::shared_ptr<VolteCall> call);

    /**
     * @brief Extract IMSI from subscriber context manager by UE IP
     */
    std::optional<std::string> resolveImsiByIp(const std::string& ue_ip);

    /**
     * @brief Extract IMSI from SIP P-Asserted-Identity if present
     */
    std::optional<std::string> extractImsiFromSip(const SipMessage& sip);
};

}  // namespace correlation
}  // namespace callflow
