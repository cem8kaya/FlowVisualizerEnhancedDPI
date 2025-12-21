#pragma once

#include "correlation/procedure_state_machine.h"

namespace callflow {
namespace correlation {

/**
 * VoLTE Call Setup Procedure State Machine
 *
 * Tracks the VoLTE call setup procedure across IMS, PCRF, and EPC:
 * 1. SIP: INVITE (UE → P-CSCF)
 * 2. SIP: 100 Trying
 * 3. Diameter Rx: AAR (P-CSCF → PCRF) - Request media authorization
 * 4. Diameter Rx: AAA (PCRF → P-CSCF) - Authorized
 * 5. Diameter Gx: RAR (PCRF → P-GW) - Install policy/QoS
 * 6. Diameter Gx: RAA (P-GW → PCRF) - Acknowledged
 * 7. GTPv2-C: Create Bearer Request (Dedicated bearer for VoLTE)
 * 8. GTPv2-C: Create Bearer Response
 * 9. SIP: 180 Ringing
 * 10. SIP: 200 OK (Call accepted)
 * 11. SIP: ACK
 * 12. RTP: Media flows start
 */
class VoLteCallMachine : public ProcedureStateMachine {
public:
    enum class State {
        IDLE,
        INVITE_SENT,
        TRYING_RECEIVED,
        MEDIA_AUTHORIZATION_IN_PROGRESS,
        MEDIA_AUTHORIZED,
        POLICY_INSTALLATION_IN_PROGRESS,
        POLICY_INSTALLED,
        DEDICATED_BEARER_CREATION_IN_PROGRESS,
        DEDICATED_BEARER_CREATED,
        RINGING,
        CALL_CONNECTED,
        MEDIA_ACTIVE,
        CALL_RELEASED,
        FAILED
    };

    struct Metrics {
        // Timing metrics
        std::chrono::milliseconds invite_to_trying{0};                // Target: < 100ms
        std::chrono::milliseconds media_authorization_time{0};        // Rx AAR to AAA
        std::chrono::milliseconds policy_installation_time{0};        // Gx RAR to RAA
        std::chrono::milliseconds dedicated_bearer_setup_time{0};     // GTP Create Bearer
        std::chrono::milliseconds post_dial_delay{0};                 // INVITE to 180 Ringing
        std::chrono::milliseconds call_setup_time{0};                 // INVITE to 200 OK
        std::chrono::milliseconds answer_to_media{0};                 // 200 OK to RTP

        // Identifiers
        std::optional<std::string> sip_call_id;
        std::optional<std::string> imsi;
        std::optional<std::string> calling_number;
        std::optional<std::string> called_number;
        std::optional<uint32_t> dedicated_bearer_teid;
        std::optional<uint8_t> dedicated_bearer_qci;  // Should be QCI 1 for VoLTE voice
        std::optional<std::string> icid;  // From P-Charging-Vector for billing correlation
        std::optional<uint32_t> rtp_ssrc;

        // QoS metrics
        std::optional<uint32_t> guaranteed_bitrate_ul;  // kbps
        std::optional<uint32_t> guaranteed_bitrate_dl;  // kbps

        nlohmann::json toJson() const;
    };

    VoLteCallMachine();

    // ProcedureStateMachine interface
    bool processMessage(const SessionMessageRef& msg) override;
    bool isComplete() const override { return current_state_ == State::MEDIA_ACTIVE; }
    bool isFailed() const override { return current_state_ == State::FAILED; }
    ProcedureType getProcedureType() const override { return ProcedureType::VOLTE_CALL_SETUP; }
    std::chrono::system_clock::time_point getStartTime() const override { return start_time_; }
    std::optional<std::chrono::system_clock::time_point> getEndTime() const override;
    std::optional<std::chrono::milliseconds> getDuration() const override;
    std::vector<ProcedureStep> getSteps() const override { return steps_; }
    nlohmann::json getMetrics() const override { return metrics_.toJson(); }
    nlohmann::json toJson() const override;
    std::string getStateDescription() const override;

    // VoLTE specific
    State getCurrentState() const { return current_state_; }
    const Metrics& getCallMetrics() const { return metrics_; }

private:
    State current_state_ = State::IDLE;
    Metrics metrics_;
    std::vector<ProcedureStep> steps_;

    std::chrono::system_clock::time_point start_time_;
    std::chrono::system_clock::time_point end_time_;

    // Timing checkpoint markers
    std::chrono::system_clock::time_point invite_time_;
    std::chrono::system_clock::time_point trying_time_;
    std::chrono::system_clock::time_point rx_aar_time_;
    std::chrono::system_clock::time_point rx_aaa_time_;
    std::chrono::system_clock::time_point gx_rar_time_;
    std::chrono::system_clock::time_point gx_raa_time_;
    std::chrono::system_clock::time_point bearer_req_time_;
    std::chrono::system_clock::time_point bearer_resp_time_;
    std::chrono::system_clock::time_point ringing_time_;
    std::chrono::system_clock::time_point ok_time_;
    std::chrono::system_clock::time_point media_start_time_;

    void transitionTo(State new_state, const SessionMessageRef& msg);
    void recordStep(const std::string& step_name, const SessionMessageRef& msg,
                    bool expected = true);
    std::string stateToString(State state) const;
};

} // namespace correlation
} // namespace callflow
