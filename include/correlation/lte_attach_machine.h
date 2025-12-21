#pragma once

#include "correlation/procedure_state_machine.h"

namespace callflow {
namespace correlation {

/**
 * LTE Attach Procedure State Machine
 *
 * Tracks the standard LTE attach procedure:
 * 1. S1AP: Initial UE Message → NAS: Attach Request
 * 2. S1AP: Downlink NAS Transport → NAS: Authentication Request
 * 3. S1AP: Uplink NAS Transport → NAS: Authentication Response
 * 4. S1AP: Downlink NAS Transport → NAS: Security Mode Command
 * 5. S1AP: Uplink NAS Transport → NAS: Security Mode Complete
 * 6. GTPv2-C: Create Session Request (S11: MME → S-GW)
 * 7. GTPv2-C: Create Session Response
 * 8. S1AP: Initial Context Setup Request (MME → eNodeB)
 * 9. S1AP: Initial Context Setup Response
 * 10. S1AP: Downlink NAS Transport → NAS: Attach Accept
 * 11. S1AP: Uplink NAS Transport → NAS: Attach Complete
 */
class LteAttachMachine : public ProcedureStateMachine {
public:
    enum class State {
        IDLE,
        ATTACH_REQUESTED,
        AUTHENTICATION_IN_PROGRESS,
        AUTHENTICATION_COMPLETE,
        SECURITY_MODE_IN_PROGRESS,
        SECURITY_MODE_COMPLETE,
        GTP_SESSION_CREATION_IN_PROGRESS,
        GTP_SESSION_CREATED,
        INITIAL_CONTEXT_SETUP_IN_PROGRESS,
        ATTACH_ACCEPTED,
        ATTACHED,   // Attach Complete received
        FAILED
    };

    struct Metrics {
        // Timing metrics (in milliseconds)
        std::chrono::milliseconds attach_request_to_auth_request{0};    // Target: < 100ms
        std::chrono::milliseconds auth_request_to_auth_response{0};     // Target: < 100ms
        std::chrono::milliseconds auth_to_security_mode{0};             // Target: < 100ms
        std::chrono::milliseconds security_mode_to_gtp_create{0};       // Target: < 100ms
        std::chrono::milliseconds gtp_create_to_gtp_response{0};        // Target: < 200ms
        std::chrono::milliseconds gtp_response_to_context_setup{0};     // Target: < 50ms
        std::chrono::milliseconds context_setup_to_attach_accept{0};    // Target: < 100ms
        std::chrono::milliseconds attach_accept_to_complete{0};         // Target: < 100ms
        std::chrono::milliseconds total_attach_time{0};                 // Target: < 1000ms

        // Identifiers
        std::optional<std::string> imsi;
        std::optional<uint32_t> mme_ue_s1ap_id;
        std::optional<uint32_t> enb_ue_s1ap_id;
        std::optional<uint32_t> teid_s1u;
        std::optional<std::string> ue_ip;
        std::optional<std::string> apn;

        nlohmann::json toJson() const;
    };

    LteAttachMachine();

    // ProcedureStateMachine interface
    bool processMessage(const SessionMessageRef& msg) override;
    bool isComplete() const override { return current_state_ == State::ATTACHED; }
    bool isFailed() const override { return current_state_ == State::FAILED; }
    ProcedureType getProcedureType() const override { return ProcedureType::LTE_ATTACH; }
    std::chrono::system_clock::time_point getStartTime() const override { return start_time_; }
    std::optional<std::chrono::system_clock::time_point> getEndTime() const override;
    std::optional<std::chrono::milliseconds> getDuration() const override;
    std::vector<ProcedureStep> getSteps() const override { return steps_; }
    nlohmann::json getMetrics() const override { return metrics_.toJson(); }
    nlohmann::json toJson() const override;
    std::string getStateDescription() const override;

    // LTE Attach specific
    State getCurrentState() const { return current_state_; }
    const Metrics& getAttachMetrics() const { return metrics_; }

private:
    State current_state_ = State::IDLE;
    Metrics metrics_;
    std::vector<ProcedureStep> steps_;

    std::chrono::system_clock::time_point start_time_;
    std::chrono::system_clock::time_point end_time_;
    std::chrono::system_clock::time_point last_message_time_;

    // Timing checkpoint markers
    std::chrono::system_clock::time_point attach_request_time_;
    std::chrono::system_clock::time_point auth_request_time_;
    std::chrono::system_clock::time_point auth_response_time_;
    std::chrono::system_clock::time_point security_mode_cmd_time_;
    std::chrono::system_clock::time_point security_mode_complete_time_;
    std::chrono::system_clock::time_point gtp_create_time_;
    std::chrono::system_clock::time_point gtp_response_time_;
    std::chrono::system_clock::time_point context_setup_time_;
    std::chrono::system_clock::time_point attach_accept_time_;

    void transitionTo(State new_state, const SessionMessageRef& msg);
    void recordStep(const std::string& step_name, const SessionMessageRef& msg,
                    bool expected = true);
    void calculateMetrics();
    std::string stateToString(State state) const;
};

} // namespace correlation
} // namespace callflow
