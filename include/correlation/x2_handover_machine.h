#pragma once

#include "correlation/procedure_state_machine.h"

namespace callflow {
namespace correlation {

/**
 * X2 Handover Procedure State Machine
 *
 * Tracks the X2-based handover procedure (intra-LTE, no MME involvement for prep):
 * 1. X2AP: Handover Request (Source eNodeB → Target eNodeB)
 * 2. X2AP: Handover Request Acknowledge
 * 3. X2AP: SN Status Transfer (Source → Target)
 * 4. S1AP: Path Switch Request (Target eNodeB → MME)
 * 5. GTPv2-C: Modify Bearer Request (MME → S-GW, update TEIDs)
 * 6. GTPv2-C: Modify Bearer Response
 * 7. S1AP: Path Switch Request Acknowledge
 * 8. X2AP: UE Context Release (Target → Source)
 * 9. GTP-U: Data now flows via new path (new TEID)
 */
class X2HandoverMachine : public ProcedureStateMachine {
public:
    enum class State {
        IDLE,
        HANDOVER_REQUESTED,
        HANDOVER_PREPARED,
        SN_STATUS_TRANSFERRED,
        PATH_SWITCH_REQUESTED,
        BEARER_MODIFIED,
        PATH_SWITCH_ACKNOWLEDGED,
        HANDOVER_COMPLETE,
        CONTEXT_RELEASED,
        FAILED
    };

    struct Metrics {
        // Timing metrics
        std::chrono::milliseconds handover_request_to_ack{0};         // Target: < 50ms
        std::chrono::milliseconds path_switch_to_bearer_modify{0};    // Target: < 100ms
        std::chrono::milliseconds bearer_modify_latency{0};           // Target: < 100ms
        std::chrono::milliseconds total_handover_time{0};             // Target: < 500ms
        std::chrono::milliseconds handover_preparation_time{0};       // Request to Ack
        std::chrono::milliseconds handover_execution_time{0};         // Ack to Context Release

        // Identifiers
        std::optional<std::string> imsi;
        std::optional<uint32_t> mme_ue_s1ap_id;
        std::optional<uint32_t> old_enb_ue_s1ap_id;
        std::optional<uint32_t> new_enb_ue_s1ap_id;
        std::optional<uint32_t> old_teid_s1u;
        std::optional<uint32_t> new_teid_s1u;
        std::optional<std::string> source_enb_id;
        std::optional<std::string> target_enb_id;

        // Performance indicators
        bool interruption_time_met{false};  // < 27.5ms for intra-frequency HO (3GPP target)

        nlohmann::json toJson() const;
    };

    X2HandoverMachine();

    // ProcedureStateMachine interface
    bool processMessage(const SessionMessageRef& msg) override;
    bool isComplete() const override { return current_state_ == State::CONTEXT_RELEASED; }
    bool isFailed() const override { return current_state_ == State::FAILED; }
    ProcedureType getProcedureType() const override { return ProcedureType::LTE_HANDOVER_X2; }
    std::chrono::system_clock::time_point getStartTime() const override { return start_time_; }
    std::optional<std::chrono::system_clock::time_point> getEndTime() const override;
    std::optional<std::chrono::milliseconds> getDuration() const override;
    std::vector<ProcedureStep> getSteps() const override { return steps_; }
    nlohmann::json getMetrics() const override { return metrics_.toJson(); }
    nlohmann::json toJson() const override;
    std::string getStateDescription() const override;

    // X2 Handover specific
    State getCurrentState() const { return current_state_; }
    const Metrics& getHandoverMetrics() const { return metrics_; }

private:
    State current_state_ = State::IDLE;
    Metrics metrics_;
    std::vector<ProcedureStep> steps_;

    std::chrono::system_clock::time_point start_time_;
    std::chrono::system_clock::time_point end_time_;

    // Timing checkpoint markers
    std::chrono::system_clock::time_point handover_request_time_;
    std::chrono::system_clock::time_point handover_ack_time_;
    std::chrono::system_clock::time_point sn_status_time_;
    std::chrono::system_clock::time_point path_switch_time_;
    std::chrono::system_clock::time_point bearer_modify_req_time_;
    std::chrono::system_clock::time_point bearer_modify_resp_time_;
    std::chrono::system_clock::time_point path_switch_ack_time_;

    void transitionTo(State new_state, const SessionMessageRef& msg);
    void recordStep(const std::string& step_name, const SessionMessageRef& msg,
                    bool expected = true);
    std::string stateToString(State state) const;
};

} // namespace correlation
} // namespace callflow
