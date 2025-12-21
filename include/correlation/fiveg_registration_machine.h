#pragma once

#include "correlation/procedure_state_machine.h"

namespace callflow {
namespace correlation {

/**
 * 5G Registration Procedure State Machine
 *
 * Similar to LTE Attach but for 5G networks:
 * 1. NGAP: Initial UE Message → 5G NAS: Registration Request
 * 2. NGAP: Downlink NAS Transport → 5G NAS: Authentication Request
 * 3. NGAP: Uplink NAS Transport → 5G NAS: Authentication Response
 * 4. NGAP: Downlink NAS Transport → 5G NAS: Security Mode Command
 * 5. NGAP: Uplink NAS Transport → 5G NAS: Security Mode Complete
 * 6. NGAP: Initial Context Setup Request
 * 7. NGAP: Initial Context Setup Response
 * 8. 5G NAS: Registration Accept
 * 9. 5G NAS: Registration Complete
 */
class FiveGRegistrationMachine : public ProcedureStateMachine {
public:
    enum class State {
        IDLE,
        REGISTRATION_REQUESTED,
        AUTHENTICATION_IN_PROGRESS,
        AUTHENTICATION_COMPLETE,
        SECURITY_MODE_IN_PROGRESS,
        SECURITY_MODE_COMPLETE,
        INITIAL_CONTEXT_SETUP_IN_PROGRESS,
        REGISTRATION_ACCEPTED,
        REGISTERED,
        FAILED
    };

    struct Metrics {
        std::chrono::milliseconds total_registration_time{0};
        std::optional<std::string> supi;  // 5G subscriber identifier
        std::optional<uint64_t> amf_ue_ngap_id;
        std::optional<uint64_t> ran_ue_ngap_id;

        nlohmann::json toJson() const;
    };

    FiveGRegistrationMachine();

    bool processMessage(const SessionMessageRef& msg) override;
    bool isComplete() const override { return current_state_ == State::REGISTERED; }
    bool isFailed() const override { return current_state_ == State::FAILED; }
    ProcedureType getProcedureType() const override { return ProcedureType::FIVEG_REGISTRATION; }
    std::chrono::system_clock::time_point getStartTime() const override { return start_time_; }
    std::optional<std::chrono::system_clock::time_point> getEndTime() const override;
    std::optional<std::chrono::milliseconds> getDuration() const override;
    std::vector<ProcedureStep> getSteps() const override { return steps_; }
    nlohmann::json getMetrics() const override { return metrics_.toJson(); }
    nlohmann::json toJson() const override;
    std::string getStateDescription() const override;

    State getCurrentState() const { return current_state_; }

private:
    State current_state_ = State::IDLE;
    Metrics metrics_;
    std::vector<ProcedureStep> steps_;
    std::chrono::system_clock::time_point start_time_;
    std::chrono::system_clock::time_point end_time_;

    void transitionTo(State new_state, const SessionMessageRef& msg);
    void recordStep(const std::string& step_name, const SessionMessageRef& msg,
                    bool expected = true);
    std::string stateToString(State state) const;
};

} // namespace correlation
} // namespace callflow
