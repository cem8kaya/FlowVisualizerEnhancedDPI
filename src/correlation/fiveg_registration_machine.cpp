#include "correlation/fiveg_registration_machine.h"

#include "common/logger.h"

namespace callflow {
namespace correlation {

FiveGRegistrationMachine::FiveGRegistrationMachine() {
    LOG_DEBUG("5G Registration state machine created");
}

bool FiveGRegistrationMachine::processMessage(const SessionMessageRef& msg) {
    bool state_changed = false;

    switch (current_state_) {
        case State::IDLE:
            if (msg.message_type == MessageType::NGAP_INITIAL_UE_MESSAGE &&
                hasNasMessageType(msg.parsed_data, MessageType::NAS5G_REGISTRATION_REQUEST)) {
                start_time_ = msg.timestamp;
                recordStep("Registration Request", msg, true);
                transitionTo(State::REGISTRATION_REQUESTED, msg);
                state_changed = true;
            }
            break;

        case State::REGISTRATION_REQUESTED:
            if (msg.message_type == MessageType::NGAP_DOWNLINK_NAS_TRANSPORT &&
                hasNasMessageType(msg.parsed_data, MessageType::NAS5G_AUTHENTICATION_REQUEST)) {
                recordStep("Authentication Request", msg, true);
                transitionTo(State::AUTHENTICATION_IN_PROGRESS, msg);
                state_changed = true;
            }
            break;

        case State::AUTHENTICATION_IN_PROGRESS:
            if (msg.message_type == MessageType::NGAP_UPLINK_NAS_TRANSPORT &&
                hasNasMessageType(msg.parsed_data, MessageType::NAS5G_AUTHENTICATION_RESPONSE)) {
                recordStep("Authentication Response", msg, true);
                transitionTo(State::AUTHENTICATION_COMPLETE, msg);
                state_changed = true;
            }
            break;

        case State::AUTHENTICATION_COMPLETE:
            if (msg.message_type == MessageType::NGAP_DOWNLINK_NAS_TRANSPORT &&
                hasNasMessageType(msg.parsed_data, MessageType::NAS5G_SECURITY_MODE_COMMAND)) {
                recordStep("Security Mode Command", msg, true);
                transitionTo(State::SECURITY_MODE_IN_PROGRESS, msg);
                state_changed = true;
            }
            break;

        case State::SECURITY_MODE_IN_PROGRESS:
            if (msg.message_type == MessageType::NGAP_UPLINK_NAS_TRANSPORT &&
                hasNasMessageType(msg.parsed_data, MessageType::NAS5G_SECURITY_MODE_COMPLETE)) {
                recordStep("Security Mode Complete", msg, true);
                transitionTo(State::SECURITY_MODE_COMPLETE, msg);
                state_changed = true;
            }
            break;

        case State::SECURITY_MODE_COMPLETE:
            if (msg.message_type == MessageType::NGAP_INITIAL_CONTEXT_SETUP_REQ) {
                recordStep("Initial Context Setup Request", msg, true);
                transitionTo(State::INITIAL_CONTEXT_SETUP_IN_PROGRESS, msg);
                state_changed = true;
            }
            break;

        case State::INITIAL_CONTEXT_SETUP_IN_PROGRESS:
            if (msg.message_type == MessageType::NGAP_DOWNLINK_NAS_TRANSPORT &&
                hasNasMessageType(msg.parsed_data, MessageType::NAS5G_REGISTRATION_ACCEPT)) {
                recordStep("Registration Accept", msg, true);
                transitionTo(State::REGISTRATION_ACCEPTED, msg);
                state_changed = true;
            }
            break;

        case State::REGISTRATION_ACCEPTED:
            if (msg.message_type == MessageType::NGAP_UPLINK_NAS_TRANSPORT &&
                hasNasMessageType(msg.parsed_data, MessageType::NAS5G_REGISTRATION_COMPLETE)) {
                end_time_ = msg.timestamp;
                metrics_.total_registration_time =
                    std::chrono::duration_cast<std::chrono::milliseconds>(end_time_ - start_time_);
                recordStep("Registration Complete", msg, true);
                transitionTo(State::REGISTERED, msg);
                state_changed = true;
                LOG_INFO("5G Registration completed in {}ms",
                        metrics_.total_registration_time.count());
            }
            break;

        case State::REGISTERED:
        case State::FAILED:
            break;
    }

    return state_changed;
}

void FiveGRegistrationMachine::transitionTo(State new_state, const SessionMessageRef& msg) {
    (void)msg;  // Parameter used for interface consistency but not needed here
    LOG_DEBUG("5G Registration state: {} -> {}", stateToString(current_state_),
             stateToString(new_state));
    current_state_ = new_state;
}

void FiveGRegistrationMachine::recordStep(const std::string& step_name,
                                           const SessionMessageRef& msg, bool expected) {
    ProcedureStep step;
    step.step_name = step_name;
    step.message_type = msg.message_type;
    step.timestamp = msg.timestamp;
    step.expected = expected;
    if (!steps_.empty()) {
        step.latency_from_previous = std::chrono::duration_cast<std::chrono::milliseconds>(
            msg.timestamp - steps_.back().timestamp);
    }
    steps_.push_back(step);
}

std::optional<std::chrono::system_clock::time_point> FiveGRegistrationMachine::getEndTime() const {
    return current_state_ == State::REGISTERED ? std::optional(end_time_) : std::nullopt;
}

std::optional<std::chrono::milliseconds> FiveGRegistrationMachine::getDuration() const {
    return current_state_ == State::REGISTERED ? std::optional(metrics_.total_registration_time)
                                                 : std::nullopt;
}

nlohmann::json FiveGRegistrationMachine::toJson() const {
    nlohmann::json j;
    j["procedure"] = procedureTypeToString(getProcedureType());
    j["state"] = stateToString(current_state_);
    j["complete"] = isComplete();
    j["failed"] = isFailed();
    j["metrics"] = metrics_.toJson();
    nlohmann::json steps_json = nlohmann::json::array();
    for (const auto& step : steps_) {
        steps_json.push_back(step.toJson());
    }
    j["steps"] = steps_json;
    return j;
}

std::string FiveGRegistrationMachine::getStateDescription() const {
    switch (current_state_) {
        case State::IDLE:
            return "Waiting for Registration Request";
        case State::REGISTRATION_REQUESTED:
            return "Registration requested";
        case State::AUTHENTICATION_IN_PROGRESS:
            return "Authentication in progress";
        case State::AUTHENTICATION_COMPLETE:
            return "Authentication complete";
        case State::SECURITY_MODE_IN_PROGRESS:
            return "Security mode in progress";
        case State::SECURITY_MODE_COMPLETE:
            return "Security mode complete";
        case State::INITIAL_CONTEXT_SETUP_IN_PROGRESS:
            return "Initial context setup in progress";
        case State::REGISTRATION_ACCEPTED:
            return "Registration accepted";
        case State::REGISTERED:
            return "Registration complete";
        case State::FAILED:
            return "Registration failed";
        default:
            return "Unknown";
    }
}

std::string FiveGRegistrationMachine::stateToString(State state) const {
    switch (state) {
        case State::IDLE:
            return "IDLE";
        case State::REGISTRATION_REQUESTED:
            return "REGISTRATION_REQUESTED";
        case State::AUTHENTICATION_IN_PROGRESS:
            return "AUTHENTICATION_IN_PROGRESS";
        case State::AUTHENTICATION_COMPLETE:
            return "AUTHENTICATION_COMPLETE";
        case State::SECURITY_MODE_IN_PROGRESS:
            return "SECURITY_MODE_IN_PROGRESS";
        case State::SECURITY_MODE_COMPLETE:
            return "SECURITY_MODE_COMPLETE";
        case State::INITIAL_CONTEXT_SETUP_IN_PROGRESS:
            return "INITIAL_CONTEXT_SETUP_IN_PROGRESS";
        case State::REGISTRATION_ACCEPTED:
            return "REGISTRATION_ACCEPTED";
        case State::REGISTERED:
            return "REGISTERED";
        case State::FAILED:
            return "FAILED";
        default:
            return "UNKNOWN";
    }
}

nlohmann::json FiveGRegistrationMachine::Metrics::toJson() const {
    nlohmann::json j;
    if (supi.has_value())
        j["supi"] = supi.value();
    if (amf_ue_ngap_id.has_value())
        j["amf_ue_ngap_id"] = amf_ue_ngap_id.value();
    if (ran_ue_ngap_id.has_value())
        j["ran_ue_ngap_id"] = ran_ue_ngap_id.value();
    j["total_registration_time_ms"] = total_registration_time.count();
    return j;
}

} // namespace correlation
} // namespace callflow
