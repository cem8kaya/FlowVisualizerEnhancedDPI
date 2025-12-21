#include "correlation/x2_handover_machine.h"

#include "common/logger.h"

namespace callflow {
namespace correlation {

X2HandoverMachine::X2HandoverMachine() {
    LOG_DEBUG("X2 Handover state machine created");
}

bool X2HandoverMachine::processMessage(const SessionMessageRef& msg) {
    bool state_changed = false;

    switch (current_state_) {
        case State::IDLE:
            // Look for X2AP Handover Request
            if (msg.message_type == MessageType::X2AP_HANDOVER_REQUEST) {
                start_time_ = msg.timestamp;
                handover_request_time_ = msg.timestamp;

                // Extract identifiers
                metrics_.imsi = extractImsi(msg.parsed_data);
                if (msg.correlation_key.enb_ue_s1ap_id.has_value()) {
                    metrics_.old_enb_ue_s1ap_id = msg.correlation_key.enb_ue_s1ap_id.value();
                }
                if (msg.correlation_key.mme_ue_s1ap_id.has_value()) {
                    metrics_.mme_ue_s1ap_id = msg.correlation_key.mme_ue_s1ap_id.value();
                }

                // Extract source eNB ID
                if (msg.parsed_data.contains("source_enb_id")) {
                    metrics_.source_enb_id = msg.parsed_data["source_enb_id"].get<std::string>();
                }

                recordStep("X2 Handover Request", msg, true);
                transitionTo(State::HANDOVER_REQUESTED, msg);
                state_changed = true;
            }
            break;

        case State::HANDOVER_REQUESTED:
            // Look for X2AP Handover Request Acknowledge
            if (msg.message_type == MessageType::X2AP_HANDOVER_REQUEST_ACK) {
                handover_ack_time_ = msg.timestamp;
                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                    msg.timestamp - handover_request_time_);
                metrics_.handover_request_to_ack = duration;
                metrics_.handover_preparation_time = duration;

                // Extract target eNB ID
                if (msg.parsed_data.contains("target_enb_id")) {
                    metrics_.target_enb_id = msg.parsed_data["target_enb_id"].get<std::string>();
                }

                recordStep("X2 Handover Request Acknowledge", msg, true);
                transitionTo(State::HANDOVER_PREPARED, msg);
                state_changed = true;
            } else if (msg.message_type == MessageType::X2AP_HANDOVER_CANCEL) {
                recordStep("X2 Handover Cancel", msg, false);
                transitionTo(State::FAILED, msg);
                state_changed = true;
            }
            break;

        case State::HANDOVER_PREPARED:
            // Look for SN Status Transfer
            if (msg.message_type == MessageType::X2AP_SN_STATUS_TRANSFER) {
                sn_status_time_ = msg.timestamp;

                recordStep("SN Status Transfer", msg, true);
                transitionTo(State::SN_STATUS_TRANSFERRED, msg);
                state_changed = true;
            }
            // Or directly to Path Switch Request (some implementations skip SN Status)
            else if (msg.message_type == MessageType::S1AP_PATH_SWITCH_REQUEST) {
                path_switch_time_ = msg.timestamp;

                // Extract new eNB UE S1AP ID
                if (msg.correlation_key.enb_ue_s1ap_id.has_value()) {
                    metrics_.new_enb_ue_s1ap_id = msg.correlation_key.enb_ue_s1ap_id.value();
                }

                recordStep("Path Switch Request", msg, true);
                transitionTo(State::PATH_SWITCH_REQUESTED, msg);
                state_changed = true;
            }
            break;

        case State::SN_STATUS_TRANSFERRED:
            // Look for Path Switch Request
            if (msg.message_type == MessageType::S1AP_PATH_SWITCH_REQUEST) {
                path_switch_time_ = msg.timestamp;

                // Extract new eNB UE S1AP ID
                if (msg.correlation_key.enb_ue_s1ap_id.has_value()) {
                    metrics_.new_enb_ue_s1ap_id = msg.correlation_key.enb_ue_s1ap_id.value();
                }

                recordStep("Path Switch Request", msg, true);
                transitionTo(State::PATH_SWITCH_REQUESTED, msg);
                state_changed = true;
            }
            break;

        case State::PATH_SWITCH_REQUESTED:
            // Look for Modify Bearer Request
            if (msg.message_type == MessageType::GTP_MODIFY_BEARER_REQ) {
                bearer_modify_req_time_ = msg.timestamp;
                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                    msg.timestamp - path_switch_time_);
                metrics_.path_switch_to_bearer_modify = duration;

                // Extract old TEID (being replaced)
                if (msg.parsed_data.contains("old_teid")) {
                    metrics_.old_teid_s1u = msg.parsed_data["old_teid"].get<uint32_t>();
                }

                recordStep("Modify Bearer Request", msg, true);
                // Don't transition yet - wait for response
                state_changed = true;
            }
            // Or look for Modify Bearer Response
            else if (msg.message_type == MessageType::GTP_MODIFY_BEARER_RESP) {
                bearer_modify_resp_time_ = msg.timestamp;
                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                    msg.timestamp - bearer_modify_req_time_);
                metrics_.bearer_modify_latency = duration;

                // Extract new TEID
                metrics_.new_teid_s1u = extractTeid(msg.parsed_data, "S1-U");

                recordStep("Modify Bearer Response", msg, true);
                transitionTo(State::BEARER_MODIFIED, msg);
                state_changed = true;
            }
            break;

        case State::BEARER_MODIFIED:
            // Look for Path Switch Request Acknowledge
            if (msg.message_type == MessageType::S1AP_PATH_SWITCH_REQUEST_ACK) {
                path_switch_ack_time_ = msg.timestamp;

                recordStep("Path Switch Request Acknowledge", msg, true);
                transitionTo(State::PATH_SWITCH_ACKNOWLEDGED, msg);
                state_changed = true;
            }
            break;

        case State::PATH_SWITCH_ACKNOWLEDGED:
            // Look for UE Context Release
            if (msg.message_type == MessageType::X2AP_UE_CONTEXT_RELEASE) {
                end_time_ = msg.timestamp;

                // Calculate total handover time
                metrics_.total_handover_time = std::chrono::duration_cast<std::chrono::milliseconds>(
                    msg.timestamp - handover_request_time_);

                // Calculate execution time (after preparation)
                metrics_.handover_execution_time = std::chrono::duration_cast<std::chrono::milliseconds>(
                    msg.timestamp - handover_ack_time_);

                // Check if interruption time target was met (< 27.5ms for intra-freq)
                // This is approximate - real interruption time would be measured from last
                // data packet on old path to first data packet on new path
                metrics_.interruption_time_met = (metrics_.handover_execution_time.count() < 30);

                recordStep("UE Context Release", msg, true);
                transitionTo(State::CONTEXT_RELEASED, msg);
                state_changed = true;

                LOG_INFO("X2 Handover completed for IMSI {} in {}ms (prep: {}ms, exec: {}ms)",
                        metrics_.imsi.value_or("unknown"),
                        metrics_.total_handover_time.count(),
                        metrics_.handover_preparation_time.count(),
                        metrics_.handover_execution_time.count());
            }
            break;

        case State::CONTEXT_RELEASED:
            // Procedure complete
            break;

        case State::FAILED:
            // Procedure failed
            break;
    }

    return state_changed;
}

void X2HandoverMachine::transitionTo(State new_state, const SessionMessageRef& msg) {
    LOG_DEBUG("X2 Handover state: {} -> {}", stateToString(current_state_),
             stateToString(new_state));
    current_state_ = new_state;
}

void X2HandoverMachine::recordStep(const std::string& step_name, const SessionMessageRef& msg,
                                    bool expected) {
    ProcedureStep step;
    step.step_name = step_name;
    step.message_type = msg.message_type;
    step.timestamp = msg.timestamp;
    step.expected = expected;

    if (!steps_.empty()) {
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            msg.timestamp - steps_.back().timestamp);
        step.latency_from_previous = duration;
    }

    steps_.push_back(step);
}

std::optional<std::chrono::system_clock::time_point> X2HandoverMachine::getEndTime() const {
    if (current_state_ == State::CONTEXT_RELEASED) {
        return end_time_;
    }
    return std::nullopt;
}

std::optional<std::chrono::milliseconds> X2HandoverMachine::getDuration() const {
    if (current_state_ == State::CONTEXT_RELEASED) {
        return metrics_.total_handover_time;
    }
    return std::nullopt;
}

nlohmann::json X2HandoverMachine::toJson() const {
    nlohmann::json j;
    j["procedure"] = procedureTypeToString(getProcedureType());
    j["state"] = stateToString(current_state_);
    j["state_description"] = getStateDescription();
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

std::string X2HandoverMachine::getStateDescription() const {
    switch (current_state_) {
        case State::IDLE:
            return "Waiting for handover request";
        case State::HANDOVER_REQUESTED:
            return "Handover requested, waiting for acknowledgment";
        case State::HANDOVER_PREPARED:
            return "Handover prepared, waiting for SN status or path switch";
        case State::SN_STATUS_TRANSFERRED:
            return "SN status transferred, waiting for path switch";
        case State::PATH_SWITCH_REQUESTED:
            return "Path switch requested, waiting for bearer modification";
        case State::BEARER_MODIFIED:
            return "Bearer modified, waiting for path switch acknowledgment";
        case State::PATH_SWITCH_ACKNOWLEDGED:
            return "Path switch acknowledged, waiting for context release";
        case State::HANDOVER_COMPLETE:
            return "Handover complete";
        case State::CONTEXT_RELEASED:
            return "Context released, handover completed";
        case State::FAILED:
            return "Handover failed";
        default:
            return "Unknown state";
    }
}

std::string X2HandoverMachine::stateToString(State state) const {
    switch (state) {
        case State::IDLE:
            return "IDLE";
        case State::HANDOVER_REQUESTED:
            return "HANDOVER_REQUESTED";
        case State::HANDOVER_PREPARED:
            return "HANDOVER_PREPARED";
        case State::SN_STATUS_TRANSFERRED:
            return "SN_STATUS_TRANSFERRED";
        case State::PATH_SWITCH_REQUESTED:
            return "PATH_SWITCH_REQUESTED";
        case State::BEARER_MODIFIED:
            return "BEARER_MODIFIED";
        case State::PATH_SWITCH_ACKNOWLEDGED:
            return "PATH_SWITCH_ACKNOWLEDGED";
        case State::HANDOVER_COMPLETE:
            return "HANDOVER_COMPLETE";
        case State::CONTEXT_RELEASED:
            return "CONTEXT_RELEASED";
        case State::FAILED:
            return "FAILED";
        default:
            return "UNKNOWN";
    }
}

nlohmann::json X2HandoverMachine::Metrics::toJson() const {
    nlohmann::json j;

    if (imsi.has_value())
        j["imsi"] = imsi.value();
    if (mme_ue_s1ap_id.has_value())
        j["mme_ue_s1ap_id"] = mme_ue_s1ap_id.value();
    if (old_enb_ue_s1ap_id.has_value())
        j["old_enb_ue_s1ap_id"] = old_enb_ue_s1ap_id.value();
    if (new_enb_ue_s1ap_id.has_value())
        j["new_enb_ue_s1ap_id"] = new_enb_ue_s1ap_id.value();
    if (old_teid_s1u.has_value())
        j["old_teid_s1u"] = old_teid_s1u.value();
    if (new_teid_s1u.has_value())
        j["new_teid_s1u"] = new_teid_s1u.value();
    if (source_enb_id.has_value())
        j["source_enb_id"] = source_enb_id.value();
    if (target_enb_id.has_value())
        j["target_enb_id"] = target_enb_id.value();

    j["timings"] = {
        {"handover_request_to_ack_ms", handover_request_to_ack.count()},
        {"path_switch_to_bearer_modify_ms", path_switch_to_bearer_modify.count()},
        {"bearer_modify_latency_ms", bearer_modify_latency.count()},
        {"handover_preparation_time_ms", handover_preparation_time.count()},
        {"handover_execution_time_ms", handover_execution_time.count()},
        {"total_handover_time_ms", total_handover_time.count()}
    };

    j["performance"] = {
        {"total_within_target", total_handover_time.count() < 500},
        {"preparation_within_target", handover_request_to_ack.count() < 50},
        {"interruption_time_met", interruption_time_met}
    };

    return j;
}

} // namespace correlation
} // namespace callflow
