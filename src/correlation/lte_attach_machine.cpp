#include "correlation/lte_attach_machine.h"

#include "common/logger.h"

namespace callflow {
namespace correlation {

LteAttachMachine::LteAttachMachine() {
    LOG_DEBUG("LTE Attach state machine created");
}

bool LteAttachMachine::processMessage(const SessionMessageRef& msg) {
    bool state_changed = false;

    switch (current_state_) {
        case State::IDLE:
            // Look for Initial UE Message with Attach Request
            if (msg.message_type == MessageType::S1AP_INITIAL_UE_MESSAGE &&
                hasNasMessageType(msg.parsed_data, MessageType::NAS_ATTACH_REQUEST)) {

                start_time_ = msg.timestamp;
                attach_request_time_ = msg.timestamp;
                last_message_time_ = msg.timestamp;

                // Extract IMSI
                metrics_.imsi = extractImsi(msg.parsed_data);

                // Extract MME-UE-S1AP-ID and eNB-UE-S1AP-ID
                if (msg.correlation_key.mme_ue_s1ap_id.has_value()) {
                    metrics_.mme_ue_s1ap_id = msg.correlation_key.mme_ue_s1ap_id.value();
                }
                if (msg.correlation_key.enb_ue_s1ap_id.has_value()) {
                    metrics_.enb_ue_s1ap_id = msg.correlation_key.enb_ue_s1ap_id.value();
                }

                // Extract APN if available
                if (msg.correlation_key.apn.has_value()) {
                    metrics_.apn = msg.correlation_key.apn.value();
                }

                recordStep("Attach Request", msg, true);
                transitionTo(State::ATTACH_REQUESTED, msg);
                state_changed = true;
            }
            break;

        case State::ATTACH_REQUESTED:
            // Look for Authentication Request
            if (msg.message_type == MessageType::S1AP_DOWNLINK_NAS_TRANSPORT &&
                hasNasMessageType(msg.parsed_data, MessageType::NAS_AUTHENTICATION_REQUEST)) {

                auth_request_time_ = msg.timestamp;
                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                    msg.timestamp - attach_request_time_);
                metrics_.attach_request_to_auth_request = duration;
                last_message_time_ = msg.timestamp;

                recordStep("Authentication Request", msg, true);
                transitionTo(State::AUTHENTICATION_IN_PROGRESS, msg);
                state_changed = true;
            }
            break;

        case State::AUTHENTICATION_IN_PROGRESS:
            // Look for Authentication Response
            if (msg.message_type == MessageType::S1AP_UPLINK_NAS_TRANSPORT &&
                hasNasMessageType(msg.parsed_data, MessageType::NAS_AUTHENTICATION_RESPONSE)) {

                auth_response_time_ = msg.timestamp;
                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                    msg.timestamp - auth_request_time_);
                metrics_.auth_request_to_auth_response = duration;
                last_message_time_ = msg.timestamp;

                recordStep("Authentication Response", msg, true);
                transitionTo(State::AUTHENTICATION_COMPLETE, msg);
                state_changed = true;
            } else if (msg.message_type == MessageType::S1AP_UPLINK_NAS_TRANSPORT &&
                       hasNasMessageType(msg.parsed_data,
                                         MessageType::NAS_AUTHENTICATION_FAILURE)) {
                recordStep("Authentication Failure", msg, false);
                transitionTo(State::FAILED, msg);
                state_changed = true;
            }
            break;

        case State::AUTHENTICATION_COMPLETE:
            // Look for Security Mode Command
            if (msg.message_type == MessageType::S1AP_DOWNLINK_NAS_TRANSPORT &&
                hasNasMessageType(msg.parsed_data, MessageType::NAS_SECURITY_MODE_COMMAND)) {

                security_mode_cmd_time_ = msg.timestamp;
                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                    msg.timestamp - auth_response_time_);
                metrics_.auth_to_security_mode = duration;
                last_message_time_ = msg.timestamp;

                recordStep("Security Mode Command", msg, true);
                transitionTo(State::SECURITY_MODE_IN_PROGRESS, msg);
                state_changed = true;
            }
            break;

        case State::SECURITY_MODE_IN_PROGRESS:
            // Look for Security Mode Complete
            if (msg.message_type == MessageType::S1AP_UPLINK_NAS_TRANSPORT &&
                hasNasMessageType(msg.parsed_data, MessageType::NAS_SECURITY_MODE_COMPLETE)) {

                security_mode_complete_time_ = msg.timestamp;
                last_message_time_ = msg.timestamp;

                recordStep("Security Mode Complete", msg, true);
                transitionTo(State::SECURITY_MODE_COMPLETE, msg);
                state_changed = true;
            }
            break;

        case State::SECURITY_MODE_COMPLETE:
            // Look for GTP Create Session Request
            if (msg.message_type == MessageType::GTP_CREATE_SESSION_REQ) {

                gtp_create_time_ = msg.timestamp;
                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                    msg.timestamp - security_mode_complete_time_);
                metrics_.security_mode_to_gtp_create = duration;
                last_message_time_ = msg.timestamp;

                recordStep("GTP Create Session Request", msg, true);
                transitionTo(State::GTP_SESSION_CREATION_IN_PROGRESS, msg);
                state_changed = true;
            }
            break;

        case State::GTP_SESSION_CREATION_IN_PROGRESS:
            // Look for GTP Create Session Response
            if (msg.message_type == MessageType::GTP_CREATE_SESSION_RESP) {

                gtp_response_time_ = msg.timestamp;
                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                    msg.timestamp - gtp_create_time_);
                metrics_.gtp_create_to_gtp_response = duration;
                last_message_time_ = msg.timestamp;

                // Extract TEID and UE IP
                metrics_.teid_s1u = extractTeid(msg.parsed_data, "S1-U");
                if (msg.correlation_key.ue_ipv4.has_value()) {
                    metrics_.ue_ip = msg.correlation_key.ue_ipv4.value();
                } else if (msg.parsed_data.contains("ue_ip_address")) {
                    if (msg.parsed_data["ue_ip_address"].contains("ipv4")) {
                        metrics_.ue_ip = msg.parsed_data["ue_ip_address"]["ipv4"].get<std::string>();
                    }
                }

                recordStep("GTP Create Session Response", msg, true);
                transitionTo(State::GTP_SESSION_CREATED, msg);
                state_changed = true;
            }
            break;

        case State::GTP_SESSION_CREATED:
            // Look for Initial Context Setup Request
            if (msg.message_type == MessageType::S1AP_INITIAL_CONTEXT_SETUP_REQ) {

                context_setup_time_ = msg.timestamp;
                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                    msg.timestamp - gtp_response_time_);
                metrics_.gtp_response_to_context_setup = duration;
                last_message_time_ = msg.timestamp;

                recordStep("Initial Context Setup Request", msg, true);
                transitionTo(State::INITIAL_CONTEXT_SETUP_IN_PROGRESS, msg);
                state_changed = true;
            }
            break;

        case State::INITIAL_CONTEXT_SETUP_IN_PROGRESS:
            // Initial Context Setup Response (acknowledgment, doesn't change timing)
            if (msg.message_type == MessageType::S1AP_INITIAL_CONTEXT_SETUP_RESP) {
                recordStep("Initial Context Setup Response", msg, true);
                last_message_time_ = msg.timestamp;
                // Don't change state - wait for Attach Accept
            }
            // Look for Attach Accept (may come before or after Setup Response)
            else if (msg.message_type == MessageType::S1AP_DOWNLINK_NAS_TRANSPORT &&
                     hasNasMessageType(msg.parsed_data, MessageType::NAS_ATTACH_ACCEPT)) {

                attach_accept_time_ = msg.timestamp;
                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                    msg.timestamp - context_setup_time_);
                metrics_.context_setup_to_attach_accept = duration;
                last_message_time_ = msg.timestamp;

                recordStep("Attach Accept", msg, true);
                transitionTo(State::ATTACH_ACCEPTED, msg);
                state_changed = true;
            }
            break;

        case State::ATTACH_ACCEPTED:
            // Look for Attach Complete
            if (msg.message_type == MessageType::S1AP_UPLINK_NAS_TRANSPORT &&
                hasNasMessageType(msg.parsed_data, MessageType::NAS_ATTACH_COMPLETE)) {

                end_time_ = msg.timestamp;
                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                    msg.timestamp - attach_accept_time_);
                metrics_.attach_accept_to_complete = duration;

                // Calculate total attach time
                metrics_.total_attach_time = std::chrono::duration_cast<std::chrono::milliseconds>(
                    msg.timestamp - attach_request_time_);

                recordStep("Attach Complete", msg, true);
                transitionTo(State::ATTACHED, msg);
                state_changed = true;

                LOG_INFO("LTE Attach completed for IMSI {} in {}ms",
                        metrics_.imsi.value_or("unknown"), metrics_.total_attach_time.count());
            }
            break;

        case State::ATTACHED:
            // Procedure complete, no more transitions
            break;

        case State::FAILED:
            // Procedure failed, no recovery
            break;
    }

    return state_changed;
}

void LteAttachMachine::transitionTo(State new_state, const SessionMessageRef& msg) {
    LOG_DEBUG("LTE Attach state: {} -> {}", stateToString(current_state_),
             stateToString(new_state));
    current_state_ = new_state;
}

void LteAttachMachine::recordStep(const std::string& step_name, const SessionMessageRef& msg,
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

std::optional<std::chrono::system_clock::time_point> LteAttachMachine::getEndTime() const {
    if (current_state_ == State::ATTACHED) {
        return end_time_;
    }
    return std::nullopt;
}

std::optional<std::chrono::milliseconds> LteAttachMachine::getDuration() const {
    if (current_state_ == State::ATTACHED) {
        return metrics_.total_attach_time;
    }
    return std::nullopt;
}

nlohmann::json LteAttachMachine::toJson() const {
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

std::string LteAttachMachine::getStateDescription() const {
    switch (current_state_) {
        case State::IDLE:
            return "Waiting for Attach Request";
        case State::ATTACH_REQUESTED:
            return "Attach requested, waiting for authentication";
        case State::AUTHENTICATION_IN_PROGRESS:
            return "Authentication in progress";
        case State::AUTHENTICATION_COMPLETE:
            return "Authentication complete, waiting for security mode";
        case State::SECURITY_MODE_IN_PROGRESS:
            return "Security mode command in progress";
        case State::SECURITY_MODE_COMPLETE:
            return "Security established, waiting for GTP session creation";
        case State::GTP_SESSION_CREATION_IN_PROGRESS:
            return "GTP session being created";
        case State::GTP_SESSION_CREATED:
            return "GTP session created, waiting for context setup";
        case State::INITIAL_CONTEXT_SETUP_IN_PROGRESS:
            return "Initial context setup in progress";
        case State::ATTACH_ACCEPTED:
            return "Attach accepted, waiting for completion";
        case State::ATTACHED:
            return "Attach procedure completed successfully";
        case State::FAILED:
            return "Attach procedure failed";
        default:
            return "Unknown state";
    }
}

std::string LteAttachMachine::stateToString(State state) const {
    switch (state) {
        case State::IDLE:
            return "IDLE";
        case State::ATTACH_REQUESTED:
            return "ATTACH_REQUESTED";
        case State::AUTHENTICATION_IN_PROGRESS:
            return "AUTHENTICATION_IN_PROGRESS";
        case State::AUTHENTICATION_COMPLETE:
            return "AUTHENTICATION_COMPLETE";
        case State::SECURITY_MODE_IN_PROGRESS:
            return "SECURITY_MODE_IN_PROGRESS";
        case State::SECURITY_MODE_COMPLETE:
            return "SECURITY_MODE_COMPLETE";
        case State::GTP_SESSION_CREATION_IN_PROGRESS:
            return "GTP_SESSION_CREATION_IN_PROGRESS";
        case State::GTP_SESSION_CREATED:
            return "GTP_SESSION_CREATED";
        case State::INITIAL_CONTEXT_SETUP_IN_PROGRESS:
            return "INITIAL_CONTEXT_SETUP_IN_PROGRESS";
        case State::ATTACH_ACCEPTED:
            return "ATTACH_ACCEPTED";
        case State::ATTACHED:
            return "ATTACHED";
        case State::FAILED:
            return "FAILED";
        default:
            return "UNKNOWN";
    }
}

nlohmann::json LteAttachMachine::Metrics::toJson() const {
    nlohmann::json j;

    if (imsi.has_value())
        j["imsi"] = imsi.value();
    if (mme_ue_s1ap_id.has_value())
        j["mme_ue_s1ap_id"] = mme_ue_s1ap_id.value();
    if (enb_ue_s1ap_id.has_value())
        j["enb_ue_s1ap_id"] = enb_ue_s1ap_id.value();
    if (teid_s1u.has_value())
        j["teid_s1u"] = teid_s1u.value();
    if (ue_ip.has_value())
        j["ue_ip"] = ue_ip.value();
    if (apn.has_value())
        j["apn"] = apn.value();

    j["timings"] = {
        {"attach_to_auth_ms", attach_request_to_auth_request.count()},
        {"auth_req_to_resp_ms", auth_request_to_auth_response.count()},
        {"auth_to_security_ms", auth_to_security_mode.count()},
        {"security_to_gtp_ms", security_mode_to_gtp_create.count()},
        {"gtp_create_latency_ms", gtp_create_to_gtp_response.count()},
        {"gtp_to_context_setup_ms", gtp_response_to_context_setup.count()},
        {"context_to_accept_ms", context_setup_to_attach_accept.count()},
        {"accept_to_complete_ms", attach_accept_to_complete.count()},
        {"total_attach_time_ms", total_attach_time.count()}
    };

    // Add performance indicators
    nlohmann::json perf;
    perf["total_within_target"] = (total_attach_time.count() < 1000);
    perf["gtp_within_target"] = (gtp_create_to_gtp_response.count() < 200);
    perf["auth_within_target"] = (auth_request_to_auth_response.count() < 100);
    j["performance"] = perf;

    return j;
}

} // namespace correlation
} // namespace callflow
