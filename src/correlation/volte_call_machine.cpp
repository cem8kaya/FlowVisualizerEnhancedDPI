#include "correlation/volte_call_machine.h"

#include "common/logger.h"

namespace callflow {
namespace correlation {

VoLteCallMachine::VoLteCallMachine() {
    LOG_DEBUG("VoLTE Call Setup state machine created");
}

bool VoLteCallMachine::processMessage(const SessionMessageRef& msg) {
    bool state_changed = false;

    switch (current_state_) {
        case State::IDLE:
            // Look for SIP INVITE
            if (msg.message_type == MessageType::SIP_INVITE) {
                start_time_ = msg.timestamp;
                invite_time_ = msg.timestamp;

                // Extract SIP Call-ID
                if (msg.correlation_key.sip_call_id.has_value()) {
                    metrics_.sip_call_id = msg.correlation_key.sip_call_id.value();
                } else if (msg.parsed_data.contains("call_id")) {
                    metrics_.sip_call_id = msg.parsed_data["call_id"].get<std::string>();
                }

                // Extract calling/called numbers
                if (msg.parsed_data.contains("from")) {
                    metrics_.calling_number = msg.parsed_data["from"].get<std::string>();
                }
                if (msg.parsed_data.contains("to")) {
                    metrics_.called_number = msg.parsed_data["to"].get<std::string>();
                }

                // Extract P-Charging-Vector ICID
                if (msg.parsed_data.contains("p_charging_vector") &&
                    msg.parsed_data["p_charging_vector"].contains("icid")) {
                    metrics_.icid = msg.parsed_data["p_charging_vector"]["icid"].get<std::string>();
                }

                // Extract IMSI from P-Asserted-Identity or correlation key
                metrics_.imsi = extractImsi(msg.parsed_data);

                recordStep("SIP INVITE", msg, true);
                transitionTo(State::INVITE_SENT, msg);
                state_changed = true;
            }
            break;

        case State::INVITE_SENT:
            // Look for 100 Trying
            if (msg.message_type == MessageType::SIP_TRYING) {
                trying_time_ = msg.timestamp;
                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                    msg.timestamp - invite_time_);
                metrics_.invite_to_trying = duration;

                recordStep("SIP 100 Trying", msg, true);
                transitionTo(State::TRYING_RECEIVED, msg);
                state_changed = true;
            }
            // Or skip directly to Diameter AAR if no 100 Trying seen
            else if (msg.message_type == MessageType::DIAMETER_AAR) {
                rx_aar_time_ = msg.timestamp;

                recordStep("Diameter Rx AAR", msg, true);
                transitionTo(State::MEDIA_AUTHORIZATION_IN_PROGRESS, msg);
                state_changed = true;
            }
            break;

        case State::TRYING_RECEIVED:
            // Look for Diameter Rx AAR (media authorization request)
            if (msg.message_type == MessageType::DIAMETER_AAR) {
                rx_aar_time_ = msg.timestamp;

                recordStep("Diameter Rx AAR", msg, true);
                transitionTo(State::MEDIA_AUTHORIZATION_IN_PROGRESS, msg);
                state_changed = true;
            }
            break;

        case State::MEDIA_AUTHORIZATION_IN_PROGRESS:
            // Look for Diameter Rx AAA (media authorization answer)
            if (msg.message_type == MessageType::DIAMETER_AAA) {
                rx_aaa_time_ = msg.timestamp;
                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                    msg.timestamp - rx_aar_time_);
                metrics_.media_authorization_time = duration;

                recordStep("Diameter Rx AAA", msg, true);
                transitionTo(State::MEDIA_AUTHORIZED, msg);
                state_changed = true;
            }
            break;

        case State::MEDIA_AUTHORIZED:
            // Look for Diameter Gx RAR (policy push from PCRF)
            if (msg.message_type == MessageType::DIAMETER_RAR) {
                gx_rar_time_ = msg.timestamp;

                // Extract QoS information
                if (msg.parsed_data.contains("qos")) {
                    const auto& qos = msg.parsed_data["qos"];
                    if (qos.contains("qci")) {
                        metrics_.dedicated_bearer_qci = qos["qci"].get<uint8_t>();
                    }
                    if (qos.contains("gbr_ul")) {
                        metrics_.guaranteed_bitrate_ul = qos["gbr_ul"].get<uint32_t>();
                    }
                    if (qos.contains("gbr_dl")) {
                        metrics_.guaranteed_bitrate_dl = qos["gbr_dl"].get<uint32_t>();
                    }
                }

                recordStep("Diameter Gx RAR", msg, true);
                transitionTo(State::POLICY_INSTALLATION_IN_PROGRESS, msg);
                state_changed = true;
            }
            break;

        case State::POLICY_INSTALLATION_IN_PROGRESS:
            // Look for Diameter Gx RAA
            if (msg.message_type == MessageType::DIAMETER_RAA) {
                gx_raa_time_ = msg.timestamp;
                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                    msg.timestamp - gx_rar_time_);
                metrics_.policy_installation_time = duration;

                recordStep("Diameter Gx RAA", msg, true);
                transitionTo(State::POLICY_INSTALLED, msg);
                state_changed = true;
            }
            break;

        case State::POLICY_INSTALLED:
            // Look for GTP Create Bearer Request (dedicated bearer for VoLTE)
            if (msg.message_type == MessageType::GTP_CREATE_BEARER_REQ) {
                bearer_req_time_ = msg.timestamp;

                // Extract bearer information
                if (msg.correlation_key.eps_bearer_id.has_value()) {
                    // Dedicated bearer ID
                }

                recordStep("GTP Create Bearer Request", msg, true);
                transitionTo(State::DEDICATED_BEARER_CREATION_IN_PROGRESS, msg);
                state_changed = true;
            }
            break;

        case State::DEDICATED_BEARER_CREATION_IN_PROGRESS:
            // Look for GTP Create Bearer Response
            if (msg.message_type == MessageType::GTP_CREATE_BEARER_RESP) {
                bearer_resp_time_ = msg.timestamp;
                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                    msg.timestamp - bearer_req_time_);
                metrics_.dedicated_bearer_setup_time = duration;

                // Extract dedicated bearer TEID
                metrics_.dedicated_bearer_teid = extractTeid(msg.parsed_data, "S1-U");

                recordStep("GTP Create Bearer Response", msg, true);
                transitionTo(State::DEDICATED_BEARER_CREATED, msg);
                state_changed = true;
            }
            break;

        case State::DEDICATED_BEARER_CREATED:
            // Look for 180 Ringing
            if (msg.message_type == MessageType::SIP_RINGING) {
                ringing_time_ = msg.timestamp;
                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                    msg.timestamp - invite_time_);
                metrics_.post_dial_delay = duration;

                recordStep("SIP 180 Ringing", msg, true);
                transitionTo(State::RINGING, msg);
                state_changed = true;
            }
            break;

        case State::RINGING:
            // Look for 200 OK
            if (msg.message_type == MessageType::SIP_OK) {
                ok_time_ = msg.timestamp;
                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                    msg.timestamp - invite_time_);
                metrics_.call_setup_time = duration;

                recordStep("SIP 200 OK", msg, true);
                transitionTo(State::CALL_CONNECTED, msg);
                state_changed = true;
            }
            // Handle call rejection
            else if (msg.message_type == MessageType::SIP_BYE ||
                     msg.message_type == MessageType::SIP_CANCEL) {
                recordStep("Call Rejected/Cancelled", msg, false);
                transitionTo(State::FAILED, msg);
                state_changed = true;
            }
            break;

        case State::CALL_CONNECTED:
            // Look for ACK
            if (msg.message_type == MessageType::SIP_ACK) {
                recordStep("SIP ACK", msg, true);
                // Stay in CALL_CONNECTED - wait for media
            }
            // Look for RTP media start (using protocol type since we may not have specific msg type)
            else if (msg.protocol == ProtocolType::RTP) {
                media_start_time_ = msg.timestamp;
                end_time_ = msg.timestamp;
                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                    msg.timestamp - ok_time_);
                metrics_.answer_to_media = duration;

                // Extract RTP SSRC
                if (msg.correlation_key.rtp_ssrc.has_value()) {
                    metrics_.rtp_ssrc = msg.correlation_key.rtp_ssrc.value();
                } else if (msg.parsed_data.contains("ssrc")) {
                    metrics_.rtp_ssrc = msg.parsed_data["ssrc"].get<uint32_t>();
                }

                recordStep("RTP Media Start", msg, true);
                transitionTo(State::MEDIA_ACTIVE, msg);
                state_changed = true;

                LOG_INFO("VoLTE Call Setup completed for Call-ID {} in {}ms "
                        "(PDD: {}ms, bearer setup: {}ms)",
                        metrics_.sip_call_id.value_or("unknown"),
                        metrics_.call_setup_time.count(),
                        metrics_.post_dial_delay.count(),
                        metrics_.dedicated_bearer_setup_time.count());
            }
            break;

        case State::MEDIA_ACTIVE:
            // Call active - could track BYE for call release
            if (msg.message_type == MessageType::SIP_BYE) {
                recordStep("SIP BYE", msg, true);
                transitionTo(State::CALL_RELEASED, msg);
                state_changed = true;
            }
            break;

        case State::CALL_RELEASED:
        case State::FAILED:
            // Terminal states
            break;
    }

    return state_changed;
}

void VoLteCallMachine::transitionTo(State new_state, const SessionMessageRef& msg) {
    (void)msg;  // Parameter used for interface consistency but not needed here
    LOG_DEBUG("VoLTE Call state: {} -> {}", stateToString(current_state_),
             stateToString(new_state));
    current_state_ = new_state;
}

void VoLteCallMachine::recordStep(const std::string& step_name, const SessionMessageRef& msg,
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

std::optional<std::chrono::system_clock::time_point> VoLteCallMachine::getEndTime() const {
    if (current_state_ == State::MEDIA_ACTIVE || current_state_ == State::CALL_RELEASED) {
        return end_time_;
    }
    return std::nullopt;
}

std::optional<std::chrono::milliseconds> VoLteCallMachine::getDuration() const {
    if (current_state_ == State::MEDIA_ACTIVE || current_state_ == State::CALL_RELEASED) {
        return metrics_.call_setup_time;
    }
    return std::nullopt;
}

nlohmann::json VoLteCallMachine::toJson() const {
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

std::string VoLteCallMachine::getStateDescription() const {
    switch (current_state_) {
        case State::IDLE:
            return "Waiting for SIP INVITE";
        case State::INVITE_SENT:
            return "INVITE sent, waiting for response";
        case State::TRYING_RECEIVED:
            return "100 Trying received, waiting for media authorization";
        case State::MEDIA_AUTHORIZATION_IN_PROGRESS:
            return "Media authorization in progress (Diameter Rx)";
        case State::MEDIA_AUTHORIZED:
            return "Media authorized, waiting for policy installation";
        case State::POLICY_INSTALLATION_IN_PROGRESS:
            return "Policy installation in progress (Diameter Gx)";
        case State::POLICY_INSTALLED:
            return "Policy installed, waiting for dedicated bearer";
        case State::DEDICATED_BEARER_CREATION_IN_PROGRESS:
            return "Dedicated bearer being created";
        case State::DEDICATED_BEARER_CREATED:
            return "Dedicated bearer created, waiting for ringing";
        case State::RINGING:
            return "Ringing, waiting for answer";
        case State::CALL_CONNECTED:
            return "Call connected, waiting for media";
        case State::MEDIA_ACTIVE:
            return "Media active, call in progress";
        case State::CALL_RELEASED:
            return "Call released";
        case State::FAILED:
            return "Call setup failed";
        default:
            return "Unknown state";
    }
}

std::string VoLteCallMachine::stateToString(State state) const {
    switch (state) {
        case State::IDLE:
            return "IDLE";
        case State::INVITE_SENT:
            return "INVITE_SENT";
        case State::TRYING_RECEIVED:
            return "TRYING_RECEIVED";
        case State::MEDIA_AUTHORIZATION_IN_PROGRESS:
            return "MEDIA_AUTHORIZATION_IN_PROGRESS";
        case State::MEDIA_AUTHORIZED:
            return "MEDIA_AUTHORIZED";
        case State::POLICY_INSTALLATION_IN_PROGRESS:
            return "POLICY_INSTALLATION_IN_PROGRESS";
        case State::POLICY_INSTALLED:
            return "POLICY_INSTALLED";
        case State::DEDICATED_BEARER_CREATION_IN_PROGRESS:
            return "DEDICATED_BEARER_CREATION_IN_PROGRESS";
        case State::DEDICATED_BEARER_CREATED:
            return "DEDICATED_BEARER_CREATED";
        case State::RINGING:
            return "RINGING";
        case State::CALL_CONNECTED:
            return "CALL_CONNECTED";
        case State::MEDIA_ACTIVE:
            return "MEDIA_ACTIVE";
        case State::CALL_RELEASED:
            return "CALL_RELEASED";
        case State::FAILED:
            return "FAILED";
        default:
            return "UNKNOWN";
    }
}

nlohmann::json VoLteCallMachine::Metrics::toJson() const {
    nlohmann::json j;

    if (sip_call_id.has_value())
        j["sip_call_id"] = sip_call_id.value();
    if (imsi.has_value())
        j["imsi"] = imsi.value();
    if (calling_number.has_value())
        j["calling_number"] = calling_number.value();
    if (called_number.has_value())
        j["called_number"] = called_number.value();
    if (dedicated_bearer_teid.has_value())
        j["dedicated_bearer_teid"] = dedicated_bearer_teid.value();
    if (dedicated_bearer_qci.has_value())
        j["dedicated_bearer_qci"] = dedicated_bearer_qci.value();
    if (icid.has_value())
        j["icid"] = icid.value();
    if (rtp_ssrc.has_value())
        j["rtp_ssrc"] = rtp_ssrc.value();

    j["timings"] = {
        {"invite_to_trying_ms", invite_to_trying.count()},
        {"media_authorization_time_ms", media_authorization_time.count()},
        {"policy_installation_time_ms", policy_installation_time.count()},
        {"dedicated_bearer_setup_time_ms", dedicated_bearer_setup_time.count()},
        {"post_dial_delay_ms", post_dial_delay.count()},
        {"call_setup_time_ms", call_setup_time.count()},
        {"answer_to_media_ms", answer_to_media.count()}
    };

    if (guaranteed_bitrate_ul.has_value() || guaranteed_bitrate_dl.has_value()) {
        nlohmann::json qos;
        if (guaranteed_bitrate_ul.has_value())
            qos["gbr_ul_kbps"] = guaranteed_bitrate_ul.value();
        if (guaranteed_bitrate_dl.has_value())
            qos["gbr_dl_kbps"] = guaranteed_bitrate_dl.value();
        j["qos"] = qos;
    }

    j["performance"] = {
        {"call_setup_within_target", call_setup_time.count() < 3000},  // 3 seconds
        {"pdd_within_target", post_dial_delay.count() < 2000},         // 2 seconds
        {"qci_correct", dedicated_bearer_qci.value_or(0) == 1}         // QCI 1 for voice
    };

    return j;
}

} // namespace correlation
} // namespace callflow
