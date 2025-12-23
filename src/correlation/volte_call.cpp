#include "correlation/volte_call.h"
#include <algorithm>
#include <spdlog/spdlog.h>

namespace callflow {
namespace correlation {

// ============================================================================
// VolteCall::SipLeg JSON serialization
// ============================================================================

nlohmann::json VolteCall::SipLeg::toJson() const {
    nlohmann::json j;
    j["session_id"] = session_id;
    j["call_id"] = call_id;
    j["from_uri"] = from_uri;
    j["to_uri"] = to_uri;
    j["p_cscf_ip"] = p_cscf_ip;

    // Timestamps
    j["invite_time"] = std::chrono::system_clock::to_time_t(invite_time);
    if (trying_time) {
        j["trying_time"] = std::chrono::system_clock::to_time_t(*trying_time);
    }
    if (ringing_time) {
        j["ringing_time"] = std::chrono::system_clock::to_time_t(*ringing_time);
    }
    if (answer_time) {
        j["answer_time"] = std::chrono::system_clock::to_time_t(*answer_time);
    }
    if (ack_time) {
        j["ack_time"] = std::chrono::system_clock::to_time_t(*ack_time);
    }
    if (bye_time) {
        j["bye_time"] = std::chrono::system_clock::to_time_t(*bye_time);
    }

    // Media
    j["audio_codec"] = audio_codec;
    j["rtp_port_local"] = rtp_port_local;
    j["rtp_port_remote"] = rtp_port_remote;
    j["remote_ip"] = remote_ip;

    return j;
}

// ============================================================================
// VolteCall::RxLeg JSON serialization
// ============================================================================

nlohmann::json VolteCall::RxLeg::toJson() const {
    nlohmann::json j;
    j["session_id"] = session_id;
    j["af_app_id"] = af_app_id;
    j["framed_ip"] = framed_ip;
    j["aar_time"] = std::chrono::system_clock::to_time_t(aar_time);
    if (aaa_time) {
        j["aaa_time"] = std::chrono::system_clock::to_time_t(*aaa_time);
    }
    j["result_code"] = result_code;

    nlohmann::json components = nlohmann::json::array();
    for (const auto& mc : media_components) {
        nlohmann::json comp;
        comp["flow_number"] = mc.flow_number;
        comp["media_type"] = mc.media_type;
        comp["max_bandwidth_ul"] = mc.max_bandwidth_ul;
        comp["max_bandwidth_dl"] = mc.max_bandwidth_dl;
        comp["flow_description"] = mc.flow_description;
        components.push_back(comp);
    }
    j["media_components"] = components;

    return j;
}

// ============================================================================
// VolteCall::GxLeg JSON serialization
// ============================================================================

nlohmann::json VolteCall::GxLeg::toJson() const {
    nlohmann::json j;
    j["session_id"] = session_id;
    j["framed_ip"] = framed_ip;
    j["rar_time"] = std::chrono::system_clock::to_time_t(rar_time);
    if (raa_time) {
        j["raa_time"] = std::chrono::system_clock::to_time_t(*raa_time);
    }

    nlohmann::json rules = nlohmann::json::array();
    for (const auto& rule : charging_rules) {
        nlohmann::json r;
        r["rule_name"] = rule.rule_name;
        r["qci"] = rule.qci;
        r["guaranteed_bandwidth_ul"] = rule.guaranteed_bandwidth_ul;
        r["guaranteed_bandwidth_dl"] = rule.guaranteed_bandwidth_dl;
        rules.push_back(r);
    }
    j["charging_rules"] = rules;

    return j;
}

// ============================================================================
// VolteCall::BearerLeg JSON serialization
// ============================================================================

nlohmann::json VolteCall::BearerLeg::toJson() const {
    nlohmann::json j;
    j["session_id"] = session_id;
    j["teid_uplink"] = teid_uplink;
    j["teid_downlink"] = teid_downlink;
    j["eps_bearer_id"] = eps_bearer_id;
    j["qci"] = qci;
    j["gbr_ul"] = gbr_ul;
    j["gbr_dl"] = gbr_dl;
    j["request_time"] = std::chrono::system_clock::to_time_t(request_time);
    if (response_time) {
        j["response_time"] = std::chrono::system_clock::to_time_t(*response_time);
    }
    j["cause"] = cause;
    return j;
}

// ============================================================================
// VolteCall::RtpLeg JSON serialization
// ============================================================================

nlohmann::json VolteCall::RtpLeg::toJson() const {
    nlohmann::json j;
    j["ssrc"] = ssrc;
    j["local_ip"] = local_ip;
    j["local_port"] = local_port;
    j["remote_ip"] = remote_ip;
    j["remote_port"] = remote_port;

    nlohmann::json ul;
    ul["packets"] = uplink.packets;
    ul["bytes"] = uplink.bytes;
    ul["packet_loss_rate"] = uplink.packet_loss_rate;
    ul["jitter_ms"] = uplink.jitter_ms;
    ul["mos_estimate"] = uplink.mos_estimate;
    if (uplink.packets > 0) {
        ul["first_packet"] = std::chrono::system_clock::to_time_t(uplink.first_packet);
        ul["last_packet"] = std::chrono::system_clock::to_time_t(uplink.last_packet);
    }
    j["uplink"] = ul;

    nlohmann::json dl;
    dl["packets"] = downlink.packets;
    dl["bytes"] = downlink.bytes;
    dl["packet_loss_rate"] = downlink.packet_loss_rate;
    dl["jitter_ms"] = downlink.jitter_ms;
    dl["mos_estimate"] = downlink.mos_estimate;
    if (downlink.packets > 0) {
        dl["first_packet"] = std::chrono::system_clock::to_time_t(downlink.first_packet);
        dl["last_packet"] = std::chrono::system_clock::to_time_t(downlink.last_packet);
    }
    j["downlink"] = dl;

    return j;
}

// ============================================================================
// VolteCall::Metrics JSON serialization
// ============================================================================

nlohmann::json VolteCall::Metrics::toJson() const {
    nlohmann::json j;
    j["setup_time_ms"] = setup_time.count();
    j["post_dial_delay_ms"] = post_dial_delay.count();
    j["answer_delay_ms"] = answer_delay.count();
    j["bearer_setup_time_ms"] = bearer_setup_time.count();
    j["rx_authorization_time_ms"] = rx_authorization_time.count();
    j["total_call_duration_ms"] = total_call_duration.count();
    j["media_duration_ms"] = media_duration.count();
    j["avg_mos"] = avg_mos;
    j["packet_loss_rate"] = packet_loss_rate;
    j["jitter_ms"] = jitter_ms;
    return j;
}

// ============================================================================
// VolteCall methods
// ============================================================================

bool VolteCall::isComplete() const {
    return state == State::COMPLETED || state == State::FAILED || state == State::CANCELLED;
}

bool VolteCall::isFailed() const {
    return state == State::FAILED || state == State::CANCELLED;
}

bool VolteCall::hasMedia() const {
    return rtp_leg.has_value() &&
           (rtp_leg->uplink.packets > 0 || rtp_leg->downlink.packets > 0);
}

nlohmann::json VolteCall::toJson() const {
    nlohmann::json j;

    // Identifiers
    j["call_id"] = call_id;
    j["icid"] = icid;
    j["imsi"] = imsi;
    j["msisdn"] = msisdn;
    j["calling_number"] = calling_number;
    j["called_number"] = called_number;

    // State
    j["state"] = static_cast<int>(state);
    j["state_name"] = [this]() {
        switch (state) {
            case State::INITIATING: return "INITIATING";
            case State::TRYING: return "TRYING";
            case State::RINGING: return "RINGING";
            case State::ANSWERED: return "ANSWERED";
            case State::CONFIRMED: return "CONFIRMED";
            case State::MEDIA_ACTIVE: return "MEDIA_ACTIVE";
            case State::TERMINATING: return "TERMINATING";
            case State::COMPLETED: return "COMPLETED";
            case State::FAILED: return "FAILED";
            case State::CANCELLED: return "CANCELLED";
            default: return "UNKNOWN";
        }
    }();
    j["state_reason"] = state_reason;

    // Legs
    j["sip_leg"] = sip_leg.toJson();
    if (rx_leg) {
        j["rx_leg"] = rx_leg->toJson();
    }
    if (gx_leg) {
        j["gx_leg"] = gx_leg->toJson();
    }
    if (bearer_leg) {
        j["bearer_leg"] = bearer_leg->toJson();
    }
    if (rtp_leg) {
        j["rtp_leg"] = rtp_leg->toJson();
    }

    // Metrics
    j["metrics"] = metrics.toJson();

    // Timestamps
    j["start_time"] = std::chrono::system_clock::to_time_t(start_time);
    j["end_time"] = std::chrono::system_clock::to_time_t(end_time);

    return j;
}

nlohmann::json VolteCall::toLadderDiagramJson() const {
    nlohmann::json diagram;
    diagram["call_id"] = call_id;
    diagram["type"] = "volte_call";

    // Participants
    diagram["participants"] = nlohmann::json::array({
        {{"id", "ue"}, {"name", "UE (" + msisdn + ")"}},
        {{"id", "pcscf"}, {"name", "P-CSCF"}},
        {{"id", "pcrf"}, {"name", "PCRF"}},
        {{"id", "pgw"}, {"name", "PGW"}},
        {{"id", "sgw"}, {"name", "SGW"}},
        {{"id", "remote"}, {"name", "Remote Party"}}
    });

    // Messages in chronological order
    nlohmann::json messages = nlohmann::json::array();

    // SIP signaling
    messages.push_back({
        {"timestamp", std::chrono::system_clock::to_time_t(sip_leg.invite_time)},
        {"from", "ue"},
        {"to", "pcscf"},
        {"protocol", "SIP"},
        {"message", "INVITE"},
        {"details", "Call-ID: " + call_id}
    });

    if (sip_leg.trying_time) {
        messages.push_back({
            {"timestamp", std::chrono::system_clock::to_time_t(*sip_leg.trying_time)},
            {"from", "pcscf"},
            {"to", "ue"},
            {"protocol", "SIP"},
            {"message", "100 Trying"},
            {"details", ""}
        });
    }

    // DIAMETER Rx (if present)
    if (rx_leg) {
        messages.push_back({
            {"timestamp", std::chrono::system_clock::to_time_t(rx_leg->aar_time)},
            {"from", "pcscf"},
            {"to", "pcrf"},
            {"protocol", "DIAMETER Rx"},
            {"message", "AAR"},
            {"details", "Media authorization request"}
        });

        if (rx_leg->aaa_time) {
            messages.push_back({
                {"timestamp", std::chrono::system_clock::to_time_t(*rx_leg->aaa_time)},
                {"from", "pcrf"},
                {"to", "pcscf"},
                {"protocol", "DIAMETER Rx"},
                {"message", "AAA"},
                {"details", "Result-Code: " + std::to_string(rx_leg->result_code)}
            });
        }
    }

    // DIAMETER Gx (if present)
    if (gx_leg) {
        messages.push_back({
            {"timestamp", std::chrono::system_clock::to_time_t(gx_leg->rar_time)},
            {"from", "pcrf"},
            {"to", "pgw"},
            {"protocol", "DIAMETER Gx"},
            {"message", "RAR"},
            {"details", "Policy installation"}
        });

        if (gx_leg->raa_time) {
            messages.push_back({
                {"timestamp", std::chrono::system_clock::to_time_t(*gx_leg->raa_time)},
                {"from", "pgw"},
                {"to", "pcrf"},
                {"protocol", "DIAMETER Gx"},
                {"message", "RAA"},
                {"details", "Policy acknowledged"}
            });
        }
    }

    // GTP bearer creation (if present)
    if (bearer_leg) {
        messages.push_back({
            {"timestamp", std::chrono::system_clock::to_time_t(bearer_leg->request_time)},
            {"from", "pgw"},
            {"to", "sgw"},
            {"protocol", "GTP-C"},
            {"message", "Create Bearer Request"},
            {"details", "QCI=" + std::to_string(bearer_leg->qci) + " EBI=" + std::to_string(bearer_leg->eps_bearer_id)}
        });

        if (bearer_leg->response_time) {
            messages.push_back({
                {"timestamp", std::chrono::system_clock::to_time_t(*bearer_leg->response_time)},
                {"from", "sgw"},
                {"to", "pgw"},
                {"protocol", "GTP-C"},
                {"message", "Create Bearer Response"},
                {"details", "Cause=" + std::to_string(bearer_leg->cause)}
            });
        }
    }

    // SIP ringing/answer
    if (sip_leg.ringing_time) {
        messages.push_back({
            {"timestamp", std::chrono::system_clock::to_time_t(*sip_leg.ringing_time)},
            {"from", "pcscf"},
            {"to", "ue"},
            {"protocol", "SIP"},
            {"message", "180 Ringing"},
            {"details", ""}
        });
    }

    if (sip_leg.answer_time) {
        messages.push_back({
            {"timestamp", std::chrono::system_clock::to_time_t(*sip_leg.answer_time)},
            {"from", "pcscf"},
            {"to", "ue"},
            {"protocol", "SIP"},
            {"message", "200 OK"},
            {"details", ""}
        });
    }

    if (sip_leg.ack_time) {
        messages.push_back({
            {"timestamp", std::chrono::system_clock::to_time_t(*sip_leg.ack_time)},
            {"from", "ue"},
            {"to", "pcscf"},
            {"protocol", "SIP"},
            {"message", "ACK"},
            {"details", ""}
        });
    }

    // RTP media (if present)
    if (rtp_leg && rtp_leg->uplink.packets > 0) {
        messages.push_back({
            {"timestamp", std::chrono::system_clock::to_time_t(rtp_leg->uplink.first_packet)},
            {"from", "ue"},
            {"to", "remote"},
            {"protocol", "RTP"},
            {"message", "Media Start"},
            {"details", "SSRC: " + std::to_string(rtp_leg->ssrc)}
        });
    }

    // SIP BYE
    if (sip_leg.bye_time) {
        messages.push_back({
            {"timestamp", std::chrono::system_clock::to_time_t(*sip_leg.bye_time)},
            {"from", "ue"},
            {"to", "pcscf"},
            {"protocol", "SIP"},
            {"message", "BYE"},
            {"details", ""}
        });
    }

    // Sort messages by timestamp
    std::sort(messages.begin(), messages.end(),
        [](const nlohmann::json& a, const nlohmann::json& b) {
            return a["timestamp"] < b["timestamp"];
        });

    diagram["messages"] = messages;
    diagram["metrics"] = metrics.toJson();

    return diagram;
}

// ============================================================================
// VolteCallCorrelator implementation
// ============================================================================

VolteCallCorrelator::VolteCallCorrelator(std::shared_ptr<SubscriberContextManager> context_mgr)
    : context_mgr_(context_mgr) {
    spdlog::info("VolteCallCorrelator initialized");
}

void VolteCallCorrelator::processSipMessage(const session::SessionMessageRef& msg,
                                           const protocol::SipMessage& sip) {
    if (sip.call_id.empty()) {
        spdlog::warn("SIP message without Call-ID, skipping");
        return;
    }

    std::shared_ptr<VolteCall> call = findByCallId(sip.call_id);

    // Handle INVITE - create new call
    if (sip.is_request && sip.method == "INVITE") {
        if (!call) {
            call = std::make_shared<VolteCall>();
            call->call_id = sip.call_id;
            call->start_time = msg.timestamp;
            call->state = VolteCall::State::INITIATING;

            // Extract basic info
            call->sip_leg.session_id = msg.message_id;
            call->sip_leg.call_id = sip.call_id;
            call->sip_leg.from_uri = sip.from;
            call->sip_leg.to_uri = sip.to;
            call->sip_leg.p_cscf_ip = msg.dst_ip;  // P-CSCF is destination of INVITE
            call->sip_leg.invite_time = msg.timestamp;

            // Extract calling/called numbers
            if (sip.p_asserted_identity && !sip.p_asserted_identity->empty()) {
                call->calling_number = (*sip.p_asserted_identity)[0].uri;
            }
            call->called_number = sip.request_uri;

            // Extract ICID for billing correlation
            if (sip.p_charging_vector) {
                call->icid = sip.p_charging_vector->icid;
                icid_to_call_id_[call->icid] = call->call_id;

                // Register ICID with subscriber context
                auto imsi_opt = resolveImsiByIp(msg.src_ip);
                if (imsi_opt) {
                    call->imsi = *imsi_opt;
                    auto ctx = context_mgr_->findByImsi(call->imsi);
                    if (ctx) {
                        ctx->icids.insert(call->icid);
                    }
                }
            }

            // Extract SDP info
            if (sip.sdp) {
                for (const auto& media : sip.sdp->media_descriptions) {
                    if (media.media_type == "audio") {
                        call->sip_leg.rtp_port_local = media.port;
                        if (!media.rtpmap.empty()) {
                            call->sip_leg.audio_codec = media.rtpmap[0].encoding_name;
                        }
                    }
                }
            }

            // Resolve subscriber identity
            if (call->imsi.empty()) {
                auto imsi_opt = extractImsiFromSip(sip);
                if (imsi_opt) {
                    call->imsi = *imsi_opt;
                } else {
                    // Try by source IP
                    imsi_opt = resolveImsiByIp(msg.src_ip);
                    if (imsi_opt) {
                        call->imsi = *imsi_opt;
                    }
                }
            }

            // Index the call
            calls_by_call_id_[call->call_id] = call;
            if (!call->imsi.empty()) {
                imsi_to_call_ids_.emplace(call->imsi, call->call_id);
            }

            spdlog::info("Created new VoLTE call: Call-ID={}, ICID={}, IMSI={}, calling={}, called={}",
                        call->call_id, call->icid, call->imsi, call->calling_number, call->called_number);
        }
    }

    if (!call) {
        spdlog::debug("SIP message for unknown call: {}", sip.call_id);
        return;
    }

    // Handle SIP responses
    if (!sip.is_request) {
        if (sip.status_code == 100) {
            // 100 Trying
            call->sip_leg.trying_time = msg.timestamp;
            updateCallState(call, VolteCall::State::TRYING, "100 Trying");
        } else if (sip.status_code == 180 || sip.status_code == 183) {
            // 180 Ringing or 183 Session Progress
            call->sip_leg.ringing_time = msg.timestamp;
            updateCallState(call, VolteCall::State::RINGING, std::to_string(sip.status_code) + " " + sip.reason_phrase);
        } else if (sip.status_code == 200) {
            // 200 OK
            call->sip_leg.answer_time = msg.timestamp;

            // Extract remote SDP info
            if (sip.sdp) {
                call->sip_leg.remote_ip = sip.sdp->connection_address;
                for (const auto& media : sip.sdp->media_descriptions) {
                    if (media.media_type == "audio") {
                        call->sip_leg.rtp_port_remote = media.port;
                    }
                }
            }

            updateCallState(call, VolteCall::State::ANSWERED, "200 OK");
        } else if (sip.status_code >= 300) {
            // Failure response
            updateCallState(call, VolteCall::State::FAILED,
                          std::to_string(sip.status_code) + " " + sip.reason_phrase);
        }
    }

    // Handle ACK
    if (sip.is_request && sip.method == "ACK") {
        call->sip_leg.ack_time = msg.timestamp;
        updateCallState(call, VolteCall::State::CONFIRMED, "ACK");
    }

    // Handle BYE
    if (sip.is_request && sip.method == "BYE") {
        call->sip_leg.bye_time = msg.timestamp;
        call->end_time = msg.timestamp;
        updateCallState(call, VolteCall::State::TERMINATING, "BYE");
        updateCallState(call, VolteCall::State::COMPLETED, "Call ended normally");
    }

    // Handle CANCEL
    if (sip.is_request && sip.method == "CANCEL") {
        call->end_time = msg.timestamp;
        updateCallState(call, VolteCall::State::CANCELLED, "CANCEL");
    }
}

void VolteCallCorrelator::processDiameterRx(const session::SessionMessageRef& msg,
                                           const protocol::DiameterMessage& dia) {
    // Extract session ID and ICID for correlation
    std::string session_id = dia.session_id.value_or("");
    std::string icid;
    std::string framed_ip;

    // Parse AVPs for ICID and Framed-IP-Address
    // Note: In real implementation, you'd need to parse specific AVPs
    // For now, we'll use the correlation key
    if (msg.correlation_key.icid) {
        icid = *msg.correlation_key.icid;
    }
    if (msg.correlation_key.ue_ipv4) {
        framed_ip = *msg.correlation_key.ue_ipv4;
    }

    // Find call by ICID
    std::shared_ptr<VolteCall> call;
    if (!icid.empty()) {
        call = findByIcid(icid);
    }

    // If not found by ICID, try by UE IP and recent call
    if (!call && !framed_ip.empty()) {
        auto imsi_opt = resolveImsiByIp(framed_ip);
        if (imsi_opt) {
            auto calls = findByImsi(*imsi_opt);
            // Find most recent active call
            for (auto& c : calls) {
                if (!c->isComplete()) {
                    call = c;
                    break;
                }
            }
        }
    }

    if (!call) {
        spdlog::debug("DIAMETER Rx message for unknown call, ICID={}", icid);
        return;
    }

    // Determine message type
    auto msg_type = dia.getMessageType();

    if (msg_type == session::MessageType::DIAMETER_AAR) {
        // AAR - Media authorization request
        if (!call->rx_leg) {
            call->rx_leg = VolteCall::RxLeg();
        }
        call->rx_leg->session_id = session_id;
        call->rx_leg->framed_ip = framed_ip;
        call->rx_leg->aar_time = msg.timestamp;

        // Register index
        if (!session_id.empty()) {
            rx_session_to_call_id_[session_id] = call->call_id;
        }

        spdlog::debug("Correlated DIAMETER Rx AAR to call {}", call->call_id);

    } else if (msg_type == session::MessageType::DIAMETER_AAA) {
        // AAA - Media authorization answer
        if (!call->rx_leg) {
            call->rx_leg = VolteCall::RxLeg();
        }
        call->rx_leg->aaa_time = msg.timestamp;
        if (dia.result_code) {
            call->rx_leg->result_code = *dia.result_code;
        }

        spdlog::debug("Correlated DIAMETER Rx AAA to call {}, result_code={}",
                     call->call_id, call->rx_leg->result_code);
    }
}

void VolteCallCorrelator::processDiameterGx(const session::SessionMessageRef& msg,
                                           const protocol::DiameterMessage& dia) {
    std::string session_id = dia.session_id.value_or("");
    std::string framed_ip;

    if (msg.correlation_key.ue_ipv4) {
        framed_ip = *msg.correlation_key.ue_ipv4;
    }

    // Find call by UE IP
    std::shared_ptr<VolteCall> call;
    if (!framed_ip.empty()) {
        auto imsi_opt = resolveImsiByIp(framed_ip);
        if (imsi_opt) {
            auto calls = findByImsi(*imsi_opt);
            for (auto& c : calls) {
                if (!c->isComplete()) {
                    call = c;
                    break;
                }
            }
        }
    }

    if (!call) {
        spdlog::debug("DIAMETER Gx message for unknown call");
        return;
    }

    auto msg_type = dia.getMessageType();

    if (msg_type == session::MessageType::DIAMETER_RAR) {
        // RAR - Policy installation
        if (!call->gx_leg) {
            call->gx_leg = VolteCall::GxLeg();
        }
        call->gx_leg->session_id = session_id;
        call->gx_leg->framed_ip = framed_ip;
        call->gx_leg->rar_time = msg.timestamp;

        spdlog::debug("Correlated DIAMETER Gx RAR to call {}", call->call_id);

    } else if (msg_type == session::MessageType::DIAMETER_RAA) {
        // RAA - Policy installation acknowledgment
        if (!call->gx_leg) {
            call->gx_leg = VolteCall::GxLeg();
        }
        call->gx_leg->raa_time = msg.timestamp;

        spdlog::debug("Correlated DIAMETER Gx RAA to call {}", call->call_id);
    }
}

void VolteCallCorrelator::processGtpBearer(const session::SessionMessageRef& msg,
                                          const protocol::GtpMessage& gtp) {
    // Look for Create Bearer Request/Response with QCI=1 (voice)
    auto msg_type = gtp.getMessageType();

    if (msg_type != session::MessageType::GTP_CREATE_BEARER_REQ &&
        msg_type != session::MessageType::GTP_CREATE_BEARER_RESP) {
        return;
    }

    // Extract IMSI and QCI from GTP message
    std::string imsi = gtp.imsi.value_or("");
    if (imsi.empty() && msg.correlation_key.imsi) {
        imsi = *msg.correlation_key.imsi;
    }

    if (imsi.empty()) {
        return;
    }

    // Find most recent active call for this IMSI
    auto calls = findByImsi(imsi);
    std::shared_ptr<VolteCall> call;
    for (auto& c : calls) {
        if (!c->isComplete() && !c->bearer_leg) {
            call = c;
            break;
        }
    }

    if (!call) {
        spdlog::debug("GTP bearer message for IMSI {} but no active call found", imsi);
        return;
    }

    if (msg_type == session::MessageType::GTP_CREATE_BEARER_REQ) {
        if (!call->bearer_leg) {
            call->bearer_leg = VolteCall::BearerLeg();
        }
        call->bearer_leg->session_id = msg.message_id;
        call->bearer_leg->request_time = msg.timestamp;

        // Extract TEID from correlation key
        if (msg.correlation_key.teid_s1u) {
            call->bearer_leg->teid_uplink = *msg.correlation_key.teid_s1u;
            teid_to_call_id_[call->bearer_leg->teid_uplink] = call->call_id;
        }
        if (msg.correlation_key.teid_s5u) {
            call->bearer_leg->teid_downlink = *msg.correlation_key.teid_s5u;
            teid_to_call_id_[call->bearer_leg->teid_downlink] = call->call_id;
        }

        // Extract EPS bearer ID
        if (msg.correlation_key.eps_bearer_id) {
            call->bearer_leg->eps_bearer_id = *msg.correlation_key.eps_bearer_id;
        }

        // Assume QCI=1 for VoLTE
        call->bearer_leg->qci = 1;

        spdlog::info("Correlated GTP Create Bearer Request to call {}, TEID_UL={}, EBI={}",
                    call->call_id, call->bearer_leg->teid_uplink, call->bearer_leg->eps_bearer_id);

    } else if (msg_type == session::MessageType::GTP_CREATE_BEARER_RESP) {
        if (!call->bearer_leg) {
            call->bearer_leg = VolteCall::BearerLeg();
        }
        call->bearer_leg->response_time = msg.timestamp;
        if (gtp.cause) {
            call->bearer_leg->cause = *gtp.cause;
        }

        spdlog::debug("Correlated GTP Create Bearer Response to call {}, cause={}",
                     call->call_id, call->bearer_leg->cause);
    }
}

void VolteCallCorrelator::processRtpPacket(const session::SessionMessageRef& msg,
                                          const protocol::RtpHeader& rtp) {
    // Find call by UE IP and RTP port
    std::string ue_ip = msg.src_ip;
    uint16_t port = msg.src_port;

    // Try to find call with matching SDP ports
    std::shared_ptr<VolteCall> call;
    for (auto& [call_id, c] : calls_by_call_id_) {
        if (c->isComplete()) continue;

        // Check if port matches SDP-negotiated port
        if (c->sip_leg.rtp_port_local == port || c->sip_leg.rtp_port_remote == port) {
            // Also check if IP matches (via subscriber context)
            if (!c->imsi.empty()) {
                auto ctx = context_mgr_->findByImsi(c->imsi);
                if (ctx && ctx->ue_ipv4_addresses.count(ue_ip) > 0) {
                    call = c;
                    break;
                }
            }
        }
    }

    if (!call) {
        // No matching call found
        return;
    }

    // Initialize RTP leg if not present
    if (!call->rtp_leg) {
        call->rtp_leg = VolteCall::RtpLeg();
        call->rtp_leg->ssrc = rtp.ssrc;
        call->rtp_leg->local_ip = msg.src_ip;
        call->rtp_leg->local_port = msg.src_port;
        call->rtp_leg->remote_ip = msg.dst_ip;
        call->rtp_leg->remote_port = msg.dst_port;

        spdlog::info("Correlated RTP stream to call {}, SSRC={}", call->call_id, rtp.ssrc);
    }

    // Update RTP statistics
    // Determine direction based on IP/port
    bool is_uplink = (msg.src_ip == call->rtp_leg->local_ip);
    auto& direction = is_uplink ? call->rtp_leg->uplink : call->rtp_leg->downlink;

    direction.packets++;
    direction.bytes += msg.payload_length;

    if (direction.packets == 1) {
        direction.first_packet = msg.timestamp;
    }
    direction.last_packet = msg.timestamp;

    // Mark call as having active media
    if (call->state == VolteCall::State::CONFIRMED) {
        updateCallState(call, VolteCall::State::MEDIA_ACTIVE, "RTP detected");
    }
}

std::shared_ptr<VolteCall> VolteCallCorrelator::findByCallId(const std::string& call_id) {
    auto it = calls_by_call_id_.find(call_id);
    return (it != calls_by_call_id_.end()) ? it->second : nullptr;
}

std::shared_ptr<VolteCall> VolteCallCorrelator::findByIcid(const std::string& icid) {
    auto it = icid_to_call_id_.find(icid);
    if (it != icid_to_call_id_.end()) {
        return findByCallId(it->second);
    }
    return nullptr;
}

std::shared_ptr<VolteCall> VolteCallCorrelator::findByRxSessionId(const std::string& session_id) {
    auto it = rx_session_to_call_id_.find(session_id);
    if (it != rx_session_to_call_id_.end()) {
        return findByCallId(it->second);
    }
    return nullptr;
}

std::shared_ptr<VolteCall> VolteCallCorrelator::findByTeid(uint32_t teid) {
    auto it = teid_to_call_id_.find(teid);
    if (it != teid_to_call_id_.end()) {
        return findByCallId(it->second);
    }
    return nullptr;
}

std::vector<std::shared_ptr<VolteCall>> VolteCallCorrelator::findByImsi(const std::string& imsi) {
    std::vector<std::shared_ptr<VolteCall>> result;
    auto range = imsi_to_call_ids_.equal_range(imsi);
    for (auto it = range.first; it != range.second; ++it) {
        auto call = findByCallId(it->second);
        if (call) {
            result.push_back(call);
        }
    }
    return result;
}

std::vector<std::shared_ptr<VolteCall>> VolteCallCorrelator::getAllCalls() const {
    std::vector<std::shared_ptr<VolteCall>> result;
    result.reserve(calls_by_call_id_.size());
    for (const auto& [call_id, call] : calls_by_call_id_) {
        result.push_back(call);
    }
    return result;
}

std::vector<std::shared_ptr<VolteCall>> VolteCallCorrelator::getActiveCalls() const {
    std::vector<std::shared_ptr<VolteCall>> result;
    for (const auto& [call_id, call] : calls_by_call_id_) {
        if (!call->isComplete()) {
            result.push_back(call);
        }
    }
    return result;
}

size_t VolteCallCorrelator::cleanupCompletedCalls(std::chrono::seconds retention) {
    auto cutoff = std::chrono::system_clock::now() - retention;
    size_t removed = 0;

    std::vector<std::string> to_remove;
    for (const auto& [call_id, call] : calls_by_call_id_) {
        if (call->isComplete() && call->end_time < cutoff) {
            to_remove.push_back(call_id);
        }
    }

    for (const auto& call_id : to_remove) {
        auto call = calls_by_call_id_[call_id];

        // Remove from all indices
        calls_by_call_id_.erase(call_id);
        icid_to_call_id_.erase(call->icid);
        if (call->rx_leg) {
            rx_session_to_call_id_.erase(call->rx_leg->session_id);
        }
        if (call->bearer_leg) {
            teid_to_call_id_.erase(call->bearer_leg->teid_uplink);
            teid_to_call_id_.erase(call->bearer_leg->teid_downlink);
        }

        auto range = imsi_to_call_ids_.equal_range(call->imsi);
        for (auto it = range.first; it != range.second;) {
            if (it->second == call_id) {
                it = imsi_to_call_ids_.erase(it);
            } else {
                ++it;
            }
        }

        removed++;
    }

    if (removed > 0) {
        spdlog::info("Cleaned up {} completed VoLTE calls older than {}s", removed, retention.count());
    }

    return removed;
}

VolteCallCorrelator::Stats VolteCallCorrelator::getStats() const {
    Stats stats;
    stats.total_calls = calls_by_call_id_.size();

    double total_setup_time = 0.0;
    double total_mos = 0.0;
    size_t mos_count = 0;

    for (const auto& [call_id, call] : calls_by_call_id_) {
        if (call->state == VolteCall::State::COMPLETED) {
            stats.successful_calls++;
        } else if (call->isFailed()) {
            stats.failed_calls++;
        } else {
            stats.active_calls++;
        }

        if (call->metrics.setup_time.count() > 0) {
            total_setup_time += call->metrics.setup_time.count();
        }

        if (call->metrics.avg_mos > 0) {
            total_mos += call->metrics.avg_mos;
            mos_count++;
        }
    }

    if (stats.total_calls > 0) {
        stats.avg_setup_time_ms = total_setup_time / stats.total_calls;
    }
    if (mos_count > 0) {
        stats.avg_mos = total_mos / mos_count;
    }

    return stats;
}

void VolteCallCorrelator::updateCallState(std::shared_ptr<VolteCall> call,
                                         VolteCall::State new_state,
                                         const std::string& reason) {
    if (call->state != new_state) {
        spdlog::debug("Call {} state: {} -> {} ({})",
                     call->call_id, static_cast<int>(call->state), static_cast<int>(new_state), reason);
        call->state = new_state;
        call->state_reason = reason;

        // Calculate metrics on state transitions
        calculateMetrics(call);
    }
}

void VolteCallCorrelator::calculateMetrics(std::shared_ptr<VolteCall> call) {
    auto& metrics = call->metrics;

    // Setup time: INVITE → 200 OK
    if (call->sip_leg.answer_time) {
        metrics.setup_time = std::chrono::duration_cast<std::chrono::milliseconds>(
            *call->sip_leg.answer_time - call->sip_leg.invite_time);
    }

    // Post-dial delay: INVITE → 180 Ringing
    if (call->sip_leg.ringing_time) {
        metrics.post_dial_delay = std::chrono::duration_cast<std::chrono::milliseconds>(
            *call->sip_leg.ringing_time - call->sip_leg.invite_time);
    }

    // Answer delay: 180 → 200 OK
    if (call->sip_leg.answer_time && call->sip_leg.ringing_time) {
        metrics.answer_delay = std::chrono::duration_cast<std::chrono::milliseconds>(
            *call->sip_leg.answer_time - *call->sip_leg.ringing_time);
    }

    // Bearer setup time
    if (call->bearer_leg && call->bearer_leg->response_time) {
        metrics.bearer_setup_time = std::chrono::duration_cast<std::chrono::milliseconds>(
            *call->bearer_leg->response_time - call->bearer_leg->request_time);
    }

    // Rx authorization time
    if (call->rx_leg && call->rx_leg->aaa_time) {
        metrics.rx_authorization_time = std::chrono::duration_cast<std::chrono::milliseconds>(
            *call->rx_leg->aaa_time - call->rx_leg->aar_time);
    }

    // Total call duration
    if (call->end_time > call->start_time) {
        metrics.total_call_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            call->end_time - call->start_time);
    }

    // Media duration
    if (call->rtp_leg) {
        if (call->rtp_leg->uplink.packets > 0) {
            metrics.media_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                call->rtp_leg->uplink.last_packet - call->rtp_leg->uplink.first_packet);
        }

        // Average MOS and quality metrics
        double mos_sum = 0.0;
        int mos_count = 0;
        if (call->rtp_leg->uplink.mos_estimate > 0) {
            mos_sum += call->rtp_leg->uplink.mos_estimate;
            mos_count++;
        }
        if (call->rtp_leg->downlink.mos_estimate > 0) {
            mos_sum += call->rtp_leg->downlink.mos_estimate;
            mos_count++;
        }
        if (mos_count > 0) {
            metrics.avg_mos = mos_sum / mos_count;
        }

        // Average packet loss and jitter
        metrics.packet_loss_rate = (call->rtp_leg->uplink.packet_loss_rate +
                                   call->rtp_leg->downlink.packet_loss_rate) / 2.0;
        metrics.jitter_ms = (call->rtp_leg->uplink.jitter_ms +
                            call->rtp_leg->downlink.jitter_ms) / 2.0;
    }
}

std::optional<std::string> VolteCallCorrelator::resolveImsiByIp(const std::string& ue_ip) {
    auto ctx = context_mgr_->findByUeIp(ue_ip);
    if (ctx) {
        return ctx->getPrimaryIdentifier();
    }
    return std::nullopt;
}

std::optional<std::string> VolteCallCorrelator::extractImsiFromSip(const protocol::SipMessage& sip) {
    // In some deployments, IMSI might be in P-Asserted-Identity as tel URI or SIP URI
    // Format: sip:imsi@ims.mnc001.mcc001.3gppnetwork.org
    if (sip.p_asserted_identity && !sip.p_asserted_identity->empty()) {
        for (const auto& identity : *sip.p_asserted_identity) {
            std::string uri = identity.uri;
            size_t imsi_pos = uri.find("imsi");
            if (imsi_pos != std::string::npos) {
                // Extract digits after "imsi"
                std::string potential_imsi;
                for (size_t i = imsi_pos + 4; i < uri.size() && std::isdigit(uri[i]); i++) {
                    potential_imsi += uri[i];
                }
                if (potential_imsi.length() >= 14 && potential_imsi.length() <= 15) {
                    return potential_imsi;
                }
            }
        }
    }
    return std::nullopt;
}

}  // namespace correlation
}  // namespace callflow
