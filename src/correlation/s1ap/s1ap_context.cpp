#include "correlation/s1ap/s1ap_context.h"

#include <algorithm>
#include <sstream>

namespace callflow {
namespace correlation {

S1apContext::S1apContext() = default;

S1apContext::S1apContext(uint32_t mme_ue_id, uint32_t enb_ue_id)
    : mme_ue_s1ap_id_(mme_ue_id), enb_ue_s1ap_id_(enb_ue_id) {}

void S1apContext::addMessage(const S1apMessage& msg) {
    messages_.push_back(msg);
    updateTimeWindow(msg);
    updateState(msg);
    updateErabState(msg);
    updateLocation(msg);
    extractIdentifiers(msg);
}

std::vector<NasMessage> S1apContext::getNasMessages() const {
    std::vector<NasMessage> nas_messages;

    for (const auto& s1ap_msg : messages_) {
        if (auto nas_pdu = s1ap_msg.getNasPdu()) {
            nas_messages.push_back(*nas_pdu);
        }
    }

    return nas_messages;
}

void S1apContext::finalize() {
    // Any cleanup or final processing
}

void S1apContext::updateErabState(const S1apMessage& msg) {
    // Update E-RAB state based on message
    const auto& erab_list = msg.getErabList();

    for (const auto& erab_info : erab_list) {
        // Find or create E-RAB state
        auto it = std::find_if(erabs_.begin(), erabs_.end(), [&](const ErabState& state) {
            return state.erab_id == erab_info.erab_id;
        });

        if (it == erabs_.end()) {
            // New E-RAB
            ErabState state;
            state.erab_id = erab_info.erab_id;
            state.active = true;
            state.qci = erab_info.qci;
            state.transport_layer_address = erab_info.transport_layer_address;
            state.gtp_teid = erab_info.gtp_teid;
            state.setup_time = msg.getTimestamp();
            erabs_.push_back(state);
        } else {
            // Update existing E-RAB
            it->qci = erab_info.qci;
            it->transport_layer_address = erab_info.transport_layer_address;
            it->gtp_teid = erab_info.gtp_teid;
        }
    }

    // Check for E-RAB release
    switch (msg.getMessageType()) {
        case S1apMessageType::E_RAB_RELEASE_COMMAND:
        case S1apMessageType::E_RAB_RELEASE_RESPONSE:
        case S1apMessageType::E_RAB_RELEASE_INDICATION:
            for (const auto& erab_info : erab_list) {
                auto it = std::find_if(erabs_.begin(), erabs_.end(), [&](const ErabState& state) {
                    return state.erab_id == erab_info.erab_id;
                });
                if (it != erabs_.end()) {
                    it->active = false;
                    it->release_time = msg.getTimestamp();
                }
            }
            break;
        default:
            break;
    }
}

void S1apContext::updateLocation(const S1apMessage& msg) {
    if (auto tai = msg.getTai()) {
        current_tai_ = tai;
    }
    if (auto ecgi = msg.getEcgi()) {
        current_ecgi_ = ecgi;
    }
}

void S1apContext::updateState(const S1apMessage& msg) {
    switch (msg.getMessageType()) {
        case S1apMessageType::INITIAL_UE_MESSAGE:
            state_ = State::INITIAL;
            break;

        case S1apMessageType::INITIAL_CONTEXT_SETUP_REQUEST:
            state_ = State::CONTEXT_SETUP;
            break;

        case S1apMessageType::INITIAL_CONTEXT_SETUP_RESPONSE:
            state_ = State::ACTIVE;
            break;

        case S1apMessageType::UE_CONTEXT_RELEASE_REQUEST:
        case S1apMessageType::UE_CONTEXT_RELEASE_COMMAND:
            state_ = State::RELEASE_PENDING;
            if (auto cause_type = msg.getCauseType()) {
                release_cause_type_ = cause_type;
            }
            if (auto cause_value = msg.getCauseValue()) {
                release_cause_value_ = cause_value;
            }
            break;

        case S1apMessageType::UE_CONTEXT_RELEASE_COMPLETE:
            state_ = State::RELEASED;
            break;

        default:
            break;
    }
}

void S1apContext::updateTimeWindow(const S1apMessage& msg) {
    double msg_time = msg.getTimestamp();
    uint32_t msg_frame = msg.getFrameNum();

    if (start_time_ == 0.0 || msg_time < start_time_) {
        start_time_ = msg_time;
        start_frame_ = msg_frame;
    }

    if (msg_time > end_time_) {
        end_time_ = msg_time;
        end_frame_ = msg_frame;
    }
}

void S1apContext::extractIdentifiers(const S1apMessage& msg) {
    // Extract identifiers from embedded NAS messages
    if (auto nas_pdu = msg.getNasPdu()) {
        if (auto imsi = nas_pdu->getImsi(); imsi && !imsi_) {
            imsi_ = imsi;
        }
        if (auto imei = nas_pdu->getImei(); imei && !imei_) {
            imei_ = imei;
        }
        if (auto tmsi = nas_pdu->getTmsi(); tmsi && !tmsi_) {
            tmsi_ = tmsi;
        }
    }
}

std::string S1apContext::toString() const {
    std::ostringstream oss;

    oss << "S1AP Context [MME-UE-ID=" << mme_ue_s1ap_id_ << ", eNB-UE-ID=" << enb_ue_s1ap_id_
        << ", Messages=" << messages_.size() << ", E-RABs=" << erabs_.size();

    if (imsi_)
        oss << ", IMSI=" << *imsi_;

    oss << ", State=";
    switch (state_) {
        case State::INITIAL:
            oss << "Initial";
            break;
        case State::CONTEXT_SETUP:
            oss << "Context Setup";
            break;
        case State::ACTIVE:
            oss << "Active";
            break;
        case State::RELEASE_PENDING:
            oss << "Release Pending";
            break;
        case State::RELEASED:
            oss << "Released";
            break;
    }

    oss << "]";

    return oss.str();
}

}  // namespace correlation
}  // namespace callflow
