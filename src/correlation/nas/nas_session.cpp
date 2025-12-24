#include "correlation/nas/nas_session.h"
#include "correlation/gtpv2/gtpv2_types.h"
#include <sstream>

namespace callflow {
namespace correlation {

NasSession::NasSession() = default;

void NasSession::addMessage(const NasMessage& msg) {
    messages_.push_back(msg);
    updateTimeWindow(msg);
    extractIdentifiers(msg);
    extractPdnInfo(msg);
    updateEmmState(msg);
}

void NasSession::setS1apContext(uint32_t mme_ue_id, uint32_t enb_ue_id) {
    mme_ue_s1ap_id_ = mme_ue_id;
    enb_ue_s1ap_id_ = enb_ue_id;
}

void NasSession::finalize() {
    detectPdnClass();

    // Determine session type based on messages
    for (const auto& msg : messages_) {
        if (msg.isEmm()) {
            type_ = NasSessionType::EMM;
            break;
        } else if (msg.isEsm()) {
            type_ = NasSessionType::ESM;
        }
    }
}

void NasSession::extractIdentifiers(const NasMessage& msg) {
    if (auto imsi = msg.getImsi(); imsi && !imsi_) {
        imsi_ = imsi;
    }
    if (auto imei = msg.getImei(); imei && !imei_) {
        imei_ = imei;
    }
    if (auto imeisv = msg.getImeisv(); imeisv && !imeisv_) {
        imeisv_ = imeisv;
    }
    if (auto guti = msg.getGuti(); guti && !guti_) {
        guti_ = guti;
    }
    if (auto tmsi = msg.getTmsi(); tmsi && !tmsi_) {
        tmsi_ = tmsi;
    }
}

void NasSession::extractPdnInfo(const NasMessage& msg) {
    if (auto apn = msg.getApn(); apn && !apn_) {
        apn_ = apn;
    }
    if (auto pdn_addr = msg.getPdnAddress(); pdn_addr && !pdn_address_) {
        pdn_address_ = pdn_addr;
    }
    if (auto ebi = msg.getEpsBearerId(); ebi && !eps_bearer_id_) {
        eps_bearer_id_ = ebi;
    }
    if (auto lbi = msg.getLinkedEpsBearerId(); lbi && !linked_bearer_id_) {
        linked_bearer_id_ = lbi;
    }
    if (auto qci = msg.getQci(); qci && !qci_) {
        qci_ = qci;
    }
}

void NasSession::updateEmmState(const NasMessage& msg) {
    if (!msg.getEmmMessageType()) {
        return;
    }

    auto emm_type = *msg.getEmmMessageType();

    switch (emm_type) {
        case NasEmmMessageType::ATTACH_REQUEST:
            emm_state_ = EmmState::REGISTERED_INITIATED;
            break;
        case NasEmmMessageType::ATTACH_ACCEPT:
        case NasEmmMessageType::TAU_ACCEPT:
            emm_state_ = EmmState::REGISTERED;
            break;
        case NasEmmMessageType::DETACH_REQUEST:
            emm_state_ = EmmState::DEREGISTERED_INITIATED;
            break;
        case NasEmmMessageType::DETACH_ACCEPT:
            emm_state_ = EmmState::DEREGISTERED;
            break;
        case NasEmmMessageType::TAU_REQUEST:
            emm_state_ = EmmState::TAU_INITIATED;
            break;
        case NasEmmMessageType::SERVICE_REQUEST:
        case NasEmmMessageType::EXTENDED_SERVICE_REQUEST:
            emm_state_ = EmmState::SERVICE_REQUEST_INITIATED;
            break;
        case NasEmmMessageType::SECURITY_MODE_COMPLETE:
            security_activated_ = true;
            break;
        default:
            break;
    }
}

void NasSession::updateTimeWindow(const NasMessage& msg) {
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

void NasSession::detectPdnClass() {
    if (!apn_) {
        pdn_class_ = PdnClass::OTHER;
        return;
    }

    pdn_class_ = classifyPdnFromApn(*apn_);
}

std::string NasSession::toString() const {
    std::ostringstream oss;

    oss << "NAS Session [Type=";
    switch (type_) {
        case NasSessionType::EMM: oss << "EMM"; break;
        case NasSessionType::ESM: oss << "ESM"; break;
        default: oss << "Unknown"; break;
    }

    oss << ", Messages=" << messages_.size();

    if (imsi_) oss << ", IMSI=" << *imsi_;
    if (apn_) oss << ", APN=" << *apn_;
    if (eps_bearer_id_) oss << ", EBI=" << static_cast<int>(*eps_bearer_id_);

    oss << "]";

    return oss.str();
}

} // namespace correlation
} // namespace callflow
