#include "correlation/s1ap/s1ap_message.h"
#include <sstream>

namespace callflow {
namespace correlation {

std::string S1apMessage::TrackingAreaIdentity::toString() const {
    return mcc + mnc + "-" + std::to_string(tac);
}

std::string S1apMessage::EcgiInfo::toString() const {
    std::ostringstream oss;
    oss << mcc << mnc << "-" << std::hex << cell_id;
    return oss.str();
}

std::string S1apMessage::STmsi::toString() const {
    std::ostringstream oss;
    oss << "MMEC=" << static_cast<int>(mmec) << ",M-TMSI=" << m_tmsi;
    return oss.str();
}

S1apMessage::Direction S1apMessage::getDirection() const {
    switch (message_type_) {
        // Uplink (eNB -> MME)
        case S1apMessageType::INITIAL_UE_MESSAGE:
        case S1apMessageType::UPLINK_NAS_TRANSPORT:
        case S1apMessageType::INITIAL_CONTEXT_SETUP_RESPONSE:
        case S1apMessageType::INITIAL_CONTEXT_SETUP_FAILURE:
        case S1apMessageType::UE_CONTEXT_RELEASE_REQUEST:
        case S1apMessageType::UE_CONTEXT_RELEASE_COMPLETE:
        case S1apMessageType::E_RAB_SETUP_RESPONSE:
        case S1apMessageType::HANDOVER_REQUIRED:
        case S1apMessageType::HANDOVER_NOTIFY:
        case S1apMessageType::PATH_SWITCH_REQUEST:
            return Direction::UPLINK;

        // Downlink (MME -> eNB)
        case S1apMessageType::DOWNLINK_NAS_TRANSPORT:
        case S1apMessageType::INITIAL_CONTEXT_SETUP_REQUEST:
        case S1apMessageType::UE_CONTEXT_RELEASE_COMMAND:
        case S1apMessageType::E_RAB_SETUP_REQUEST:
        case S1apMessageType::E_RAB_MODIFY_REQUEST:
        case S1apMessageType::E_RAB_RELEASE_COMMAND:
        case S1apMessageType::HANDOVER_REQUEST:
        case S1apMessageType::PAGING:
            return Direction::DOWNLINK;

        default:
            return Direction::UNKNOWN;
    }
}

bool S1apMessage::isUeAssociated() const {
    return correlation::isUeAssociated(procedure_code_);
}

bool S1apMessage::containsNasPdu() const {
    return correlation::containsNasPdu(procedure_code_);
}

std::optional<S1apMessage> S1apMessage::parse(const uint8_t* data,
                                               size_t length,
                                               uint32_t frame_num,
                                               double timestamp) {
    if (!data || length < 3) {
        return std::nullopt;
    }

    // This is a simplified parser stub
    // A full implementation would use ASN.1 PER decoding for S1AP

    S1apMessage msg;
    msg.frame_num_ = frame_num;
    msg.timestamp_ = timestamp;
    msg.setRawData(data, length);

    // For now, we'll create a minimal parser that extracts basic info
    // In production, this would use a proper ASN.1 decoder

    // Simplified: assume procedure code is extractable
    // (Real implementation needs full ASN.1 PER decoding)

    return msg;
}

std::string S1apMessage::toString() const {
    std::ostringstream oss;

    oss << getS1apMessageTypeName(message_type_);
    oss << " [Frame=" << frame_num_ << ", Time=" << timestamp_;

    if (mme_ue_s1ap_id_) {
        oss << ", MME-UE-ID=" << *mme_ue_s1ap_id_;
    }
    if (enb_ue_s1ap_id_) {
        oss << ", eNB-UE-ID=" << *enb_ue_s1ap_id_;
    }

    oss << "]";

    return oss.str();
}

} // namespace correlation
} // namespace callflow
