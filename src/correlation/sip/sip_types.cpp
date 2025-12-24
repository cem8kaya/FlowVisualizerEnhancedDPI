#include "correlation/sip/sip_types.h"

namespace callflow {
namespace correlation {

std::string sipSessionTypeToString(SipSessionType type) {
    switch (type) {
        case SipSessionType::REGISTRATION:
            return "REGISTRATION";
        case SipSessionType::DEREGISTRATION:
            return "DEREGISTRATION";
        case SipSessionType::THIRD_PARTY_REG:
            return "THIRD_PARTY_REG";
        case SipSessionType::VOICE_CALL:
            return "VOICE_CALL";
        case SipSessionType::VIDEO_CALL:
            return "VIDEO_CALL";
        case SipSessionType::EMERGENCY_CALL:
            return "EMERGENCY_CALL";
        case SipSessionType::SMS_MESSAGE:
            return "SMS_MESSAGE";
        case SipSessionType::SUBSCRIBE_NOTIFY:
            return "SUBSCRIBE_NOTIFY";
        case SipSessionType::OPTIONS:
            return "OPTIONS";
        case SipSessionType::REFER:
            return "REFER";
        case SipSessionType::INFO:
            return "INFO";
        case SipSessionType::UNKNOWN:
        default:
            return "UNKNOWN";
    }
}

std::string sipDialogStateToString(SipDialogState state) {
    switch (state) {
        case SipDialogState::INIT:
            return "INIT";
        case SipDialogState::CALLING:
            return "CALLING";
        case SipDialogState::PROCEEDING:
            return "PROCEEDING";
        case SipDialogState::EARLY:
            return "EARLY";
        case SipDialogState::CONFIRMED:
            return "CONFIRMED";
        case SipDialogState::TERMINATED:
            return "TERMINATED";
        default:
            return "UNKNOWN";
    }
}

std::string sipCallPartyToString(SipCallParty party) {
    switch (party) {
        case SipCallParty::CALLER_MO:
            return "CALLER_MO";
        case SipCallParty::CALLEE_MT:
            return "CALLEE_MT";
        case SipCallParty::FORWARD_TARGET:
            return "FORWARD_TARGET";
        case SipCallParty::NETWORK_ELEMENT:
            return "NETWORK_ELEMENT";
        default:
            return "UNKNOWN";
    }
}

std::string sipDirectionToString(SipDirection direction) {
    switch (direction) {
        case SipDirection::ORIGINATING:
            return "ORIGINATING";
        case SipDirection::TERMINATING:
            return "TERMINATING";
        case SipDirection::NETWORK_INTERNAL:
            return "NETWORK_INTERNAL";
        default:
            return "UNKNOWN";
    }
}

} // namespace correlation
} // namespace callflow
