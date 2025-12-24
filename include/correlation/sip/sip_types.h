#pragma once

#include <string>
#include <vector>
#include <optional>
#include <chrono>
#include <cstdint>

namespace callflow {
namespace correlation {

enum class SipSessionType {
    REGISTRATION,           // REGISTER with expires > 0
    DEREGISTRATION,         // REGISTER with expires = 0
    THIRD_PARTY_REG,        // Third-party registration (TAS)
    VOICE_CALL,             // INVITE for audio
    VIDEO_CALL,             // INVITE for audio+video
    EMERGENCY_CALL,         // INVITE to emergency URN
    SMS_MESSAGE,            // MESSAGE method
    SUBSCRIBE_NOTIFY,       // SUBSCRIBE/NOTIFY
    OPTIONS,                // OPTIONS (keepalive)
    REFER,                  // Call transfer
    INFO,                   // Mid-call INFO (DTMF, etc.)
    UNKNOWN
};

enum class SipDialogState {
    INIT,           // Initial state
    CALLING,        // INVITE sent
    PROCEEDING,     // 1xx received
    EARLY,          // 1xx with To-tag (early dialog)
    CONFIRMED,      // 2xx received
    TERMINATED      // BYE or error response
};

enum class SipCallParty {
    CALLER_MO,          // Mobile Originating party (UEa)
    CALLEE_MT,          // Mobile Terminating party (UEb)
    FORWARD_TARGET,     // Call forwarding target (UEc)
    NETWORK_ELEMENT     // IMS network element
};

enum class SipDirection {
    ORIGINATING,        // From UE towards network
    TERMINATING,        // From network towards UE
    NETWORK_INTERNAL    // Between network elements
};

struct SipMediaInfo {
    std::string media_type;     // "audio", "video"
    std::string connection_ip;
    uint16_t port = 0;
    std::string direction;      // "sendrecv", "sendonly", "recvonly", "inactive"
    std::vector<std::string> codecs;
};

struct SipViaHeader {
    std::string protocol;       // "SIP/2.0/UDP", "SIP/2.0/TCP"
    std::string sent_by;        // IP:port
    std::string branch;
    std::optional<std::string> received;
    std::optional<uint16_t> rport;
    int index = 0;              // Position in Via stack (0 = topmost)
};

struct SipContactHeader {
    std::string uri;
    std::string user;
    std::string host;
    std::optional<int> expires;
    std::optional<std::string> instance;
    std::optional<std::string> pub_gruu;
};

// Helper functions
std::string sipSessionTypeToString(SipSessionType type);
std::string sipDialogStateToString(SipDialogState state);
std::string sipCallPartyToString(SipCallParty party);
std::string sipDirectionToString(SipDirection direction);

} // namespace correlation
} // namespace callflow
