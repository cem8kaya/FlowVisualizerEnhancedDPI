#pragma once

#include <variant>

#include "common/types.h"

// Forward declarations
namespace callflow {
struct SipMessage;
struct GtpMessage;
struct DiameterMessage;
}  // namespace callflow

namespace callflow {

struct ParsedPacket {
    ProtocolType protocol;
    // Pointers to the parsed message structures.
    // We use pointers because the actual storage is likely managed elsewhere (e.g. stack or
    // PacketProcessor) and we just want a lightweight view for the FieldRegistry.
    std::variant<std::monostate, const SipMessage*, const GtpMessage*, const DiameterMessage*>
        message;

    ParsedPacket(const SipMessage* msg) : protocol(ProtocolType::SIP), message(msg) {}
    ParsedPacket(const GtpMessage* msg)
        : protocol(ProtocolType::GTP_C /* or GTP_U */), message(msg) {}  // Simplified
    ParsedPacket(const DiameterMessage* msg) : protocol(ProtocolType::DIAMETER), message(msg) {}
    ParsedPacket() : protocol(ProtocolType::UNKNOWN), message(std::monostate{}) {}
};

}  // namespace callflow
