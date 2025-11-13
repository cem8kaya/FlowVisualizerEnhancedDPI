#pragma once

#include "common/types.h"
#include "flow_manager/session_correlator.h"
#include <nlohmann/json.hpp>

namespace callflow {

/**
 * Event builder - creates structured events from parsed packets
 */
class EventBuilder {
public:
    EventBuilder() = default;
    ~EventBuilder() = default;

    /**
     * Build event from parsed protocol data
     */
    SessionEvent buildEvent(const PacketMetadata& packet,
                           ProtocolType protocol,
                           const nlohmann::json& parsed_data);

private:
    MessageType inferMessageType(ProtocolType protocol, const nlohmann::json& data);
    std::string createShortDescription(ProtocolType protocol,
                                      MessageType msg_type,
                                      const nlohmann::json& data);
    Direction inferDirection(const FiveTuple& ft);
};

}  // namespace callflow
