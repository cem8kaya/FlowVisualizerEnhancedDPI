#include "event_extractor/event_builder.h"

#include "common/utils.h"

namespace callflow {

SessionEvent EventBuilder::buildEvent(const PacketMetadata& packet, ProtocolType protocol,
                                      const nlohmann::json& parsed_data) {
    SessionEvent event;

    event.event_id = utils::generateUuid();
    event.timestamp = packet.timestamp;
    event.protocol = protocol;
    event.packet_ref = packet.packet_id;
    event.direction = inferDirection(packet.five_tuple);
    event.message_type = inferMessageType(protocol, parsed_data);
    event.short_description = createShortDescription(protocol, event.message_type, parsed_data);
    event.details = parsed_data;

    return event;
}

MessageType EventBuilder::inferMessageType(ProtocolType protocol, const nlohmann::json& data) {
    if (protocol == ProtocolType::SIP) {
        if (data.contains("is_request") && data["is_request"].get<bool>()) {
            std::string method = data.value("method", "");
            if (method == "INVITE")
                return MessageType::SIP_INVITE;
            if (method == "ACK")
                return MessageType::SIP_ACK;
            if (method == "BYE")
                return MessageType::SIP_BYE;
            if (method == "CANCEL")
                return MessageType::SIP_CANCEL;
            if (method == "REGISTER")
                return MessageType::SIP_REGISTER;
        } else if (data.contains("status_code")) {
            int code = data["status_code"].get<int>();
            if (code == 100)
                return MessageType::SIP_TRYING;
            if (code == 180)
                return MessageType::SIP_RINGING;
            if (code == 200)
                return MessageType::SIP_OK;
        }
    }

    return MessageType::UNKNOWN;
}

std::string EventBuilder::createShortDescription(ProtocolType protocol, MessageType msg_type,
                                                 const nlohmann::json& data) {
    std::string desc = protocolTypeToString(protocol);

    if (msg_type != MessageType::UNKNOWN) {
        desc += " " + messageTypeToString(msg_type);
    }

    // Add additional context
    if (protocol == ProtocolType::SIP) {
        if (data.contains("from")) {
            // Extract just the user part from SIP URI
            std::string from = data["from"].get<std::string>();
            size_t start = from.find("sip:");
            if (start != std::string::npos) {
                start += 4;
                size_t end = from.find('@', start);
                if (end != std::string::npos) {
                    std::string user = from.substr(start, end - start);
                    desc += " from " + user;
                }
            }
        }
    } else if (msg_type == MessageType::FIVEG_SBA_INTERACTION) {
        // Consumer -> Producer: Service Name
        // e.g., AMF -> UDM: nudm-ueau
        std::string service = data.value("service", "Unknown");
        std::string nf_type = data.value("nf_type", "NF");
        std::string api = data.value("api", "");

        desc = "5G SBA: " + nf_type + " (" + service + ") " + api;
    }

    return desc;
}

Direction EventBuilder::inferDirection(const FiveTuple& ft) {
    // Simple heuristic: lower port number is likely the server
    if (ft.src_port < 10000 && ft.dst_port > 10000) {
        return Direction::SERVER_TO_CLIENT;
    } else if (ft.dst_port < 10000 && ft.src_port > 10000) {
        return Direction::CLIENT_TO_SERVER;
    }

    return Direction::UNKNOWN;
}

}  // namespace callflow
