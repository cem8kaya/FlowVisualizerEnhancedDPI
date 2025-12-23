#include "correlation/procedure_state_machine.h"

namespace callflow {
namespace correlation {

// ============================================================================
// ProcedureStep
// ============================================================================

nlohmann::json ProcedureStep::toJson() const {
    nlohmann::json j;
    j["step_name"] = step_name;
    j["message_type"] = messageTypeToString(message_type);
    j["timestamp"] =
        std::chrono::duration_cast<std::chrono::milliseconds>(timestamp.time_since_epoch()).count();
    if (latency_from_previous.has_value()) {
        j["latency_ms"] = latency_from_previous->count();
    }
    j["expected"] = expected;
    return j;
}

// ============================================================================
// Helper functions
// ============================================================================

std::optional<MessageType> extractNasMessageType(const nlohmann::json& parsed_data) {
    // For S1AP messages carrying NAS PDUs
    if (parsed_data.contains("nas") && parsed_data["nas"].is_object()) {
        const auto& nas = parsed_data["nas"];
        if (nas.contains("message_type") && nas["message_type"].is_string()) {
            std::string msg_type = nas["message_type"].get<std::string>();

            // LTE NAS messages
            if (msg_type == "ATTACH_REQUEST")
                return MessageType::NAS_ATTACH_REQUEST;
            if (msg_type == "ATTACH_ACCEPT")
                return MessageType::NAS_ATTACH_ACCEPT;
            if (msg_type == "ATTACH_COMPLETE")
                return MessageType::NAS_ATTACH_COMPLETE;
            if (msg_type == "ATTACH_REJECT")
                return MessageType::NAS_ATTACH_REJECT;
            if (msg_type == "AUTHENTICATION_REQUEST")
                return MessageType::NAS_AUTHENTICATION_REQUEST;
            if (msg_type == "AUTHENTICATION_RESPONSE")
                return MessageType::NAS_AUTHENTICATION_RESPONSE;
            if (msg_type == "SECURITY_MODE_COMMAND")
                return MessageType::NAS_SECURITY_MODE_COMMAND;
            if (msg_type == "SECURITY_MODE_COMPLETE")
                return MessageType::NAS_SECURITY_MODE_COMPLETE;
            if (msg_type == "PDN_CONNECTIVITY_REQUEST")
                return MessageType::NAS_PDN_CONNECTIVITY_REQUEST;

            // 5G NAS messages
            if (msg_type == "REGISTRATION_REQUEST")
                return MessageType::NAS5G_REGISTRATION_REQUEST;
            if (msg_type == "REGISTRATION_ACCEPT")
                return MessageType::NAS5G_REGISTRATION_ACCEPT;
            if (msg_type == "REGISTRATION_COMPLETE")
                return MessageType::NAS5G_REGISTRATION_COMPLETE;
            if (msg_type == "PDU_SESSION_ESTABLISHMENT_REQUEST")
                return MessageType::NAS5G_PDU_SESSION_ESTABLISHMENT_REQUEST;
            if (msg_type == "PDU_SESSION_ESTABLISHMENT_ACCEPT")
                return MessageType::NAS5G_PDU_SESSION_ESTABLISHMENT_ACCEPT;
        }
    }

    return std::nullopt;
}

bool hasNasMessageType(const nlohmann::json& parsed_data, MessageType expected_type) {
    auto nas_type = extractNasMessageType(parsed_data);
    return nas_type.has_value() && nas_type.value() == expected_type;
}

std::optional<std::string> extractImsi(const nlohmann::json& parsed_data) {
    // Try NAS mobile identity
    if (parsed_data.contains("nas") && parsed_data["nas"].is_object()) {
        const auto& nas = parsed_data["nas"];
        if (nas.contains("mobile_identity") && nas["mobile_identity"].is_object()) {
            const auto& mi = nas["mobile_identity"];
            if (mi.contains("imsi") && mi["imsi"].is_string()) {
                return mi["imsi"].get<std::string>();
            }
        }
    }

    // Try top-level IMSI
    if (parsed_data.contains("imsi") && parsed_data["imsi"].is_string()) {
        return parsed_data["imsi"].get<std::string>();
    }

    return std::nullopt;
}

std::optional<uint32_t> extractTeid(const nlohmann::json& parsed_data,
                                    const std::string& interface_type) {
    if (!parsed_data.contains("fteids") || !parsed_data["fteids"].is_array()) {
        return std::nullopt;
    }

    for (const auto& fteid : parsed_data["fteids"]) {
        if (!fteid.is_object()) {
            continue;
        }

        // Check if this FTEID matches the requested interface type
        if (fteid.contains("interface_type") && fteid["interface_type"].is_string()) {
            std::string iface = fteid["interface_type"].get<std::string>();
            if (iface.find(interface_type) != std::string::npos) {
                if (fteid.contains("teid") && fteid["teid"].is_number_unsigned()) {
                    return fteid["teid"].get<uint32_t>();
                }
            }
        }
    }

    // Also try direct TEID field
    if (parsed_data.contains("teid") && parsed_data["teid"].is_number_unsigned()) {
        return parsed_data["teid"].get<uint32_t>();
    }

    return std::nullopt;
}

}  // namespace correlation
}  // namespace callflow
