#include "protocol_parsers/diameter/diameter_base.h"
#include "protocol_parsers/diameter/diameter_types.h"
#include <cstring>
#include <arpa/inet.h>

namespace callflow {
namespace diameter {

// ============================================================================
// DiameterHeader Implementation
// ============================================================================

DiameterHeader::DiameterHeader()
    : version(DIAMETER_VERSION),
      message_length(0),
      request(false),
      proxyable(false),
      error(false),
      potentially_retransmitted(false),
      command_code(0),
      application_id(0),
      hop_by_hop_id(0),
      end_to_end_id(0) {}

nlohmann::json DiameterHeader::toJson() const {
    nlohmann::json j;
    j["version"] = version;
    j["message_length"] = message_length;
    j["flags"] = {
        {"request", request},
        {"proxyable", proxyable},
        {"error", error},
        {"potentially_retransmitted", potentially_retransmitted}
    };
    j["command_code"] = command_code;
    j["command_name"] = getCommandName();
    j["application_id"] = application_id;
    j["application_name"] = getApplicationIDName(application_id);
    j["hop_by_hop_id"] = hop_by_hop_id;
    j["end_to_end_id"] = end_to_end_id;
    return j;
}

std::string DiameterHeader::getCommandName() const {
    return getCommandCodeName(command_code) + " (" + getDirection() + ")";
}

// ============================================================================
// DiameterAVP Implementation
// ============================================================================

DiameterAVP::DiameterAVP()
    : code(0),
      vendor_specific(false),
      mandatory(false),
      protected_(false),
      length(0) {}

nlohmann::json DiameterAVP::toJson() const {
    nlohmann::json j;
    j["code"] = code;
    j["name"] = getAVPName();
    j["flags"] = {
        {"vendor_specific", vendor_specific},
        {"mandatory", mandatory},
        {"protected", protected_}
    };
    j["length"] = length;

    if (vendor_id.has_value()) {
        j["vendor_id"] = vendor_id.value();
    }

    // Try to represent decoded value
    if (std::holds_alternative<std::string>(decoded_value)) {
        j["value"] = std::get<std::string>(decoded_value);
    } else if (std::holds_alternative<uint32_t>(decoded_value)) {
        j["value"] = std::get<uint32_t>(decoded_value);
    } else if (std::holds_alternative<uint64_t>(decoded_value)) {
        j["value"] = std::get<uint64_t>(decoded_value);
    } else if (std::holds_alternative<int32_t>(decoded_value)) {
        j["value"] = std::get<int32_t>(decoded_value);
    } else if (std::holds_alternative<int64_t>(decoded_value)) {
        j["value"] = std::get<int64_t>(decoded_value);
    } else if (std::holds_alternative<float>(decoded_value)) {
        j["value"] = std::get<float>(decoded_value);
    } else if (std::holds_alternative<double>(decoded_value)) {
        j["value"] = std::get<double>(decoded_value);
    } else {
        // Try to represent data as string if it looks like text
        std::string str_data = getDataAsString();
        if (!str_data.empty()) {
            j["value"] = str_data;
        } else {
            // Otherwise represent as hex
            std::string hex_str;
            for (auto byte : data) {
                char buf[3];
                snprintf(buf, sizeof(buf), "%02x", byte);
                hex_str += buf;
            }
            j["value_hex"] = hex_str;
        }
    }

    return j;
}

std::string DiameterAVP::getDataAsString() const {
    if (data.empty()) {
        return "";
    }

    // Check if data is printable ASCII/UTF-8
    for (auto byte : data) {
        if (byte == 0) break;  // Null terminator
        if (byte < 0x20 && byte != 0x09 && byte != 0x0A && byte != 0x0D) {
            return "";  // Non-printable character
        }
        if (byte > 0x7E && byte < 0x80) {
            return "";  // Non-ASCII, non-UTF8
        }
    }

    return std::string(reinterpret_cast<const char*>(data.data()), data.size());
}

std::optional<uint32_t> DiameterAVP::getDataAsUint32() const {
    if (data.size() != 4) {
        return std::nullopt;
    }

    uint32_t value;
    std::memcpy(&value, data.data(), 4);
    return ntohl(value);
}

std::optional<uint64_t> DiameterAVP::getDataAsUint64() const {
    if (data.size() != 8) {
        return std::nullopt;
    }

    uint64_t value;
    std::memcpy(&value, data.data(), 8);
    // Convert from network byte order (big-endian)
    return be64toh(value);
}

std::optional<int32_t> DiameterAVP::getDataAsInt32() const {
    if (data.size() != 4) {
        return std::nullopt;
    }

    int32_t value;
    std::memcpy(&value, data.data(), 4);
    return static_cast<int32_t>(ntohl(static_cast<uint32_t>(value)));
}

std::optional<int64_t> DiameterAVP::getDataAsInt64() const {
    if (data.size() != 8) {
        return std::nullopt;
    }

    int64_t value;
    std::memcpy(&value, data.data(), 8);
    return static_cast<int64_t>(be64toh(static_cast<uint64_t>(value)));
}

std::optional<std::vector<std::shared_ptr<DiameterAVP>>> DiameterAVP::getGroupedAVPs() const {
    if (std::holds_alternative<std::vector<std::shared_ptr<DiameterAVP>>>(decoded_value)) {
        return std::get<std::vector<std::shared_ptr<DiameterAVP>>>(decoded_value);
    }
    return std::nullopt;
}

std::string DiameterAVP::getAVPName() const {
    // Map common AVP codes to names
    switch (static_cast<DiameterAVPCode>(code)) {
        case DiameterAVPCode::SESSION_ID: return "Session-Id";
        case DiameterAVPCode::ORIGIN_HOST: return "Origin-Host";
        case DiameterAVPCode::ORIGIN_REALM: return "Origin-Realm";
        case DiameterAVPCode::DESTINATION_HOST: return "Destination-Host";
        case DiameterAVPCode::DESTINATION_REALM: return "Destination-Realm";
        case DiameterAVPCode::RESULT_CODE: return "Result-Code";
        case DiameterAVPCode::USER_NAME: return "User-Name";
        case DiameterAVPCode::AUTH_APPLICATION_ID: return "Auth-Application-Id";
        case DiameterAVPCode::ACCT_APPLICATION_ID: return "Acct-Application-Id";
        case DiameterAVPCode::VENDOR_ID: return "Vendor-Id";
        case DiameterAVPCode::PRODUCT_NAME: return "Product-Name";
        case DiameterAVPCode::FIRMWARE_REVISION: return "Firmware-Revision";
        case DiameterAVPCode::HOST_IP_ADDRESS: return "Host-IP-Address";
        default:
            return "AVP-" + std::to_string(code);
    }
}

size_t DiameterAVP::getDataLength() const {
    size_t header_size = vendor_specific ? DIAMETER_AVP_HEADER_VENDOR_SIZE : DIAMETER_AVP_HEADER_MIN_SIZE;
    return length > header_size ? (length - header_size) : 0;
}

size_t DiameterAVP::getTotalLength() const {
    // AVPs are padded to 4-byte boundaries
    size_t padding = (4 - (length % 4)) % 4;
    return length + padding;
}

// ============================================================================
// DiameterMessage Implementation
// ============================================================================

DiameterMessage::DiameterMessage() = default;

nlohmann::json DiameterMessage::toJson() const {
    nlohmann::json j;
    j["header"] = header.toJson();

    // Add extracted common fields
    if (session_id.has_value()) {
        j["session_id"] = session_id.value();
    }
    if (origin_host.has_value()) {
        j["origin_host"] = origin_host.value();
    }
    if (origin_realm.has_value()) {
        j["origin_realm"] = origin_realm.value();
    }
    if (destination_host.has_value()) {
        j["destination_host"] = destination_host.value();
    }
    if (destination_realm.has_value()) {
        j["destination_realm"] = destination_realm.value();
    }
    if (result_code.has_value()) {
        j["result_code"] = result_code.value();
        j["result_code_name"] = getResultCodeName(result_code.value());
        j["result_category"] = getResultCodeCategory(result_code.value());
    }
    if (auth_application_id.has_value()) {
        j["auth_application_id"] = auth_application_id.value();
    }
    if (acct_application_id.has_value()) {
        j["acct_application_id"] = acct_application_id.value();
    }

    // Add AVPs
    nlohmann::json avps_json = nlohmann::json::array();
    for (const auto& avp : avps) {
        if (avp) {
            avps_json.push_back(avp->toJson());
        }
    }
    j["avps"] = avps_json;
    j["avp_count"] = avps.size();

    return j;
}

std::optional<std::string> DiameterMessage::getResultCodeName() const {
    if (result_code.has_value()) {
        return diameter::getResultCodeName(result_code.value());
    }
    return std::nullopt;
}

bool DiameterMessage::isSuccess() const {
    return result_code.has_value() && result_code.value() >= 2000 && result_code.value() < 3000;
}

bool DiameterMessage::isError() const {
    return header.error || (result_code.has_value() && result_code.value() >= 3000);
}

std::shared_ptr<DiameterAVP> DiameterMessage::findAVP(uint32_t code) const {
    for (const auto& avp : avps) {
        if (avp && avp->code == code) {
            return avp;
        }
    }
    return nullptr;
}

std::vector<std::shared_ptr<DiameterAVP>> DiameterMessage::findAllAVPs(uint32_t code) const {
    std::vector<std::shared_ptr<DiameterAVP>> result;
    for (const auto& avp : avps) {
        if (avp && avp->code == code) {
            result.push_back(avp);
        }
    }
    return result;
}

std::shared_ptr<DiameterAVP> DiameterMessage::findAVP(uint32_t code, uint32_t vendor_id) const {
    for (const auto& avp : avps) {
        if (avp && avp->code == code && avp->vendor_id.has_value() && avp->vendor_id.value() == vendor_id) {
            return avp;
        }
    }
    return nullptr;
}

DiameterInterface DiameterMessage::getInterface() const {
    return getInterfaceFromApplicationID(header.application_id);
}

void DiameterMessage::extractCommonFields() {
    for (const auto& avp : avps) {
        if (!avp) continue;

        switch (static_cast<DiameterAVPCode>(avp->code)) {
            case DiameterAVPCode::SESSION_ID:
                session_id = avp->getDataAsString();
                break;
            case DiameterAVPCode::ORIGIN_HOST:
                origin_host = avp->getDataAsString();
                break;
            case DiameterAVPCode::ORIGIN_REALM:
                origin_realm = avp->getDataAsString();
                break;
            case DiameterAVPCode::DESTINATION_HOST:
                destination_host = avp->getDataAsString();
                break;
            case DiameterAVPCode::DESTINATION_REALM:
                destination_realm = avp->getDataAsString();
                break;
            case DiameterAVPCode::RESULT_CODE:
                result_code = avp->getDataAsUint32();
                break;
            case DiameterAVPCode::AUTH_APPLICATION_ID:
                auth_application_id = avp->getDataAsUint32();
                break;
            case DiameterAVPCode::ACCT_APPLICATION_ID:
                acct_application_id = avp->getDataAsUint32();
                break;
            default:
                break;
        }
    }
}

}  // namespace diameter
}  // namespace callflow
