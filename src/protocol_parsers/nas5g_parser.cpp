#include "protocol_parsers/nas5g_parser.h"

#include <cstring>
#include <iomanip>
#include <sstream>

#include "common/logger.h"
#include "common/utils.h"  // Added utils

namespace callflow {

// ============================================================================
// Nas5gMessage Methods
// ============================================================================

nlohmann::json Nas5gMessage::toJson() const {
    nlohmann::json j;
    j["security_header_type"] = static_cast<int>(security_header_type);
    j["message_type"] = message_type;
    j["message_type_name"] = getMessageTypeName();
    j["payload_length"] = payload.size();
    j["is_5gmm"] = is5gmm();
    j["is_5gsm"] = is5gsm();

    // Add decoded fields
    if (supi.has_value())
        j["supi"] = supi.value();
    if (five_g_guti.has_value())
        j["five_g_guti"] = five_g_guti.value();
    if (pdu_session_id.has_value())
        j["pdu_session_id"] = pdu_session_id.value();
    if (pti.has_value())
        j["pti"] = pti.value();
    if (request_type.has_value())
        j["request_type"] = request_type.value();
    if (dnn.has_value())
        j["dnn"] = dnn.value();
    if (s_nssai.has_value())
        j["s_nssai"] = s_nssai.value();

    // Add recursive IEs
    if (!ies.empty()) {
        j["ies"] = nlohmann::json::array();
        for (const auto& ie : ies) {
            j["ies"].push_back(ie.toJson());
        }
    }

    return j;
}

MessageType Nas5gMessage::getMessageType() const {
    switch (static_cast<Nas5gMessageType>(message_type)) {
        case Nas5gMessageType::REGISTRATION_REQUEST:
            return MessageType::NAS5G_REGISTRATION_REQUEST;
        case Nas5gMessageType::REGISTRATION_ACCEPT:
            return MessageType::NAS5G_REGISTRATION_ACCEPT;
        case Nas5gMessageType::DEREGISTRATION_REQUEST_UE_ORIGINATING:
        case Nas5gMessageType::DEREGISTRATION_REQUEST_UE_TERMINATED:
            return MessageType::NAS5G_DEREGISTRATION_REQUEST;
        case Nas5gMessageType::PDU_SESSION_ESTABLISHMENT_REQUEST:
            return MessageType::NAS5G_PDU_SESSION_ESTABLISHMENT_REQUEST;
        case Nas5gMessageType::PDU_SESSION_MODIFICATION_REQUEST:
        case Nas5gMessageType::PDU_SESSION_MODIFICATION_COMMAND:
            return MessageType::NAS5G_PDU_SESSION_MODIFICATION;
        default:
            return MessageType::UNKNOWN;
    }
}

std::string Nas5gMessage::getMessageTypeName() const {
    // Basic mapping for known types (same as before but can be expanded)
    switch (static_cast<Nas5gMessageType>(message_type)) {
        case Nas5gMessageType::REGISTRATION_REQUEST:
            return "Registration-Request";
        case Nas5gMessageType::REGISTRATION_ACCEPT:
            return "Registration-Accept";
        case Nas5gMessageType::REGISTRATION_COMPLETE:
            return "Registration-Complete";
        case Nas5gMessageType::REGISTRATION_REJECT:
            return "Registration-Reject";
        case Nas5gMessageType::DEREGISTRATION_REQUEST_UE_ORIGINATING:
            return "Deregistration-Request-UE-Orig";
        case Nas5gMessageType::DEREGISTRATION_ACCEPT_UE_ORIGINATING:
            return "Deregistration-Accept-UE-Orig";
        case Nas5gMessageType::DEREGISTRATION_REQUEST_UE_TERMINATED:
            return "Deregistration-Request-UE-Term";
        case Nas5gMessageType::DEREGISTRATION_ACCEPT_UE_TERMINATED:
            return "Deregistration-Accept-UE-Term";
        case Nas5gMessageType::SERVICE_REQUEST:
            return "Service-Request";
        case Nas5gMessageType::SERVICE_REJECT:
            return "Service-Reject";
        case Nas5gMessageType::SERVICE_ACCEPT:
            return "Service-Accept";
        case Nas5gMessageType::CONFIGURATION_UPDATE_COMMAND:
            return "Configuration-Update-Command";
        case Nas5gMessageType::CONFIGURATION_UPDATE_COMPLETE:
            return "Configuration-Update-Complete";
        case Nas5gMessageType::AUTHENTICATION_REQUEST:
            return "Authentication-Request";
        case Nas5gMessageType::AUTHENTICATION_RESPONSE:
            return "Authentication-Response";
        case Nas5gMessageType::AUTHENTICATION_REJECT:
            return "Authentication-Reject";
        case Nas5gMessageType::AUTHENTICATION_FAILURE:
            return "Authentication-Failure";
        case Nas5gMessageType::AUTHENTICATION_RESULT:
            return "Authentication-Result";
        case Nas5gMessageType::IDENTITY_REQUEST:
            return "Identity-Request";
        case Nas5gMessageType::IDENTITY_RESPONSE:
            return "Identity-Response";
        case Nas5gMessageType::SECURITY_MODE_COMMAND:
            return "Security-Mode-Command";
        case Nas5gMessageType::SECURITY_MODE_COMPLETE:
            return "Security-Mode-Complete";
        case Nas5gMessageType::SECURITY_MODE_REJECT:
            return "Security-Mode-Reject";
        case Nas5gMessageType::PDU_SESSION_ESTABLISHMENT_REQUEST:
            return "PDU-Session-Establishment-Request";
        case Nas5gMessageType::PDU_SESSION_ESTABLISHMENT_ACCEPT:
            return "PDU-Session-Establishment-Accept";
        case Nas5gMessageType::PDU_SESSION_ESTABLISHMENT_REJECT:
            return "PDU-Session-Establishment-Reject";
        case Nas5gMessageType::PDU_SESSION_AUTHENTICATION_COMMAND:
            return "PDU-Session-Authentication-Command";
        case Nas5gMessageType::PDU_SESSION_AUTHENTICATION_COMPLETE:
            return "PDU-Session-Authentication-Complete";
        case Nas5gMessageType::PDU_SESSION_AUTHENTICATION_RESULT:
            return "PDU-Session-Authentication-Result";
        case Nas5gMessageType::PDU_SESSION_MODIFICATION_REQUEST:
            return "PDU-Session-Modification-Request";
        case Nas5gMessageType::PDU_SESSION_MODIFICATION_REJECT:
            return "PDU-Session-Modification-Reject";
        case Nas5gMessageType::PDU_SESSION_MODIFICATION_COMMAND:
            return "PDU-Session-Modification-Command";
        case Nas5gMessageType::PDU_SESSION_MODIFICATION_COMPLETE:
            return "PDU-Session-Modification-Complete";
        case Nas5gMessageType::PDU_SESSION_MODIFICATION_COMMAND_REJECT:
            return "PDU-Session-Modification-Command-Reject";
        case Nas5gMessageType::PDU_SESSION_RELEASE_REQUEST:
            return "PDU-Session-Release-Request";
        case Nas5gMessageType::PDU_SESSION_RELEASE_REJECT:
            return "PDU-Session-Release-Reject";
        case Nas5gMessageType::PDU_SESSION_RELEASE_COMMAND:
            return "PDU-Session-Release-Command";
        case Nas5gMessageType::PDU_SESSION_RELEASE_COMPLETE:
            return "PDU-Session-Release-Complete";
        default:
            return "Unknown-5G-NAS-Message-" + std::to_string(message_type);
    }
}

bool Nas5gMessage::is5gmm() const {
    return (message_type >= 0x40 && message_type < 0xc0);
}

bool Nas5gMessage::is5gsm() const {
    return (message_type >= 0xc0);
}

// ============================================================================
// Nas5gParser Methods
// ============================================================================

bool Nas5gParser::isNas5g(const uint8_t* data, size_t len) {
    if (!data || len < 3)
        return false;
    uint8_t epd = data[0];
    return (epd == 0x7E || epd == 0x2E);
}

std::optional<Nas5gMessage> Nas5gParser::parse(const uint8_t* data, size_t len,
                                               NasSecurityContext* context) {
    if (!isNas5g(data, len)) {
        return std::nullopt;
    }

    // 1. Parse Outer Header
    auto msg_opt = parseHeader(data, len);
    if (!msg_opt.has_value()) {
        return std::nullopt;
    }

    Nas5gMessage msg = msg_opt.value();

    // 2. Handle Security Protection
    if (msg.security_header_type != Nas5gSecurityHeaderType::PLAIN_NAS_MESSAGE) {
        // If we have a context and this is a protected message
        if (context && msg.payload.size() > 0) {
            // Retrieve Sequence Number from the original data (offset 6)
            // Header: EPD(1) + SecHdr(1) + MAC(4) + SEQ(1) = 7 bytes
            if (len < 7)
                return msg;
            uint8_t seq_num = data[6];

            // Estimate NAS COUNT (Overflow handling simplified)
            // We need to compare received seq_num with expected.
            // For simplicity, we just use the seq_num with current overflow or 0 if not tracked
            // deeply yet In a real implementation: verify MAC first, then decrypt.

            uint32_t count = seq_num;  // Simplified: ignore overflow for now

            // Verify Integrity (MAC is at data[2]..data[5])
            std::array<uint8_t, 4> rx_mac;
            std::memcpy(rx_mac.data(), data + 2, 4);

            // The input to integrity check is COUNT + HEADER + PAYLOAD?
            // Actually, it's complex. Let's skip integrity verification in this step
            // and focus on decryption to get the inner message.

            // Decrypt
            // Payload starts at offset 7.
            std::vector<uint8_t> inner_payload = context->decrypt(
                msg.payload, count,
                NasDirection::UPLINK);  // Assume Uplink? Needs to be passed in or inferred.
            // For PCAP analysis, we might need to know direction from IP header.
            // Nas5gParser::parse signature might need Direction.

            if (!inner_payload.empty()) {
                // 3. Parse Inner Message (Recursive)
                // The inner message has its own EPD and Header if it's not SERVICE_REQUEST?
                // Standard says: "Secure NAS transport" contains "Plain NAS message"
                // So we recurse.

                // However, we must prevent infinite recursion if decryption fails (returns garbage
                // that looks like NAS) Check if inner payload looks like valid NAS
                if (isNas5g(inner_payload.data(), inner_payload.size())) {
                    // Parse inner, but don't pass context again (to avoid double decryption if
                    // wrongly inferred) Actually, inner message is PLAIN.
                    auto inner_msg_opt = parse(inner_payload.data(), inner_payload.size(), nullptr);
                    if (inner_msg_opt.has_value()) {
                        return inner_msg_opt.value();
                    }
                }

                // If recursion failed, maybe it's not a full message but just payload?
                // Return the outer message but with decrypted payload attached as a
                // "Decrypted-Payload" IE?
                NasIe decrypted_ie;
                decrypted_ie.name = "Decrypted Payload";
                decrypted_ie.raw_data = inner_payload;
                msg.ies.push_back(decrypted_ie);
                return msg;
            }
        }
    }

    // Parse message body based on type
    if (msg.is5gmm()) {
        parse5gmmMessage(msg);
    } else if (msg.is5gsm()) {
        parse5gsmMessage(msg);
    }

    // Extract IEs
    extractIEs(msg);

    return msg;
}

std::optional<Nas5gMessage> Nas5gParser::parseHeader(const uint8_t* data, size_t len) {
    if (len < 3)
        return std::nullopt;

    Nas5gMessage msg;
    size_t offset = 0;

    // Byte 0: EPD
    uint8_t epd = data[offset++];

    // Byte 1: Security Header Type
    uint8_t sec_hdr = data[offset++];
    msg.security_header_type = static_cast<Nas5gSecurityHeaderType>((sec_hdr >> 4) & 0x0F);

    // If security protected
    if (msg.security_header_type != Nas5gSecurityHeaderType::PLAIN_NAS_MESSAGE) {
        // MAC (4 bytes)
        if (len < offset + 4)
            return std::nullopt;
        offset += 4;

        // Sequence Number (1 byte)
        if (len < offset + 1)
            return std::nullopt;
        // uint8_t seq_num = data[offset]; // We should capture this
        offset += 1;

        // For protected messages, the rest is the encrypted payload (or cleartext if just
        // integrity) Note: Protected message contains Complete NAS Message as payload. The inner
        // message has its own EPD and Msg Type. If we are just parsing the outer wrapper, we stop
        // here for payload.
        if (offset < len) {
            msg.payload.resize(len - offset);
            std::memcpy(msg.payload.data(), data + offset, len - offset);
        }
        // Message Type is NOT valid here for the outer wrapper (it's part of the encrypted payload)
        // But the struct requires a message_type.
        // The outer header doesn't strictly have a "message type" field in the same place?
        // Actually, for Security Protected NAS messages, the EPD and Security Header are the
        // header. There is no Message Type field in the security header part. The payload starts
        // immediately. So we should set message_type to something placeholder or 0.
        msg.message_type = 0;

        return msg;
    }

    // Message Type
    if (offset >= len)
        return std::nullopt;
    msg.message_type = data[offset++];

    // For 5GSM (EPD=0x2E), PDU Session ID and PTI
    if (epd == 0x2E) {
        if (len < offset + 2)
            return std::nullopt;
        msg.pdu_session_id = data[offset++];
        msg.pti = data[offset++];
    }

    // Copy remaining payload
    if (offset < len) {
        msg.payload.resize(len - offset);
        std::memcpy(msg.payload.data(), data + offset, len - offset);
    }

    return msg;
}

void Nas5gParser::parse5gmmMessage(Nas5gMessage& msg) {
    if (msg.payload.empty())
        return;
    // 5GMM specific parsing (e.g. initial simplified logic, now mostly handled by extractIEs)
}

void Nas5gParser::parse5gsmMessage(Nas5gMessage& msg) {
    if (msg.payload.empty())
        return;
    // 5GSM specific parsing
}

// ... helper decoding functions (decodeMobileIdentity, etc.) ...
// For brevity in this turn, I will retain previous helpers or implement them if I rewrite the file.
// Since I am overwriting, I must include them.

void Nas5gParser::extractIEs(Nas5gMessage& msg) {
    if (msg.payload.empty())
        return;

    const uint8_t* data = msg.payload.data();
    size_t len = msg.payload.size();
    size_t offset = 0;

    // Map of IEIs to names/types (Simplified)
    // Common IEs:
    // 0x77: 5GS Mobile Identity (TLV-E)
    // 0x54: 5GS Registration Type (TV 1)
    // 0x2E: UE Security Capability (TLV)
    // 0x71: 5GS Mobile Identity (TLV) ?

    while (offset < len) {
        uint8_t iei = data[offset];
        NasIe ie;
        ie.iei = iei;
        bool parsed = false;

        // 1. Mobile Identity (TLV-E)
        if (iei == 0x77) {
            if (offset + 3 <= len) {
                uint16_t ie_len = (data[offset + 1] << 8) | data[offset + 2];
                offset += 3;
                if (offset + ie_len <= len) {
                    ie.name = "5GS Mobile Identity";
                    ie.raw_data.assign(data + offset, data + offset + ie_len);
                    ie.decoded_value =
                        decodeMobileIdentity(ie.raw_data.data(), ie_len).value_or("Raw");
                    msg.ies.push_back(ie);

                    if (!msg.supi.has_value())
                        msg.supi = ie.decoded_value;
                    if (ie.decoded_value.find("5G-GUTI") != std::string::npos)
                        msg.five_g_guti = ie.decoded_value;

                    offset += ie_len;
                    parsed = true;
                }
            }
        }
        // 2. UE Security Capability (TLV 2-? depending on standard version, usually length byte)
        else if (iei == 0x2E) {
            if (offset + 1 < len) {
                uint8_t ie_len = data[offset + 1];
                offset += 2;
                if (offset + ie_len <= len) {
                    ie.name = "UE Security Capability";
                    ie.raw_data.assign(data + offset, data + offset + ie_len);
                    // Decode capabilities...
                    ie.decoded_value =
                        "UE Security Capability (Len=" + std::to_string(ie_len) + ")";
                    msg.ies.push_back(ie);
                    offset += ie_len;
                    parsed = true;
                }
            }
        }
        // 3. DNN (TLV) - 0x25
        else if (iei == 0x25) {
            if (offset + 1 < len) {
                // TV / T types (Fixed Length IEs or Type Only)
                if ((iei & 0xF0) == 0x90 ||
                    (iei & 0xF0) == 0xA0) {  // Example: Type 1 TV (half octet)
                    parsed = true;
                    offset++;
                } else if (iei == 0x01) {  // 9.11.3.47 Requested NB-N1 mode promise (T)
                    ie.name = "Requested NB-N1 mode promise";
                    parsed = true;
                    offset++;
                }

                // TLV Types (Variable Length)
                if (!parsed) {
                    offset++;  // Skip IEI
                    if (offset >= len) {
                        msg.ies.push_back(ie);
                        break;
                    }

                    size_t ie_len = 0;
                    [[maybe_unused]] size_t len_bytes = 1;

                    // Check for TLV-E (Extended Length) IEs
                    if (iei == 0x7E || iei == 0x7F || iei == 0x7D) {
                        // TLV-E: Length is 2 bytes
                        if (offset + 2 > len)
                            break;
                        ie_len = (data[offset] << 8) | data[offset + 1];
                        offset += 2;
                        len_bytes = 2;
                    } else {
                        // Standard TLV
                        ie_len = data[offset];
                        offset++;
                    }

                    if (offset + ie_len > len) {
                        // Truncated IE
                        ie.raw_data.assign(data + offset, data + len);
                        offset = len;
                    } else {
                        ie.raw_data.assign(data + offset, data + offset + ie_len);
                        offset += ie_len;
                    }

                    // Decode known IEs
                    switch (iei) {
                        case 0x77:  // 5GS Mobile Identity
                            ie.name = "5GS Mobile Identity";
                            ie.decoded_value =
                                decodeMobileIdentity(ie.raw_data.data(), ie.raw_data.size())
                                    .value_or("");
                            if (!ie.decoded_value.empty())
                                msg.supi = ie.decoded_value;
                            break;
                        case 0x2E:  // UE Security Capability
                            ie.name = "UE Security Capability";
                            break;
                        case 0x54:  // 5GS Tracking Area Identity List
                            ie.name = "5GS TAI List";
                            break;
                        case 0x15:  // Allowed NSSAI
                        case 0x22:  // S-NSSAI
                            ie.name = "NSSAI";
                            ie.decoded_value =
                                decodeSNssai(ie.raw_data.data(), ie.raw_data.size()).value_or("");
                            break;
                        case 0x25:  // DNN
                            ie.name = "DNN";
                            ie.decoded_value =
                                decodeDnn(ie.raw_data.data(), ie.raw_data.size()).value_or("");
                            if (!ie.decoded_value.empty())
                                msg.dnn = ie.decoded_value;
                            break;
                        case 0x71:  // 5GS Mobile Identity Type
                            ie.name = "5GS Mobile Identity Type";
                            break;
                        case 0x7E:  // Payload Container
                            ie.name = "Payload Container";
                            break;
                        default:
                            ie.name = "Unknown IE (0x" + utils::toHexString(iei) + ")";
                            break;
                    }

                    msg.ies.push_back(ie);
                }
            }
        }
    }
}

std::optional<std::string> Nas5gParser::decodeMobileIdentity(const uint8_t* data, size_t len) {
    if (len < 1)
        return std::nullopt;

    // TS 24.501 9.11.3.4
    uint8_t type = data[0] & 0x07;

    if (type == 0x01) {  // SUCI
        return decodeSupci(data, len);
    } else if (type == 0x02) {  // 5G-GUTI
        return decode5gGuti(data, len);
    } else if (type == 0x03) {  // IMEI
        // Similar BCD structure to IMSI but with IMEI
        return "IMEI-" + utils::bcdToString(data, len, 1);
    } else if (type == 0x04) {  // 5G-S-TMSI
        return "5G-S-TMSI";
    }

    return "Unknown-Mobile-ID-Type-" + std::to_string(type);
}

std::optional<std::string> Nas5gParser::decodeSupci(const uint8_t* data, size_t len) {
    (void)data; (void)len;
    if (len < 4)
        return std::nullopt;
    return "SUCI (Encrypted)";
}

std::optional<std::string> Nas5gParser::decode5gGuti(const uint8_t* data, size_t len) {
    (void)data; (void)len;
    return "5G-GUTI";
}

std::optional<std::string> Nas5gParser::decodeDnn(const uint8_t* data, size_t len) {
    if (len == 0)
        return std::nullopt;
    std::string dnn;
    size_t pos = 0;
    while (pos < len) {
        uint8_t label_len = data[pos];
        pos++;
        if (pos + label_len > len)
            break;
        if (!dnn.empty())
            dnn += ".";
        dnn.append(reinterpret_cast<const char*>(data + pos), label_len);
        pos += label_len;
    }
    return dnn;
}

std::optional<std::string> Nas5gParser::decodeSNssai(const uint8_t* data, size_t len) {
    if (len < 1)
        return std::nullopt;
    uint8_t sst = data[0];
    std::string nssai = "SST: " + std::to_string(sst);
    if (len >= 4) {
        uint32_t sd = (data[1] << 16) | (data[2] << 8) | data[3];
        nssai += ", SD: 0x" + utils::toHexString(sd);
    }
    return nssai;
}

}  // namespace callflow
