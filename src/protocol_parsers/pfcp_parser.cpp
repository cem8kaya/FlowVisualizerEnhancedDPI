#include "protocol_parsers/pfcp_parser.h"
#include "common/logger.h"
#include <cstring>
#include <arpa/inet.h>
#include <sstream>
#include <iomanip>

namespace callflow {

// ============================================================================
// PfcpHeader Methods
// ============================================================================

nlohmann::json PfcpHeader::toJson() const {
    nlohmann::json j;
    j["version"] = version;
    j["seid_present"] = spare;
    j["message_type"] = message_type;
    j["message_type_name"] = pfcpMessageTypeToString(static_cast<PfcpMessageType>(message_type));
    j["message_length"] = message_length;
    if (seid.has_value()) {
        j["seid"] = seid.value();
    }
    j["sequence_number"] = sequence_number;
    if (message_priority) {
        j["message_priority"] = message_priority_value;
    }
    return j;
}

// ============================================================================
// PfcpInformationElement Methods
// ============================================================================

nlohmann::json PfcpInformationElement::toJson() const {
    nlohmann::json j;
    j["type"] = type;
    j["type_name"] = getTypeName();
    j["length"] = length;

    // Try to represent data as string if appropriate
    std::string str_data = getDataAsString();
    if (!str_data.empty()) {
        j["data"] = str_data;
    } else {
        // Otherwise represent as hex array for debugging
        j["data_hex"] = nlohmann::json::array();
        size_t max_display = std::min(data.size(), size_t(32));
        for (size_t i = 0; i < max_display; ++i) {
            j["data_hex"].push_back(data[i]);
        }
        if (data.size() > max_display) {
            j["data_truncated"] = true;
        }
    }

    return j;
}

std::string PfcpInformationElement::getTypeName() const {
    return pfcpIeTypeToString(static_cast<PfcpIeType>(type));
}

std::optional<uint8_t> PfcpInformationElement::getDataAsUint8() const {
    if (data.empty()) {
        return std::nullopt;
    }
    return data[0];
}

std::optional<uint16_t> PfcpInformationElement::getDataAsUint16() const {
    if (data.size() < 2) {
        return std::nullopt;
    }
    uint16_t value;
    std::memcpy(&value, data.data(), 2);
    return ntohs(value);
}

std::optional<uint32_t> PfcpInformationElement::getDataAsUint32() const {
    if (data.size() < 4) {
        return std::nullopt;
    }
    uint32_t value;
    std::memcpy(&value, data.data(), 4);
    return ntohl(value);
}

std::optional<uint64_t> PfcpInformationElement::getDataAsUint64() const {
    if (data.size() < 8) {
        return std::nullopt;
    }
    uint64_t value;
    std::memcpy(&value, data.data(), 8);
    return be64toh(value);
}

std::string PfcpInformationElement::getDataAsString() const {
    if (data.empty()) {
        return "";
    }

    // Check if data is printable ASCII
    for (auto byte : data) {
        if (byte < 0x20 || byte > 0x7E) {
            return "";  // Non-printable character
        }
    }

    return std::string(reinterpret_cast<const char*>(data.data()), data.size());
}

// ============================================================================
// PfcpFSeid Methods
// ============================================================================

nlohmann::json PfcpFSeid::toJson() const {
    nlohmann::json j;
    j["seid"] = seid;
    if (ipv4.has_value()) {
        j["ipv4"] = ipv4.value();
    }
    if (ipv6.has_value()) {
        j["ipv6"] = ipv6.value();
    }
    return j;
}

// ============================================================================
// PfcpFTeid Methods
// ============================================================================

nlohmann::json PfcpFTeid::toJson() const {
    nlohmann::json j;
    j["teid"] = teid;
    j["choose"] = choose;
    if (choose) {
        j["choose_id"] = choose_id;
    }
    if (ipv4.has_value()) {
        j["ipv4"] = ipv4.value();
    }
    if (ipv6.has_value()) {
        j["ipv6"] = ipv6.value();
    }
    return j;
}

// ============================================================================
// PfcpUeIpAddress Methods
// ============================================================================

nlohmann::json PfcpUeIpAddress::toJson() const {
    nlohmann::json j;
    if (ipv4.has_value()) {
        j["ipv4"] = ipv4.value();
    }
    if (ipv6.has_value()) {
        j["ipv6"] = ipv6.value();
    }
    j["is_source"] = is_source;
    j["is_destination"] = is_destination;
    return j;
}

// ============================================================================
// PfcpPdr Methods
// ============================================================================

nlohmann::json PfcpPdr::toJson() const {
    nlohmann::json j;
    j["pdr_id"] = pdr_id;
    j["precedence"] = precedence;
    if (source_interface.has_value()) {
        j["source_interface"] = pfcpSourceInterfaceToString(source_interface.value());
    }
    if (f_teid.has_value()) {
        j["f_teid"] = f_teid->toJson();
    }
    if (network_instance.has_value()) {
        j["network_instance"] = network_instance.value();
    }
    if (ue_ip_address.has_value()) {
        j["ue_ip_address"] = ue_ip_address->toJson();
    }
    if (linked_far_id.has_value()) {
        j["linked_far_id"] = linked_far_id.value();
    }
    return j;
}

// ============================================================================
// PfcpFar Methods
// ============================================================================

nlohmann::json PfcpFar::toJson() const {
    nlohmann::json j;
    j["far_id"] = far_id;
    j["apply_action"]["drop"] = apply_action.drop;
    j["apply_action"]["forward"] = apply_action.forward;
    j["apply_action"]["buffer"] = apply_action.buffer;
    j["apply_action"]["notify_cp"] = apply_action.notify_cp;
    j["apply_action"]["duplicate"] = apply_action.duplicate;
    if (destination_interface.has_value()) {
        j["destination_interface"] = pfcpDestinationInterfaceToString(destination_interface.value());
    }
    if (outer_header_creation.has_value()) {
        j["outer_header_creation"] = outer_header_creation->toJson();
    }
    if (network_instance.has_value()) {
        j["network_instance"] = network_instance.value();
    }
    return j;
}

// ============================================================================
// PfcpUrr Methods
// ============================================================================

nlohmann::json PfcpUrr::toJson() const {
    nlohmann::json j;
    j["urr_id"] = urr_id;
    j["measurement_method"] = measurement_method;
    if (volume_threshold.has_value()) {
        j["volume_threshold"] = volume_threshold.value();
    }
    if (time_threshold.has_value()) {
        j["time_threshold"] = time_threshold.value();
    }
    return j;
}

// ============================================================================
// PfcpQer Methods
// ============================================================================

nlohmann::json PfcpQer::toJson() const {
    nlohmann::json j;
    j["qer_id"] = qer_id;
    j["qci"] = qci;
    if (mbr_uplink.has_value()) {
        j["mbr_uplink"] = mbr_uplink.value();
    }
    if (mbr_downlink.has_value()) {
        j["mbr_downlink"] = mbr_downlink.value();
    }
    if (gbr_uplink.has_value()) {
        j["gbr_uplink"] = gbr_uplink.value();
    }
    if (gbr_downlink.has_value()) {
        j["gbr_downlink"] = gbr_downlink.value();
    }
    return j;
}

// ============================================================================
// PfcpMessage Methods
// ============================================================================

nlohmann::json PfcpMessage::toJson() const {
    nlohmann::json j;
    j["header"] = header.toJson();
    j["message_type_name"] = getMessageTypeName();
    j["is_session_message"] = isSessionMessage();

    if (f_seid.has_value()) {
        j["f_seid"] = f_seid->toJson();
    }
    if (node_id.has_value()) {
        j["node_id"] = node_id.value();
    }

    // Add PDRs
    if (!pdrs.empty()) {
        nlohmann::json pdrs_json = nlohmann::json::array();
        for (const auto& pdr : pdrs) {
            pdrs_json.push_back(pdr.toJson());
        }
        j["pdrs"] = pdrs_json;
        j["pdr_count"] = pdrs.size();
    }

    // Add FARs
    if (!fars.empty()) {
        nlohmann::json fars_json = nlohmann::json::array();
        for (const auto& far : fars) {
            fars_json.push_back(far.toJson());
        }
        j["fars"] = fars_json;
        j["far_count"] = fars.size();
    }

    // Add URRs
    if (!urrs.empty()) {
        nlohmann::json urrs_json = nlohmann::json::array();
        for (const auto& urr : urrs) {
            urrs_json.push_back(urr.toJson());
        }
        j["urrs"] = urrs_json;
        j["urr_count"] = urrs.size();
    }

    // Add QERs
    if (!qers.empty()) {
        nlohmann::json qers_json = nlohmann::json::array();
        for (const auto& qer : qers) {
            qers_json.push_back(qer.toJson());
        }
        j["qers"] = qers_json;
        j["qer_count"] = qers.size();
    }

    // Add top-level IEs (simplified)
    j["ie_count"] = ies.size();

    return j;
}

MessageType PfcpMessage::getMessageType() const {
    // PFCP doesn't have specific MessageType mappings in common types yet
    // For now, return UNKNOWN - can be extended later
    return MessageType::UNKNOWN;
}

std::string PfcpMessage::getMessageTypeName() const {
    return pfcpMessageTypeToString(static_cast<PfcpMessageType>(header.message_type));
}

bool PfcpMessage::isSessionMessage() const {
    uint8_t mt = header.message_type;
    return mt >= 50 && mt <= 57;  // Session-related messages are 50-57
}

std::optional<uint64_t> PfcpMessage::getSessionId() const {
    return header.seid;
}

// ============================================================================
// PfcpParser Methods
// ============================================================================

bool PfcpParser::isPfcp(const uint8_t* data, size_t len) {
    if (!data || len < 4) {
        return false;
    }

    // Check for PFCP version 1
    uint8_t flags = data[0];
    uint8_t version = (flags >> 5) & 0x07;

    if (version != 1) {
        return false;
    }

    // Check message type is in valid range
    uint8_t msg_type = data[1];
    if ((msg_type >= 1 && msg_type <= 13) ||    // Node messages
        (msg_type >= 50 && msg_type <= 57)) {    // Session messages
        return true;
    }

    return false;
}

std::optional<PfcpMessage> PfcpParser::parse(const uint8_t* data, size_t len) {
    if (!isPfcp(data, len)) {
        LOG_DEBUG("Not a valid PFCP message");
        return std::nullopt;
    }

    size_t offset = 0;

    // Parse header
    auto header_opt = parseHeader(data, len, offset);
    if (!header_opt.has_value()) {
        LOG_ERROR("Failed to parse PFCP header");
        return std::nullopt;
    }

    PfcpMessage msg;
    msg.header = header_opt.value();

    // Check if we have the complete message
    size_t total_len = 4 + msg.header.message_length;
    if (len < total_len) {
        LOG_DEBUG("Incomplete PFCP message: have " << len << " bytes, need " << total_len);
        return std::nullopt;
    }

    // Parse IEs
    if (!parseInformationElements(data, total_len, offset, msg.ies)) {
        LOG_ERROR("Failed to parse PFCP IEs");
        return std::nullopt;
    }

    // Extract common fields
    extractCommonFields(msg);

    LOG_DEBUG("Parsed PFCP message: " << msg.getMessageTypeName()
              << " with " << msg.ies.size() << " IEs, "
              << msg.pdrs.size() << " PDRs, "
              << msg.fars.size() << " FARs");

    return msg;
}

std::optional<PfcpHeader> PfcpParser::parseHeader(const uint8_t* data, size_t len, size_t& offset) {
    if (len < 4) {
        return std::nullopt;
    }

    PfcpHeader header;

    // Byte 0: Flags
    uint8_t flags = data[0];
    header.version = (flags >> 5) & 0x07;           // Version (bits 5-7)
    header.spare = (flags & 0x01) != 0;             // S flag (bit 0) - SEID present
    header.message_priority = (flags & 0x02) != 0;  // MP flag (bit 1)

    // Byte 1: Message Type
    header.message_type = data[1];

    // Bytes 2-3: Message Length
    std::memcpy(&header.message_length, data + 2, 2);
    header.message_length = ntohs(header.message_length);

    offset = 4;

    // If S flag is set, SEID is present (8 bytes)
    if (header.spare) {
        if (len < 16) {
            return std::nullopt;
        }

        uint64_t seid;
        std::memcpy(&seid, data + offset, 8);
        header.seid = be64toh(seid);
        offset += 8;
    }

    // Sequence number (3 bytes) and message priority/spare (1 byte)
    if (offset + 4 > len) {
        return std::nullopt;
    }

    header.sequence_number = (static_cast<uint32_t>(data[offset]) << 16) |
                            (static_cast<uint32_t>(data[offset + 1]) << 8) |
                            static_cast<uint32_t>(data[offset + 2]);

    if (header.message_priority) {
        header.message_priority_value = (data[offset + 3] >> 4) & 0x0F;
    }

    offset += 4;

    return header;
}

bool PfcpParser::parseInformationElements(const uint8_t* data, size_t len, size_t offset,
                                          std::vector<PfcpInformationElement>& ies) {
    while (offset < len) {
        auto ie_opt = parseIe(data, len, offset);
        if (!ie_opt.has_value()) {
            // Failed to parse IE - might be end of valid data
            break;
        }

        ies.push_back(ie_opt.value());
    }

    return true;
}

std::optional<PfcpInformationElement> PfcpParser::parseIe(const uint8_t* data, size_t len,
                                                          size_t& offset) {
    // IE header is at least 4 bytes (Type: 2 bytes, Length: 2 bytes)
    if (offset + 4 > len) {
        LOG_DEBUG("Not enough data for PFCP IE header at offset " << offset);
        return std::nullopt;
    }

    PfcpInformationElement ie;

    // Bytes 0-1: IE Type (2 bytes, big-endian)
    std::memcpy(&ie.type, data + offset, 2);
    ie.type = ntohs(ie.type);

    // Bytes 2-3: IE Length (2 bytes, big-endian)
    std::memcpy(&ie.length, data + offset + 2, 2);
    ie.length = ntohs(ie.length);

    // Check if we have enough data
    if (offset + 4 + ie.length > len) {
        LOG_DEBUG("Not enough data for PFCP IE data at offset " << offset
                  << ", need " << (4 + ie.length) << " bytes");
        return std::nullopt;
    }

    // Copy IE data
    ie.data.resize(ie.length);
    std::memcpy(ie.data.data(), data + offset + 4, ie.length);

    offset += 4 + ie.length;

    return ie;
}

void PfcpParser::extractCommonFields(PfcpMessage& msg) {
    // Extract F-SEID
    msg.f_seid = extractFSeid(msg.ies);

    // Extract Node ID
    msg.node_id = extractNodeId(msg.ies);

    // Extract PDRs, FARs, URRs, QERs
    msg.pdrs = extractPdrRules(msg.ies);
    msg.fars = extractFarRules(msg.ies);
    msg.urrs = extractUrrRules(msg.ies);
    msg.qers = extractQerRules(msg.ies);
}

std::optional<PfcpFSeid> PfcpParser::extractFSeid(const std::vector<PfcpInformationElement>& ies) {
    for (const auto& ie : ies) {
        if (static_cast<PfcpIeType>(ie.type) == PfcpIeType::F_SEID) {
            return decodeFSeid(ie.data);
        }
    }
    return std::nullopt;
}

std::optional<std::string> PfcpParser::extractNodeId(const std::vector<PfcpInformationElement>& ies) {
    for (const auto& ie : ies) {
        if (static_cast<PfcpIeType>(ie.type) == PfcpIeType::NODE_ID) {
            return decodeNodeId(ie.data);
        }
    }
    return std::nullopt;
}

std::vector<PfcpPdr> PfcpParser::extractPdrRules(const std::vector<PfcpInformationElement>& ies) {
    std::vector<PfcpPdr> pdrs;

    for (const auto& ie : ies) {
        if (static_cast<PfcpIeType>(ie.type) == PfcpIeType::CREATE_PDR) {
            PfcpPdr pdr;
            pdr.ies = parseGroupedIe(ie.data);

            // Parse PDR IEs
            for (const auto& pdr_ie : pdr.ies) {
                PfcpIeType pdr_ie_type = static_cast<PfcpIeType>(pdr_ie.type);

                if (pdr_ie_type == PfcpIeType::PDR_ID) {
                    auto id = pdr_ie.getDataAsUint16();
                    if (id.has_value()) {
                        pdr.pdr_id = id.value();
                    }
                } else if (pdr_ie_type == PfcpIeType::PRECEDENCE) {
                    auto prec = pdr_ie.getDataAsUint32();
                    if (prec.has_value()) {
                        pdr.precedence = prec.value();
                    }
                } else if (pdr_ie_type == PfcpIeType::SOURCE_INTERFACE) {
                    auto si = pdr_ie.getDataAsUint8();
                    if (si.has_value()) {
                        pdr.source_interface = static_cast<PfcpSourceInterface>(si.value() & 0x0F);
                    }
                } else if (pdr_ie_type == PfcpIeType::F_TEID) {
                    pdr.f_teid = decodeFTeid(pdr_ie.data);
                } else if (pdr_ie_type == PfcpIeType::NETWORK_INSTANCE) {
                    pdr.network_instance = decodeNetworkInstance(pdr_ie.data);
                } else if (pdr_ie_type == PfcpIeType::UE_IP_ADDRESS) {
                    pdr.ue_ip_address = decodeUeIpAddress(pdr_ie.data);
                } else if (pdr_ie_type == PfcpIeType::PDI) {
                    // PDI is also a grouped IE, parse recursively
                    auto pdi_ies = parseGroupedIe(pdr_ie.data);
                    for (const auto& pdi_ie : pdi_ies) {
                        PfcpIeType pdi_ie_type = static_cast<PfcpIeType>(pdi_ie.type);
                        if (pdi_ie_type == PfcpIeType::SOURCE_INTERFACE) {
                            auto si = pdi_ie.getDataAsUint8();
                            if (si.has_value()) {
                                pdr.source_interface = static_cast<PfcpSourceInterface>(si.value() & 0x0F);
                            }
                        } else if (pdi_ie_type == PfcpIeType::F_TEID) {
                            pdr.f_teid = decodeFTeid(pdi_ie.data);
                        } else if (pdi_ie_type == PfcpIeType::NETWORK_INSTANCE) {
                            pdr.network_instance = decodeNetworkInstance(pdi_ie.data);
                        } else if (pdi_ie_type == PfcpIeType::UE_IP_ADDRESS) {
                            pdr.ue_ip_address = decodeUeIpAddress(pdi_ie.data);
                        }
                    }
                }
            }

            pdrs.push_back(pdr);
        }
    }

    return pdrs;
}

std::vector<PfcpFar> PfcpParser::extractFarRules(const std::vector<PfcpInformationElement>& ies) {
    std::vector<PfcpFar> fars;

    for (const auto& ie : ies) {
        if (static_cast<PfcpIeType>(ie.type) == PfcpIeType::CREATE_FAR) {
            PfcpFar far;
            far.ies = parseGroupedIe(ie.data);
            far.apply_action = {false, false, false, false, false};

            // Parse FAR IEs
            for (const auto& far_ie : far.ies) {
                PfcpIeType far_ie_type = static_cast<PfcpIeType>(far_ie.type);

                if (far_ie_type == PfcpIeType::FAR_ID) {
                    auto id = far_ie.getDataAsUint32();
                    if (id.has_value()) {
                        far.far_id = id.value();
                    }
                } else if (far_ie_type == PfcpIeType::APPLY_ACTION) {
                    if (!far_ie.data.empty()) {
                        uint8_t action = far_ie.data[0];
                        far.apply_action.drop = (action & 0x01) != 0;
                        far.apply_action.forward = (action & 0x02) != 0;
                        far.apply_action.buffer = (action & 0x04) != 0;
                        far.apply_action.notify_cp = (action & 0x08) != 0;
                        far.apply_action.duplicate = (action & 0x10) != 0;
                    }
                } else if (far_ie_type == PfcpIeType::FORWARDING_PARAMETERS) {
                    // Parse forwarding parameters (grouped IE)
                    auto fwd_ies = parseGroupedIe(far_ie.data);
                    for (const auto& fwd_ie : fwd_ies) {
                        PfcpIeType fwd_ie_type = static_cast<PfcpIeType>(fwd_ie.type);
                        if (fwd_ie_type == PfcpIeType::DESTINATION_INTERFACE) {
                            auto di = fwd_ie.getDataAsUint8();
                            if (di.has_value()) {
                                far.destination_interface = static_cast<PfcpDestinationInterface>(di.value() & 0x0F);
                            }
                        } else if (fwd_ie_type == PfcpIeType::OUTER_HEADER_CREATION) {
                            far.outer_header_creation = decodeFTeid(fwd_ie.data);
                        } else if (fwd_ie_type == PfcpIeType::NETWORK_INSTANCE) {
                            far.network_instance = decodeNetworkInstance(fwd_ie.data);
                        }
                    }
                }
            }

            fars.push_back(far);
        }
    }

    return fars;
}

std::vector<PfcpUrr> PfcpParser::extractUrrRules(const std::vector<PfcpInformationElement>& ies) {
    std::vector<PfcpUrr> urrs;

    for (const auto& ie : ies) {
        if (static_cast<PfcpIeType>(ie.type) == PfcpIeType::CREATE_URR) {
            PfcpUrr urr;
            urr.ies = parseGroupedIe(ie.data);

            // Parse URR IEs
            for (const auto& urr_ie : urr.ies) {
                PfcpIeType urr_ie_type = static_cast<PfcpIeType>(urr_ie.type);

                if (urr_ie_type == PfcpIeType::URR_ID) {
                    auto id = urr_ie.getDataAsUint32();
                    if (id.has_value()) {
                        urr.urr_id = id.value();
                    }
                } else if (urr_ie_type == PfcpIeType::MEASUREMENT_METHOD) {
                    auto mm = urr_ie.getDataAsUint32();
                    if (mm.has_value()) {
                        urr.measurement_method = mm.value();
                    }
                } else if (urr_ie_type == PfcpIeType::VOLUME_THRESHOLD) {
                    auto vt = urr_ie.getDataAsUint64();
                    if (vt.has_value()) {
                        urr.volume_threshold = vt.value();
                    }
                } else if (urr_ie_type == PfcpIeType::TIME_THRESHOLD) {
                    auto tt = urr_ie.getDataAsUint32();
                    if (tt.has_value()) {
                        urr.time_threshold = tt.value();
                    }
                }
            }

            urrs.push_back(urr);
        }
    }

    return urrs;
}

std::vector<PfcpQer> PfcpParser::extractQerRules(const std::vector<PfcpInformationElement>& ies) {
    std::vector<PfcpQer> qers;

    for (const auto& ie : ies) {
        if (static_cast<PfcpIeType>(ie.type) == PfcpIeType::CREATE_QER) {
            PfcpQer qer;
            qer.qci = 0;
            qer.ies = parseGroupedIe(ie.data);

            // Parse QER IEs
            for (const auto& qer_ie : qer.ies) {
                PfcpIeType qer_ie_type = static_cast<PfcpIeType>(qer_ie.type);

                if (qer_ie_type == PfcpIeType::QER_ID) {
                    auto id = qer_ie.getDataAsUint32();
                    if (id.has_value()) {
                        qer.qer_id = id.value();
                    }
                } else if (qer_ie_type == PfcpIeType::GATE_STATUS) {
                    auto gs = qer_ie.getDataAsUint8();
                    if (gs.has_value()) {
                        qer.qci = gs.value();
                    }
                } else if (qer_ie_type == PfcpIeType::MBR) {
                    // MBR contains both UL and DL (5 bytes each)
                    if (qer_ie.data.size() >= 10) {
                        uint64_t ul, dl;
                        std::memcpy(&ul, qer_ie.data.data(), 5);
                        std::memcpy(&dl, qer_ie.data.data() + 5, 5);
                        qer.mbr_uplink = ul;
                        qer.mbr_downlink = dl;
                    }
                } else if (qer_ie_type == PfcpIeType::GBR) {
                    // GBR contains both UL and DL (5 bytes each)
                    if (qer_ie.data.size() >= 10) {
                        uint64_t ul, dl;
                        std::memcpy(&ul, qer_ie.data.data(), 5);
                        std::memcpy(&dl, qer_ie.data.data() + 5, 5);
                        qer.gbr_uplink = ul;
                        qer.gbr_downlink = dl;
                    }
                }
            }

            qers.push_back(qer);
        }
    }

    return qers;
}

std::vector<PfcpInformationElement> PfcpParser::parseGroupedIe(const std::vector<uint8_t>& data) {
    std::vector<PfcpInformationElement> ies;
    size_t offset = 0;

    while (offset < data.size()) {
        auto ie_opt = parseIe(data.data(), data.size(), offset);
        if (!ie_opt.has_value()) {
            break;
        }
        ies.push_back(ie_opt.value());
    }

    return ies;
}

std::optional<PfcpFSeid> PfcpParser::decodeFSeid(const std::vector<uint8_t>& data) {
    if (data.size() < 9) {
        return std::nullopt;
    }

    PfcpFSeid fseid;

    // Byte 0: Flags (V4 and V6 bits)
    uint8_t flags = data[0];
    bool v4 = (flags & 0x02) != 0;
    bool v6 = (flags & 0x01) != 0;

    // Bytes 1-8: SEID
    std::memcpy(&fseid.seid, data.data() + 1, 8);
    fseid.seid = be64toh(fseid.seid);

    size_t offset = 9;

    // IPv4 address (4 bytes, if V4 flag is set)
    if (v4 && offset + 4 <= data.size()) {
        struct in_addr addr;
        std::memcpy(&addr, data.data() + offset, 4);
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN);
        fseid.ipv4 = std::string(ip_str);
        offset += 4;
    }

    // IPv6 address (16 bytes, if V6 flag is set)
    if (v6 && offset + 16 <= data.size()) {
        struct in6_addr addr;
        std::memcpy(&addr, data.data() + offset, 16);
        char ip_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &addr, ip_str, INET6_ADDRSTRLEN);
        fseid.ipv6 = std::string(ip_str);
    }

    return fseid;
}

std::optional<PfcpFTeid> PfcpParser::decodeFTeid(const std::vector<uint8_t>& data) {
    if (data.size() < 5) {
        return std::nullopt;
    }

    PfcpFTeid fteid;

    // Byte 0: Flags
    uint8_t flags = data[0];
    bool v4 = (flags & 0x02) != 0;
    bool v6 = (flags & 0x01) != 0;
    fteid.choose = (flags & 0x08) != 0;
    fteid.choose_id = (flags >> 4) & 0x0F;

    // Bytes 1-4: TEID
    std::memcpy(&fteid.teid, data.data() + 1, 4);
    fteid.teid = ntohl(fteid.teid);

    size_t offset = 5;

    // IPv4 address (4 bytes, if V4 flag is set)
    if (v4 && offset + 4 <= data.size()) {
        struct in_addr addr;
        std::memcpy(&addr, data.data() + offset, 4);
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN);
        fteid.ipv4 = std::string(ip_str);
        offset += 4;
    }

    // IPv6 address (16 bytes, if V6 flag is set)
    if (v6 && offset + 16 <= data.size()) {
        struct in6_addr addr;
        std::memcpy(&addr, data.data() + offset, 16);
        char ip_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &addr, ip_str, INET6_ADDRSTRLEN);
        fteid.ipv6 = std::string(ip_str);
    }

    return fteid;
}

std::optional<PfcpUeIpAddress> PfcpParser::decodeUeIpAddress(const std::vector<uint8_t>& data) {
    if (data.empty()) {
        return std::nullopt;
    }

    PfcpUeIpAddress ue_ip;

    // Byte 0: Flags
    uint8_t flags = data[0];
    bool v4 = (flags & 0x02) != 0;
    bool v6 = (flags & 0x01) != 0;
    ue_ip.is_source = (flags & 0x04) != 0;
    ue_ip.is_destination = (flags & 0x08) != 0;

    size_t offset = 1;

    // IPv4 address (4 bytes, if V4 flag is set)
    if (v4 && offset + 4 <= data.size()) {
        struct in_addr addr;
        std::memcpy(&addr, data.data() + offset, 4);
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN);
        ue_ip.ipv4 = std::string(ip_str);
        offset += 4;
    }

    // IPv6 address (16 bytes, if V6 flag is set)
    if (v6 && offset + 16 <= data.size()) {
        struct in6_addr addr;
        std::memcpy(&addr, data.data() + offset, 16);
        char ip_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &addr, ip_str, INET6_ADDRSTRLEN);
        ue_ip.ipv6 = std::string(ip_str);
    }

    return ue_ip;
}

std::string PfcpParser::decodeNodeId(const std::vector<uint8_t>& data) {
    if (data.empty()) {
        return "";
    }

    // Byte 0: Node ID type
    uint8_t type = data[0] & 0x0F;

    if (type == 0) {  // IPv4
        if (data.size() >= 5) {
            struct in_addr addr;
            std::memcpy(&addr, data.data() + 1, 4);
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN);
            return std::string(ip_str);
        }
    } else if (type == 1) {  // IPv6
        if (data.size() >= 17) {
            struct in6_addr addr;
            std::memcpy(&addr, data.data() + 1, 16);
            char ip_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &addr, ip_str, INET6_ADDRSTRLEN);
            return std::string(ip_str);
        }
    } else if (type == 2) {  // FQDN
        return std::string(reinterpret_cast<const char*>(data.data() + 1), data.size() - 1);
    }

    return "";
}

std::string PfcpParser::decodeNetworkInstance(const std::vector<uint8_t>& data) {
    if (data.empty()) {
        return "";
    }
    return std::string(reinterpret_cast<const char*>(data.data()), data.size());
}

// ============================================================================
// Helper functions
// ============================================================================

std::string pfcpMessageTypeToString(PfcpMessageType type) {
    switch (type) {
        case PfcpMessageType::HEARTBEAT_REQUEST: return "Heartbeat-Request";
        case PfcpMessageType::HEARTBEAT_RESPONSE: return "Heartbeat-Response";
        case PfcpMessageType::PFD_MANAGEMENT_REQUEST: return "PFD-Management-Request";
        case PfcpMessageType::PFD_MANAGEMENT_RESPONSE: return "PFD-Management-Response";
        case PfcpMessageType::ASSOCIATION_SETUP_REQUEST: return "Association-Setup-Request";
        case PfcpMessageType::ASSOCIATION_SETUP_RESPONSE: return "Association-Setup-Response";
        case PfcpMessageType::ASSOCIATION_UPDATE_REQUEST: return "Association-Update-Request";
        case PfcpMessageType::ASSOCIATION_UPDATE_RESPONSE: return "Association-Update-Response";
        case PfcpMessageType::ASSOCIATION_RELEASE_REQUEST: return "Association-Release-Request";
        case PfcpMessageType::ASSOCIATION_RELEASE_RESPONSE: return "Association-Release-Response";
        case PfcpMessageType::VERSION_NOT_SUPPORTED: return "Version-Not-Supported";
        case PfcpMessageType::NODE_REPORT_REQUEST: return "Node-Report-Request";
        case PfcpMessageType::NODE_REPORT_RESPONSE: return "Node-Report-Response";
        case PfcpMessageType::SESSION_ESTABLISHMENT_REQUEST: return "Session-Establishment-Request";
        case PfcpMessageType::SESSION_ESTABLISHMENT_RESPONSE: return "Session-Establishment-Response";
        case PfcpMessageType::SESSION_MODIFICATION_REQUEST: return "Session-Modification-Request";
        case PfcpMessageType::SESSION_MODIFICATION_RESPONSE: return "Session-Modification-Response";
        case PfcpMessageType::SESSION_DELETION_REQUEST: return "Session-Deletion-Request";
        case PfcpMessageType::SESSION_DELETION_RESPONSE: return "Session-Deletion-Response";
        case PfcpMessageType::SESSION_REPORT_REQUEST: return "Session-Report-Request";
        case PfcpMessageType::SESSION_REPORT_RESPONSE: return "Session-Report-Response";
        default: return "Unknown-" + std::to_string(static_cast<uint8_t>(type));
    }
}

std::string pfcpIeTypeToString(PfcpIeType type) {
    switch (type) {
        case PfcpIeType::CREATE_PDR: return "Create-PDR";
        case PfcpIeType::PDI: return "PDI";
        case PfcpIeType::CREATE_FAR: return "Create-FAR";
        case PfcpIeType::FORWARDING_PARAMETERS: return "Forwarding-Parameters";
        case PfcpIeType::DUPLICATING_PARAMETERS: return "Duplicating-Parameters";
        case PfcpIeType::CREATE_URR: return "Create-URR";
        case PfcpIeType::CREATE_QER: return "Create-QER";
        case PfcpIeType::CREATED_PDR: return "Created-PDR";
        case PfcpIeType::UPDATE_PDR: return "Update-PDR";
        case PfcpIeType::UPDATE_FAR: return "Update-FAR";
        case PfcpIeType::UPDATE_FORWARDING_PARAMETERS: return "Update-Forwarding-Parameters";
        case PfcpIeType::UPDATE_BAR: return "Update-BAR";
        case PfcpIeType::UPDATE_URR: return "Update-URR";
        case PfcpIeType::UPDATE_QER: return "Update-QER";
        case PfcpIeType::REMOVE_PDR: return "Remove-PDR";
        case PfcpIeType::REMOVE_FAR: return "Remove-FAR";
        case PfcpIeType::REMOVE_URR: return "Remove-URR";
        case PfcpIeType::REMOVE_QER: return "Remove-QER";
        case PfcpIeType::CAUSE: return "Cause";
        case PfcpIeType::SOURCE_INTERFACE: return "Source-Interface";
        case PfcpIeType::F_TEID: return "F-TEID";
        case PfcpIeType::NETWORK_INSTANCE: return "Network-Instance";
        case PfcpIeType::SDF_FILTER: return "SDF-Filter";
        case PfcpIeType::APPLICATION_ID: return "Application-ID";
        case PfcpIeType::GATE_STATUS: return "Gate-Status";
        case PfcpIeType::MBR: return "MBR";
        case PfcpIeType::GBR: return "GBR";
        case PfcpIeType::QER_CORRELATION_ID: return "QER-Correlation-ID";
        case PfcpIeType::PRECEDENCE: return "Precedence";
        case PfcpIeType::TRANSPORT_LEVEL_MARKING: return "Transport-Level-Marking";
        case PfcpIeType::VOLUME_THRESHOLD: return "Volume-Threshold";
        case PfcpIeType::TIME_THRESHOLD: return "Time-Threshold";
        case PfcpIeType::MONITORING_TIME: return "Monitoring-Time";
        case PfcpIeType::SUBSEQUENT_VOLUME_THRESHOLD: return "Subsequent-Volume-Threshold";
        case PfcpIeType::SUBSEQUENT_TIME_THRESHOLD: return "Subsequent-Time-Threshold";
        case PfcpIeType::INACTIVITY_DETECTION_TIME: return "Inactivity-Detection-Time";
        case PfcpIeType::REPORTING_TRIGGERS: return "Reporting-Triggers";
        case PfcpIeType::REDIRECT_INFORMATION: return "Redirect-Information";
        case PfcpIeType::REPORT_TYPE: return "Report-Type";
        case PfcpIeType::OFFENDING_IE: return "Offending-IE";
        case PfcpIeType::FORWARDING_POLICY: return "Forwarding-Policy";
        case PfcpIeType::DESTINATION_INTERFACE: return "Destination-Interface";
        case PfcpIeType::UP_FUNCTION_FEATURES: return "UP-Function-Features";
        case PfcpIeType::APPLY_ACTION: return "Apply-Action";
        case PfcpIeType::DOWNLINK_DATA_SERVICE_INFORMATION: return "Downlink-Data-Service-Information";
        case PfcpIeType::DOWNLINK_DATA_NOTIFICATION_DELAY: return "Downlink-Data-Notification-Delay";
        case PfcpIeType::DL_BUFFERING_DURATION: return "DL-Buffering-Duration";
        case PfcpIeType::DL_BUFFERING_SUGGESTED_PACKET_COUNT: return "DL-Buffering-Suggested-Packet-Count";
        case PfcpIeType::PFCPSMREQ_FLAGS: return "PFCPSMReq-Flags";
        case PfcpIeType::PFCPSRRSP_FLAGS: return "PFCPSRRsp-Flags";
        case PfcpIeType::LOAD_CONTROL_INFORMATION: return "Load-Control-Information";
        case PfcpIeType::SEQUENCE_NUMBER: return "Sequence-Number";
        case PfcpIeType::METRIC: return "Metric";
        case PfcpIeType::OVERLOAD_CONTROL_INFORMATION: return "Overload-Control-Information";
        case PfcpIeType::TIMER: return "Timer";
        case PfcpIeType::PDR_ID: return "PDR-ID";
        case PfcpIeType::F_SEID: return "F-SEID";
        case PfcpIeType::APPLICATION_ID_PFDS: return "Application-ID-PFDs";
        case PfcpIeType::PFD_CONTEXT: return "PFD-Context";
        case PfcpIeType::NODE_ID: return "Node-ID";
        case PfcpIeType::PFD_CONTENTS: return "PFD-Contents";
        case PfcpIeType::MEASUREMENT_METHOD: return "Measurement-Method";
        case PfcpIeType::USAGE_REPORT_TRIGGER: return "Usage-Report-Trigger";
        case PfcpIeType::MEASUREMENT_PERIOD: return "Measurement-Period";
        case PfcpIeType::FQ_CSID: return "FQ-CSID";
        case PfcpIeType::VOLUME_MEASUREMENT: return "Volume-Measurement";
        case PfcpIeType::DURATION_MEASUREMENT: return "Duration-Measurement";
        case PfcpIeType::APPLICATION_DETECTION_INFORMATION: return "Application-Detection-Information";
        case PfcpIeType::TIME_OF_FIRST_PACKET: return "Time-Of-First-Packet";
        case PfcpIeType::TIME_OF_LAST_PACKET: return "Time-Of-Last-Packet";
        case PfcpIeType::QUOTA_HOLDING_TIME: return "Quota-Holding-Time";
        case PfcpIeType::DROPPED_DL_TRAFFIC_THRESHOLD: return "Dropped-DL-Traffic-Threshold";
        case PfcpIeType::VOLUME_QUOTA: return "Volume-Quota";
        case PfcpIeType::TIME_QUOTA: return "Time-Quota";
        case PfcpIeType::START_TIME: return "Start-Time";
        case PfcpIeType::END_TIME: return "End-Time";
        case PfcpIeType::QUERY_URR: return "Query-URR";
        case PfcpIeType::USAGE_REPORT_SMR: return "Usage-Report-SMR";
        case PfcpIeType::USAGE_REPORT_SDR: return "Usage-Report-SDR";
        case PfcpIeType::USAGE_REPORT_SRR: return "Usage-Report-SRR";
        case PfcpIeType::URR_ID: return "URR-ID";
        case PfcpIeType::LINKED_URR_ID: return "Linked-URR-ID";
        case PfcpIeType::DOWNLINK_DATA_REPORT: return "Downlink-Data-Report";
        case PfcpIeType::OUTER_HEADER_CREATION: return "Outer-Header-Creation";
        case PfcpIeType::CREATE_BAR: return "Create-BAR";
        case PfcpIeType::UPDATE_BAR_SMR: return "Update-BAR-SMR";
        case PfcpIeType::REMOVE_BAR: return "Remove-BAR";
        case PfcpIeType::BAR_ID: return "BAR-ID";
        case PfcpIeType::CP_FUNCTION_FEATURES: return "CP-Function-Features";
        case PfcpIeType::USAGE_INFORMATION: return "Usage-Information";
        case PfcpIeType::APPLICATION_INSTANCE_ID: return "Application-Instance-ID";
        case PfcpIeType::FLOW_INFORMATION: return "Flow-Information";
        case PfcpIeType::UE_IP_ADDRESS: return "UE-IP-Address";
        case PfcpIeType::PACKET_RATE: return "Packet-Rate";
        case PfcpIeType::OUTER_HEADER_REMOVAL: return "Outer-Header-Removal";
        case PfcpIeType::RECOVERY_TIME_STAMP: return "Recovery-Time-Stamp";
        case PfcpIeType::DL_FLOW_LEVEL_MARKING: return "DL-Flow-Level-Marking";
        case PfcpIeType::HEADER_ENRICHMENT: return "Header-Enrichment";
        case PfcpIeType::ERROR_INDICATION_REPORT: return "Error-Indication-Report";
        case PfcpIeType::MEASUREMENT_INFORMATION: return "Measurement-Information";
        case PfcpIeType::NODE_REPORT_TYPE: return "Node-Report-Type";
        case PfcpIeType::USER_PLANE_PATH_FAILURE_REPORT: return "User-Plane-Path-Failure-Report";
        case PfcpIeType::REMOTE_GTP_U_PEER: return "Remote-GTP-U-Peer";
        case PfcpIeType::UR_SEQN: return "UR-SEQN";
        case PfcpIeType::UPDATE_DUPLICATING_PARAMETERS: return "Update-Duplicating-Parameters";
        case PfcpIeType::ACTIVATE_PREDEFINED_RULES: return "Activate-Predefined-Rules";
        case PfcpIeType::DEACTIVATE_PREDEFINED_RULES: return "Deactivate-Predefined-Rules";
        case PfcpIeType::FAR_ID: return "FAR-ID";
        case PfcpIeType::QER_ID: return "QER-ID";
        case PfcpIeType::OCI_FLAGS: return "OCI-Flags";
        case PfcpIeType::PFCP_ASSOCIATION_RELEASE_REQUEST: return "PFCP-Association-Release-Request";
        case PfcpIeType::GRACEFUL_RELEASE_PERIOD: return "Graceful-Release-Period";
        case PfcpIeType::PDN_TYPE: return "PDN-Type";
        case PfcpIeType::FAILED_RULE_ID: return "Failed-Rule-ID";
        case PfcpIeType::TIME_QUOTA_MECHANISM: return "Time-Quota-Mechanism";
        case PfcpIeType::USER_PLANE_IP_RESOURCE_INFORMATION: return "User-Plane-IP-Resource-Information";
        case PfcpIeType::USER_PLANE_INACTIVITY_TIMER: return "User-Plane-Inactivity-Timer";
        case PfcpIeType::AGGREGATED_URRS: return "Aggregated-URRs";
        case PfcpIeType::MULTIPLIER: return "Multiplier";
        case PfcpIeType::AGGREGATED_URR_ID: return "Aggregated-URR-ID";
        default: return "Unknown-" + std::to_string(static_cast<uint16_t>(type));
    }
}

std::string pfcpSourceInterfaceToString(PfcpSourceInterface iface) {
    switch (iface) {
        case PfcpSourceInterface::ACCESS: return "Access";
        case PfcpSourceInterface::CORE: return "Core";
        case PfcpSourceInterface::SGI_LAN: return "SGi-LAN/N6-LAN";
        case PfcpSourceInterface::CP_FUNCTION: return "CP-Function";
        default: return "Unknown";
    }
}

std::string pfcpDestinationInterfaceToString(PfcpDestinationInterface iface) {
    switch (iface) {
        case PfcpDestinationInterface::ACCESS: return "Access";
        case PfcpDestinationInterface::CORE: return "Core";
        case PfcpDestinationInterface::SGI_LAN: return "SGi-LAN/N6-LAN";
        case PfcpDestinationInterface::CP_FUNCTION: return "CP-Function";
        case PfcpDestinationInterface::LI_FUNCTION: return "LI-Function";
        default: return "Unknown";
    }
}

}  // namespace callflow
