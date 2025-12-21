#include "protocol_parsers/gtp/gtpv2_ie_parser.h"
#include "common/logger.h"
#include <cstring>
#include <arpa/inet.h>
#include <sstream>
#include <iomanip>

namespace callflow {
namespace gtp {

// ============================================================================
// GtpV2IE Methods
// ============================================================================

nlohmann::json GtpV2IE::toJson() const {
    nlohmann::json j = header.toJson();

    // Add hex dump of value for debugging
    std::ostringstream oss;
    for (size_t i = 0; i < value.size() && i < 32; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(value[i]);
        if (i < value.size() - 1 && i < 31) oss << " ";
    }
    if (value.size() > 32) {
        oss << "...";
    }
    j["value_hex"] = oss.str();
    j["value_size"] = value.size();

    return j;
}

// ============================================================================
// GtpV2IEParser Methods
// ============================================================================

std::vector<GtpV2IE> GtpV2IEParser::parseIEs(const uint8_t* data, size_t length) {
    std::vector<GtpV2IE> ies;
    size_t offset = 0;

    while (offset < length) {
        auto ie_opt = parseIE(data, length, offset);
        if (!ie_opt.has_value()) {
            LOG_DEBUG("Failed to parse IE at offset " << offset);
            break;
        }
        ies.push_back(ie_opt.value());
    }

    LOG_DEBUG("Parsed " << ies.size() << " IEs from " << length << " bytes");
    return ies;
}

std::optional<GtpV2IE> GtpV2IEParser::parseIE(const uint8_t* data, size_t length, size_t& offset) {
    // IE header is 4 bytes minimum
    if (offset + 4 > length) {
        LOG_DEBUG("Not enough data for IE header at offset " << offset);
        return std::nullopt;
    }

    GtpV2IE ie;

    // Byte 0: IE Type
    ie.header.type = static_cast<GtpV2IEType>(data[offset]);

    // Bytes 1-2: IE Length (network byte order)
    uint16_t ie_length;
    std::memcpy(&ie_length, data + offset + 1, 2);
    ie.header.length = ntohs(ie_length);

    // Byte 3: Instance (bits 7-4) + CR flag (bit 3) + Spare (bits 2-0)
    uint8_t byte3 = data[offset + 3];
    ie.header.instance = (byte3 >> 4) & 0x0F;
    ie.header.cr_flag = (byte3 & 0x08) != 0;

    // Check if we have enough data for IE value
    if (offset + 4 + ie.header.length > length) {
        LOG_DEBUG("Not enough data for IE value at offset " << offset << ", need " << ie.header.length << " bytes");
        return std::nullopt;
    }

    // Copy IE value
    ie.value.resize(ie.header.length);
    std::memcpy(ie.value.data(), data + offset + 4, ie.header.length);

    offset += 4 + ie.header.length;

    LOG_DEBUG("Parsed IE: type=" << static_cast<int>(ie.header.type)
              << " (" << getIETypeName(ie.header.type) << ")"
              << ", length=" << ie.header.length
              << ", instance=" << static_cast<int>(ie.header.instance));

    return ie;
}

// ============================================================================
// BCD Decoding
// ============================================================================

std::string GtpV2IEParser::decodeBCD(const uint8_t* data, size_t length) {
    std::ostringstream oss;

    for (size_t i = 0; i < length; ++i) {
        uint8_t byte = data[i];

        // Lower nibble (first digit)
        uint8_t low_nibble = byte & 0x0F;
        if (low_nibble <= 9) {
            oss << static_cast<char>('0' + low_nibble);
        } else if (low_nibble == 0x0F) {
            break;  // Filler digit
        }

        // Upper nibble (second digit)
        uint8_t high_nibble = (byte >> 4) & 0x0F;
        if (high_nibble <= 9) {
            oss << static_cast<char>('0' + high_nibble);
        } else if (high_nibble == 0x0F) {
            break;  // Filler digit
        }
    }

    return oss.str();
}

// ============================================================================
// APN Decoding
// ============================================================================

std::string GtpV2IEParser::decodeAPN(const std::vector<uint8_t>& data) {
    if (data.empty()) {
        return "";
    }

    std::ostringstream oss;
    size_t offset = 0;
    bool first = true;

    while (offset < data.size()) {
        uint8_t label_len = data[offset];
        if (label_len == 0) {
            break;  // End of APN
        }

        offset++;

        if (offset + label_len > data.size()) {
            break;  // Invalid length
        }

        if (!first) {
            oss << '.';
        }
        first = false;

        for (size_t i = 0; i < label_len; ++i) {
            oss << static_cast<char>(data[offset + i]);
        }

        offset += label_len;
    }

    return oss.str();
}

// ============================================================================
// IMSI Parser
// ============================================================================

std::optional<GtpV2IMSI> GtpV2IEParser::parseIMSI(const GtpV2IE& ie) {
    if (ie.header.type != GtpV2IEType::IMSI) {
        LOG_ERROR("IE is not IMSI type");
        return std::nullopt;
    }

    return GtpV2IMSI::parse(ie.value);
}

std::optional<GtpV2IMSI> GtpV2IMSI::parse(const std::vector<uint8_t>& data) {
    if (data.size() < 1 || data.size() > 8) {
        LOG_ERROR("Invalid IMSI length: " << data.size());
        return std::nullopt;
    }

    GtpV2IMSI imsi;
    imsi.imsi = GtpV2IEParser::decodeBCD(data.data(), data.size());

    if (imsi.imsi.length() < 6 || imsi.imsi.length() > 15) {
        LOG_ERROR("Invalid IMSI decimal length: " << imsi.imsi.length());
        return std::nullopt;
    }

    LOG_DEBUG("Parsed IMSI: " << imsi.imsi);
    return imsi;
}

// ============================================================================
// F-TEID Parser
// ============================================================================

std::optional<GtpV2FTEID> GtpV2IEParser::parseFTEID(const GtpV2IE& ie) {
    if (ie.header.type != GtpV2IEType::F_TEID) {
        LOG_ERROR("IE is not F-TEID type");
        return std::nullopt;
    }

    return GtpV2FTEID::parse(ie.value);
}

std::optional<GtpV2FTEID> GtpV2FTEID::parse(const std::vector<uint8_t>& data) {
    if (data.size() < 5) {
        LOG_ERROR("Invalid F-TEID length: " << data.size() << " (minimum 5 bytes)");
        return std::nullopt;
    }

    GtpV2FTEID fteid;

    // Byte 0: Flags
    uint8_t flags = data[0];
    bool v4 = (flags & 0x80) != 0;
    bool v6 = (flags & 0x40) != 0;
    uint8_t iface_type = flags & 0x3F;
    fteid.interface_type = static_cast<FTEIDInterfaceType>(iface_type);

    // Bytes 1-4: TEID/GRE Key (network byte order)
    uint32_t teid_nbo;
    std::memcpy(&teid_nbo, &data[1], 4);
    fteid.teid = ntohl(teid_nbo);

    size_t offset = 5;

    // IPv4 address (if V4 flag set)
    if (v4) {
        if (data.size() < offset + 4) {
            LOG_ERROR("Invalid F-TEID length for IPv4: " << data.size());
            return std::nullopt;
        }
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &data[offset], ip_str, INET_ADDRSTRLEN);
        fteid.ipv4_address = ip_str;
        offset += 4;
    }

    // IPv6 address (if V6 flag set)
    if (v6) {
        if (data.size() < offset + 16) {
            LOG_ERROR("Invalid F-TEID length for IPv6: " << data.size());
            return std::nullopt;
        }
        char ip_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &data[offset], ip_str, INET6_ADDRSTRLEN);
        fteid.ipv6_address = ip_str;
        offset += 16;
    }

    LOG_DEBUG("Parsed F-TEID: interface=" << fteid.getInterfaceTypeName()
              << ", TEID=0x" << std::hex << fteid.teid << std::dec
              << (fteid.ipv4_address.has_value() ? ", IPv4=" + fteid.ipv4_address.value() : "")
              << (fteid.ipv6_address.has_value() ? ", IPv6=" + fteid.ipv6_address.value() : ""));

    return fteid;
}

// ============================================================================
// Bearer QoS Parser
// ============================================================================

std::optional<GtpV2BearerQoS> GtpV2IEParser::parseBearerQoS(const GtpV2IE& ie) {
    if (ie.header.type != GtpV2IEType::BEARER_QOS) {
        LOG_ERROR("IE is not Bearer QoS type");
        return std::nullopt;
    }

    return GtpV2BearerQoS::parse(ie.value);
}

uint64_t GtpV2IEParser::decodeBitRate(uint8_t encoded) {
    if (encoded == 0) {
        return 0;  // Subscribed maximum bit rate
    } else if (encoded <= 63) {
        return static_cast<uint64_t>(encoded) * 1000;  // kbps
    } else if (encoded <= 127) {
        return static_cast<uint64_t>(64 + (encoded - 64) * 8) * 1000;  // kbps
    } else if (encoded <= 254) {
        return static_cast<uint64_t>(576 + (encoded - 128) * 64) * 1000;  // kbps
    } else {
        return 0;  // Indicates value incremented in next extension
    }
}

std::optional<GtpV2BearerQoS> GtpV2BearerQoS::parse(const std::vector<uint8_t>& data) {
    if (data.size() < 22) {
        LOG_ERROR("Invalid Bearer QoS length: " << data.size() << " (minimum 22 bytes)");
        return std::nullopt;
    }

    GtpV2BearerQoS qos;

    // Byte 0: Flags
    uint8_t byte0 = data[0];
    qos.pci = (byte0 >> 6) & 0x01;
    qos.pl = (byte0 >> 2) & 0x0F;
    qos.pvi = (byte0 >> 1) & 0x01;

    // Byte 1: QCI
    qos.qci = data[1];

    // Bytes 2-6: Max Bit Rate Uplink (40 bits)
    uint64_t mbr_ul = 0;
    for (int i = 0; i < 5; ++i) {
        mbr_ul = (mbr_ul << 8) | data[2 + i];
    }
    qos.max_bitrate_uplink = mbr_ul;

    // Bytes 7-11: Max Bit Rate Downlink (40 bits)
    uint64_t mbr_dl = 0;
    for (int i = 0; i < 5; ++i) {
        mbr_dl = (mbr_dl << 8) | data[7 + i];
    }
    qos.max_bitrate_downlink = mbr_dl;

    // Bytes 12-16: Guaranteed Bit Rate Uplink (40 bits)
    uint64_t gbr_ul = 0;
    for (int i = 0; i < 5; ++i) {
        gbr_ul = (gbr_ul << 8) | data[12 + i];
    }
    qos.guaranteed_bitrate_uplink = gbr_ul;

    // Bytes 17-21: Guaranteed Bit Rate Downlink (40 bits)
    uint64_t gbr_dl = 0;
    for (int i = 0; i < 5; ++i) {
        gbr_dl = (gbr_dl << 8) | data[17 + i];
    }
    qos.guaranteed_bitrate_downlink = gbr_dl;

    LOG_DEBUG("Parsed Bearer QoS: QCI=" << static_cast<int>(qos.qci)
              << ", PL=" << static_cast<int>(qos.pl)
              << ", MBR_UL=" << qos.max_bitrate_uplink
              << ", MBR_DL=" << qos.max_bitrate_downlink);

    return qos;
}

// ============================================================================
// PDN Address Allocation Parser
// ============================================================================

std::optional<GtpV2PDNAddressAllocation> GtpV2IEParser::parsePAA(const GtpV2IE& ie) {
    if (ie.header.type != GtpV2IEType::PAA) {
        LOG_ERROR("IE is not PAA type");
        return std::nullopt;
    }

    return GtpV2PDNAddressAllocation::parse(ie.value);
}

std::optional<GtpV2PDNAddressAllocation> GtpV2PDNAddressAllocation::parse(const std::vector<uint8_t>& data) {
    if (data.size() < 1) {
        LOG_ERROR("Invalid PAA length: " << data.size());
        return std::nullopt;
    }

    GtpV2PDNAddressAllocation paa;

    // Byte 0: PDN Type
    paa.pdn_type = static_cast<PDNType>(data[0] & 0x07);

    size_t offset = 1;

    switch (paa.pdn_type) {
        case PDNType::IPv4:
            if (data.size() < offset + 4) {
                LOG_ERROR("Invalid PAA IPv4 length: " << data.size());
                return std::nullopt;
            }
            {
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &data[offset], ip_str, INET_ADDRSTRLEN);
                paa.ipv4_address = ip_str;
            }
            break;

        case PDNType::IPv6:
            if (data.size() < offset + 1) {
                LOG_ERROR("Invalid PAA IPv6 length: " << data.size());
                return std::nullopt;
            }
            paa.ipv6_prefix_length = data[offset];
            offset++;
            if (data.size() < offset + 16) {
                LOG_ERROR("Invalid PAA IPv6 address length: " << data.size());
                return std::nullopt;
            }
            {
                char ip_str[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &data[offset], ip_str, INET6_ADDRSTRLEN);
                paa.ipv6_address = ip_str;
            }
            break;

        case PDNType::IPv4v6:
            // IPv4 address
            if (data.size() < offset + 4) {
                LOG_ERROR("Invalid PAA IPv4v6 IPv4 length: " << data.size());
                return std::nullopt;
            }
            {
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &data[offset], ip_str, INET_ADDRSTRLEN);
                paa.ipv4_address = ip_str;
            }
            offset += 4;

            // IPv6 prefix length
            if (data.size() < offset + 1) {
                LOG_ERROR("Invalid PAA IPv4v6 prefix length: " << data.size());
                return std::nullopt;
            }
            paa.ipv6_prefix_length = data[offset];
            offset++;

            // IPv6 address
            if (data.size() < offset + 16) {
                LOG_ERROR("Invalid PAA IPv4v6 IPv6 address length: " << data.size());
                return std::nullopt;
            }
            {
                char ip_str[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &data[offset], ip_str, INET6_ADDRSTRLEN);
                paa.ipv6_address = ip_str;
            }
            break;

        case PDNType::NON_IP:
            // No address allocation for Non-IP PDN type
            break;

        default:
            LOG_ERROR("Unknown PDN type: " << static_cast<int>(paa.pdn_type));
            return std::nullopt;
    }

    LOG_DEBUG("Parsed PAA: type=" << getPDNTypeName(paa.pdn_type)
              << (paa.ipv4_address.has_value() ? ", IPv4=" + paa.ipv4_address.value() : "")
              << (paa.ipv6_address.has_value() ? ", IPv6=" + paa.ipv6_address.value() : ""));

    return paa;
}

// ============================================================================
// Bearer Context Parser (Grouped IE)
// ============================================================================

std::optional<GtpV2BearerContext> GtpV2IEParser::parseBearerContext(const GtpV2IE& ie) {
    if (ie.header.type != GtpV2IEType::BEARER_CONTEXT) {
        LOG_ERROR("IE is not Bearer Context type");
        return std::nullopt;
    }

    return GtpV2BearerContext::parse(ie.value);
}

std::optional<GtpV2BearerContext> GtpV2BearerContext::parse(const std::vector<uint8_t>& data) {
    GtpV2BearerContext bearer_ctx;

    // Parse nested IEs
    std::vector<GtpV2IE> nested_ies = GtpV2IEParser::parseIEs(data.data(), data.size());

    LOG_DEBUG("Bearer Context contains " << nested_ies.size() << " nested IEs");

    for (const auto& nested_ie : nested_ies) {
        switch (nested_ie.header.type) {
            case GtpV2IEType::EPS_BEARER_ID: {
                if (nested_ie.value.size() >= 1) {
                    bearer_ctx.eps_bearer_id = nested_ie.value[0];
                    LOG_DEBUG("Bearer Context: EPS Bearer ID = " << static_cast<int>(bearer_ctx.eps_bearer_id.value()));
                }
                break;
            }

            case GtpV2IEType::BEARER_QOS: {
                auto qos_opt = GtpV2BearerQoS::parse(nested_ie.value);
                if (qos_opt.has_value()) {
                    bearer_ctx.qos = qos_opt.value();
                    LOG_DEBUG("Bearer Context: QoS parsed");
                }
                break;
            }

            case GtpV2IEType::F_TEID: {
                auto fteid_opt = GtpV2FTEID::parse(nested_ie.value);
                if (fteid_opt.has_value()) {
                    bearer_ctx.fteids.push_back(fteid_opt.value());
                    LOG_DEBUG("Bearer Context: F-TEID parsed (TEID=0x" << std::hex << fteid_opt.value().teid << std::dec << ")");
                }
                break;
            }

            case GtpV2IEType::CHARGING_ID: {
                if (nested_ie.value.size() >= 4) {
                    uint32_t charging_id_nbo;
                    std::memcpy(&charging_id_nbo, nested_ie.value.data(), 4);
                    bearer_ctx.charging_id = ntohl(charging_id_nbo);
                    LOG_DEBUG("Bearer Context: Charging ID = " << bearer_ctx.charging_id.value());
                }
                break;
            }

            case GtpV2IEType::CAUSE: {
                if (nested_ie.value.size() >= 2) {
                    bearer_ctx.cause = static_cast<CauseValue>(nested_ie.value[0]);
                    LOG_DEBUG("Bearer Context: Cause = " << static_cast<int>(nested_ie.value[0]));
                }
                break;
            }

            case GtpV2IEType::BEARER_FLAGS: {
                if (nested_ie.value.size() >= 1) {
                    bearer_ctx.bearer_flags = nested_ie.value[0];
                    LOG_DEBUG("Bearer Context: Bearer Flags = 0x" << std::hex << static_cast<int>(bearer_ctx.bearer_flags.value()) << std::dec);
                }
                break;
            }

            default:
                LOG_DEBUG("Bearer Context: Unhandled nested IE type " << static_cast<int>(nested_ie.header.type));
                break;
        }
    }

    return bearer_ctx;
}

// ============================================================================
// Additional IE Parsers
// ============================================================================

std::optional<GtpV2Cause> GtpV2IEParser::parseCause(const GtpV2IE& ie) {
    if (ie.header.type != GtpV2IEType::CAUSE) {
        return std::nullopt;
    }
    return GtpV2Cause::parse(ie.value);
}

std::optional<GtpV2Cause> GtpV2Cause::parse(const std::vector<uint8_t>& data) {
    if (data.size() < 2) {
        return std::nullopt;
    }

    GtpV2Cause cause;
    cause.cause_value = static_cast<CauseValue>(data[0]);

    uint8_t byte1 = data[1];
    cause.pce = (byte1 & 0x04) != 0;
    cause.bce = (byte1 & 0x02) != 0;
    cause.cs = (byte1 & 0x01) != 0;

    // Optional offending IE information
    if (data.size() >= 6) {
        cause.offending_ie_type = static_cast<GtpV2IEType>(data[2]);
        uint16_t length_nbo;
        std::memcpy(&length_nbo, &data[3], 2);
        cause.offending_ie_length = ntohs(length_nbo);
        cause.offending_ie_instance = (data[5] >> 4) & 0x0F;
    }

    return cause;
}

std::optional<std::string> GtpV2IEParser::parseAPN(const GtpV2IE& ie) {
    if (ie.header.type != GtpV2IEType::APN) {
        return std::nullopt;
    }
    return decodeAPN(ie.value);
}

std::optional<GtpV2AMBR> GtpV2IEParser::parseAMBR(const GtpV2IE& ie) {
    if (ie.header.type != GtpV2IEType::AMBR) {
        return std::nullopt;
    }
    return GtpV2AMBR::parse(ie.value);
}

std::optional<GtpV2AMBR> GtpV2AMBR::parse(const std::vector<uint8_t>& data) {
    if (data.size() < 8) {
        return std::nullopt;
    }

    GtpV2AMBR ambr;

    uint32_t ul_nbo, dl_nbo;
    std::memcpy(&ul_nbo, &data[0], 4);
    std::memcpy(&dl_nbo, &data[4], 4);

    ambr.uplink = ntohl(ul_nbo);
    ambr.downlink = ntohl(dl_nbo);

    return ambr;
}

std::optional<GtpV2ServingNetwork> GtpV2IEParser::parseServingNetwork(const GtpV2IE& ie) {
    if (ie.header.type != GtpV2IEType::SERVING_NETWORK) {
        return std::nullopt;
    }
    return GtpV2ServingNetwork::parse(ie.value);
}

std::optional<GtpV2ServingNetwork> GtpV2ServingNetwork::parse(const std::vector<uint8_t>& data) {
    if (data.size() < 3) {
        return std::nullopt;
    }

    GtpV2ServingNetwork sn;

    // Decode MCC and MNC from BCD
    std::ostringstream mcc_oss, mnc_oss;

    // MCC digit 1
    mcc_oss << static_cast<char>('0' + (data[0] & 0x0F));
    // MCC digit 2
    mcc_oss << static_cast<char>('0' + ((data[0] >> 4) & 0x0F));
    // MCC digit 3
    mcc_oss << static_cast<char>('0' + (data[1] & 0x0F));

    sn.mcc = mcc_oss.str();

    // MNC digit 3 (or filler)
    uint8_t mnc3 = (data[1] >> 4) & 0x0F;
    // MNC digit 1
    mnc_oss << static_cast<char>('0' + (data[2] & 0x0F));
    // MNC digit 2
    mnc_oss << static_cast<char>('0' + ((data[2] >> 4) & 0x0F));

    // MNC digit 3 if not filler
    if (mnc3 != 0x0F) {
        mnc_oss << static_cast<char>('0' + mnc3);
    }

    sn.mnc = mnc_oss.str();

    return sn;
}

std::optional<GtpV2ULI> GtpV2IEParser::parseULI(const GtpV2IE& ie) {
    if (ie.header.type != GtpV2IEType::ULI) {
        return std::nullopt;
    }
    return GtpV2ULI::parse(ie.value);
}

std::optional<GtpV2ULI> GtpV2ULI::parse(const std::vector<uint8_t>& data) {
    if (data.size() < 1) {
        return std::nullopt;
    }

    GtpV2ULI uli;

    uint8_t flags = data[0];
    uli.cgi_present = (flags & 0x01) != 0;
    uli.sai_present = (flags & 0x02) != 0;
    uli.rai_present = (flags & 0x04) != 0;
    uli.tai_present = (flags & 0x08) != 0;
    uli.ecgi_present = (flags & 0x10) != 0;
    uli.lai_present = (flags & 0x20) != 0;

    size_t offset = 1;

    // Parse TAI if present
    if (uli.tai_present && data.size() >= offset + 5) {
        std::ostringstream mcc_oss, mnc_oss;
        mcc_oss << static_cast<char>('0' + (data[offset] & 0x0F));
        mcc_oss << static_cast<char>('0' + ((data[offset] >> 4) & 0x0F));
        mcc_oss << static_cast<char>('0' + (data[offset + 1] & 0x0F));
        uli.tai_mcc = mcc_oss.str();

        uint8_t mnc3 = (data[offset + 1] >> 4) & 0x0F;
        mnc_oss << static_cast<char>('0' + (data[offset + 2] & 0x0F));
        mnc_oss << static_cast<char>('0' + ((data[offset + 2] >> 4) & 0x0F));
        if (mnc3 != 0x0F) {
            mnc_oss << static_cast<char>('0' + mnc3);
        }
        uli.tai_mnc = mnc_oss.str();

        uint16_t tac_nbo;
        std::memcpy(&tac_nbo, &data[offset + 3], 2);
        uli.tai_tac = ntohs(tac_nbo);

        offset += 5;
    }

    // Parse ECGI if present
    if (uli.ecgi_present && data.size() >= offset + 7) {
        std::ostringstream mcc_oss, mnc_oss;
        mcc_oss << static_cast<char>('0' + (data[offset] & 0x0F));
        mcc_oss << static_cast<char>('0' + ((data[offset] >> 4) & 0x0F));
        mcc_oss << static_cast<char>('0' + (data[offset + 1] & 0x0F));
        uli.ecgi_mcc = mcc_oss.str();

        uint8_t mnc3 = (data[offset + 1] >> 4) & 0x0F;
        mnc_oss << static_cast<char>('0' + (data[offset + 2] & 0x0F));
        mnc_oss << static_cast<char>('0' + ((data[offset + 2] >> 4) & 0x0F));
        if (mnc3 != 0x0F) {
            mnc_oss << static_cast<char>('0' + mnc3);
        }
        uli.ecgi_mnc = mnc_oss.str();

        uint32_t eci = 0;
        eci = (static_cast<uint32_t>(data[offset + 3]) << 20) |
              (static_cast<uint32_t>(data[offset + 4]) << 12) |
              (static_cast<uint32_t>(data[offset + 5]) << 4) |
              (static_cast<uint32_t>(data[offset + 6]) >> 4);
        uli.ecgi_eci = eci;

        offset += 7;
    }

    return uli;
}

std::optional<RATType> GtpV2IEParser::parseRATType(const GtpV2IE& ie) {
    if (ie.header.type != GtpV2IEType::RAT_TYPE || ie.value.size() < 1) {
        return std::nullopt;
    }
    return static_cast<RATType>(ie.value[0]);
}

std::optional<uint8_t> GtpV2IEParser::parseRecovery(const GtpV2IE& ie) {
    if (ie.header.type != GtpV2IEType::RECOVERY || ie.value.size() < 1) {
        return std::nullopt;
    }
    return ie.value[0];
}

std::optional<uint8_t> GtpV2IEParser::parseEPSBearerID(const GtpV2IE& ie) {
    if (ie.header.type != GtpV2IEType::EPS_BEARER_ID || ie.value.size() < 1) {
        return std::nullopt;
    }
    return ie.value[0];
}

std::optional<std::string> GtpV2IEParser::parseMSISDN(const GtpV2IE& ie) {
    if (ie.header.type != GtpV2IEType::MSISDN || ie.value.size() < 2) {
        return std::nullopt;
    }
    // Skip first byte (contains extension, type of number, numbering plan)
    return decodeBCD(ie.value.data() + 1, ie.value.size() - 1);
}

std::optional<std::string> GtpV2IEParser::parseMEI(const GtpV2IE& ie) {
    if (ie.header.type != GtpV2IEType::MEI || ie.value.empty()) {
        return std::nullopt;
    }
    return decodeBCD(ie.value.data(), ie.value.size());
}

std::optional<GtpV2Indication> GtpV2IEParser::parseIndication(const GtpV2IE& ie) {
    if (ie.header.type != GtpV2IEType::INDICATION) {
        return std::nullopt;
    }
    return GtpV2Indication::parse(ie.value);
}

std::optional<GtpV2Indication> GtpV2Indication::parse(const std::vector<uint8_t>& data) {
    if (data.empty()) {
        return std::nullopt;
    }

    GtpV2Indication ind;
    ind.flags = 0;

    // Read up to 8 bytes of flags
    size_t bytes_to_read = std::min(data.size(), size_t(8));
    for (size_t i = 0; i < bytes_to_read; ++i) {
        ind.flags |= (static_cast<uint64_t>(data[i]) << (i * 8));
    }

    return ind;
}

std::optional<PDNType> GtpV2IEParser::parsePDNType(const GtpV2IE& ie) {
    if (ie.header.type != GtpV2IEType::PDN_TYPE || ie.value.size() < 1) {
        return std::nullopt;
    }
    return static_cast<PDNType>(ie.value[0] & 0x07);
}

std::optional<uint32_t> GtpV2IEParser::parseChargingID(const GtpV2IE& ie) {
    if (ie.header.type != GtpV2IEType::CHARGING_ID || ie.value.size() < 4) {
        return std::nullopt;
    }
    uint32_t id_nbo;
    std::memcpy(&id_nbo, ie.value.data(), 4);
    return ntohl(id_nbo);
}

}  // namespace gtp
}  // namespace callflow
