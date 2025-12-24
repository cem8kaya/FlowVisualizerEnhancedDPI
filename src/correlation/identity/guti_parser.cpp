#include "correlation/identity/guti_parser.h"
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace callflow {
namespace correlation {

std::optional<Guti4G> GutiParser::parse4G(const uint8_t* data, size_t length) {
    // Delegate to the implementation in Guti4G::parse
    return Guti4G::parse(data, length);
}

std::optional<Guti5G> GutiParser::parse5G(const uint8_t* data, size_t length) {
    // Delegate to the implementation in Guti5G::parse
    return Guti5G::parse(data, length);
}

std::optional<Guti4G> GutiParser::parse4GFromHex(const std::string& hex_string) {
    auto bytes = hexStringToBytes(hex_string);
    if (bytes.size() != 11) {
        return std::nullopt;
    }
    return parse4G(bytes.data(), bytes.size());
}

std::optional<Guti5G> GutiParser::parse5GFromHex(const std::string& hex_string) {
    auto bytes = hexStringToBytes(hex_string);
    if (bytes.size() != 11) {
        return std::nullopt;
    }
    return parse5G(bytes.data(), bytes.size());
}

size_t GutiParser::encode4G(const Guti4G& guti, uint8_t* output) {
    if (!output) {
        return 0;
    }

    // Encode MCC/MNC (3 bytes)
    encodeMccMnc(guti.mcc, guti.mnc, output);

    // MME Group ID (2 bytes, big-endian)
    output[3] = (guti.mme_group_id >> 8) & 0xFF;
    output[4] = guti.mme_group_id & 0xFF;

    // MME Code (1 byte)
    output[5] = guti.mme_code;

    // M-TMSI (4 bytes, big-endian)
    output[6] = (guti.m_tmsi >> 24) & 0xFF;
    output[7] = (guti.m_tmsi >> 16) & 0xFF;
    output[8] = (guti.m_tmsi >> 8) & 0xFF;
    output[9] = guti.m_tmsi & 0xFF;

    // Padding byte (not always present, but included for completeness)
    output[10] = 0xFF;

    return 11;
}

size_t GutiParser::encode5G(const Guti5G& guti, uint8_t* output) {
    if (!output) {
        return 0;
    }

    // Encode MCC/MNC (3 bytes)
    encodeMccMnc(guti.mcc, guti.mnc, output);

    // AMF Region ID (1 byte)
    output[3] = guti.amf_region_id;

    // AMF Set ID (10 bits) and AMF Pointer (6 bits) in 2 bytes
    uint16_t amf_field = ((guti.amf_set_id & 0x3FF) << 6) | (guti.amf_pointer & 0x3F);
    output[4] = (amf_field >> 8) & 0xFF;
    output[5] = amf_field & 0xFF;

    // 5G-TMSI (4 bytes, big-endian)
    output[6] = (guti.fiveG_tmsi >> 24) & 0xFF;
    output[7] = (guti.fiveG_tmsi >> 16) & 0xFF;
    output[8] = (guti.fiveG_tmsi >> 8) & 0xFF;
    output[9] = guti.fiveG_tmsi & 0xFF;

    // Padding byte
    output[10] = 0xFF;

    return 11;
}

bool GutiParser::isSameMmePool(const Guti4G& guti1, const Guti4G& guti2) {
    // Same MME pool means same MCC, MNC, and MME Group ID
    return (guti1.mcc == guti2.mcc &&
            guti1.mnc == guti2.mnc &&
            guti1.mme_group_id == guti2.mme_group_id);
}

bool GutiParser::isSameAmfSet(const Guti5G& guti1, const Guti5G& guti2) {
    // Same AMF set means same MCC, MNC, AMF Region ID, and AMF Set ID
    return (guti1.mcc == guti2.mcc &&
            guti1.mnc == guti2.mnc &&
            guti1.amf_region_id == guti2.amf_region_id &&
            guti1.amf_set_id == guti2.amf_set_id);
}

std::vector<uint8_t> GutiParser::hexStringToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;

    // Remove spaces and colons
    std::string clean_hex;
    for (char c : hex) {
        if (std::isxdigit(c)) {
            clean_hex += c;
        }
    }

    // Must be even length
    if (clean_hex.length() % 2 != 0) {
        return bytes;
    }

    bytes.reserve(clean_hex.length() / 2);

    for (size_t i = 0; i < clean_hex.length(); i += 2) {
        std::string byte_str = clean_hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
        bytes.push_back(byte);
    }

    return bytes;
}

void GutiParser::encodeMccMnc(const std::string& mcc, const std::string& mnc, uint8_t* output) {
    // MCC/MNC BCD encoding:
    // Byte 0: MCC digit 2 | MCC digit 1
    // Byte 1: MNC digit 3 | MCC digit 3
    // Byte 2: MNC digit 2 | MNC digit 1

    if (mcc.length() != 3) {
        // Invalid MCC
        output[0] = output[1] = output[2] = 0xFF;
        return;
    }

    // Encode MCC
    output[0] = ((mcc[1] - '0') << 4) | (mcc[0] - '0');
    output[1] = (mcc[2] - '0');

    // Encode MNC
    if (mnc.length() == 2) {
        output[1] |= (0x0F << 4);  // Filler for 2-digit MNC
        output[2] = ((mnc[1] - '0') << 4) | (mnc[0] - '0');
    } else if (mnc.length() == 3) {
        output[1] |= ((mnc[2] - '0') << 4);
        output[2] = ((mnc[1] - '0') << 4) | (mnc[0] - '0');
    } else {
        // Invalid MNC
        output[1] |= (0x0F << 4);
        output[2] = 0xFF;
    }
}

bool GutiParser::decodeMccMnc(const uint8_t* data, std::string& mcc, std::string& mnc) {
    if (!data) {
        return false;
    }

    // Decode MCC
    char mcc_str[4];
    mcc_str[0] = '0' + (data[0] & 0x0F);
    mcc_str[1] = '0' + ((data[0] >> 4) & 0x0F);
    mcc_str[2] = '0' + (data[1] & 0x0F);
    mcc_str[3] = '\0';
    mcc = mcc_str;

    // Decode MNC
    char mnc_str[4];
    mnc_str[0] = '0' + (data[2] & 0x0F);
    mnc_str[1] = '0' + ((data[2] >> 4) & 0x0F);

    uint8_t mnc_digit3 = (data[1] >> 4) & 0x0F;
    if (mnc_digit3 != 0x0F) {
        // 3-digit MNC
        mnc_str[2] = '0' + mnc_digit3;
        mnc_str[3] = '\0';
    } else {
        // 2-digit MNC
        mnc_str[2] = '\0';
    }
    mnc = mnc_str;

    return true;
}

} // namespace correlation
} // namespace callflow
