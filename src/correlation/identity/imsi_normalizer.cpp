#include "correlation/identity/imsi_normalizer.h"

#include <algorithm>
#include <cctype>
#include <sstream>

namespace callflow {
namespace correlation {

// MCC to MNC length mapping (countries with 3-digit MNC)
// Most countries use 2-digit MNC, so we only list exceptions
const std::unordered_map<std::string, int> ImsiNormalizer::MCC_MNC_LENGTHS = {
    {"302", 3},  // Canada
    {"310", 3},  // USA (some operators use 3-digit)
    {"311", 3},  // USA
    {"312", 3},  // USA
    {"313", 3},  // USA
    {"316", 3},  // USA
    {"334", 3},  // Mexico
    {"338", 3},  // Jamaica
    {"342", 3},  // Barbados
    {"344", 3},  // Antigua and Barbuda
    {"346", 3},  // Cayman Islands
    {"348", 3},  // British Virgin Islands
    {"350", 3},  // Bermuda
    {"352", 3},  // Grenada
    {"354", 3},  // Montserrat
    {"356", 3},  // Saint Kitts and Nevis
    {"358", 3},  // Saint Lucia
    {"360", 3},  // Saint Vincent and the Grenadines
    {"362", 3},  // Bonaire, Sint Eustatius and Saba
    {"363", 3},  // Aruba
    {"364", 3},  // Bahamas
    {"365", 3},  // Anguilla
    {"366", 3},  // Dominica
    {"368", 3},  // Cuba
    {"370", 3},  // Dominican Republic
    {"372", 3},  // Haiti
    {"374", 3},  // Trinidad and Tobago
    {"376", 3},  // Turks and Caicos Islands
    {"732", 3},  // Colombia
};

std::optional<NormalizedImsi> ImsiNormalizer::normalize(const std::string& input) {
    if (input.empty()) {
        return std::nullopt;
    }

    std::string working = input;

    // Strip common prefixes
    working = stripPrefix(working);

    // Handle Diameter username format
    if (working.find('@') != std::string::npos) {
        return fromDiameterUsername(input);
    }

    // Extract digits only
    std::string digits = extractDigits(working);

    // IMSI must be exactly 15 digits
    if (digits.length() != 15) {
        return std::nullopt;
    }

    // Validate format
    if (!isValid(digits)) {
        return std::nullopt;
    }

    NormalizedImsi result;
    result.raw = input;
    result.digits = digits;

    // Extract MCC (first 3 digits)
    result.mcc = extractMcc(digits);
    if (result.mcc.empty()) {
        return std::nullopt;
    }

    // Extract MNC (next 2-3 digits)
    result.mnc = extractMnc(digits);
    if (result.mnc.empty()) {
        return std::nullopt;
    }

    // Extract MSIN (remaining digits)
    result.msin = extractMsin(digits, result.mnc.length());

    return result;
}

std::optional<NormalizedImsi> ImsiNormalizer::fromBcd(const uint8_t* data, size_t length) {
    if (!data || length == 0) {
        return std::nullopt;
    }

    // BCD encoding: 2 digits per byte, with 0xF as filler
    // Example: IMSI 310260123456789
    // BCD: 13 02 06 21 43 65 87 F9
    std::string digits;
    digits.reserve(length * 2);

    for (size_t i = 0; i < length; ++i) {
        uint8_t byte = data[i];

        // Lower nibble (first digit)
        uint8_t low = byte & 0x0F;
        if (low == 0x0F)
            break;  // Filler, end of IMSI
        if (low > 9)
            return std::nullopt;  // Invalid BCD
        digits += ('0' + low);

        // Upper nibble (second digit)
        uint8_t high = (byte >> 4) & 0x0F;
        if (high == 0x0F)
            break;  // Filler, end of IMSI
        if (high > 9)
            return std::nullopt;  // Invalid BCD
        digits += ('0' + high);
    }

    // IMSI should be 15 digits
    if (digits.length() != 15) {
        return std::nullopt;
    }

    return normalize(digits);
}

std::optional<NormalizedImsi> ImsiNormalizer::fromDiameterUsername(const std::string& username) {
    // Diameter User-Name format: IMSI@realm
    // Example: "310260123456789@ims.mnc260.mcc310.3gppnetwork.org"
    // Or: "imsi-310260123456789@realm"

    size_t at_pos = username.find('@');
    if (at_pos == std::string::npos) {
        return normalize(username);
    }

    std::string user_part = username.substr(0, at_pos);
    return normalize(user_part);
}

bool ImsiNormalizer::isValid(const std::string& imsi) {
    // IMSI must be exactly 15 digits
    if (imsi.length() != 15) {
        return false;
    }

    // All characters must be digits
    for (char c : imsi) {
        if (!std::isdigit(c)) {
            return false;
        }
    }

    // First 3 digits (MCC) should be valid (200-799)
    if (imsi.length() >= 3) {
        int mcc = std::stoi(imsi.substr(0, 3));
        if (mcc < 200 || mcc > 799) {
            return false;
        }
    }

    return true;
}

std::string ImsiNormalizer::extractMcc(const std::string& imsi_digits) {
    if (imsi_digits.length() < 3) {
        return "";
    }
    return imsi_digits.substr(0, 3);
}

std::string ImsiNormalizer::extractMnc(const std::string& imsi_digits) {
    if (imsi_digits.length() < 5) {
        return "";
    }

    std::string mcc = extractMcc(imsi_digits);
    std::string first_digit = imsi_digits.substr(3, 1);

    // Determine MNC length (2 or 3 digits)
    int mnc_length = detectMncLength(mcc, first_digit);

    if (imsi_digits.length() < static_cast<size_t>(3 + mnc_length)) {
        return "";
    }

    return imsi_digits.substr(3, mnc_length);
}

std::string ImsiNormalizer::extractMsin(const std::string& imsi_digits, int mnc_length) {
    size_t msin_start = 3 + mnc_length;
    if (imsi_digits.length() <= msin_start) {
        return "";
    }
    return imsi_digits.substr(msin_start);
}

std::string ImsiNormalizer::extractDigits(const std::string& input) {
    std::string result;
    for (char c : input) {
        if (std::isdigit(c)) {
            result += c;
        }
    }
    return result;
}

std::string ImsiNormalizer::stripPrefix(const std::string& input) {
    std::string working = input;

    // Remove common prefixes
    if (working.find("imsi-") == 0) {
        working = working.substr(5);
    } else if (working.find("imsi:") == 0) {
        working = working.substr(5);
    } else if (working.find("IMSI") == 0) {
        working = working.substr(4);
    }

    return working;
}

int ImsiNormalizer::detectMncLength(const std::string& mcc, const std::string& /*first_digit*/) {
    // Check if MCC is in the list of countries with 3-digit MNC
    auto it = MCC_MNC_LENGTHS.find(mcc);
    if (it != MCC_MNC_LENGTHS.end()) {
        return it->second;
    }

    // Default to 2-digit MNC
    // In real implementation, could use ITU database or heuristics
    // For now, assume 2 digits for most countries
    return 2;
}

}  // namespace correlation
}  // namespace callflow
