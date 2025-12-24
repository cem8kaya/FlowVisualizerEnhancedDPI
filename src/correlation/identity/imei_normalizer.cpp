#include "correlation/identity/imei_normalizer.h"
#include <algorithm>
#include <cctype>

namespace callflow {
namespace correlation {

std::optional<NormalizedImei> ImeiNormalizer::normalize(const std::string& input) {
    if (input.empty()) {
        return std::nullopt;
    }

    std::string working = input;

    // Strip common prefixes
    working = stripPrefix(working);

    // Extract digits only
    std::string digits = extractDigits(working);

    NormalizedImei result;
    result.raw = input;

    // Handle different IMEI formats
    if (digits.length() == 14) {
        // IMEI without check digit
        if (!isValidImei(digits)) {
            return std::nullopt;
        }
        result.imei = digits;
    } else if (digits.length() == 15) {
        // IMEI with check digit - verify and strip it
        if (!verifyCheckDigit(digits)) {
            // Might be invalid, but accept it anyway
        }
        result.imei = digits.substr(0, 14);
    } else if (digits.length() == 16) {
        // IMEISV (IMEI Software Version)
        if (!isValidImeisv(digits)) {
            return std::nullopt;
        }
        result.imei = digits.substr(0, 14);
        result.imeisv = digits;
    } else {
        // Invalid length
        return std::nullopt;
    }

    // Extract TAC (Type Allocation Code) - first 8 digits
    result.tac = extractTac(result.imei);

    // Extract SNR (Serial Number) - next 6 digits
    result.snr = extractSnr(result.imei);

    return result;
}

std::optional<NormalizedImei> ImeiNormalizer::fromBcd(const uint8_t* data, size_t length) {
    if (!data || length == 0) {
        return std::nullopt;
    }

    // BCD encoding: 2 digits per byte, with 0xF as filler
    // IMEI/IMEISV is typically 8 bytes (14-16 digits)
    std::string digits;
    digits.reserve(length * 2);

    for (size_t i = 0; i < length; ++i) {
        uint8_t byte = data[i];

        // Lower nibble (first digit)
        uint8_t low = byte & 0x0F;
        if (low == 0x0F) break;  // Filler, end of IMEI
        if (low > 9) return std::nullopt;  // Invalid BCD
        digits += ('0' + low);

        // Upper nibble (second digit)
        uint8_t high = (byte >> 4) & 0x0F;
        if (high == 0x0F) break;  // Filler, end of IMEI
        if (high > 9) return std::nullopt;  // Invalid BCD
        digits += ('0' + high);
    }

    // IMEI should be 14-16 digits
    if (digits.length() < 14 || digits.length() > 16) {
        return std::nullopt;
    }

    return normalize(digits);
}

bool ImeiNormalizer::isValidImei(const std::string& imei) {
    // IMEI must be exactly 14 digits
    if (imei.length() != 14) {
        return false;
    }

    // All characters must be digits
    for (char c : imei) {
        if (!std::isdigit(c)) {
            return false;
        }
    }

    return true;
}

bool ImeiNormalizer::isValidImeisv(const std::string& imeisv) {
    // IMEISV must be exactly 16 digits
    if (imeisv.length() != 16) {
        return false;
    }

    // All characters must be digits
    for (char c : imeisv) {
        if (!std::isdigit(c)) {
            return false;
        }
    }

    return true;
}

int ImeiNormalizer::calculateCheckDigit(const std::string& imei) {
    if (imei.length() != 14) {
        return -1;
    }

    // Luhn algorithm
    int sum = 0;
    for (size_t i = 0; i < 14; ++i) {
        int digit = imei[i] - '0';

        // Double every second digit (from right, so odd positions from left in 0-indexed)
        if (i % 2 == 1) {
            digit *= 2;
            if (digit > 9) {
                digit -= 9;  // Sum of digits (e.g., 16 -> 1+6 = 7)
            }
        }

        sum += digit;
    }

    // Check digit makes the sum divisible by 10
    int check_digit = (10 - (sum % 10)) % 10;
    return check_digit;
}

bool ImeiNormalizer::verifyCheckDigit(const std::string& imei) {
    if (imei.length() != 15) {
        return false;
    }

    std::string base = imei.substr(0, 14);
    int expected_check = calculateCheckDigit(base);
    int actual_check = imei[14] - '0';

    return expected_check == actual_check;
}

std::string ImeiNormalizer::extractTac(const std::string& imei) {
    if (imei.length() < 8) {
        return "";
    }
    return imei.substr(0, 8);
}

std::string ImeiNormalizer::extractSnr(const std::string& imei) {
    if (imei.length() < 14) {
        return "";
    }
    return imei.substr(8, 6);
}

std::string ImeiNormalizer::extractDigits(const std::string& input) {
    std::string result;
    for (char c : input) {
        if (std::isdigit(c)) {
            result += c;
        }
    }
    return result;
}

std::string ImeiNormalizer::stripPrefix(const std::string& input) {
    std::string working = input;

    // Remove common prefixes
    if (working.find("imei-") == 0) {
        working = working.substr(5);
    } else if (working.find("imei:") == 0) {
        working = working.substr(5);
    } else if (working.find("IMEI") == 0) {
        working = working.substr(4);
    } else if (working.find("imeisv-") == 0) {
        working = working.substr(7);
    } else if (working.find("imeisv:") == 0) {
        working = working.substr(7);
    }

    return working;
}

} // namespace correlation
} // namespace callflow
