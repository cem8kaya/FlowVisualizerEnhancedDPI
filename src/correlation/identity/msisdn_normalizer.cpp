#include "correlation/identity/msisdn_normalizer.h"
#include <algorithm>
#include <cctype>

namespace callflow {
namespace correlation {

// Common country codes (extend as needed)
const std::unordered_map<std::string, std::string> MsisdnNormalizer::COUNTRY_CODES = {
    {"1", "US/CA"},     // North America
    {"44", "UK"},       // United Kingdom
    {"49", "DE"},       // Germany
    {"33", "FR"},       // France
    {"81", "JP"},       // Japan
    {"86", "CN"},       // China
    {"91", "IN"},       // India
    {"90", "TR"},       // Turkey
    {"7", "RU"},        // Russia
    {"39", "IT"},       // Italy
    {"34", "ES"},       // Spain
    {"82", "KR"},       // South Korea
    {"61", "AU"},       // Australia
    {"55", "BR"},       // Brazil
    {"52", "MX"},       // Mexico
    {"31", "NL"},       // Netherlands
    {"46", "SE"},       // Sweden
    {"47", "NO"},       // Norway
    {"45", "DK"},       // Denmark
    {"41", "CH"},       // Switzerland
    {"43", "AT"},       // Austria
    {"32", "BE"},       // Belgium
    {"351", "PT"},      // Portugal
    {"353", "IE"},      // Ireland
    {"358", "FI"},      // Finland
    {"420", "CZ"},      // Czech Republic
    {"421", "SK"},      // Slovakia
    {"48", "PL"},       // Poland
    {"30", "GR"},       // Greece
};

NormalizedMsisdn MsisdnNormalizer::normalize(const std::string& input) {
    NormalizedMsisdn result;
    result.raw = input;

    std::string working = input;

    // Handle SIP URI
    if (working.find("sip:") == 0 || working.find("sips:") == 0) {
        auto parsed = fromSipUri(working);
        if (parsed) return *parsed;
    }

    // Handle TEL URI
    if (working.find("tel:") == 0) {
        auto parsed = fromTelUri(working);
        if (parsed) return *parsed;
    }

    // Remove common prefixes
    if (working.find("msisdn-") == 0) {
        working = working.substr(7);
    }

    // Extract digits only
    result.digits_only = extractDigits(working);

    // Detect and extract country code
    result.country_code = detectCountryCode(result.digits_only);

    // Create international form
    if (!result.country_code.empty()) {
        result.international = result.digits_only;
        // National form: strip country code and leading zeros
        std::string national = result.digits_only.substr(result.country_code.length());
        result.national = stripLeadingZeros(national);
    } else {
        // Assume it's already national format
        result.national = stripLeadingZeros(result.digits_only);
        result.international = result.digits_only;  // Best guess
    }

    return result;
}

std::optional<NormalizedMsisdn> MsisdnNormalizer::fromSipUri(const std::string& uri) {
    NormalizedMsisdn result;
    result.raw = uri;

    std::string working = uri;

    // Remove sip: or sips: prefix
    if (working.find("sips:") == 0) {
        working = working.substr(5);
    } else if (working.find("sip:") == 0) {
        working = working.substr(4);
    }

    // Remove everything after @ (domain part)
    size_t at_pos = working.find('@');
    if (at_pos != std::string::npos) {
        working = working.substr(0, at_pos);
    }

    // Remove URI parameters (everything after first ;)
    working = removeUriParameters(working);

    // Remove visual separators
    working.erase(std::remove_if(working.begin(), working.end(),
        [](char c) { return c == '-' || c == '.' || c == '(' || c == ')' || c == ' '; }),
        working.end());

    // Extract digits (and + sign)
    result.digits_only = extractDigits(working);

    if (result.digits_only.empty()) {
        return std::nullopt;
    }

    // Handle + prefix for international
    bool has_plus = (uri.find('+') != std::string::npos);

    if (has_plus || result.digits_only.length() > 10) {
        result.country_code = detectCountryCode(result.digits_only);
        result.international = result.digits_only;
        if (!result.country_code.empty()) {
            std::string national = result.digits_only.substr(result.country_code.length());
            result.national = stripLeadingZeros(national);
        } else {
            result.national = stripLeadingZeros(result.digits_only);
        }
    } else {
        result.national = stripLeadingZeros(result.digits_only);
        result.international = result.digits_only;
    }

    return result;
}

std::optional<NormalizedMsisdn> MsisdnNormalizer::fromTelUri(const std::string& uri) {
    NormalizedMsisdn result;
    result.raw = uri;

    std::string working = uri;

    // Remove tel: prefix
    if (working.find("tel:") == 0) {
        working = working.substr(4);
    }

    // Remove parameters
    working = removeUriParameters(working);

    // TEL URIs typically use visual separators
    working.erase(std::remove_if(working.begin(), working.end(),
        [](char c) { return c == '-' || c == '.' || c == '(' || c == ')' || c == ' '; }),
        working.end());

    result.digits_only = extractDigits(working);

    if (result.digits_only.empty()) {
        return std::nullopt;
    }

    // TEL URIs with + are always international
    if (uri.find('+') != std::string::npos) {
        result.country_code = detectCountryCode(result.digits_only);
        result.international = result.digits_only;
        if (!result.country_code.empty()) {
            std::string national = result.digits_only.substr(result.country_code.length());
            result.national = stripLeadingZeros(national);
        } else {
            result.national = stripLeadingZeros(result.digits_only);
        }
    } else {
        result.national = stripLeadingZeros(result.digits_only);
        result.international = result.digits_only;
    }

    return result;
}

bool MsisdnNormalizer::matches(const NormalizedMsisdn& m1,
                               const NormalizedMsisdn& m2,
                               size_t suffix_digits) {
    // Exact match on national form
    if (!m1.national.empty() && !m2.national.empty() &&
        m1.national == m2.national) {
        return true;
    }

    // Exact match on international form
    if (!m1.international.empty() && !m2.international.empty() &&
        m1.international == m2.international) {
        return true;
    }

    // Suffix matching (last N digits)
    if (m1.digits_only.length() >= suffix_digits &&
        m2.digits_only.length() >= suffix_digits) {
        std::string suffix1 = m1.digits_only.substr(
            m1.digits_only.length() - suffix_digits);
        std::string suffix2 = m2.digits_only.substr(
            m2.digits_only.length() - suffix_digits);
        if (suffix1 == suffix2) {
            return true;
        }
    }

    // One contains the other (for partial matches)
    if (m1.national.length() > 6 && m2.national.length() > 6) {
        if (m1.national.find(m2.national) != std::string::npos ||
            m2.national.find(m1.national) != std::string::npos) {
            return true;
        }
    }

    return false;
}

bool MsisdnNormalizer::matches(const std::string& raw,
                               const NormalizedMsisdn& normalized,
                               size_t suffix_digits) {
    NormalizedMsisdn parsed = normalize(raw);
    return matches(parsed, normalized, suffix_digits);
}

std::string MsisdnNormalizer::extractDigits(const std::string& input) {
    std::string result;
    for (char c : input) {
        if (std::isdigit(c)) {
            result += c;
        }
    }
    return result;
}

std::string MsisdnNormalizer::stripLeadingZeros(const std::string& input) {
    size_t start = 0;
    while (start < input.length() && input[start] == '0') {
        start++;
    }
    if (start == input.length()) {
        return "0";  // All zeros
    }
    return input.substr(start);
}

std::string MsisdnNormalizer::detectCountryCode(const std::string& digits) {
    // Try 3-digit codes first, then 2-digit, then 1-digit
    for (int len = 3; len >= 1; len--) {
        if (digits.length() > static_cast<size_t>(len)) {
            std::string prefix = digits.substr(0, len);
            if (COUNTRY_CODES.find(prefix) != COUNTRY_CODES.end()) {
                return prefix;
            }
        }
    }
    return "";
}

std::string MsisdnNormalizer::removeUriParameters(const std::string& uri) {
    size_t semi_pos = uri.find(';');
    if (semi_pos != std::string::npos) {
        return uri.substr(0, semi_pos);
    }
    return uri;
}

} // namespace correlation
} // namespace callflow
