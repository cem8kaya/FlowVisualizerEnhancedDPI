#pragma once

#include "subscriber_identity.h"
#include <unordered_map>

namespace callflow {
namespace correlation {

class MsisdnNormalizer {
public:
    /**
     * @brief Normalize MSISDN from various input formats
     * @param input Raw MSISDN string (SIP URI, TEL URI, digits, etc.)
     * @return Normalized MSISDN structure
     */
    static NormalizedMsisdn normalize(const std::string& input);

    /**
     * @brief Extract MSISDN from SIP URI
     * @param uri Full SIP URI (e.g., "sip:+1234@domain;user=phone")
     * @return Normalized MSISDN or nullopt if not found
     */
    static std::optional<NormalizedMsisdn> fromSipUri(const std::string& uri);

    /**
     * @brief Extract MSISDN from TEL URI
     * @param uri Full TEL URI (e.g., "tel:+1-234-567-8901")
     * @return Normalized MSISDN or nullopt if not found
     */
    static std::optional<NormalizedMsisdn> fromTelUri(const std::string& uri);

    /**
     * @brief Check if two MSISDNs match (with fuzzy matching)
     * @param m1 First MSISDN
     * @param m2 Second MSISDN
     * @param suffix_digits Minimum suffix digits to match (default 9)
     * @return true if MSISDNs match
     */
    static bool matches(const NormalizedMsisdn& m1,
                       const NormalizedMsisdn& m2,
                       size_t suffix_digits = 9);

    /**
     * @brief Check if raw string matches a normalized MSISDN
     */
    static bool matches(const std::string& raw,
                       const NormalizedMsisdn& normalized,
                       size_t suffix_digits = 9);

private:
    static std::string extractDigits(const std::string& input);
    static std::string stripLeadingZeros(const std::string& input);
    static std::string detectCountryCode(const std::string& digits);
    static std::string removeUriParameters(const std::string& uri);

    // Country code patterns
    static const std::unordered_map<std::string, std::string> COUNTRY_CODES;
};

} // namespace correlation
} // namespace callflow
