#pragma once

#include "subscriber_identity.h"

namespace callflow {
namespace correlation {

class ImsiNormalizer {
public:
    /**
     * @brief Normalize IMSI from various input formats
     * @param input Raw IMSI string (digits, BCD, prefixed, etc.)
     * @return Normalized IMSI structure or nullopt if invalid
     */
    static std::optional<NormalizedImsi> normalize(const std::string& input);

    /**
     * @brief Parse IMSI from BCD-encoded data (as in GTP/Diameter)
     * @param data BCD-encoded IMSI bytes
     * @param length Length of data in bytes
     * @return Normalized IMSI or nullopt if invalid
     */
    static std::optional<NormalizedImsi> fromBcd(const uint8_t* data, size_t length);

    /**
     * @brief Parse IMSI from Diameter User-Name AVP format
     * @param username Diameter username (e.g., "310260123456789@ims.mnc260.mcc310.3gppnetwork.org")
     * @return Normalized IMSI or nullopt if not found
     */
    static std::optional<NormalizedImsi> fromDiameterUsername(const std::string& username);

    /**
     * @brief Validate IMSI format (15 digits, valid MCC/MNC)
     * @param imsi IMSI string to validate
     * @return true if valid IMSI format
     */
    static bool isValid(const std::string& imsi);

    /**
     * @brief Extract MCC from IMSI digits
     * @param imsi_digits 15-digit IMSI string
     * @return MCC (3 digits) or empty if invalid
     */
    static std::string extractMcc(const std::string& imsi_digits);

    /**
     * @brief Extract MNC from IMSI digits
     * @param imsi_digits 15-digit IMSI string
     * @return MNC (2-3 digits) or empty if invalid
     */
    static std::string extractMnc(const std::string& imsi_digits);

    /**
     * @brief Extract MSIN from IMSI digits
     * @param imsi_digits 15-digit IMSI string
     * @param mnc_length Length of MNC (2 or 3 digits)
     * @return MSIN or empty if invalid
     */
    static std::string extractMsin(const std::string& imsi_digits, int mnc_length);

private:
    static std::string extractDigits(const std::string& input);
    static std::string stripPrefix(const std::string& input);
    static int detectMncLength(const std::string& mcc, const std::string& first_digit);

    // Known MNC lengths for specific MCCs (some countries use 3-digit MNC)
    static const std::unordered_map<std::string, int> MCC_MNC_LENGTHS;
};

} // namespace correlation
} // namespace callflow
