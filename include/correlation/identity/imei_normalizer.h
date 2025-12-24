#pragma once

#include "subscriber_identity.h"

namespace callflow {
namespace correlation {

class ImeiNormalizer {
public:
    /**
     * @brief Normalize IMEI/IMEISV from various input formats
     * @param input Raw IMEI string (14, 15, or 16 digits)
     * @return Normalized IMEI structure or nullopt if invalid
     */
    static std::optional<NormalizedImei> normalize(const std::string& input);

    /**
     * @brief Parse IMEI from BCD-encoded data (as in GTP)
     * @param data BCD-encoded IMEI bytes
     * @param length Length of data in bytes
     * @return Normalized IMEI or nullopt if invalid
     */
    static std::optional<NormalizedImei> fromBcd(const uint8_t* data, size_t length);

    /**
     * @brief Validate IMEI format (14 digits without check digit)
     * @param imei IMEI string to validate
     * @return true if valid IMEI format
     */
    static bool isValidImei(const std::string& imei);

    /**
     * @brief Validate IMEISV format (16 digits)
     * @param imeisv IMEISV string to validate
     * @return true if valid IMEISV format
     */
    static bool isValidImeisv(const std::string& imeisv);

    /**
     * @brief Calculate Luhn check digit for IMEI
     * @param imei 14-digit IMEI (without check digit)
     * @return Check digit (0-9)
     */
    static int calculateCheckDigit(const std::string& imei);

    /**
     * @brief Verify IMEI check digit
     * @param imei 15-digit IMEI (with check digit)
     * @return true if check digit is valid
     */
    static bool verifyCheckDigit(const std::string& imei);

    /**
     * @brief Extract TAC (Type Allocation Code) from IMEI
     * @param imei IMEI string
     * @return TAC (8 digits) or empty if invalid
     */
    static std::string extractTac(const std::string& imei);

    /**
     * @brief Extract SNR (Serial Number) from IMEI
     * @param imei IMEI string
     * @return SNR (6 digits) or empty if invalid
     */
    static std::string extractSnr(const std::string& imei);

private:
    static std::string extractDigits(const std::string& input);
    static std::string stripPrefix(const std::string& input);
};

} // namespace correlation
} // namespace callflow
