#pragma once

#include "subscriber_identity.h"
#include <string>

namespace callflow {
namespace correlation {

class GutiParser {
public:
    /**
     * @brief Parse 4G GUTI from BCD-encoded data
     * @param data BCD-encoded GUTI bytes (11 bytes)
     * @param length Length of data in bytes
     * @return Parsed GUTI or nullopt if invalid
     */
    static std::optional<Guti4G> parse4G(const uint8_t* data, size_t length);

    /**
     * @brief Parse 5G-GUTI from BCD-encoded data
     * @param data BCD-encoded 5G-GUTI bytes (11 bytes)
     * @param length Length of data in bytes
     * @return Parsed 5G-GUTI or nullopt if invalid
     */
    static std::optional<Guti5G> parse5G(const uint8_t* data, size_t length);

    /**
     * @brief Parse GUTI from hex string representation
     * @param hex_string Hex string of GUTI (22 hex chars = 11 bytes)
     * @param is_5g true for 5G-GUTI, false for 4G GUTI
     * @return Parsed GUTI or nullopt if invalid
     */
    static std::optional<Guti4G> parse4GFromHex(const std::string& hex_string);
    static std::optional<Guti5G> parse5GFromHex(const std::string& hex_string);

    /**
     * @brief Encode 4G GUTI to BCD format
     * @param guti GUTI structure to encode
     * @param output Output buffer (must be at least 11 bytes)
     * @return Number of bytes written, or 0 on error
     */
    static size_t encode4G(const Guti4G& guti, uint8_t* output);

    /**
     * @brief Encode 5G-GUTI to BCD format
     * @param guti 5G-GUTI structure to encode
     * @param output Output buffer (must be at least 11 bytes)
     * @return Number of bytes written, or 0 on error
     */
    static size_t encode5G(const Guti5G& guti, uint8_t* output);

    /**
     * @brief Extract M-TMSI from 4G GUTI
     */
    static uint32_t extractMTmsi(const Guti4G& guti) {
        return guti.m_tmsi;
    }

    /**
     * @brief Extract 5G-TMSI from 5G-GUTI
     */
    static uint32_t extract5GTmsi(const Guti5G& guti) {
        return guti.fiveG_tmsi;
    }

    /**
     * @brief Check if two 4G GUTIs belong to the same MME pool
     */
    static bool isSameMmePool(const Guti4G& guti1, const Guti4G& guti2);

    /**
     * @brief Check if two 5G-GUTIs belong to the same AMF set
     */
    static bool isSameAmfSet(const Guti5G& guti1, const Guti5G& guti2);

private:
    static std::vector<uint8_t> hexStringToBytes(const std::string& hex);
    static void encodeMccMnc(const std::string& mcc, const std::string& mnc, uint8_t* output);
    static bool decodeMccMnc(const uint8_t* data, std::string& mcc, std::string& mnc);
};

} // namespace correlation
} // namespace callflow
