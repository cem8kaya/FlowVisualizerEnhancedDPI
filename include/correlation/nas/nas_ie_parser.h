#pragma once

#include "correlation/nas/nas_types.h"
#include "correlation/nas/nas_message.h"
#include "correlation/identity/subscriber_identity.h"
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace callflow {
namespace correlation {

/**
 * @brief NAS Information Element Parser
 *
 * Parses NAS IEs according to TS 24.301 specification.
 * Handles both EMM and ESM information elements.
 */
class NasIEParser {
public:
    NasIEParser() = default;
    ~NasIEParser() = default;

    /**
     * @brief Parse Mobile Identity IE (TS 24.301 section 9.9.2.3)
     * @param data IE data (without length field)
     * @param length IE length
     * @return Mobile identity type
     */
    static MobileIdentityType parseMobileIdentityType(const uint8_t* data, size_t length);

    /**
     * @brief Parse IMSI from Mobile Identity IE
     * @param data IE data
     * @param length IE length
     * @return IMSI string (15 digits) or nullopt
     */
    static std::optional<std::string> parseImsi(const uint8_t* data, size_t length);

    /**
     * @brief Parse IMEI from Mobile Identity IE
     * @param data IE data
     * @param length IE length
     * @return IMEI string (15 digits) or nullopt
     */
    static std::optional<std::string> parseImei(const uint8_t* data, size_t length);

    /**
     * @brief Parse IMEISV from Mobile Identity IE
     * @param data IE data
     * @param length IE length
     * @return IMEISV string (16 digits) or nullopt
     */
    static std::optional<std::string> parseImeisv(const uint8_t* data, size_t length);

    /**
     * @brief Parse TMSI from Mobile Identity IE
     * @param data IE data
     * @param length IE length
     * @return TMSI value or nullopt
     */
    static std::optional<uint32_t> parseTmsi(const uint8_t* data, size_t length);

    /**
     * @brief Parse GUTI from Mobile Identity IE
     * @param data IE data
     * @param length IE length
     * @return GUTI structure or nullopt
     */
    static std::optional<Guti4G> parseGuti(const uint8_t* data, size_t length);

    /**
     * @brief Parse APN (Access Point Name) IE (TS 24.301 section 9.9.4.1)
     * @param data IE data
     * @param length IE length
     * @return APN string (e.g., "internet", "ims") or nullopt
     */
    static std::optional<std::string> parseApn(const uint8_t* data, size_t length);

    /**
     * @brief Parse PDN Address IE (TS 24.301 section 9.9.4.9)
     * @param data IE data
     * @param length IE length
     * @param pdn_type Output: PDN type
     * @return PDN address (IPv4, IPv6, or IPv4v6) or nullopt
     */
    static std::optional<std::string> parsePdnAddress(const uint8_t* data,
                                                       size_t length,
                                                       NasPdnType* pdn_type);

    /**
     * @brief Parse EPS QoS IE (TS 24.301 section 9.9.4.3)
     * @param data IE data
     * @param length IE length
     * @return QCI (QoS Class Identifier) or nullopt
     */
    static std::optional<uint8_t> parseEpsQos(const uint8_t* data, size_t length);

    /**
     * @brief Parse Tracking Area Identity (TAI) IE (TS 24.301 section 9.9.3.32)
     * @param data IE data
     * @param length IE length
     * @return TAI structure or nullopt
     */
    static std::optional<NasMessage::TrackingAreaIdentity> parseTai(const uint8_t* data, size_t length);

    /**
     * @brief Decode BCD (Binary-Coded Decimal) digit string
     * @param data BCD data
     * @param length Length of data
     * @param skip_filler Skip 0xF filler digits
     * @return Decoded digit string
     */
    static std::string decodeBcdDigits(const uint8_t* data, size_t length, bool skip_filler = true);

    /**
     * @brief Decode TBCD (Telephony BCD) string (swapped nibbles)
     * @param data TBCD data
     * @param length Length of data
     * @param skip_filler Skip 0xF filler digits
     * @return Decoded digit string
     */
    static std::string decodeTbcdDigits(const uint8_t* data, size_t length, bool skip_filler = true);

    /**
     * @brief Decode MCC/MNC from PLMN (Public Land Mobile Network) identifier
     * @param data PLMN data (3 bytes)
     * @param mcc Output: Mobile Country Code (3 digits)
     * @param mnc Output: Mobile Network Code (2-3 digits)
     * @return true if successful
     */
    static bool decodePlmn(const uint8_t* data, std::string& mcc, std::string& mnc);

    /**
     * @brief Parse all IEs from a NAS message
     * @param msg Message to populate with parsed IEs
     * @param data NAS message payload (after header)
     * @param length Payload length
     * @return true if successful
     */
    static bool parseAllIEs(NasMessage& msg, const uint8_t* data, size_t length);

private:
    // Helper for parsing Type 1-6 IEs (variable length encoding)
    static bool skipToNextIE(const uint8_t*& data, size_t& remaining, size_t ie_length);

    // Helper for extracting IE value based on IE format
    static std::optional<std::vector<uint8_t>> extractIEValue(
        const uint8_t*& data,
        size_t& remaining,
        uint8_t ie_type,
        bool is_type4 = true  // Type 4 (LV) vs Type 3 (V)
    );
};

} // namespace correlation
} // namespace callflow
