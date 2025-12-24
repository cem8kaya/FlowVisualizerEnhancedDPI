#include "correlation/nas/nas_ie_parser.h"
#include <cstring>
#include <sstream>
#include <iomanip>

namespace callflow {
namespace correlation {

std::string NasIEParser::decodeTbcdDigits(const uint8_t* data, size_t length, bool skip_filler) {
    std::string result;
    result.reserve(length * 2);

    for (size_t i = 0; i < length; ++i) {
        uint8_t low_nibble = data[i] & 0x0F;
        uint8_t high_nibble = (data[i] >> 4) & 0x0F;

        // Add low nibble
        if (low_nibble <= 9) {
            result += ('0' + low_nibble);
        } else if (!skip_filler || low_nibble != 0x0F) {
            // Non-digit, non-filler
            result += ('A' + (low_nibble - 10));
        }

        // Add high nibble
        if (high_nibble <= 9) {
            result += ('0' + high_nibble);
        } else if (!skip_filler || high_nibble != 0x0F) {
            // Non-digit, non-filler
            result += ('A' + (high_nibble - 10));
        }
    }

    return result;
}

std::string NasIEParser::decodeBcdDigits(const uint8_t* data, size_t length, bool skip_filler) {
    std::string result;
    result.reserve(length * 2);

    for (size_t i = 0; i < length; ++i) {
        uint8_t high_nibble = (data[i] >> 4) & 0x0F;
        uint8_t low_nibble = data[i] & 0x0F;

        // Add high nibble first (BCD, not TBCD)
        if (high_nibble <= 9) {
            result += ('0' + high_nibble);
        } else if (!skip_filler || high_nibble != 0x0F) {
            result += ('A' + (high_nibble - 10));
        }

        // Add low nibble
        if (low_nibble <= 9) {
            result += ('0' + low_nibble);
        } else if (!skip_filler || low_nibble != 0x0F) {
            result += ('A' + (low_nibble - 10));
        }
    }

    return result;
}

bool NasIEParser::decodePlmn(const uint8_t* data, std::string& mcc, std::string& mnc) {
    if (!data) return false;

    // PLMN encoding: TS 24.008 section 10.5.1.13
    // Octet 1: MCC digit 2 | MCC digit 1
    // Octet 2: MNC digit 3 | MCC digit 3
    // Octet 3: MNC digit 2 | MNC digit 1

    uint8_t mcc1 = data[0] & 0x0F;
    uint8_t mcc2 = (data[0] >> 4) & 0x0F;
    uint8_t mcc3 = data[1] & 0x0F;
    uint8_t mnc3 = (data[1] >> 4) & 0x0F;
    uint8_t mnc1 = data[2] & 0x0F;
    uint8_t mnc2 = (data[2] >> 4) & 0x0F;

    // Build MCC (always 3 digits)
    mcc.clear();
    mcc += ('0' + mcc1);
    mcc += ('0' + mcc2);
    mcc += ('0' + mcc3);

    // Build MNC (2 or 3 digits)
    mnc.clear();
    mnc += ('0' + mnc1);
    mnc += ('0' + mnc2);
    if (mnc3 != 0x0F) {  // 3-digit MNC
        mnc += ('0' + mnc3);
    }

    return true;
}

MobileIdentityType NasIEParser::parseMobileIdentityType(const uint8_t* data, size_t length) {
    if (!data || length < 1) {
        return MobileIdentityType::NO_IDENTITY;
    }

    // Type is in the lower 3 bits of the first octet
    uint8_t type = data[0] & 0x07;
    return static_cast<MobileIdentityType>(type);
}

std::optional<std::string> NasIEParser::parseImsi(const uint8_t* data, size_t length) {
    if (!data || length < 3) {
        return std::nullopt;
    }

    MobileIdentityType type = parseMobileIdentityType(data, length);
    if (type != MobileIdentityType::IMSI) {
        return std::nullopt;
    }

    // IMSI is encoded in TBCD, starting from bit 5 of octet 1
    // First digit is in bits 5-8 of octet 1
    uint8_t first_digit = (data[0] >> 4) & 0x0F;
    if (first_digit > 9) {
        return std::nullopt;
    }

    std::string imsi;
    imsi += ('0' + first_digit);

    // Remaining digits are TBCD encoded in remaining octets
    imsi += decodeTbcdDigits(data + 1, length - 1, true);

    // IMSI should be 15 digits
    if (imsi.length() != 15) {
        // Pad or truncate if needed
        if (imsi.length() > 15) {
            imsi = imsi.substr(0, 15);
        }
    }

    return imsi;
}

std::optional<std::string> NasIEParser::parseImei(const uint8_t* data, size_t length) {
    if (!data || length < 8) {
        return std::nullopt;
    }

    MobileIdentityType type = parseMobileIdentityType(data, length);
    if (type != MobileIdentityType::IMEI) {
        return std::nullopt;
    }

    // IMEI is 15 digits, TBCD encoded
    std::string imei = decodeTbcdDigits(data + 1, length - 1, true);

    if (imei.length() > 15) {
        imei = imei.substr(0, 15);
    }

    return imei;
}

std::optional<std::string> NasIEParser::parseImeisv(const uint8_t* data, size_t length) {
    if (!data || length < 9) {
        return std::nullopt;
    }

    MobileIdentityType type = parseMobileIdentityType(data, length);
    if (type != MobileIdentityType::IMEISV) {
        return std::nullopt;
    }

    // IMEISV is 16 digits, TBCD encoded
    std::string imeisv = decodeTbcdDigits(data + 1, length - 1, true);

    if (imeisv.length() > 16) {
        imeisv = imeisv.substr(0, 16);
    }

    return imeisv;
}

std::optional<uint32_t> NasIEParser::parseTmsi(const uint8_t* data, size_t length) {
    if (!data || length < 5) {
        return std::nullopt;
    }

    MobileIdentityType type = parseMobileIdentityType(data, length);
    if (type != MobileIdentityType::TMSI) {
        return std::nullopt;
    }

    // TMSI is 4 octets
    uint32_t tmsi = (static_cast<uint32_t>(data[1]) << 24) |
                    (static_cast<uint32_t>(data[2]) << 16) |
                    (static_cast<uint32_t>(data[3]) << 8) |
                    static_cast<uint32_t>(data[4]);

    return tmsi;
}

std::optional<Guti4G> NasIEParser::parseGuti(const uint8_t* data, size_t length) {
    if (!data || length < 11) {
        return std::nullopt;
    }

    MobileIdentityType type = parseMobileIdentityType(data, length);
    if (type != MobileIdentityType::GUTI) {
        return std::nullopt;
    }

    Guti4G guti;

    // Decode PLMN (octets 2-4)
    if (!decodePlmn(data + 1, guti.mcc, guti.mnc)) {
        return std::nullopt;
    }

    // MME Group ID (octets 5-6)
    guti.mme_group_id = (static_cast<uint16_t>(data[4]) << 8) | data[5];

    // MME Code (octet 7)
    guti.mme_code = data[6];

    // M-TMSI (octets 8-11)
    guti.m_tmsi = (static_cast<uint32_t>(data[7]) << 24) |
                  (static_cast<uint32_t>(data[8]) << 16) |
                  (static_cast<uint32_t>(data[9]) << 8) |
                  static_cast<uint32_t>(data[10]);

    return guti;
}

std::optional<std::string> NasIEParser::parseApn(const uint8_t* data, size_t length) {
    if (!data || length < 1) {
        return std::nullopt;
    }

    // APN is encoded as per TS 23.003
    // Label length followed by label, repeated
    std::string apn;
    size_t offset = 0;

    while (offset < length) {
        uint8_t label_length = data[offset];
        if (label_length == 0 || offset + 1 + label_length > length) {
            break;
        }

        if (!apn.empty()) {
            apn += '.';
        }

        apn.append(reinterpret_cast<const char*>(data + offset + 1), label_length);
        offset += 1 + label_length;
    }

    return apn.empty() ? std::nullopt : std::optional<std::string>(apn);
}

std::optional<std::string> NasIEParser::parsePdnAddress(const uint8_t* data,
                                                         size_t length,
                                                         NasPdnType* pdn_type) {
    if (!data || length < 2) {
        return std::nullopt;
    }

    // PDN type is in the lower 3 bits of octet 1
    uint8_t type_value = data[0] & 0x07;
    NasPdnType type = static_cast<NasPdnType>(type_value);

    if (pdn_type) {
        *pdn_type = type;
    }

    std::string address;

    switch (type) {
        case NasPdnType::IPV4:
            if (length >= 5) {
                // IPv4 address (4 octets)
                std::ostringstream oss;
                oss << static_cast<int>(data[1]) << "."
                    << static_cast<int>(data[2]) << "."
                    << static_cast<int>(data[3]) << "."
                    << static_cast<int>(data[4]);
                address = oss.str();
            }
            break;

        case NasPdnType::IPV6:
            if (length >= 9) {
                // IPv6 prefix (8 octets)
                std::ostringstream oss;
                oss << std::hex << std::setfill('0');
                for (size_t i = 1; i < 9; i += 2) {
                    if (i > 1) oss << ":";
                    oss << std::setw(2) << static_cast<int>(data[i])
                        << std::setw(2) << static_cast<int>(data[i + 1]);
                }
                address = oss.str();
            }
            break;

        case NasPdnType::IPV4V6:
            if (length >= 5) {
                // IPv4 first
                std::ostringstream oss;
                oss << static_cast<int>(data[1]) << "."
                    << static_cast<int>(data[2]) << "."
                    << static_cast<int>(data[3]) << "."
                    << static_cast<int>(data[4]);
                address = oss.str();
            }
            break;

        default:
            break;
    }

    return address.empty() ? std::nullopt : std::optional<std::string>(address);
}

std::optional<uint8_t> NasIEParser::parseEpsQos(const uint8_t* data, size_t length) {
    if (!data || length < 1) {
        return std::nullopt;
    }

    // QCI is in octet 1
    uint8_t qci = data[0];
    if (qci == 0 || qci > 9) {
        // Extended QCI values or invalid
        return std::nullopt;
    }

    return qci;
}

std::optional<NasMessage::TrackingAreaIdentity> NasIEParser::parseTai(const uint8_t* data, size_t length) {
    if (!data || length < 5) {
        return std::nullopt;
    }

    NasMessage::TrackingAreaIdentity tai;

    // Decode PLMN (octets 1-3)
    if (!decodePlmn(data, tai.mcc, tai.mnc)) {
        return std::nullopt;
    }

    // TAC (octets 4-5)
    tai.tac = (static_cast<uint16_t>(data[3]) << 8) | data[4];

    return tai;
}

bool NasIEParser::parseAllIEs(NasMessage& msg, const uint8_t* data, size_t length) {
    // This is a simplified parser that extracts key IEs
    // A full implementation would parse all IEs according to message type

    size_t offset = 0;

    while (offset < length) {
        // Check if we have at least 2 bytes for IE type and length
        if (offset + 2 > length) {
            break;
        }

        uint8_t ie_type = data[offset];
        uint8_t ie_length = data[offset + 1];

        if (offset + 2 + ie_length > length) {
            break;
        }

        const uint8_t* ie_data = data + offset + 2;

        // Parse specific IEs based on type
        switch (static_cast<NasIEType>(ie_type)) {
            case NasIEType::EPS_MOBILE_IDENTITY: {
                MobileIdentityType id_type = parseMobileIdentityType(ie_data, ie_length);
                switch (id_type) {
                    case MobileIdentityType::IMSI:
                        if (auto imsi = parseImsi(ie_data, ie_length)) {
                            msg.setImsi(*imsi);
                        }
                        break;
                    case MobileIdentityType::IMEI:
                        if (auto imei = parseImei(ie_data, ie_length)) {
                            msg.setImei(*imei);
                        }
                        break;
                    case MobileIdentityType::IMEISV:
                        if (auto imeisv = parseImeisv(ie_data, ie_length)) {
                            msg.setImeisv(*imeisv);
                        }
                        break;
                    case MobileIdentityType::GUTI:
                        if (auto guti = parseGuti(ie_data, ie_length)) {
                            msg.setGuti(*guti);
                        }
                        break;
                    case MobileIdentityType::TMSI:
                        if (auto tmsi = parseTmsi(ie_data, ie_length)) {
                            msg.setTmsi(*tmsi);
                        }
                        break;
                    default:
                        break;
                }
                break;
            }

            case NasIEType::ACCESS_POINT_NAME:
                if (auto apn = parseApn(ie_data, ie_length)) {
                    msg.setApn(*apn);
                }
                break;

            case NasIEType::PDN_ADDRESS: {
                NasPdnType pdn_type;
                if (auto pdn_addr = parsePdnAddress(ie_data, ie_length, &pdn_type)) {
                    msg.setPdnAddress(*pdn_addr);
                    msg.setPdnType(pdn_type);
                }
                break;
            }

            case NasIEType::EPS_QOS:
                if (auto qci = parseEpsQos(ie_data, ie_length)) {
                    msg.setQci(*qci);
                }
                break;

            case NasIEType::TAI:
                if (auto tai = parseTai(ie_data, ie_length)) {
                    msg.setTai(*tai);
                }
                break;

            default:
                // Skip unknown IEs
                break;
        }

        offset += 2 + ie_length;
    }

    return true;
}

} // namespace correlation
} // namespace callflow
