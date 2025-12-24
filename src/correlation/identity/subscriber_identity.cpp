#include "correlation/identity/subscriber_identity.h"
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace callflow {
namespace correlation {

// NormalizedMsisdn implementation
bool NormalizedMsisdn::operator==(const NormalizedMsisdn& other) const {
    return digits_only == other.digits_only;
}

bool NormalizedMsisdn::matches(const NormalizedMsisdn& other) const {
    // Exact match on national or international form
    if (!national.empty() && !other.national.empty() && national == other.national) {
        return true;
    }
    if (!international.empty() && !other.international.empty() &&
        international == other.international) {
        return true;
    }

    // Suffix matching (last 9 digits)
    if (digits_only.length() >= 9 && other.digits_only.length() >= 9) {
        std::string suffix1 = digits_only.substr(digits_only.length() - 9);
        std::string suffix2 = other.digits_only.substr(other.digits_only.length() - 9);
        if (suffix1 == suffix2) {
            return true;
        }
    }

    return false;
}

// NormalizedImsi implementation
bool NormalizedImsi::operator==(const NormalizedImsi& other) const {
    return digits == other.digits;
}

std::string NormalizedImsi::getPlmn() const {
    return mcc + mnc;
}

// NormalizedImei implementation
bool NormalizedImei::operator==(const NormalizedImei& other) const {
    return imei == other.imei;
}

// Guti4G implementation
std::string Guti4G::toString() const {
    std::ostringstream oss;
    oss << "GUTI{MCC=" << mcc
        << ",MNC=" << mnc
        << ",MME-GID=" << mme_group_id
        << ",MME-CODE=" << static_cast<int>(mme_code)
        << ",M-TMSI=0x" << std::hex << std::setfill('0') << std::setw(8) << m_tmsi
        << "}";
    return oss.str();
}

std::optional<Guti4G> Guti4G::parse(const uint8_t* data, size_t length) {
    // 3GPP TS 24.301: GUTI is 11 bytes
    // MCC+MNC (3 bytes BCD) + MME Group ID (2 bytes) + MME Code (1 byte) + M-TMSI (4 bytes)
    if (length < 11) {
        return std::nullopt;
    }

    Guti4G guti;

    // Parse MCC/MNC from BCD (simplified - assumes proper BCD encoding)
    // Byte 0: MCC digit 2 | MCC digit 1
    // Byte 1: MNC digit 3 | MCC digit 3
    // Byte 2: MNC digit 2 | MNC digit 1

    char mcc_str[4];
    char mnc_str[4];

    mcc_str[0] = '0' + (data[0] & 0x0F);
    mcc_str[1] = '0' + ((data[0] >> 4) & 0x0F);
    mcc_str[2] = '0' + (data[1] & 0x0F);
    mcc_str[3] = '\0';
    guti.mcc = mcc_str;

    mnc_str[0] = '0' + (data[2] & 0x0F);
    mnc_str[1] = '0' + ((data[2] >> 4) & 0x0F);
    uint8_t mnc_digit3 = (data[1] >> 4) & 0x0F;
    if (mnc_digit3 != 0x0F) {  // 3-digit MNC
        mnc_str[2] = '0' + mnc_digit3;
        mnc_str[3] = '\0';
    } else {  // 2-digit MNC
        mnc_str[2] = '\0';
    }
    guti.mnc = mnc_str;

    // MME Group ID (2 bytes, big-endian)
    guti.mme_group_id = (static_cast<uint16_t>(data[3]) << 8) | data[4];

    // MME Code (1 byte)
    guti.mme_code = data[5];

    // M-TMSI (4 bytes, big-endian)
    guti.m_tmsi = (static_cast<uint32_t>(data[6]) << 24) |
                  (static_cast<uint32_t>(data[7]) << 16) |
                  (static_cast<uint32_t>(data[8]) << 8) |
                  static_cast<uint32_t>(data[9]);

    return guti;
}

// Guti5G implementation
std::string Guti5G::toString() const {
    std::ostringstream oss;
    oss << "5G-GUTI{MCC=" << mcc
        << ",MNC=" << mnc
        << ",AMF-REGION=" << static_cast<int>(amf_region_id)
        << ",AMF-SET=" << amf_set_id
        << ",AMF-PTR=" << static_cast<int>(amf_pointer)
        << ",5G-TMSI=0x" << std::hex << std::setfill('0') << std::setw(8) << fiveG_tmsi
        << "}";
    return oss.str();
}

std::optional<Guti5G> Guti5G::parse(const uint8_t* data, size_t length) {
    // 3GPP TS 24.501: 5G-GUTI is 11 bytes
    // MCC+MNC (3 bytes BCD) + AMF Region ID (1 byte) + AMF Set ID (2 bytes, 10 bits) +
    // AMF Pointer (6 bits) + 5G-TMSI (4 bytes)
    if (length < 11) {
        return std::nullopt;
    }

    Guti5G guti;

    // Parse MCC/MNC (same as 4G)
    char mcc_str[4];
    char mnc_str[4];

    mcc_str[0] = '0' + (data[0] & 0x0F);
    mcc_str[1] = '0' + ((data[0] >> 4) & 0x0F);
    mcc_str[2] = '0' + (data[1] & 0x0F);
    mcc_str[3] = '\0';
    guti.mcc = mcc_str;

    mnc_str[0] = '0' + (data[2] & 0x0F);
    mnc_str[1] = '0' + ((data[2] >> 4) & 0x0F);
    uint8_t mnc_digit3 = (data[1] >> 4) & 0x0F;
    if (mnc_digit3 != 0x0F) {
        mnc_str[2] = '0' + mnc_digit3;
        mnc_str[3] = '\0';
    } else {
        mnc_str[2] = '\0';
    }
    guti.mnc = mnc_str;

    // AMF Region ID (1 byte)
    guti.amf_region_id = data[3];

    // AMF Set ID (10 bits) and AMF Pointer (6 bits) are in 2 bytes
    // AMF Set ID: bits 15-6 of the 2-byte field
    // AMF Pointer: bits 5-0 of the 2-byte field
    uint16_t amf_field = (static_cast<uint16_t>(data[4]) << 8) | data[5];
    guti.amf_set_id = (amf_field >> 6) & 0x3FF;  // 10 bits
    guti.amf_pointer = amf_field & 0x3F;          // 6 bits

    // 5G-TMSI (4 bytes, big-endian)
    guti.fiveG_tmsi = (static_cast<uint32_t>(data[6]) << 24) |
                      (static_cast<uint32_t>(data[7]) << 16) |
                      (static_cast<uint32_t>(data[8]) << 8) |
                      static_cast<uint32_t>(data[9]);

    return guti;
}

// NetworkEndpoint implementation
std::string NetworkEndpoint::getIpv6Prefix(int prefix_len) const {
    if (ipv6.empty() || prefix_len <= 0 || prefix_len > 128) {
        return "";
    }

    // Simplified: extract first N bits of IPv6 address
    // For /64, take first 4 hextets (first 64 bits)
    size_t colon_count = 0;
    size_t pos = 0;
    int target_colons = prefix_len / 16;

    for (size_t i = 0; i < ipv6.length() && colon_count < target_colons; ++i) {
        if (ipv6[i] == ':') {
            colon_count++;
        }
        pos = i;
    }

    return ipv6.substr(0, pos + 1) + "::/";
}

bool NetworkEndpoint::matchesIp(const std::string& ip) const {
    return ipv4 == ip || ipv6 == ip;
}

bool NetworkEndpoint::matchesIpPrefix(const std::string& prefix) const {
    if (prefix.empty()) {
        return false;
    }

    // Simple prefix matching
    if (!ipv4.empty() && ipv4.find(prefix) == 0) {
        return true;
    }
    if (!ipv6.empty() && ipv6.find(prefix) == 0) {
        return true;
    }

    return false;
}

// SubscriberIdentity implementation
bool SubscriberIdentity::matches(const SubscriberIdentity& other) const {
    // Check IMSI match (strongest)
    if (imsi.has_value() && other.imsi.has_value()) {
        if (*imsi == *other.imsi) {
            return true;
        }
    }

    // Check MSISDN match
    if (msisdn.has_value() && other.msisdn.has_value()) {
        if (msisdn->matches(*other.msisdn)) {
            return true;
        }
    }

    // Check IMEI match
    if (imei.has_value() && other.imei.has_value()) {
        if (*imei == *other.imei) {
            return true;
        }
    }

    // Check GUTI match
    if (guti.has_value() && other.guti.has_value()) {
        if (guti->m_tmsi == other.guti->m_tmsi &&
            guti->mcc == other.guti->mcc &&
            guti->mnc == other.guti->mnc) {
            return true;
        }
    }

    // Check 5G-GUTI match
    if (guti_5g.has_value() && other.guti_5g.has_value()) {
        if (guti_5g->fiveG_tmsi == other.guti_5g->fiveG_tmsi &&
            guti_5g->mcc == other.guti_5g->mcc &&
            guti_5g->mnc == other.guti_5g->mnc) {
            return true;
        }
    }

    // Check IP address match
    for (const auto& ep1 : endpoints) {
        for (const auto& ep2 : other.endpoints) {
            if (ep1.matchesIp(ep2.ipv4) || ep1.matchesIp(ep2.ipv6)) {
                return true;
            }
        }
    }

    return false;
}

void SubscriberIdentity::merge(const SubscriberIdentity& other) {
    // Merge identifiers (prefer non-empty values)
    if (!imsi.has_value() && other.imsi.has_value()) {
        imsi = other.imsi;
    }
    if (!msisdn.has_value() && other.msisdn.has_value()) {
        msisdn = other.msisdn;
    }
    if (!imei.has_value() && other.imei.has_value()) {
        imei = other.imei;
    }

    // Merge temporary IDs (update to latest)
    if (other.guti.has_value()) {
        guti = other.guti;
    }
    if (other.guti_5g.has_value()) {
        guti_5g = other.guti_5g;
    }
    if (other.tmsi.has_value()) {
        tmsi = other.tmsi;
    }
    if (other.tmsi_5g.has_value()) {
        tmsi_5g = other.tmsi_5g;
    }

    // Merge endpoints (avoid duplicates)
    for (const auto& ep : other.endpoints) {
        bool found = false;
        for (const auto& existing : endpoints) {
            if (existing.matchesIp(ep.ipv4) || existing.matchesIp(ep.ipv6)) {
                found = true;
                break;
            }
        }
        if (!found) {
            endpoints.push_back(ep);
        }
    }

    // Merge APN/DNN
    if (apn.empty() && !other.apn.empty()) {
        apn = other.apn;
    }
    if (pdn_type.empty() && !other.pdn_type.empty()) {
        pdn_type = other.pdn_type;
    }

    // Merge confidence scores (keep higher values)
    for (const auto& [key, value] : other.confidence) {
        if (confidence.find(key) == confidence.end() || confidence[key] < value) {
            confidence[key] = value;
        }
    }

    // Update timestamps
    if (other.first_seen < first_seen) {
        first_seen = other.first_seen;
    }
    if (other.last_seen > last_seen) {
        last_seen = other.last_seen;
    }
}

std::string SubscriberIdentity::getPrimaryKey() const {
    // Prefer IMSI as the most stable identifier
    if (imsi.has_value()) {
        return "imsi:" + imsi->digits;
    }

    // Then MSISDN
    if (msisdn.has_value()) {
        return "msisdn:" + msisdn->international;
    }

    // Then IMEI
    if (imei.has_value()) {
        return "imei:" + imei->imei;
    }

    // Then GUTI
    if (guti.has_value()) {
        std::ostringstream oss;
        oss << "guti:" << guti->mcc << guti->mnc << "-"
            << std::hex << guti->m_tmsi;
        return oss.str();
    }

    // Then 5G-GUTI
    if (guti_5g.has_value()) {
        std::ostringstream oss;
        oss << "5g-guti:" << guti_5g->mcc << guti_5g->mnc << "-"
            << std::hex << guti_5g->fiveG_tmsi;
        return oss.str();
    }

    // Fallback to IP if available
    if (!endpoints.empty() && endpoints[0].hasIpv4()) {
        return "ip:" + endpoints[0].ipv4;
    }
    if (!endpoints.empty() && endpoints[0].hasIpv6()) {
        return "ip:" + endpoints[0].ipv6;
    }

    return "unknown";
}

} // namespace correlation
} // namespace callflow
