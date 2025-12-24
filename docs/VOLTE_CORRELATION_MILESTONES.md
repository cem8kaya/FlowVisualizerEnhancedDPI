# VoLTE Cross-Protocol Correlation Implementation
## Complete Milestone Prompts for Claude Code

**Total Estimated Time**: 14 weeks  
**Total Milestones**: 8  
**Total Estimated Lines of Code**: ~15,000 C++

---

# Table of Contents

1. [Milestone 1: Subscriber Identity Management](#milestone-1-subscriber-identity-management-2-weeks)
2. [Milestone 2: SIP Intra-Protocol Correlator](#milestone-2-sip-intra-protocol-correlator-2-weeks)
3. [Milestone 3: Diameter Intra-Protocol Correlator](#milestone-3-diameter-intra-protocol-correlator-2-weeks)
4. [Milestone 4: GTPv2 Intra-Protocol Correlator](#milestone-4-gtpv2-intra-protocol-correlator-2-weeks)
5. [Milestone 5: NAS/S1AP Correlator](#milestone-5-nass1ap-correlator-2-weeks)
6. [Milestone 6: RTP Stream Correlator](#milestone-6-rtp-stream-correlator-1-week)
7. [Milestone 7: VoLTE Inter-Protocol Correlator](#milestone-7-volte-inter-protocol-correlator-2-weeks)
8. [Milestone 8: Testing, API & Optimization](#milestone-8-testing-api--optimization-1-week)

---

# Milestone 1: Subscriber Identity Management (2 weeks)

## PROMPT 1.1: Core Subscriber Identity Types

```markdown
# Subscriber Identity Management - Core Types
## nDPI Callflow Visualizer - VoLTE Correlation Foundation

**Context:**
I'm building the nDPI Callflow Visualizer in C++. This is the foundation for VoLTE cross-protocol correlation. I need to implement a subscriber identity management system that tracks and normalizes IMSI, MSISDN, IMEI, and temporary identities (GUTI, TMSI) across all protocols.

**Analysis Reference:**
Based on analysis of a production Python correlator, subscriber identities appear in various formats:
- MSISDN: `sip:+1234567890@domain`, `tel:+1234567890`, `01234567890`, `+11234567890`
- IMSI: 15 digits, sometimes with leading zeros
- IMEI: 14 digits (IMEI) or 16 digits (IMEISV)
- GUTI: MCC+MNC+MME Group ID+MME Code+M-TMSI

**3GPP References:**
- TS 23.003 (Numbering, Addressing and Identification)
- TS 23.008 (Organization of Subscriber Data)

---

## Requirements

### 1. MSISDN Normalization

Handle all MSISDN format variations found in telecom protocols:

```cpp
// Input formats to handle:
// SIP URI: "sip:+14155551234@ims.example.com;user=phone"
// SIP URI: "sip:14155551234@ims.example.com"
// TEL URI: "tel:+14155551234"
// TEL URI: "tel:+1-415-555-1234"
// National: "04155551234" (with leading zero)
// International: "+14155551234"
// Raw digits: "14155551234"
// With parameters: "+14155551234;npdi;rn=+14155550000"

// Output: normalized form for matching
// Example: "4155551234" (stripped leading zeros and country code for national matching)
// Also preserve: "14155551234" (international form for display)
```

### 2. IMSI Normalization

```cpp
// Input formats:
// Standard: "310260123456789" (15 digits)
// With prefix: "imsi-310260123456789"
// From Diameter: packed BCD in 3GPP-IMSI AVP
// From GTP: BCD encoded in IMSI IE
// From NAS: BCD encoded in Mobile Identity IE

// Output: "310260123456789" (always 15 digits)
// Also extract: MCC="310", MNC="260"
```

### 3. IMEI/IMEISV Normalization

```cpp
// Input formats:
// IMEI: "35123456789012" (14 digits)
// IMEISV: "3512345678901234" (16 digits)
// With prefix: "imei-35123456789012"
// With check digit: "351234567890120" (15 digits)

// Output: 
// IMEI: "35123456789012" (14 digits, no check digit)
// IMEISV: "3512345678901234" (16 digits)
// TAC (Type Allocation Code): "35123456" (first 8 digits)
```

### 4. GUTI/TMSI Structures

```cpp
// 4G GUTI structure:
// MCC (3 digits) + MNC (2-3 digits) + MME Group ID (16 bits) + MME Code (8 bits) + M-TMSI (32 bits)

// 5G-GUTI structure:
// MCC (3 digits) + MNC (2-3 digits) + AMF Region ID (8 bits) + AMF Set ID (10 bits) + AMF Pointer (6 bits) + 5G-TMSI (32 bits)
```

---

## Implementation

### File Structure

```
include/correlation/
├── identity/
│   ├── subscriber_identity.h      // Core identity structures
│   ├── msisdn_normalizer.h        // MSISDN parsing and normalization
│   ├── imsi_normalizer.h          // IMSI parsing and normalization
│   ├── imei_normalizer.h          // IMEI/IMEISV parsing
│   ├── guti_parser.h              // GUTI/5G-GUTI parsing
│   └── identity_matcher.h         // Identity matching algorithms

src/correlation/identity/
├── subscriber_identity.cpp
├── msisdn_normalizer.cpp
├── imsi_normalizer.cpp
├── imei_normalizer.cpp
├── guti_parser.cpp
└── identity_matcher.cpp

tests/unit/identity/
├── test_msisdn_normalizer.cpp
├── test_imsi_normalizer.cpp
├── test_imei_normalizer.cpp
├── test_guti_parser.cpp
└── test_identity_matcher.cpp
```

### Core Header: subscriber_identity.h

```cpp
#pragma once

#include <string>
#include <optional>
#include <vector>
#include <unordered_map>
#include <chrono>

namespace callflow {
namespace correlation {

/**
 * @brief Normalized MSISDN with multiple representations
 */
struct NormalizedMsisdn {
    std::string raw;              // Original input
    std::string digits_only;      // All digits extracted
    std::string national;         // Without country code, leading zeros stripped
    std::string international;    // With country code (E.164)
    std::string country_code;     // Detected country code
    
    bool operator==(const NormalizedMsisdn& other) const;
    bool matches(const NormalizedMsisdn& other) const;  // Fuzzy matching
};

/**
 * @brief Normalized IMSI with PLMN extraction
 */
struct NormalizedImsi {
    std::string raw;              // Original input
    std::string digits;           // 15-digit IMSI
    std::string mcc;              // Mobile Country Code (3 digits)
    std::string mnc;              // Mobile Network Code (2-3 digits)
    std::string msin;             // Mobile Subscriber Identification Number
    
    bool operator==(const NormalizedImsi& other) const;
    std::string getPlmn() const;  // MCC + MNC
};

/**
 * @brief Normalized IMEI/IMEISV
 */
struct NormalizedImei {
    std::string raw;              // Original input
    std::string imei;             // 14-digit IMEI
    std::optional<std::string> imeisv;  // 16-digit IMEISV if available
    std::string tac;              // Type Allocation Code (8 digits)
    std::string snr;              // Serial Number (6 digits)
    
    bool operator==(const NormalizedImei& other) const;
};

/**
 * @brief 4G GUTI structure
 */
struct Guti4G {
    std::string mcc;              // 3 digits
    std::string mnc;              // 2-3 digits
    uint16_t mme_group_id;
    uint8_t mme_code;
    uint32_t m_tmsi;
    
    std::string toString() const;
    static std::optional<Guti4G> parse(const uint8_t* data, size_t length);
};

/**
 * @brief 5G-GUTI structure  
 */
struct Guti5G {
    std::string mcc;              // 3 digits
    std::string mnc;              // 2-3 digits
    uint8_t amf_region_id;
    uint16_t amf_set_id;          // 10 bits
    uint8_t amf_pointer;          // 6 bits
    uint32_t fiveG_tmsi;
    
    std::string toString() const;
    static std::optional<Guti5G> parse(const uint8_t* data, size_t length);
};

/**
 * @brief Network endpoint information
 */
struct NetworkEndpoint {
    std::string ipv4;
    std::string ipv6;
    uint16_t port = 0;
    
    // GTP-U tunnel info
    std::optional<std::string> gtpu_peer_ip;
    std::optional<uint32_t> gtpu_teid;
    
    bool hasIpv4() const { return !ipv4.empty(); }
    bool hasIpv6() const { return !ipv6.empty(); }
    std::string getIpv6Prefix(int prefix_len = 64) const;
    bool matchesIp(const std::string& ip) const;
    bool matchesIpPrefix(const std::string& prefix) const;
};

/**
 * @brief Complete subscriber identity container
 */
struct SubscriberIdentity {
    // Primary identifiers
    std::optional<NormalizedImsi> imsi;
    std::optional<NormalizedMsisdn> msisdn;
    std::optional<NormalizedImei> imei;
    
    // Temporary identifiers (4G)
    std::optional<Guti4G> guti;
    std::optional<uint32_t> tmsi;
    std::optional<uint32_t> p_tmsi;
    
    // Temporary identifiers (5G)
    std::optional<Guti5G> guti_5g;
    std::optional<uint32_t> tmsi_5g;
    
    // Network endpoints associated with this subscriber
    std::vector<NetworkEndpoint> endpoints;
    
    // APN/DNN information
    std::string apn;
    std::string pdn_type;  // "ipv4", "ipv6", "ipv4v6"
    
    // Confidence scores (0.0 to 1.0)
    std::unordered_map<std::string, float> confidence;
    
    // Timestamps
    std::chrono::steady_clock::time_point first_seen;
    std::chrono::steady_clock::time_point last_seen;
    
    // Methods
    bool hasImsi() const { return imsi.has_value(); }
    bool hasMsisdn() const { return msisdn.has_value(); }
    bool hasImei() const { return imei.has_value(); }
    
    bool matches(const SubscriberIdentity& other) const;
    void merge(const SubscriberIdentity& other);
    
    std::string getPrimaryKey() const;  // Best available identifier
};

/**
 * @brief Identity source tracking
 */
enum class IdentitySource {
    SIP_FROM_HEADER,
    SIP_TO_HEADER,
    SIP_PAI_HEADER,
    SIP_PPI_HEADER,
    SIP_CONTACT_HEADER,
    DIAMETER_USER_NAME,
    DIAMETER_3GPP_IMSI,
    DIAMETER_PUBLIC_IDENTITY,
    DIAMETER_FRAMED_IP,
    GTP_IMSI_IE,
    GTP_MSISDN_IE,
    GTP_MEI_IE,
    GTP_PDN_ADDRESS,
    GTP_FTEID,
    NAS_MOBILE_IDENTITY,
    NAS_GUTI,
    S1AP_NAS_PDU,
    UNKNOWN
};

} // namespace correlation
} // namespace callflow
```

### MSISDN Normalizer: msisdn_normalizer.h

```cpp
#pragma once

#include "subscriber_identity.h"
#include <regex>

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
```

### MSISDN Normalizer Implementation: msisdn_normalizer.cpp

```cpp
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
    // Add more as needed
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
    bool has_plus = (working.find('+') != std::string::npos);
    
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
```

---

## Testing Requirements

Create comprehensive unit tests:

```cpp
// tests/unit/identity/test_msisdn_normalizer.cpp

#include <gtest/gtest.h>
#include "correlation/identity/msisdn_normalizer.h"

using namespace callflow::correlation;

class MsisdnNormalizerTest : public ::testing::Test {};

TEST_F(MsisdnNormalizerTest, NormalizeSipUri) {
    auto result = MsisdnNormalizer::normalize("sip:+14155551234@ims.example.com;user=phone");
    EXPECT_EQ(result.digits_only, "14155551234");
    EXPECT_EQ(result.national, "4155551234");
    EXPECT_EQ(result.country_code, "1");
}

TEST_F(MsisdnNormalizerTest, NormalizeTelUri) {
    auto result = MsisdnNormalizer::normalize("tel:+1-415-555-1234");
    EXPECT_EQ(result.digits_only, "14155551234");
    EXPECT_EQ(result.national, "4155551234");
}

TEST_F(MsisdnNormalizerTest, NormalizeNationalFormat) {
    auto result = MsisdnNormalizer::normalize("04155551234");
    EXPECT_EQ(result.national, "4155551234");
}

TEST_F(MsisdnNormalizerTest, MatchingSameNumber) {
    auto m1 = MsisdnNormalizer::normalize("sip:+14155551234@domain");
    auto m2 = MsisdnNormalizer::normalize("tel:+1-415-555-1234");
    EXPECT_TRUE(MsisdnNormalizer::matches(m1, m2));
}

TEST_F(MsisdnNormalizerTest, MatchingNationalInternational) {
    auto m1 = MsisdnNormalizer::normalize("+14155551234");
    auto m2 = MsisdnNormalizer::normalize("04155551234");
    EXPECT_TRUE(MsisdnNormalizer::matches(m1, m2));
}

TEST_F(MsisdnNormalizerTest, NoMatchDifferentNumbers) {
    auto m1 = MsisdnNormalizer::normalize("+14155551234");
    auto m2 = MsisdnNormalizer::normalize("+14155559999");
    EXPECT_FALSE(MsisdnNormalizer::matches(m1, m2));
}

TEST_F(MsisdnNormalizerTest, HandleComplexSipUri) {
    auto result = MsisdnNormalizer::normalize(
        "sip:+14155551234;npdi;rn=+14155550000@ims.example.com;user=phone");
    EXPECT_EQ(result.digits_only, "14155551234");
}

TEST_F(MsisdnNormalizerTest, HandleTurkishNumber) {
    auto result = MsisdnNormalizer::normalize("sip:+905321234567@domain");
    EXPECT_EQ(result.digits_only, "905321234567");
    EXPECT_EQ(result.country_code, "90");
    EXPECT_EQ(result.national, "5321234567");
}
```

---

## Success Criteria

- [ ] MSISDN normalizer handles all SIP URI formats
- [ ] MSISDN normalizer handles all TEL URI formats
- [ ] MSISDN matching works for national vs international
- [ ] IMSI normalizer extracts MCC/MNC correctly
- [ ] IMEI normalizer extracts TAC correctly
- [ ] GUTI parser handles 4G and 5G formats
- [ ] Unit test coverage > 90%
- [ ] All tests passing

---

## Deliverables

1. `subscriber_identity.h` - Core identity structures
2. `msisdn_normalizer.h/.cpp` - MSISDN parsing and matching
3. `imsi_normalizer.h/.cpp` - IMSI parsing
4. `imei_normalizer.h/.cpp` - IMEI/IMEISV parsing
5. `guti_parser.h/.cpp` - GUTI/5G-GUTI parsing
6. Unit tests for all normalizers
7. Documentation with format examples
```

---

## PROMPT 1.2: Subscriber Context Manager

```markdown
# Subscriber Context Manager
## nDPI Callflow Visualizer - Identity Tracking Across Protocols

**Context:**
Continuing from Prompt 1.1, I now need to implement the Subscriber Context Manager that maintains a unified view of each subscriber across all protocol messages. This component links IMSI ↔ MSISDN ↔ IMEI and tracks UE IP addresses.

**Key Insight from Python Analysis:**
The production correlator uses a "forward-fill/backward-fill" approach to propagate identifiers:
- If IMSI is seen in GTPv2 and MSISDN in SIP for the same session, link them
- If UE IP is seen in both, use it to correlate
- Build a unified subscriber profile across the PCAP

---

## Requirements

### 1. Subscriber Context Storage

```cpp
// Key requirements:
// - Fast lookup by any identifier (IMSI, MSISDN, IMEI, UE IP)
// - Automatic merging of contexts when new links discovered
// - Track which protocols contributed which identifiers
// - Support multiple UE IPs per subscriber (default + IMS bearers)
```

### 2. Identity Propagation

```cpp
// Propagation rules from Python correlator:
// Rule 1: IMSI → MSISDN (if same GTP/Diameter session)
// Rule 2: MSISDN → IMSI (if same GTP/Diameter session)
// Rule 3: UE_IPv4 → (MSISDN, IMSI, IMEI, APN)
// Rule 4: UE_IPv6_prefix → (MSISDN, IMSI, IMEI, APN)
// Rule 5: GTP-U TEID → (MSISDN, IMSI, IMEI)
// Rule 6: (IMEI, 4G_TMSI) → (MSISDN, IMSI) for S1AP/NAS-EPS
// Rule 7: Intra-protocol correlator → (MSISDN, IMSI, IMEI) except for CALL sessions
```

---

## Implementation

### subscriber_context_manager.h

```cpp
#pragma once

#include "correlation/identity/subscriber_identity.h"
#include <unordered_map>
#include <shared_mutex>
#include <memory>
#include <functional>

namespace callflow {
namespace correlation {

/**
 * @brief Manages subscriber contexts across all protocols
 * 
 * Maintains a unified view of subscriber identities, handling:
 * - Multi-key lookup (IMSI, MSISDN, IMEI, IP)
 * - Context merging when new links discovered
 * - Identity propagation across protocols
 */
class SubscriberContextManager {
public:
    using ContextPtr = std::shared_ptr<SubscriberIdentity>;
    using ContextCallback = std::function<void(ContextPtr)>;
    
    SubscriberContextManager() = default;
    ~SubscriberContextManager() = default;
    
    // Non-copyable
    SubscriberContextManager(const SubscriberContextManager&) = delete;
    SubscriberContextManager& operator=(const SubscriberContextManager&) = delete;
    
    /**
     * @brief Get or create subscriber context by IMSI
     */
    ContextPtr getOrCreateByImsi(const std::string& imsi);
    
    /**
     * @brief Get or create subscriber context by MSISDN
     */
    ContextPtr getOrCreateByMsisdn(const std::string& msisdn);
    
    /**
     * @brief Get or create subscriber context by IMEI
     */
    ContextPtr getOrCreateByImei(const std::string& imei);
    
    /**
     * @brief Get or create subscriber context by UE IP address
     */
    ContextPtr getOrCreateByUeIp(const std::string& ip);
    
    /**
     * @brief Find subscriber context by any identifier
     * @return nullptr if not found
     */
    ContextPtr findByImsi(const std::string& imsi) const;
    ContextPtr findByMsisdn(const std::string& msisdn) const;
    ContextPtr findByImei(const std::string& imei) const;
    ContextPtr findByUeIp(const std::string& ip) const;
    ContextPtr findByGuti(const Guti4G& guti) const;
    ContextPtr findByTmsi(uint32_t tmsi) const;
    
    /**
     * @brief Link two identifiers together
     * If both exist in different contexts, merge them
     */
    void linkImsiMsisdn(const std::string& imsi, const std::string& msisdn);
    void linkImsiImei(const std::string& imsi, const std::string& imei);
    void linkMsisdnUeIp(const std::string& msisdn, const std::string& ip);
    void linkImsiUeIp(const std::string& imsi, const std::string& ip);
    void linkImsiGuti(const std::string& imsi, const Guti4G& guti);
    void linkImsiTmsi(const std::string& imsi, uint32_t tmsi);
    
    /**
     * @brief Add GTP-U tunnel info to subscriber
     */
    void addGtpuTunnel(const std::string& imsi_or_msisdn, 
                       const std::string& peer_ip, 
                       uint32_t teid);
    
    /**
     * @brief Run identity propagation algorithm
     * Propagates identifiers across linked contexts
     */
    void propagateIdentities();
    
    /**
     * @brief Get all subscriber contexts
     */
    std::vector<ContextPtr> getAllContexts() const;
    
    /**
     * @brief Get statistics
     */
    struct Stats {
        size_t total_contexts;
        size_t contexts_with_imsi;
        size_t contexts_with_msisdn;
        size_t contexts_with_imei;
        size_t contexts_with_ue_ip;
        size_t merge_operations;
    };
    Stats getStats() const;
    
    /**
     * @brief Clear all contexts
     */
    void clear();

private:
    mutable std::shared_mutex mutex_;
    
    // Primary storage - all contexts
    std::vector<ContextPtr> contexts_;
    
    // Index maps for fast lookup
    std::unordered_map<std::string, ContextPtr> imsi_index_;      // IMSI -> Context
    std::unordered_map<std::string, ContextPtr> msisdn_index_;    // Normalized MSISDN -> Context
    std::unordered_map<std::string, ContextPtr> imei_index_;      // IMEI -> Context
    std::unordered_map<std::string, ContextPtr> ip_index_;        // UE IP -> Context
    std::unordered_map<uint32_t, ContextPtr> tmsi_index_;         // TMSI -> Context
    
    // Statistics
    mutable Stats stats_{};
    
    // Internal methods
    ContextPtr createContext();
    void mergeContexts(ContextPtr primary, ContextPtr secondary);
    void updateIndices(ContextPtr context);
    void removeFromIndices(ContextPtr context);
    
    std::string normalizeForIndex(const std::string& msisdn) const;
};

/**
 * @brief Builder for updating subscriber context from protocol messages
 */
class SubscriberContextBuilder {
public:
    explicit SubscriberContextBuilder(SubscriberContextManager& manager);
    
    // From SIP message
    SubscriberContextBuilder& fromSipFrom(const std::string& from_uri);
    SubscriberContextBuilder& fromSipTo(const std::string& to_uri);
    SubscriberContextBuilder& fromSipPai(const std::string& pai);
    SubscriberContextBuilder& fromSipContact(const std::string& contact, 
                                              const std::string& ip);
    
    // From Diameter message
    SubscriberContextBuilder& fromDiameterImsi(const std::string& imsi);
    SubscriberContextBuilder& fromDiameterMsisdn(const std::string& msisdn);
    SubscriberContextBuilder& fromDiameterFramedIp(const std::string& ip);
    SubscriberContextBuilder& fromDiameterPublicIdentity(const std::string& pub_id);
    
    // From GTPv2 message
    SubscriberContextBuilder& fromGtpImsi(const std::string& imsi);
    SubscriberContextBuilder& fromGtpMsisdn(const std::string& msisdn);
    SubscriberContextBuilder& fromGtpMei(const std::string& mei);
    SubscriberContextBuilder& fromGtpPdnAddress(const std::string& ip);
    SubscriberContextBuilder& fromGtpFteid(const std::string& ip, uint32_t teid);
    SubscriberContextBuilder& fromGtpApn(const std::string& apn);
    
    // From NAS message
    SubscriberContextBuilder& fromNasImsi(const std::string& imsi);
    SubscriberContextBuilder& fromNasImei(const std::string& imei);
    SubscriberContextBuilder& fromNasGuti(const Guti4G& guti);
    SubscriberContextBuilder& fromNasTmsi(uint32_t tmsi);
    
    // Build and get context
    SubscriberContextManager::ContextPtr build();
    
private:
    SubscriberContextManager& manager_;
    
    std::optional<std::string> imsi_;
    std::optional<std::string> msisdn_;
    std::optional<std::string> imei_;
    std::optional<std::string> ue_ip_;
    std::optional<Guti4G> guti_;
    std::optional<uint32_t> tmsi_;
    std::optional<std::string> apn_;
    std::vector<std::pair<std::string, uint32_t>> gtp_tunnels_;
};

} // namespace correlation
} // namespace callflow
```

### subscriber_context_manager.cpp

```cpp
#include "correlation/identity/subscriber_context_manager.h"
#include "correlation/identity/msisdn_normalizer.h"
#include <algorithm>

namespace callflow {
namespace correlation {

SubscriberContextManager::ContextPtr 
SubscriberContextManager::getOrCreateByImsi(const std::string& imsi) {
    std::unique_lock lock(mutex_);
    
    auto it = imsi_index_.find(imsi);
    if (it != imsi_index_.end()) {
        return it->second;
    }
    
    auto context = createContext();
    context->imsi = NormalizedImsi{imsi, imsi, "", "", ""};  // TODO: Full parsing
    imsi_index_[imsi] = context;
    return context;
}

SubscriberContextManager::ContextPtr 
SubscriberContextManager::getOrCreateByMsisdn(const std::string& msisdn) {
    std::unique_lock lock(mutex_);
    
    std::string normalized = normalizeForIndex(msisdn);
    auto it = msisdn_index_.find(normalized);
    if (it != msisdn_index_.end()) {
        return it->second;
    }
    
    auto context = createContext();
    context->msisdn = MsisdnNormalizer::normalize(msisdn);
    msisdn_index_[normalized] = context;
    return context;
}

SubscriberContextManager::ContextPtr 
SubscriberContextManager::getOrCreateByUeIp(const std::string& ip) {
    std::unique_lock lock(mutex_);
    
    auto it = ip_index_.find(ip);
    if (it != ip_index_.end()) {
        return it->second;
    }
    
    auto context = createContext();
    NetworkEndpoint endpoint;
    if (ip.find(':') != std::string::npos) {
        endpoint.ipv6 = ip;
    } else {
        endpoint.ipv4 = ip;
    }
    context->endpoints.push_back(endpoint);
    ip_index_[ip] = context;
    return context;
}

void SubscriberContextManager::linkImsiMsisdn(const std::string& imsi, 
                                               const std::string& msisdn) {
    std::unique_lock lock(mutex_);
    
    auto imsi_ctx = findByImsi(imsi);
    std::string normalized_msisdn = normalizeForIndex(msisdn);
    auto msisdn_ctx = findByMsisdn(msisdn);
    
    if (imsi_ctx && msisdn_ctx) {
        if (imsi_ctx != msisdn_ctx) {
            // Different contexts - need to merge
            mergeContexts(imsi_ctx, msisdn_ctx);
        }
    } else if (imsi_ctx && !msisdn_ctx) {
        // Add MSISDN to existing IMSI context
        imsi_ctx->msisdn = MsisdnNormalizer::normalize(msisdn);
        msisdn_index_[normalized_msisdn] = imsi_ctx;
    } else if (!imsi_ctx && msisdn_ctx) {
        // Add IMSI to existing MSISDN context
        msisdn_ctx->imsi = NormalizedImsi{imsi, imsi, "", "", ""};
        imsi_index_[imsi] = msisdn_ctx;
    } else {
        // Create new context with both
        auto context = createContext();
        context->imsi = NormalizedImsi{imsi, imsi, "", "", ""};
        context->msisdn = MsisdnNormalizer::normalize(msisdn);
        imsi_index_[imsi] = context;
        msisdn_index_[normalized_msisdn] = context;
    }
}

void SubscriberContextManager::mergeContexts(ContextPtr primary, 
                                              ContextPtr secondary) {
    // Merge identifiers from secondary into primary
    if (!primary->imsi && secondary->imsi) {
        primary->imsi = secondary->imsi;
    }
    if (!primary->msisdn && secondary->msisdn) {
        primary->msisdn = secondary->msisdn;
    }
    if (!primary->imei && secondary->imei) {
        primary->imei = secondary->imei;
    }
    if (!primary->guti && secondary->guti) {
        primary->guti = secondary->guti;
    }
    if (!primary->tmsi && secondary->tmsi) {
        primary->tmsi = secondary->tmsi;
    }
    
    // Merge endpoints
    for (const auto& ep : secondary->endpoints) {
        primary->endpoints.push_back(ep);
    }
    
    // Merge confidence scores
    for (const auto& [key, score] : secondary->confidence) {
        if (primary->confidence.find(key) == primary->confidence.end() ||
            primary->confidence[key] < score) {
            primary->confidence[key] = score;
        }
    }
    
    // Update all indices to point to primary
    updateIndices(primary);
    
    // Remove secondary from contexts list
    contexts_.erase(
        std::remove(contexts_.begin(), contexts_.end(), secondary),
        contexts_.end());
    
    stats_.merge_operations++;
}

void SubscriberContextManager::propagateIdentities() {
    std::unique_lock lock(mutex_);
    
    // Build IP to context mapping for fast lookup
    std::unordered_map<std::string, std::vector<ContextPtr>> ip_to_contexts;
    
    for (const auto& ctx : contexts_) {
        for (const auto& ep : ctx->endpoints) {
            if (!ep.ipv4.empty()) {
                ip_to_contexts[ep.ipv4].push_back(ctx);
            }
            if (!ep.ipv6.empty()) {
                ip_to_contexts[ep.ipv6].push_back(ctx);
                // Also index by prefix
                std::string prefix = ep.getIpv6Prefix(64);
                if (!prefix.empty()) {
                    ip_to_contexts[prefix].push_back(ctx);
                }
            }
        }
    }
    
    // Link contexts that share IP addresses
    for (const auto& [ip, ctxs] : ip_to_contexts) {
        if (ctxs.size() > 1) {
            auto primary = ctxs[0];
            for (size_t i = 1; i < ctxs.size(); i++) {
                if (primary != ctxs[i]) {
                    mergeContexts(primary, ctxs[i]);
                }
            }
        }
    }
    
    // Propagate IMSI → MSISDN and vice versa
    for (const auto& ctx : contexts_) {
        if (ctx->imsi && !ctx->msisdn) {
            // Look for MSISDN in other contexts with same IMSI
            // (This would come from Diameter/GTP linking)
        }
        if (ctx->msisdn && !ctx->imsi) {
            // Look for IMSI in other contexts with same MSISDN
        }
    }
}

SubscriberContextManager::ContextPtr SubscriberContextManager::createContext() {
    auto context = std::make_shared<SubscriberIdentity>();
    context->first_seen = std::chrono::steady_clock::now();
    context->last_seen = context->first_seen;
    contexts_.push_back(context);
    stats_.total_contexts++;
    return context;
}

std::string SubscriberContextManager::normalizeForIndex(
    const std::string& msisdn) const {
    auto normalized = MsisdnNormalizer::normalize(msisdn);
    return normalized.national;  // Use national form for indexing
}

void SubscriberContextManager::updateIndices(ContextPtr context) {
    if (context->imsi) {
        imsi_index_[context->imsi->digits] = context;
    }
    if (context->msisdn) {
        msisdn_index_[context->msisdn->national] = context;
    }
    if (context->imei) {
        imei_index_[context->imei->imei] = context;
    }
    if (context->tmsi) {
        tmsi_index_[*context->tmsi] = context;
    }
    for (const auto& ep : context->endpoints) {
        if (!ep.ipv4.empty()) {
            ip_index_[ep.ipv4] = context;
        }
        if (!ep.ipv6.empty()) {
            ip_index_[ep.ipv6] = context;
        }
    }
}

} // namespace correlation
} // namespace callflow
```

---

## Success Criteria

- [ ] Fast O(1) lookup by any identifier
- [ ] Automatic context merging when links discovered
- [ ] Identity propagation algorithm works correctly
- [ ] Thread-safe operations
- [ ] Memory efficient (shared pointers)
- [ ] Unit test coverage > 85%
```

---

# Milestone 2: SIP Intra-Protocol Correlator (2 weeks)

## PROMPT 2.1: SIP Session Detection and Dialog Tracking

```markdown
# SIP Intra-Protocol Correlator
## nDPI Callflow Visualizer - SIP Call Detection and Dialog Tracking

**Context:**
I'm building the nDPI Callflow Visualizer. This prompt implements the SIP intra-protocol correlator that groups SIP messages into sessions, detects call types (registration, voice call, SMS, etc.), and tracks dialogs.

**Analysis Reference:**
The Python SIP parser (sip_dt.py, 8610 lines) handles:
- Session detection by Call-ID
- Dialog tracking by From-tag + To-tag
- Transaction tracking by CSeq + Branch
- MO/MT detection via Via header analysis
- Call party extraction from PAI/PPI/From/To headers
- Subsession types: registration, call, message, subscribe_notify

**3GPP References:**
- RFC 3261 (SIP: Session Initiation Protocol)
- TS 24.229 (IMS SIP/SDP)
- RFC 3665 (SIP Basic Call Flow Examples)

---

## Requirements

### 1. SIP Session Types

```cpp
enum class SipSessionType {
    REGISTRATION,           // REGISTER with expires > 0
    DEREGISTRATION,         // REGISTER with expires = 0
    THIRD_PARTY_REG,        // Third-party registration (TAS)
    VOICE_CALL,             // INVITE for audio
    VIDEO_CALL,             // INVITE for audio+video
    EMERGENCY_CALL,         // INVITE to emergency URN
    SMS_MESSAGE,            // MESSAGE method
    SUBSCRIBE_NOTIFY,       // SUBSCRIBE/NOTIFY
    OPTIONS,                // OPTIONS (keepalive)
    REFER,                  // Call transfer
    INFO,                   // Mid-call INFO (DTMF, etc.)
    UNKNOWN
};
```

### 2. Dialog State Machine

```cpp
enum class SipDialogState {
    INIT,           // Initial state
    CALLING,        // INVITE sent
    PROCEEDING,     // 1xx received
    EARLY,          // 1xx with To-tag (early dialog)
    CONFIRMED,      // 2xx received
    TERMINATED      // BYE or error response
};
```

### 3. Call Party Detection

```cpp
// Detect caller (UEa), callee (UEb), forwarding target (UEc)
// From headers: From, P-Asserted-Identity, P-Preferred-Identity
// Detect MO vs MT based on:
//   - Via header count (MO has more Vias on outbound)
//   - Network element positions (P-CSCF, S-CSCF, etc.)
```

---

## Implementation

### File Structure

```
include/correlation/sip/
├── sip_types.h              // Enums and basic structures
├── sip_session.h            // SIP session container
├── sip_dialog.h             // SIP dialog tracking
├── sip_transaction.h        // SIP transaction (CSeq+Branch)
├── sip_correlator.h         // Main SIP correlator
└── sip_call_detector.h      // Call type detection logic

src/correlation/sip/
├── sip_session.cpp
├── sip_dialog.cpp
├── sip_transaction.cpp
├── sip_correlator.cpp
└── sip_call_detector.cpp

tests/unit/sip/
├── test_sip_dialog.cpp
├── test_sip_transaction.cpp
├── test_sip_correlator.cpp
└── test_sip_call_detector.cpp
```

### sip_types.h

```cpp
#pragma once

#include <string>
#include <vector>
#include <optional>
#include <chrono>
#include <cstdint>

namespace callflow {
namespace correlation {

enum class SipSessionType {
    REGISTRATION,
    DEREGISTRATION,
    THIRD_PARTY_REG,
    VOICE_CALL,
    VIDEO_CALL,
    EMERGENCY_CALL,
    SMS_MESSAGE,
    SUBSCRIBE_NOTIFY,
    OPTIONS,
    REFER,
    INFO,
    UNKNOWN
};

enum class SipDialogState {
    INIT,
    CALLING,
    PROCEEDING,
    EARLY,
    CONFIRMED,
    TERMINATED
};

enum class SipCallParty {
    CALLER_MO,          // Mobile Originating party (UEa)
    CALLEE_MT,          // Mobile Terminating party (UEb)
    FORWARD_TARGET,     // Call forwarding target (UEc)
    NETWORK_ELEMENT     // IMS network element
};

enum class SipDirection {
    ORIGINATING,        // From UE towards network
    TERMINATING,        // From network towards UE
    NETWORK_INTERNAL    // Between network elements
};

struct SipMediaInfo {
    std::string media_type;     // "audio", "video"
    std::string connection_ip;
    uint16_t port;
    std::string direction;      // "sendrecv", "sendonly", "recvonly", "inactive"
    std::vector<std::string> codecs;
};

struct SipViaHeader {
    std::string protocol;       // "SIP/2.0/UDP", "SIP/2.0/TCP"
    std::string sent_by;        // IP:port
    std::string branch;
    std::optional<std::string> received;
    std::optional<uint16_t> rport;
    int index;                  // Position in Via stack (0 = topmost)
};

struct SipContactHeader {
    std::string uri;
    std::string user;
    std::string host;
    std::optional<int> expires;
    std::optional<std::string> instance;
    std::optional<std::string> pub_gruu;
};

std::string sipSessionTypeToString(SipSessionType type);
std::string sipDialogStateToString(SipDialogState state);

} // namespace correlation
} // namespace callflow
```

### sip_session.h

```cpp
#pragma once

#include "correlation/sip/sip_types.h"
#include "correlation/sip/sip_dialog.h"
#include "correlation/identity/subscriber_identity.h"
#include <vector>
#include <memory>
#include <unordered_map>

namespace callflow {
namespace correlation {

// Forward declarations
class SipMessage;
class SipTransaction;

/**
 * @brief Represents a complete SIP session
 * 
 * A session is identified by Call-ID and contains:
 * - One or more dialogs (for forking scenarios)
 * - Transactions within each dialog
 * - Extracted call party information
 */
class SipSession {
public:
    SipSession(const std::string& call_id);
    ~SipSession() = default;
    
    // Session identification
    std::string getCallId() const { return call_id_; }
    std::string getSessionId() const { return session_id_; }
    SipSessionType getType() const { return type_; }
    
    // Add message to session
    void addMessage(const SipMessage& msg);
    
    // Get messages
    const std::vector<SipMessage>& getMessages() const { return messages_; }
    size_t getMessageCount() const { return messages_.size(); }
    
    // Dialog management
    SipDialog* getOrCreateDialog(const std::string& from_tag, 
                                  const std::string& to_tag);
    SipDialog* findDialog(const std::string& from_tag, 
                          const std::string& to_tag) const;
    const std::vector<std::unique_ptr<SipDialog>>& getDialogs() const { 
        return dialogs_; 
    }
    
    // Call party information
    std::string getCallerMsisdn() const { return caller_msisdn_; }
    std::string getCalleeMsisdn() const { return callee_msisdn_; }
    std::optional<std::string> getForwardTargetMsisdn() const { 
        return forward_target_msisdn_; 
    }
    
    std::string getCallerIp() const { return caller_ip_; }
    std::string getCalleeIp() const { return callee_ip_; }
    
    // Time window
    double getStartTime() const { return start_time_; }
    double getEndTime() const { return end_time_; }
    uint32_t getStartFrame() const { return start_frame_; }
    uint32_t getEndFrame() const { return end_frame_; }
    
    // Media information
    const std::vector<SipMediaInfo>& getMediaInfo() const { return media_; }
    bool hasAudio() const;
    bool hasVideo() const;
    
    // Correlation IDs
    void setIntraCorrelator(const std::string& id) { intra_correlator_ = id; }
    std::string getIntraCorrelator() const { return intra_correlator_; }
    
    void setInterCorrelator(const std::string& id) { inter_correlator_ = id; }
    std::string getInterCorrelator() const { return inter_correlator_; }
    
    // Finalize session (detect type, extract parties, etc.)
    void finalize();

private:
    std::string call_id_;
    std::string session_id_;     // Generated: timestamp_S_sequence
    SipSessionType type_ = SipSessionType::UNKNOWN;
    
    std::vector<SipMessage> messages_;
    std::vector<std::unique_ptr<SipDialog>> dialogs_;
    
    // Call parties (normalized MSISDNs)
    std::string caller_msisdn_;
    std::string callee_msisdn_;
    std::optional<std::string> forward_target_msisdn_;
    
    // UE IP addresses (for cross-protocol correlation)
    std::string caller_ip_;
    std::string caller_ipv6_prefix_;
    std::string callee_ip_;
    std::string callee_ipv6_prefix_;
    
    // Media
    std::vector<SipMediaInfo> media_;
    
    // Time window
    double start_time_ = 0.0;
    double end_time_ = 0.0;
    uint32_t start_frame_ = 0;
    uint32_t end_frame_ = 0;
    
    // Correlation IDs
    std::string intra_correlator_;
    std::string inter_correlator_;
    
    // Internal methods
    void detectSessionType();
    void extractCallParties();
    void extractMediaInfo();
    void extractUeIpAddresses();
    void updateTimeWindow(const SipMessage& msg);
    
    std::string extractMsisdnFromHeader(const std::string& header_value);
};

} // namespace correlation
} // namespace callflow
```

### sip_correlator.h

```cpp
#pragma once

#include "correlation/sip/sip_session.h"
#include "correlation/identity/subscriber_context_manager.h"
#include <unordered_map>
#include <memory>
#include <mutex>

namespace callflow {
namespace correlation {

/**
 * @brief SIP intra-protocol correlator
 * 
 * Groups SIP messages into sessions based on Call-ID,
 * detects session types, and extracts call party information.
 */
class SipCorrelator {
public:
    SipCorrelator();
    explicit SipCorrelator(SubscriberContextManager* ctx_manager);
    ~SipCorrelator() = default;
    
    /**
     * @brief Add a parsed SIP message
     */
    void addMessage(const SipMessage& msg);
    
    /**
     * @brief Finalize all sessions (call after all messages added)
     */
    void finalize();
    
    /**
     * @brief Get all sessions
     */
    std::vector<SipSession*> getSessions();
    
    /**
     * @brief Get sessions of specific type
     */
    std::vector<SipSession*> getSessionsByType(SipSessionType type);
    
    /**
     * @brief Get voice/video call sessions only
     */
    std::vector<SipSession*> getCallSessions();
    
    /**
     * @brief Find session by Call-ID
     */
    SipSession* findByCallId(const std::string& call_id);
    
    /**
     * @brief Find sessions by MSISDN (caller or callee)
     */
    std::vector<SipSession*> findByMsisdn(const std::string& msisdn);
    
    /**
     * @brief Get session by frame number
     */
    SipSession* findByFrame(uint32_t frame_number);
    
    /**
     * @brief Get statistics
     */
    struct Stats {
        size_t total_messages = 0;
        size_t total_sessions = 0;
        size_t registration_sessions = 0;
        size_t voice_call_sessions = 0;
        size_t video_call_sessions = 0;
        size_t sms_sessions = 0;
        size_t other_sessions = 0;
    };
    Stats getStats() const;
    
    /**
     * @brief Clear all sessions
     */
    void clear();

private:
    std::mutex mutex_;
    std::unordered_map<std::string, std::unique_ptr<SipSession>> sessions_;
    // Key: Call-ID
    
    SubscriberContextManager* ctx_manager_ = nullptr;
    
    int session_sequence_ = 0;
    Stats stats_;
    
    std::string generateSessionId(double timestamp);
    void updateSubscriberContext(const SipSession& session);
};

} // namespace correlation
} // namespace callflow
```

### sip_correlator.cpp (Key Implementation)

```cpp
#include "correlation/sip/sip_correlator.h"
#include "correlation/identity/msisdn_normalizer.h"
#include <algorithm>

namespace callflow {
namespace correlation {

SipCorrelator::SipCorrelator() = default;

SipCorrelator::SipCorrelator(SubscriberContextManager* ctx_manager)
    : ctx_manager_(ctx_manager) {}

void SipCorrelator::addMessage(const SipMessage& msg) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    const std::string& call_id = msg.getCallId();
    if (call_id.empty()) {
        return;  // Invalid SIP message
    }
    
    // Get or create session
    auto it = sessions_.find(call_id);
    if (it == sessions_.end()) {
        auto session = std::make_unique<SipSession>(call_id);
        session->setIntraCorrelator(generateSessionId(msg.getTimestamp()));
        sessions_[call_id] = std::move(session);
        it = sessions_.find(call_id);
    }
    
    it->second->addMessage(msg);
    stats_.total_messages++;
}

void SipCorrelator::finalize() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (auto& [call_id, session] : sessions_) {
        session->finalize();
        
        // Update statistics
        stats_.total_sessions++;
        switch (session->getType()) {
            case SipSessionType::REGISTRATION:
            case SipSessionType::DEREGISTRATION:
            case SipSessionType::THIRD_PARTY_REG:
                stats_.registration_sessions++;
                break;
            case SipSessionType::VOICE_CALL:
                stats_.voice_call_sessions++;
                break;
            case SipSessionType::VIDEO_CALL:
                stats_.video_call_sessions++;
                break;
            case SipSessionType::SMS_MESSAGE:
                stats_.sms_sessions++;
                break;
            default:
                stats_.other_sessions++;
                break;
        }
        
        // Update subscriber context if available
        if (ctx_manager_) {
            updateSubscriberContext(*session);
        }
    }
}

std::vector<SipSession*> SipCorrelator::getCallSessions() {
    std::vector<SipSession*> result;
    
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [call_id, session] : sessions_) {
        SipSessionType type = session->getType();
        if (type == SipSessionType::VOICE_CALL || 
            type == SipSessionType::VIDEO_CALL ||
            type == SipSessionType::EMERGENCY_CALL) {
            result.push_back(session.get());
        }
    }
    
    // Sort by start time
    std::sort(result.begin(), result.end(),
        [](SipSession* a, SipSession* b) {
            return a->getStartTime() < b->getStartTime();
        });
    
    return result;
}

std::vector<SipSession*> SipCorrelator::findByMsisdn(const std::string& msisdn) {
    std::vector<SipSession*> result;
    auto normalized = MsisdnNormalizer::normalize(msisdn);
    
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [call_id, session] : sessions_) {
        auto caller = MsisdnNormalizer::normalize(session->getCallerMsisdn());
        auto callee = MsisdnNormalizer::normalize(session->getCalleeMsisdn());
        
        if (MsisdnNormalizer::matches(normalized, caller) ||
            MsisdnNormalizer::matches(normalized, callee)) {
            result.push_back(session.get());
        }
    }
    
    return result;
}

std::string SipCorrelator::generateSessionId(double timestamp) {
    // Format: timestamp_S_sequence (e.g., "1702396800.123_S_1")
    session_sequence_++;
    return std::to_string(timestamp) + "_S_" + std::to_string(session_sequence_);
}

void SipCorrelator::updateSubscriberContext(const SipSession& session) {
    // Update caller context
    if (!session.getCallerMsisdn().empty()) {
        auto ctx = ctx_manager_->getOrCreateByMsisdn(session.getCallerMsisdn());
        if (!session.getCallerIp().empty()) {
            NetworkEndpoint ep;
            ep.ipv4 = session.getCallerIp();
            ctx->endpoints.push_back(ep);
        }
    }
    
    // Update callee context
    if (!session.getCalleeMsisdn().empty()) {
        auto ctx = ctx_manager_->getOrCreateByMsisdn(session.getCalleeMsisdn());
        if (!session.getCalleeIp().empty()) {
            NetworkEndpoint ep;
            ep.ipv4 = session.getCalleeIp();
            ctx->endpoints.push_back(ep);
        }
    }
}

} // namespace correlation
} // namespace callflow
```

---

## Testing Requirements

```cpp
// Test voice call detection
TEST(SipCorrelatorTest, DetectVoiceCall) {
    SipCorrelator correlator;
    
    // Add INVITE
    SipMessage invite;
    invite.setCallId("test-call-1@example.com");
    invite.setMethod("INVITE");
    invite.setFromUri("sip:+14155551234@ims.example.com");
    invite.setToUri("sip:+14155555678@ims.example.com");
    // ... set other fields
    correlator.addMessage(invite);
    
    // Add 200 OK
    SipMessage ok;
    ok.setCallId("test-call-1@example.com");
    ok.setStatusCode(200);
    ok.setFromUri("sip:+14155551234@ims.example.com");
    ok.setToUri("sip:+14155555678@ims.example.com");
    correlator.addMessage(ok);
    
    // Finalize and verify
    correlator.finalize();
    auto sessions = correlator.getCallSessions();
    ASSERT_EQ(sessions.size(), 1);
    EXPECT_EQ(sessions[0]->getType(), SipSessionType::VOICE_CALL);
    EXPECT_EQ(sessions[0]->getCallerMsisdn(), "4155551234");
    EXPECT_EQ(sessions[0]->getCalleeMsisdn(), "4155555678");
}
```

---

## Success Criteria

- [ ] Correctly groups messages by Call-ID
- [ ] Detects registration vs voice call vs SMS
- [ ] Extracts caller/callee MSISDNs from various headers
- [ ] Detects call forwarding (UEc)
- [ ] Extracts UE IP addresses from Contact/SDP
- [ ] Tracks dialog state correctly
- [ ] Unit test coverage > 85%
```

---

# Milestone 3: Diameter Intra-Protocol Correlator (2 weeks)

## PROMPT 3.1: Diameter Session Tracking and Interface Detection

```markdown
# Diameter Intra-Protocol Correlator
## nDPI Callflow Visualizer - Diameter Session Tracking

**Context:**
I'm building the nDPI Callflow Visualizer. This prompt implements the Diameter intra-protocol correlator that groups Diameter messages into sessions, detects interfaces (S6a, Gx, Rx, Cx, Sh, etc.), and extracts subscriber information.

**Analysis Reference:**
The Python Diameter parser (diameter.py, 2150 lines) handles:
- Session detection by Session-ID
- Request/Answer linking by Hop-by-Hop-ID
- Interface detection by Application-ID
- Subscriber info extraction (IMSI, MSISDN, Framed-IP)
- CCR/CCA types for Gx (Initial/Update/Terminate)

**3GPP References:**
- RFC 6733 (Diameter Base Protocol)
- TS 29.272 (S6a Interface)
- TS 29.212 (Gx Interface - Policy and Charging Control)
- TS 29.214 (Rx Interface - Policy and Charging Control)
- TS 29.228/229 (Cx/Dx Interfaces)
- TS 29.328/329 (Sh Interface)
- TS 32.299 (Gy/Ro Interface - Charging)

---

## Requirements

### 1. Diameter Interface Detection

```cpp
// Detect interface from Application-ID
const std::unordered_map<uint32_t, std::string> APPLICATION_ID_TO_INTERFACE = {
    {0, "Base"},
    {3, "Gz/Rf"},
    {4, "Gy/Ro"},
    {16777216, "Cx"},
    {16777217, "Sh/Sp"},
    {16777219, "Wx"},
    {16777236, "Rx"},
    {16777238, "Gx"},
    {16777250, "STa/SWa"},
    {16777251, "S6a/S6d"},
    {16777252, "S13"},
    {16777255, "SLg"},
    {16777264, "SWm"},
    {16777265, "SWx"},
    {16777272, "S6b"},
    {16777291, "SLh"},
    {16777302, "Sy"},
    {16777303, "Sd"},
};
```

### 2. Command Code Meanings

```cpp
// Common Diameter command codes
const std::unordered_map<uint16_t, std::string> COMMAND_CODES = {
    {257, "Capabilities-Exchange"},
    {258, "Re-Auth"},
    {265, "AA"},
    {268, "Diameter-EAP"},
    {271, "Accounting"},
    {272, "Credit-Control"},      // Gx CCR/CCA, Gy CCR/CCA
    {274, "Abort-Session"},
    {275, "Session-Termination"},
    {280, "Device-Watchdog"},
    {282, "Disconnect-Peer"},
    {300, "User-Authorization"},   // Cx UAR/UAA
    {301, "Server-Assignment"},    // Cx SAR/SAA
    {302, "Location-Info"},        // Cx LIR/LIA
    {303, "Multimedia-Auth"},      // Cx MAR/MAA
    {304, "Registration-Termination"}, // Cx RTR/RTA
    {305, "Push-Profile"},         // Cx PPR/PPA
    {306, "User-Data"},            // Sh UDR/UDA
    {307, "Profile-Update"},       // Sh PUR/PUA
    {308, "Subscribe-Notifications"}, // Sh SNR/SNA
    {309, "Push-Notification"},    // Sh PNR/PNA
    {316, "Update-Location"},      // S6a ULR/ULA
    {317, "Cancel-Location"},      // S6a CLR/CLA
    {318, "Authentication-Information"}, // S6a AIR/AIA
    {319, "Insert-Subscriber-Data"}, // S6a IDR/IDA
    {320, "Delete-Subscriber-Data"}, // S6a DSR/DSA
    {321, "Purge-UE"},             // S6a PUR/PUA
    {323, "Notify"},               // S6a NOR/NOA
};
```

### 3. CCR/CCA Types (for Gx)

```cpp
enum class DiameterCCRequestType {
    INITIAL = 1,      // Session establishment
    UPDATE = 2,       // Session modification
    TERMINATION = 3,  // Session termination
    EVENT = 4         // Event-based charging
};
```

---

## Implementation

### File Structure

```
include/correlation/diameter/
├── diameter_types.h           // Enums and constants
├── diameter_session.h         // Diameter session container
├── diameter_avp_parser.h      // AVP extraction utilities
├── diameter_correlator.h      // Main Diameter correlator
└── diameter_interface.h       // Interface-specific logic

src/correlation/diameter/
├── diameter_session.cpp
├── diameter_avp_parser.cpp
├── diameter_correlator.cpp
└── diameter_interface.cpp

tests/unit/diameter/
├── test_diameter_session.cpp
├── test_diameter_avp_parser.cpp
└── test_diameter_correlator.cpp
```

### diameter_types.h

```cpp
#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <optional>

namespace callflow {
namespace correlation {

enum class DiameterInterface {
    BASE,
    S6A_S6D,    // MME ↔ HSS
    GX,         // P-GW ↔ PCRF (Policy)
    RX,         // P-CSCF ↔ PCRF (QoS for IMS)
    GY_RO,      // P-GW ↔ OCS (Online Charging)
    GZ_RF,      // P-GW ↔ OFCS (Offline Charging)
    CX,         // I/S-CSCF ↔ HSS (IMS Registration)
    SH_SP,      // AS ↔ HSS (Subscriber Data)
    SY,         // PCRF ↔ OCS (Spending Limit)
    S13,        // MME ↔ EIR (Equipment Check)
    SWX,        // AAA ↔ HSS
    SWM,        // ePDG ↔ AAA
    S6B,        // P-GW ↔ AAA
    SD,         // PCRF ↔ TDF
    UNKNOWN
};

enum class DiameterCCRequestType : uint32_t {
    INITIAL = 1,
    UPDATE = 2,
    TERMINATION = 3,
    EVENT = 4
};

enum class DiameterMessageType {
    REQUEST,
    ANSWER
};

struct DiameterResultCode {
    uint32_t code;
    bool is_success;
    std::string description;
    
    static DiameterResultCode parse(uint32_t result_code);
    static DiameterResultCode parseExperimental(uint32_t vendor_id, 
                                                 uint32_t result_code);
};

// Application ID to Interface mapping
DiameterInterface getInterfaceFromAppId(uint32_t application_id);
std::string interfaceToString(DiameterInterface iface);

// Command code description
std::string getCommandDescription(uint16_t command_code);

} // namespace correlation
} // namespace callflow
```

### diameter_session.h

```cpp
#pragma once

#include "correlation/diameter/diameter_types.h"
#include "correlation/identity/subscriber_identity.h"
#include <vector>
#include <optional>

namespace callflow {
namespace correlation {

class DiameterMessage;

/**
 * @brief Represents a Diameter session
 * 
 * A session is identified by Session-ID and contains:
 * - All request/answer pairs
 * - Interface type
 * - Subscriber information
 * - PDN connection info (for Gx)
 */
class DiameterSession {
public:
    DiameterSession(const std::string& session_id);
    ~DiameterSession() = default;
    
    // Session identification
    std::string getSessionId() const { return session_id_; }
    DiameterInterface getInterface() const { return interface_; }
    std::string getInterfaceName() const;
    
    // Add message to session
    void addMessage(const DiameterMessage& msg);
    
    // Get messages
    const std::vector<DiameterMessage>& getMessages() const { return messages_; }
    size_t getMessageCount() const { return messages_.size(); }
    
    // Request/Answer linking
    const DiameterMessage* findAnswer(const DiameterMessage& request) const;
    const DiameterMessage* findRequest(const DiameterMessage& answer) const;
    
    // Subscriber information
    std::optional<std::string> getImsi() const { return imsi_; }
    std::optional<std::string> getMsisdn() const { return msisdn_; }
    std::optional<std::string> getPublicIdentity() const { return public_identity_; }
    
    // Network information
    std::optional<std::string> getFramedIpAddress() const { return framed_ip_; }
    std::optional<std::string> getFramedIpv6Prefix() const { return framed_ipv6_prefix_; }
    std::optional<std::string> getCalledStationId() const { return called_station_id_; }
    
    // Gx-specific
    std::optional<DiameterCCRequestType> getCCRequestType() const { return ccr_type_; }
    std::vector<std::string> getChargingRuleNames() const { return charging_rules_; }
    std::optional<uint8_t> getQci() const { return qci_; }
    
    // Time window
    double getStartTime() const { return start_time_; }
    double getEndTime() const { return end_time_; }
    uint32_t getStartFrame() const { return start_frame_; }
    uint32_t getEndFrame() const { return end_frame_; }
    
    // Correlation
    void setIntraCorrelator(const std::string& id) { intra_correlator_ = id; }
    std::string getIntraCorrelator() const { return intra_correlator_; }
    
    void setInterCorrelator(const std::string& id) { inter_correlator_ = id; }
    std::string getInterCorrelator() const { return inter_correlator_; }
    
    // Result tracking
    bool hasErrors() const { return has_errors_; }
    std::vector<DiameterResultCode> getResultCodes() const { return result_codes_; }
    
    // Finalize session
    void finalize();

private:
    std::string session_id_;
    DiameterInterface interface_ = DiameterInterface::UNKNOWN;
    
    std::vector<DiameterMessage> messages_;
    
    // Subscriber info
    std::optional<std::string> imsi_;
    std::optional<std::string> msisdn_;
    std::optional<std::string> public_identity_;
    
    // Network info
    std::optional<std::string> framed_ip_;
    std::optional<std::string> framed_ipv6_prefix_;
    std::optional<std::string> called_station_id_;  // APN
    
    // Gx-specific
    std::optional<DiameterCCRequestType> ccr_type_;
    std::vector<std::string> charging_rules_;
    std::optional<uint8_t> qci_;
    
    // Time window
    double start_time_ = 0.0;
    double end_time_ = 0.0;
    uint32_t start_frame_ = 0;
    uint32_t end_frame_ = 0;
    
    // Correlation
    std::string intra_correlator_;
    std::string inter_correlator_;
    
    // Result tracking
    bool has_errors_ = false;
    std::vector<DiameterResultCode> result_codes_;
    
    // Internal methods
    void detectInterface();
    void extractSubscriberInfo();
    void extractNetworkInfo();
    void extractGxInfo();
    void updateTimeWindow(const DiameterMessage& msg);
};

} // namespace correlation
} // namespace callflow
```

### diameter_correlator.h

```cpp
#pragma once

#include "correlation/diameter/diameter_session.h"
#include "correlation/identity/subscriber_context_manager.h"
#include <unordered_map>
#include <memory>
#include <mutex>

namespace callflow {
namespace correlation {

/**
 * @brief Diameter intra-protocol correlator
 * 
 * Groups Diameter messages into sessions based on Session-ID,
 * links requests to answers, and extracts subscriber information.
 */
class DiameterCorrelator {
public:
    DiameterCorrelator();
    explicit DiameterCorrelator(SubscriberContextManager* ctx_manager);
    ~DiameterCorrelator() = default;
    
    /**
     * @brief Add a parsed Diameter message
     */
    void addMessage(const DiameterMessage& msg);
    
    /**
     * @brief Finalize all sessions
     */
    void finalize();
    
    /**
     * @brief Get all sessions
     */
    std::vector<DiameterSession*> getSessions();
    
    /**
     * @brief Get sessions by interface
     */
    std::vector<DiameterSession*> getSessionsByInterface(DiameterInterface iface);
    
    /**
     * @brief Get Gx sessions (for VoLTE correlation)
     */
    std::vector<DiameterSession*> getGxSessions();
    
    /**
     * @brief Get Rx sessions (for VoLTE correlation)
     */
    std::vector<DiameterSession*> getRxSessions();
    
    /**
     * @brief Find session by Session-ID
     */
    DiameterSession* findBySessionId(const std::string& session_id);
    
    /**
     * @brief Find sessions by IMSI
     */
    std::vector<DiameterSession*> findByImsi(const std::string& imsi);
    
    /**
     * @brief Find sessions by Framed-IP-Address
     */
    std::vector<DiameterSession*> findByFramedIp(const std::string& ip);
    
    /**
     * @brief Get statistics
     */
    struct Stats {
        size_t total_messages = 0;
        size_t total_sessions = 0;
        std::unordered_map<DiameterInterface, size_t> sessions_by_interface;
        size_t error_responses = 0;
    };
    Stats getStats() const;
    
    /**
     * @brief Clear all sessions
     */
    void clear();

private:
    std::mutex mutex_;
    std::unordered_map<std::string, std::unique_ptr<DiameterSession>> sessions_;
    
    SubscriberContextManager* ctx_manager_ = nullptr;
    
    int session_sequence_ = 0;
    Stats stats_;
    
    std::string generateSessionId(double timestamp);
    void updateSubscriberContext(const DiameterSession& session);
};

} // namespace correlation
} // namespace callflow
```

---

## Success Criteria

- [ ] Correctly groups messages by Session-ID
- [ ] Links requests to answers by Hop-by-Hop-ID
- [ ] Detects interface from Application-ID
- [ ] Extracts IMSI, MSISDN, Framed-IP-Address
- [ ] Tracks Gx CCR types (I/U/T)
- [ ] Handles error responses
- [ ] Unit test coverage > 85%
```

---

# (Continued in next milestones...)

Due to length, I'll provide a summary of the remaining milestones. The full prompts follow the same detailed structure.

---

# Milestone 4: GTPv2 Intra-Protocol Correlator (2 weeks)

**Key Features:**
- Session tracking by Control TEID + Sequence
- Bearer management (default, dedicated, linked)
- F-TEID extraction for GTP-U correlation
- IMSI/MSISDN/MEI extraction
- PDN address (UE IP) tracking
- APN detection (IMS vs internet)

---

# Milestone 5: NAS/S1AP Correlator (2 weeks)

**Key Features:**
- EMM message parsing (Attach, TAU, Detach)
- ESM message parsing (PDN Connectivity, Bearer activation)
- IMSI/IMEI/GUTI extraction
- Security context tracking
- Link to S1AP by NAS-PDU IE

---

# Milestone 6: RTP Stream Correlator (1 week)

**Key Features:**
- Stream detection by SSRC
- 5-tuple tracking
- Jitter and packet loss calculation
- Link to SIP session by media IP/port

---

# Milestone 7: VoLTE Inter-Protocol Correlator (2 weeks)

**Key Features:**
- Cross-protocol linking algorithm
- Time-windowed correlation
- MSISDN/IMSI/UE-IP based matching
- Call flow assembly
- Statistics aggregation

---

# Milestone 8: Testing, API & Optimization (1 week)

**Key Features:**
- Integration tests with sample PCAPs
- REST API extensions
- Performance optimization
- Documentation
