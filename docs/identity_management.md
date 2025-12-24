# Subscriber Identity Management - Core Types

## Overview

The subscriber identity management system provides comprehensive normalization, parsing, and matching capabilities for telecom subscriber identities across all protocols used in VoLTE correlation.

## Architecture

```
include/correlation/identity/
├── subscriber_identity.h      # Core identity structures
├── msisdn_normalizer.h        # MSISDN parsing and normalization
├── imsi_normalizer.h          # IMSI parsing and normalization
├── imei_normalizer.h          # IMEI/IMEISV parsing
├── guti_parser.h              # GUTI/5G-GUTI parsing
└── identity_matcher.h         # Identity matching algorithms

src/correlation/identity/
├── subscriber_identity.cpp
├── msisdn_normalizer.cpp
├── imsi_normalizer.cpp
├── imei_normalizer.cpp
├── guti_parser.cpp
└── identity_matcher.cpp
```

## Core Components

### 1. MSISDN Normalizer

Handles all MSISDN format variations found in telecom protocols:

**Input formats supported:**
- SIP URI: `sip:+14155551234@ims.example.com;user=phone`
- SIP URI without plus: `sip:14155551234@ims.example.com`
- TEL URI: `tel:+14155551234`
- TEL URI with formatting: `tel:+1-415-555-1234`
- National format: `04155551234` (with leading zero)
- International: `+14155551234`
- Raw digits: `14155551234`
- With parameters: `+14155551234;npdi;rn=+14155550000`

**Example usage:**

```cpp
#include "correlation/identity/msisdn_normalizer.h"

using namespace callflow::correlation;

// Normalize from SIP URI
auto msisdn = MsisdnNormalizer::normalize("sip:+14155551234@ims.example.com");
// Result:
//   digits_only: "14155551234"
//   national: "4155551234"
//   international: "14155551234"
//   country_code: "1"

// Match two MSISDNs
auto m1 = MsisdnNormalizer::normalize("sip:+14155551234@domain");
auto m2 = MsisdnNormalizer::normalize("tel:+1-415-555-1234");
bool matches = MsisdnNormalizer::matches(m1, m2);  // true
```

### 2. IMSI Normalizer

Parses and normalizes IMSI from various sources:

**Input formats supported:**
- Standard: `310260123456789` (15 digits)
- With prefix: `imsi-310260123456789`
- From Diameter: `310260123456789@ims.mnc260.mcc310.3gppnetwork.org`
- BCD encoded (from GTP/Diameter AVPs)

**Example usage:**

```cpp
#include "correlation/identity/imsi_normalizer.h"

using namespace callflow::correlation;

// Normalize from string
auto imsi = ImsiNormalizer::normalize("310260123456789");
// Result:
//   digits: "310260123456789"
//   mcc: "310"
//   mnc: "260"
//   msin: "123456789"
//   getPlmn(): "310260"

// Parse from Diameter username
auto imsi2 = ImsiNormalizer::fromDiameterUsername(
    "310260123456789@ims.mnc260.mcc310.3gppnetwork.org");

// Parse from BCD (GTP IMSI IE)
uint8_t bcd_data[] = {0x13, 0x02, 0x06, 0x21, 0x43, 0x65, 0x87, 0xF9};
auto imsi3 = ImsiNormalizer::fromBcd(bcd_data, sizeof(bcd_data));
```

### 3. IMEI Normalizer

Handles IMEI and IMEISV parsing:

**Input formats supported:**
- IMEI (14 digits): `35123456789012`
- IMEI with check digit (15 digits): `351234567890120`
- IMEISV (16 digits): `3512345678901234`
- With prefix: `imei-35123456789012`
- BCD encoded

**Example usage:**

```cpp
#include "correlation/identity/imei_normalizer.h"

using namespace callflow::correlation;

// Normalize IMEI
auto imei = ImeiNormalizer::normalize("35123456789012");
// Result:
//   imei: "35123456789012"
//   tac: "35123456" (Type Allocation Code)
//   snr: "789012" (Serial Number)

// Normalize IMEISV
auto imeisv = ImeiNormalizer::normalize("3512345678901234");
// Result:
//   imei: "35123456789012"
//   imeisv: "3512345678901234"
//   tac: "35123456"

// Verify check digit
bool valid = ImeiNormalizer::verifyCheckDigit("351234567890120");
```

### 4. GUTI Parser

Parses 4G GUTI and 5G-GUTI structures:

**Structures:**
- **4G GUTI**: MCC (3 digits) + MNC (2-3 digits) + MME Group ID (16 bits) + MME Code (8 bits) + M-TMSI (32 bits)
- **5G-GUTI**: MCC (3 digits) + MNC (2-3 digits) + AMF Region ID (8 bits) + AMF Set ID (10 bits) + AMF Pointer (6 bits) + 5G-TMSI (32 bits)

**Example usage:**

```cpp
#include "correlation/identity/guti_parser.h"

using namespace callflow::correlation;

// Parse 4G GUTI from BCD
uint8_t guti_data[11] = { /* BCD encoded GUTI */ };
auto guti4g = GutiParser::parse4G(guti_data, sizeof(guti_data));

// Parse 5G-GUTI from BCD
auto guti5g = GutiParser::parse5G(guti_data, sizeof(guti_data));

// Check if same MME pool
Guti4G guti1, guti2;
bool same_pool = GutiParser::isSameMmePool(guti1, guti2);

// Encode GUTI to BCD
uint8_t output[11];
size_t written = GutiParser::encode4G(guti4g.value(), output);
```

### 5. Identity Matcher

High-level matching algorithms for subscriber identities:

**Match confidence levels:**
- **EXACT**: Perfect match (IMSI, IMEI exact)
- **HIGH**: High confidence (MSISDN international, IP+APN)
- **MEDIUM**: Medium confidence (MSISDN national, IP)
- **LOW**: Low confidence (suffix match, prefix match)
- **NONE**: No match

**Example usage:**

```cpp
#include "correlation/identity/identity_matcher.h"

using namespace callflow::correlation;

// Create two subscriber identities
SubscriberIdentity id1, id2;
id1.imsi = ImsiNormalizer::normalize("310260123456789");
id2.imsi = ImsiNormalizer::normalize("310260123456789");

// Match identities
auto result = IdentityMatcher::match(id1, id2);
if (result.isMatch()) {
    std::cout << "Match confidence: " << (int)result.confidence << std::endl;
    std::cout << "Reason: " << result.reason << std::endl;
    std::cout << "Score: " << result.score << std::endl;
}

// Match by specific method
auto imsi_match = IdentityMatcher::matchByImsi(id1, id2);
auto msisdn_match = IdentityMatcher::matchByMsisdn(id1, id2);
auto ip_match = IdentityMatcher::matchByIp(id1, id2);

// Calculate overall match score (0.0 to 1.0)
float score = IdentityMatcher::calculateMatchScore(id1, id2);
```

## Complete Subscriber Identity Structure

```cpp
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

    // Network endpoints
    std::vector<NetworkEndpoint> endpoints;

    // APN/DNN information
    std::string apn;
    std::string pdn_type;  // "ipv4", "ipv6", "ipv4v6"

    // Confidence scores
    std::unordered_map<std::string, float> confidence;

    // Timestamps
    std::chrono::steady_clock::time_point first_seen;
    std::chrono::steady_clock::time_point last_seen;
};
```

## VoLTE Correlation Use Cases

### Use Case 1: Correlate SIP INVITE with GTP-C Session

```cpp
// Extract MSISDN from SIP P-Asserted-Identity
auto msisdn_sip = MsisdnNormalizer::fromSipUri(pai_header);

// Extract IMSI from GTP-C Create Session Request
auto imsi_gtp = ImsiNormalizer::fromBcd(imsi_ie_data, imsi_ie_len);

// Create subscriber identities
SubscriberIdentity sip_identity, gtp_identity;
sip_identity.msisdn = msisdn_sip;
gtp_identity.imsi = imsi_gtp;

// Try to match (will use MSISDN or IP correlation)
auto match_result = IdentityMatcher::match(sip_identity, gtp_identity);
```

### Use Case 2: Track Subscriber Across Handover

```cpp
// Before handover
SubscriberIdentity before;
before.imsi = ImsiNormalizer::normalize("310260123456789");
before.guti = old_guti;
NetworkEndpoint ep1;
ep1.ipv4 = "10.1.1.100";
before.endpoints.push_back(ep1);

// After handover (new GUTI, possibly new IP)
SubscriberIdentity after;
after.guti = new_guti;
NetworkEndpoint ep2;
ep2.ipv4 = "10.1.2.200";
after.endpoints.push_back(ep2);

// Match will fail on IP, but succeed if IMSI appears later
// Or match on same MME pool
if (GutiParser::isSameMmePool(*before.guti, *after.guti)) {
    // Likely same subscriber
}
```

### Use Case 3: Merge Identity Information

```cpp
SubscriberIdentity combined;

// From SIP
combined.msisdn = MsisdnNormalizer::normalize("sip:+14155551234@ims");

// From GTP-C
combined.imsi = ImsiNormalizer::normalize("310260123456789");
combined.imei = ImeiNormalizer::normalize("35123456789012");

// From Diameter Gx
NetworkEndpoint ep;
ep.ipv4 = "10.1.1.100";
combined.endpoints.push_back(ep);
combined.apn = "internet";

// Now we have a complete subscriber profile
std::string key = combined.getPrimaryKey();  // "imsi:310260123456789"
```

## Testing

Run all identity tests:

```bash
# Build and run all identity tests
ctest -R test_.*_normalizer
ctest -R test_guti_parser
ctest -R test_identity_matcher

# Run specific test
./build/tests/test_msisdn_normalizer
./build/tests/test_imsi_normalizer
./build/tests/test_imei_normalizer
./build/tests/test_guti_parser
./build/tests/test_identity_matcher
```

## Performance Considerations

1. **MSISDN Normalization**: O(n) where n is string length, very fast
2. **IMSI/IMEI Normalization**: O(n), minimal overhead
3. **BCD Parsing**: O(n) where n is byte length
4. **Identity Matching**: O(1) for exact matches, O(n) for suffix matching where n is number of digits
5. **GUTI Parsing**: O(1), fixed size structures

## Future Enhancements

1. **Country Code Database**: Expand country code mappings for better international support
2. **MCC/MNC Database**: Use ITU database for accurate MNC length detection
3. **IMEI TAC Database**: Validate against official TAC database
4. **Caching**: Add LRU cache for frequently normalized identities
5. **5G SUPI/SUCI**: Add support for 5G Subscription Permanent Identifier and Concealed Identifier

## References

- **3GPP TS 23.003**: Numbering, Addressing and Identification
- **3GPP TS 23.008**: Organization of Subscriber Data
- **3GPP TS 24.301**: NAS protocol for EPS (4G GUTI structure)
- **3GPP TS 24.501**: NAS protocol for 5GS (5G-GUTI structure)
- **RFC 3986**: URI Generic Syntax
- **RFC 3966**: TEL URI Scheme
- **ITU-E.164**: International Public Telecommunication Numbering Plan
