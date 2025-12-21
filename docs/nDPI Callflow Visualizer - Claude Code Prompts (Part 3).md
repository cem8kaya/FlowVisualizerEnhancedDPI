# nDPI Callflow Visualizer - Claude Code Prompts (Part 3)
## Prompts 6-20: State Machines, Control Plane, AAA, 5G, Testing
## **INCLUDES SIP ENHANCEMENT FOR VoLTE/VoNR**

---

### PROMPT 6: SIP Parser Enhancement for VoLTE/VoNR Support

```markdown
# SIP Parser Enhancement - VoLTE/VoNR 3GPP Extensions
## nDPI Callflow Visualizer - IMS/VoLTE/VoNR Support

**Context:**
I'm enhancing the nDPI Callflow Visualizer's existing SIP parser to support VoLTE (Voice over LTE) and VoNR (Voice over NR/5G) by implementing 3GPP-specific SIP extensions. The current parser handles basic SIP headers (Call-ID, From, To, Via, Contact, CSeq) and SDP, but is missing critical IMS/VoLTE P-headers defined in RFC 7315 and 3GPP TS 24.229.

Current implementation location:
- `include/protocol_parsers/sip_parser.h`
- `src/protocol_parsers/sip_parser.cpp`

**3GPP References:** 
- TS 24.229 (IMS Call Control)
- RFC 7315 (Private Header Fields for SIP)
- RFC 3312 (Integration of Resource Management and SIP)
- GSMA IR.92 (IMS Profile for VoLTE)
- GSMA IR.94 (IMS Profile for VoNR/5G)

**Requirements:**

1. **3GPP P-Headers (RFC 7315)**
   
   **P-Asserted-Identity** (Critical for caller ID):
   - Format: `P-Asserted-Identity: "Alice" <sip:alice@example.com>, <tel:+1234567890>`
   - Network-asserted user identity (used for billing, calling party display)
   - Can contain multiple identities (SIP URI, Tel URI)
   - Parse display name and URI
   
   **P-Access-Network-Info** (Critical for QoS, roaming):
   - Format: `P-Access-Network-Info: 3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=234150999999999`
   - Indicates access network type: 3GPP-E-UTRAN (LTE), 3GPP-NR (5G), IEEE-802.11 (WiFi)
   - Contains cell ID (ECGI for LTE, NCGI for 5G)
   - Parse access type and cell ID
   - Example LTE: `3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=<MCC><MNC><CellID>`
   - Example 5G: `3GPP-NR; nrcgi=<MCC><MNC><NRCellID>`
   
   **P-Visited-Network-ID** (Roaming):
   - Format: `P-Visited-Network-ID: "Visited Network"`
   - Identifies visited network in roaming scenarios
   - String or token format
   
   **P-Charging-Vector** (Billing correlation):
   - Format: `P-Charging-Vector: icid-value=1234567890; icid-generated-at=192.0.2.1; orig-ioi=home1.net; term-ioi=home2.net`
   - **icid-value**: IMS Charging ID (critical for billing correlation with Diameter Ro/Rf)
   - **icid-generated-at**: IP address where ICID was generated
   - **orig-ioi**: Originating Inter-Operator Identifier
   - **term-ioi**: Terminating Inter-Operator Identifier
   - Parse all fields as key-value pairs
   
   **P-Charging-Function-Addresses**:
   - Format: `P-Charging-Function-Addresses: ccf=192.0.2.10; ecf=192.0.2.20`
   - **ccf**: Charging Collection Function address (offline charging)
   - **ecf**: Event Charging Function address (online charging)
   - Multiple CCF/ECF addresses possible
   
   **P-Served-User** (ISC interface):
   - Format: `P-Served-User: <sip:user@example.com>; sescase=orig; regstate=reg`
   - Indicates served user on ISC interface (S-CSCF to AS)
   - **sescase**: Session case (orig/term)
   - **regstate**: Registration state (reg/unreg)
   
   **P-Preferred-Identity**:
   - Format: `P-Preferred-Identity: "Alice" <sip:alice@example.com>`
   - User's preferred identity for network assertion
   
   **P-Early-Media**:
   - Format: `P-Early-Media: supported`
   - Indicates early media support

2. **IMS Session Timer Headers**
   
   **Session-Expires**:
   - Format: `Session-Expires: 1800; refresher=uac`
   - Session timer value in seconds
   - Refresher role: uac (client) or uas (server)
   
   **Min-SE** (Minimum Session Expiration):
   - Format: `Min-SE: 90`
   - Minimum acceptable session timer value

3. **IMS Routing Headers**
   
   **Path** (Registration):
   - Format: `Path: <sip:pcscf.example.com;lr>`
   - Records P-CSCF address during registration
   - Can have multiple Path entries
   
   **Service-Route** (Registration response):
   - Format: `Service-Route: <sip:scscf.example.com;lr>`
   - Provides route to S-CSCF
   
   **Record-Route**:
   - Enhanced parsing for IMS proxies
   - May contain double Record-Route (P-CSCF adds two)

4. **IMS Feature Negotiation Headers**
   
   **Require**:
   - Format: `Require: 100rel, timer, precondition`
   - Lists required SIP extensions
   - Common values: 100rel (PRACK), timer, precondition, sec-agree
   
   **Supported**:
   - Format: `Supported: 100rel, timer, replaces, gruu`
   - Lists supported SIP extensions
   
   **Allow**:
   - Enhanced to track IMS methods: INVITE, ACK, BYE, CANCEL, UPDATE, PRACK, REFER, SUBSCRIBE, NOTIFY

5. **Security Headers (IPSec/TLS)**
   
   **Security-Client** (UE capabilities):
   - Format: `Security-Client: ipsec-3gpp; alg=hmac-sha-1-96; spi-c=1234; spi-s=5678; port-c=5062; port-s=5064`
   - IPSec parameters: algorithm, SPIs, ports
   
   **Security-Server** (Network capabilities):
   - Same format as Security-Client
   
   **Security-Verify** (Confirmation):
   - Same format, echoes negotiated parameters

6. **Privacy Headers**
   
   **Privacy**:
   - Format: `Privacy: id; header; user`
   - Privacy levels: id, header, session, user, none, critical
   - Parse multiple privacy values

7. **Geolocation Headers (RFC 6442)**
   
   **Geolocation**:
   - Format: `Geolocation: <sip:geolocation.example.com>`
   - Reference to geolocation information
   
   **Geolocation-Routing**:
   - Format: `Geolocation-Routing: yes`
   - Indicates if geolocation used for routing
   
   **Geolocation-Error**:
   - Format: `Geolocation-Error: <error-code> <error-description>`

8. **Enhanced SDP for IMS**
   
   **QoS Preconditions** (RFC 3312):
   - `a=curr:qos local none` / `a=curr:qos remote none`
   - `a=des:qos mandatory local sendrecv` / `a=des:qos mandatory remote sendrecv`
   - Parse current and desired QoS states
   
   **Bandwidth Modifiers**:
   - `b=AS:64` (Application-Specific bandwidth in kbps)
   - `b=RS:800` / `b=RR:2000` (RTCP bandwidth)
   - `b=TIAS:64000` (Transport Independent Application Specific, in bps)
   
   **IMS Media Attributes**:
   - `a=sendrecv` / `a=sendonly` / `a=recvonly` / `a=inactive`
   - `a=rtcp:<port>` (explicit RTCP port)
   - `a=ptime:20` (packet time)
   - `a=maxptime:40` (maximum packet time)
   
   **Codec Negotiation**:
   - Enhanced parsing for `a=rtpmap` (payload type mapping)
   - `a=fmtp` (format parameters, e.g., AMR mode-set)
   - Example: `a=fmtp:97 mode-set=0,2,4,7; mode-change-period=2`

9. **Refer Headers (Call Transfer)**
   
   **Refer-To**:
   - Format: `Refer-To: <sip:transfer-target@example.com>`
   - Target of call transfer
   
   **Referred-By**:
   - Format: `Referred-By: <sip:referrer@example.com>`
   - Who initiated the transfer
   
   **Replaces** (in Refer-To):
   - Format: `Replaces: call-id@host;to-tag=abc;from-tag=def`
   - Replaces existing dialog

10. **Subscription Headers (SUBSCRIBE/NOTIFY)**
    
    **Event**:
    - Format: `Event: presence` / `Event: reg` / `Event: conference`
    - Event package type
    
    **Subscription-State**:
    - Format: `Subscription-State: active;expires=3600` / `Subscription-State: terminated;reason=timeout`
    - State: active, pending, terminated
    - Reason for termination

**File Structure:**
```
include/protocol_parsers/
  sip_parser.h          # Enhance existing
  sip_3gpp_headers.h    # NEW: 3GPP header structures
  sip_ims_types.h       # NEW: IMS-specific types

src/protocol_parsers/
  sip_parser.cpp        # Enhance existing
  sip_3gpp_parser.cpp   # NEW: P-header parsing
  sip_sdp_ims.cpp       # NEW: Enhanced SDP for IMS

tests/unit/
  test_sip_3gpp_headers.cpp    # NEW
  test_sip_ims_sdp.cpp          # NEW

tests/pcaps/
  volte_register.pcap           # NEW: IMS registration with P-headers
  volte_call.pcap               # NEW: Complete VoLTE call
  vonr_call.pcap                # NEW: 5G VoNR call
```

**Implementation Guide:**

Enhance `sip_parser.h`:
```cpp
#pragma once
#include <map>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <vector>
#include "common/types.h"

namespace callflow {

// NEW: 3GPP P-headers structures
struct SipPAssertedIdentity {
    std::string display_name;
    std::string uri;  // SIP URI or Tel URI
    
    static std::optional<std::vector<SipPAssertedIdentity>> parse(const std::string& value);
};

struct SipPAccessNetworkInfo {
    enum class AccessType {
        THREEGPP_E_UTRAN_FDD,  // LTE FDD
        THREEGPP_E_UTRAN_TDD,  // LTE TDD
        THREEGPP_NR,            // 5G NR
        IEEE_802_11,            // WiFi
        UNKNOWN
    };
    AccessType access_type;
    std::optional<std::string> cell_id;  // ECGI (LTE) or NCGI (5G)
    std::map<std::string, std::string> parameters;
    
    static std::optional<SipPAccessNetworkInfo> parse(const std::string& value);
};

struct SipPChargingVector {
    std::string icid_value;  // IMS Charging ID (CRITICAL)
    std::optional<std::string> icid_generated_at;
    std::optional<std::string> orig_ioi;  // Originating IOI
    std::optional<std::string> term_ioi;  // Terminating IOI
    
    static std::optional<SipPChargingVector> parse(const std::string& value);
};

struct SipPChargingFunctionAddresses {
    std::vector<std::string> ccf_addresses;  // Charging Collection Function
    std::vector<std::string> ecf_addresses;  // Event Charging Function
    
    static std::optional<SipPChargingFunctionAddresses> parse(const std::string& value);
};

struct SipSecurityInfo {
    std::string mechanism;  // "ipsec-3gpp", "tls"
    std::optional<std::string> algorithm;  // "hmac-sha-1-96", "hmac-md5-96"
    std::optional<uint32_t> spi_c;  // SPI client
    std::optional<uint32_t> spi_s;  // SPI server
    std::optional<uint16_t> port_c;  // Port client
    std::optional<uint16_t> port_s;  // Port server
    
    static std::optional<SipSecurityInfo> parse(const std::string& value);
};

// Enhanced SDP structures
struct SipSdpQosPrecondition {
    std::string direction;  // "local" or "remote"
    std::string status;     // "none", "send", "recv", "sendrecv"
    
    static std::optional<SipSdpQosPrecondition> parseCurrent(const std::string& value);
    static std::optional<SipSdpQosPrecondition> parseDesired(const std::string& value);
};

// Enhanced SIP message structure
struct SipMessage {
    // Existing fields (from current parser)
    bool is_request;
    std::string method;
    std::string request_uri;
    int status_code;
    std::string reason_phrase;
    std::string call_id;
    std::string from;
    std::string to;
    std::string via;
    std::string contact;
    std::string cseq;
    std::string content_type;
    std::map<std::string, std::string> headers;
    std::string body;
    
    // Existing SDP
    struct SdpInfo {
        std::string session_name;
        std::string connection_address;
        uint16_t rtp_port;
        uint16_t rtcp_port;
        std::vector<std::string> media_descriptions;
        std::map<std::string, std::string> attributes;
        
        // NEW: IMS QoS preconditions
        std::optional<SipSdpQosPrecondition> qos_current_local;
        std::optional<SipSdpQosPrecondition> qos_current_remote;
        std::optional<SipSdpQosPrecondition> qos_desired_local;
        std::optional<SipSdpQosPrecondition> qos_desired_remote;
        
        // NEW: Bandwidth info
        std::optional<uint32_t> bandwidth_as;   // kbps
        std::optional<uint32_t> bandwidth_tias; // bps
    };
    std::optional<SdpInfo> sdp;
    
    // NEW: 3GPP P-headers
    std::optional<std::vector<SipPAssertedIdentity>> p_asserted_identity;
    std::optional<SipPAccessNetworkInfo> p_access_network_info;
    std::optional<std::string> p_visited_network_id;
    std::optional<SipPChargingVector> p_charging_vector;  // CRITICAL for billing
    std::optional<SipPChargingFunctionAddresses> p_charging_function_addresses;
    std::optional<std::string> p_served_user;
    std::optional<std::string> p_preferred_identity;
    std::optional<std::string> p_early_media;
    
    // NEW: IMS session timers
    std::optional<uint32_t> session_expires;
    std::optional<std::string> session_expires_refresher;  // "uac" or "uas"
    std::optional<uint32_t> min_se;
    
    // NEW: IMS routing
    std::vector<std::string> path;
    std::vector<std::string> service_route;
    std::vector<std::string> record_route;
    
    // NEW: Feature negotiation
    std::vector<std::string> require;
    std::vector<std::string> supported;
    std::vector<std::string> allow;
    
    // NEW: Security
    std::optional<SipSecurityInfo> security_client;
    std::optional<SipSecurityInfo> security_server;
    std::optional<SipSecurityInfo> security_verify;
    
    // NEW: Privacy
    std::vector<std::string> privacy;  // "id", "header", "user", etc.
    
    // NEW: Geolocation
    std::optional<std::string> geolocation;
    std::optional<std::string> geolocation_routing;
    std::optional<std::string> geolocation_error;
    
    // NEW: Call transfer
    std::optional<std::string> refer_to;
    std::optional<std::string> referred_by;
    std::optional<std::string> replaces;
    
    // NEW: Subscriptions
    std::optional<std::string> event;
    std::optional<std::string> subscription_state;
    
    nlohmann::json toJson() const;
};

class SipParser {
public:
    SipParser() = default;
    ~SipParser() = default;
    
    std::optional<SipMessage> parse(const uint8_t* data, size_t len);
    static bool isSipMessage(const uint8_t* data, size_t len);
    static std::optional<std::string> extractCallId(const uint8_t* data, size_t len);
    static MessageType getMessageType(const SipMessage& msg);
    
private:
    bool parseRequestLine(const std::string& line, SipMessage& msg);
    bool parseStatusLine(const std::string& line, SipMessage& msg);
    void parseHeaders(const std::vector<std::string>& lines, SipMessage& msg);
    void parseSdp(const std::string& body, SipMessage& msg);
    
    // NEW: 3GPP header parsing
    void parsePHeaders(SipMessage& msg);
    void parseImsHeaders(SipMessage& msg);
    void parseSecurityHeaders(SipMessage& msg);
    
    // NEW: Enhanced SDP parsing
    void parseSdpQosPreconditions(SipMessage::SdpInfo& sdp, const std::vector<std::string>& lines);
    void parseSdpBandwidth(SipMessage::SdpInfo& sdp, const std::vector<std::string>& lines);
    
    std::vector<std::string> splitLines(const std::string& text);
    std::pair<std::string, std::string> parseHeader(const std::string& line);
    static std::string trim(const std::string& str);
    static std::vector<std::string> splitCommaList(const std::string& str);
};

} // namespace callflow
```

Create `sip_3gpp_parser.cpp`:
```cpp
#include "protocol_parsers/sip_parser.h"
#include <sstream>
#include <algorithm>

namespace callflow {

std::optional<std::vector<SipPAssertedIdentity>> SipPAssertedIdentity::parse(const std::string& value) {
    std::vector<SipPAssertedIdentity> identities;
    
    // P-Asserted-Identity can have multiple identities separated by commas
    // Format: "Display Name" <sip:user@domain>, <tel:+1234567890>
    
    size_t pos = 0;
    while (pos < value.length()) {
        SipPAssertedIdentity identity;
        
        // Skip whitespace
        while (pos < value.length() && std::isspace(value[pos])) pos++;
        
        // Check for display name in quotes
        if (value[pos] == '"') {
            pos++;
            size_t end_quote = value.find('"', pos);
            if (end_quote != std::string::npos) {
                identity.display_name = value.substr(pos, end_quote - pos);
                pos = end_quote + 1;
            }
        }
        
        // Find URI in angle brackets
        size_t uri_start = value.find('<', pos);
        if (uri_start == std::string::npos) break;
        
        size_t uri_end = value.find('>', uri_start);
        if (uri_end == std::string::npos) break;
        
        identity.uri = value.substr(uri_start + 1, uri_end - uri_start - 1);
        identities.push_back(identity);
        
        pos = uri_end + 1;
        
        // Skip comma if present
        size_t comma = value.find(',', pos);
        if (comma != std::string::npos) {
            pos = comma + 1;
        } else {
            break;
        }
    }
    
    return identities.empty() ? std::nullopt : std::make_optional(identities);
}

std::optional<SipPAccessNetworkInfo> SipPAccessNetworkInfo::parse(const std::string& value) {
    SipPAccessNetworkInfo info;
    
    // Format: 3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=234150999999999
    // Format: 3GPP-NR; nrcgi=001010000000001
    
    std::istringstream iss(value);
    std::string access_str;
    std::getline(iss, access_str, ';');
    
    // Trim
    access_str.erase(0, access_str.find_first_not_of(" \t"));
    access_str.erase(access_str.find_last_not_of(" \t") + 1);
    
    if (access_str == "3GPP-E-UTRAN-FDD") {
        info.access_type = AccessType::THREEGPP_E_UTRAN_FDD;
    } else if (access_str == "3GPP-E-UTRAN-TDD") {
        info.access_type = AccessType::THREEGPP_E_UTRAN_TDD;
    } else if (access_str == "3GPP-NR") {
        info.access_type = AccessType::THREEGPP_NR;
    } else if (access_str == "IEEE-802.11") {
        info.access_type = AccessType::IEEE_802_11;
    } else {
        info.access_type = AccessType::UNKNOWN;
    }
    
    // Parse parameters
    std::string param;
    while (std::getline(iss, param, ';')) {
        size_t eq = param.find('=');
        if (eq != std::string::npos) {
            std::string key = param.substr(0, eq);
            std::string val = param.substr(eq + 1);
            
            // Trim
            key.erase(0, key.find_first_not_of(" \t"));
            key.erase(key.find_last_not_of(" \t") + 1);
            val.erase(0, val.find_first_not_of(" \t"));
            val.erase(val.find_last_not_of(" \t") + 1);
            
            if (key == "utran-cell-id-3gpp" || key == "nrcgi") {
                info.cell_id = val;
            }
            
            info.parameters[key] = val;
        }
    }
    
    return info;
}

std::optional<SipPChargingVector> SipPChargingVector::parse(const std::string& value) {
    SipPChargingVector charging;
    
    // Format: icid-value=1234567890; icid-generated-at=192.0.2.1; orig-ioi=home1.net; term-ioi=home2.net
    
    std::istringstream iss(value);
    std::string param;
    
    while (std::getline(iss, param, ';')) {
        size_t eq = param.find('=');
        if (eq != std::string::npos) {
            std::string key = param.substr(0, eq);
            std::string val = param.substr(eq + 1);
            
            // Trim
            key.erase(0, key.find_first_not_of(" \t"));
            key.erase(key.find_last_not_of(" \t") + 1);
            val.erase(0, val.find_first_not_of(" \t"));
            val.erase(val.find_last_not_of(" \t") + 1);
            
            if (key == "icid-value") {
                charging.icid_value = val;
            } else if (key == "icid-generated-at") {
                charging.icid_generated_at = val;
            } else if (key == "orig-ioi") {
                charging.orig_ioi = val;
            } else if (key == "term-ioi") {
                charging.term_ioi = val;
            }
        }
    }
    
    if (charging.icid_value.empty()) {
        return std::nullopt;
    }
    
    return charging;
}

void SipParser::parsePHeaders(SipMessage& msg) {
    // P-Asserted-Identity
    auto it = msg.headers.find("P-Asserted-Identity");
    if (it != msg.headers.end()) {
        msg.p_asserted_identity = SipPAssertedIdentity::parse(it->second);
    }
    
    // P-Access-Network-Info
    it = msg.headers.find("P-Access-Network-Info");
    if (it != msg.headers.end()) {
        msg.p_access_network_info = SipPAccessNetworkInfo::parse(it->second);
    }
    
    // P-Visited-Network-ID
    it = msg.headers.find("P-Visited-Network-ID");
    if (it != msg.headers.end()) {
        msg.p_visited_network_id = it->second;
    }
    
    // P-Charging-Vector (CRITICAL)
    it = msg.headers.find("P-Charging-Vector");
    if (it != msg.headers.end()) {
        msg.p_charging_vector = SipPChargingVector::parse(it->second);
    }
    
    // P-Charging-Function-Addresses
    it = msg.headers.find("P-Charging-Function-Addresses");
    if (it != msg.headers.end()) {
        msg.p_charging_function_addresses = SipPChargingFunctionAddresses::parse(it->second);
    }
    
    // P-Served-User
    it = msg.headers.find("P-Served-User");
    if (it != msg.headers.end()) {
        msg.p_served_user = it->second;
    }
    
    // P-Preferred-Identity
    it = msg.headers.find("P-Preferred-Identity");
    if (it != msg.headers.end()) {
        msg.p_preferred_identity = it->second;
    }
    
    // P-Early-Media
    it = msg.headers.find("P-Early-Media");
    if (it != msg.headers.end()) {
        msg.p_early_media = it->second;
    }
}

void SipParser::parseImsHeaders(SipMessage& msg) {
    // Session-Expires
    auto it = msg.headers.find("Session-Expires");
    if (it != msg.headers.end()) {
        std::istringstream iss(it->second);
        uint32_t expires;
        if (iss >> expires) {
            msg.session_expires = expires;
            
            // Check for refresher parameter
            size_t refresher_pos = it->second.find("refresher=");
            if (refresher_pos != std::string::npos) {
                msg.session_expires_refresher = it->second.substr(refresher_pos + 10, 3);
            }
        }
    }
    
    // Min-SE
    it = msg.headers.find("Min-SE");
    if (it != msg.headers.end()) {
        std::istringstream iss(it->second);
        uint32_t min_se;
        if (iss >> min_se) {
            msg.min_se = min_se;
        }
    }
    
    // Path
    it = msg.headers.find("Path");
    if (it != msg.headers.end()) {
        msg.path = splitCommaList(it->second);
    }
    
    // Service-Route
    it = msg.headers.find("Service-Route");
    if (it != msg.headers.end()) {
        msg.service_route = splitCommaList(it->second);
    }
    
    // Require
    it = msg.headers.find("Require");
    if (it != msg.headers.end()) {
        msg.require = splitCommaList(it->second);
    }
    
    // Supported
    it = msg.headers.find("Supported");
    if (it != msg.headers.end()) {
        msg.supported = splitCommaList(it->second);
    }
    
    // Allow
    it = msg.headers.find("Allow");
    if (it != msg.headers.end()) {
        msg.allow = splitCommaList(it->second);
    }
    
    // Privacy
    it = msg.headers.find("Privacy");
    if (it != msg.headers.end()) {
        msg.privacy = splitCommaList(it->second);
    }
    
    // Event
    it = msg.headers.find("Event");
    if (it != msg.headers.end()) {
        msg.event = it->second;
    }
    
    // Subscription-State
    it = msg.headers.find("Subscription-State");
    if (it != msg.headers.end()) {
        msg.subscription_state = it->second;
    }
}

std::vector<std::string> SipParser::splitCommaList(const std::string& str) {
    std::vector<std::string> result;
    std::istringstream iss(str);
    std::string item;
    
    while (std::getline(iss, item, ',')) {
        item.erase(0, item.find_first_not_of(" \t"));
        item.erase(item.find_last_not_of(" \t") + 1);
        if (!item.empty()) {
            result.push_back(item);
        }
    }
    
    return result;
}

} // namespace callflow
```

**Integration with Existing Code:**

Update `SipParser::parse()` to call new parsing functions:
```cpp
std::optional<SipMessage> SipParser::parse(const uint8_t* data, size_t len) {
    // ... existing parsing ...
    
    // NEW: Parse 3GPP P-headers
    parsePHeaders(msg);
    
    // NEW: Parse IMS-specific headers
    parseImsHeaders(msg);
    
    // NEW: Parse security headers
    parseSecurityHeaders(msg);
    
    return msg;
}
```

**Correlation with Diameter:**

When processing SIP messages with P-Charging-Vector:
```cpp
void SessionCorrelator::processSipMessage(const SipMessage& sip_msg, const std::string& session_id) {
    // Extract ICID from P-Charging-Vector
    if (sip_msg.p_charging_vector.has_value()) {
        std::string icid = sip_msg.p_charging_vector->icid_value;
        
        // Store ICID for correlation with Diameter Ro/Rf charging
        charging_correlator_.linkSipToDiameter(session_id, icid);
        
        LOG_INFO("SIP Call-ID " << sip_msg.call_id << " linked to ICID " << icid);
    }
    
    // Extract cell ID from P-Access-Network-Info for location tracking
    if (sip_msg.p_access_network_info.has_value() && 
        sip_msg.p_access_network_info->cell_id.has_value()) {
        std::string cell_id = sip_msg.p_access_network_info->cell_id.value();
        location_tracker_.updateLocation(session_id, cell_id);
    }
}
```

**Testing Requirements:**

1. Unit test: Parse P-Asserted-Identity with multiple identities
2. Unit test: Parse P-Access-Network-Info for LTE (3GPP-E-UTRAN)
3. Unit test: Parse P-Access-Network-Info for 5G (3GPP-NR)
4. Unit test: Parse P-Charging-Vector and extract ICID
5. Unit test: Parse Security-Client with IPSec parameters
6. Unit test: Parse SDP QoS preconditions (a=curr, a=des)
7. Unit test: Parse Session-Expires with refresher
8. Integration test: Complete VoLTE REGISTER with all P-headers
9. Integration test: Complete VoLTE INVITE with SDP preconditions
10. Integration test: VoNR call (5G) with 3GPP-NR access type

Create test vectors:
```cpp
// VoLTE REGISTER with P-headers
const char* volte_register = 
    "REGISTER sip:ims.example.com SIP/2.0\r\n"
    "Via: SIP/2.0/UDP 192.0.2.100:5060;branch=z9hG4bK776asdhds\r\n"
    "From: <sip:user@ims.example.com>;tag=1928301774\r\n"
    "To: <sip:user@ims.example.com>\r\n"
    "Call-ID: a84b4c76e66710@192.0.2.100\r\n"
    "CSeq: 314159 REGISTER\r\n"
    "Contact: <sip:user@192.0.2.100:5060>;expires=600000\r\n"
    "P-Access-Network-Info: 3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=234150999999999\r\n"
    "P-Visited-Network-ID: \"Visited Network\"\r\n"
    "Path: <sip:pcscf.example.com;lr>\r\n"
    "Require: path, sec-agree\r\n"
    "Supported: 100rel, timer, gruu\r\n"
    "Security-Client: ipsec-3gpp; alg=hmac-sha-1-96; spi-c=1234; spi-s=5678; port-c=5062; port-s=5064\r\n"
    "Content-Length: 0\r\n\r\n";

// VoLTE INVITE with P-Charging-Vector
const char* volte_invite =
    "INVITE sip:+1234567890@ims.example.com SIP/2.0\r\n"
    "Via: SIP/2.0/UDP 192.0.2.100:5060;branch=z9hG4bKnashds8\r\n"
    "From: <sip:alice@ims.example.com>;tag=1928301774\r\n"
    "To: <tel:+1234567890>\r\n"
    "Call-ID: volte-call-12345@192.0.2.100\r\n"
    "CSeq: 1 INVITE\r\n"
    "Contact: <sip:alice@192.0.2.100:5060>\r\n"
    "P-Asserted-Identity: \"Alice\" <sip:alice@ims.example.com>, <tel:+1987654321>\r\n"
    "P-Access-Network-Info: 3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=234150999999999\r\n"
    "P-Charging-Vector: icid-value=AyretyU0dm+6O2IrT5tAFrbHLso=; icid-generated-at=192.0.2.1; orig-ioi=home1.net; term-ioi=home2.net\r\n"
    "P-Charging-Function-Addresses: ccf=192.0.2.10; ecf=192.0.2.20\r\n"
    "Session-Expires: 1800; refresher=uac\r\n"
    "Min-SE: 90\r\n"
    "Supported: 100rel, timer, precondition\r\n"
    "Require: 100rel, precondition\r\n"
    "Content-Type: application/sdp\r\n"
    "Content-Length: 450\r\n\r\n"
    "v=0\r\n"
    "o=alice 2890844526 2890844526 IN IP4 192.0.2.100\r\n"
    "s=VoLTE Call\r\n"
    "c=IN IP4 192.0.2.100\r\n"
    "b=AS:64\r\n"
    "b=TIAS:64000\r\n"
    "t=0 0\r\n"
    "m=audio 49170 RTP/AVP 97 98\r\n"
    "a=rtpmap:97 AMR/8000/1\r\n"
    "a=fmtp:97 mode-set=0,2,4,7; mode-change-period=2\r\n"
    "a=rtpmap:98 telephone-event/8000\r\n"
    "a=fmtp:98 0-15\r\n"
    "a=ptime:20\r\n"
    "a=maxptime:40\r\n"
    "a=curr:qos local none\r\n"
    "a=curr:qos remote none\r\n"
    "a=des:qos mandatory local sendrecv\r\n"
    "a=des:qos mandatory remote sendrecv\r\n"
    "a=sendrecv\r\n";
```

**Acceptance Criteria:**
- ✅ Parse all 8 critical P-headers
- ✅ Extract P-Charging-Vector ICID for billing correlation
- ✅ Parse P-Access-Network-Info for LTE and 5G
- ✅ Parse Security-Client/Server/Verify for IPSec
- ✅ Parse IMS session timer headers
- ✅ Parse Path and Service-Route for IMS routing
- ✅ Parse enhanced SDP (QoS preconditions, bandwidth)
- ✅ Support VoLTE and VoNR scenarios
- ✅ Unit test coverage > 90%
- ✅ Correlation with Diameter charging (via ICID)

**Performance:**
- Parse rate: 50,000+ SIP messages/sec (including P-headers)
- Memory: < 1KB per parsed message
- Latency: < 20µs per message

Please implement with comprehensive P-header parsing and thorough testing with real VoLTE/VoNR captures. The P-Charging-Vector ICID is CRITICAL for end-to-end billing correlation with Diameter Ro/Rf interfaces.
```

---

### PROMPT 7: Procedure State Machines for Standard 3GPP Flows

```markdown
# Procedure State Machine Implementation
## nDPI Callflow Visualizer - Recognizing Standard Telecom Procedures

**Context:**
I'm building the nDPI Callflow Visualizer. This component implements procedure state machines that recognize and track standard 3GPP telecommunication flows like LTE Attach, 5G Registration, X2 Handover, VoLTE Call Setup, etc. State machines detect when a procedure begins, track its progress through expected message sequences, calculate timing metrics, and flag deviations from normal flows.

This is essential for:
- Automatic procedure classification (Attach vs Handover vs Call)
- Step-by-step progress tracking
- Latency measurement at each step
- Failure detection (incomplete procedures)
- Deviation detection (unexpected messages)

**Requirements:**

1. **State Machine Framework**
   
   Generic state machine base class:
   ```cpp
   class ProcedureStateMachine {
   public:
       enum class State {
           IDLE,
           // Procedure-specific states defined by subclasses
       };
       
       enum class Trigger {
           // Message types that trigger state transitions
       };
       
       struct Transition {
           State from_state;
           Trigger trigger;
           State to_state;
           std::optional<std::string> expected_message;
           std::optional<std::chrono::milliseconds> timeout;
       };
       
       virtual ~ProcedureStateMachine() = default;
       
       // Process new message
       virtual bool processMessage(const SessionMessageRef& msg) = 0;
       
       // Check if procedure is complete
       virtual bool isComplete() const = 0;
       
       // Check if procedure failed
       virtual bool isFailed() const = 0;
       
       // Get current state
       virtual State getCurrentState() const = 0;
       
       // Get procedure metrics
       virtual nlohmann::json getMetrics() const = 0;
       
       // Get procedure timeline
       virtual std::vector<ProcedureStep> getSteps() const = 0;
   };
   
   struct ProcedureStep {
       std::string step_name;
       MessageType message_type;
       std::chrono::system_clock::time_point timestamp;
       std::optional<std::chrono::milliseconds> latency_from_previous;
       bool expected;  // Was this message expected at this step?
   };
   ```

2. **LTE Attach Procedure State Machine**
   
   Expected message sequence:
   ```
   1. RRC Connection Request (optional, often not in PCAP)
   2. S1AP: Initial UE Message → NAS: Attach Request
   3. S1AP: Downlink NAS Transport → NAS: Authentication Request
   4. S1AP: Uplink NAS Transport → NAS: Authentication Response
   5. S1AP: Downlink NAS Transport → NAS: Security Mode Command
   6. S1AP: Uplink NAS Transport → NAS: Security Mode Complete
   7. GTPv2-C: Create Session Request (S11: MME → S-GW)
   8. GTPv2-C: Create Session Response (S11: S-GW → MME)
   9. S1AP: Initial Context Setup Request (MME → eNodeB)
   10. S1AP: Initial Context Setup Response (eNodeB → MME)
   11. S1AP: Downlink NAS Transport → NAS: Attach Accept
   12. S1AP: Uplink NAS Transport → NAS: Attach Complete
   13. GTP-U: User data starts flowing (S1-U, S5/S8)
   ```
   
   States:
   ```cpp
   enum class LteAttachState {
       IDLE,
       ATTACH_REQUESTED,
       AUTHENTICATION_IN_PROGRESS,
       AUTHENTICATION_COMPLETE,
       SECURITY_MODE_IN_PROGRESS,
       SECURITY_MODE_COMPLETE,
       GTP_SESSION_CREATION_IN_PROGRESS,
       GTP_SESSION_CREATED,
       INITIAL_CONTEXT_SETUP_IN_PROGRESS,
       ATTACH_ACCEPTED,
       ATTACHED,  // Attach Complete received
       FAILED
   };
   ```
   
   Timing metrics:
   ```cpp
   struct LteAttachMetrics {
       std::chrono::milliseconds attach_request_to_auth_request;    // Target: < 100ms
       std::chrono::milliseconds auth_request_to_auth_response;     // Target: < 100ms
       std::chrono::milliseconds auth_to_security_mode;             // Target: < 100ms
       std::chrono::milliseconds security_mode_to_gtp_create;       // Target: < 100ms
       std::chrono::milliseconds gtp_create_to_gtp_response;        // Target: < 200ms
       std::chrono::milliseconds gtp_response_to_context_setup;     // Target: < 50ms
       std::chrono::milliseconds context_setup_to_attach_accept;    // Target: < 100ms
       std::chrono::milliseconds attach_accept_to_complete;         // Target: < 100ms
       std::chrono::milliseconds total_attach_time;                 // Target: < 1000ms
   };
   ```

3. **5G Registration Procedure State Machine**
   
   Expected sequence:
   ```
   1. NGAP: Initial UE Message → 5G NAS: Registration Request
   2. NGAP: Downlink NAS Transport → 5G NAS: Authentication Request
   3. NGAP: Uplink NAS Transport → 5G NAS: Authentication Response
   4. NGAP: Downlink NAS Transport → 5G NAS: Security Mode Command
   5. NGAP: Uplink NAS Transport → 5G NAS: Security Mode Complete
   6. NGAP: Initial Context Setup Request
   7. NGAP: Initial Context Setup Response
   8. 5G NAS: Registration Accept
   9. 5G NAS: Registration Complete
   10. PFCP: Session Establishment Request (N4: SMF → UPF)
   11. PFCP: Session Establishment Response
   12. 5G NAS: PDU Session Establishment Request
   13. 5G NAS: PDU Session Establishment Accept
   ```
   
   Similar state enum and metrics as LTE Attach

4. **X2 Handover Procedure State Machine**
   
   Expected sequence:
   ```
   1. X2AP: Handover Request (Source eNodeB → Target eNodeB)
   2. X2AP: Handover Request Acknowledge
   3. S1AP: Downlink S1 CDMA2000 Tunneling (optional)
   4. X2AP: SN Status Transfer (Source → Target)
   5. S1AP: Path Switch Request (Target eNodeB → MME)
   6. GTPv2-C: Modify Bearer Request (MME → S-GW, update TEIDs)
   7. GTPv2-C: Modify Bearer Response
   8. S1AP: Path Switch Request Acknowledge
   9. X2AP: UE Context Release (Target → Source)
   10. GTP-U: Data now flows via new path (new TEID)
   ```
   
   States:
   ```cpp
   enum class X2HandoverState {
       IDLE,
       HANDOVER_REQUESTED,
       HANDOVER_PREPARED,
       SN_STATUS_TRANSFERRED,
       PATH_SWITCH_REQUESTED,
       BEARER_MODIFIED,
       HANDOVER_COMPLETE,
       CONTEXT_RELEASED,
       FAILED
   };
   ```
   
   Metrics:
   ```cpp
   struct X2HandoverMetrics {
       std::chrono::milliseconds handover_request_to_ack;        // Target: < 50ms
       std::chrono::milliseconds path_switch_to_bearer_modify;   // Target: < 100ms
       std::chrono::milliseconds bearer_modify_latency;          // Target: < 100ms
       std::chrono::milliseconds total_handover_time;            // Target: < 500ms
       uint32_t old_teid_s1u;
       uint32_t new_teid_s1u;
       bool interruption_time_met;  // < 27.5ms for intra-frequency
   };
   ```

5. **S1 Handover Procedure State Machine**
   
   Expected sequence (Source → Target via MME):
   ```
   1. S1AP: Handover Required (Source eNodeB → MME)
   2. S1AP: Handover Request (MME → Target eNodeB)
   3. S1AP: Handover Request Acknowledge (Target → MME)
   4. S1AP: Handover Command (MME → Source eNodeB)
   5. S1AP: Handover Notify (Target eNodeB → MME)
   6. GTPv2-C: Modify Bearer Request (MME → S-GW)
   7. GTPv2-C: Modify Bearer Response
   8. S1AP: UE Context Release Command (MME → Source eNodeB)
   9. S1AP: UE Context Release Complete
   ```

6. **VoLTE Call Setup Procedure State Machine**
   
   Expected sequence:
   ```
   1. SIP: INVITE (UE → P-CSCF)
   2. SIP: 100 Trying
   3. Diameter Rx: AAR (P-CSCF → PCRF) - Request for media resources
   4. Diameter Rx: AAA (PCRF → P-CSCF) - Authorized
   5. Diameter Gx: RAR (PCRF → P-GW) - Install policy
   6. Diameter Gx: RAA (P-GW → PCRF) - Acknowledged
   7. GTPv2-C: Create Bearer Request (Dedicated bearer for VoLTE)
   8. GTPv2-C: Create Bearer Response
   9. SIP: 180 Ringing
   10. SIP: 200 OK (Call accepted)
   11. SIP: ACK
   12. RTP: Media flows start
   13. RTCP: Quality feedback
   ```
   
   States:
   ```cpp
   enum class VoLteCallState {
       IDLE,
       INVITE_SENT,
       TRYING_RECEIVED,
       MEDIA_AUTHORIZATION_IN_PROGRESS,
       POLICY_INSTALLED,
       DEDICATED_BEARER_CREATION_IN_PROGRESS,
       DEDICATED_BEARER_CREATED,
       RINGING,
       CALL_CONNECTED,
       MEDIA_ACTIVE,
       CALL_RELEASED,
       FAILED
   };
   ```
   
   Metrics:
   ```cpp
   struct VoLteCallMetrics {
       std::chrono::milliseconds invite_to_trying;               // Target: < 100ms
       std::chrono::milliseconds media_authorization_time;       // Rx AAR to AAA
       std::chrono::milliseconds policy_installation_time;       // Gx RAR to RAA
       std::chrono::milliseconds dedicated_bearer_setup_time;    // GTP Create Bearer
       std::chrono::milliseconds post_dial_delay;                // INVITE to 180 Ringing
       std::chrono::milliseconds call_setup_time;                // INVITE to 200 OK
       std::chrono::milliseconds answer_to_media;                // 200 OK to RTP
       uint32_t dedicated_bearer_teid;
       uint8_t dedicated_bearer_qci;  // Should be QCI 1 for VoLTE voice
       std::string icid;  // From P-Charging-Vector for billing correlation
   };
   ```

7. **PDU Session Establishment (5G) State Machine**
   
   Expected sequence:
   ```
   1. 5G NAS: PDU Session Establishment Request
   2. HTTP/2 SBI: Nsmf_PDUSession_CreateSMContext (AMF → SMF)
   3. HTTP/2 SBI: Nudm_SDM_Get (SMF → UDM) - Get subscription data
   4. PFCP: Session Establishment Request (SMF → UPF)
   5. PFCP: Session Establishment Response
   6. HTTP/2 SBI: Npcf_SMPolicyControl_Create (SMF → PCF) - Get PCC rules
   7. HTTP/2 SBI: Namf_Communication_N1N2MessageTransfer (SMF → AMF)
   8. NGAP: PDU Session Resource Setup Request (AMF → gNB)
   9. NGAP: PDU Session Resource Setup Response
   10. 5G NAS: PDU Session Establishment Accept
   11. GTP-U: User data starts on N3 interface
   ```

**File Structure:**
```
include/correlation/
  procedure_state_machine.h      // Base class
  lte_attach_machine.h
  fiveg_registration_machine.h
  x2_handover_machine.h
  s1_handover_machine.h
  volte_call_machine.h
  pdu_session_machine.h
  procedure_detector.h           // Auto-detect procedures

src/correlation/
  procedure_state_machine.cpp
  lte_attach_machine.cpp
  fiveg_registration_machine.cpp
  x2_handover_machine.cpp
  s1_handover_machine.cpp
  volte_call_machine.cpp
  pdu_session_machine.cpp
  procedure_detector.cpp

tests/unit/
  test_lte_attach_machine.cpp
  test_x2_handover_machine.cpp
  test_volte_call_machine.cpp

tests/integration/
  test_complete_lte_attach.cpp
  test_complete_volte_call.cpp
```

**Implementation Guide:**

Create `lte_attach_machine.h`:
```cpp
#pragma once
#include "procedure_state_machine.h"

namespace callflow {
namespace correlation {

class LteAttachMachine : public ProcedureStateMachine {
public:
    enum class State {
        IDLE,
        ATTACH_REQUESTED,
        AUTHENTICATION_IN_PROGRESS,
        AUTHENTICATION_COMPLETE,
        SECURITY_MODE_IN_PROGRESS,
        SECURITY_MODE_COMPLETE,
        GTP_SESSION_CREATION_IN_PROGRESS,
        GTP_SESSION_CREATED,
        INITIAL_CONTEXT_SETUP_IN_PROGRESS,
        ATTACH_ACCEPTED,
        ATTACHED,
        FAILED
    };
    
    struct Metrics {
        std::chrono::milliseconds attach_request_to_auth_request{0};
        std::chrono::milliseconds auth_request_to_auth_response{0};
        std::chrono::milliseconds auth_to_security_mode{0};
        std::chrono::milliseconds security_mode_to_gtp_create{0};
        std::chrono::milliseconds gtp_create_to_gtp_response{0};
        std::chrono::milliseconds gtp_response_to_context_setup{0};
        std::chrono::milliseconds context_setup_to_attach_accept{0};
        std::chrono::milliseconds attach_accept_to_complete{0};
        std::chrono::milliseconds total_attach_time{0};
        
        // Identifiers
        std::optional<std::string> imsi;
        std::optional<uint32_t> mme_ue_s1ap_id;
        std::optional<uint32_t> enb_ue_s1ap_id;
        std::optional<uint32_t> teid_s1u;
        std::optional<std::string> ue_ip;
        
        nlohmann::json toJson() const;
    };
    
    LteAttachMachine();
    
    bool processMessage(const SessionMessageRef& msg) override;
    bool isComplete() const override { return current_state_ == State::ATTACHED; }
    bool isFailed() const override { return current_state_ == State::FAILED; }
    State getCurrentState() const { return current_state_; }
    
    Metrics getMetrics() const { return metrics_; }
    std::vector<ProcedureStep> getSteps() const override;
    nlohmann::json toJson() const;
    
private:
    State current_state_ = State::IDLE;
    Metrics metrics_;
    std::vector<ProcedureStep> steps_;
    
    std::chrono::system_clock::time_point attach_request_time_;
    std::chrono::system_clock::time_point last_message_time_;
    
    void transitionTo(State new_state, const SessionMessageRef& msg);
    void recordStep(const std::string& step_name, const SessionMessageRef& msg, bool expected = true);
    void calculateMetrics();
};

} // namespace correlation
} // namespace callflow
```

Create `lte_attach_machine.cpp`:
```cpp
#include "correlation/lte_attach_machine.h"
#include "common/logger.h"

namespace callflow {
namespace correlation {

LteAttachMachine::LteAttachMachine() {
    LOG_DEBUG("LTE Attach state machine created");
}

bool LteAttachMachine::processMessage(const SessionMessageRef& msg) {
    bool state_changed = false;
    
    switch (current_state_) {
        case State::IDLE:
            if (msg.message_type == MessageType::S1AP_INITIAL_UE_MESSAGE) {
                // Check if NAS PDU contains Attach Request
                if (msg.parsed_data.contains("nas") && 
                    msg.parsed_data["nas"].contains("message_type") &&
                    msg.parsed_data["nas"]["message_type"] == "ATTACH_REQUEST") {
                    
                    attach_request_time_ = msg.timestamp;
                    last_message_time_ = msg.timestamp;
                    
                    // Extract IMSI
                    if (msg.parsed_data["nas"].contains("mobile_identity") &&
                        msg.parsed_data["nas"]["mobile_identity"].contains("imsi")) {
                        metrics_.imsi = msg.parsed_data["nas"]["mobile_identity"]["imsi"].get<std::string>();
                    }
                    
                    // Extract MME-UE-S1AP-ID
                    if (msg.parsed_data.contains("mme_ue_s1ap_id")) {
                        metrics_.mme_ue_s1ap_id = msg.parsed_data["mme_ue_s1ap_id"].get<uint32_t>();
                    }
                    
                    recordStep("Attach Request", msg, true);
                    transitionTo(State::ATTACH_REQUESTED, msg);
                    state_changed = true;
                }
            }
            break;
        
        case State::ATTACH_REQUESTED:
            if (msg.message_type == MessageType::S1AP_DOWNLINK_NAS_TRANSPORT &&
                msg.parsed_data.contains("nas") &&
                msg.parsed_data["nas"]["message_type"] == "AUTHENTICATION_REQUEST") {
                
                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                    msg.timestamp - last_message_time_);
                metrics_.attach_request_to_auth_request = duration;
                last_message_time_ = msg.timestamp;
                
                recordStep("Authentication Request", msg, true);
                transitionTo(State::AUTHENTICATION_IN_PROGRESS, msg);
                state_changed = true;
            }
            break;
        
        case State::AUTHENTICATION_IN_PROGRESS:
            if (msg.message_type == MessageType::S1AP_UPLINK_NAS_TRANSPORT &&
                msg.parsed_data.contains("nas") &&
                msg.parsed_data["nas"]["message_type"] == "AUTHENTICATION_RESPONSE") {
                
                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                    msg.timestamp - last_message_time_);
                metrics_.auth_request_to_auth_response = duration;
                last_message_time_ = msg.timestamp;
                
                recordStep("Authentication Response", msg, true);
                transitionTo(State::AUTHENTICATION_COMPLETE, msg);
                state_changed = true;
            }
            break;
        
        case State::AUTHENTICATION_COMPLETE:
            if (msg.message_type == MessageType::S1AP_DOWNLINK_NAS_TRANSPORT &&
                msg.parsed_data.contains("nas") &&
                msg.parsed_data["nas"]["message_type"] == "SECURITY_MODE_COMMAND") {
                
                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                    msg.timestamp - last_message_time_);
                metrics_.auth_to_security_mode = duration;
                last_message_time_ = msg.timestamp;
                
                recordStep("Security Mode Command", msg, true);
                transitionTo(State::SECURITY_MODE_IN_PROGRESS, msg);
                state_changed = true;
            }
            break;
        
        case State::SECURITY_MODE_IN_PROGRESS:
            if (msg.message_type == MessageType::S1AP_UPLINK_NAS_TRANSPORT &&
                msg.parsed_data.contains("nas") &&
                msg.parsed_data["nas"]["message_type"] == "SECURITY_MODE_COMPLETE") {
                
                recordStep("Security Mode Complete", msg, true);
                transitionTo(State::SECURITY_MODE_COMPLETE, msg);
                last_message_time_ = msg.timestamp;
                state_changed = true;
            }
            break;
        
        case State::SECURITY_MODE_COMPLETE:
            if (msg.message_type == MessageType::GTP_CREATE_SESSION_REQ) {
                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                    msg.timestamp - last_message_time_);
                metrics_.security_mode_to_gtp_create = duration;
                last_message_time_ = msg.timestamp;
                
                recordStep("GTP Create Session Request", msg, true);
                transitionTo(State::GTP_SESSION_CREATION_IN_PROGRESS, msg);
                state_changed = true;
            }
            break;
        
        case State::GTP_SESSION_CREATION_IN_PROGRESS:
            if (msg.message_type == MessageType::GTP_CREATE_SESSION_RESP) {
                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                    msg.timestamp - last_message_time_);
                metrics_.gtp_create_to_gtp_response = duration;
                last_message_time_ = msg.timestamp;
                
                // Extract TEID and UE IP
                if (msg.parsed_data.contains("fteids")) {
                    // Find S1-U TEID
                    for (const auto& fteid : msg.parsed_data["fteids"]) {
                        if (fteid.contains("interface_type") && 
                            fteid["interface_type"].get<std::string>().find("S1-U") != std::string::npos) {
                            metrics_.teid_s1u = fteid["teid"].get<uint32_t>();
                            break;
                        }
                    }
                }
                if (msg.parsed_data.contains("ue_ip_address")) {
                    metrics_.ue_ip = msg.parsed_data["ue_ip_address"]["ipv4"].get<std::string>();
                }
                
                recordStep("GTP Create Session Response", msg, true);
                transitionTo(State::GTP_SESSION_CREATED, msg);
                state_changed = true;
            }
            break;
        
        case State::GTP_SESSION_CREATED:
            if (msg.message_type == MessageType::S1AP_INITIAL_CONTEXT_SETUP_REQ) {
                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                    msg.timestamp - last_message_time_);
                metrics_.gtp_response_to_context_setup = duration;
                last_message_time_ = msg.timestamp;
                
                recordStep("Initial Context Setup Request", msg, true);
                transitionTo(State::INITIAL_CONTEXT_SETUP_IN_PROGRESS, msg);
                state_changed = true;
            }
            break;
        
        case State::INITIAL_CONTEXT_SETUP_IN_PROGRESS:
            if (msg.message_type == MessageType::S1AP_INITIAL_CONTEXT_SETUP_RESP) {
                recordStep("Initial Context Setup Response", msg, true);
                last_message_time_ = msg.timestamp;
            } else if (msg.message_type == MessageType::S1AP_DOWNLINK_NAS_TRANSPORT &&
                       msg.parsed_data.contains("nas") &&
                       msg.parsed_data["nas"]["message_type"] == "ATTACH_ACCEPT") {
                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                    msg.timestamp - last_message_time_);
                metrics_.context_setup_to_attach_accept = duration;
                last_message_time_ = msg.timestamp;
                
                recordStep("Attach Accept", msg, true);
                transitionTo(State::ATTACH_ACCEPTED, msg);
                state_changed = true;
            }
            break;
        
        case State::ATTACH_ACCEPTED:
            if (msg.message_type == MessageType::S1AP_UPLINK_NAS_TRANSPORT &&
                msg.parsed_data.contains("nas") &&
                msg.parsed_data["nas"]["message_type"] == "ATTACH_COMPLETE") {
                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                    msg.timestamp - last_message_time_);
                metrics_.attach_accept_to_complete = duration;
                
                // Calculate total attach time
                metrics_.total_attach_time = std::chrono::duration_cast<std::chrono::milliseconds>(
                    msg.timestamp - attach_request_time_);
                
                recordStep("Attach Complete", msg, true);
                transitionTo(State::ATTACHED, msg);
                state_changed = true;
                
                LOG_INFO("LTE Attach completed for IMSI " << metrics_.imsi.value_or("unknown") 
                         << " in " << metrics_.total_attach_time.count() << "ms");
            }
            break;
        
        case State::ATTACHED:
            // Procedure complete, no more transitions
            break;
        
        case State::FAILED:
            // Procedure failed, no recovery
            break;
    }
    
    return state_changed;
}

void LteAttachMachine::transitionTo(State new_state, const SessionMessageRef& msg) {
    LOG_DEBUG("LTE Attach state: " << static_cast<int>(current_state_) 
              << " -> " << static_cast<int>(new_state));
    current_state_ = new_state;
}

void LteAttachMachine::recordStep(const std::string& step_name, 
                                   const SessionMessageRef& msg, 
                                   bool expected) {
    ProcedureStep step;
    step.step_name = step_name;
    step.message_type = msg.message_type;
    step.timestamp = msg.timestamp;
    step.expected = expected;
    
    if (!steps_.empty()) {
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            msg.timestamp - steps_.back().timestamp);
        step.latency_from_previous = duration;
    }
    
    steps_.push_back(step);
}

std::vector<ProcedureStep> LteAttachMachine::getSteps() const {
    return steps_;
}

nlohmann::json LteAttachMachine::toJson() const {
    nlohmann::json j;
    j["procedure"] = "LTE_ATTACH";
    j["state"] = static_cast<int>(current_state_);
    j["complete"] = isComplete();
    j["failed"] = isFailed();
    j["metrics"] = metrics_.toJson();
    
    nlohmann::json steps_json = nlohmann::json::array();
    for (const auto& step : steps_) {
        nlohmann::json step_json;
        step_json["name"] = step.step_name;
        step_json["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
            step.timestamp.time_since_epoch()).count();
        if (step.latency_from_previous.has_value()) {
            step_json["latency_ms"] = step.latency_from_previous->count();
        }
        step_json["expected"] = step.expected;
        steps_json.push_back(step_json);
    }
    j["steps"] = steps_json;
    
    return j;
}

nlohmann::json LteAttachMachine::Metrics::toJson() const {
    nlohmann::json j;
    
    if (imsi.has_value()) j["imsi"] = imsi.value();
    if (mme_ue_s1ap_id.has_value()) j["mme_ue_s1ap_id"] = mme_ue_s1ap_id.value();
    if (teid_s1u.has_value()) j["teid_s1u"] = teid_s1u.value();
    if (ue_ip.has_value()) j["ue_ip"] = ue_ip.value();
    
    j["timings"] = {
        {"attach_to_auth_ms", attach_request_to_auth_request.count()},
        {"auth_req_to_resp_ms", auth_request_to_auth_response.count()},
        {"auth_to_security_ms", auth_to_security_mode.count()},
        {"security_to_gtp_ms", security_mode_to_gtp_create.count()},
        {"gtp_create_latency_ms", gtp_create_to_gtp_response.count()},
        {"gtp_to_context_setup_ms", gtp_response_to_context_setup.count()},
        {"context_to_accept_ms", context_setup_to_attach_accept.count()},
        {"accept_to_complete_ms", attach_accept_to_complete.count()},
        {"total_attach_time_ms", total_attach_time.count()}
    };
    
    return j;
}

} // namespace correlation
} // namespace callflow
```

**Integration with SessionCorrelator:**

```cpp
class EnhancedSessionCorrelator {
private:
    std::unordered_map<std::string, std::unique_ptr<LteAttachMachine>> lte_attach_machines_;
    std::unordered_map<std::string, std::unique_ptr<VoLteCallMachine>> volte_call_machines_;
    // ... other procedure machines
    
public:
    void addMessage(const SessionMessageRef& msg) {
        // ... existing correlation ...
        
        // Try to match with existing procedures
        for (auto& [session_id, machine] : lte_attach_machines_) {
            if (machine->processMessage(msg)) {
                if (machine->isComplete()) {
                    LOG_INFO("LTE Attach completed: " << machine->toJson().dump());
                    // Store completed procedure
                }
            }
        }
        
        // Try to start new procedures
        if (msg.message_type == MessageType::S1AP_INITIAL_UE_MESSAGE) {
            auto machine = std::make_unique<LteAttachMachine>();
            if (machine->processMessage(msg)) {
                lte_attach_machines_[session_id] = std::move(machine);
            }
        }
    }
};
```

**Testing Requirements:**

1. Unit test: LTE Attach state machine with complete sequence
2. Unit test: LTE Attach with authentication failure
3. Unit test: X2 Handover complete procedure
4. Unit test: VoLTE call setup with Diameter Rx/Gx
5. Integration test: Real PCAP with multiple concurrent procedures
6. Performance test: 1000 concurrent state machines

**Acceptance Criteria:**
- ✅ Implement 6+ standard procedure state machines
- ✅ Automatically detect procedure start
- ✅ Track state transitions accurately
- ✅ Calculate detailed timing metrics
- ✅ Detect incomplete/failed procedures
- ✅ Flag unexpected messages
- ✅ Support concurrent procedures (1000+)
- ✅ Unit test coverage > 90%

**Performance:**
- State transition latency: < 100ns
- Memory: < 5KB per active procedure
- Support: 10,000+ concurrent procedures

Please implement with comprehensive state tracking and detailed timing metrics for performance analysis.
```

---

Due to length constraints, I'll save this and continue with the remaining prompts. Let me present what we have so far.