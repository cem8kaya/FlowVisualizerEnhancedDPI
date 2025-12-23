# MILESTONE 11: DIAMETER Policy Interfaces (Gx/Rx/Gy)

**Duration:** 1.5 weeks  
**Priority:** High  
**Dependencies:** M3 (DIAMETER base parser)

## Objectives
- Implement DIAMETER Gx parser (Policy and Charging Control)
- Implement DIAMETER Rx parser (IMS QoS Authorization)
- Implement DIAMETER Gy parser (Online Charging)
- Support charging rule and media component parsing

## 3GPP References
- **Gx:** TS 29.212 - Policy and Charging Control over Gx reference point
- **Rx:** TS 29.214 - Policy and Charging Control over Rx reference point
- **Gy:** TS 32.299 - Diameter charging applications (Online Charging)

---

## PROMPT 11.1: DIAMETER Gx Interface Parser

```markdown
# DIAMETER Gx Interface Parser
## nDPI Callflow Visualizer - Policy and Charging Control

**Context:**
I'm enhancing the nDPI Callflow Visualizer. Gx is the interface between PCRF (Policy and Charging Rules Function) and PCEF (Policy and Charging Enforcement Function, typically the PGW/SMF). It's critical for:
- VoLTE: Installing QCI-1 dedicated bearers for voice
- Data sessions: Enforcing fair usage policies
- QoS management: Applying bandwidth limits and ARP

**3GPP Reference:** TS 29.212 (Policy and Charging Control over Gx)

**Requirements:**

1. **Gx Message Types and Application ID**

```cpp
// include/protocol_parsers/diameter/diameter_gx.h
#pragma once

#include "protocol_parsers/diameter_parser.h"

namespace callflow {
namespace diameter {

// Gx Application ID
static constexpr uint32_t GX_APPLICATION_ID = 16777238;

// Gx Command Codes
enum class GxCommandCode : uint32_t {
    CC_REQUEST = 272,   // CCR - Credit Control Request
    CC_ANSWER = 272,    // CCA - Credit Control Answer
    RE_AUTH_REQUEST = 258,  // RAR - Re-Auth Request
    RE_AUTH_ANSWER = 258    // RAA - Re-Auth Answer
};

// CC-Request-Type values (AVP 416)
enum class CcRequestType : uint32_t {
    INITIAL_REQUEST = 1,
    UPDATE_REQUEST = 2,
    TERMINATION_REQUEST = 3,
    EVENT_REQUEST = 4
};

// Gx AVP Codes (3GPP Vendor ID = 10415)
enum class GxAVPCode : uint32_t {
    // Session control (base DIAMETER)
    CC_REQUEST_TYPE = 416,
    CC_REQUEST_NUMBER = 415,
    
    // Subscription identification
    SUBSCRIPTION_ID = 443,
    SUBSCRIPTION_ID_DATA = 444,
    SUBSCRIPTION_ID_TYPE = 450,
    
    // Bearer management (3GPP)
    BEARER_IDENTIFIER = 1020,
    BEARER_OPERATION = 1021,
    DEFAULT_EPS_BEARER_QOS = 1049,
    
    // QoS-Information grouped AVP (3GPP)
    QOS_INFORMATION = 1016,
    QOS_CLASS_IDENTIFIER = 1028,
    MAX_REQUESTED_BANDWIDTH_UL = 516,
    MAX_REQUESTED_BANDWIDTH_DL = 515,
    GUARANTEED_BITRATE_UL = 1026,
    GUARANTEED_BITRATE_DL = 1025,
    
    // Allocation and Retention Priority (ARP)
    ALLOCATION_RETENTION_PRIORITY = 1034,
    PRIORITY_LEVEL = 1046,
    PRE_EMPTION_CAPABILITY = 1047,
    PRE_EMPTION_VULNERABILITY = 1048,
    
    // Charging Rules
    CHARGING_RULE_INSTALL = 1001,
    CHARGING_RULE_REMOVE = 1002,
    CHARGING_RULE_DEFINITION = 1003,
    CHARGING_RULE_BASE_NAME = 1004,
    CHARGING_RULE_NAME = 1005,
    
    // Flow information
    FLOW_INFORMATION = 1058,
    FLOW_DESCRIPTION = 507,
    FLOW_DIRECTION = 1080,
    
    // User identity and network info
    FRAMED_IP_ADDRESS = 8,
    FRAMED_IPV6_PREFIX = 97,
    CALLED_STATION_ID = 30,  // APN
    
    // Triggers and events
    EVENT_TRIGGER = 1006,
    
    // Results and reporting
    RULE_FAILURE_CODE = 1031,
    CHARGING_RULE_REPORT = 1018,
    PCC_RULE_STATUS = 1019,
    
    // Rating
    RATING_GROUP = 432,
    SERVICE_IDENTIFIER = 439,
    PRECEDENCE = 1010,
    
    // Usage monitoring
    USAGE_MONITORING_INFORMATION = 1067,
    MONITORING_KEY = 1066,
    GRANTED_SERVICE_UNIT = 431,
    USED_SERVICE_UNIT = 446
};

// Event Trigger values (TS 29.212 Section 5.3.7)
enum class EventTrigger : uint32_t {
    SGSN_CHANGE = 0,
    QOS_CHANGE = 1,
    RAT_CHANGE = 2,
    TFT_CHANGE = 3,
    PLMN_CHANGE = 4,
    LOSS_OF_BEARER = 5,
    RECOVERY_OF_BEARER = 6,
    IP_CAN_CHANGE = 7,
    QOS_CHANGE_EXCEEDING_AUTHORIZATION = 11,
    RAI_CHANGE = 12,
    USER_LOCATION_CHANGE = 13,
    NO_EVENT_TRIGGERS = 14,
    OUT_OF_CREDIT = 15,
    REALLOCATION_OF_CREDIT = 16,
    REVALIDATION_TIMEOUT = 17,
    UE_IP_ADDRESS_ALLOCATE = 18,
    UE_IP_ADDRESS_RELEASE = 19,
    DEFAULT_EPS_BEARER_QOS_CHANGE = 20,
    AN_GW_CHANGE = 21,
    SUCCESSFUL_RESOURCE_ALLOCATION = 22,
    RESOURCE_MODIFICATION_REQUEST = 23,
    PGW_TRACE_CONTROL = 24,
    UE_TIME_ZONE_CHANGE = 25,
    TAI_CHANGE = 26,
    ECGI_CHANGE = 27,
    CHARGING_CORRELATION_EXCHANGE = 28,
    APN_AMBR_MODIFICATION_FAILURE = 29,
    USER_CSG_INFORMATION_CHANGE = 30,
    USAGE_REPORT = 33,
    DEFAULT_EPS_BEARER_QOS_MODIFICATION_FAILURE = 34,
    USER_CSG_HYBRID_SUBSCRIBED_INFORMATION_CHANGE = 35,
    USER_CSG_HYBRID_UNSUBSCRIBED_INFORMATION_CHANGE = 36,
    ROUTING_RULE_CHANGE = 37,
    APPLICATION_START = 39,
    APPLICATION_STOP = 40,
    CS_TO_PS_HANDOVER = 42,
    UE_LOCAL_IP_ADDRESS_CHANGE = 43,
    HENB_LOCAL_IP_ADDRESS_CHANGE = 44,
    ACCESS_NETWORK_INFO_REPORT = 45,
    CREDIT_MANAGEMENT_SESSION_FAILURE = 46,
    DEFAULT_QOS_CHANGE = 47,
    CHANGE_OF_UE_PRESENCE_IN_PRESENCE_REPORTING_AREA_REPORT = 48
};

// Flow Description structure
struct FlowDescription {
    std::string description;    // IPFilterRule format (RFC 3588)
    enum class Direction { 
        UNSPECIFIED = 0,
        DOWNLINK = 1,  // IN - to UE
        UPLINK = 2,    // OUT - from UE
        BIDIRECTIONAL = 3 
    } direction = Direction::UNSPECIFIED;
    
    nlohmann::json toJson() const;
};

// Charging Rule Definition
struct ChargingRule {
    std::string rule_name;
    std::optional<std::string> rule_base_name;
    std::vector<FlowDescription> flows;
    
    // QoS parameters
    std::optional<uint8_t> qci;
    std::optional<uint32_t> max_bandwidth_ul;      // bits/sec
    std::optional<uint32_t> max_bandwidth_dl;      // bits/sec
    std::optional<uint32_t> guaranteed_bandwidth_ul; // bits/sec
    std::optional<uint32_t> guaranteed_bandwidth_dl; // bits/sec
    
    // Allocation Retention Priority
    std::optional<uint8_t> priority_level;         // 1-15 (1=highest)
    std::optional<bool> pre_emption_capability;    // can preempt others
    std::optional<bool> pre_emption_vulnerability; // can be preempted
    
    // Rating and charging
    std::optional<uint32_t> rating_group;
    std::optional<uint32_t> service_identifier;
    
    // Rule precedence
    std::optional<uint32_t> precedence;
    
    // Metering method
    enum class MeteringMethod {
        DURATION = 0,
        VOLUME = 1,
        DURATION_VOLUME = 2
    };
    std::optional<MeteringMethod> metering_method;
    
    // Online/offline charging
    std::optional<bool> online;
    std::optional<bool> offline;
    
    nlohmann::json toJson() const;
};

// QoS Information grouped AVP
struct QoSInformation {
    std::optional<uint8_t> qci;
    std::optional<uint32_t> max_bandwidth_ul;
    std::optional<uint32_t> max_bandwidth_dl;
    std::optional<uint32_t> guaranteed_bandwidth_ul;
    std::optional<uint32_t> guaranteed_bandwidth_dl;
    std::optional<uint32_t> apn_aggregate_max_bandwidth_ul;
    std::optional<uint32_t> apn_aggregate_max_bandwidth_dl;
    
    // ARP
    std::optional<uint8_t> priority_level;
    std::optional<bool> pre_emption_capability;
    std::optional<bool> pre_emption_vulnerability;
    
    nlohmann::json toJson() const;
};

// Gx CCR Message (PCEF → PCRF)
struct GxCCR {
    CcRequestType request_type;
    uint32_t request_number;
    std::string session_id;
    std::string origin_host;
    std::string origin_realm;
    std::string destination_realm;
    
    // Subscription ID (IMSI/MSISDN)
    std::optional<std::string> imsi;
    std::optional<std::string> msisdn;
    
    // Network information
    std::optional<std::string> framed_ip_address;
    std::optional<std::string> framed_ipv6_prefix;
    std::optional<std::string> called_station_id;  // APN
    std::optional<std::string> access_network_charging_identifier;
    
    // 3GPP user location
    std::optional<std::string> tgpp_user_location_info;  // hex encoded
    std::optional<std::string> rai;
    std::optional<uint32_t> rat_type;
    
    // Bearer
    std::optional<std::string> bearer_identifier;
    std::optional<uint8_t> bearer_operation;  // 0=establish, 1=modify, 2=release
    
    // Default QoS
    std::optional<QoSInformation> default_qos;
    
    // Event triggers that occurred
    std::vector<EventTrigger> event_triggers;
    
    // Usage reports
    std::vector<std::pair<std::string, uint64_t>> usage_reports; // monitoring_key → bytes
    
    nlohmann::json toJson() const;
};

// Gx CCA Message (PCRF → PCEF)
struct GxCCA {
    uint32_t result_code;
    std::optional<uint32_t> experimental_result_code;
    std::string session_id;
    CcRequestType request_type;
    uint32_t request_number;
    std::string origin_host;
    std::string origin_realm;
    
    // Rules to install
    std::vector<ChargingRule> rules_to_install;
    
    // Rule names to remove
    std::vector<std::string> rules_to_remove;
    
    // Default QoS for the session
    std::optional<QoSInformation> default_qos;
    
    // Event triggers to subscribe to
    std::vector<EventTrigger> event_triggers;
    
    // Revalidation time (seconds)
    std::optional<uint32_t> revalidation_time;
    
    nlohmann::json toJson() const;
};

// Gx RAR Message (PCRF → PCEF) - Push from PCRF
struct GxRAR {
    std::string session_id;
    std::string origin_host;
    std::string origin_realm;
    std::string destination_host;
    std::string destination_realm;
    uint32_t auth_application_id = GX_APPLICATION_ID;
    
    // Re-Auth-Request-Type
    enum class ReAuthRequestType : uint32_t {
        AUTHORIZE_ONLY = 0,
        AUTHORIZE_AUTHENTICATE = 1
    };
    ReAuthRequestType re_auth_request_type = ReAuthRequestType::AUTHORIZE_ONLY;
    
    // Rules to install
    std::vector<ChargingRule> rules_to_install;
    
    // Rules to remove
    std::vector<std::string> rules_to_remove;
    
    // QoS update
    std::optional<QoSInformation> default_qos;
    
    // Event trigger changes
    std::vector<EventTrigger> event_triggers_to_add;
    std::vector<EventTrigger> event_triggers_to_remove;
    
    // Session release cause
    std::optional<uint32_t> session_release_cause;
    
    nlohmann::json toJson() const;
};

// Gx RAA Message (PCEF → PCRF)
struct GxRAA {
    std::string session_id;
    uint32_t result_code;
    std::optional<uint32_t> experimental_result_code;
    std::string origin_host;
    std::string origin_realm;
    
    // Rule installation/removal reports
    struct RuleReport {
        std::string rule_name;
        enum class Status { ACTIVE = 0, INACTIVE = 1, REMOVED = 2 } status;
        std::optional<uint32_t> rule_failure_code;
    };
    std::vector<RuleReport> rule_reports;
    
    nlohmann::json toJson() const;
};

// Main Gx Parser Class
class DiameterGxParser {
public:
    static GxCCR parseCCR(const DiameterMessage& msg);
    static GxCCA parseCCA(const DiameterMessage& msg);
    static GxRAR parseRAR(const DiameterMessage& msg);
    static GxRAA parseRAA(const DiameterMessage& msg);
    
    static bool isGx(const DiameterMessage& msg) {
        return msg.header.application_id == GX_APPLICATION_ID;
    }
    
    static bool isCCR(const DiameterMessage& msg) {
        return msg.header.command_code == 272 && msg.header.flags.request;
    }
    
    static bool isCCA(const DiameterMessage& msg) {
        return msg.header.command_code == 272 && !msg.header.flags.request;
    }
    
    static bool isRAR(const DiameterMessage& msg) {
        return msg.header.command_code == 258 && msg.header.flags.request;
    }
    
    static bool isRAA(const DiameterMessage& msg) {
        return msg.header.command_code == 258 && !msg.header.flags.request;
    }
    
    static ChargingRule parseChargingRuleDefinition(const DiameterAVP& avp);
    static QoSInformation parseQoSInformation(const DiameterAVP& avp);
    static FlowDescription parseFlowDescription(const std::string& filter_rule);

private:
    static std::string parseSubscriptionId(const std::vector<DiameterAVP>& avps, uint32_t type);
    static std::vector<EventTrigger> parseEventTriggers(const std::vector<DiameterAVP>& avps);
    static std::string ipv4ToString(uint32_t ip);
};

}  // namespace diameter
}  // namespace callflow
```

**File Structure:**
```
include/protocol_parsers/diameter/
  diameter_gx.h
  gx_types.h

src/protocol_parsers/diameter/
  diameter_gx_parser.cpp
  gx_charging_rule_parser.cpp

tests/unit/
  test_diameter_gx.cpp
  test_gx_charging_rules.cpp

tests/pcaps/
  gx_ccr_initial.pcap
  gx_cca_with_rules.pcap
  gx_rar_volte_bearer.pcap
```

**Testing Requirements:**

1. Unit test: Parse CCR-Initial with IMSI/APN
2. Unit test: Parse CCA with charging rules
3. Unit test: Parse RAR for VoLTE bearer installation
4. Unit test: Parse RAA with rule reports
5. Unit test: Parse Charging-Rule-Definition grouped AVP
6. Unit test: Parse QoS-Information grouped AVP
7. Unit test: Extract IMSI from Subscription-Id
8. Unit test: Parse Flow-Description IPFilterRule
9. Integration test: Gx session for data (CCR-I/CCA-I/CCR-T/CCA-T)
10. Integration test: Gx RAR/RAA for VoLTE dedicated bearer

**Acceptance Criteria:**
- ✅ Parse all Gx message types (CCR/CCA/RAR/RAA)
- ✅ Extract charging rules with full QoS parameters
- ✅ Parse all event trigger types
- ✅ Extract subscription identifiers (IMSI/MSISDN)
- ✅ Support grouped AVPs (Charging-Rule-Definition, QoS-Information)
- ✅ Handle missing optional AVPs gracefully
- ✅ Unit test coverage > 90%

Please implement with comprehensive error handling for malformed AVPs and detailed logging.
```

---

## PROMPT 11.2: DIAMETER Rx Interface Parser

```markdown
# DIAMETER Rx Interface Parser
## nDPI Callflow Visualizer - IMS QoS Authorization

**Context:**
I'm enhancing the nDPI Callflow Visualizer. Rx is the interface between the Application Function (AF, typically P-CSCF for VoLTE) and the PCRF. It's used for:
- VoLTE call setup: Requesting QoS for voice media (QCI-1)
- IMS emergency calls: Priority handling
- Video calling: Requesting GBR bearers for video
- SDP-to-QoS mapping: Translating SDP media descriptions to bearer requirements

**3GPP Reference:** TS 29.214 (Policy and Charging Control over Rx reference point)

**Requirements:**

1. **Rx Message Types and Application ID**

```cpp
// include/protocol_parsers/diameter/diameter_rx.h
#pragma once

#include "protocol_parsers/diameter_parser.h"

namespace callflow {
namespace diameter {

// Rx Application ID (3GPP)
static constexpr uint32_t RX_APPLICATION_ID = 16777236;

// Rx Command Codes
enum class RxCommandCode : uint32_t {
    AA_REQUEST = 265,   // AAR - AA Request (AF → PCRF)
    AA_ANSWER = 265,    // AAA - AA Answer (PCRF → AF)
    RE_AUTH_REQUEST = 258,  // RAR - Re-Auth Request (PCRF → AF)
    RE_AUTH_ANSWER = 258,   // RAA - Re-Auth Answer (AF → PCRF)
    SESSION_TERMINATION_REQUEST = 275,  // STR
    SESSION_TERMINATION_ANSWER = 275,   // STA
    ABORT_SESSION_REQUEST = 274,  // ASR (PCRF → AF)
    ABORT_SESSION_ANSWER = 274    // ASA (AF → PCRF)
};

// Rx-Request-Type values (AVP 1027)
enum class RxRequestType : uint32_t {
    INITIAL_REQUEST = 0,
    UPDATE_REQUEST = 1
};

// Rx AVP Codes (3GPP Vendor ID = 10415)
enum class RxAVPCode : uint32_t {
    // Media component description
    MEDIA_COMPONENT_DESCRIPTION = 517,
    MEDIA_COMPONENT_NUMBER = 518,
    MEDIA_TYPE = 520,
    MAX_REQUESTED_BANDWIDTH_UL = 516,
    MAX_REQUESTED_BANDWIDTH_DL = 515,
    MIN_REQUESTED_BANDWIDTH_UL = 534,
    MIN_REQUESTED_BANDWIDTH_DL = 533,
    FLOW_STATUS = 511,
    RESERVATION_PRIORITY = 458,
    
    // Media sub-component
    MEDIA_SUB_COMPONENT = 519,
    FLOW_NUMBER = 509,
    FLOW_DESCRIPTION = 507,
    FLOW_USAGE = 512,
    
    // RTP/RTCP
    RR_BANDWIDTH = 521,
    RS_BANDWIDTH = 522,
    
    // Codec data
    CODEC_DATA = 524,
    
    // Session linking
    AF_APPLICATION_IDENTIFIER = 504,
    AF_CHARGING_IDENTIFIER = 505,  // ICID
    
    // Specific actions
    SPECIFIC_ACTION = 513,
    
    // Service info
    SERVICE_INFO_STATUS = 527,
    SIP_FORKING_INDICATION = 523,
    
    // Rx-Request-Type
    RX_REQUEST_TYPE = 1027,
    
    // Sponsoring
    SPONSOR_IDENTITY = 531,
    APPLICATION_SERVICE_PROVIDER_IDENTITY = 532,
    
    // Emergency
    MPS_IDENTIFIER = 528,
    PRIORITY_SHARING_INDICATOR = 550,
    
    // Access network info
    IP_DOMAIN_ID = 537,
    ACCESS_NETWORK_CHARGING_IDENTIFIER_VALUE = 503,
    
    // Results
    ACCEPTABLE_SERVICE_INFO = 526
};

// Media Type values (AVP 520)
enum class MediaType : uint32_t {
    AUDIO = 0,
    VIDEO = 1,
    DATA = 2,
    APPLICATION = 3,
    CONTROL = 4,
    TEXT = 5,
    MESSAGE = 6,
    OTHER = 0xFFFFFFFF
};

// Flow Status values (AVP 511)
enum class FlowStatus : uint32_t {
    ENABLED_UPLINK = 0,
    ENABLED_DOWNLINK = 1,
    ENABLED = 2,
    DISABLED = 3,
    REMOVED = 4
};

// Specific Action values (AVP 513)
enum class SpecificAction : uint32_t {
    CHARGING_CORRELATION_EXCHANGE = 1,
    INDICATION_OF_LOSS_OF_BEARER = 2,
    INDICATION_OF_RECOVERY_OF_BEARER = 3,
    INDICATION_OF_RELEASE_OF_BEARER = 4,
    IP_CAN_CHANGE = 6,
    INDICATION_OF_OUT_OF_CREDIT = 7,
    INDICATION_OF_SUCCESSFUL_RESOURCES_ALLOCATION = 8,
    INDICATION_OF_FAILED_RESOURCES_ALLOCATION = 9,
    INDICATION_OF_LIMITED_PCC_DEPLOYMENT = 10,
    ACCESS_NETWORK_INFO_REPORT = 12,
    INDICATION_OF_RECOVERY_FROM_LIMITED_PCC_DEPLOYMENT = 13
};

// Flow Usage values (AVP 512)
enum class FlowUsage : uint32_t {
    NO_INFORMATION = 0,
    RTCP = 1,
    AF_SIGNALLING = 2
};

// Media Sub-Component structure
struct MediaSubComponent {
    uint32_t flow_number;
    std::vector<FlowDescription> flow_descriptions;
    std::optional<FlowUsage> flow_usage;
    std::optional<FlowStatus> flow_status;
    std::optional<uint32_t> max_requested_bandwidth_ul;
    std::optional<uint32_t> max_requested_bandwidth_dl;
    
    nlohmann::json toJson() const;
};

// Media Component Description
struct MediaComponentDescription {
    uint32_t media_component_number;
    std::optional<MediaType> media_type;
    std::optional<uint32_t> max_requested_bandwidth_ul;
    std::optional<uint32_t> max_requested_bandwidth_dl;
    std::optional<uint32_t> min_requested_bandwidth_ul;
    std::optional<uint32_t> min_requested_bandwidth_dl;
    std::optional<FlowStatus> flow_status;
    std::optional<uint8_t> reservation_priority;  // 0=DEFAULT, 1-15 for emergency
    std::optional<uint32_t> rr_bandwidth;  // RTCP RR bandwidth
    std::optional<uint32_t> rs_bandwidth;  // RTCP RS bandwidth
    
    // Codec information (from SDP)
    std::vector<std::string> codec_data;
    
    // Sub-components (individual flows)
    std::vector<MediaSubComponent> sub_components;
    
    // For AF-generated rules
    std::optional<std::string> af_application_identifier;
    
    nlohmann::json toJson() const;
};

// Rx AAR Message (AF → PCRF)
struct RxAAR {
    std::string session_id;
    std::string origin_host;
    std::string origin_realm;
    std::string destination_realm;
    uint32_t auth_application_id = RX_APPLICATION_ID;
    
    // Request type
    RxRequestType request_type = RxRequestType::INITIAL_REQUEST;
    
    // Subscription
    std::optional<std::string> subscription_id;  // SIP URI or TEL URI
    std::optional<std::string> framed_ip_address;
    std::optional<std::string> framed_ipv6_prefix;
    
    // IMS Charging Identifier - links to SIP P-Charging-Vector
    std::optional<std::string> af_charging_identifier;  // ICID
    
    // AF application
    std::optional<std::string> af_application_identifier;
    
    // Media components (from SDP)
    std::vector<MediaComponentDescription> media_components;
    
    // Specific actions to subscribe to
    std::vector<SpecificAction> specific_actions;
    
    // Service URN (for emergency calls)
    std::optional<std::string> service_urn;
    
    // Sponsoring (for zero-rating)
    std::optional<std::string> sponsor_identity;
    
    // SIP forking (for parallel forking scenarios)
    std::optional<bool> sip_forking_indication;
    
    nlohmann::json toJson() const;
};

// Rx AAA Message (PCRF → AF)
struct RxAAA {
    std::string session_id;
    uint32_t result_code;
    std::optional<uint32_t> experimental_result_code;
    std::string origin_host;
    std::string origin_realm;
    uint32_t auth_application_id = RX_APPLICATION_ID;
    
    // Granted media components (may differ from requested)
    std::vector<MediaComponentDescription> acceptable_service_info;
    
    // Access network charging identifier (for correlation with Gx)
    std::optional<std::string> access_network_charging_identifier;
    
    // IP-CAN type
    std::optional<uint32_t> ip_can_type;
    std::optional<uint32_t> rat_type;
    
    nlohmann::json toJson() const;
};

// Rx RAR Message (PCRF → AF) - Notify AF of bearer changes
struct RxRAR {
    std::string session_id;
    std::string origin_host;
    std::string origin_realm;
    std::string destination_host;
    std::string destination_realm;
    uint32_t auth_application_id = RX_APPLICATION_ID;
    
    // Actions that triggered this RAR
    std::vector<SpecificAction> specific_actions;
    
    // Abort cause (if session should be terminated)
    std::optional<uint32_t> abort_cause;
    
    // Access network info
    std::optional<uint32_t> ip_can_type;
    std::optional<uint32_t> rat_type;
    std::optional<std::string> tgpp_user_location_info;
    
    nlohmann::json toJson() const;
};

// Rx RAA Message (AF → PCRF)
struct RxRAA {
    std::string session_id;
    uint32_t result_code;
    std::optional<uint32_t> experimental_result_code;
    std::string origin_host;
    std::string origin_realm;
    
    // Updated media components (if AF modified the session)
    std::vector<MediaComponentDescription> media_components;
    
    nlohmann::json toJson() const;
};

// Rx STR Message (AF → PCRF) - Session Termination
struct RxSTR {
    std::string session_id;
    std::string origin_host;
    std::string origin_realm;
    std::string destination_realm;
    uint32_t auth_application_id = RX_APPLICATION_ID;
    
    // Termination cause
    uint32_t termination_cause;
    
    nlohmann::json toJson() const;
};

// Rx STA Message (PCRF → AF)
struct RxSTA {
    std::string session_id;
    uint32_t result_code;
    std::optional<uint32_t> experimental_result_code;
    std::string origin_host;
    std::string origin_realm;
    
    nlohmann::json toJson() const;
};

// Rx ASR Message (PCRF → AF) - Abort Session
struct RxASR {
    std::string session_id;
    std::string origin_host;
    std::string origin_realm;
    std::string destination_host;
    std::string destination_realm;
    uint32_t auth_application_id = RX_APPLICATION_ID;
    
    // Abort cause
    uint32_t abort_cause;
    
    nlohmann::json toJson() const;
};

// Rx ASA Message (AF → PCRF)
struct RxASA {
    std::string session_id;
    uint32_t result_code;
    std::string origin_host;
    std::string origin_realm;
    
    nlohmann::json toJson() const;
};

// Main Rx Parser Class
class DiameterRxParser {
public:
    static RxAAR parseAAR(const DiameterMessage& msg);
    static RxAAA parseAAA(const DiameterMessage& msg);
    static RxRAR parseRAR(const DiameterMessage& msg);
    static RxRAA parseRAA(const DiameterMessage& msg);
    static RxSTR parseSTR(const DiameterMessage& msg);
    static RxSTA parseSTA(const DiameterMessage& msg);
    static RxASR parseASR(const DiameterMessage& msg);
    static RxASA parseASA(const DiameterMessage& msg);
    
    static bool isRx(const DiameterMessage& msg) {
        return msg.header.application_id == RX_APPLICATION_ID;
    }
    
    static bool isAAR(const DiameterMessage& msg) {
        return msg.header.command_code == 265 && msg.header.flags.request;
    }
    
    static bool isAAA(const DiameterMessage& msg) {
        return msg.header.command_code == 265 && !msg.header.flags.request;
    }
    
    static bool isRAR(const DiameterMessage& msg) {
        return msg.header.command_code == 258 && msg.header.flags.request;
    }
    
    static bool isRAA(const DiameterMessage& msg) {
        return msg.header.command_code == 258 && !msg.header.flags.request;
    }
    
    static bool isSTR(const DiameterMessage& msg) {
        return msg.header.command_code == 275 && msg.header.flags.request;
    }
    
    static bool isSTA(const DiameterMessage& msg) {
        return msg.header.command_code == 275 && !msg.header.flags.request;
    }
    
    static MediaComponentDescription parseMediaComponentDescription(const DiameterAVP& avp);
    static MediaSubComponent parseMediaSubComponent(const DiameterAVP& avp);
    
    // Helper to extract ICID for VoLTE correlation
    static std::optional<std::string> extractIcid(const RxAAR& aar);

private:
    static std::vector<SpecificAction> parseSpecificActions(const std::vector<DiameterAVP>& avps);
    static std::string parseCodecData(const DiameterAVP& avp);
};

}  // namespace diameter
}  // namespace callflow
```

**VoLTE Call Flow Integration:**
```
UE          P-CSCF        S-CSCF        PCRF         PGW
 |            |             |            |            |
 |--INVITE--->|             |            |            |
 |            |--INVITE---->|            |            |
 |            |             |            |            |
 |            |--------AAR (ICID, QCI-1, bandwidth)-->|
 |            |             |            |--CCR-U (RAR trigger)-->
 |            |             |            |<--CCA-U (install rule)--
 |            |<-------AAA (success)--------------------|
 |            |             |            |            |
 |<--100 Trying|            |            |            |
 |            |             |            |--RAR (rule)-->
 |            |             |            |<--RAA-------|
 |            |             |            |            |
 |<--180 Ring-|             |            |            |
 |            |             |            |            |
 |<--200 OK---|             |            |            |
 |---ACK----->|             |            |            |
```

**File Structure:**
```
include/protocol_parsers/diameter/
  diameter_rx.h
  rx_types.h

src/protocol_parsers/diameter/
  diameter_rx_parser.cpp
  rx_media_component_parser.cpp

tests/unit/
  test_diameter_rx.cpp
  test_rx_media_components.cpp

tests/pcaps/
  rx_aar_volte_audio.pcap
  rx_aaa_success.pcap
  rx_aar_video_call.pcap
  rx_rar_bearer_loss.pcap
```

**Testing Requirements:**

1. Unit test: Parse AAR for VoLTE audio call
2. Unit test: Parse AAR for video call with multiple media components
3. Unit test: Parse AAA success response
4. Unit test: Parse AAA with experimental result code
5. Unit test: Parse RAR for bearer loss notification
6. Unit test: Parse RAA response
7. Unit test: Parse STR/STA for session termination
8. Unit test: Extract Media-Component-Description
9. Unit test: Extract ICID from AF-Charging-Identifier
10. Integration test: Full Rx session for VoLTE (AAR/AAA/STR/STA)
11. Integration test: Bearer loss notification (RAR/RAA)

**Acceptance Criteria:**
- ✅ Parse all Rx message types (AAR/AAA/RAR/RAA/STR/STA/ASR/ASA)
- ✅ Extract media component descriptions with all sub-components
- ✅ Parse codec data for media type identification
- ✅ Extract ICID for VoLTE call correlation
- ✅ Support specific action subscriptions
- ✅ Handle emergency call priority
- ✅ Unit test coverage > 90%

Please implement with support for correlating Rx sessions to SIP calls via ICID.
```

---

## PROMPT 11.3: DIAMETER Gy Interface Parser

```markdown
# DIAMETER Gy Interface Parser
## nDPI Callflow Visualizer - Online Charging System

**Context:**
I'm enhancing the nDPI Callflow Visualizer. Gy is the interface between the Charging Trigger Function (CTF, typically the PGW/GGSN) and the Online Charging System (OCS). It's used for:
- Prepaid charging: Credit control for data and voice
- Real-time balance management: Quota grants and usage reporting
- Service-based charging: Different rates per service (streaming, browsing, etc.)
- Roaming charging: Home-routed vs. visited PLMN charging

**3GPP Reference:** TS 32.299 (Diameter charging applications)

**Requirements:**

1. **Gy Message Types and Application ID**

```cpp
// include/protocol_parsers/diameter/diameter_gy.h
#pragma once

#include "protocol_parsers/diameter_parser.h"

namespace callflow {
namespace diameter {

// Gy Application ID (3GPP Charging)
static constexpr uint32_t GY_APPLICATION_ID = 4;  // Diameter Credit Control

// Gy Command Codes (same as Ro for online charging)
enum class GyCommandCode : uint32_t {
    CC_REQUEST = 272,   // CCR
    CC_ANSWER = 272     // CCA
};

// CC-Request-Type values
enum class GyCcRequestType : uint32_t {
    INITIAL_REQUEST = 1,
    UPDATE_REQUEST = 2,
    TERMINATION_REQUEST = 3,
    EVENT_REQUEST = 4
};

// Gy AVP Codes (mix of RFC 4006 and 3GPP TS 32.299)
enum class GyAVPCode : uint32_t {
    // Credit Control (RFC 4006)
    CC_REQUEST_TYPE = 416,
    CC_REQUEST_NUMBER = 415,
    CC_SESSION_FAILOVER = 418,
    
    // Requested/Granted/Used Service Unit
    REQUESTED_SERVICE_UNIT = 437,
    GRANTED_SERVICE_UNIT = 431,
    USED_SERVICE_UNIT = 446,
    CC_TIME = 420,
    CC_MONEY = 413,
    CC_TOTAL_OCTETS = 421,
    CC_INPUT_OCTETS = 412,
    CC_OUTPUT_OCTETS = 414,
    CC_SERVICE_SPECIFIC_UNITS = 417,
    
    // Multiple Services
    MULTIPLE_SERVICES_INDICATOR = 455,
    MULTIPLE_SERVICES_CREDIT_CONTROL = 456,
    
    // Rating
    RATING_GROUP = 432,
    SERVICE_IDENTIFIER = 439,
    
    // Subscription
    SUBSCRIPTION_ID = 443,
    SUBSCRIPTION_ID_TYPE = 450,
    SUBSCRIPTION_ID_DATA = 444,
    
    // Results
    RESULT_CODE = 268,
    FINAL_UNIT_INDICATION = 430,
    FINAL_UNIT_ACTION = 449,
    
    // Validity
    VALIDITY_TIME = 448,
    
    // Quota
    QUOTA_HOLDING_TIME = 871,
    QUOTA_CONSUMPTION_TIME = 881,
    
    // 3GPP Charging (Vendor ID 10415)
    TGPP_CHARGING_ID = 2,
    TGPP_PDP_TYPE = 3,
    TGPP_GPRS_NEGOTIATED_QOS_PROFILE = 5,
    TGPP_IMSI = 1,
    TGPP_GGSN_MCC_MNC = 9,
    TGPP_NSAPI = 10,
    TGPP_SGSN_MCC_MNC = 18,
    TGPP_MS_TIMEZONE = 23,
    TGPP_USER_LOCATION_INFO = 22,
    TGPP_RAT_TYPE = 21,
    
    // Service Information
    SERVICE_INFORMATION = 873,
    PS_INFORMATION = 874,
    IMS_INFORMATION = 876,
    
    // PS Information contents
    TGPP_CHARGING_CHARACTERISTICS = 13,
    CALLED_STATION_ID = 30,  // APN
    TGPP_SELECTION_MODE = 12,
    START_TIME = 2041,
    STOP_TIME = 2042,
    
    // Low balance
    LOW_BALANCE_INDICATION = 2020,
    REMAINING_BALANCE = 2021,
    
    // Service context
    SERVICE_CONTEXT_ID = 461,
    
    // Trigger
    TRIGGER_TYPE = 870,
    TRIGGER = 1264,
    
    // QoS
    QOS_INFORMATION = 1016,
    APN_AGGREGATE_MAX_BITRATE_UL = 1041,
    APN_AGGREGATE_MAX_BITRATE_DL = 1040
};

// Subscription-Id-Type values
enum class SubscriptionIdType : uint32_t {
    END_USER_E164 = 0,
    END_USER_IMSI = 1,
    END_USER_SIP_URI = 2,
    END_USER_NAI = 3,
    END_USER_PRIVATE = 4
};

// Final-Unit-Action values
enum class FinalUnitAction : uint32_t {
    TERMINATE = 0,
    REDIRECT = 1,
    RESTRICT_ACCESS = 2
};

// Trigger-Type values
enum class TriggerType : uint32_t {
    CHANGE_IN_SGSN_IP_ADDRESS = 1,
    CHANGE_IN_QOS = 2,
    CHANGE_IN_LOCATION = 3,
    CHANGE_IN_RAT = 4,
    CHANGE_IN_UE_TIMEZONE = 5,
    CHANGEINQOS_TRAFFIC_CLASS = 10,
    CHANGEINQOS_RELIABILITY_CLASS = 11,
    CHANGEINQOS_DELAY_CLASS = 12,
    CHANGEINQOS_PEAK_THROUGHPUT = 13,
    CHANGEINQOS_PRECEDENCE_CLASS = 14,
    CHANGEINQOS_MEAN_THROUGHPUT = 15,
    CHANGEINQOS_MAXIMUM_BIT_RATE_FOR_UPLINK = 16,
    CHANGEINQOS_MAXIMUM_BIT_RATE_FOR_DOWNLINK = 17,
    CHANGEINQOS_RESIDUAL_BER = 18,
    CHANGEINQOS_SDU_ERROR_RATIO = 19,
    CHANGEINQOS_TRANSFER_DELAY = 20,
    CHANGEINQOS_TRAFFIC_HANDLING_PRIORITY = 21,
    CHANGEINQOS_GUARANTEED_BIT_RATE_FOR_UPLINK = 22,
    CHANGEINQOS_GUARANTEED_BIT_RATE_FOR_DOWNLINK = 23
};

// Service Unit (granted/used)
struct ServiceUnit {
    std::optional<uint32_t> time_seconds;          // CC-Time
    std::optional<uint64_t> total_octets;          // CC-Total-Octets
    std::optional<uint64_t> input_octets;          // CC-Input-Octets (uplink)
    std::optional<uint64_t> output_octets;         // CC-Output-Octets (downlink)
    std::optional<uint64_t> service_specific_units;
    
    nlohmann::json toJson() const;
};

// Multiple Services Credit Control
struct MultipleServicesCreditControl {
    std::optional<uint32_t> rating_group;
    std::optional<uint32_t> service_identifier;
    
    std::optional<ServiceUnit> requested_service_unit;
    std::optional<ServiceUnit> granted_service_unit;
    std::optional<ServiceUnit> used_service_unit;
    
    // Result for this rating group
    std::optional<uint32_t> result_code;
    
    // Quota management
    std::optional<uint32_t> validity_time;
    std::optional<uint32_t> quota_holding_time;
    
    // Final unit handling
    std::optional<FinalUnitAction> final_unit_action;
    
    // Triggers for next update
    std::vector<TriggerType> trigger_types;
    
    nlohmann::json toJson() const;
};

// PS-Information (for data sessions)
struct PSInformation {
    std::optional<std::string> tgpp_charging_id;
    std::optional<std::string> called_station_id;  // APN
    std::optional<uint8_t> tgpp_pdp_type;
    std::optional<std::string> sgsn_address;
    std::optional<std::string> ggsn_address;
    std::optional<std::string> tgpp_imsi_mcc_mnc;
    std::optional<std::string> tgpp_ggsn_mcc_mnc;
    std::optional<std::string> tgpp_sgsn_mcc_mnc;
    std::optional<std::string> tgpp_user_location_info;  // hex
    std::optional<uint8_t> tgpp_rat_type;
    std::optional<std::string> tgpp_ms_timezone;
    
    // Timestamps
    std::optional<std::chrono::system_clock::time_point> start_time;
    std::optional<std::chrono::system_clock::time_point> stop_time;
    
    // QoS
    std::optional<uint32_t> apn_aggregate_max_bitrate_ul;
    std::optional<uint32_t> apn_aggregate_max_bitrate_dl;
    
    nlohmann::json toJson() const;
};

// IMS-Information (for VoLTE sessions)
struct IMSInformation {
    std::optional<std::string> node_functionality;
    std::optional<std::string> role_of_node;
    std::optional<std::string> calling_party_address;
    std::optional<std::string> called_party_address;
    std::optional<std::string> icid;
    std::optional<std::string> ioi;  // Inter-Operator Identifier
    
    // SIP methods for event-based charging
    std::optional<std::string> sip_request_method;
    std::optional<std::string> sip_response_timestamp;
    
    nlohmann::json toJson() const;
};

// Service Information
struct ServiceInformation {
    std::optional<PSInformation> ps_information;
    std::optional<IMSInformation> ims_information;
    
    nlohmann::json toJson() const;
};

// Gy CCR Message (CTF → OCS)
struct GyCCR {
    GyCcRequestType request_type;
    uint32_t request_number;
    std::string session_id;
    std::string origin_host;
    std::string origin_realm;
    std::string destination_realm;
    uint32_t auth_application_id = GY_APPLICATION_ID;
    
    // Service context
    std::string service_context_id;
    
    // Subscription
    std::optional<std::string> imsi;
    std::optional<std::string> msisdn;
    
    // Multiple Services
    bool multiple_services_indicator = true;
    std::vector<MultipleServicesCreditControl> multiple_services_cc;
    
    // Service information
    std::optional<ServiceInformation> service_information;
    
    // Event timestamp
    std::optional<std::chrono::system_clock::time_point> event_timestamp;
    
    // User equipment info
    std::optional<std::string> user_equipment_info;  // IMEISV
    
    nlohmann::json toJson() const;
};

// Gy CCA Message (OCS → CTF)
struct GyCCA {
    uint32_t result_code;
    std::optional<uint32_t> experimental_result_code;
    std::string session_id;
    GyCcRequestType request_type;
    uint32_t request_number;
    std::string origin_host;
    std::string origin_realm;
    uint32_t auth_application_id = GY_APPLICATION_ID;
    
    // Credit control answers for each rating group
    std::vector<MultipleServicesCreditControl> multiple_services_cc;
    
    // Session failover
    std::optional<bool> cc_session_failover;
    
    // Low balance warning
    std::optional<bool> low_balance_indication;
    std::optional<double> remaining_balance;
    std::optional<std::string> currency_code;
    
    // Validity
    std::optional<uint32_t> validity_time;
    
    nlohmann::json toJson() const;
};

// Main Gy Parser Class
class DiameterGyParser {
public:
    static GyCCR parseCCR(const DiameterMessage& msg);
    static GyCCA parseCCA(const DiameterMessage& msg);
    
    static bool isGy(const DiameterMessage& msg) {
        // Gy uses application ID 4 (Credit Control)
        // Distinguish from other CC apps by service-context-id or AVPs
        return msg.header.application_id == GY_APPLICATION_ID;
    }
    
    static bool isCCR(const DiameterMessage& msg) {
        return msg.header.command_code == 272 && msg.header.flags.request;
    }
    
    static bool isCCA(const DiameterMessage& msg) {
        return msg.header.command_code == 272 && !msg.header.flags.request;
    }
    
    static ServiceUnit parseServiceUnit(const DiameterAVP& avp);
    static MultipleServicesCreditControl parseMSCC(const DiameterAVP& avp);
    static ServiceInformation parseServiceInformation(const DiameterAVP& avp);
    static PSInformation parsePSInformation(const DiameterAVP& avp);
    static IMSInformation parseIMSInformation(const DiameterAVP& avp);

private:
    static std::string parseSubscriptionId(const std::vector<DiameterAVP>& avps, SubscriptionIdType type);
    static std::vector<TriggerType> parseTriggers(const std::vector<DiameterAVP>& avps);
};

}  // namespace diameter
}  // namespace callflow
```

**Data Session Charging Flow:**
```
UE          PGW/GGSN(CTF)        OCS
 |              |                 |
 |--Attach----->|                 |
 |              |                 |
 |              |---CCR-I (rating_group, RSU)-->|
 |              |<--CCA-I (GSU: 100MB, validity: 1h)--|
 |              |                 |
 |<--IP assigned|                 |
 |              |                 |
 |--Data------->|                 |
 |<--Data-------|                 |
 |              |                 |
 |              |---CCR-U (USU: 50MB, RSU)-->|
 |              |<--CCA-U (GSU: 100MB)--|
 |              |                 |
 |--Detach----->|                 |
 |              |---CCR-T (USU: 30MB)-->|
 |              |<--CCA-T (final)--|
```

**File Structure:**
```
include/protocol_parsers/diameter/
  diameter_gy.h
  gy_types.h

src/protocol_parsers/diameter/
  diameter_gy_parser.cpp
  gy_service_unit_parser.cpp
  gy_service_info_parser.cpp

tests/unit/
  test_diameter_gy.cpp
  test_gy_service_units.cpp
  test_gy_mscc.cpp

tests/pcaps/
  gy_ccr_initial_data.pcap
  gy_cca_with_quota.pcap
  gy_ccr_update_usage.pcap
  gy_cca_low_balance.pcap
  gy_ccr_termination.pcap
```

**Testing Requirements:**

1. Unit test: Parse CCR-Initial for data session
2. Unit test: Parse CCA with granted quota
3. Unit test: Parse CCR-Update with usage report
4. Unit test: Parse CCA-Update with renewed quota
5. Unit test: Parse CCR-Termination
6. Unit test: Parse CCA-Termination (final)
7. Unit test: Parse Multiple-Services-Credit-Control
8. Unit test: Extract Granted-Service-Unit
9. Unit test: Extract Used-Service-Unit
10. Unit test: Parse PS-Information
11. Unit test: Parse IMS-Information for VoLTE
12. Unit test: Low balance indication
13. Unit test: Final unit action handling
14. Integration test: Full data session (CCR-I/CCA-I/CCR-U/CCA-U/CCR-T/CCA-T)
15. Integration test: Quota exhaustion scenario

**Acceptance Criteria:**
- ✅ Parse all Gy message types (CCR/CCA with all request types)
- ✅ Extract granted/used service units (time, octets)
- ✅ Support multiple rating groups per session
- ✅ Extract PS-Information for data sessions
- ✅ Extract IMS-Information for VoLTE sessions
- ✅ Handle low balance and final unit actions
- ✅ Parse triggers for reporting
- ✅ Unit test coverage > 90%

Please implement with comprehensive usage tracking for correlation with session duration.
```

---

## Summary: DIAMETER Policy Interface Integration

### Cross-Interface Correlation

The three DIAMETER policy interfaces work together in VoLTE and data sessions:

```
                    ┌─────────────────────────────────────────┐
                    │                 PCRF                     │
                    │  (Policy and Charging Rules Function)   │
                    └─────────────────────────────────────────┘
                       ▲         │          │
                    Rx │         │ Gx       │ Gx
                 (QoS) │         │(Policy)  │(Policy)
                       │         ▼          ▼
┌────────────┐    ┌────────┐  ┌──────┐    ┌──────┐    ┌────────┐
│   P-CSCF   │◀──▶│   AF   │  │ PCEF │◀──▶│ PGW  │◀──▶│  OCS   │
│ (IMS Proxy)│    └────────┘  └──────┘    └──────┘    │ (Gy)   │
└────────────┘                              │         └────────┘
      ▲                                     │
      │ SIP                                 │ GTP
      ▼                                     ▼
┌────────────┐                        ┌────────────┐
│     UE     │◀──────────────────────▶│   eNodeB   │
└────────────┘                        └────────────┘
```

### VoLTE Call Correlation Keys

| Interface | Key for Correlation |
|-----------|---------------------|
| SIP ↔ Rx  | ICID (P-Charging-Vector → AF-Charging-Identifier) |
| Rx ↔ Gx   | Framed-IP-Address |
| Gx ↔ GTP  | IMSI + Bearer ID |
| Gy ↔ GTP  | 3GPP-Charging-Id |

### Implementation Order

1. **Gx first** - Foundation for policy control
2. **Rx second** - Depends on Gx understanding for RAR/RAA
3. **Gy third** - Builds on both for charging correlation

### Integration Points in VolteCallCorrelator

```cpp
// In volte_call_correlator.cpp

void VolteCallCorrelator::processDiameterMessage(
    const SessionMessageRef& msg,
    const DiameterMessage& dia) {
    
    if (DiameterGxParser::isGx(dia)) {
        processGxMessage(msg, dia);
    } else if (DiameterRxParser::isRx(dia)) {
        processRxMessage(msg, dia);
    } else if (DiameterGyParser::isGy(dia)) {
        processGyMessage(msg, dia);
    }
}

void VolteCallCorrelator::processRxMessage(
    const SessionMessageRef& msg,
    const DiameterMessage& dia) {
    
    if (DiameterRxParser::isAAR(dia)) {
        auto aar = DiameterRxParser::parseAAR(dia);
        
        // Extract ICID for correlation with SIP
        if (auto icid = DiameterRxParser::extractIcid(aar)) {
            // Find VoLTE call by ICID
            if (auto call = findByIcid(*icid)) {
                // Link Rx session to call
                call->rx_leg.session_id = aar.session_id;
                call->rx_leg.aar_time = msg.timestamp;
                
                // Extract requested QoS
                for (const auto& mc : aar.media_components) {
                    if (mc.media_type == MediaType::AUDIO) {
                        call->rx_leg.requested_bandwidth_ul = mc.max_requested_bandwidth_ul;
                        call->rx_leg.requested_bandwidth_dl = mc.max_requested_bandwidth_dl;
                    }
                }
            }
        }
    }
}
```

---

## Testing PCAPs Required

Create test PCAPs containing:

1. **gx_data_session.pcap**
   - CCR-I/CCA-I with default bearer QoS
   - CCR-U/CCA-U with usage report
   - CCR-T/CCA-T

2. **gx_volte_bearer.pcap**
   - RAR with QCI-1 rule for voice
   - RAA success

3. **rx_volte_audio.pcap**
   - AAR with audio media component
   - AAA with granted QoS

4. **rx_video_call.pcap**
   - AAR with audio + video components
   - AAA with both granted

5. **gy_prepaid_data.pcap**
   - CCR-I with quota request
   - CCA-I with granted 100MB
   - CCR-U with 80MB used
   - CCA-U with 100MB renewed
   - CCR-T final usage

6. **combined_volte.pcap**
   - Full VoLTE flow: SIP INVITE → Rx AAR/AAA → Gx RAR/RAA → GTP → RTP
