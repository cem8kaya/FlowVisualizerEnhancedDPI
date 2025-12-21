#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace callflow {
namespace gtp {

/**
 * GTPv2-C Information Element Types (3GPP TS 29.274)
 */
enum class GtpV2IEType : uint8_t {
    RESERVED = 0,
    IMSI = 1,
    CAUSE = 2,
    RECOVERY = 3,
    STN_SR = 51,
    APN = 71,
    AMBR = 72,
    EPS_BEARER_ID = 73,
    IP_ADDRESS_V4 = 74,
    MEI = 75,
    MSISDN = 76,
    INDICATION = 77,
    PCO = 78,
    PAA = 79,  // PDN Address Allocation
    BEARER_QOS = 80,
    FLOW_QOS = 81,
    RAT_TYPE = 82,
    SERVING_NETWORK = 83,
    BEARER_TFT = 84,
    TAD = 85,
    ULI = 86,  // User Location Information
    F_TEID = 87,
    TMSI = 88,
    GLOBAL_CN_ID = 89,
    S103PDF = 90,
    S1UDF = 91,
    DELAY_VALUE = 92,
    BEARER_CONTEXT = 93,
    CHARGING_ID = 94,
    CHARGING_CHARACTERISTICS = 95,
    TRACE_INFORMATION = 96,
    BEARER_FLAGS = 97,
    PDN_TYPE = 99,
    PTI = 100,
    DRX_PARAMETER = 101,
    UE_NETWORK_CAPABILITY = 102,
    MM_CONTEXT = 103,
    PDN_CONNECTION = 104,
    PDU_NUMBERS = 105,
    P_TMSI = 106,
    P_TMSI_SIGNATURE = 107,
    HOP_COUNTER = 108,
    UE_TIME_ZONE = 109,
    TRACE_REFERENCE = 110,
    COMPLETE_REQUEST_MESSAGE = 111,
    GUTI = 112,
    F_CONTAINER = 113,
    F_CAUSE = 114,
    PLMN_ID = 115,
    TARGET_IDENTIFICATION = 116,
    PACKET_FLOW_ID = 117,
    RAB_CONTEXT = 118,
    SOURCE_RNC_PDCP_CONTEXT_INFO = 119,
    PORT_NUMBER = 126,
    APN_RESTRICTION = 127,
    SELECTION_MODE = 128,
    SOURCE_IDENTIFICATION = 129,
    CHANGE_REPORTING_ACTION = 131,
    FQ_CSID = 132,
    CHANNEL = 133,
    EMLPP_PRIORITY = 134,
    NODE_TYPE = 135,
    NODE_IDENTIFIER = 136,
    FQDN = 136,
    TI = 137,
    MBMS_SESSION_DURATION = 138,
    MBMS_SERVICE_AREA = 139,
    MBMS_SESSION_IDENTIFIER = 140,
    MBMS_FLOW_IDENTIFIER = 141,
    MBMS_IP_MULTICAST_DISTRIBUTION = 142,
    MBMS_DISTRIBUTION_ACKNOWLEDGE = 143,
    RFSP_INDEX = 144,
    UCI = 145,
    CSG_INFORMATION_REPORTING_ACTION = 146,
    CSG_ID = 147,
    CMI = 148,
    SERVICE_INDICATOR = 149,
    DETACH_TYPE = 150,
    LDN = 151,
    NODE_FEATURES = 152,
    MBMS_TIME_TO_DATA_TRANSFER = 153,
    THROTTLING = 154,
    ARP = 155,
    EPC_TIMER = 156,
    SIGNALLING_PRIORITY_INDICATION = 157,
    TMGI = 158,
    ADDITIONAL_MM_CONTEXT_FOR_SRVCC = 159,
    ADDITIONAL_FLAGS_FOR_SRVCC = 160,
    MDT_CONFIGURATION = 162,
    APCO = 163,
    ABSOLUTE_TIME_OF_MBMS_DATA_TRANSFER = 164,
    HENB_INFORMATION_REPORTING = 165,
    IPV4_CONFIGURATION_PARAMETERS = 166,
    CHANGE_TO_REPORT_FLAGS = 167,
    ACTION_INDICATION = 168,
    TWAN_IDENTIFIER = 169,
    ULI_TIMESTAMP = 170,
    MBMS_FLAGS = 171,
    RAN_NAS_CAUSE = 172,
    CN_OPERATOR_SELECTION_ENTITY = 173,
    TRUSTED_WLAN_MODE_INDICATION = 174,
    NODE_NUMBER = 175,
    NODE_IDENTIFIER_2 = 176,
    PRESENCE_REPORTING_AREA_ACTION = 177,
    PRESENCE_REPORTING_AREA_INFORMATION = 178,
    TWAN_IDENTIFIER_TIMESTAMP = 179,
    OVERLOAD_CONTROL_INFORMATION = 180,
    LOAD_CONTROL_INFORMATION = 181,
    METRIC = 182,
    SEQUENCE_NUMBER = 183,
    APN_AND_RELATIVE_CAPACITY = 184,
    WLAN_OFFLOADABILITY_INDICATION = 185,
    PAGING_AND_SERVICE_INFORMATION = 186,
    INTEGER_NUMBER = 187,
    MILLISECOND_TIME_STAMP = 188,
    MONITORING_EVENT_INFORMATION = 189,
    ECGI_LIST = 190,
    REMOTE_UE_CONTEXT = 191,
    REMOTE_USER_ID = 192,
    REMOTE_UE_IP_INFORMATION = 193,
    CIOT_OPTIMIZATIONS_SUPPORT_INDICATION = 194,
    SCEF_PDN_CONNECTION = 195,
    HEADER_COMPRESSION_CONFIGURATION = 196,
    EXTENDED_PROTOCOL_CONFIGURATION_OPTIONS = 197,
    SERVING_PLMN_RATE_CONTROL = 198,
    COUNTER = 199,
    MAPPED_UE_USAGE_TYPE = 200,
    SECONDARY_RAT_USAGE_DATA_REPORT = 201,
    UP_FUNCTION_SELECTION_INDICATION_FLAGS = 202,
    MAXIMUM_PACKET_LOSS_RATE = 203,
    APN_RATE_CONTROL_STATUS = 204,
    EXTENDED_TRACE_INFORMATION = 205,
    MONITORING_EVENT_EXTENSION_INFORMATION = 206,
    ADDITIONAL_RRM_POLICY_INDEX = 207,
    V2X_CONTEXT = 208,
    PC5_QOS_PARAMETERS = 209,
    SERVICES_AUTHORIZED = 210,
    BIT_RATE = 211,
    PC5_QOS_FLOW = 212,
    SGI_PTP_TUNNEL_ADDRESS = 213,
    PGW_CHANGE_INFO = 214,
    PGW_FQDN = 215,
    GROUP_ID = 216,
    PSI = 217,
    PGW_SET_FQDN = 218,
    PRIVATE_EXTENSION = 255
};

/**
 * GTPv2-C Message Types (3GPP TS 29.274)
 */
enum class GtpV2MessageType : uint8_t {
    ECHO_REQUEST = 1,
    ECHO_RESPONSE = 2,
    VERSION_NOT_SUPPORTED_INDICATION = 3,
    CREATE_SESSION_REQUEST = 32,
    CREATE_SESSION_RESPONSE = 33,
    MODIFY_BEARER_REQUEST = 34,
    MODIFY_BEARER_RESPONSE = 35,
    DELETE_SESSION_REQUEST = 36,
    DELETE_SESSION_RESPONSE = 37,
    CHANGE_NOTIFICATION_REQUEST = 38,
    CHANGE_NOTIFICATION_RESPONSE = 39,
    REMOTE_UE_REPORT_NOTIFICATION = 40,
    REMOTE_UE_REPORT_ACKNOWLEDGE = 41,
    MODIFY_BEARER_COMMAND = 64,
    MODIFY_BEARER_FAILURE_INDICATION = 65,
    DELETE_BEARER_COMMAND = 66,
    DELETE_BEARER_FAILURE_INDICATION = 67,
    BEARER_RESOURCE_COMMAND = 68,
    BEARER_RESOURCE_FAILURE_INDICATION = 69,
    DOWNLINK_DATA_NOTIFICATION_FAILURE_INDICATION = 70,
    TRACE_SESSION_ACTIVATION = 71,
    TRACE_SESSION_DEACTIVATION = 72,
    STOP_PAGING_INDICATION = 73,
    CREATE_BEARER_REQUEST = 95,
    CREATE_BEARER_RESPONSE = 96,
    UPDATE_BEARER_REQUEST = 97,
    UPDATE_BEARER_RESPONSE = 98,
    DELETE_BEARER_REQUEST = 99,
    DELETE_BEARER_RESPONSE = 100,
    DELETE_PDN_CONNECTION_SET_REQUEST = 101,
    DELETE_PDN_CONNECTION_SET_RESPONSE = 102,
    PGW_DOWNLINK_TRIGGERING_NOTIFICATION = 103,
    PGW_DOWNLINK_TRIGGERING_ACKNOWLEDGE = 104,
    IDENTIFICATION_REQUEST = 128,
    IDENTIFICATION_RESPONSE = 129,
    CONTEXT_REQUEST = 130,
    CONTEXT_RESPONSE = 131,
    CONTEXT_ACKNOWLEDGE = 132,
    FORWARD_RELOCATION_REQUEST = 133,
    FORWARD_RELOCATION_RESPONSE = 134,
    FORWARD_RELOCATION_COMPLETE_NOTIFICATION = 135,
    FORWARD_RELOCATION_COMPLETE_ACKNOWLEDGE = 136,
    FORWARD_ACCESS_CONTEXT_NOTIFICATION = 137,
    FORWARD_ACCESS_CONTEXT_ACKNOWLEDGE = 138,
    RELOCATION_CANCEL_REQUEST = 139,
    RELOCATION_CANCEL_RESPONSE = 140,
    CONFIGURATION_TRANSFER_TUNNEL = 141,
    DETACH_NOTIFICATION = 149,
    DETACH_ACKNOWLEDGE = 150,
    CS_PAGING_INDICATION = 151,
    RAN_INFORMATION_RELAY = 152,
    ALERT_MME_NOTIFICATION = 153,
    ALERT_MME_ACKNOWLEDGE = 154,
    UE_ACTIVITY_NOTIFICATION = 155,
    UE_ACTIVITY_ACKNOWLEDGE = 156,
    ISR_STATUS_INDICATION = 157,
    UE_REGISTRATION_QUERY_REQUEST = 158,
    UE_REGISTRATION_QUERY_RESPONSE = 159,
    CREATE_FORWARDING_TUNNEL_REQUEST = 160,
    CREATE_FORWARDING_TUNNEL_RESPONSE = 161,
    SUSPEND_NOTIFICATION = 162,
    SUSPEND_ACKNOWLEDGE = 163,
    RESUME_NOTIFICATION = 164,
    RESUME_ACKNOWLEDGE = 165,
    CREATE_INDIRECT_DATA_FORWARDING_TUNNEL_REQUEST = 166,
    CREATE_INDIRECT_DATA_FORWARDING_TUNNEL_RESPONSE = 167,
    DELETE_INDIRECT_DATA_FORWARDING_TUNNEL_REQUEST = 168,
    DELETE_INDIRECT_DATA_FORWARDING_TUNNEL_RESPONSE = 169,
    RELEASE_ACCESS_BEARERS_REQUEST = 170,
    RELEASE_ACCESS_BEARERS_RESPONSE = 171,
    DOWNLINK_DATA_NOTIFICATION = 176,
    DOWNLINK_DATA_NOTIFICATION_ACKNOWLEDGE = 177,
    PGW_RESTART_NOTIFICATION = 179,
    PGW_RESTART_NOTIFICATION_ACKNOWLEDGE = 180,
    UPDATE_PDN_CONNECTION_SET_REQUEST = 200,
    UPDATE_PDN_CONNECTION_SET_RESPONSE = 201,
    MODIFY_ACCESS_BEARERS_REQUEST = 211,
    MODIFY_ACCESS_BEARERS_RESPONSE = 212,
    MBMS_SESSION_START_REQUEST = 231,
    MBMS_SESSION_START_RESPONSE = 232,
    MBMS_SESSION_UPDATE_REQUEST = 233,
    MBMS_SESSION_UPDATE_RESPONSE = 234,
    MBMS_SESSION_STOP_REQUEST = 235,
    MBMS_SESSION_STOP_RESPONSE = 236
};

/**
 * F-TEID Interface Types (3GPP TS 29.274 Section 8.22)
 */
enum class FTEIDInterfaceType : uint8_t {
    S1_U_ENODEB_GTP_U = 0,
    S1_U_SGW_GTP_U = 1,
    S12_RNC_GTP_U = 2,
    S12_SGW_GTP_U = 3,
    S5_S8_SGW_GTP_U = 4,
    S5_S8_PGW_GTP_U = 5,
    S5_S8_SGW_GTP_C = 6,
    S5_S8_PGW_GTP_C = 7,
    S5_S8_SGW_PMIPV6 = 8,
    S5_S8_PGW_PMIPV6 = 9,
    S11_MME_GTP_C = 10,
    S11_S4_SGW_GTP_C = 11,
    S10_MME_GTP_C = 12,
    S3_MME_GTP_C = 13,
    S3_SGSN_GTP_C = 14,
    S4_SGSN_GTP_U = 15,
    S4_SGW_GTP_U = 16,
    S4_SGSN_GTP_C = 17,
    S16_SGSN_GTP_C = 18,
    ENODEB_GTP_U_DL_DATA_FORWARDING = 19,
    ENODEB_GTP_U_UL_DATA_FORWARDING = 20,
    RNC_GTP_U_DATA_FORWARDING = 21,
    SGW_GTP_U_DL_DATA_FORWARDING = 22,
    SM_MBMS_GW_GTP_C = 23,
    SN_MBMS_GW_GTP_C = 24,
    SM_MME_GTP_C = 25,
    SN_SGSN_GTP_C = 26,
    SGW_GTP_U_UL_DATA_FORWARDING = 27,
    SN_SGSN_GTP_U = 28,
    S2B_EPDG_GTP_C = 29,
    S2B_U_EPDG_GTP_U = 30,
    S2B_PGW_GTP_C = 31,
    S2B_U_PGW_GTP_U = 32,
    S2A_TWAN_GTP_U = 33,
    S2A_TWAN_GTP_C = 34,
    S2A_PGW_GTP_C = 35,
    S2A_PGW_GTP_U = 36,
    S11_MME_GTP_U = 37,
    S11_SGW_GTP_U = 38
};

/**
 * PDN Type values (3GPP TS 29.274 Section 8.34)
 */
enum class PDNType : uint8_t {
    IPv4 = 1,
    IPv6 = 2,
    IPv4v6 = 3,
    NON_IP = 4
};

/**
 * RAT Type values (3GPP TS 29.274 Section 8.17)
 */
enum class RATType : uint8_t {
    UTRAN = 1,
    GERAN = 2,
    WLAN = 3,
    GAN = 4,
    HSPA_EVOLUTION = 5,
    EUTRAN = 6,
    VIRTUAL = 7,
    EUTRAN_NB_IOT = 8,
    LTE_M = 9,
    NR = 10
};

/**
 * Cause values (3GPP TS 29.274 Section 8.4)
 */
enum class CauseValue : uint8_t {
    REQUEST_ACCEPTED = 16,
    REQUEST_ACCEPTED_PARTIALLY = 17,
    NEW_PDN_TYPE_DUE_TO_NETWORK_PREFERENCE = 18,
    NEW_PDN_TYPE_DUE_TO_SINGLE_ADDRESS_BEARER_ONLY = 19,
    CONTEXT_NOT_FOUND = 64,
    INVALID_MESSAGE_FORMAT = 65,
    VERSION_NOT_SUPPORTED_BY_NEXT_PEER = 66,
    INVALID_LENGTH = 67,
    SERVICE_NOT_SUPPORTED = 68,
    MANDATORY_IE_INCORRECT = 69,
    MANDATORY_IE_MISSING = 70,
    SYSTEM_FAILURE = 72,
    NO_RESOURCES_AVAILABLE = 73,
    SEMANTIC_ERROR_IN_THE_TFT_OPERATION = 74,
    SYNTACTIC_ERROR_IN_THE_TFT_OPERATION = 75,
    SEMANTIC_ERRORS_IN_PACKET_FILTER = 76,
    SYNTACTIC_ERRORS_IN_PACKET_FILTER = 77,
    MISSING_OR_UNKNOWN_APN = 78,
    GRE_KEY_NOT_FOUND = 80,
    RELOCATION_FAILURE = 81,
    DENIED_IN_RAT = 82,
    PREFERRED_PDN_TYPE_NOT_SUPPORTED = 83,
    ALL_DYNAMIC_ADDRESSES_ARE_OCCUPIED = 84,
    UE_CONTEXT_WITHOUT_TFT_ALREADY_ACTIVATED = 85,
    PROTOCOL_TYPE_NOT_SUPPORTED = 86,
    UE_NOT_RESPONDING = 87,
    UE_REFUSES = 88,
    SERVICE_DENIED = 89,
    UNABLE_TO_PAGE_UE = 90,
    NO_MEMORY_AVAILABLE = 91,
    USER_AUTHENTICATION_FAILED = 92,
    APN_ACCESS_DENIED_NO_SUBSCRIPTION = 93,
    REQUEST_REJECTED = 94,
    P_TMSI_SIGNATURE_MISMATCH = 95
};

/**
 * GTPv2-C Information Element Header
 */
struct GtpV2IEHeader {
    GtpV2IEType type;
    uint16_t length;
    uint8_t instance;
    bool cr_flag;  // Comprehension Required flag

    nlohmann::json toJson() const;
};

/**
 * IMSI Information Element (3GPP TS 29.274 Section 8.3)
 */
struct GtpV2IMSI {
    std::string imsi;  // 15 digits max (e.g., "001010123456789")

    nlohmann::json toJson() const;
    static std::optional<GtpV2IMSI> parse(const std::vector<uint8_t>& data);
};

/**
 * F-TEID Information Element (3GPP TS 29.274 Section 8.22)
 * **MOST CRITICAL for TEID correlation**
 */
struct GtpV2FTEID {
    FTEIDInterfaceType interface_type;
    uint32_t teid;  // Tunnel Endpoint Identifier - **CRITICAL**
    std::optional<std::string> ipv4_address;
    std::optional<std::string> ipv6_address;

    nlohmann::json toJson() const;
    std::string getInterfaceTypeName() const;
    static std::optional<GtpV2FTEID> parse(const std::vector<uint8_t>& data);
};

/**
 * Bearer QoS Information Element (3GPP TS 29.274 Section 8.15)
 */
struct GtpV2BearerQoS {
    uint8_t pci;  // Pre-emption Capability
    uint8_t pl;   // Priority Level
    uint8_t pvi;  // Pre-emption Vulnerability
    uint8_t qci;  // QoS Class Identifier
    uint64_t max_bitrate_uplink;         // bps
    uint64_t max_bitrate_downlink;       // bps
    uint64_t guaranteed_bitrate_uplink;  // bps
    uint64_t guaranteed_bitrate_downlink;// bps

    nlohmann::json toJson() const;
    std::string getQCIName() const;
    static std::optional<GtpV2BearerQoS> parse(const std::vector<uint8_t>& data);
};

/**
 * PDN Address Allocation (PAA) Information Element (3GPP TS 29.274 Section 8.14)
 */
struct GtpV2PDNAddressAllocation {
    PDNType pdn_type;
    std::optional<std::string> ipv4_address;
    std::optional<std::string> ipv6_address;
    std::optional<uint8_t> ipv6_prefix_length;

    nlohmann::json toJson() const;
    static std::optional<GtpV2PDNAddressAllocation> parse(const std::vector<uint8_t>& data);
};

/**
 * Bearer Context Grouped IE (3GPP TS 29.274 Section 8.28)
 * Contains nested IEs
 */
struct GtpV2BearerContext {
    std::optional<uint8_t> eps_bearer_id;
    std::optional<GtpV2BearerQoS> qos;
    std::vector<GtpV2FTEID> fteids;  // Can have multiple F-TEIDs
    std::optional<uint32_t> charging_id;
    std::optional<CauseValue> cause;
    std::optional<uint8_t> bearer_flags;

    nlohmann::json toJson() const;
    static std::optional<GtpV2BearerContext> parse(const std::vector<uint8_t>& data);
};

/**
 * Cause Information Element (3GPP TS 29.274 Section 8.4)
 */
struct GtpV2Cause {
    CauseValue cause_value;
    bool pce;  // PDN Connection Exists
    bool bce;  // Bearer Context Exists
    bool cs;   // Cause Source
    std::optional<GtpV2IEType> offending_ie_type;
    std::optional<uint16_t> offending_ie_length;
    std::optional<uint8_t> offending_ie_instance;

    nlohmann::json toJson() const;
    std::string getCauseName() const;
    static std::optional<GtpV2Cause> parse(const std::vector<uint8_t>& data);
};

/**
 * AMBR (Aggregate Maximum Bit Rate) Information Element (3GPP TS 29.274 Section 8.7)
 */
struct GtpV2AMBR {
    uint32_t uplink;    // kbps
    uint32_t downlink;  // kbps

    nlohmann::json toJson() const;
    static std::optional<GtpV2AMBR> parse(const std::vector<uint8_t>& data);
};

/**
 * Serving Network Information Element (3GPP TS 29.274 Section 8.18)
 */
struct GtpV2ServingNetwork {
    std::string mcc;  // Mobile Country Code (3 digits)
    std::string mnc;  // Mobile Network Code (2-3 digits)

    nlohmann::json toJson() const;
    std::string getPlmnId() const;
    static std::optional<GtpV2ServingNetwork> parse(const std::vector<uint8_t>& data);
};

/**
 * User Location Information (ULI) Information Element (3GPP TS 29.274 Section 8.21)
 */
struct GtpV2ULI {
    bool cgi_present;
    bool sai_present;
    bool rai_present;
    bool tai_present;
    bool ecgi_present;
    bool lai_present;

    // TAI (Tracking Area Identity)
    std::optional<std::string> tai_mcc;
    std::optional<std::string> tai_mnc;
    std::optional<uint16_t> tai_tac;

    // ECGI (E-UTRAN Cell Global Identifier)
    std::optional<std::string> ecgi_mcc;
    std::optional<std::string> ecgi_mnc;
    std::optional<uint32_t> ecgi_eci;

    nlohmann::json toJson() const;
    static std::optional<GtpV2ULI> parse(const std::vector<uint8_t>& data);
};

/**
 * Indication Flags Information Element (3GPP TS 29.274 Section 8.12)
 */
struct GtpV2Indication {
    uint64_t flags;  // Combination of indication flags

    nlohmann::json toJson() const;
    static std::optional<GtpV2Indication> parse(const std::vector<uint8_t>& data);
};

/**
 * Get IE type name string
 */
std::string getIETypeName(GtpV2IEType type);

/**
 * Get message type name string
 */
std::string getMessageTypeName(GtpV2MessageType type);

/**
 * Get RAT type name string
 */
std::string getRATTypeName(RATType rat);

/**
 * Get PDN type name string
 */
std::string getPDNTypeName(PDNType pdn);

}  // namespace gtp
}  // namespace callflow
