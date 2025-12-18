#pragma once

#include "common/types.h"
#include <optional>
#include <vector>
#include <nlohmann/json.hpp>

namespace callflow {

/**
 * GTPv1 message types (3GPP TS 29.060)
 */
enum class GtpV1MessageType : uint8_t {
    ECHO_REQUEST = 1,
    ECHO_RESPONSE = 2,
    VERSION_NOT_SUPPORTED = 3,
    NODE_ALIVE_REQUEST = 4,
    NODE_ALIVE_RESPONSE = 5,
    REDIRECTION_REQUEST = 6,
    REDIRECTION_RESPONSE = 7,
    CREATE_PDP_CONTEXT_REQUEST = 16,
    CREATE_PDP_CONTEXT_RESPONSE = 17,
    UPDATE_PDP_CONTEXT_REQUEST = 18,
    UPDATE_PDP_CONTEXT_RESPONSE = 19,
    DELETE_PDP_CONTEXT_REQUEST = 20,
    DELETE_PDP_CONTEXT_RESPONSE = 21,
    INITIATE_PDP_CONTEXT_ACTIVATION_REQUEST = 22,
    INITIATE_PDP_CONTEXT_ACTIVATION_RESPONSE = 23,
    ERROR_INDICATION = 26,
    PDU_NOTIFICATION_REQUEST = 27,
    PDU_NOTIFICATION_RESPONSE = 28,
    PDU_NOTIFICATION_REJECT_REQUEST = 29,
    PDU_NOTIFICATION_REJECT_RESPONSE = 30,
    SUPPORTED_EXTENSION_HEADERS_NOTIFICATION = 31,
    SEND_ROUTEING_INFORMATION_FOR_GPRS_REQUEST = 32,
    SEND_ROUTEING_INFORMATION_FOR_GPRS_RESPONSE = 33,
    FAILURE_REPORT_REQUEST = 34,
    FAILURE_REPORT_RESPONSE = 35,
    NOTE_MS_GPRS_PRESENT_REQUEST = 36,
    NOTE_MS_GPRS_PRESENT_RESPONSE = 37,
    IDENTIFICATION_REQUEST = 48,
    IDENTIFICATION_RESPONSE = 49,
    SGSN_CONTEXT_REQUEST = 50,
    SGSN_CONTEXT_RESPONSE = 51,
    SGSN_CONTEXT_ACKNOWLEDGE = 52,
    FORWARD_RELOCATION_REQUEST = 53,
    FORWARD_RELOCATION_RESPONSE = 54,
    FORWARD_RELOCATION_COMPLETE = 55,
    RELOCATION_CANCEL_REQUEST = 56,
    RELOCATION_CANCEL_RESPONSE = 57,
    FORWARD_SRNS_CONTEXT = 58,
    FORWARD_RELOCATION_COMPLETE_ACKNOWLEDGE = 59,
    FORWARD_SRNS_CONTEXT_ACKNOWLEDGE = 60,
    UE_REGISTRATION_QUERY_REQUEST = 61,
    UE_REGISTRATION_QUERY_RESPONSE = 62,
    RAN_INFORMATION_RELAY = 70,
    MBMS_NOTIFICATION_REQUEST = 96,
    MBMS_NOTIFICATION_RESPONSE = 97,
    MBMS_NOTIFICATION_REJECT_REQUEST = 98,
    MBMS_NOTIFICATION_REJECT_RESPONSE = 99,
    CREATE_MBMS_CONTEXT_REQUEST = 100,
    CREATE_MBMS_CONTEXT_RESPONSE = 101,
    UPDATE_MBMS_CONTEXT_REQUEST = 102,
    UPDATE_MBMS_CONTEXT_RESPONSE = 103,
    DELETE_MBMS_CONTEXT_REQUEST = 104,
    DELETE_MBMS_CONTEXT_RESPONSE = 105,
    MBMS_REGISTRATION_REQUEST = 112,
    MBMS_REGISTRATION_RESPONSE = 113,
    MBMS_DE_REGISTRATION_REQUEST = 114,
    MBMS_DE_REGISTRATION_RESPONSE = 115,
    MBMS_SESSION_START_REQUEST = 116,
    MBMS_SESSION_START_RESPONSE = 117,
    MBMS_SESSION_STOP_REQUEST = 118,
    MBMS_SESSION_STOP_RESPONSE = 119,
    MBMS_SESSION_UPDATE_REQUEST = 120,
    MBMS_SESSION_UPDATE_RESPONSE = 121,
    MS_INFO_CHANGE_NOTIFICATION_REQUEST = 128,
    MS_INFO_CHANGE_NOTIFICATION_RESPONSE = 129,
    DATA_RECORD_TRANSFER_REQUEST = 240,
    DATA_RECORD_TRANSFER_RESPONSE = 241,
    END_MARKER = 254,
    G_PDU = 255  // User plane data
};

/**
 * GTPv1 Information Element types (3GPP TS 29.060)
 */
enum class GtpV1IeType : uint8_t {
    CAUSE = 1,
    IMSI = 2,
    RAI = 3,               // Routing Area Identity
    TLLI = 4,              // Temporary Logical Link Identity
    P_TMSI = 5,            // Packet TMSI
    QOS_PROFILE = 6,
    REORDERING_REQUIRED = 8,
    AUTHENTICATION_TRIPLET = 9,
    MAP_CAUSE = 11,
    P_TMSI_SIGNATURE = 12,
    MS_VALIDATED = 13,
    RECOVERY = 14,
    SELECTION_MODE = 15,
    TEID_DATA_I = 16,      // TEID Data I
    TEID_CONTROL_PLANE = 17,
    TEID_DATA_II = 18,
    TEARDOWN_IND = 19,
    NSAPI = 20,            // Network layer Service Access Point Identifier
    RANAP_CAUSE = 21,
    RAB_CONTEXT = 22,
    RADIO_PRIORITY_SMS = 23,
    RADIO_PRIORITY = 24,
    PACKET_FLOW_ID = 25,
    CHARGING_CHARACTERISTICS = 26,
    TRACE_REFERENCE = 27,
    TRACE_TYPE = 28,
    MS_NOT_REACHABLE_REASON = 29,
    CHARGING_ID = 127,
    END_USER_ADDRESS = 128,
    MM_CONTEXT = 129,
    PDP_CONTEXT = 130,
    APN = 131,             // Access Point Name
    PROTOCOL_CONFIG_OPTIONS = 132,
    GSN_ADDRESS = 133,     // GGSN/SGSN Address
    MSISDN = 134,
    QOS = 135,
    AUTHENTICATION_QUINTUPLET = 136,
    TRAFFIC_FLOW_TEMPLATE = 137,
    TARGET_IDENTIFICATION = 138,
    UTRAN_TRANSPARENT_CONTAINER = 139,
    RAB_SETUP_INFO = 140,
    EXTENSION_HEADER_TYPE_LIST = 141,
    TRIGGER_ID = 142,
    OMC_IDENTITY = 143,
    RAN_TRANSPARENT_CONTAINER = 144,
    PDP_CONTEXT_PRIORITIZATION = 145,
    ADDITIONAL_RAB_SETUP_INFO = 146,
    SGSN_NUMBER = 147,
    COMMON_FLAGS = 148,
    APN_RESTRICTION = 149,
    RADIO_PRIORITY_LCS = 150,
    RAT_TYPE = 151,
    USER_LOCATION_INFO = 152,
    MS_TIME_ZONE = 153,
    IMEI_SV = 154,
    CAMEL_CHARGING_INFO_CONTAINER = 155,
    MBMS_UE_CONTEXT = 156,
    TMGI = 157,            // Temporary Mobile Group Identity
    RIM_ROUTING_ADDRESS = 158,
    MBMS_PROTOCOL_CONFIG_OPTIONS = 159,
    MBMS_SERVICE_AREA = 160,
    SOURCE_RNC_PDCP_CONTEXT_INFO = 161,
    ADDITIONAL_TRACE_INFO = 162,
    HOP_COUNTER = 163,
    SELECTED_PLMN_ID = 164,
    MBMS_SESSION_IDENTIFIER = 165,
    MBMS_2G_3G_INDICATOR = 166,
    ENHANCED_NSAPI = 167,
    MBMS_SESSION_DURATION = 168,
    ADDITIONAL_MBMS_TRACE_INFO = 169,
    MBMS_SESSION_REPETITION_NUMBER = 170,
    MBMS_TIME_TO_DATA_TRANSFER = 171,
    BSS_CONTAINER = 173,
    CELL_IDENTIFICATION = 174,
    PDU_NUMBERS = 175,
    BSSGP_CAUSE = 176,
    REQUIRED_MBMS_BEARER_CAPABILITIES = 177,
    RIM_ROUTING_ADDRESS_DISCRIMINATOR = 178,
    LIST_OF_SETUP_PFCS = 179,
    PS_HANDOVER_XID_PARAMETERS = 180,
    MS_INFO_CHANGE_REPORTING_ACTION = 181,
    DIRECT_TUNNEL_FLAGS = 182,
    CORRELATION_ID = 183,
    BEARER_CONTROL_MODE = 184,
    MBMS_FLOW_IDENTIFIER = 185,
    MBMS_IP_MULTICAST_DISTRIBUTION = 186,
    MBMS_DISTRIBUTION_ACKNOWLEDGEMENT = 187,
    RELIABLE_INTER_RAT_HANDOVER_INFO = 188,
    RFSP_INDEX = 189,
    FQDN = 190,
    EVOLVED_ALLOCATION_RETENTION_PRIORITY_I = 191,
    EVOLVED_ALLOCATION_RETENTION_PRIORITY_II = 192,
    EXTENDED_COMMON_FLAGS = 193,
    UCI = 194,             // User CSG Information
    CSG_INFORMATION_REPORTING_ACTION = 195,
    CSG_ID = 196,
    CSG_MEMBERSHIP_INDICATION = 197,
    AGGREGATE_MAXIMUM_BIT_RATE = 198,
    UE_NETWORK_CAPABILITY = 199,
    UE_AMBR = 200,
    APN_AMBR_WITH_NSAPI = 201,
    GGSN_BACK_OFF_TIME = 202,
    SIGNALLING_PRIORITY_INDICATION = 203,
    SIGNALLING_PRIORITY_INDICATION_WITH_NSAPI = 204,
    HIGHER_BITRATES_THAN_16_MBPS_FLAG = 205,
    ADDITIONAL_MM_CONTEXT_FOR_SRVCC = 206,
    ADDITIONAL_FLAGS_FOR_SRVCC = 207,
    STN_SR = 208,
    C_MSISDN = 209,
    EXTENDED_RANAP_CAUSE = 210,
    ENODEB_ID = 211,
    SELECTION_MODE_WITH_NSAPI = 212,
    ULI_TIMESTAMP = 213,
    LHN_ID_WITH_NSAPI = 214,
    CN_OPERATOR_SELECTION_ENTITY = 215,
    UE_USAGE_TYPE = 216,
    EXTENDED_COMMON_FLAGS_II = 217,
    NODE_IDENTIFIER = 218,
    CIOT_OPTIMIZATIONS_SUPPORT_INDICATION = 219,
    SCEF_PDN_CONNECTION = 220,
    IOV_UPDATES_COUNTER = 221,
    MAPPED_UE_USAGE_TYPE = 222,
    UP_FUNCTION_SELECTION_INDICATION_FLAGS = 223,
    CHARGING_GATEWAY_ADDRESS = 251,
    PRIVATE_EXTENSION = 255
};

/**
 * GTPv1 header structure (3GPP TS 29.060)
 */
struct GtpV1Header {
    uint8_t version;              // Version (3 bits, should be 1)
    uint8_t protocol_type;        // Protocol Type (1 bit, 1=GTP, 0=GTP')
    bool extension_header;        // Extension Header flag
    bool sequence_number_flag;    // Sequence Number flag
    bool n_pdu_number_flag;       // N-PDU Number flag
    uint8_t message_type;         // Message type (1 byte)
    uint16_t message_length;      // Message length (2 bytes, excluding initial 8 bytes)
    uint32_t teid;                // Tunnel Endpoint Identifier (4 bytes)

    // Optional fields (present if any of the flags are set)
    std::optional<uint16_t> sequence_number;      // Sequence number (2 bytes)
    std::optional<uint8_t> n_pdu_number;          // N-PDU number (1 byte)
    std::optional<uint8_t> next_extension_header; // Next extension header type (1 byte)

    nlohmann::json toJson() const;
};

/**
 * GTPv1 Information Element structure
 */
struct GtpV1InformationElement {
    uint8_t type;                 // IE type (1 byte)
    std::vector<uint8_t> data;    // IE data (variable length, type-dependent)

    nlohmann::json toJson() const;

    /**
     * Get IE data as string (for IMSI, MSISDN, APN, etc.)
     */
    std::string getDataAsString() const;

    /**
     * Get IE type name
     */
    std::string getTypeName() const;

    /**
     * Get IE length (extracted from data for TLV types)
     */
    uint16_t getLength() const;
};

/**
 * Complete GTPv1 message structure
 */
struct GtpV1Message {
    GtpV1Header header;
    std::vector<GtpV1InformationElement> ies;

    // Common extracted fields
    std::optional<std::string> imsi;
    std::optional<std::string> apn;
    std::optional<std::string> msisdn;
    std::optional<uint8_t> cause;
    std::optional<uint32_t> teid_data;
    std::optional<uint32_t> teid_control;
    std::optional<uint8_t> nsapi;
    std::vector<uint8_t> qos_profile;
    std::optional<std::string> gsn_address;

    nlohmann::json toJson() const;

    /**
     * Get message type for session correlation
     */
    MessageType getMessageType() const;

    /**
     * Get human-readable message type name
     */
    std::string getMessageTypeName() const;

    /**
     * Check if this is a user plane message (G-PDU)
     */
    bool isUserPlane() const;
};

/**
 * GTPv1 protocol parser (3GPP TS 29.060)
 */
class GtpV1Parser {
public:
    GtpV1Parser() = default;
    ~GtpV1Parser() = default;

    /**
     * Parse GTPv1 message from packet payload
     * @param data Packet payload data
     * @param len Payload length
     * @return Parsed GTPv1 message or nullopt if parsing fails
     */
    std::optional<GtpV1Message> parse(const uint8_t* data, size_t len);

    /**
     * Check if data appears to be a GTPv1 message
     */
    static bool isGtpV1(const uint8_t* data, size_t len);

private:
    /**
     * Parse GTPv1 header
     */
    std::optional<GtpV1Header> parseHeader(const uint8_t* data, size_t len);

    /**
     * Parse IEs from message
     */
    bool parseIes(const uint8_t* data, size_t len, size_t offset,
                  std::vector<GtpV1InformationElement>& ies);

    /**
     * Parse single IE
     */
    std::optional<GtpV1InformationElement> parseIe(const uint8_t* data, size_t len,
                                                   size_t& offset, uint8_t ie_type);

    /**
     * Extract common fields from IEs
     */
    void extractCommonFields(GtpV1Message& msg);

    /**
     * Decode IMSI from IE data (BCD encoded)
     */
    static std::string decodeImsi(const std::vector<uint8_t>& data);

    /**
     * Decode MSISDN from IE data (BCD encoded)
     */
    static std::string decodeMsisdn(const std::vector<uint8_t>& data);

    /**
     * Decode APN from IE data (length-prefixed labels)
     */
    static std::string decodeApn(const std::vector<uint8_t>& data);

    /**
     * Decode GSN address from IE data (IPv4 or IPv6)
     */
    static std::string decodeGsnAddress(const std::vector<uint8_t>& data);

    /**
     * Get IE length based on type (fixed or variable TLV)
     */
    static std::optional<size_t> getIeLength(uint8_t type, const uint8_t* data,
                                             size_t len, size_t offset);
};

}  // namespace callflow
