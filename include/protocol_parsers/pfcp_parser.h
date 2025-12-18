#pragma once

#include "common/types.h"
#include <optional>
#include <vector>
#include <nlohmann/json.hpp>

namespace callflow {

/**
 * PFCP Message Types (3GPP TS 29.244)
 * PFCP is used between control plane and user plane functions (SMF-UPF in 5G, PGW-C/U in LTE)
 */
enum class PfcpMessageType : uint8_t {
    // Node related messages
    HEARTBEAT_REQUEST = 1,
    HEARTBEAT_RESPONSE = 2,
    PFD_MANAGEMENT_REQUEST = 3,
    PFD_MANAGEMENT_RESPONSE = 4,
    ASSOCIATION_SETUP_REQUEST = 5,
    ASSOCIATION_SETUP_RESPONSE = 6,
    ASSOCIATION_UPDATE_REQUEST = 7,
    ASSOCIATION_UPDATE_RESPONSE = 8,
    ASSOCIATION_RELEASE_REQUEST = 9,
    ASSOCIATION_RELEASE_RESPONSE = 10,
    VERSION_NOT_SUPPORTED = 11,
    NODE_REPORT_REQUEST = 12,
    NODE_REPORT_RESPONSE = 13,

    // Session related messages
    SESSION_ESTABLISHMENT_REQUEST = 50,
    SESSION_ESTABLISHMENT_RESPONSE = 51,
    SESSION_MODIFICATION_REQUEST = 52,
    SESSION_MODIFICATION_RESPONSE = 53,
    SESSION_DELETION_REQUEST = 54,
    SESSION_DELETION_RESPONSE = 55,
    SESSION_REPORT_REQUEST = 56,
    SESSION_REPORT_RESPONSE = 57,

    UNKNOWN = 0xFF
};

/**
 * PFCP Information Element Types (3GPP TS 29.244 Section 8.2)
 */
enum class PfcpIeType : uint16_t {
    // Network instance and node identification
    CREATE_PDR = 1,                         // Packet Detection Rule
    PDI = 2,                                // Packet Detection Information
    CREATE_FAR = 3,                         // Forwarding Action Rule
    FORWARDING_PARAMETERS = 4,
    DUPLICATING_PARAMETERS = 5,
    CREATE_URR = 6,                         // Usage Reporting Rule
    CREATE_QER = 7,                         // QoS Enforcement Rule
    CREATED_PDR = 8,
    UPDATE_PDR = 9,
    UPDATE_FAR = 10,
    UPDATE_FORWARDING_PARAMETERS = 11,
    UPDATE_BAR = 12,                        // Buffering Action Rule
    UPDATE_URR = 13,
    UPDATE_QER = 14,
    REMOVE_PDR = 15,
    REMOVE_FAR = 16,
    REMOVE_URR = 17,
    REMOVE_QER = 18,

    // Cause
    CAUSE = 19,
    SOURCE_INTERFACE = 20,
    F_TEID = 21,                            // Fully Qualified TEID (for GTP-U)
    NETWORK_INSTANCE = 22,
    SDF_FILTER = 23,                        // Service Data Flow Filter
    APPLICATION_ID = 24,
    GATE_STATUS = 25,
    MBR = 26,                               // Maximum Bit Rate
    GBR = 27,                               // Guaranteed Bit Rate
    QER_CORRELATION_ID = 28,
    PRECEDENCE = 29,
    TRANSPORT_LEVEL_MARKING = 30,
    VOLUME_THRESHOLD = 31,
    TIME_THRESHOLD = 32,
    MONITORING_TIME = 33,
    SUBSEQUENT_VOLUME_THRESHOLD = 34,
    SUBSEQUENT_TIME_THRESHOLD = 35,
    INACTIVITY_DETECTION_TIME = 36,
    REPORTING_TRIGGERS = 37,
    REDIRECT_INFORMATION = 38,
    REPORT_TYPE = 39,
    OFFENDING_IE = 40,
    FORWARDING_POLICY = 41,
    DESTINATION_INTERFACE = 42,
    UP_FUNCTION_FEATURES = 43,
    APPLY_ACTION = 44,
    DOWNLINK_DATA_SERVICE_INFORMATION = 45,
    DOWNLINK_DATA_NOTIFICATION_DELAY = 46,
    DL_BUFFERING_DURATION = 47,
    DL_BUFFERING_SUGGESTED_PACKET_COUNT = 48,
    PFCPSMREQ_FLAGS = 49,                   // PFCPSMReq-Flags
    PFCPSRRSP_FLAGS = 50,                   // PFCPSRRsp-Flags

    // Session endpoint and identifiers
    LOAD_CONTROL_INFORMATION = 51,
    SEQUENCE_NUMBER = 52,
    METRIC = 53,
    OVERLOAD_CONTROL_INFORMATION = 54,
    TIMER = 55,
    PDR_ID = 56,                            // Packet Detection Rule ID
    F_SEID = 57,                            // Fully Qualified Session Endpoint Identifier
    APPLICATION_ID_PFDS = 58,
    PFD_CONTEXT = 59,
    NODE_ID = 60,
    PFD_CONTENTS = 61,
    MEASUREMENT_METHOD = 62,
    USAGE_REPORT_TRIGGER = 63,
    MEASUREMENT_PERIOD = 64,
    FQ_CSID = 65,                           // Fully Qualified PDN Connection Set Identifier
    VOLUME_MEASUREMENT = 66,
    DURATION_MEASUREMENT = 67,
    APPLICATION_DETECTION_INFORMATION = 68,
    TIME_OF_FIRST_PACKET = 69,
    TIME_OF_LAST_PACKET = 70,
    QUOTA_HOLDING_TIME = 71,
    DROPPED_DL_TRAFFIC_THRESHOLD = 72,
    VOLUME_QUOTA = 73,
    TIME_QUOTA = 74,
    START_TIME = 75,
    END_TIME = 76,
    QUERY_URR = 77,
    USAGE_REPORT_SMR = 78,
    USAGE_REPORT_SDR = 79,
    USAGE_REPORT_SRR = 80,
    URR_ID = 81,                            // Usage Reporting Rule ID
    LINKED_URR_ID = 82,
    DOWNLINK_DATA_REPORT = 83,
    OUTER_HEADER_CREATION = 84,
    CREATE_BAR = 85,
    UPDATE_BAR_SMR = 86,
    REMOVE_BAR = 87,
    BAR_ID = 88,
    CP_FUNCTION_FEATURES = 89,
    USAGE_INFORMATION = 90,
    APPLICATION_INSTANCE_ID = 91,
    FLOW_INFORMATION = 92,
    UE_IP_ADDRESS = 93,                     // UE IP address
    PACKET_RATE = 94,
    OUTER_HEADER_REMOVAL = 95,
    RECOVERY_TIME_STAMP = 96,
    DL_FLOW_LEVEL_MARKING = 97,
    HEADER_ENRICHMENT = 98,
    ERROR_INDICATION_REPORT = 99,
    MEASUREMENT_INFORMATION = 100,
    NODE_REPORT_TYPE = 101,
    USER_PLANE_PATH_FAILURE_REPORT = 102,
    REMOTE_GTP_U_PEER = 103,
    UR_SEQN = 104,
    UPDATE_DUPLICATING_PARAMETERS = 105,
    ACTIVATE_PREDEFINED_RULES = 106,
    DEACTIVATE_PREDEFINED_RULES = 107,
    FAR_ID = 108,                           // Forwarding Action Rule ID
    QER_ID = 109,                           // QoS Enforcement Rule ID
    OCI_FLAGS = 110,
    PFCP_ASSOCIATION_RELEASE_REQUEST = 111,
    GRACEFUL_RELEASE_PERIOD = 112,
    PDN_TYPE = 113,
    FAILED_RULE_ID = 114,
    TIME_QUOTA_MECHANISM = 115,
    USER_PLANE_IP_RESOURCE_INFORMATION = 116,
    USER_PLANE_INACTIVITY_TIMER = 117,
    AGGREGATED_URRS = 118,
    MULTIPLIER = 119,
    AGGREGATED_URR_ID = 120,

    UNKNOWN = 0xFFFF
};

/**
 * PFCP Source Interface (IE Type 20)
 */
enum class PfcpSourceInterface : uint8_t {
    ACCESS = 0,         // From access network (N3 in 5G, S1-U in LTE)
    CORE = 1,           // From core network (N6 in 5G, SGi in LTE)
    SGI_LAN = 2,        // From SGi-LAN/N6-LAN
    CP_FUNCTION = 3     // From CP function
};

/**
 * PFCP Destination Interface (IE Type 42)
 */
enum class PfcpDestinationInterface : uint8_t {
    ACCESS = 0,         // To access network (N3 in 5G, S1-U in LTE)
    CORE = 1,           // To core network (N6 in 5G, SGi in LTE)
    SGI_LAN = 2,        // To SGi-LAN/N6-LAN
    CP_FUNCTION = 3,    // To CP function
    LI_FUNCTION = 4     // To Lawful Intercept function
};

/**
 * PFCP Apply Action flags (IE Type 44)
 */
struct PfcpApplyAction {
    bool drop;          // DROP: Drop the packet
    bool forward;       // FORW: Forward the packet
    bool buffer;        // BUFF: Buffer the packet
    bool notify_cp;     // NOCP: Notify CP function
    bool duplicate;     // DUPL: Duplicate the packet
};

/**
 * PFCP Header structure
 */
struct PfcpHeader {
    uint8_t version;                        // Version (3 bits) - should be 1
    bool spare;                             // S flag (SEID present)
    bool message_priority;                  // MP flag
    uint8_t message_type;                   // Message type (1 byte)
    uint16_t message_length;                // Message length (2 bytes)
    std::optional<uint64_t> seid;           // Session Endpoint Identifier (8 bytes, if S flag)
    uint32_t sequence_number;               // Sequence number (3 bytes)
    uint8_t message_priority_value;         // Message priority (4 bits, if MP flag)

    nlohmann::json toJson() const;
};

/**
 * PFCP Information Element structure
 */
struct PfcpInformationElement {
    uint16_t type;                          // IE type (2 bytes)
    uint16_t length;                        // IE length (2 bytes)
    std::vector<uint8_t> data;              // IE data

    nlohmann::json toJson() const;

    /**
     * Get IE type name
     */
    std::string getTypeName() const;

    /**
     * Get IE data as uint8
     */
    std::optional<uint8_t> getDataAsUint8() const;

    /**
     * Get IE data as uint16
     */
    std::optional<uint16_t> getDataAsUint16() const;

    /**
     * Get IE data as uint32
     */
    std::optional<uint32_t> getDataAsUint32() const;

    /**
     * Get IE data as uint64
     */
    std::optional<uint64_t> getDataAsUint64() const;

    /**
     * Get IE data as string (for node ID, network instance, etc.)
     */
    std::string getDataAsString() const;
};

/**
 * F-SEID (Fully Qualified Session Endpoint Identifier) structure
 */
struct PfcpFSeid {
    uint64_t seid;                          // Session Endpoint Identifier
    std::optional<std::string> ipv4;        // IPv4 address
    std::optional<std::string> ipv6;        // IPv6 address

    nlohmann::json toJson() const;
};

/**
 * F-TEID (Fully Qualified TEID) structure
 */
struct PfcpFTeid {
    uint32_t teid;                          // Tunnel Endpoint Identifier
    std::optional<std::string> ipv4;        // IPv4 address
    std::optional<std::string> ipv6;        // IPv6 address
    bool choose;                            // Choose flag
    uint8_t choose_id;                      // Choose ID

    nlohmann::json toJson() const;
};

/**
 * UE IP Address structure
 */
struct PfcpUeIpAddress {
    std::optional<std::string> ipv4;        // IPv4 address
    std::optional<std::string> ipv6;        // IPv6 address
    bool is_source;                         // Source or destination
    bool is_destination;

    nlohmann::json toJson() const;
};

/**
 * PDR (Packet Detection Rule) structure
 */
struct PfcpPdr {
    uint16_t pdr_id;                        // PDR ID
    uint32_t precedence;                    // Precedence
    std::optional<PfcpSourceInterface> source_interface;
    std::optional<PfcpFTeid> f_teid;        // F-TEID for GTP-U matching
    std::optional<std::string> network_instance;
    std::optional<PfcpUeIpAddress> ue_ip_address;
    std::optional<uint16_t> linked_far_id;  // Linked FAR ID
    std::vector<PfcpInformationElement> ies; // All IEs in PDR

    nlohmann::json toJson() const;
};

/**
 * FAR (Forwarding Action Rule) structure
 */
struct PfcpFar {
    uint32_t far_id;                        // FAR ID
    PfcpApplyAction apply_action;           // Apply action flags
    std::optional<PfcpDestinationInterface> destination_interface;
    std::optional<PfcpFTeid> outer_header_creation; // For GTP-U encapsulation
    std::optional<std::string> network_instance;
    std::vector<PfcpInformationElement> ies; // All IEs in FAR

    nlohmann::json toJson() const;
};

/**
 * URR (Usage Reporting Rule) structure
 */
struct PfcpUrr {
    uint32_t urr_id;                        // URR ID
    uint32_t measurement_method;            // Measurement method flags
    std::optional<uint64_t> volume_threshold;
    std::optional<uint32_t> time_threshold;
    std::vector<PfcpInformationElement> ies; // All IEs in URR

    nlohmann::json toJson() const;
};

/**
 * QER (QoS Enforcement Rule) structure
 */
struct PfcpQer {
    uint32_t qer_id;                        // QER ID
    uint8_t qci;                            // QoS Class Identifier
    std::optional<uint64_t> mbr_uplink;     // Maximum Bit Rate uplink
    std::optional<uint64_t> mbr_downlink;   // Maximum Bit Rate downlink
    std::optional<uint64_t> gbr_uplink;     // Guaranteed Bit Rate uplink
    std::optional<uint64_t> gbr_downlink;   // Guaranteed Bit Rate downlink
    std::vector<PfcpInformationElement> ies; // All IEs in QER

    nlohmann::json toJson() const;
};

/**
 * Complete PFCP message structure
 */
struct PfcpMessage {
    PfcpHeader header;
    std::vector<PfcpInformationElement> ies;

    // Decoded structures
    std::optional<PfcpFSeid> f_seid;
    std::optional<std::string> node_id;
    std::vector<PfcpPdr> pdrs;
    std::vector<PfcpFar> fars;
    std::vector<PfcpUrr> urrs;
    std::vector<PfcpQer> qers;

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
     * Check if this is a session-related message
     */
    bool isSessionMessage() const;

    /**
     * Get session ID (SEID) if present
     */
    std::optional<uint64_t> getSessionId() const;
};

/**
 * PFCP Protocol Parser (3GPP TS 29.244)
 * Parses Packet Forwarding Control Protocol messages between SMF and UPF (5G)
 * or PGW-C and PGW-U (LTE)
 */
class PfcpParser {
public:
    PfcpParser() = default;
    ~PfcpParser() = default;

    /**
     * Parse PFCP message from UDP payload
     * @param data UDP payload data
     * @param len Payload length
     * @return Parsed PFCP message or nullopt if parsing fails
     */
    std::optional<PfcpMessage> parse(const uint8_t* data, size_t len);

    /**
     * Check if data appears to be a PFCP message
     * PFCP uses UDP port 8805
     */
    static bool isPfcp(const uint8_t* data, size_t len);

private:
    /**
     * Parse PFCP header
     */
    std::optional<PfcpHeader> parseHeader(const uint8_t* data, size_t len, size_t& offset);

    /**
     * Parse Information Elements from message
     */
    bool parseInformationElements(const uint8_t* data, size_t len, size_t offset,
                                   std::vector<PfcpInformationElement>& ies);

    /**
     * Parse single IE
     */
    std::optional<PfcpInformationElement> parseIe(const uint8_t* data, size_t len,
                                                   size_t& offset);

    /**
     * Extract session ID (F-SEID) from IEs
     */
    std::optional<PfcpFSeid> extractFSeid(const std::vector<PfcpInformationElement>& ies);

    /**
     * Extract node ID from IEs
     */
    std::optional<std::string> extractNodeId(const std::vector<PfcpInformationElement>& ies);

    /**
     * Extract PDR rules from IEs
     */
    std::vector<PfcpPdr> extractPdrRules(const std::vector<PfcpInformationElement>& ies);

    /**
     * Extract FAR rules from IEs
     */
    std::vector<PfcpFar> extractFarRules(const std::vector<PfcpInformationElement>& ies);

    /**
     * Extract URR rules from IEs
     */
    std::vector<PfcpUrr> extractUrrRules(const std::vector<PfcpInformationElement>& ies);

    /**
     * Extract QER rules from IEs
     */
    std::vector<PfcpQer> extractQerRules(const std::vector<PfcpInformationElement>& ies);

    /**
     * Parse grouped IE (PDR, FAR, URR, QER contain nested IEs)
     */
    std::vector<PfcpInformationElement> parseGroupedIe(const std::vector<uint8_t>& data);

    /**
     * Decode F-SEID from IE data
     */
    static std::optional<PfcpFSeid> decodeFSeid(const std::vector<uint8_t>& data);

    /**
     * Decode F-TEID from IE data
     */
    static std::optional<PfcpFTeid> decodeFTeid(const std::vector<uint8_t>& data);

    /**
     * Decode UE IP address from IE data
     */
    static std::optional<PfcpUeIpAddress> decodeUeIpAddress(const std::vector<uint8_t>& data);

    /**
     * Decode node ID from IE data
     */
    static std::string decodeNodeId(const std::vector<uint8_t>& data);

    /**
     * Decode network instance from IE data
     */
    static std::string decodeNetworkInstance(const std::vector<uint8_t>& data);

    /**
     * Extract common fields from message
     */
    void extractCommonFields(PfcpMessage& msg);
};

/**
 * Convert PFCP message type to string
 */
std::string pfcpMessageTypeToString(PfcpMessageType type);

/**
 * Convert PFCP IE type to string
 */
std::string pfcpIeTypeToString(PfcpIeType type);

/**
 * Convert PFCP source interface to string
 */
std::string pfcpSourceInterfaceToString(PfcpSourceInterface iface);

/**
 * Convert PFCP destination interface to string
 */
std::string pfcpDestinationInterfaceToString(PfcpDestinationInterface iface);

}  // namespace callflow
