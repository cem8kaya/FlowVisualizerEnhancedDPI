#pragma once

#include "common/types.h"
#include <optional>
#include <vector>
#include <nlohmann/json.hpp>

namespace callflow {

/**
 * PFCP message types (3GPP TS 29.244)
 */
enum class PfcpMessageType : uint8_t {
    // Session management messages
    SESSION_ESTABLISHMENT_REQUEST = 50,
    SESSION_ESTABLISHMENT_RESPONSE = 51,
    SESSION_MODIFICATION_REQUEST = 52,
    SESSION_MODIFICATION_RESPONSE = 53,
    SESSION_DELETION_REQUEST = 54,
    SESSION_DELETION_RESPONSE = 55,
    SESSION_REPORT_REQUEST = 56,
    SESSION_REPORT_RESPONSE = 57,

    // Node management messages
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
    NODE_REPORT_REQUEST = 12,
    NODE_REPORT_RESPONSE = 13,
    SESSION_SET_DELETION_REQUEST = 14,
    SESSION_SET_DELETION_RESPONSE = 15
};

/**
 * PFCP Information Element types
 */
enum class PfcpIeType : uint16_t {
    // Common IEs
    CAUSE = 19,
    SOURCE_INTERFACE = 20,
    F_TEID = 21,
    NETWORK_INSTANCE = 22,
    SDF_FILTER = 23,
    APPLICATION_ID = 24,
    GATE_STATUS = 25,

    // Session IEs
    F_SEID = 57,  // Fully Qualified Session Endpoint Identifier
    NODE_ID = 60,
    PDR_ID = 56,  // Packet Detection Rule ID
    FAR_ID = 108, // Forwarding Action Rule ID
    QER_ID = 109, // QoS Enforcement Rule ID
    URR_ID = 81,  // Usage Reporting Rule ID

    // PDR (Packet Detection Rule) IEs
    CREATE_PDR = 1,
    PDI = 2,      // Packet Detection Information
    OUTER_HEADER_REMOVAL = 95,

    // FAR (Forwarding Action Rule) IEs
    CREATE_FAR = 3,
    APPLY_ACTION = 44,
    FORWARDING_PARAMETERS = 4,
    DESTINATION_INTERFACE = 42,

    // QER (QoS Enforcement Rule) IEs
    CREATE_QER = 7,
    QER_CORRELATION_ID = 28,
    GATE_STATUS_IE = 25,
    MBR = 26,  // Maximum Bit Rate
    GBR = 27,  // Guaranteed Bit Rate

    // URR (Usage Reporting Rule) IEs
    CREATE_URR = 6,
    MEASUREMENT_METHOD = 62,
    REPORTING_TRIGGERS = 37,

    // Traffic endpoint IEs
    UE_IP_ADDRESS = 93,
    SDF_FILTER_IE = 23,

    // Recovery timestamp
    RECOVERY_TIME_STAMP = 96,

    // User Plane IEs
    UP_FUNCTION_FEATURES = 43,
    CP_FUNCTION_FEATURES = 89
};

/**
 * PFCP header structure (TS 29.244 Section 7.2.2)
 */
struct PfcpHeader {
    uint8_t version;              // Version (3 bits), should be 1
    bool spare;                   // Spare bit
    bool mp;                      // Message Priority
    bool s;                       // SEID flag (Session Endpoint ID present)
    uint8_t message_type;         // Message type (1 byte)
    uint16_t message_length;      // Message length (2 bytes, excluding header)
    uint64_t seid;                // Session Endpoint Identifier (8 bytes, if S flag)
    uint32_t sequence_number;     // Sequence number (3 bytes)
    uint8_t message_priority;     // Message priority (4 bits, if MP flag)

    nlohmann::json toJson() const;
};

/**
 * PFCP Information Element structure
 */
struct PfcpInformationElement {
    uint16_t type;                // IE type (2 bytes)
    uint16_t length;              // IE length (2 bytes)
    std::vector<uint8_t> data;    // IE data

    nlohmann::json toJson() const;

    /**
     * Get IE data as string
     */
    std::string getDataAsString() const;

    /**
     * Get IE data as uint32
     */
    std::optional<uint32_t> getDataAsUint32() const;

    /**
     * Get IE data as uint64
     */
    std::optional<uint64_t> getDataAsUint64() const;

    /**
     * Get IE type name
     */
    std::string getTypeName() const;
};

/**
 * Complete PFCP message structure
 */
struct PfcpMessage {
    PfcpHeader header;
    std::vector<PfcpInformationElement> ies;

    // Common extracted fields
    std::optional<uint64_t> f_seid;
    std::optional<uint32_t> f_teid;
    std::optional<std::string> node_id;
    std::optional<uint8_t> cause;
    std::optional<std::string> ue_ip_address;
    std::optional<uint32_t> recovery_timestamp;

    nlohmann::json toJson() const;

    /**
     * Get message type for session correlation
     */
    MessageType getMessageType() const;

    /**
     * Get human-readable message type name
     */
    std::string getMessageTypeName() const;
};

/**
 * PFCP protocol parser (3GPP TS 29.244)
 */
class PfcpParser {
public:
    PfcpParser() = default;
    ~PfcpParser() = default;

    /**
     * Parse PFCP message from packet payload
     * @param data Packet payload data
     * @param len Payload length
     * @return Parsed PFCP message or nullopt if parsing fails
     */
    std::optional<PfcpMessage> parse(const uint8_t* data, size_t len);

    /**
     * Check if data appears to be a PFCP message
     */
    static bool isPfcp(const uint8_t* data, size_t len);

private:
    /**
     * Parse PFCP header
     */
    std::optional<PfcpHeader> parseHeader(const uint8_t* data, size_t len);

    /**
     * Parse IEs from message
     */
    bool parseIes(const uint8_t* data, size_t len, size_t offset,
                  std::vector<PfcpInformationElement>& ies);

    /**
     * Parse single IE
     */
    std::optional<PfcpInformationElement> parseIe(const uint8_t* data, size_t len,
                                                  size_t& offset);

    /**
     * Extract common fields from IEs
     */
    void extractCommonFields(PfcpMessage& msg);

    /**
     * Decode Node ID from IE data
     */
    static std::string decodeNodeId(const std::vector<uint8_t>& data);

    /**
     * Decode UE IP address from IE data
     */
    static std::string decodeUeIpAddress(const std::vector<uint8_t>& data);

    /**
     * Decode F-SEID (Fully Qualified Session Endpoint Identifier)
     */
    static std::optional<uint64_t> decodeFSeid(const std::vector<uint8_t>& data);

    /**
     * Decode F-TEID
     */
    static std::optional<uint32_t> decodeFTeid(const std::vector<uint8_t>& data);
};

}  // namespace callflow
