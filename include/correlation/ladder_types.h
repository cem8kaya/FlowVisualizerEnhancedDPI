#ifndef LADDER_TYPES_H
#define LADDER_TYPES_H

#include <string>
#include <vector>
#include <optional>
#include <chrono>
#include <nlohmann/json.hpp>
#include "../common/types.h"

namespace flowviz {

/**
 * Direction of message flow in ladder diagram
 */
enum class MessageDirection {
    REQUEST,      // Client -> Server request
    RESPONSE,     // Server -> Client response
    INDICATION,   // One-way notification
    BIDIRECTIONAL // Cannot determine direction
};

/**
 * Type of network participant
 */
enum class ParticipantType {
    UE,          // User Equipment
    ENODEB,      // LTE eNodeB
    GNODEB,      // 5G gNodeB
    MME,         // Mobility Management Entity
    AMF,         // Access and Mobility Management Function
    SGW,         // Serving Gateway
    PGW,         // PDN Gateway
    UPF,         // User Plane Function
    SMF,         // Session Management Function
    HSS,         // Home Subscriber Server
    UDM,         // Unified Data Management
    PCRF,        // Policy and Charging Rules Function
    PCF,         // Policy Control Function
    P_CSCF,      // Proxy Call Session Control Function
    I_CSCF,      // Interrogating CSCF
    S_CSCF,      // Serving CSCF
    AS,          // Application Server
    OCS,         // Online Charging System
    DNS,         // DNS Server
    DHCP,        // DHCP Server
    UNKNOWN      // Unknown or unclassified
};

/**
 * Information about a network participant
 */
struct ParticipantInfo {
    std::string id;                      // Unique ID (e.g., "MME-01", "eNodeB-10.0.1.50")
    ParticipantType type;                // Participant type
    std::string ip_address;              // IP address
    std::optional<std::string> friendly_name;  // User-friendly name
    std::optional<uint16_t> port;        // Port number if relevant

    // Serialization
    nlohmann::json toJson() const;

    // Comparison for deduplication
    bool operator==(const ParticipantInfo& other) const {
        return id == other.id && ip_address == other.ip_address;
    }
};

/**
 * Single event in ladder diagram (a message between participants)
 */
struct LadderEvent {
    std::string event_id;                // Unique UUID
    std::chrono::system_clock::time_point timestamp;  // Precise timestamp
    uint64_t timestamp_us;               // Microseconds since epoch (for JSON)

    std::string from_participant;        // Source participant ID
    std::string to_participant;          // Destination participant ID
    std::string interface;               // 3GPP interface (e.g., "S1-MME", "S11")
    ProtocolType protocol;               // Protocol type
    std::string protocol_name;           // Human-readable protocol name
    MessageType message_type;            // Message type enum
    std::string message;                 // Human-readable message name

    MessageDirection direction;          // Message direction

    // Optional fields
    std::optional<nlohmann::json> details;        // Message-specific details
    std::optional<std::string> procedure;         // Procedure name
    std::optional<uint32_t> procedure_step;       // Step number in procedure
    std::optional<std::string> correlation_id;    // Links related messages
    std::optional<uint64_t> latency_us;           // Latency from request (microseconds)

    // Original message reference
    std::optional<std::string> message_id;        // Reference to original SessionMessageRef

    // Serialization
    nlohmann::json toJson() const;

    // Comparison for sorting
    bool operator<(const LadderEvent& other) const {
        return timestamp < other.timestamp;
    }
};

/**
 * Grouping of events by procedure
 */
struct ProcedureGroup {
    std::string procedure_id;            // Unique UUID
    std::string procedure_name;          // Human-readable name
    std::string start_event_id;          // First event ID
    std::optional<std::string> end_event_id;      // Last event ID (if completed)
    std::chrono::system_clock::time_point start_time;
    std::optional<std::chrono::system_clock::time_point> end_time;
    std::chrono::milliseconds duration;  // Total duration
    bool success;                        // Success/failure status
    uint32_t total_events;               // Number of events

    // For nested procedures (e.g., VoLTE call contains bearer creation)
    std::vector<std::string> child_procedure_ids;

    // Serialization
    nlohmann::json toJson() const;
};

/**
 * Metrics for ladder diagram
 */
struct LadderMetrics {
    uint32_t total_events;
    std::chrono::milliseconds total_duration;
    std::chrono::milliseconds average_inter_event;
    std::map<std::string, uint64_t> latencies;  // Named latencies in microseconds

    nlohmann::json toJson() const;
};

/**
 * Complete ladder diagram data structure
 */
struct LadderDiagram {
    std::string diagram_type = "ladder";
    std::string title;
    std::string session_id;
    std::chrono::system_clock::time_point start_time;
    std::optional<std::chrono::system_clock::time_point> end_time;
    std::chrono::milliseconds duration_ms;

    std::vector<ParticipantInfo> participants;
    std::vector<LadderEvent> events;
    std::vector<ProcedureGroup> procedures;
    LadderMetrics metrics;

    // Serialization
    nlohmann::json toJson() const;
};

/**
 * Convert enums to strings
 */
std::string toString(ParticipantType type);
std::string toString(MessageDirection direction);
std::string participantTypeToString(ParticipantType type);
ParticipantType stringToParticipantType(const std::string& str);

} // namespace flowviz

#endif // LADDER_TYPES_H
