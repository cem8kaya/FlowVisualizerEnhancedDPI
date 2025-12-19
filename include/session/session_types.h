#pragma once

#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "common/types.h"

namespace callflow {

/**
 * Enhanced Session Type enumeration
 * Identifies specific types of mobile network sessions
 */
enum class EnhancedSessionType {
    UNKNOWN = 0,

    // LTE session types
    LTE_ATTACH,           // Initial attach procedure
    LTE_PDN_CONNECT,      // PDN connectivity establishment
    LTE_HANDOVER_X2,      // X2-based handover
    LTE_HANDOVER_S1,      // S1-based handover
    LTE_SERVICE_REQUEST,  // Service request (idle to connected)
    LTE_DETACH,           // Detach procedure

    // 5G session types
    G5_REGISTRATION,     // Initial/periodic registration
    G5_PDU_SESSION,      // PDU session establishment
    G5_HANDOVER,         // 5G handover (N2/Xn)
    G5_SERVICE_REQUEST,  // Service request
    G5_DEREGISTRATION,   // Deregistration procedure

    // Application-level sessions
    VOLTE_CALL,       // VoLTE voice call (IMS)
    VIDEO_STREAMING,  // Video streaming session
    WEB_BROWSING,     // HTTP/HTTPS browsing
    DATA_TRANSFER,    // Generic data transfer

    // Mixed/special sessions
    MIXED,      // Multiple session types
    INCOMPLETE  // Incomplete session (missing messages)
};

/**
 * Interface Type enumeration
 * Identifies the 3GPP interface where a message was captured
 */
enum class InterfaceType {
    UNKNOWN = 0,

    // LTE interfaces
    S1_MME,  // S1-AP between eNodeB and MME
    S1_U,    // GTP-U between eNodeB and SGW
    S11,     // GTPv2-C between MME and SGW
    S5_S8,   // GTPv2-C/GTP-U between SGW and PGW
    SGI,     // IP interface between PGW and external networks
    X2,      // X2AP between eNodeBs

    // 5G interfaces
    N1,  // NAS between UE and AMF
    N2,  // NGAP between gNB and AMF
    N3,  // GTP-U between gNB and UPF
    N4,  // PFCP between SMF and UPF
    N6,  // IP interface between UPF and data network
    XN,  // Xn interface between gNBs

    // IMS/VoLTE interfaces
    IMS_SIP,  // SIP signaling
    IMS_RTP,  // RTP media

    // Other
    DIAMETER,  // Diameter signaling
    HTTP_API   // HTTP/REST APIs
};

/**
 * Session Correlation Key
 * Contains all identifiers that can be used to correlate messages across interfaces
 */
struct SessionCorrelationKey {
    // Primary subscriber identifiers
    std::optional<std::string> imsi;    // IMSI (LTE)
    std::optional<std::string> supi;    // SUPI (5G)
    std::optional<std::string> guti;    // GUTI (Globally Unique Temporary Identifier)
    std::optional<std::string> msisdn;  // Phone number

    // Session identifiers
    std::optional<uint32_t> teid_s1u;       // TEID for S1-U (eNodeB-SGW)
    std::optional<uint32_t> teid_s5u;       // TEID for S5/S8-U (SGW-PGW)
    std::optional<uint64_t> seid_n4;        // SEID for N4 PFCP (SMF-UPF)
    std::optional<uint8_t> pdu_session_id;  // PDU Session ID (5G)
    std::optional<uint8_t> eps_bearer_id;   // EPS Bearer ID (LTE)

    // UE context identifiers
    std::optional<uint32_t> enb_ue_s1ap_id;  // eNodeB UE S1AP ID (LTE)
    std::optional<uint32_t> mme_ue_s1ap_id;  // MME UE S1AP ID (LTE)
    std::optional<uint64_t> ran_ue_ngap_id;  // RAN UE NGAP ID (5G)
    std::optional<uint64_t> amf_ue_ngap_id;  // AMF UE NGAP ID (5G)

    // IP addresses
    std::optional<std::string> ue_ipv4;     // UE IPv4 address
    std::optional<std::string> ue_ipv6;     // UE IPv6 address
    std::optional<std::string> pgw_upf_ip;  // PGW/UPF IP address

    // Network identifiers
    std::optional<std::string> apn;  // Access Point Name (LTE)
    std::optional<std::string> dnn;  // Data Network Name (5G)
    std::optional<std::string> network_instance;

    // Application identifiers
    std::optional<std::string> sip_call_id;  // SIP Call-ID for VoLTE
    std::optional<uint32_t> rtp_ssrc;        // RTP SSRC

    /**
     * Check if this key matches another key (partial match)
     * Returns true if any common identifier matches
     */
    bool matches(const SessionCorrelationKey& other) const;

    /**
     * Merge another key into this one (union of all identifiers)
     */
    void merge(const SessionCorrelationKey& other);

    /**
     * Convert to JSON for debugging and storage
     */
    nlohmann::json toJson() const;

    /**
     * Get a unique hash for this correlation key
     */
    size_t hash() const;

    /**
     * Get primary identifier (IMSI/SUPI) for indexing
     */
    std::string getPrimaryIdentifier() const;
};

/**
 * Session Message Reference
 * Links a protocol message to a session
 */
struct SessionMessageRef {
    std::string message_id;                 // Unique message ID (from database)
    PacketId packet_id;                     // Packet ID
    Timestamp timestamp;                    // Message timestamp
    InterfaceType interface;                // Interface where message was captured
    ProtocolType protocol;                  // Protocol type
    MessageType message_type;               // Specific message type
    SessionCorrelationKey correlation_key;  // Extracted correlation keys
    uint32_t sequence_in_session;           // Sequence number within session

    // 5-tuple info for UI display
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port;
    uint16_t dst_port;

    nlohmann::json toJson() const;
};

/**
 * Session Leg
 * Represents a sequence of messages on a single interface
 */
struct SessionLeg {
    InterfaceType interface;
    std::vector<SessionMessageRef> messages;
    Timestamp start_time;
    Timestamp end_time;
    uint64_t total_bytes;

    nlohmann::json toJson() const;

    /**
     * Get duration in milliseconds
     */
    uint64_t getDurationMs() const;
};

/**
 * Complete Session
 * Represents a correlated session across multiple interfaces
 */
struct Session {
    std::string session_id;                                 // Unique session ID (UUID)
    EnhancedSessionType session_type;                       // Detected session type
    SessionCorrelationKey correlation_key;                  // Primary correlation key
    Timestamp start_time;                                   // Session start time
    Timestamp end_time;                                     // Session end time
    std::vector<SessionLeg> legs;                           // Messages grouped by interface
    std::vector<InterfaceType> interfaces_involved;         // All interfaces involved
    std::unordered_map<std::string, std::string> metadata;  // Additional metadata

    // Statistics
    uint64_t total_packets;
    uint64_t total_bytes;
    std::optional<uint32_t> setup_time_ms;  // Time to establish session
    bool is_complete;                       // Whether session has proper start/end

    nlohmann::json toJson() const;

    /**
     * Get all messages in chronological order
     */
    std::vector<SessionMessageRef> getAllMessages() const;

    /**
     * Get messages for a specific interface
     */
    std::vector<SessionMessageRef> getMessagesForInterface(InterfaceType interface) const;

    /**
     * Get session duration in milliseconds
     */
    uint64_t getDurationMs() const;

    /**
     * Add a message to the session
     */
    void addMessage(const SessionMessageRef& msg);

    /**
     * Finalize session (compute statistics, sort messages, etc.)
     */
    void finalize();
};

/**
 * Session Statistics
 * Aggregated statistics for a session
 */
struct SessionStatistics {
    uint32_t total_sessions;
    std::unordered_map<EnhancedSessionType, uint32_t> sessions_by_type;
    std::unordered_map<InterfaceType, uint32_t> messages_by_interface;
    uint64_t total_messages;
    uint64_t total_bytes;
    double average_session_duration_ms;
    double average_setup_time_ms;

    nlohmann::json toJson() const;
};

// ============================================================================
// Helper functions
// ============================================================================

/**
 * Convert EnhancedSessionType to string
 */
std::string enhancedSessionTypeToString(EnhancedSessionType type);

/**
 * Convert string to EnhancedSessionType
 */
EnhancedSessionType stringToEnhancedSessionType(const std::string& str);

/**
 * Convert InterfaceType to string
 */
std::string interfaceTypeToString(InterfaceType type);

/**
 * Convert string to InterfaceType
 */
InterfaceType stringToInterfaceType(const std::string& str);

/**
 * Determine interface type from protocol and port
 */
InterfaceType detectInterfaceType(ProtocolType protocol, uint16_t src_port, uint16_t dst_port);

}  // namespace callflow

// Hash function for SessionCorrelationKey
namespace std {
template <>
struct hash<callflow::SessionCorrelationKey> {
    size_t operator()(const callflow::SessionCorrelationKey& key) const { return key.hash(); }
};
}  // namespace std
