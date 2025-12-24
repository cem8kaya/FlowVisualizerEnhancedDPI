#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace callflow {

// Type aliases for clarity
using Timestamp = std::chrono::system_clock::time_point;
using SessionId = std::string;
using PacketId = std::string;
using EventId = std::string;
using JobId = std::string;

// Packet direction
enum class Direction { UNKNOWN = 0, CLIENT_TO_SERVER, SERVER_TO_CLIENT, BIDIRECTIONAL };

std::string directionToString(Direction dir);
Direction stringToDirection(const std::string& str);

// Protocol types
enum class ProtocolType {
    UNKNOWN = 0,
    SIP,
    RTP,
    RTCP,
    GTP_C,
    GTP_U = 5,
    PFCP,          // PFCP was 6 implicitly, now it will be 6 explicitly if GTP_U is 5.
    DIAMETER = 7,  // DIAMETER was 7 implicitly, now it will be 7 explicitly.
    HTTP2,
    HTTP,
    DNS,
    DHCP = 11,  // DHCP is new, assigned 11.
    NGAP = 12,
    S1AP,
    X2AP,  // NGAP is new, assigned 12.
    SCTP,
    TCP,
    UDP,
    IP
};

// EnhancedSessionType moved to session/session_types.h

std::string protocolTypeToString(ProtocolType proto);
ProtocolType stringToProtocolType(const std::string& str);

// Session type
enum class SessionType {
    UNKNOWN = 0,
    VOLTE,     // VoLTE call (SIP + RTP)
    GTP,       // GTP bearer session
    PFCP,      // PFCP session (5G control plane)
    DIAMETER,  // DIAMETER session
    HTTP2,     // HTTP/2 session
    MIXED      // Mixed/uncategorized
};

std::string sessionTypeToString(SessionType type);
SessionType stringToSessionType(const std::string& str);

// Message type (for specific protocol messages)
enum class MessageType {
    UNKNOWN = 0,
    // SIP
    SIP_INVITE,
    SIP_TRYING,
    SIP_RINGING,
    SIP_SESSION_PROGRESS,
    SIP_OK,
    SIP_ACK,
    SIP_BYE,
    SIP_CANCEL,
    SIP_REGISTER,
    SIP_OPTIONS,
    SIP_UPDATE,
    SIP_PRACK,
    // DIAMETER
    DIAMETER_CCR,
    DIAMETER_CCA,
    DIAMETER_AAR,
    DIAMETER_AAA,
    DIAMETER_RAR,  // Re-Auth Request (policy push)
    DIAMETER_RAA,  // Re-Auth Answer
    // GTP
    GTP_CREATE_SESSION_REQ,
    GTP_CREATE_SESSION_RESP,
    GTP_MODIFY_BEARER_REQ,
    GTP_MODIFY_BEARER_RESP,
    GTP_DELETE_SESSION_REQ,
    GTP_DELETE_SESSION_RESP,
    GTP_CREATE_BEARER_REQ,
    GTP_CREATE_BEARER_RESP,
    GTP_DELETE_BEARER_REQ,
    GTP_DELETE_BEARER_RESP,
    GTP_ECHO_REQ,
    GTP_ECHO_RESP,
    // PFCP (5G control plane)
    PFCP_HEARTBEAT_REQ,
    PFCP_HEARTBEAT_RESP,
    PFCP_ASSOCIATION_SETUP_REQ,
    PFCP_ASSOCIATION_SETUP_RESP,
    PFCP_SESSION_ESTABLISHMENT_REQ,
    PFCP_SESSION_ESTABLISHMENT_RESP,
    PFCP_SESSION_MODIFICATION_REQ,
    PFCP_SESSION_MODIFICATION_RESP,
    PFCP_SESSION_DELETION_REQ,
    PFCP_SESSION_DELETION_RESP,
    PFCP_SESSION_REPORT_REQ,
    PFCP_SESSION_REPORT_RESP,
    // HTTP/2
    HTTP2_HEADERS,
    HTTP2_DATA,
    HTTP2_SETTINGS,
    HTTP2_PING,
    HTTP2_GOAWAY,
    // S1AP (LTE control plane)
    S1AP_INITIAL_UE_MESSAGE,
    S1AP_DOWNLINK_NAS_TRANSPORT,
    S1AP_UPLINK_NAS_TRANSPORT,
    S1AP_INITIAL_CONTEXT_SETUP_REQ,
    S1AP_INITIAL_CONTEXT_SETUP_RESP,
    S1AP_UE_CONTEXT_RELEASE_COMMAND,
    S1AP_UE_CONTEXT_RELEASE_COMPLETE,
    S1AP_HANDOVER_REQUIRED,
    S1AP_HANDOVER_REQUEST,
    S1AP_HANDOVER_REQUEST_ACK,
    S1AP_HANDOVER_COMMAND,
    S1AP_HANDOVER_NOTIFY,
    S1AP_PATH_SWITCH_REQUEST,
    S1AP_PATH_SWITCH_REQUEST_ACK,
    S1AP_E_RAB_SETUP_REQ,
    S1AP_E_RAB_SETUP_RESP,
    // X2AP (LTE handover)
    X2AP_HANDOVER_REQUEST,
    X2AP_HANDOVER_REQUEST_ACK,
    X2AP_HANDOVER_PREPARATION,
    X2AP_HANDOVER_CANCEL,
    X2AP_SN_STATUS_TRANSFER,
    X2AP_UE_CONTEXT_RELEASE,
    X2AP_SETUP,
    X2AP_RESET,
    X2AP_ENB_CONFIGURATION_UPDATE,
    X2AP_RESOURCE_STATUS_REPORTING,
    X2AP_CELL_ACTIVATION,
    // NGAP (5G control plane)
    NGAP_INITIAL_UE_MESSAGE,
    NGAP_DOWNLINK_NAS_TRANSPORT,
    NGAP_UPLINK_NAS_TRANSPORT,
    NGAP_INITIAL_CONTEXT_SETUP_REQ,
    NGAP_INITIAL_CONTEXT_SETUP_RESP,
    NGAP_PDU_SESSION_RESOURCE_SETUP_REQ,
    NGAP_PDU_SESSION_RESOURCE_SETUP_RESP,
    NGAP_PDU_SESSION_RESOURCE_RELEASE,
    NGAP_HANDOVER_PREPARATION,
    NGAP_HANDOVER_REQUEST,
    NGAP_HANDOVER_REQUEST_ACK,
    NGAP_HANDOVER_NOTIFY,
    NGAP_PATH_SWITCH_REQUEST,
    NGAP_PATH_SWITCH_REQUEST_ACK,
    NGAP_NG_SETUP,
    NGAP_AMF_CONFIGURATION_UPDATE,
    // LTE NAS
    NAS_ATTACH_REQUEST,
    NAS_ATTACH_ACCEPT,
    NAS_ATTACH_COMPLETE,
    NAS_ATTACH_REJECT,
    NAS_DETACH_REQUEST,
    NAS_AUTHENTICATION_REQUEST,
    NAS_AUTHENTICATION_RESPONSE,
    NAS_AUTHENTICATION_FAILURE,
    NAS_SECURITY_MODE_COMMAND,
    NAS_SECURITY_MODE_COMPLETE,
    NAS_ESM_INFORMATION_REQUEST,
    NAS_ESM_INFORMATION_RESPONSE,
    NAS_PDN_CONNECTIVITY_REQUEST,
    NAS_PDN_CONNECTIVITY_REJECT,
    NAS_ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST,
    NAS_ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_REQUEST,
    // 5G NAS
    NAS5G_REGISTRATION_REQUEST,
    NAS5G_REGISTRATION_ACCEPT,
    NAS5G_REGISTRATION_COMPLETE,
    NAS5G_REGISTRATION_REJECT,
    NAS5G_DEREGISTRATION_REQUEST,
    NAS5G_AUTHENTICATION_REQUEST,
    NAS5G_AUTHENTICATION_RESPONSE,
    NAS5G_SECURITY_MODE_COMMAND,
    NAS5G_SECURITY_MODE_COMPLETE,
    NAS5G_PDU_SESSION_ESTABLISHMENT_REQUEST,
    NAS5G_PDU_SESSION_ESTABLISHMENT_ACCEPT,
    NAS5G_PDU_SESSION_ESTABLISHMENT_REJECT,
    NAS5G_PDU_SESSION_MODIFICATION,
    NAS5G_PDU_SESSION_RELEASE,
    // 5G SBA (HTTP/2)
    FIVEG_SBA_INTERACTION
};

std::string messageTypeToString(MessageType type);

// Network 5-tuple
struct FiveTuple {
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;  // IP protocol number (TCP=6, UDP=17, etc.)

    bool operator==(const FiveTuple& other) const;
    bool operator<(const FiveTuple& other) const {
        if (src_ip != other.src_ip)
            return src_ip < other.src_ip;
        if (dst_ip != other.dst_ip)
            return dst_ip < other.dst_ip;
        if (src_port != other.src_port)
            return src_port < other.src_port;
        if (dst_port != other.dst_port)
            return dst_port < other.dst_port;
        return protocol < other.protocol;
    }
    std::string toString() const;
    size_t hash() const;
};

// Network participant (endpoint)
struct Participant {
    std::string ip;
    uint16_t port;

    std::string toString() const { return ip + ":" + std::to_string(port); }

    bool operator==(const Participant& other) const { return ip == other.ip && port == other.port; }
};

// Packet metadata
struct PacketMetadata {
    PacketId packet_id;
    Timestamp timestamp;
    uint32_t frame_number;
    size_t packet_length;
    FiveTuple five_tuple;
    ProtocolType detected_protocol;
    std::vector<uint8_t> raw_data;
};

// Session metrics
struct SessionMetrics {
    uint64_t total_packets = 0;
    uint64_t total_bytes = 0;
    double rtp_packet_loss = 0.0;
    double rtp_jitter_ms = 0.0;
    uint32_t setup_time_ms = 0;
    std::optional<uint32_t> duration_ms;
};

// Job status enumeration
enum class JobStatus { QUEUED = 0, RUNNING, COMPLETED, FAILED };

std::string jobStatusToString(JobStatus status);
JobStatus stringToJobStatus(const std::string& str);

// Job information structure
struct JobInfo {
    JobId job_id;
    std::string input_filename;
    std::string original_filename;
    std::string output_filename;
    JobStatus status;
    int progress;  // 0-100
    Timestamp created_at;
    Timestamp started_at;
    Timestamp completed_at;
    std::string error_message;  // if failed
    std::vector<SessionId> session_ids;
    size_t session_count = 0;
    size_t total_packets = 0;
    size_t total_bytes = 0;

    // PCAPNG Metadata
    std::vector<std::string> comments;
    struct InterfaceStats {
        uint32_t interface_id;
        std::string interface_name;
        uint64_t packets_received;
        uint64_t packets_dropped;
    };
    std::vector<InterfaceStats> interface_stats;
};

// Database configuration
struct DatabaseConfig {
    bool enabled = true;
    std::string path = "./callflowd.db";
    int retention_days = 7;
    bool auto_vacuum = true;
    int busy_timeout_ms = 5000;
};

// UE Key Configuration
struct UEKeyConfig {
    std::string imsi;
    std::string k_nas_enc;  // Hex string
    std::string k_nas_int;  // Hex string
    std::string k_amf;      // Hex string (optional)
    int algorithm_enc = 0;  // 0=NEA0, 1=128-NEA1, 2=128-NEA2, 3=128-NEA3
    int algorithm_int = 0;  // 0=NIA0, 1=128-NIA1, 2=128-NIA2, 3=128-NIA3
};

// Configuration
struct Config {
    // Processing
    int worker_threads = 4;
    size_t max_packet_queue_size = 10000;

    // Memory limits
    size_t max_memory_mb = 16384;  // 16GB
    size_t max_flows = 100000;

    // Timeouts
    uint32_t flow_timeout_sec = 300;
    uint32_t session_timeout_sec = 600;

    // Output
    std::string output_dir = "./output";
    bool export_pcap_subsets = false;

    // API server
    bool enable_api_server = false;
    uint16_t api_port = 8080;
    std::string api_bind_address = "0.0.0.0";
    int api_worker_threads = 4;
    size_t max_upload_size_mb = 10240;  // 10GB
    std::string upload_dir = "/tmp/callflow-uploads";
    std::string results_dir = "/tmp/callflow-results";
    uint32_t retention_hours = 24;

    // WebSocket
    uint32_t ws_heartbeat_interval_sec = 30;
    size_t ws_event_queue_max = 1000;

    // nDPI
    bool enable_ndpi = true;
    std::vector<std::string> ndpi_protocols = {"SIP", "RTP", "HTTP", "DNS", "TLS"};

    // Database
    DatabaseConfig database;

    // UE Keys (for NAS decryption)
    std::vector<UEKeyConfig> ue_keys;
};

}  // namespace callflow

// Hash function for FiveTuple (for use in unordered_map)
namespace std {
template <>
struct hash<callflow::FiveTuple> {
    size_t operator()(const callflow::FiveTuple& ft) const { return ft.hash(); }
};
}  // namespace std
