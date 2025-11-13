#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <chrono>
#include <memory>
#include <optional>

namespace callflow {

// Type aliases for clarity
using Timestamp = std::chrono::system_clock::time_point;
using SessionId = std::string;
using PacketId = std::string;
using EventId = std::string;
using JobId = std::string;

// Packet direction
enum class Direction {
    UNKNOWN = 0,
    CLIENT_TO_SERVER,
    SERVER_TO_CLIENT,
    BIDIRECTIONAL
};

std::string directionToString(Direction dir);
Direction stringToDirection(const std::string& str);

// Protocol types
enum class ProtocolType {
    UNKNOWN = 0,
    SIP,
    RTP,
    RTCP,
    GTP_C,
    GTP_U,
    DIAMETER,
    HTTP2,
    HTTP,
    DNS,
    SCTP,
    TCP,
    UDP,
    IP
};

std::string protocolTypeToString(ProtocolType proto);
ProtocolType stringToProtocolType(const std::string& str);

// Session type
enum class SessionType {
    UNKNOWN = 0,
    VOLTE,         // VoLTE call (SIP + RTP)
    GTP,           // GTP bearer session
    DIAMETER,      // DIAMETER session
    HTTP2,         // HTTP/2 session
    MIXED          // Mixed/uncategorized
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
    // GTP
    GTP_CREATE_SESSION_REQ,
    GTP_CREATE_SESSION_RESP,
    GTP_DELETE_SESSION_REQ,
    GTP_DELETE_SESSION_RESP,
    GTP_ECHO_REQ,
    GTP_ECHO_RESP,
    // HTTP/2 (frames)
    HTTP2_HEADERS,
    HTTP2_DATA,
    HTTP2_SETTINGS,
    HTTP2_PING,
    HTTP2_GOAWAY,
    // HTTP/2 (request/response)
    HTTP2_GET,
    HTTP2_POST,
    HTTP2_PUT,
    HTTP2_DELETE,
    HTTP2_REQUEST,
    HTTP2_RESPONSE
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
    std::string toString() const;
    size_t hash() const;
};

// Network participant (endpoint)
struct Participant {
    std::string ip;
    uint16_t port;

    std::string toString() const {
        return ip + ":" + std::to_string(port);
    }

    bool operator==(const Participant& other) const {
        return ip == other.ip && port == other.port;
    }
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
enum class JobStatus {
    QUEUED = 0,
    RUNNING,
    COMPLETED,
    FAILED
};

std::string jobStatusToString(JobStatus status);
JobStatus stringToJobStatus(const std::string& str);

// Job information structure
struct JobInfo {
    JobId job_id;
    std::string input_filename;
    std::string output_filename;
    JobStatus status;
    int progress;  // 0-100
    Timestamp created_at;
    Timestamp started_at;
    Timestamp completed_at;
    std::string error_message;  // if failed
    std::vector<SessionId> session_ids;
    size_t total_packets = 0;
    size_t total_bytes = 0;
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
};

}  // namespace callflow

// Hash function for FiveTuple (for use in unordered_map)
namespace std {
template <>
struct hash<callflow::FiveTuple> {
    size_t operator()(const callflow::FiveTuple& ft) const {
        return ft.hash();
    }
};
}  // namespace std
