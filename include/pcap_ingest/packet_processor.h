#pragma once

#include <pcap/pcap.h>  // for pcap_pkthdr

#include <chrono>
#include <mutex>
#include <set>
#include <unordered_map>

#include "common/types.h"
#include "pcap_ingest/ip_reassembler.h"
#include "pcap_ingest/link_layer_parser.h"
#include "pcap_ingest/tcp_reassembler.h"
#include "protocol_parsers/fiveg_sba_parser.h"
#include "protocol_parsers/http2_parser.h"
#include "session/session_correlator.h"
#include "transport/sctp_parser.h"

namespace callflow {

/**
 * SipPortTracker - Tracks non-standard SIP ports discovered during processing
 *
 * When SIP is detected on a non-standard port (e.g., via content inspection),
 * this tracker registers that port for future fast-path detection.
 */
class SipPortTracker {
public:
    SipPortTracker();

    /**
     * Register a non-standard SIP port
     *
     * @param port Port number to register
     */
    void registerSipPort(uint16_t port);

    /**
     * Check if a port is a known SIP port (standard or registered)
     *
     * @param port Port to check
     * @return true if port is registered as SIP port
     */
    bool isSipPort(uint16_t port) const;

    /**
     * Get all known SIP ports
     *
     * @return Set of all known SIP ports
     */
    std::set<uint16_t> getAllSipPorts() const;

private:
    mutable std::mutex mutex_;
    std::set<uint16_t> known_sip_ports_;
};

/**
 * DynamicPortTracker - Tracks RTP ports learned from SDP negotiation
 *
 * When SIP messages are parsed, SDP bodies contain media port information.
 * This tracker maintains a mapping of these dynamically allocated RTP ports
 * to their associated SIP Call-ID, enabling accurate RTP classification
 * even when ports are outside the standard range.
 */
class DynamicPortTracker {
public:
    /**
     * Register RTP ports learned from SDP
     *
     * @param call_id SIP Call-ID associated with the RTP stream
     * @param local_port Local RTP port (from SDP m= line)
     * @param remote_port Remote RTP port (from SDP connection)
     */
    void registerRtpPorts(const std::string& call_id,
                          uint16_t local_port,
                          uint16_t remote_port);

    /**
     * Check if a port is a known RTP port
     *
     * @param port Port to check
     * @return true if port is registered as RTP port
     */
    bool isKnownRtpPort(uint16_t port) const;

    /**
     * Get Call-ID associated with an RTP port
     *
     * @param port RTP port
     * @return Call-ID if found, nullopt otherwise
     */
    std::optional<std::string> getCallIdByPort(uint16_t port) const;

    /**
     * Remove expired port mappings
     * Call periodically to cleanup old entries
     *
     * @param current_time Current timestamp
     * @return Number of expired entries removed
     */
    size_t cleanupExpired(Timestamp current_time);

private:
    struct PortEntry {
        std::string call_id;
        Timestamp registered_at;
    };

    mutable std::mutex mutex_;
    std::unordered_map<uint16_t, PortEntry> port_to_call_id_;

    // Expire entries after 5 minutes (typical call duration)
    static constexpr std::chrono::seconds PORT_TTL{300};
};

/**
 * Orchestrates packet processing:
 * 1. Link Layer Stripping
 * 2. IP Defragmentation
 * 3. TCP Reassembly
 * 4. SCTP Stream Reassembly
 * 5. Protocol Parsing (via EnhancedSessionCorrelator handling)
 */
class PacketProcessor {
public:
    PacketProcessor(EnhancedSessionCorrelator& correlator);

    /**
     * Process a raw packet from PCAP/PCAPNG
     * @param data Raw packet data (including Link Header)
     * @param len Packet length
     * @param ts Packet timestamp (std::chrono)
     * @param frame_number Frame number
     * @param dlt Data Link Type
     */
    void processPacket(const uint8_t* data, size_t len, Timestamp ts, uint32_t frame_number,
                       int dlt);

private:
    EnhancedSessionCorrelator& correlator_;
    LinkLayerParser link_parser_;
    IpReassembler ip_reassembler_;
    TcpReassembler tcp_reassembler_;
    SctpParser sctp_parser_;

    // Stateful parsers
    // Map: FiveTuple -> Http2Connection
    // Note: We use FiveTuple hash as key for simpler map, or specialized hash map
    // Map: FiveTuple -> Http2Connection
    // Note: We use FiveTuple hash as key for simpler map, or specialized hash map
    std::unordered_map<FiveTuple, Http2Connection> http2_sessions_;

    struct TcpStreamBuffer {
        std::vector<uint8_t> buffer;
    };

    /**
     * Enhanced TCP stream buffer for SIP with message boundary detection
     * Handles fragmented SIP messages and multiple messages in single TCP segment
     */
    class SipTcpStreamBuffer {
    public:
        SipTcpStreamBuffer() = default;

        /**
         * Append data to buffer
         */
        void appendData(const uint8_t* data, size_t len);

        /**
         * Extract all complete SIP messages from buffer
         * @return Vector of complete SIP messages
         */
        std::vector<std::vector<uint8_t>> extractCompleteMessages();

        /**
         * Reset buffer (overflow protection)
         */
        void reset();

        /**
         * Get current buffer size
         */
        size_t getBufferSize() const { return buffer_.size(); }

        // Public constants for buffer size limits
        static constexpr size_t MAX_SIP_MESSAGE_SIZE = 64 * 1024;  // 64KB
        static constexpr size_t MAX_BUFFER_SIZE = 256 * 1024;      // 256KB total

    private:
        std::vector<uint8_t> buffer_;

        /**
         * Detect complete SIP message boundaries
         * @param start_pos Starting position in buffer
         * @return Length of complete message if found, nullopt otherwise
         */
        std::optional<size_t> findMessageBoundary(size_t start_pos) const;
    };

    // TCP Buffers for SIP and Diameter
    std::unordered_map<FiveTuple, SipTcpStreamBuffer> sip_tcp_buffers_;
    std::unordered_map<FiveTuple, TcpStreamBuffer> diameter_sessions_;

    // Parsers
    FiveGSbaParser sba_parser_;
    Http2Parser http2_parser_;

    // Dynamic port tracker for RTP
    DynamicPortTracker dynamic_port_tracker_;

    // SIP port tracker for non-standard ports
    SipPortTracker sip_port_tracker_;

    void processIpPacket(const std::vector<uint8_t>& ip_packet, Timestamp ts, uint32_t frame_number,
                         int recursion_depth = 0);
    void processTransportAndPayload(const PacketMetadata& metadata,
                                    const std::vector<uint8_t>& payload, int recursion_depth);

    /**
     * Process reassembled SCTP messages and route by PPID
     */
    void processSctpMessage(const SctpReassembledMessage& message, const PacketMetadata& metadata);

public:
    /**
     * Get the dynamic port tracker instance
     * Used by SIP parser to register RTP ports from SDP
     */
    DynamicPortTracker& getDynamicPortTracker() { return dynamic_port_tracker_; }

private:
    /**
     * Check if port is a known SIP port (standard: 5060, 5061, 5062, 5063)
     */
    static bool isSipPort(uint16_t port);

    /**
     * Create PacketMetadata from TCP five-tuple
     */
    PacketMetadata createMetadataFromTcp(const FiveTuple& ft, Timestamp ts) const;
};

}  // namespace callflow
