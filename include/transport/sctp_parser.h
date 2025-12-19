#pragma once

#include "transport/sctp_reassembler.h"
#include "common/types.h"
#include <optional>
#include <vector>
#include <map>
#include <functional>
#include <nlohmann/json.hpp>

namespace callflow {

/**
 * SCTP Payload Protocol Identifiers (RFC 4960)
 * Used to identify the upper layer protocol carried in DATA chunks
 */
enum class SctpPayloadProtocolId : uint32_t {
    RESERVED = 0,
    IUA = 1,                // ISDN Q.921 User Adaptation
    M2UA = 2,               // SS7 MTP2 User Adaptation
    M3UA = 3,               // SS7 MTP3 User Adaptation
    SUA = 4,                // SS7 SCCP User Adaptation
    M2PA = 5,               // SS7 MTP2 Peer Adaptation
    V5UA = 6,               // V5.2 User Adaptation
    H248 = 7,               // H.248
    BICC = 8,               // BICC/Q.1902
    TALI = 9,               // TALI
    DUA = 10,               // DPNSS/DASS2 User Adaptation
    ASAP = 11,              // ASAP
    ENRP = 12,              // ENRP
    H323 = 13,              // H.323
    QIPC = 14,              // QIPC
    SIMCO = 15,             // SIMCO
    DDP_SEG = 16,           // DDP Segment
    DDP_STREAM = 17,        // DDP Stream
    S1AP = 18,              // S1 Application Protocol (LTE)
    RUA = 19,               // RANAP User Adaptation
    HNBAP = 20,             // HNB Application Part
    FORCES_HP = 21,         // ForCES-HP
    FORCES_MP = 22,         // ForCES-MP
    FORCES_LP = 23,         // ForCES-LP
    SBC_AP = 24,            // SBc-AP
    X2AP = 27,              // X2 Application Protocol (LTE)
    SABP = 31,              // Service Area Broadcast Protocol
    DIAMETER = 46,          // Diameter (when used over SCTP)
    NGAP = 60,              // NG Application Protocol (5G)
    XWAP = 61,              // Xw Application Protocol

    // Vendor-specific range: 0x00000080 - 0xFFFFFFFF
};

/**
 * Get human-readable name for PPID
 */
std::string getSctpPpidName(uint32_t ppid);

/**
 * SCTP chunk types (RFC 4960, RFC 6525)
 */
enum class SctpChunkType : uint8_t {
    DATA = 0,
    INIT = 1,
    INIT_ACK = 2,
    SACK = 3,
    HEARTBEAT = 4,
    HEARTBEAT_ACK = 5,
    ABORT = 6,
    SHUTDOWN = 7,
    SHUTDOWN_ACK = 8,
    ERROR = 9,
    COOKIE_ECHO = 10,
    COOKIE_ACK = 11,
    ECNE = 12,
    CWR = 13,
    SHUTDOWN_COMPLETE = 14,
    AUTH = 15,
    I_DATA = 64,  // RFC 8260
    ASCONF_ACK = 128,
    RE_CONFIG = 130,
    PAD = 132,
    FORWARD_TSN = 192,
    ASCONF = 193,
    I_FORWARD_TSN = 194
};

/**
 * SCTP association state (RFC 4960)
 */
enum class SctpAssociationState {
    CLOSED,
    COOKIE_WAIT,
    COOKIE_ECHOED,
    ESTABLISHED,
    SHUTDOWN_PENDING,
    SHUTDOWN_SENT,
    SHUTDOWN_RECEIVED,
    SHUTDOWN_ACK_SENT
};

/**
 * SCTP common header (RFC 4960 Section 3.1)
 */
struct SctpCommonHeader {
    uint16_t source_port;
    uint16_t dest_port;
    uint32_t verification_tag;
    uint32_t checksum;

    nlohmann::json toJson() const;
};

/**
 * SCTP DATA chunk (RFC 4960 Section 3.3.1)
 */
struct SctpDataChunk {
    uint8_t type;  // Should be 0 for DATA
    uint8_t flags;
    uint16_t length;
    uint32_t tsn;              // Transmission Sequence Number
    uint16_t stream_id;
    uint16_t stream_sequence;  // Stream Sequence Number (SSN)
    uint32_t payload_protocol; // Payload Protocol Identifier (PPID)
    std::vector<uint8_t> user_data;

    // Parsed flags
    bool unordered() const { return (flags & 0x04) != 0; }  // U flag
    bool beginning() const { return (flags & 0x02) != 0; }  // B flag
    bool ending() const { return (flags & 0x01) != 0; }     // E flag

    nlohmann::json toJson() const;

    /**
     * Convert to SctpDataFragment for reassembly
     */
    SctpDataFragment toFragment() const;
};

/**
 * SCTP SACK chunk (RFC 4960 Section 3.3.4)
 */
struct SctpSackChunk {
    uint8_t type;  // Should be 3 for SACK
    uint8_t flags;
    uint16_t length;
    uint32_t cumulative_tsn_ack;
    uint32_t a_rwnd;  // Advertised Receiver Window Credit
    uint16_t num_gap_ack_blocks;
    uint16_t num_duplicate_tsns;
    std::vector<std::pair<uint16_t, uint16_t>> gap_ack_blocks;  // (start, end) offsets
    std::vector<uint32_t> duplicate_tsns;

    nlohmann::json toJson() const;
};

/**
 * SCTP INIT chunk (RFC 4960 Section 3.3.2)
 */
struct SctpInitChunk {
    uint8_t type;  // Should be 1 for INIT
    uint8_t flags;
    uint16_t length;
    uint32_t initiate_tag;
    uint32_t a_rwnd;
    uint16_t num_outbound_streams;
    uint16_t num_inbound_streams;
    uint32_t initial_tsn;

    nlohmann::json toJson() const;
};

/**
 * Generic SCTP chunk
 */
struct SctpChunk {
    uint8_t type;
    uint8_t flags;
    uint16_t length;
    std::vector<uint8_t> data;

    nlohmann::json toJson() const;

    /**
     * Get chunk type name
     */
    std::string getTypeName() const;
};

/**
 * SCTP association context
 */
struct SctpAssociation {
    uint32_t association_id;  // Hash of 5-tuple or unique identifier
    uint16_t source_port;
    uint16_t dest_port;
    uint32_t local_verification_tag;
    uint32_t peer_verification_tag;
    SctpAssociationState state;

    // Stream information
    uint16_t num_outbound_streams;
    uint16_t num_inbound_streams;

    // Sequence tracking
    uint32_t local_tsn;   // Next TSN to send
    uint32_t peer_tsn;    // Next expected TSN from peer
    uint32_t cumulative_tsn_ack;  // Last cumulative TSN ack'd

    // Statistics
    uint64_t packets_sent;
    uint64_t packets_received;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t data_chunks_sent;
    uint64_t data_chunks_received;

    SctpAssociation()
        : association_id(0),
          source_port(0),
          dest_port(0),
          local_verification_tag(0),
          peer_verification_tag(0),
          state(SctpAssociationState::CLOSED),
          num_outbound_streams(0),
          num_inbound_streams(0),
          local_tsn(0),
          peer_tsn(0),
          cumulative_tsn_ack(0),
          packets_sent(0),
          packets_received(0),
          bytes_sent(0),
          bytes_received(0),
          data_chunks_sent(0),
          data_chunks_received(0) {}

    nlohmann::json toJson() const;
};

/**
 * SCTP packet (common header + chunks)
 */
struct SctpPacket {
    SctpCommonHeader header;
    std::vector<SctpChunk> chunks;
    std::vector<SctpDataChunk> data_chunks;
    std::vector<SctpSackChunk> sack_chunks;
    std::optional<SctpInitChunk> init_chunk;

    nlohmann::json toJson() const;
};

/**
 * Callback for complete reassembled messages
 */
using SctpMessageCallback = std::function<void(const SctpReassembledMessage&)>;

/**
 * SCTP protocol parser (RFC 4960)
 *
 * Parses SCTP packets, tracks associations, handles multi-streaming,
 * and provides reassembled messages via callback.
 */
class SctpParser {
public:
    SctpParser();
    ~SctpParser() = default;

    /**
     * Parse SCTP packet from packet payload
     * @param data Packet payload data
     * @param len Payload length
     * @param five_tuple Network 5-tuple for association tracking
     * @return Parsed SCTP packet or nullopt if parsing fails
     */
    std::optional<SctpPacket> parse(const uint8_t* data, size_t len,
                                    const FiveTuple& five_tuple);

    /**
     * Check if data appears to be an SCTP packet
     */
    static bool isSctp(const uint8_t* data, size_t len);

    /**
     * Set callback for reassembled messages
     * @param callback Function to call when a complete message is reassembled
     */
    void setMessageCallback(SctpMessageCallback callback);

    /**
     * Get association by ID
     * @param association_id Association identifier
     * @return Association context or nullopt if not found
     */
    std::optional<SctpAssociation> getAssociation(uint32_t association_id) const;

    /**
     * Get all associations
     * @return Vector of association IDs
     */
    std::vector<uint32_t> getAssociationIds() const;

    /**
     * Get reassembler for an association
     * @param association_id Association identifier
     * @return Reassembler or nullopt if not found
     */
    std::optional<SctpStreamReassembler> getReassembler(uint32_t association_id) const;

    /**
     * Get parser statistics
     */
    nlohmann::json getStatistics() const;

    /**
     * Clear all state
     */
    void clear();

private:
    /**
     * Parse common header
     */
    std::optional<SctpCommonHeader> parseCommonHeader(const uint8_t* data, size_t len);

    /**
     * Parse chunks from packet
     */
    bool parseChunks(const uint8_t* data, size_t len, size_t offset,
                     SctpPacket& packet);

    /**
     * Parse DATA chunk
     */
    std::optional<SctpDataChunk> parseDataChunk(const uint8_t* data, size_t len);

    /**
     * Parse SACK chunk
     */
    std::optional<SctpSackChunk> parseSackChunk(const uint8_t* data, size_t len);

    /**
     * Parse INIT chunk
     */
    std::optional<SctpInitChunk> parseInitChunk(const uint8_t* data, size_t len);

    /**
     * Get or create association
     */
    SctpAssociation& getOrCreateAssociation(const FiveTuple& five_tuple,
                                            uint32_t verification_tag);

    /**
     * Update association state based on chunk type
     */
    void updateAssociationState(SctpAssociation& assoc, SctpChunkType chunk_type);

    /**
     * Process data chunks and handle reassembly
     */
    void processDataChunks(SctpAssociation& assoc,
                          const std::vector<SctpDataChunk>& data_chunks);

    /**
     * Process SACK chunks and handle gaps
     */
    void processSackChunks(SctpAssociation& assoc,
                          const std::vector<SctpSackChunk>& sack_chunks);

    /**
     * Calculate association ID from 5-tuple
     */
    static uint32_t calculateAssociationId(const FiveTuple& five_tuple);

    /**
     * Verify SCTP checksum (CRC32C)
     */
    static bool verifyChecksum(const uint8_t* data, size_t len);

    // Association tracking
    std::map<uint32_t, SctpAssociation> associations_;

    // Per-association stream reassemblers
    std::map<uint32_t, SctpStreamReassembler> reassemblers_;

    // Message callback
    SctpMessageCallback message_callback_;

    // Global statistics
    uint64_t total_packets_parsed_;
    uint64_t total_bytes_parsed_;
    uint64_t total_associations_;
    uint64_t parse_errors_;
};

}  // namespace callflow
