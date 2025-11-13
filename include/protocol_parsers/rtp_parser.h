#pragma once

#include "common/types.h"
#include <optional>
#include <nlohmann/json.hpp>

namespace callflow {

/**
 * RTP header structure (RFC 3550)
 */
struct RtpHeader {
    uint8_t version;        // 2 bits
    bool padding;           // 1 bit
    bool extension;         // 1 bit
    uint8_t csrc_count;     // 4 bits
    bool marker;            // 1 bit
    uint8_t payload_type;   // 7 bits
    uint16_t sequence_number;
    uint32_t timestamp;
    uint32_t ssrc;
    std::vector<uint32_t> csrc_list;

    // Payload info
    size_t header_length;
    size_t payload_length;

    nlohmann::json toJson() const;
};

/**
 * RTCP packet types
 */
enum class RtcpPacketType {
    SR = 200,   // Sender Report
    RR = 201,   // Receiver Report
    SDES = 202, // Source Description
    BYE = 203,  // Goodbye
    APP = 204   // Application-Defined
};

/**
 * RTCP header structure
 */
struct RtcpHeader {
    uint8_t version;
    bool padding;
    uint8_t count;
    RtcpPacketType packet_type;
    uint16_t length;
    uint32_t ssrc;

    nlohmann::json toJson() const;
};

/**
 * RTP/RTCP parser
 */
class RtpParser {
public:
    RtpParser() = default;
    ~RtpParser() = default;

    /**
     * Parse RTP header from packet payload
     * @param data Packet payload data
     * @param len Payload length
     * @return Parsed RTP header or nullopt if parsing fails
     */
    std::optional<RtpHeader> parseRtp(const uint8_t* data, size_t len);

    /**
     * Parse RTCP packet
     */
    std::optional<RtcpHeader> parseRtcp(const uint8_t* data, size_t len);

    /**
     * Check if data appears to be RTP
     */
    static bool isRtp(const uint8_t* data, size_t len);

    /**
     * Check if data appears to be RTCP
     */
    static bool isRtcp(const uint8_t* data, size_t len);

    /**
     * Heuristic to distinguish RTP from RTCP
     * RTP typically has payload types 0-95, RTCP uses 200-204
     */
    static bool isLikelyRtp(const uint8_t* data, size_t len);

private:
    uint16_t readUint16(const uint8_t* data);
    uint32_t readUint32(const uint8_t* data);
};

/**
 * RTP stream tracker for quality metrics
 */
class RtpStreamTracker {
public:
    RtpStreamTracker(uint32_t ssrc);
    ~RtpStreamTracker() = default;

    /**
     * Process an RTP packet
     */
    void processPacket(const RtpHeader& header, Timestamp ts);

    /**
     * Get packet loss percentage
     */
    double getPacketLoss() const;

    /**
     * Get jitter in milliseconds
     */
    double getJitterMs() const;

    /**
     * Get total packets received
     */
    uint64_t getPacketsReceived() const { return packets_received_; }

    uint32_t getSsrc() const { return ssrc_; }

private:
    uint32_t ssrc_;
    uint64_t packets_received_;
    uint64_t packets_expected_;
    uint16_t max_sequence_;
    uint16_t base_sequence_;
    uint32_t last_timestamp_;
    double jitter_;
    Timestamp last_arrival_time_;
    bool initialized_;

    void updateJitter(uint32_t timestamp, Timestamp arrival_time);
};

}  // namespace callflow
