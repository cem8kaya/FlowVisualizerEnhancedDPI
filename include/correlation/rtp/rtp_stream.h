#pragma once

#include <string>
#include <vector>
#include <optional>
#include <cstdint>

namespace callflow {
namespace correlation {

/**
 * @brief RTP packet information extracted from nDPI
 */
struct RtpPacketInfo {
    uint32_t frame_number;
    double timestamp;           // Epoch time

    std::string src_ip;
    uint16_t src_port;
    std::string dst_ip;
    uint16_t dst_port;

    // RTP header fields (RFC 3550)
    uint8_t version;
    bool padding;
    bool extension;
    uint8_t csrc_count;
    bool marker;
    uint8_t payload_type;
    uint16_t sequence_number;
    uint32_t rtp_timestamp;
    uint32_t ssrc;

    size_t payload_size;
};

/**
 * @brief RTP quality metrics per RFC 3550
 */
struct RtpQualityMetrics {
    // Packet statistics
    uint32_t packets_received = 0;
    uint32_t packets_lost = 0;
    uint32_t packets_out_of_order = 0;
    uint32_t packets_duplicated = 0;

    // Loss rate
    float packet_loss_rate = 0.0f;  // 0.0 - 1.0

    // Jitter (RFC 3550 interarrival jitter in milliseconds)
    double jitter_ms = 0.0;
    double max_jitter_ms = 0.0;

    // Delay (if RTCP available)
    std::optional<double> round_trip_time_ms;

    // MOS estimate (based on packet loss and jitter)
    // E-Model calculation per ITU-T G.107
    std::optional<double> estimated_mos;  // 1.0 - 5.0

    // Codec info
    uint8_t payload_type = 0;
    std::string codec_name;
    uint32_t clock_rate = 0;

    // Sequence number tracking
    uint16_t first_seq = 0;
    uint16_t last_seq = 0;
    uint32_t seq_cycles = 0;  // Number of sequence number wrap-arounds
};

/**
 * @brief RTP stream tracker
 *
 * Represents a unidirectional RTP stream identified by SSRC.
 * Tracks packets, calculates quality metrics, and correlates with SIP sessions.
 */
class RtpStream {
public:
    RtpStream(const RtpPacketInfo& first_packet);
    ~RtpStream() = default;

    // Stream identification
    uint32_t getSsrc() const { return ssrc_; }
    std::string getSrcIp() const { return src_ip_; }
    uint16_t getSrcPort() const { return src_port_; }
    std::string getDstIp() const { return dst_ip_; }
    uint16_t getDstPort() const { return dst_port_; }

    // Add packet to stream
    void addPacket(const RtpPacketInfo& packet);

    // Packet count
    size_t getPacketCount() const { return packets_.size(); }

    // Time window
    double getStartTime() const { return start_time_; }
    double getEndTime() const { return end_time_; }
    uint32_t getStartFrame() const { return start_frame_; }
    uint32_t getEndFrame() const { return end_frame_; }
    double getDurationMs() const { return (end_time_ - start_time_) * 1000.0; }

    // Codec info
    uint8_t getPayloadType() const { return payload_type_; }
    std::string getCodecName() const { return codec_name_; }
    uint32_t getClockRate() const { return clock_rate_; }

    // Quality metrics (call after all packets added)
    RtpQualityMetrics calculateMetrics() const;

    // Direction detection
    enum class Direction {
        UPLINK,      // UE to network
        DOWNLINK,    // Network to UE
        UNKNOWN
    };
    Direction getDirection() const { return direction_; }
    void setDirection(Direction dir) { direction_ = dir; }

    // UE association (for correlation with SIP)
    void setUeIp(const std::string& ip) { ue_ip_ = ip; }
    std::optional<std::string> getUeIp() const { return ue_ip_; }
    bool isUeEndpoint(const std::string& ip) const;

    // Correlation IDs
    void setInterCorrelator(const std::string& id) { inter_correlator_ = id; }
    std::string getInterCorrelator() const { return inter_correlator_; }

    // Access packets (for detailed analysis)
    const std::vector<RtpPacketInfo>& getPackets() const { return packets_; }

private:
    uint32_t ssrc_;
    std::string src_ip_;
    uint16_t src_port_;
    std::string dst_ip_;
    uint16_t dst_port_;

    std::vector<RtpPacketInfo> packets_;

    double start_time_ = 0.0;
    double end_time_ = 0.0;
    uint32_t start_frame_ = 0;
    uint32_t end_frame_ = 0;

    uint8_t payload_type_ = 0;
    std::string codec_name_;
    uint32_t clock_rate_ = 0;

    Direction direction_ = Direction::UNKNOWN;
    std::optional<std::string> ue_ip_;

    std::string inter_correlator_;

    // Jitter calculation state (RFC 3550 Appendix A.8)
    mutable double last_arrival_time_ = 0.0;
    mutable uint32_t last_rtp_timestamp_ = 0;
    mutable double jitter_estimate_ = 0.0;
    mutable bool jitter_initialized_ = false;

    void updateJitter(const RtpPacketInfo& packet);
    std::string detectCodecName(uint8_t pt) const;
    uint32_t detectClockRate(uint8_t pt) const;

    // E-Model MOS calculation (ITU-T G.107)
    double calculateMos(float packet_loss_rate, double jitter_ms) const;
};

} // namespace correlation
} // namespace callflow
