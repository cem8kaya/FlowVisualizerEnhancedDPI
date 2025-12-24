#pragma once

#include "correlation/rtp/rtp_stream.h"
#include <unordered_map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace callflow {
namespace correlation {

/**
 * @brief RTP stream correlator
 *
 * Tracks RTP streams by SSRC and provides:
 * - Stream lookup by endpoint
 * - Quality metrics calculation
 * - Correlation to SIP sessions by UE IP and time window
 *
 * This correlator implements intra-protocol correlation (grouping RTP packets into streams)
 * and supports inter-protocol correlation with SIP sessions.
 */
class RtpCorrelator {
public:
    RtpCorrelator() = default;
    ~RtpCorrelator() = default;

    /**
     * @brief Add RTP packet
     *
     * Creates a new stream if SSRC is new, otherwise adds to existing stream.
     */
    void addPacket(const RtpPacketInfo& packet);

    /**
     * @brief Finalize all streams
     *
     * Calculates final quality metrics for all streams.
     * Should be called after all packets have been processed.
     */
    void finalize();

    // ========================================================================
    // Stream Access
    // ========================================================================

    /**
     * @brief Get all streams
     */
    std::vector<RtpStream*> getStreams();

    /**
     * @brief Find stream by SSRC
     */
    RtpStream* findBySsrc(uint32_t ssrc);

    // ========================================================================
    // Stream Lookup
    // ========================================================================

    /**
     * @brief Find streams involving an IP address
     *
     * Returns streams where the IP is either source or destination.
     */
    std::vector<RtpStream*> findByIp(const std::string& ip);

    /**
     * @brief Find streams within time window
     *
     * Returns streams that overlap with [start, end] interval.
     */
    std::vector<RtpStream*> findByTimeWindow(double start, double end);

    /**
     * @brief Find streams matching UE IP from SIP SDP
     *
     * Returns streams where UE IP has been associated.
     */
    std::vector<RtpStream*> findByUeIp(const std::string& ue_ip);

    /**
     * @brief Find streams by endpoint (IP:port pair)
     *
     * Returns streams where endpoint_ip:endpoint_port is either source or destination.
     */
    std::vector<RtpStream*> findByEndpoint(const std::string& endpoint_ip,
                                           uint16_t endpoint_port);

    // ========================================================================
    // SIP Correlation Support
    // ========================================================================

    /**
     * @brief Set UE IP for streams matching endpoint
     *
     * When SIP SDP contains media endpoint (IP:port), this associates
     * the UE IP with matching RTP streams for cross-protocol correlation.
     */
    void setUeIpForEndpoint(const std::string& endpoint_ip,
                            uint16_t endpoint_port,
                            const std::string& ue_ip);

    /**
     * @brief Correlate streams with SIP session
     *
     * Finds RTP streams matching the SIP session's media endpoints and time window.
     * Returns matched streams for uplink and downlink.
     */
    struct SipMediaMatch {
        std::vector<RtpStream*> uplink_streams;
        std::vector<RtpStream*> downlink_streams;
    };

    SipMediaMatch correlateWithSipSession(
        const std::string& ue_ip,
        const std::string& ue_media_ip,
        uint16_t ue_media_port,
        const std::string& remote_media_ip,
        uint16_t remote_media_port,
        double start_time,
        double end_time);

    // ========================================================================
    // Statistics
    // ========================================================================

    struct Stats {
        size_t total_packets = 0;
        size_t total_streams = 0;
        double avg_packet_loss = 0.0;
        double avg_jitter_ms = 0.0;
        double avg_mos = 0.0;
        size_t poor_quality_streams = 0;  // MOS < 3.0
    };

    /**
     * @brief Get aggregate statistics
     */
    Stats getStats() const;

    /**
     * @brief Clear all streams and reset state
     */
    void clear();

    /**
     * @brief Get stream count
     */
    size_t getStreamCount() const;

private:
    mutable std::mutex mutex_;

    // Primary storage: SSRC -> Stream
    std::unordered_map<uint32_t, std::unique_ptr<RtpStream>> streams_;

    // Index by IP for fast lookup (IP -> SSRCs)
    std::unordered_multimap<std::string, uint32_t> ip_index_;

    // Index by UE IP for SIP correlation (UE IP -> SSRCs)
    std::unordered_multimap<std::string, uint32_t> ue_ip_index_;

    Stats stats_;

    // Internal methods
    void updateIpIndex(RtpStream* stream);
    void updateUeIpIndex(RtpStream* stream);
    void updateStats();

    // Helper for stream key generation
    struct StreamKey {
        std::string src_ip;
        uint16_t src_port;
        std::string dst_ip;
        uint16_t dst_port;
        uint32_t ssrc;

        bool operator==(const StreamKey& other) const;
    };
};

} // namespace correlation
} // namespace callflow
