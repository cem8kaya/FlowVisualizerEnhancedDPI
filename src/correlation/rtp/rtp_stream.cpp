#include "correlation/rtp/rtp_stream.h"
#include <algorithm>
#include <cmath>
#include <set>

namespace callflow {
namespace correlation {

RtpStream::RtpStream(const RtpPacketInfo& first_packet)
    : ssrc_(first_packet.ssrc),
      src_ip_(first_packet.src_ip),
      src_port_(first_packet.src_port),
      dst_ip_(first_packet.dst_ip),
      dst_port_(first_packet.dst_port),
      start_time_(first_packet.timestamp),
      end_time_(first_packet.timestamp),
      start_frame_(first_packet.frame_number),
      end_frame_(first_packet.frame_number),
      payload_type_(first_packet.payload_type) {

    codec_name_ = detectCodecName(payload_type_);
    clock_rate_ = detectClockRate(payload_type_);

    packets_.reserve(1000);  // Pre-allocate for typical call
    addPacket(first_packet);
}

void RtpStream::addPacket(const RtpPacketInfo& packet) {
    packets_.push_back(packet);

    // Update time window
    if (packet.timestamp < start_time_) {
        start_time_ = packet.timestamp;
        start_frame_ = packet.frame_number;
    }
    if (packet.timestamp > end_time_) {
        end_time_ = packet.timestamp;
        end_frame_ = packet.frame_number;
    }

    // Update jitter calculation
    updateJitter(packet);
}

void RtpStream::updateJitter(const RtpPacketInfo& packet) {
    if (!jitter_initialized_) {
        last_arrival_time_ = packet.timestamp;
        last_rtp_timestamp_ = packet.rtp_timestamp;
        jitter_initialized_ = true;
        return;
    }

    // RFC 3550 Appendix A.8 - Interarrival jitter calculation
    // J(i) = J(i-1) + (|D(i-1,i)| - J(i-1))/16
    //
    // Where:
    // D(i,j) = (Rj - Ri) - (Sj - Si) = (Rj - Sj) - (Ri - Si)
    // R = arrival time (in RTP timestamp units)
    // S = RTP timestamp

    double current_arrival = packet.timestamp;
    uint32_t current_rtp_ts = packet.rtp_timestamp;

    // Convert arrival time to RTP timestamp units
    double arrival_in_rtp_units = current_arrival * clock_rate_;
    double last_arrival_in_rtp_units = last_arrival_time_ * clock_rate_;

    // Calculate transit time difference
    double transit = arrival_in_rtp_units - static_cast<double>(current_rtp_ts);
    double last_transit = last_arrival_in_rtp_units - static_cast<double>(last_rtp_timestamp_);
    double d = std::abs(transit - last_transit);

    // Update jitter estimate using exponential moving average
    jitter_estimate_ += (d - jitter_estimate_) / 16.0;

    last_arrival_time_ = current_arrival;
    last_rtp_timestamp_ = current_rtp_ts;
}

bool RtpStream::isUeEndpoint(const std::string& ip) const {
    if (!ue_ip_.has_value()) {
        return false;
    }
    return src_ip_ == ip || dst_ip_ == ip;
}

RtpQualityMetrics RtpStream::calculateMetrics() const {
    RtpQualityMetrics metrics;

    if (packets_.empty()) {
        return metrics;
    }

    metrics.packets_received = packets_.size();
    metrics.payload_type = payload_type_;
    metrics.codec_name = codec_name_;
    metrics.clock_rate = clock_rate_;

    // Sequence number analysis
    std::set<uint16_t> seen_sequences;
    std::vector<uint16_t> sequences;
    sequences.reserve(packets_.size());

    for (const auto& pkt : packets_) {
        sequences.push_back(pkt.sequence_number);

        if (seen_sequences.count(pkt.sequence_number)) {
            metrics.packets_duplicated++;
        } else {
            seen_sequences.insert(pkt.sequence_number);
        }
    }

    if (sequences.empty()) {
        return metrics;
    }

    metrics.first_seq = sequences.front();
    metrics.last_seq = sequences.back();

    // Calculate expected packet count with sequence number wraparound handling
    uint32_t expected_packets = 0;
    uint16_t prev_seq = sequences[0];

    for (size_t i = 1; i < sequences.size(); ++i) {
        uint16_t curr_seq = sequences[i];

        // Check for wraparound
        if (curr_seq < prev_seq) {
            // Sequence number wrapped around
            metrics.seq_cycles++;
            expected_packets += (65536 - prev_seq) + curr_seq;
        } else {
            expected_packets += (curr_seq - prev_seq);
        }

        prev_seq = curr_seq;
    }

    // Calculate packet loss
    if (expected_packets > 0) {
        int32_t lost = expected_packets - static_cast<uint32_t>(seen_sequences.size());
        if (lost > 0) {
            metrics.packets_lost = static_cast<uint32_t>(lost);
        }
    }

    // Calculate loss rate
    uint32_t total_expected = metrics.packets_received + metrics.packets_lost;
    if (total_expected > 0) {
        metrics.packet_loss_rate = static_cast<float>(metrics.packets_lost) /
                                   static_cast<float>(total_expected);
    }

    // Out of order detection
    for (size_t i = 1; i < sequences.size(); ++i) {
        uint16_t prev = sequences[i - 1];
        uint16_t curr = sequences[i];

        // Check if current is not exactly prev + 1 (accounting for wraparound)
        uint16_t expected = prev + 1;
        if (curr != expected && !(prev == 65535 && curr == 0)) {
            if (curr < prev && !(prev > 60000 && curr < 5000)) {
                // Out of order (not a wraparound)
                metrics.packets_out_of_order++;
            }
        }
    }

    // Jitter calculation (convert from RTP timestamp units to milliseconds)
    if (clock_rate_ > 0) {
        metrics.jitter_ms = (jitter_estimate_ / clock_rate_) * 1000.0;
    }

    // Calculate max jitter by checking all consecutive packet pairs
    double max_jitter = 0.0;
    for (size_t i = 1; i < packets_.size(); ++i) {
        const auto& prev = packets_[i - 1];
        const auto& curr = packets_[i];

        double arrival_diff = curr.timestamp - prev.timestamp;
        double rtp_diff = static_cast<double>(curr.rtp_timestamp - prev.rtp_timestamp) / clock_rate_;
        double jitter = std::abs(arrival_diff - rtp_diff) * 1000.0;  // Convert to ms

        if (jitter > max_jitter) {
            max_jitter = jitter;
        }
    }
    metrics.max_jitter_ms = max_jitter;

    // Calculate MOS estimate
    metrics.estimated_mos = calculateMos(metrics.packet_loss_rate, metrics.jitter_ms);

    return metrics;
}

std::string RtpStream::detectCodecName(uint8_t pt) const {
    // RFC 3551 - RTP Profile for Audio and Video Conferences
    // Static payload type assignments
    switch (pt) {
        case 0:  return "PCMU";       // G.711 μ-law
        case 3:  return "GSM";        // GSM
        case 4:  return "G723";       // G.723
        case 5:  return "DVI4-8000";  // DVI4 8kHz
        case 6:  return "DVI4-16000"; // DVI4 16kHz
        case 7:  return "LPC";        // LPC
        case 8:  return "PCMA";       // G.711 A-law
        case 9:  return "G722";       // G.722
        case 10: return "L16-2";      // L16 stereo
        case 11: return "L16";        // L16 mono
        case 12: return "QCELP";      // QCELP
        case 13: return "CN";         // Comfort Noise
        case 14: return "MPA";        // MPEG Audio
        case 15: return "G728";       // G.728
        case 16: return "DVI4-11025"; // DVI4 11.025kHz
        case 17: return "DVI4-22050"; // DVI4 22.05kHz
        case 18: return "G729";       // G.729
        case 25: return "CelB";       // CelB video
        case 26: return "JPEG";       // JPEG video
        case 28: return "nv";         // nv video
        case 31: return "H261";       // H.261 video
        case 32: return "MPV";        // MPEG Video
        case 33: return "MP2T";       // MPEG-2 Transport
        case 34: return "H263";       // H.263 video

        // VoLTE commonly uses dynamic payload types, but some typical values:
        case 96:  return "AMR";       // AMR (dynamic)
        case 97:  return "AMR-WB";    // AMR-WB (dynamic)
        case 98:  return "AMR-WB";    // AMR-WB alternate
        case 99:  return "H264";      // H.264 video (dynamic)
        case 100: return "VP8";       // VP8 video (dynamic)
        case 101: return "telephone-event";  // DTMF (RFC 4733)
        case 102: return "H264";      // H.264 alternate
        case 103: return "H265";      // H.265/HEVC (dynamic)

        default:
            if (pt >= 96 && pt <= 127) {
                return "dynamic";  // Dynamic payload type range
            }
            return "unknown";
    }
}

uint32_t RtpStream::detectClockRate(uint8_t pt) const {
    // RFC 3551 - Clock rates for static payload types
    switch (pt) {
        case 0:  return 8000;   // PCMU
        case 3:  return 8000;   // GSM
        case 4:  return 8000;   // G723
        case 5:  return 8000;   // DVI4-8000
        case 6:  return 16000;  // DVI4-16000
        case 7:  return 8000;   // LPC
        case 8:  return 8000;   // PCMA
        case 9:  return 8000;   // G722 (actual rate is 16kHz, but RTP uses 8kHz)
        case 10: return 44100;  // L16 stereo
        case 11: return 44100;  // L16 mono
        case 12: return 8000;   // QCELP
        case 13: return 8000;   // CN
        case 14: return 90000;  // MPA
        case 15: return 8000;   // G728
        case 16: return 11025;  // DVI4-11025
        case 17: return 22050;  // DVI4-22050
        case 18: return 8000;   // G729

        // Video typically uses 90kHz
        case 25: return 90000;  // CelB
        case 26: return 90000;  // JPEG
        case 28: return 90000;  // nv
        case 31: return 90000;  // H261
        case 32: return 90000;  // MPV
        case 33: return 90000;  // MP2T
        case 34: return 90000;  // H263

        // Dynamic payload types - use common defaults
        case 96:  return 8000;   // AMR
        case 97:  return 16000;  // AMR-WB
        case 98:  return 16000;  // AMR-WB
        case 99:  return 90000;  // H264
        case 100: return 90000;  // VP8
        case 101: return 8000;   // telephone-event
        case 102: return 90000;  // H264
        case 103: return 90000;  // H265

        default:
            // For unknown types, default to 8kHz for audio, 90kHz for video
            if (pt >= 96 && pt <= 127) {
                return 8000;  // Assume audio for dynamic range
            }
            return 8000;
    }
}

double RtpStream::calculateMos(float packet_loss_rate, double jitter_ms) const {
    // E-Model based MOS calculation (simplified ITU-T G.107)
    // MOS = 1 + 0.035*R + R*(R-60)*(100-R)*7*10^-6
    // Where R (R-factor) = 93.2 - Id - Ie
    //
    // Id = delay impairment
    // Ie = equipment impairment (codec + packet loss)

    // Base R-factor for good conditions
    double R = 93.2;

    // Delay impairment (Id)
    // For VoLTE, jitter contributes to effective delay
    // Simplified: Id = 0.024*delay + 0.11*(delay-177.3)*H(delay-177.3)
    // We use jitter as a proxy for delay variation
    double Id = 0.0;
    if (jitter_ms > 20.0) {
        Id = 0.024 * jitter_ms;
    }

    // Equipment impairment (Ie)
    // Codec impairment + packet loss impairment
    double Ie_codec = 0.0;

    // Codec-specific impairment values (approximate)
    if (codec_name_ == "PCMU" || codec_name_ == "PCMA") {
        Ie_codec = 0.0;  // G.711 is reference
    } else if (codec_name_ == "G729") {
        Ie_codec = 11.0;
    } else if (codec_name_ == "G723") {
        Ie_codec = 15.0;
    } else if (codec_name_ == "AMR") {
        Ie_codec = 5.0;
    } else if (codec_name_ == "AMR-WB") {
        Ie_codec = 2.0;  // AMR-WB has better quality
    } else {
        Ie_codec = 5.0;  // Default for unknown codecs
    }

    // Packet loss impairment (Bpl model)
    // Ie_pl = Ie_codec + (95 - Ie_codec) * (PL / (PL + BurstR))
    // Simplified for random loss: Ie_pl ≈ 2.5 * PL for small PL
    double packet_loss_percent = packet_loss_rate * 100.0;
    double Ie_pl = 0.0;

    if (packet_loss_percent > 0.0) {
        // For packet loss < 5%, approximately linear
        // For higher loss, use exponential model
        if (packet_loss_percent < 5.0) {
            Ie_pl = 2.5 * packet_loss_percent;
        } else {
            Ie_pl = 10.0 + (packet_loss_percent - 5.0) * 5.0;
        }
    }

    double Ie = Ie_codec + Ie_pl;

    // Calculate R-factor
    R = R - Id - Ie;

    // Clamp R to valid range [0, 100]
    if (R < 0.0) R = 0.0;
    if (R > 100.0) R = 100.0;

    // Convert R-factor to MOS
    double mos = 1.0;
    if (R < 0.0) {
        mos = 1.0;
    } else if (R > 100.0) {
        mos = 4.5;
    } else {
        mos = 1.0 + 0.035 * R + R * (R - 60.0) * (100.0 - R) * 7.0e-6;
    }

    // Clamp MOS to [1.0, 5.0]
    if (mos < 1.0) mos = 1.0;
    if (mos > 5.0) mos = 5.0;

    return mos;
}

} // namespace correlation
} // namespace callflow
