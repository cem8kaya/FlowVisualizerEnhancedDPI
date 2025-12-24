#include "correlation/rtp/rtp_correlator.h"
#include <algorithm>

namespace callflow {
namespace correlation {

void RtpCorrelator::addPacket(const RtpPacketInfo& packet) {
    std::lock_guard<std::mutex> lock(mutex_);

    stats_.total_packets++;

    auto it = streams_.find(packet.ssrc);
    if (it == streams_.end()) {
        // Create new stream
        auto stream = std::make_unique<RtpStream>(packet);
        updateIpIndex(stream.get());
        streams_[packet.ssrc] = std::move(stream);
        stats_.total_streams++;
    } else {
        // Add to existing stream
        it->second->addPacket(packet);
    }
}

void RtpCorrelator::finalize() {
    std::lock_guard<std::mutex> lock(mutex_);
    updateStats();
}

std::vector<RtpStream*> RtpCorrelator::getStreams() {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<RtpStream*> result;
    result.reserve(streams_.size());

    for (auto& pair : streams_) {
        result.push_back(pair.second.get());
    }

    return result;
}

RtpStream* RtpCorrelator::findBySsrc(uint32_t ssrc) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = streams_.find(ssrc);
    if (it != streams_.end()) {
        return it->second.get();
    }
    return nullptr;
}

std::vector<RtpStream*> RtpCorrelator::findByIp(const std::string& ip) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<RtpStream*> result;

    auto range = ip_index_.equal_range(ip);
    for (auto it = range.first; it != range.second; ++it) {
        uint32_t ssrc = it->second;
        auto stream_it = streams_.find(ssrc);
        if (stream_it != streams_.end()) {
            result.push_back(stream_it->second.get());
        }
    }

    return result;
}

std::vector<RtpStream*> RtpCorrelator::findByTimeWindow(double start, double end) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<RtpStream*> result;

    for (auto& pair : streams_) {
        RtpStream* stream = pair.second.get();

        // Check if stream overlaps with time window
        // Stream overlaps if: stream_start <= window_end AND stream_end >= window_start
        if (stream->getStartTime() <= end && stream->getEndTime() >= start) {
            result.push_back(stream);
        }
    }

    return result;
}

std::vector<RtpStream*> RtpCorrelator::findByUeIp(const std::string& ue_ip) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<RtpStream*> result;

    auto range = ue_ip_index_.equal_range(ue_ip);
    for (auto it = range.first; it != range.second; ++it) {
        uint32_t ssrc = it->second;
        auto stream_it = streams_.find(ssrc);
        if (stream_it != streams_.end()) {
            result.push_back(stream_it->second.get());
        }
    }

    return result;
}

std::vector<RtpStream*> RtpCorrelator::findByEndpoint(const std::string& endpoint_ip,
                                                       uint16_t endpoint_port) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<RtpStream*> result;

    // Find streams by IP first
    auto range = ip_index_.equal_range(endpoint_ip);
    for (auto it = range.first; it != range.second; ++it) {
        uint32_t ssrc = it->second;
        auto stream_it = streams_.find(ssrc);
        if (stream_it != streams_.end()) {
            RtpStream* stream = stream_it->second.get();

            // Check if port matches
            if ((stream->getSrcIp() == endpoint_ip && stream->getSrcPort() == endpoint_port) ||
                (stream->getDstIp() == endpoint_ip && stream->getDstPort() == endpoint_port)) {
                result.push_back(stream);
            }
        }
    }

    return result;
}

void RtpCorrelator::setUeIpForEndpoint(const std::string& endpoint_ip,
                                       uint16_t endpoint_port,
                                       const std::string& ue_ip) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Find streams matching the endpoint
    auto range = ip_index_.equal_range(endpoint_ip);
    for (auto it = range.first; it != range.second; ++it) {
        uint32_t ssrc = it->second;
        auto stream_it = streams_.find(ssrc);
        if (stream_it != streams_.end()) {
            RtpStream* stream = stream_it->second.get();

            // Check if port matches
            if ((stream->getSrcIp() == endpoint_ip && stream->getSrcPort() == endpoint_port) ||
                (stream->getDstIp() == endpoint_ip && stream->getDstPort() == endpoint_port)) {

                stream->setUeIp(ue_ip);
                updateUeIpIndex(stream);

                // Set direction based on which endpoint is the UE
                if (stream->getSrcIp() == endpoint_ip) {
                    stream->setDirection(RtpStream::Direction::UPLINK);
                } else {
                    stream->setDirection(RtpStream::Direction::DOWNLINK);
                }
            }
        }
    }
}

RtpCorrelator::SipMediaMatch RtpCorrelator::correlateWithSipSession(
    const std::string& ue_ip,
    const std::string& ue_media_ip,
    uint16_t ue_media_port,
    const std::string& remote_media_ip,
    uint16_t remote_media_port,
    double start_time,
    double end_time) {

    std::lock_guard<std::mutex> lock(mutex_);

    SipMediaMatch match;

    // Find streams in the time window
    for (auto& pair : streams_) {
        RtpStream* stream = pair.second.get();

        // Check time overlap
        if (stream->getStartTime() > end_time || stream->getEndTime() < start_time) {
            continue;
        }

        // Check if stream matches UE media endpoint
        bool is_uplink = false;
        bool is_downlink = false;

        // Uplink: UE media IP:port -> remote media IP:port
        if (stream->getSrcIp() == ue_media_ip &&
            stream->getSrcPort() == ue_media_port &&
            stream->getDstIp() == remote_media_ip &&
            stream->getDstPort() == remote_media_port) {
            is_uplink = true;
        }

        // Downlink: remote media IP:port -> UE media IP:port
        if (stream->getSrcIp() == remote_media_ip &&
            stream->getSrcPort() == remote_media_port &&
            stream->getDstIp() == ue_media_ip &&
            stream->getDstPort() == ue_media_port) {
            is_downlink = true;
        }

        if (is_uplink) {
            stream->setUeIp(ue_ip);
            stream->setDirection(RtpStream::Direction::UPLINK);
            updateUeIpIndex(stream);
            match.uplink_streams.push_back(stream);
        } else if (is_downlink) {
            stream->setUeIp(ue_ip);
            stream->setDirection(RtpStream::Direction::DOWNLINK);
            updateUeIpIndex(stream);
            match.downlink_streams.push_back(stream);
        }
    }

    return match;
}

RtpCorrelator::Stats RtpCorrelator::getStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

void RtpCorrelator::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    streams_.clear();
    ip_index_.clear();
    ue_ip_index_.clear();
    stats_ = Stats();
}

size_t RtpCorrelator::getStreamCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return streams_.size();
}

void RtpCorrelator::updateIpIndex(RtpStream* stream) {
    // Add both source and destination IPs to index
    ip_index_.insert({stream->getSrcIp(), stream->getSsrc()});
    ip_index_.insert({stream->getDstIp(), stream->getSsrc()});
}

void RtpCorrelator::updateUeIpIndex(RtpStream* stream) {
    auto ue_ip = stream->getUeIp();
    if (ue_ip.has_value()) {
        ue_ip_index_.insert({ue_ip.value(), stream->getSsrc()});
    }
}

void RtpCorrelator::updateStats() {
    stats_.total_streams = streams_.size();

    if (streams_.empty()) {
        return;
    }

    double total_loss = 0.0;
    double total_jitter = 0.0;
    double total_mos = 0.0;
    size_t mos_count = 0;

    for (auto& pair : streams_) {
        RtpStream* stream = pair.second.get();
        RtpQualityMetrics metrics = stream->calculateMetrics();

        total_loss += metrics.packet_loss_rate;
        total_jitter += metrics.jitter_ms;

        if (metrics.estimated_mos.has_value()) {
            total_mos += metrics.estimated_mos.value();
            mos_count++;

            if (metrics.estimated_mos.value() < 3.0) {
                stats_.poor_quality_streams++;
            }
        }
    }

    size_t stream_count = streams_.size();
    stats_.avg_packet_loss = total_loss / stream_count;
    stats_.avg_jitter_ms = total_jitter / stream_count;

    if (mos_count > 0) {
        stats_.avg_mos = total_mos / mos_count;
    }
}

bool RtpCorrelator::StreamKey::operator==(const StreamKey& other) const {
    return src_ip == other.src_ip &&
           src_port == other.src_port &&
           dst_ip == other.dst_ip &&
           dst_port == other.dst_port &&
           ssrc == other.ssrc;
}

} // namespace correlation
} // namespace callflow
