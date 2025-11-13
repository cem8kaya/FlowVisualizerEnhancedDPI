#include "protocol_parsers/rtp_parser.h"
#include "common/logger.h"
#include "common/utils.h"
#include <cstring>

namespace callflow {

nlohmann::json RtpHeader::toJson() const {
    nlohmann::json j;
    j["version"] = version;
    j["padding"] = padding;
    j["extension"] = extension;
    j["csrc_count"] = csrc_count;
    j["marker"] = marker;
    j["payload_type"] = payload_type;
    j["sequence_number"] = sequence_number;
    j["timestamp"] = timestamp;
    j["ssrc"] = ssrc;
    j["header_length"] = header_length;
    j["payload_length"] = payload_length;

    if (!csrc_list.empty()) {
        j["csrc_list"] = csrc_list;
    }

    return j;
}

nlohmann::json RtcpHeader::toJson() const {
    nlohmann::json j;
    j["version"] = version;
    j["padding"] = padding;
    j["count"] = count;
    j["packet_type"] = static_cast<int>(packet_type);
    j["length"] = length;
    j["ssrc"] = ssrc;
    return j;
}

std::optional<RtpHeader> RtpParser::parseRtp(const uint8_t* data, size_t len) {
    // Minimum RTP header is 12 bytes
    if (!data || len < 12) {
        return std::nullopt;
    }

    RtpHeader header;

    // Byte 0: V(2), P(1), X(1), CC(4)
    header.version = (data[0] >> 6) & 0x03;
    header.padding = (data[0] >> 5) & 0x01;
    header.extension = (data[0] >> 4) & 0x01;
    header.csrc_count = data[0] & 0x0F;

    // Byte 1: M(1), PT(7)
    header.marker = (data[1] >> 7) & 0x01;
    header.payload_type = data[1] & 0x7F;

    // Bytes 2-3: Sequence number
    header.sequence_number = readUint16(&data[2]);

    // Bytes 4-7: Timestamp
    header.timestamp = readUint32(&data[4]);

    // Bytes 8-11: SSRC
    header.ssrc = readUint32(&data[8]);

    // Calculate header length
    header.header_length = 12 + (header.csrc_count * 4);

    // Check if we have enough data for CSRC list
    if (len < header.header_length) {
        LOG_DEBUG("RTP packet too short for CSRC list");
        return std::nullopt;
    }

    // Parse CSRC list if present
    for (uint8_t i = 0; i < header.csrc_count; ++i) {
        uint32_t csrc = readUint32(&data[12 + (i * 4)]);
        header.csrc_list.push_back(csrc);
    }

    // Handle extension header if present
    if (header.extension) {
        if (len < header.header_length + 4) {
            LOG_DEBUG("RTP packet too short for extension header");
            return std::nullopt;
        }
        uint16_t ext_length = readUint16(&data[header.header_length + 2]);
        header.header_length += 4 + (ext_length * 4);
    }

    // Calculate payload length
    if (len > header.header_length) {
        header.payload_length = len - header.header_length;
    } else {
        header.payload_length = 0;
    }

    // Validate version (should be 2)
    if (header.version != 2) {
        LOG_DEBUG("Invalid RTP version: " << (int)header.version);
        return std::nullopt;
    }

    return header;
}

std::optional<RtcpHeader> RtpParser::parseRtcp(const uint8_t* data, size_t len) {
    // Minimum RTCP header is 8 bytes
    if (!data || len < 8) {
        return std::nullopt;
    }

    RtcpHeader header;

    // Byte 0: V(2), P(1), Count(5)
    header.version = (data[0] >> 6) & 0x03;
    header.padding = (data[0] >> 5) & 0x01;
    header.count = data[0] & 0x1F;

    // Byte 1: Packet type
    header.packet_type = static_cast<RtcpPacketType>(data[1]);

    // Bytes 2-3: Length
    header.length = readUint16(&data[2]);

    // Bytes 4-7: SSRC
    header.ssrc = readUint32(&data[4]);

    // Validate version
    if (header.version != 2) {
        return std::nullopt;
    }

    // Validate packet type
    uint8_t pt = static_cast<uint8_t>(header.packet_type);
    if (pt < 200 || pt > 204) {
        return std::nullopt;
    }

    return header;
}

bool RtpParser::isRtp(const uint8_t* data, size_t len) {
    if (!data || len < 12) {
        return false;
    }

    // Check version (should be 2)
    uint8_t version = (data[0] >> 6) & 0x03;
    if (version != 2) {
        return false;
    }

    // Check payload type (RTP: 0-95)
    uint8_t pt = data[1] & 0x7F;
    if (pt > 95) {
        return false;
    }

    return true;
}

bool RtpParser::isRtcp(const uint8_t* data, size_t len) {
    if (!data || len < 8) {
        return false;
    }

    // Check version (should be 2)
    uint8_t version = (data[0] >> 6) & 0x03;
    if (version != 2) {
        return false;
    }

    // Check packet type (RTCP: 200-204)
    uint8_t pt = data[1];
    if (pt < 200 || pt > 204) {
        return false;
    }

    return true;
}

bool RtpParser::isLikelyRtp(const uint8_t* data, size_t len) {
    if (!data || len < 12) {
        return false;
    }

    uint8_t version = (data[0] >> 6) & 0x03;
    if (version != 2) {
        return false;
    }

    uint8_t pt = data[1] & 0x7F;

    // RTP typically uses payload types 0-95
    // RTCP uses 200-204
    return pt <= 95;
}

uint16_t RtpParser::readUint16(const uint8_t* data) {
    return (static_cast<uint16_t>(data[0]) << 8) |
           static_cast<uint16_t>(data[1]);
}

uint32_t RtpParser::readUint32(const uint8_t* data) {
    return (static_cast<uint32_t>(data[0]) << 24) |
           (static_cast<uint32_t>(data[1]) << 16) |
           (static_cast<uint32_t>(data[2]) << 8) |
           static_cast<uint32_t>(data[3]);
}

// RtpStreamTracker implementation

RtpStreamTracker::RtpStreamTracker(uint32_t ssrc)
    : ssrc_(ssrc),
      packets_received_(0),
      packets_expected_(0),
      max_sequence_(0),
      base_sequence_(0),
      last_timestamp_(0),
      jitter_(0.0),
      initialized_(false) {}

void RtpStreamTracker::processPacket(const RtpHeader& header, Timestamp ts) {
    if (!initialized_) {
        base_sequence_ = header.sequence_number;
        max_sequence_ = header.sequence_number;
        last_timestamp_ = header.timestamp;
        last_arrival_time_ = ts;
        initialized_ = true;
        packets_received_ = 1;
        packets_expected_ = 1;
        return;
    }

    packets_received_++;

    // Update max sequence number
    uint16_t seq = header.sequence_number;
    if (seq > max_sequence_ || (max_sequence_ - seq) > 32768) {
        max_sequence_ = seq;
    }

    // Calculate expected packets
    packets_expected_ = max_sequence_ - base_sequence_ + 1;

    // Update jitter
    updateJitter(header.timestamp, ts);

    last_timestamp_ = header.timestamp;
    last_arrival_time_ = ts;
}

double RtpStreamTracker::getPacketLoss() const {
    if (packets_expected_ == 0) {
        return 0.0;
    }

    int64_t lost = static_cast<int64_t>(packets_expected_) -
                   static_cast<int64_t>(packets_received_);

    if (lost < 0) {
        lost = 0;  // Handle wraps
    }

    return static_cast<double>(lost) / static_cast<double>(packets_expected_);
}

double RtpStreamTracker::getJitterMs() const {
    return jitter_;
}

void RtpStreamTracker::updateJitter(uint32_t timestamp, Timestamp arrival_time) {
    // Calculate interarrival jitter (RFC 3550 Section 6.4.1)
    // Assumes 8000 Hz timestamp clock (standard for audio)
    const double TIMESTAMP_HZ = 8000.0;

    int64_t arrival_diff_us = utils::timeDiffMs(last_arrival_time_, arrival_time) * 1000;
    int64_t timestamp_diff = static_cast<int64_t>(timestamp) -
                             static_cast<int64_t>(last_timestamp_);

    // Convert timestamp difference to microseconds
    int64_t timestamp_diff_us = (timestamp_diff * 1000000) / TIMESTAMP_HZ;

    // Calculate jitter
    int64_t d = arrival_diff_us - timestamp_diff_us;
    if (d < 0) d = -d;

    // Update jitter using exponential average
    jitter_ = jitter_ + (static_cast<double>(d) - jitter_) / 16.0;
}

}  // namespace callflow
