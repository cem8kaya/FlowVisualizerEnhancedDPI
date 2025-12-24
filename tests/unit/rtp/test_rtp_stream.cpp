#include <gtest/gtest.h>
#include "correlation/rtp/rtp_stream.h"
#include <cmath>

using namespace callflow::correlation;

// ============================================================================
// Test Fixtures
// ============================================================================

class RtpStreamTest : public ::testing::Test {
protected:
    // Helper to create RTP packet info
    RtpPacketInfo createPacket(
        uint32_t frame_number,
        double timestamp,
        const std::string& src_ip,
        uint16_t src_port,
        const std::string& dst_ip,
        uint16_t dst_port,
        uint8_t payload_type,
        uint16_t sequence_number,
        uint32_t rtp_timestamp,
        uint32_t ssrc) {

        RtpPacketInfo pkt;
        pkt.frame_number = frame_number;
        pkt.timestamp = timestamp;
        pkt.src_ip = src_ip;
        pkt.src_port = src_port;
        pkt.dst_ip = dst_ip;
        pkt.dst_port = dst_port;
        pkt.version = 2;
        pkt.padding = false;
        pkt.extension = false;
        pkt.csrc_count = 0;
        pkt.marker = false;
        pkt.payload_type = payload_type;
        pkt.sequence_number = sequence_number;
        pkt.rtp_timestamp = rtp_timestamp;
        pkt.ssrc = ssrc;
        pkt.payload_size = 160;  // Typical for G.711 @ 20ms

        return pkt;
    }
};

// ============================================================================
// Basic Functionality Tests
// ============================================================================

TEST_F(RtpStreamTest, CreateStream) {
    auto pkt = createPacket(1, 1.0, "10.0.0.1", 5000, "10.0.0.2", 5001, 0, 1000, 8000, 12345);
    RtpStream stream(pkt);

    EXPECT_EQ(stream.getSsrc(), 12345u);
    EXPECT_EQ(stream.getSrcIp(), "10.0.0.1");
    EXPECT_EQ(stream.getSrcPort(), 5000);
    EXPECT_EQ(stream.getDstIp(), "10.0.0.2");
    EXPECT_EQ(stream.getDstPort(), 5001);
    EXPECT_EQ(stream.getPayloadType(), 0);
    EXPECT_EQ(stream.getCodecName(), "PCMU");
    EXPECT_EQ(stream.getPacketCount(), 1u);
}

TEST_F(RtpStreamTest, AddPackets) {
    auto pkt1 = createPacket(1, 1.0, "10.0.0.1", 5000, "10.0.0.2", 5001, 0, 1000, 8000, 12345);
    RtpStream stream(pkt1);

    auto pkt2 = createPacket(2, 1.02, "10.0.0.1", 5000, "10.0.0.2", 5001, 0, 1001, 8160, 12345);
    stream.addPacket(pkt2);

    auto pkt3 = createPacket(3, 1.04, "10.0.0.1", 5000, "10.0.0.2", 5001, 0, 1002, 8320, 12345);
    stream.addPacket(pkt3);

    EXPECT_EQ(stream.getPacketCount(), 3u);
    EXPECT_EQ(stream.getStartTime(), 1.0);
    EXPECT_EQ(stream.getEndTime(), 1.04);
    EXPECT_EQ(stream.getStartFrame(), 1u);
    EXPECT_EQ(stream.getEndFrame(), 3u);
}

TEST_F(RtpStreamTest, DurationCalculation) {
    auto pkt1 = createPacket(1, 1.0, "10.0.0.1", 5000, "10.0.0.2", 5001, 0, 1000, 8000, 12345);
    RtpStream stream(pkt1);

    auto pkt2 = createPacket(2, 2.5, "10.0.0.1", 5000, "10.0.0.2", 5001, 0, 1001, 8160, 12345);
    stream.addPacket(pkt2);

    // Duration should be 1.5 seconds = 1500 ms
    EXPECT_DOUBLE_EQ(stream.getDurationMs(), 1500.0);
}

// ============================================================================
// Codec Detection Tests
// ============================================================================

TEST_F(RtpStreamTest, DetectPCMU) {
    auto pkt = createPacket(1, 1.0, "10.0.0.1", 5000, "10.0.0.2", 5001, 0, 1000, 8000, 12345);
    RtpStream stream(pkt);

    EXPECT_EQ(stream.getCodecName(), "PCMU");
    EXPECT_EQ(stream.getClockRate(), 8000u);
}

TEST_F(RtpStreamTest, DetectPCMA) {
    auto pkt = createPacket(1, 1.0, "10.0.0.1", 5000, "10.0.0.2", 5001, 8, 1000, 8000, 12345);
    RtpStream stream(pkt);

    EXPECT_EQ(stream.getCodecName(), "PCMA");
    EXPECT_EQ(stream.getClockRate(), 8000u);
}

TEST_F(RtpStreamTest, DetectG729) {
    auto pkt = createPacket(1, 1.0, "10.0.0.1", 5000, "10.0.0.2", 5001, 18, 1000, 8000, 12345);
    RtpStream stream(pkt);

    EXPECT_EQ(stream.getCodecName(), "G729");
    EXPECT_EQ(stream.getClockRate(), 8000u);
}

TEST_F(RtpStreamTest, DetectAMR) {
    auto pkt = createPacket(1, 1.0, "10.0.0.1", 5000, "10.0.0.2", 5001, 96, 1000, 8000, 12345);
    RtpStream stream(pkt);

    EXPECT_EQ(stream.getCodecName(), "AMR");
    EXPECT_EQ(stream.getClockRate(), 8000u);
}

TEST_F(RtpStreamTest, DetectAMR_WB) {
    auto pkt = createPacket(1, 1.0, "10.0.0.1", 5000, "10.0.0.2", 5001, 97, 1000, 16000, 12345);
    RtpStream stream(pkt);

    EXPECT_EQ(stream.getCodecName(), "AMR-WB");
    EXPECT_EQ(stream.getClockRate(), 16000u);
}

// ============================================================================
// Quality Metrics Tests
// ============================================================================

TEST_F(RtpStreamTest, PerfectStreamMetrics) {
    auto pkt1 = createPacket(1, 1.0, "10.0.0.1", 5000, "10.0.0.2", 5001, 0, 1000, 8000, 12345);
    RtpStream stream(pkt1);

    // Add 49 more packets with perfect timing (20ms intervals)
    for (int i = 1; i < 50; ++i) {
        auto pkt = createPacket(
            i + 1,
            1.0 + i * 0.02,  // 20ms intervals
            "10.0.0.1", 5000, "10.0.0.2", 5001,
            0,
            1000 + i,
            8000 + i * 160,  // 160 samples @ 8kHz = 20ms
            12345);
        stream.addPacket(pkt);
    }

    auto metrics = stream.calculateMetrics();

    EXPECT_EQ(metrics.packets_received, 50u);
    EXPECT_EQ(metrics.packets_lost, 0u);
    EXPECT_FLOAT_EQ(metrics.packet_loss_rate, 0.0f);
    EXPECT_EQ(metrics.packets_duplicated, 0u);
    EXPECT_EQ(metrics.packets_out_of_order, 0u);

    // Jitter should be very low for perfect stream
    EXPECT_LT(metrics.jitter_ms, 1.0);

    // MOS should be high for perfect stream
    ASSERT_TRUE(metrics.estimated_mos.has_value());
    EXPECT_GT(metrics.estimated_mos.value(), 4.0);
}

TEST_F(RtpStreamTest, PacketLossDetection) {
    auto pkt1 = createPacket(1, 1.0, "10.0.0.1", 5000, "10.0.0.2", 5001, 0, 1000, 8000, 12345);
    RtpStream stream(pkt1);

    // Add packets with gaps (missing sequence numbers)
    stream.addPacket(createPacket(2, 1.02, "10.0.0.1", 5000, "10.0.0.2", 5001, 0, 1001, 8160, 12345));
    // Skip 1002 (packet lost)
    stream.addPacket(createPacket(3, 1.06, "10.0.0.1", 5000, "10.0.0.2", 5001, 0, 1003, 8480, 12345));
    // Skip 1004, 1005 (2 packets lost)
    stream.addPacket(createPacket(4, 1.10, "10.0.0.1", 5000, "10.0.0.2", 5001, 0, 1006, 8960, 12345));

    auto metrics = stream.calculateMetrics();

    EXPECT_EQ(metrics.packets_received, 4u);
    EXPECT_EQ(metrics.packets_lost, 3u);  // 1002, 1004, 1005
    EXPECT_GT(metrics.packet_loss_rate, 0.0f);
}

TEST_F(RtpStreamTest, DuplicatePacketDetection) {
    auto pkt1 = createPacket(1, 1.0, "10.0.0.1", 5000, "10.0.0.2", 5001, 0, 1000, 8000, 12345);
    RtpStream stream(pkt1);

    auto pkt2 = createPacket(2, 1.02, "10.0.0.1", 5000, "10.0.0.2", 5001, 0, 1001, 8160, 12345);
    stream.addPacket(pkt2);

    // Duplicate of pkt2
    auto pkt2_dup = createPacket(3, 1.03, "10.0.0.1", 5000, "10.0.0.2", 5001, 0, 1001, 8160, 12345);
    stream.addPacket(pkt2_dup);

    auto pkt3 = createPacket(4, 1.04, "10.0.0.1", 5000, "10.0.0.2", 5001, 0, 1002, 8320, 12345);
    stream.addPacket(pkt3);

    auto metrics = stream.calculateMetrics();

    EXPECT_EQ(metrics.packets_received, 4u);
    EXPECT_EQ(metrics.packets_duplicated, 1u);
}

TEST_F(RtpStreamTest, SequenceNumberWraparound) {
    auto pkt1 = createPacket(1, 1.0, "10.0.0.1", 5000, "10.0.0.2", 5001, 0, 65534, 8000, 12345);
    RtpStream stream(pkt1);

    stream.addPacket(createPacket(2, 1.02, "10.0.0.1", 5000, "10.0.0.2", 5001, 0, 65535, 8160, 12345));
    stream.addPacket(createPacket(3, 1.04, "10.0.0.1", 5000, "10.0.0.2", 5001, 0, 0, 8320, 12345));
    stream.addPacket(createPacket(4, 1.06, "10.0.0.1", 5000, "10.0.0.2", 5001, 0, 1, 8480, 12345));

    auto metrics = stream.calculateMetrics();

    EXPECT_EQ(metrics.packets_received, 4u);
    EXPECT_EQ(metrics.packets_lost, 0u);
    EXPECT_EQ(metrics.seq_cycles, 1u);
    EXPECT_EQ(metrics.first_seq, 65534);
    EXPECT_EQ(metrics.last_seq, 1);
}

TEST_F(RtpStreamTest, JitterCalculation) {
    auto pkt1 = createPacket(1, 1.0, "10.0.0.1", 5000, "10.0.0.2", 5001, 0, 1000, 8000, 12345);
    RtpStream stream(pkt1);

    // Add packets with varying timing (introduce jitter)
    stream.addPacket(createPacket(2, 1.025, "10.0.0.1", 5000, "10.0.0.2", 5001, 0, 1001, 8160, 12345)); // +5ms jitter
    stream.addPacket(createPacket(3, 1.035, "10.0.0.1", 5000, "10.0.0.2", 5001, 0, 1002, 8320, 12345)); // -5ms jitter
    stream.addPacket(createPacket(4, 1.06,  "10.0.0.1", 5000, "10.0.0.2", 5001, 0, 1003, 8480, 12345)); // +5ms jitter
    stream.addPacket(createPacket(5, 1.07,  "10.0.0.1", 5000, "10.0.0.2", 5001, 0, 1004, 8640, 12345)); // -10ms jitter

    auto metrics = stream.calculateMetrics();

    // Should have measurable jitter
    EXPECT_GT(metrics.jitter_ms, 0.0);
    EXPECT_GT(metrics.max_jitter_ms, 0.0);
}

TEST_F(RtpStreamTest, MOSCalculationGoodQuality) {
    auto pkt1 = createPacket(1, 1.0, "10.0.0.1", 5000, "10.0.0.2", 5001, 0, 1000, 8000, 12345);
    RtpStream stream(pkt1);

    // Add 99 more packets with good quality (low jitter, no loss)
    for (int i = 1; i < 100; ++i) {
        auto pkt = createPacket(
            i + 1,
            1.0 + i * 0.02,  // Perfect 20ms intervals
            "10.0.0.1", 5000, "10.0.0.2", 5001,
            0, 1000 + i, 8000 + i * 160, 12345);
        stream.addPacket(pkt);
    }

    auto metrics = stream.calculateMetrics();

    ASSERT_TRUE(metrics.estimated_mos.has_value());
    double mos = metrics.estimated_mos.value();

    // Good quality should have MOS > 4.0
    EXPECT_GT(mos, 4.0);
    EXPECT_LE(mos, 5.0);
}

TEST_F(RtpStreamTest, MOSCalculationPoorQuality) {
    auto pkt1 = createPacket(1, 1.0, "10.0.0.1", 5000, "10.0.0.2", 5001, 0, 1000, 8000, 12345);
    RtpStream stream(pkt1);

    // Add packets with 20% loss (add 8, skip 2 pattern)
    int seq = 1000;
    for (int i = 1; i < 50; ++i) {
        if (i % 10 < 8) {  // Add 8 out of 10 packets (20% loss)
            auto pkt = createPacket(
                i + 1,
                1.0 + seq * 0.02,
                "10.0.0.1", 5000, "10.0.0.2", 5001,
                0, seq, 8000 + seq * 160, 12345);
            stream.addPacket(pkt);
        }
        seq++;
    }

    auto metrics = stream.calculateMetrics();

    ASSERT_TRUE(metrics.estimated_mos.has_value());
    double mos = metrics.estimated_mos.value();

    // Poor quality with 20% loss should have low MOS
    EXPECT_LT(mos, 3.5);
    EXPECT_GE(mos, 1.0);
}

// ============================================================================
// Direction and UE Association Tests
// ============================================================================

TEST_F(RtpStreamTest, DirectionDetection) {
    auto pkt = createPacket(1, 1.0, "10.0.0.1", 5000, "10.0.0.2", 5001, 0, 1000, 8000, 12345);
    RtpStream stream(pkt);

    EXPECT_EQ(stream.getDirection(), RtpStream::Direction::UNKNOWN);

    stream.setDirection(RtpStream::Direction::UPLINK);
    EXPECT_EQ(stream.getDirection(), RtpStream::Direction::UPLINK);

    stream.setDirection(RtpStream::Direction::DOWNLINK);
    EXPECT_EQ(stream.getDirection(), RtpStream::Direction::DOWNLINK);
}

TEST_F(RtpStreamTest, UeIpAssociation) {
    auto pkt = createPacket(1, 1.0, "10.0.0.1", 5000, "10.0.0.2", 5001, 0, 1000, 8000, 12345);
    RtpStream stream(pkt);

    EXPECT_FALSE(stream.getUeIp().has_value());

    stream.setUeIp("10.0.0.100");
    ASSERT_TRUE(stream.getUeIp().has_value());
    EXPECT_EQ(stream.getUeIp().value(), "10.0.0.100");

    EXPECT_TRUE(stream.isUeEndpoint("10.0.0.1"));
    EXPECT_TRUE(stream.isUeEndpoint("10.0.0.2"));
    EXPECT_FALSE(stream.isUeEndpoint("10.0.0.3"));
}

TEST_F(RtpStreamTest, InterCorrelator) {
    auto pkt = createPacket(1, 1.0, "10.0.0.1", 5000, "10.0.0.2", 5001, 0, 1000, 8000, 12345);
    RtpStream stream(pkt);

    EXPECT_EQ(stream.getInterCorrelator(), "");

    stream.setInterCorrelator("SIP_SESSION_12345");
    EXPECT_EQ(stream.getInterCorrelator(), "SIP_SESSION_12345");
}

// ============================================================================
// Edge Cases
// ============================================================================

TEST_F(RtpStreamTest, EmptyStreamMetrics) {
    auto pkt = createPacket(1, 1.0, "10.0.0.1", 5000, "10.0.0.2", 5001, 0, 1000, 8000, 12345);
    RtpStream stream(pkt);

    // Stream has only one packet
    auto metrics = stream.calculateMetrics();

    EXPECT_EQ(metrics.packets_received, 1u);
    EXPECT_EQ(metrics.packets_lost, 0u);
}

TEST_F(RtpStreamTest, UnknownCodec) {
    auto pkt = createPacket(1, 1.0, "10.0.0.1", 5000, "10.0.0.2", 5001, 200, 1000, 8000, 12345);
    RtpStream stream(pkt);

    EXPECT_EQ(stream.getCodecName(), "unknown");
}
