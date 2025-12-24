#include <gtest/gtest.h>
#include "correlation/rtp/rtp_correlator.h"

using namespace callflow::correlation;

// ============================================================================
// Test Fixtures
// ============================================================================

class RtpCorrelatorTest : public ::testing::Test {
protected:
    void SetUp() override {
        correlator_ = std::make_unique<RtpCorrelator>();
    }

    void TearDown() override {
        correlator_.reset();
    }

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
        pkt.payload_size = 160;

        return pkt;
    }

    std::unique_ptr<RtpCorrelator> correlator_;
};

// ============================================================================
// Basic Functionality Tests
// ============================================================================

TEST_F(RtpCorrelatorTest, CreateEmptyCorrelator) {
    EXPECT_EQ(correlator_->getStreamCount(), 0u);

    auto stats = correlator_->getStats();
    EXPECT_EQ(stats.total_packets, 0u);
    EXPECT_EQ(stats.total_streams, 0u);
}

TEST_F(RtpCorrelatorTest, AddSinglePacket) {
    auto pkt = createPacket(1, 1.0, "10.0.0.1", 5000, "10.0.0.2", 5001, 0, 1000, 8000, 12345);
    correlator_->addPacket(pkt);

    EXPECT_EQ(correlator_->getStreamCount(), 1u);

    auto stats = correlator_->getStats();
    EXPECT_EQ(stats.total_packets, 1u);
    EXPECT_EQ(stats.total_streams, 1u);
}

TEST_F(RtpCorrelatorTest, AddMultiplePacketsSameStream) {
    auto pkt1 = createPacket(1, 1.0, "10.0.0.1", 5000, "10.0.0.2", 5001, 0, 1000, 8000, 12345);
    correlator_->addPacket(pkt1);

    auto pkt2 = createPacket(2, 1.02, "10.0.0.1", 5000, "10.0.0.2", 5001, 0, 1001, 8160, 12345);
    correlator_->addPacket(pkt2);

    auto pkt3 = createPacket(3, 1.04, "10.0.0.1", 5000, "10.0.0.2", 5001, 0, 1002, 8320, 12345);
    correlator_->addPacket(pkt3);

    EXPECT_EQ(correlator_->getStreamCount(), 1u);

    auto stats = correlator_->getStats();
    EXPECT_EQ(stats.total_packets, 3u);
    EXPECT_EQ(stats.total_streams, 1u);

    // Verify the stream has all packets
    auto stream = correlator_->findBySsrc(12345);
    ASSERT_NE(stream, nullptr);
    EXPECT_EQ(stream->getPacketCount(), 3u);
}

TEST_F(RtpCorrelatorTest, AddMultipleStreams) {
    auto pkt1 = createPacket(1, 1.0, "10.0.0.1", 5000, "10.0.0.2", 5001, 0, 1000, 8000, 12345);
    correlator_->addPacket(pkt1);

    auto pkt2 = createPacket(2, 1.0, "10.0.0.2", 5001, "10.0.0.1", 5000, 0, 2000, 8000, 54321);
    correlator_->addPacket(pkt2);

    auto pkt3 = createPacket(3, 1.0, "10.0.0.3", 6000, "10.0.0.4", 6001, 8, 3000, 8000, 99999);
    correlator_->addPacket(pkt3);

    EXPECT_EQ(correlator_->getStreamCount(), 3u);

    auto stats = correlator_->getStats();
    EXPECT_EQ(stats.total_packets, 3u);
    EXPECT_EQ(stats.total_streams, 3u);
}

// ============================================================================
// Stream Lookup Tests
// ============================================================================

TEST_F(RtpCorrelatorTest, FindBySsrc) {
    auto pkt1 = createPacket(1, 1.0, "10.0.0.1", 5000, "10.0.0.2", 5001, 0, 1000, 8000, 12345);
    correlator_->addPacket(pkt1);

    auto pkt2 = createPacket(2, 1.0, "10.0.0.2", 5001, "10.0.0.1", 5000, 0, 2000, 8000, 54321);
    correlator_->addPacket(pkt2);

    auto stream1 = correlator_->findBySsrc(12345);
    ASSERT_NE(stream1, nullptr);
    EXPECT_EQ(stream1->getSsrc(), 12345u);

    auto stream2 = correlator_->findBySsrc(54321);
    ASSERT_NE(stream2, nullptr);
    EXPECT_EQ(stream2->getSsrc(), 54321u);

    auto stream3 = correlator_->findBySsrc(99999);
    EXPECT_EQ(stream3, nullptr);
}

TEST_F(RtpCorrelatorTest, FindByIp) {
    auto pkt1 = createPacket(1, 1.0, "10.0.0.1", 5000, "10.0.0.2", 5001, 0, 1000, 8000, 12345);
    correlator_->addPacket(pkt1);

    auto pkt2 = createPacket(2, 1.0, "10.0.0.2", 5001, "10.0.0.3", 5002, 0, 2000, 8000, 54321);
    correlator_->addPacket(pkt2);

    auto pkt3 = createPacket(3, 1.0, "10.0.0.4", 6000, "10.0.0.5", 6001, 0, 3000, 8000, 99999);
    correlator_->addPacket(pkt3);

    // Find by source IP
    auto streams1 = correlator_->findByIp("10.0.0.1");
    EXPECT_EQ(streams1.size(), 1u);
    EXPECT_EQ(streams1[0]->getSsrc(), 12345u);

    // Find by destination IP (also appears as source in another stream)
    auto streams2 = correlator_->findByIp("10.0.0.2");
    EXPECT_EQ(streams2.size(), 2u);

    // Find by IP not in any stream
    auto streams3 = correlator_->findByIp("10.0.0.99");
    EXPECT_EQ(streams3.size(), 0u);
}

TEST_F(RtpCorrelatorTest, FindByEndpoint) {
    auto pkt1 = createPacket(1, 1.0, "10.0.0.1", 5000, "10.0.0.2", 5001, 0, 1000, 8000, 12345);
    correlator_->addPacket(pkt1);

    auto pkt2 = createPacket(2, 1.0, "10.0.0.1", 5002, "10.0.0.2", 5003, 0, 2000, 8000, 54321);
    correlator_->addPacket(pkt2);

    // Find by source endpoint
    auto streams1 = correlator_->findByEndpoint("10.0.0.1", 5000);
    EXPECT_EQ(streams1.size(), 1u);
    EXPECT_EQ(streams1[0]->getSsrc(), 12345u);

    // Find by destination endpoint
    auto streams2 = correlator_->findByEndpoint("10.0.0.2", 5001);
    EXPECT_EQ(streams2.size(), 1u);
    EXPECT_EQ(streams2[0]->getSsrc(), 12345u);

    // Find by IP with wrong port
    auto streams3 = correlator_->findByEndpoint("10.0.0.1", 9999);
    EXPECT_EQ(streams3.size(), 0u);
}

TEST_F(RtpCorrelatorTest, FindByTimeWindow) {
    // Stream 1: 1.0 - 2.0
    auto pkt1 = createPacket(1, 1.0, "10.0.0.1", 5000, "10.0.0.2", 5001, 0, 1000, 8000, 12345);
    correlator_->addPacket(pkt1);
    auto pkt2 = createPacket(2, 2.0, "10.0.0.1", 5000, "10.0.0.2", 5001, 0, 1001, 8160, 12345);
    correlator_->addPacket(pkt2);

    // Stream 2: 3.0 - 4.0
    auto pkt3 = createPacket(3, 3.0, "10.0.0.3", 6000, "10.0.0.4", 6001, 0, 2000, 8000, 54321);
    correlator_->addPacket(pkt3);
    auto pkt4 = createPacket(4, 4.0, "10.0.0.3", 6000, "10.0.0.4", 6001, 0, 2001, 8160, 54321);
    correlator_->addPacket(pkt4);

    // Stream 3: 5.0 - 6.0
    auto pkt5 = createPacket(5, 5.0, "10.0.0.5", 7000, "10.0.0.6", 7001, 0, 3000, 8000, 99999);
    correlator_->addPacket(pkt5);
    auto pkt6 = createPacket(6, 6.0, "10.0.0.5", 7000, "10.0.0.6", 7001, 0, 3001, 8160, 99999);
    correlator_->addPacket(pkt6);

    // Window covering stream 1 and 2
    auto streams1 = correlator_->findByTimeWindow(0.5, 3.5);
    EXPECT_EQ(streams1.size(), 2u);

    // Window covering only stream 2
    auto streams2 = correlator_->findByTimeWindow(2.5, 4.5);
    EXPECT_EQ(streams2.size(), 1u);
    EXPECT_EQ(streams2[0]->getSsrc(), 54321u);

    // Window covering all streams
    auto streams3 = correlator_->findByTimeWindow(0.0, 10.0);
    EXPECT_EQ(streams3.size(), 3u);

    // Window not overlapping any stream
    auto streams4 = correlator_->findByTimeWindow(10.0, 20.0);
    EXPECT_EQ(streams4.size(), 0u);
}

// ============================================================================
// UE IP Association Tests
// ============================================================================

TEST_F(RtpCorrelatorTest, SetUeIpForEndpoint) {
    auto pkt1 = createPacket(1, 1.0, "10.0.0.1", 5000, "10.0.0.2", 5001, 0, 1000, 8000, 12345);
    correlator_->addPacket(pkt1);

    auto pkt2 = createPacket(2, 1.0, "10.0.0.2", 5001, "10.0.0.1", 5000, 0, 2000, 8000, 54321);
    correlator_->addPacket(pkt2);

    // Associate UE IP with endpoint
    correlator_->setUeIpForEndpoint("10.0.0.1", 5000, "192.168.1.100");

    auto stream1 = correlator_->findBySsrc(12345);
    ASSERT_NE(stream1, nullptr);
    ASSERT_TRUE(stream1->getUeIp().has_value());
    EXPECT_EQ(stream1->getUeIp().value(), "192.168.1.100");
    EXPECT_EQ(stream1->getDirection(), RtpStream::Direction::UPLINK);

    auto stream2 = correlator_->findBySsrc(54321);
    ASSERT_NE(stream2, nullptr);
    ASSERT_TRUE(stream2->getUeIp().has_value());
    EXPECT_EQ(stream2->getUeIp().value(), "192.168.1.100");
    EXPECT_EQ(stream2->getDirection(), RtpStream::Direction::DOWNLINK);
}

TEST_F(RtpCorrelatorTest, FindByUeIp) {
    auto pkt1 = createPacket(1, 1.0, "10.0.0.1", 5000, "10.0.0.2", 5001, 0, 1000, 8000, 12345);
    correlator_->addPacket(pkt1);

    auto pkt2 = createPacket(2, 1.0, "10.0.0.2", 5001, "10.0.0.1", 5000, 0, 2000, 8000, 54321);
    correlator_->addPacket(pkt2);

    auto pkt3 = createPacket(3, 1.0, "10.0.0.3", 6000, "10.0.0.4", 6001, 0, 3000, 8000, 99999);
    correlator_->addPacket(pkt3);

    // Associate UE IPs
    correlator_->setUeIpForEndpoint("10.0.0.1", 5000, "192.168.1.100");
    correlator_->setUeIpForEndpoint("10.0.0.3", 6000, "192.168.1.200");

    // Find by UE IP
    auto streams1 = correlator_->findByUeIp("192.168.1.100");
    EXPECT_EQ(streams1.size(), 2u);  // Both uplink and downlink

    auto streams2 = correlator_->findByUeIp("192.168.1.200");
    EXPECT_EQ(streams2.size(), 1u);

    auto streams3 = correlator_->findByUeIp("192.168.1.300");
    EXPECT_EQ(streams3.size(), 0u);
}

// ============================================================================
// SIP Correlation Tests
// ============================================================================

TEST_F(RtpCorrelatorTest, CorrelateWithSipSession) {
    // UE uplink: 10.0.0.1:5000 -> 10.0.0.2:5001
    auto pkt1 = createPacket(1, 1.0, "10.0.0.1", 5000, "10.0.0.2", 5001, 0, 1000, 8000, 12345);
    correlator_->addPacket(pkt1);
    auto pkt2 = createPacket(2, 1.5, "10.0.0.1", 5000, "10.0.0.2", 5001, 0, 1001, 8160, 12345);
    correlator_->addPacket(pkt2);

    // Downlink: 10.0.0.2:5001 -> 10.0.0.1:5000
    auto pkt3 = createPacket(3, 1.0, "10.0.0.2", 5001, "10.0.0.1", 5000, 0, 2000, 8000, 54321);
    correlator_->addPacket(pkt3);
    auto pkt4 = createPacket(4, 1.5, "10.0.0.2", 5001, "10.0.0.1", 5000, 0, 2001, 8160, 54321);
    correlator_->addPacket(pkt4);

    // Correlate with SIP session
    auto match = correlator_->correlateWithSipSession(
        "192.168.1.100",  // UE IP (from signaling)
        "10.0.0.1",       // UE media IP (from SDP)
        5000,             // UE media port (from SDP)
        "10.0.0.2",       // Remote media IP (from SDP)
        5001,             // Remote media port (from SDP)
        0.5,              // Start time
        2.0               // End time
    );

    EXPECT_EQ(match.uplink_streams.size(), 1u);
    EXPECT_EQ(match.downlink_streams.size(), 1u);

    EXPECT_EQ(match.uplink_streams[0]->getSsrc(), 12345u);
    EXPECT_EQ(match.downlink_streams[0]->getSsrc(), 54321u);

    // Verify UE IP was set
    ASSERT_TRUE(match.uplink_streams[0]->getUeIp().has_value());
    EXPECT_EQ(match.uplink_streams[0]->getUeIp().value(), "192.168.1.100");

    ASSERT_TRUE(match.downlink_streams[0]->getUeIp().has_value());
    EXPECT_EQ(match.downlink_streams[0]->getUeIp().value(), "192.168.1.100");

    // Verify direction was set
    EXPECT_EQ(match.uplink_streams[0]->getDirection(), RtpStream::Direction::UPLINK);
    EXPECT_EQ(match.downlink_streams[0]->getDirection(), RtpStream::Direction::DOWNLINK);
}

TEST_F(RtpCorrelatorTest, CorrelateWithSipSessionTimeWindow) {
    // Stream 1: 1.0 - 2.0
    auto pkt1 = createPacket(1, 1.0, "10.0.0.1", 5000, "10.0.0.2", 5001, 0, 1000, 8000, 12345);
    correlator_->addPacket(pkt1);
    auto pkt2 = createPacket(2, 2.0, "10.0.0.1", 5000, "10.0.0.2", 5001, 0, 1001, 8160, 12345);
    correlator_->addPacket(pkt2);

    // Stream 2: 5.0 - 6.0 (outside time window)
    auto pkt3 = createPacket(3, 5.0, "10.0.0.1", 5000, "10.0.0.2", 5001, 0, 2000, 8000, 54321);
    correlator_->addPacket(pkt3);
    auto pkt4 = createPacket(4, 6.0, "10.0.0.1", 5000, "10.0.0.2", 5001, 0, 2001, 8160, 54321);
    correlator_->addPacket(pkt4);

    // Correlate with SIP session (time window 0.5 - 2.5)
    auto match = correlator_->correlateWithSipSession(
        "192.168.1.100",
        "10.0.0.1", 5000,
        "10.0.0.2", 5001,
        0.5, 2.5  // Should only match stream 1
    );

    EXPECT_EQ(match.uplink_streams.size(), 1u);
    EXPECT_EQ(match.uplink_streams[0]->getSsrc(), 12345u);
}

// ============================================================================
// Statistics Tests
// ============================================================================

TEST_F(RtpCorrelatorTest, CalculateStats) {
    // Add a perfect stream
    for (int i = 0; i < 50; ++i) {
        auto pkt = createPacket(
            i + 1, 1.0 + i * 0.02,
            "10.0.0.1", 5000, "10.0.0.2", 5001,
            0, 1000 + i, 8000 + i * 160, 12345);
        correlator_->addPacket(pkt);
    }

    // Add a stream with packet loss
    for (int i = 0; i < 50; ++i) {
        if (i % 10 < 8) {  // 20% loss
            auto pkt = createPacket(
                i + 51, 3.0 + i * 0.02,
                "10.0.0.3", 6000, "10.0.0.4", 6001,
                0, 2000 + i, 8000 + i * 160, 54321);
            correlator_->addPacket(pkt);
        }
    }

    correlator_->finalize();

    auto stats = correlator_->getStats();

    EXPECT_EQ(stats.total_streams, 2u);
    EXPECT_GT(stats.total_packets, 0u);
    EXPECT_GT(stats.avg_mos, 0.0);

    // Should have at least one poor quality stream
    EXPECT_GT(stats.poor_quality_streams, 0u);
}

// ============================================================================
// Utility Tests
// ============================================================================

TEST_F(RtpCorrelatorTest, ClearCorrelator) {
    auto pkt1 = createPacket(1, 1.0, "10.0.0.1", 5000, "10.0.0.2", 5001, 0, 1000, 8000, 12345);
    correlator_->addPacket(pkt1);

    auto pkt2 = createPacket(2, 1.0, "10.0.0.2", 5001, "10.0.0.1", 5000, 0, 2000, 8000, 54321);
    correlator_->addPacket(pkt2);

    EXPECT_EQ(correlator_->getStreamCount(), 2u);

    correlator_->clear();

    EXPECT_EQ(correlator_->getStreamCount(), 0u);
    auto stats = correlator_->getStats();
    EXPECT_EQ(stats.total_packets, 0u);
    EXPECT_EQ(stats.total_streams, 0u);
}

TEST_F(RtpCorrelatorTest, GetAllStreams) {
    auto pkt1 = createPacket(1, 1.0, "10.0.0.1", 5000, "10.0.0.2", 5001, 0, 1000, 8000, 12345);
    correlator_->addPacket(pkt1);

    auto pkt2 = createPacket(2, 1.0, "10.0.0.2", 5001, "10.0.0.1", 5000, 0, 2000, 8000, 54321);
    correlator_->addPacket(pkt2);

    auto pkt3 = createPacket(3, 1.0, "10.0.0.3", 6000, "10.0.0.4", 6001, 0, 3000, 8000, 99999);
    correlator_->addPacket(pkt3);

    auto streams = correlator_->getStreams();
    EXPECT_EQ(streams.size(), 3u);
}
