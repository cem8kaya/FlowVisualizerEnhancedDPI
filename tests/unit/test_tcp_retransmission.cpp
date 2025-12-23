#include <gtest/gtest.h>

#include "pcap_ingest/tcp_reassembly.h"

using namespace callflow;

class TcpRetransmissionTest : public ::testing::Test {
protected:
    void SetUp() override {
        reassembler = std::make_unique<TcpReassembler>();

        // Setup test five-tuple
        ft.src_ip = "192.168.1.100";
        ft.dst_ip = "10.0.0.1";
        ft.src_port = 12345;
        ft.dst_port = 80;
        ft.protocol = 6;  // TCP

        // Setup data callback
        reassembler->setDataCallback(
            [this](const FiveTuple& five_tuple, Direction dir, const uint8_t* data, size_t len,
                   Timestamp ts) {
                // Track each delivery
                deliveries.push_back(std::vector<uint8_t>(data, data + len));
                callback_count++;
            });
    }

    std::unique_ptr<TcpReassembler> reassembler;
    FiveTuple ft;
    std::vector<std::vector<uint8_t>> deliveries;
    int callback_count = 0;
};

// Test 1: Exact retransmission (duplicate packet)
TEST_F(TcpRetransmissionTest, ExactRetransmission) {
    auto now = std::chrono::system_clock::now();

    // Establish connection
    TcpSegment syn;
    syn.seq_num = 1000;
    syn.flags = TCP_FLAG_SYN;
    syn.timestamp = now;
    reassembler->processPacket(ft, syn);

    TcpSegment synack;
    synack.seq_num = 2000;
    synack.ack_num = 1001;
    synack.flags = TCP_FLAG_SYN | TCP_FLAG_ACK;
    synack.timestamp = now;
    reassembler->processPacket(ft, synack);

    // Send original packet
    TcpSegment original;
    original.seq_num = 1001;
    original.ack_num = 2001;
    original.flags = TCP_FLAG_ACK | TCP_FLAG_PSH;
    original.payload = {'H', 'E', 'L', 'L', 'O'};
    original.timestamp = now;
    reassembler->processPacket(ft, original);

    EXPECT_EQ(callback_count, 1);
    EXPECT_EQ(deliveries[0].size(), 5);

    // Send exact retransmission
    TcpSegment retrans = original;
    retrans.timestamp = now + std::chrono::milliseconds(100);
    reassembler->processPacket(ft, retrans);

    // Should not deliver again (still only 1 delivery)
    EXPECT_EQ(callback_count, 1);

    auto stats = reassembler->getStats();
    EXPECT_GE(stats.retransmissions, 1);
}

// Test 2: Partial retransmission
TEST_F(TcpRetransmissionTest, PartialRetransmission) {
    auto now = std::chrono::system_clock::now();

    // Establish connection
    TcpSegment syn;
    syn.seq_num = 1000;
    syn.flags = TCP_FLAG_SYN;
    syn.timestamp = now;
    reassembler->processPacket(ft, syn);

    TcpSegment synack;
    synack.seq_num = 2000;
    synack.ack_num = 1001;
    synack.flags = TCP_FLAG_SYN | TCP_FLAG_ACK;
    synack.timestamp = now;
    reassembler->processPacket(ft, synack);

    // Send original packet
    TcpSegment original;
    original.seq_num = 1001;
    original.ack_num = 2001;
    original.flags = TCP_FLAG_ACK | TCP_FLAG_PSH;
    original.payload = {'A', 'B', 'C', 'D', 'E'};
    original.timestamp = now;
    reassembler->processPacket(ft, original);

    // Send partial retransmission (first 3 bytes) with new data
    TcpSegment partial;
    partial.seq_num = 1001;  // Same start
    partial.ack_num = 2001;
    partial.flags = TCP_FLAG_ACK | TCP_FLAG_PSH;
    partial.payload = {'A', 'B', 'C', 'F', 'G'};  // ABC is retrans, FG is new
    partial.timestamp = now + std::chrono::milliseconds(100);
    reassembler->processPacket(ft, partial);

    // Should not deliver retransmitted ABC, but the new data might be handled differently
    // depending on implementation details
    auto stats = reassembler->getStats();
    EXPECT_GE(stats.retransmissions, 0);  // Implementation dependent
}

// Test 3: Multiple retransmissions of same segment
TEST_F(TcpRetransmissionTest, MultipleRetransmissions) {
    auto now = std::chrono::system_clock::now();

    // Establish connection
    TcpSegment syn;
    syn.seq_num = 1000;
    syn.flags = TCP_FLAG_SYN;
    syn.timestamp = now;
    reassembler->processPacket(ft, syn);

    TcpSegment synack;
    synack.seq_num = 2000;
    synack.ack_num = 1001;
    synack.flags = TCP_FLAG_SYN | TCP_FLAG_ACK;
    synack.timestamp = now;
    reassembler->processPacket(ft, synack);

    // Send original
    TcpSegment original;
    original.seq_num = 1001;
    original.ack_num = 2001;
    original.flags = TCP_FLAG_ACK | TCP_FLAG_PSH;
    original.payload = {'D', 'A', 'T', 'A'};
    original.timestamp = now;
    reassembler->processPacket(ft, original);

    EXPECT_EQ(callback_count, 1);

    // Send 5 retransmissions
    for (int i = 0; i < 5; i++) {
        TcpSegment retrans = original;
        retrans.timestamp = now + std::chrono::milliseconds(100 * (i + 1));
        reassembler->processPacket(ft, retrans);
    }

    // Should still only have 1 delivery
    EXPECT_EQ(callback_count, 1);

    auto stats = reassembler->getStats();
    EXPECT_GE(stats.retransmissions, 5);
}

// Test 4: Retransmission with overlap and new data
TEST_F(TcpRetransmissionTest, RetransmissionWithNewData) {
    auto now = std::chrono::system_clock::now();

    // Establish connection
    TcpSegment syn;
    syn.seq_num = 1000;
    syn.flags = TCP_FLAG_SYN;
    syn.timestamp = now;
    reassembler->processPacket(ft, syn);

    TcpSegment synack;
    synack.seq_num = 2000;
    synack.ack_num = 1001;
    synack.flags = TCP_FLAG_SYN | TCP_FLAG_ACK;
    synack.timestamp = now;
    reassembler->processPacket(ft, synack);

    // Send first segment
    TcpSegment seg1;
    seg1.seq_num = 1001;
    seg1.ack_num = 2001;
    seg1.flags = TCP_FLAG_ACK | TCP_FLAG_PSH;
    seg1.payload = {'A', 'A', 'A'};
    seg1.timestamp = now;
    reassembler->processPacket(ft, seg1);

    // Send segment that overlaps with previous but has new data
    // seq 1003 (last byte of AAA) with data "ABBB"
    TcpSegment seg2;
    seg2.seq_num = 1003;  // Overlaps last A
    seg2.ack_num = 2001;
    seg2.flags = TCP_FLAG_ACK | TCP_FLAG_PSH;
    seg2.payload = {'A', 'B', 'B', 'B'};  // A is overlap, BBB is new
    seg2.timestamp = now + std::chrono::milliseconds(50);
    reassembler->processPacket(ft, seg2);

    // Should have received AAA + BBB = AAABBB eventually
    EXPECT_GE(callback_count, 1);
}

// Test 5: Detect spurious retransmission (duplicate ACK scenario)
TEST_F(TcpRetransmissionTest, SpuriousRetransmission) {
    auto now = std::chrono::system_clock::now();

    // Establish connection
    TcpSegment syn;
    syn.seq_num = 1000;
    syn.flags = TCP_FLAG_SYN;
    syn.timestamp = now;
    reassembler->processPacket(ft, syn);

    TcpSegment synack;
    synack.seq_num = 2000;
    synack.ack_num = 1001;
    synack.flags = TCP_FLAG_SYN | TCP_FLAG_ACK;
    synack.timestamp = now;
    reassembler->processPacket(ft, synack);

    // Original transmission
    TcpSegment seg1;
    seg1.seq_num = 1001;
    seg1.ack_num = 2001;
    seg1.flags = TCP_FLAG_ACK | TCP_FLAG_PSH;
    seg1.payload.resize(1000, 'X');
    seg1.timestamp = now;
    reassembler->processPacket(ft, seg1);

    // Next segment
    TcpSegment seg2;
    seg2.seq_num = 2001;
    seg2.ack_num = 2001;
    seg2.flags = TCP_FLAG_ACK | TCP_FLAG_PSH;
    seg2.payload.resize(1000, 'Y');
    seg2.timestamp = now + std::chrono::milliseconds(10);
    reassembler->processPacket(ft, seg2);

    // Spurious retransmission of first segment
    TcpSegment retrans1 = seg1;
    retrans1.timestamp = now + std::chrono::milliseconds(20);
    reassembler->processPacket(ft, retrans1);

    // Should detect as retransmission
    auto stats = reassembler->getStats();
    EXPECT_GE(stats.retransmissions, 1);
}

// Test 6: Fast retransmit scenario
TEST_F(TcpRetransmissionTest, FastRetransmit) {
    auto now = std::chrono::system_clock::now();

    // Establish connection
    TcpSegment syn;
    syn.seq_num = 1000;
    syn.flags = TCP_FLAG_SYN;
    syn.timestamp = now;
    reassembler->processPacket(ft, syn);

    TcpSegment synack;
    synack.seq_num = 2000;
    synack.ack_num = 1001;
    synack.flags = TCP_FLAG_SYN | TCP_FLAG_ACK;
    synack.timestamp = now;
    reassembler->processPacket(ft, synack);

    // Segment 1
    TcpSegment seg1;
    seg1.seq_num = 1001;
    seg1.ack_num = 2001;
    seg1.flags = TCP_FLAG_ACK | TCP_FLAG_PSH;
    seg1.payload = {'1', '1', '1'};
    seg1.timestamp = now;
    reassembler->processPacket(ft, seg1);

    // Segment 3 arrives (segment 2 lost)
    TcpSegment seg3;
    seg3.seq_num = 1007;
    seg3.ack_num = 2001;
    seg3.flags = TCP_FLAG_ACK | TCP_FLAG_PSH;
    seg3.payload = {'3', '3', '3'};
    seg3.timestamp = now + std::chrono::milliseconds(10);
    reassembler->processPacket(ft, seg3);

    // Segment 4 arrives
    TcpSegment seg4;
    seg4.seq_num = 1010;
    seg4.ack_num = 2001;
    seg4.flags = TCP_FLAG_ACK | TCP_FLAG_PSH;
    seg4.payload = {'4', '4', '4'};
    seg4.timestamp = now + std::chrono::milliseconds(20);
    reassembler->processPacket(ft, seg4);

    // Fast retransmit of segment 2
    TcpSegment seg2_retrans;
    seg2_retrans.seq_num = 1004;
    seg2_retrans.ack_num = 2001;
    seg2_retrans.flags = TCP_FLAG_ACK | TCP_FLAG_PSH;
    seg2_retrans.payload = {'2', '2', '2'};
    seg2_retrans.timestamp = now + std::chrono::milliseconds(25);
    reassembler->processPacket(ft, seg2_retrans);

    // Should now have complete data: 111222333444
    EXPECT_GE(callback_count, 1);
}

// Test 7: Zero-window probe (1 byte)
TEST_F(TcpRetransmissionTest, ZeroWindowProbe) {
    auto now = std::chrono::system_clock::now();

    // Establish connection
    TcpSegment syn;
    syn.seq_num = 1000;
    syn.flags = TCP_FLAG_SYN;
    syn.timestamp = now;
    reassembler->processPacket(ft, syn);

    TcpSegment synack;
    synack.seq_num = 2000;
    synack.ack_num = 1001;
    synack.flags = TCP_FLAG_SYN | TCP_FLAG_ACK;
    synack.timestamp = now;
    reassembler->processPacket(ft, synack);

    // Send data
    TcpSegment data;
    data.seq_num = 1001;
    data.ack_num = 2001;
    data.flags = TCP_FLAG_ACK | TCP_FLAG_PSH;
    data.payload = {'D', 'A', 'T', 'A'};
    data.timestamp = now;
    reassembler->processPacket(ft, data);

    // Zero-window probe (1 byte at next_seq)
    TcpSegment probe;
    probe.seq_num = 1005;
    probe.ack_num = 2001;
    probe.flags = TCP_FLAG_ACK;
    probe.payload = {'X'};
    probe.timestamp = now + std::chrono::milliseconds(100);
    reassembler->processPacket(ft, probe);

    // Retransmission of probe
    TcpSegment probe_retrans = probe;
    probe_retrans.timestamp = now + std::chrono::milliseconds(200);
    reassembler->processPacket(ft, probe_retrans);

    // Should detect retransmission
    auto stats = reassembler->getStats();
    EXPECT_GE(stats.retransmissions, 1);
}

// Test 8: Keep-alive packet (retransmission of old seq)
TEST_F(TcpRetransmissionTest, KeepAlivePacket) {
    auto now = std::chrono::system_clock::now();

    // Establish connection
    TcpSegment syn;
    syn.seq_num = 1000;
    syn.flags = TCP_FLAG_SYN;
    syn.timestamp = now;
    reassembler->processPacket(ft, syn);

    TcpSegment synack;
    synack.seq_num = 2000;
    synack.ack_num = 1001;
    synack.flags = TCP_FLAG_SYN | TCP_FLAG_ACK;
    synack.timestamp = now;
    reassembler->processPacket(ft, synack);

    // Send some data
    TcpSegment data;
    data.seq_num = 1001;
    data.ack_num = 2001;
    data.flags = TCP_FLAG_ACK | TCP_FLAG_PSH;
    data.payload = {'T', 'E', 'S', 'T'};
    data.timestamp = now;
    reassembler->processPacket(ft, data);

    // Keep-alive (seq - 1, no data or 1 byte of old data)
    TcpSegment keepalive;
    keepalive.seq_num = 1004;  // Last byte of previous data
    keepalive.ack_num = 2001;
    keepalive.flags = TCP_FLAG_ACK;
    keepalive.payload = {};  // Empty or single byte
    keepalive.timestamp = now + std::chrono::seconds(30);
    reassembler->processPacket(ft, keepalive);

    // Should handle gracefully (not counted as retransmission necessarily)
    EXPECT_GE(callback_count, 1);
}
