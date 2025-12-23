#include <gtest/gtest.h>

#include "pcap_ingest/tcp_reassembly.h"

using namespace callflow;

class TcpReassemblyTest : public ::testing::Test {
protected:
    void SetUp() override {
        reassembler = std::make_unique<TcpReassembler>();

        // Setup test five-tuple
        ft.src_ip = "192.168.1.100";
        ft.dst_ip = "10.0.0.1";
        ft.src_port = 12345;
        ft.dst_port = 80;
        ft.protocol = 6;  // TCP

        // Setup callbacks
        reassembler->setDataCallback(
            [this](const FiveTuple& five_tuple, Direction dir, const uint8_t* data, size_t len,
                   Timestamp ts) {
                received_data.assign(data, data + len);
                callback_count++;
                last_direction = dir;
            });

        reassembler->setCloseCallback([this](const FiveTuple& five_tuple) { close_count++; });
    }

    std::unique_ptr<TcpReassembler> reassembler;
    FiveTuple ft;
    std::vector<uint8_t> received_data;
    int callback_count = 0;
    int close_count = 0;
    Direction last_direction = Direction::UNKNOWN;
};

// Test 1: Normal 3-way handshake
TEST_F(TcpReassemblyTest, ThreeWayHandshake) {
    auto now = std::chrono::system_clock::now();

    // SYN from client
    TcpSegment syn;
    syn.seq_num = 1000;
    syn.ack_num = 0;
    syn.flags = TCP_FLAG_SYN;
    syn.timestamp = now;
    reassembler->processPacket(ft, syn);

    // SYN-ACK from server
    TcpSegment synack;
    synack.seq_num = 2000;
    synack.ack_num = 1001;
    synack.flags = TCP_FLAG_SYN | TCP_FLAG_ACK;
    synack.timestamp = now;
    reassembler->processPacket(ft, synack);

    // ACK from client
    TcpSegment ack;
    ack.seq_num = 1001;
    ack.ack_num = 2001;
    ack.flags = TCP_FLAG_ACK;
    ack.timestamp = now;
    reassembler->processPacket(ft, ack);

    auto stats = reassembler->getStats();
    EXPECT_EQ(stats.total_streams, 1);
    EXPECT_EQ(stats.active_streams, 1);
}

// Test 2: In-order data delivery
TEST_F(TcpReassemblyTest, InOrderData) {
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

    // Send data in order
    TcpSegment data1;
    data1.seq_num = 1001;
    data1.ack_num = 2001;
    data1.flags = TCP_FLAG_ACK | TCP_FLAG_PSH;
    data1.payload = {'H', 'E', 'L', 'L', 'O'};
    data1.timestamp = now;
    reassembler->processPacket(ft, data1);

    EXPECT_EQ(callback_count, 1);
    EXPECT_EQ(received_data.size(), 5);
    EXPECT_EQ(std::string(received_data.begin(), received_data.end()), "HELLO");
}

// Test 3: FIN handling and buffer flush
TEST_F(TcpReassemblyTest, FinFlushesBuffer) {
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

    // Send data with FIN
    TcpSegment data_fin;
    data_fin.seq_num = 1001;
    data_fin.ack_num = 2001;
    data_fin.flags = TCP_FLAG_ACK | TCP_FLAG_FIN;
    data_fin.payload = {'B', 'Y', 'E'};
    data_fin.timestamp = now;
    reassembler->processPacket(ft, data_fin);

    EXPECT_EQ(callback_count, 1);
    EXPECT_EQ(received_data.size(), 3);
    EXPECT_EQ(std::string(received_data.begin(), received_data.end()), "BYE");
}

// Test 4: RST immediate cleanup
TEST_F(TcpReassemblyTest, RstImmediateCleanup) {
    auto now = std::chrono::system_clock::now();

    // Establish connection
    TcpSegment syn;
    syn.seq_num = 1000;
    syn.flags = TCP_FLAG_SYN;
    syn.timestamp = now;
    reassembler->processPacket(ft, syn);

    // Send RST
    TcpSegment rst;
    rst.seq_num = 1001;
    rst.flags = TCP_FLAG_RST;
    rst.timestamp = now;
    reassembler->processPacket(ft, rst);

    EXPECT_EQ(close_count, 1);
    auto stats = reassembler->getStats();
    EXPECT_EQ(stats.active_streams, 0);
}

// Test 5: Large message spanning multiple segments
TEST_F(TcpReassemblyTest, LargeMessage) {
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

    // Send 3 segments of 1000 bytes each
    std::string expected_data;
    for (int i = 0; i < 3; i++) {
        TcpSegment data;
        data.seq_num = 1001 + (i * 1000);
        data.ack_num = 2001;
        data.flags = TCP_FLAG_ACK | TCP_FLAG_PSH;
        data.payload.resize(1000, 'A' + i);
        expected_data.append(data.payload.begin(), data.payload.end());
        data.timestamp = now;
        reassembler->processPacket(ft, data);
    }

    EXPECT_EQ(callback_count, 3);
    auto stats = reassembler->getStats();
    EXPECT_EQ(stats.bytes_reassembled, 3000);
}

// Test 6: Mid-stream pickup
TEST_F(TcpReassemblyTest, MidStreamPickup) {
    auto now = std::chrono::system_clock::now();

    // Start without SYN (mid-stream)
    TcpSegment data;
    data.seq_num = 5000;
    data.ack_num = 6000;
    data.flags = TCP_FLAG_ACK | TCP_FLAG_PSH;
    data.payload = {'D', 'A', 'T', 'A'};
    data.timestamp = now;
    reassembler->processPacket(ft, data);

    EXPECT_EQ(callback_count, 1);
    EXPECT_EQ(received_data.size(), 4);
}

// Test 7: Cleanup stale streams
TEST_F(TcpReassemblyTest, CleanupStaleStreams) {
    auto now = std::chrono::system_clock::now();

    // Create a stream
    TcpSegment syn;
    syn.seq_num = 1000;
    syn.flags = TCP_FLAG_SYN;
    syn.timestamp = now;
    reassembler->processPacket(ft, syn);

    auto stats = reassembler->getStats();
    EXPECT_EQ(stats.active_streams, 1);

    // Cleanup with future timestamp
    auto future = now + std::chrono::seconds(400);
    size_t cleaned = reassembler->cleanupStaleStreams(future, std::chrono::seconds(300));

    EXPECT_EQ(cleaned, 1);
    stats = reassembler->getStats();
    EXPECT_EQ(stats.active_streams, 0);
}

// Test 8: TCP Fast Open (data with SYN)
TEST_F(TcpReassemblyTest, TcpFastOpen) {
    auto now = std::chrono::system_clock::now();

    // SYN with data (TFO)
    TcpSegment syn_data;
    syn_data.seq_num = 1000;
    syn_data.flags = TCP_FLAG_SYN;
    syn_data.payload = {'T', 'F', 'O'};
    syn_data.timestamp = now;
    reassembler->processPacket(ft, syn_data);

    EXPECT_EQ(callback_count, 1);
    EXPECT_EQ(received_data.size(), 3);
    EXPECT_EQ(std::string(received_data.begin(), received_data.end()), "TFO");
}

// Test 9: Statistics tracking
TEST_F(TcpReassemblyTest, StatisticsTracking) {
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
    data.payload.resize(100, 'X');
    data.timestamp = now;
    reassembler->processPacket(ft, data);

    auto stats = reassembler->getStats();
    EXPECT_EQ(stats.total_streams, 1);
    EXPECT_EQ(stats.active_streams, 1);
    EXPECT_EQ(stats.bytes_reassembled, 100);
}
