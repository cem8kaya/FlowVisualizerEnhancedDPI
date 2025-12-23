#include <gtest/gtest.h>

#include "pcap_ingest/tcp_reassembly.h"

using namespace callflow;

class TcpOutOfOrderTest : public ::testing::Test {
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
                // Accumulate all received data
                all_received_data.insert(all_received_data.end(), data, data + len);
                callback_count++;
            });
    }

    std::unique_ptr<TcpReassembler> reassembler;
    FiveTuple ft;
    std::vector<uint8_t> all_received_data;
    int callback_count = 0;
};

// Test 1: Simple out-of-order (3 packets arrive as 1,3,2)
TEST_F(TcpOutOfOrderTest, SimpleOutOfOrder_1_3_2) {
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

    // Send packets out of order: 1, 3, 2
    // Packet 1: seq 1001, data "AAA" (bytes 1001-1003)
    TcpSegment pkt1;
    pkt1.seq_num = 1001;
    pkt1.ack_num = 2001;
    pkt1.flags = TCP_FLAG_ACK | TCP_FLAG_PSH;
    pkt1.payload = {'A', 'A', 'A'};
    pkt1.timestamp = now;
    reassembler->processPacket(ft, pkt1);

    // Packet 3: seq 1007, data "CCC" (bytes 1007-1009) - arrives before packet 2
    TcpSegment pkt3;
    pkt3.seq_num = 1007;
    pkt3.ack_num = 2001;
    pkt3.flags = TCP_FLAG_ACK | TCP_FLAG_PSH;
    pkt3.payload = {'C', 'C', 'C'};
    pkt3.timestamp = now;
    reassembler->processPacket(ft, pkt3);

    // At this point, should have received "AAA" but not "CCC" (gap exists)
    EXPECT_EQ(callback_count, 1);
    EXPECT_EQ(all_received_data.size(), 3);

    // Packet 2: seq 1004, data "BBB" (bytes 1004-1006) - fills the gap
    TcpSegment pkt2;
    pkt2.seq_num = 1004;
    pkt2.ack_num = 2001;
    pkt2.flags = TCP_FLAG_ACK | TCP_FLAG_PSH;
    pkt2.payload = {'B', 'B', 'B'};
    pkt2.timestamp = now;
    reassembler->processPacket(ft, pkt2);

    // Now should have all data: "AAABBBCCC"
    EXPECT_EQ(callback_count, 2);  // One for AAA, one for BBB+CCC
    EXPECT_EQ(all_received_data.size(), 9);
    EXPECT_EQ(std::string(all_received_data.begin(), all_received_data.end()), "AAABBBCCC");

    auto stats = reassembler->getStats();
    EXPECT_GT(stats.out_of_order_handled, 0);
}

// Test 2: Multiple gaps
TEST_F(TcpOutOfOrderTest, MultipleGaps) {
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

    // Send packets in order: 1, 4, 5, 2, 3
    // This creates gaps that are filled later
    std::vector<int> order = {1, 4, 5, 2, 3};
    std::vector<TcpSegment> packets(5);

    for (int i = 0; i < 5; i++) {
        packets[i].seq_num = 1001 + (i * 10);
        packets[i].ack_num = 2001;
        packets[i].flags = TCP_FLAG_ACK | TCP_FLAG_PSH;
        packets[i].payload = {static_cast<uint8_t>('A' + i), static_cast<uint8_t>('A' + i)};
        packets[i].timestamp = now;
    }

    // Send in specified order
    for (int idx : order) {
        reassembler->processPacket(ft, packets[idx - 1]);
    }

    // Should eventually receive all data in correct order
    EXPECT_EQ(all_received_data.size(), 10);
    std::string expected = "AABBCCDDEE";
    EXPECT_EQ(std::string(all_received_data.begin(), all_received_data.end()), expected);

    auto stats = reassembler->getStats();
    EXPECT_GE(stats.out_of_order_handled, 2);  // At least packets 4 and 5 were out of order
}

// Test 3: Out-of-order with large gap
TEST_F(TcpOutOfOrderTest, LargeGap) {
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

    // Packet 1
    TcpSegment pkt1;
    pkt1.seq_num = 1001;
    pkt1.ack_num = 2001;
    pkt1.flags = TCP_FLAG_ACK | TCP_FLAG_PSH;
    pkt1.payload = {'S', 'T', 'A', 'R', 'T'};
    pkt1.timestamp = now;
    reassembler->processPacket(ft, pkt1);

    // Packet 2 with large gap (1000 bytes ahead)
    TcpSegment pkt2;
    pkt2.seq_num = 2006;  // 1001 + 5 + 1000
    pkt2.ack_num = 2001;
    pkt2.flags = TCP_FLAG_ACK | TCP_FLAG_PSH;
    pkt2.payload = {'E', 'N', 'D'};
    pkt2.timestamp = now;
    reassembler->processPacket(ft, pkt2);

    // Should only have received first packet
    EXPECT_EQ(all_received_data.size(), 5);

    // Fill the gap
    TcpSegment filler;
    filler.seq_num = 1006;
    filler.ack_num = 2001;
    filler.flags = TCP_FLAG_ACK | TCP_FLAG_PSH;
    filler.payload.resize(1000, 'X');
    filler.timestamp = now;
    reassembler->processPacket(ft, filler);

    // Now should have all data
    EXPECT_EQ(all_received_data.size(), 1008);  // 5 + 1000 + 3
}

// Test 4: Out-of-order at end of stream
TEST_F(TcpOutOfOrderTest, OutOfOrderBeforeFin) {
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
    TcpSegment pkt1;
    pkt1.seq_num = 1001;
    pkt1.ack_num = 2001;
    pkt1.flags = TCP_FLAG_ACK | TCP_FLAG_PSH;
    pkt1.payload = {'F', 'I', 'R', 'S', 'T'};
    pkt1.timestamp = now;
    reassembler->processPacket(ft, pkt1);

    // Send FIN before last data segment arrives
    TcpSegment fin;
    fin.seq_num = 1011;  // After FIRST (5) + LAST (5)
    fin.ack_num = 2001;
    fin.flags = TCP_FLAG_ACK | TCP_FLAG_FIN;
    fin.timestamp = now;
    reassembler->processPacket(ft, fin);

    // Now send the missing segment
    TcpSegment pkt2;
    pkt2.seq_num = 1006;
    pkt2.ack_num = 2001;
    pkt2.flags = TCP_FLAG_ACK | TCP_FLAG_PSH;
    pkt2.payload = {'L', 'A', 'S', 'T', '!'};
    pkt2.timestamp = now;
    reassembler->processPacket(ft, pkt2);

    // Should have received all data
    EXPECT_EQ(all_received_data.size(), 10);
    EXPECT_EQ(std::string(all_received_data.begin(), all_received_data.end()), "FIRSTLAST!");
}

// Test 5: Sequence number wraparound (edge case)
TEST_F(TcpOutOfOrderTest, SequenceNumberWraparound) {
    auto now = std::chrono::system_clock::now();

    // Start near wraparound point
    uint32_t near_max = 0xFFFFFFF0;  // Close to uint32_t max

    TcpSegment syn;
    syn.seq_num = near_max;
    syn.flags = TCP_FLAG_SYN;
    syn.timestamp = now;
    reassembler->processPacket(ft, syn);

    // Send data that wraps around
    TcpSegment pkt1;
    pkt1.seq_num = near_max + 1;
    pkt1.ack_num = 0;
    pkt1.flags = TCP_FLAG_ACK | TCP_FLAG_PSH;
    pkt1.payload = {'P', 'R', 'E'};
    pkt1.timestamp = now;
    reassembler->processPacket(ft, pkt1);

    // This wraps to near 0
    TcpSegment pkt2;
    pkt2.seq_num = 4;  // Wrapped around (near_max + 1 + 3 wrapped)
    pkt2.ack_num = 0;
    pkt2.flags = TCP_FLAG_ACK | TCP_FLAG_PSH;
    pkt2.payload = {'P', 'O', 'S', 'T'};
    pkt2.timestamp = now;
    reassembler->processPacket(ft, pkt2);

    // Should handle wraparound correctly
    EXPECT_EQ(all_received_data.size(), 7);
}

// Test 6: Heavy out-of-order (stress test)
TEST_F(TcpOutOfOrderTest, HeavyOutOfOrder) {
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

    // Send 20 packets in reverse order
    std::vector<TcpSegment> packets;
    for (int i = 0; i < 20; i++) {
        TcpSegment pkt;
        pkt.seq_num = 1001 + (i * 10);
        pkt.ack_num = 2001;
        pkt.flags = TCP_FLAG_ACK | TCP_FLAG_PSH;
        pkt.payload = {static_cast<uint8_t>('0' + i)};
        pkt.timestamp = now;
        packets.push_back(pkt);
    }

    // Send in reverse order
    for (int i = 19; i >= 0; i--) {
        reassembler->processPacket(ft, packets[i]);
    }

    // Should receive all data in correct order
    EXPECT_EQ(all_received_data.size(), 20);
    for (int i = 0; i < 20; i++) {
        EXPECT_EQ(all_received_data[i], '0' + i);
    }

    auto stats = reassembler->getStats();
    EXPECT_GE(stats.out_of_order_handled, 19);
}
