#include <gtest/gtest.h>
#include "transport/sctp_parser.h"
#include "transport/sctp_reassembler.h"
#include <vector>
#include <cstring>
#include <arpa/inet.h>

using namespace callflow;

/**
 * Test fixture for SCTP parser tests
 */
class SctpParserTest : public ::testing::Test {
protected:
    void SetUp() override {
        parser_ = std::make_unique<SctpParser>();
        reassembler_ = std::make_unique<SctpStreamReassembler>();
    }

    void TearDown() override {
        parser_.reset();
        reassembler_.reset();
    }

    /**
     * Calculate CRC32C checksum for SCTP
     */
    uint32_t calculateCrc32c(const std::vector<uint8_t>& data) {
        // Simplified CRC32C for testing
        // In production, use the full CRC32C implementation
        uint32_t crc = 0xFFFFFFFF;
        static const uint32_t poly = 0x82F63B78;

        for (uint8_t byte : data) {
            crc ^= byte;
            for (int i = 0; i < 8; ++i) {
                if (crc & 1) {
                    crc = (crc >> 1) ^ poly;
                } else {
                    crc = crc >> 1;
                }
            }
        }
        return ~crc;
    }

    /**
     * Create SCTP common header
     */
    std::vector<uint8_t> createSctpHeader(uint16_t src_port, uint16_t dst_port,
                                          uint32_t vtag) {
        std::vector<uint8_t> header(12);

        uint16_t src = htons(src_port);
        uint16_t dst = htons(dst_port);
        uint32_t tag = htonl(vtag);

        std::memcpy(&header[0], &src, 2);
        std::memcpy(&header[2], &dst, 2);
        std::memcpy(&header[4], &tag, 4);
        // Checksum at bytes 8-11 will be calculated later
        std::memset(&header[8], 0, 4);

        return header;
    }

    /**
     * Create SCTP DATA chunk
     */
    std::vector<uint8_t> createDataChunk(uint32_t tsn, uint16_t stream_id,
                                         uint16_t stream_seq, uint32_t ppid,
                                         const std::vector<uint8_t>& data,
                                         bool unordered = false, bool beginning = true,
                                         bool ending = true) {
        std::vector<uint8_t> chunk;

        // Chunk type (DATA = 0)
        chunk.push_back(0);

        // Flags: U=bit2, B=bit1, E=bit0
        uint8_t flags = 0;
        if (unordered) flags |= 0x04;
        if (beginning) flags |= 0x02;
        if (ending) flags |= 0x01;
        chunk.push_back(flags);

        // Length (header + data)
        uint16_t length = htons(16 + data.size());
        uint8_t len_bytes[2];
        std::memcpy(len_bytes, &length, 2);
        chunk.push_back(len_bytes[0]);
        chunk.push_back(len_bytes[1]);

        // TSN
        uint32_t tsn_net = htonl(tsn);
        uint8_t tsn_bytes[4];
        std::memcpy(tsn_bytes, &tsn_net, 4);
        chunk.insert(chunk.end(), tsn_bytes, tsn_bytes + 4);

        // Stream ID
        uint16_t sid_net = htons(stream_id);
        uint8_t sid_bytes[2];
        std::memcpy(sid_bytes, &sid_net, 2);
        chunk.insert(chunk.end(), sid_bytes, sid_bytes + 2);

        // Stream Sequence
        uint16_t ssn_net = htons(stream_seq);
        uint8_t ssn_bytes[2];
        std::memcpy(ssn_bytes, &ssn_net, 2);
        chunk.insert(chunk.end(), ssn_bytes, ssn_bytes + 2);

        // Payload Protocol ID
        uint32_t ppid_net = htonl(ppid);
        uint8_t ppid_bytes[4];
        std::memcpy(ppid_bytes, &ppid_net, 4);
        chunk.insert(chunk.end(), ppid_bytes, ppid_bytes + 4);

        // User data
        chunk.insert(chunk.end(), data.begin(), data.end());

        // Pad to 4-byte boundary
        while (chunk.size() % 4 != 0) {
            chunk.push_back(0);
        }

        return chunk;
    }

    /**
     * Create SCTP INIT chunk
     */
    std::vector<uint8_t> createInitChunk(uint32_t init_tag, uint32_t a_rwnd,
                                        uint16_t num_out_streams, uint16_t num_in_streams,
                                        uint32_t initial_tsn) {
        std::vector<uint8_t> chunk;

        // Type (INIT = 1)
        chunk.push_back(1);

        // Flags
        chunk.push_back(0);

        // Length
        uint16_t length = htons(20);
        uint8_t len_bytes[2];
        std::memcpy(len_bytes, &length, 2);
        chunk.push_back(len_bytes[0]);
        chunk.push_back(len_bytes[1]);

        // Initiate Tag
        uint32_t tag_net = htonl(init_tag);
        uint8_t tag_bytes[4];
        std::memcpy(tag_bytes, &tag_net, 4);
        chunk.insert(chunk.end(), tag_bytes, tag_bytes + 4);

        // a_rwnd
        uint32_t rwnd_net = htonl(a_rwnd);
        uint8_t rwnd_bytes[4];
        std::memcpy(rwnd_bytes, &rwnd_net, 4);
        chunk.insert(chunk.end(), rwnd_bytes, rwnd_bytes + 4);

        // Num Outbound Streams
        uint16_t out_net = htons(num_out_streams);
        uint8_t out_bytes[2];
        std::memcpy(out_bytes, &out_net, 2);
        chunk.insert(chunk.end(), out_bytes, out_bytes + 2);

        // Num Inbound Streams
        uint16_t in_net = htons(num_in_streams);
        uint8_t in_bytes[2];
        std::memcpy(in_bytes, &in_net, 2);
        chunk.insert(chunk.end(), in_bytes, in_bytes + 2);

        // Initial TSN
        uint32_t tsn_net = htonl(initial_tsn);
        uint8_t tsn_bytes[4];
        std::memcpy(tsn_bytes, &tsn_net, 4);
        chunk.insert(chunk.end(), tsn_bytes, tsn_bytes + 4);

        return chunk;
    }

    /**
     * Create complete SCTP packet
     */
    std::vector<uint8_t> createSctpPacket(uint16_t src_port, uint16_t dst_port,
                                          uint32_t vtag,
                                          const std::vector<std::vector<uint8_t>>& chunks) {
        auto packet = createSctpHeader(src_port, dst_port, vtag);

        // Add all chunks
        for (const auto& chunk : chunks) {
            packet.insert(packet.end(), chunk.begin(), chunk.end());
        }

        // Calculate and set checksum
        std::vector<uint8_t> packet_for_crc = packet;
        std::memset(&packet_for_crc[8], 0, 4);
        uint32_t checksum = calculateCrc32c(packet_for_crc);
        uint32_t checksum_net = htonl(checksum);
        std::memcpy(&packet[8], &checksum_net, 4);

        return packet;
    }

    std::unique_ptr<SctpParser> parser_;
    std::unique_ptr<SctpStreamReassembler> reassembler_;
};

// Test SCTP header parsing
TEST_F(SctpParserTest, ParseCommonHeader) {
    uint16_t src_port = 12345;
    uint16_t dst_port = 54321;
    uint32_t vtag = 0xDEADBEEF;

    auto packet = createSctpPacket(src_port, dst_port, vtag, {});

    FiveTuple ft;
    ft.src_ip = "192.168.1.1";
    ft.dst_ip = "192.168.1.2";
    ft.src_port = src_port;
    ft.dst_port = dst_port;
    ft.protocol = 132;  // SCTP

    auto result = parser_->parse(packet.data(), packet.size(), ft);
    ASSERT_TRUE(result.has_value());

    const auto& pkt = result.value();
    EXPECT_EQ(pkt.header.source_port, src_port);
    EXPECT_EQ(pkt.header.dest_port, dst_port);
    EXPECT_EQ(pkt.header.verification_tag, vtag);
}

// Test DATA chunk parsing
TEST_F(SctpParserTest, ParseDataChunk) {
    std::vector<uint8_t> user_data = {0x48, 0x65, 0x6C, 0x6C, 0x6F};  // "Hello"
    auto data_chunk = createDataChunk(100, 0, 0, 0, user_data);
    auto packet = createSctpPacket(12345, 54321, 0x12345678, {data_chunk});

    FiveTuple ft;
    ft.src_ip = "192.168.1.1";
    ft.dst_ip = "192.168.1.2";
    ft.src_port = 12345;
    ft.dst_port = 54321;
    ft.protocol = 132;

    auto result = parser_->parse(packet.data(), packet.size(), ft);
    ASSERT_TRUE(result.has_value());

    const auto& pkt = result.value();
    EXPECT_EQ(pkt.data_chunks.size(), 1);

    const auto& dc = pkt.data_chunks[0];
    EXPECT_EQ(dc.tsn, 100);
    EXPECT_EQ(dc.stream_id, 0);
    EXPECT_EQ(dc.stream_sequence, 0);
    EXPECT_EQ(dc.payload_protocol, 0);
    EXPECT_TRUE(dc.beginning());
    EXPECT_TRUE(dc.ending());
    EXPECT_FALSE(dc.unordered());
    EXPECT_EQ(dc.user_data, user_data);
}

// Test INIT chunk parsing
TEST_F(SctpParserTest, ParseInitChunk) {
    auto init_chunk = createInitChunk(0xABCDEF12, 65536, 10, 10, 1000);
    auto packet = createSctpPacket(12345, 54321, 0, {init_chunk});

    FiveTuple ft;
    ft.src_ip = "192.168.1.1";
    ft.dst_ip = "192.168.1.2";
    ft.src_port = 12345;
    ft.dst_port = 54321;
    ft.protocol = 132;

    auto result = parser_->parse(packet.data(), packet.size(), ft);
    ASSERT_TRUE(result.has_value());

    const auto& pkt = result.value();
    ASSERT_TRUE(pkt.init_chunk.has_value());

    const auto& init = pkt.init_chunk.value();
    EXPECT_EQ(init.initiate_tag, 0xABCDEF12);
    EXPECT_EQ(init.a_rwnd, 65536);
    EXPECT_EQ(init.num_outbound_streams, 10);
    EXPECT_EQ(init.num_inbound_streams, 10);
    EXPECT_EQ(init.initial_tsn, 1000);
}

// Test stream reassembly - single fragment
TEST_F(SctpParserTest, ReassembleSingleFragment) {
    SctpDataFragment frag;
    frag.stream_id = 0;
    frag.tsn = 100;
    frag.stream_sequence = 0;
    frag.payload_protocol = 0;
    frag.unordered = false;
    frag.beginning = true;
    frag.ending = true;
    frag.data = {0x01, 0x02, 0x03, 0x04};

    auto result = reassembler_->addFragment(frag);
    ASSERT_TRUE(result.has_value());

    const auto& msg = result.value();
    EXPECT_EQ(msg.stream_id, 0);
    EXPECT_EQ(msg.stream_sequence, 0);
    EXPECT_EQ(msg.data, frag.data);
    EXPECT_EQ(msg.fragment_count, 1);
}

// Test stream reassembly - multiple fragments
TEST_F(SctpParserTest, ReassembleMultipleFragments) {
    // First fragment (B flag set)
    SctpDataFragment frag1;
    frag1.stream_id = 0;
    frag1.tsn = 100;
    frag1.stream_sequence = 0;
    frag1.payload_protocol = 0;
    frag1.unordered = false;
    frag1.beginning = true;
    frag1.ending = false;
    frag1.data = {0x01, 0x02};

    // Middle fragment
    SctpDataFragment frag2;
    frag2.stream_id = 0;
    frag2.tsn = 101;
    frag2.stream_sequence = 0;
    frag2.payload_protocol = 0;
    frag2.unordered = false;
    frag2.beginning = false;
    frag2.ending = false;
    frag2.data = {0x03, 0x04};

    // Last fragment (E flag set)
    SctpDataFragment frag3;
    frag3.stream_id = 0;
    frag3.tsn = 102;
    frag3.stream_sequence = 0;
    frag3.payload_protocol = 0;
    frag3.unordered = false;
    frag3.beginning = false;
    frag3.ending = true;
    frag3.data = {0x05, 0x06};

    // Add fragments in order
    auto result1 = reassembler_->addFragment(frag1);
    EXPECT_FALSE(result1.has_value());  // Not complete yet

    auto result2 = reassembler_->addFragment(frag2);
    EXPECT_FALSE(result2.has_value());  // Not complete yet

    auto result3 = reassembler_->addFragment(frag3);
    ASSERT_TRUE(result3.has_value());  // Should be complete

    const auto& msg = result3.value();
    EXPECT_EQ(msg.stream_id, 0);
    EXPECT_EQ(msg.stream_sequence, 0);
    EXPECT_EQ(msg.fragment_count, 3);

    std::vector<uint8_t> expected_data = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    EXPECT_EQ(msg.data, expected_data);
}

// Test multi-stream reassembly
TEST_F(SctpParserTest, MultiStreamReassembly) {
    // Stream 0 message
    SctpDataFragment frag0;
    frag0.stream_id = 0;
    frag0.tsn = 100;
    frag0.stream_sequence = 0;
    frag0.payload_protocol = 0;
    frag0.unordered = false;
    frag0.beginning = true;
    frag0.ending = true;
    frag0.data = {0xAA, 0xBB};

    // Stream 1 message
    SctpDataFragment frag1;
    frag1.stream_id = 1;
    frag1.tsn = 101;
    frag1.stream_sequence = 0;
    frag1.payload_protocol = 0;
    frag1.unordered = false;
    frag1.beginning = true;
    frag1.ending = true;
    frag1.data = {0xCC, 0xDD};

    auto result0 = reassembler_->addFragment(frag0);
    ASSERT_TRUE(result0.has_value());
    EXPECT_EQ(result0.value().stream_id, 0);

    auto result1 = reassembler_->addFragment(frag1);
    ASSERT_TRUE(result1.has_value());
    EXPECT_EQ(result1.value().stream_id, 1);
}

// Test unordered delivery
TEST_F(SctpParserTest, UnorderedDelivery) {
    SctpDataFragment frag;
    frag.stream_id = 0;
    frag.tsn = 100;
    frag.stream_sequence = 0;  // SSN doesn't matter for unordered
    frag.payload_protocol = 0;
    frag.unordered = true;
    frag.beginning = true;
    frag.ending = true;
    frag.data = {0x11, 0x22, 0x33};

    auto result = reassembler_->addFragment(frag);
    ASSERT_TRUE(result.has_value());

    const auto& msg = result.value();
    EXPECT_EQ(msg.data, frag.data);
}

// Test gap handling
TEST_F(SctpParserTest, HandleGap) {
    reassembler_->handleGap(0, 100, 105);

    // Gap should clear any fragments in that TSN range
    auto stream_ctx = reassembler_->getStreamContext(0);
    // Stream may not exist if no fragments were added
}

// Test stream reset
TEST_F(SctpParserTest, ResetStream) {
    // Add a fragment
    SctpDataFragment frag;
    frag.stream_id = 0;
    frag.tsn = 100;
    frag.stream_sequence = 0;
    frag.payload_protocol = 0;
    frag.unordered = false;
    frag.beginning = true;
    frag.ending = true;
    frag.data = {0x01, 0x02};

    reassembler_->addFragment(frag);

    // Reset the stream
    reassembler_->resetStream(0);

    auto stream_ctx = reassembler_->getStreamContext(0);
    ASSERT_TRUE(stream_ctx.has_value());
    EXPECT_EQ(stream_ctx.value().state, SctpStreamState::RESET_PENDING);
}

// Test statistics
TEST_F(SctpParserTest, ReassemblerStatistics) {
    SctpDataFragment frag;
    frag.stream_id = 0;
    frag.tsn = 100;
    frag.stream_sequence = 0;
    frag.payload_protocol = 0;
    frag.unordered = false;
    frag.beginning = true;
    frag.ending = true;
    frag.data = {0x01, 0x02, 0x03};

    reassembler_->addFragment(frag);

    auto stats = reassembler_->getStatistics();
    EXPECT_TRUE(stats.contains("total_fragments"));
    EXPECT_TRUE(stats.contains("total_messages"));
    EXPECT_EQ(stats["total_fragments"], 1);
    EXPECT_EQ(stats["total_messages"], 1);
}

// Test JSON serialization
TEST_F(SctpParserTest, JsonSerialization) {
    auto data_chunk = createDataChunk(100, 0, 0, 0, {0x01, 0x02});
    auto packet = createSctpPacket(12345, 54321, 0x12345678, {data_chunk});

    FiveTuple ft;
    ft.src_ip = "192.168.1.1";
    ft.dst_ip = "192.168.1.2";
    ft.src_port = 12345;
    ft.dst_port = 54321;
    ft.protocol = 132;

    auto result = parser_->parse(packet.data(), packet.size(), ft);
    ASSERT_TRUE(result.has_value());

    auto json = result.value().toJson();
    EXPECT_TRUE(json.contains("header"));
    EXPECT_TRUE(json.contains("chunk_count"));
    EXPECT_TRUE(json.contains("data_chunks"));
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
