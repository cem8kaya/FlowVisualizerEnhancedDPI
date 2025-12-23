#include <gtest/gtest.h>
#include "pcap_ingest/pcapng_reader.h"
#include "pcap_ingest/multi_interface_reader.h"
#include "pcap_ingest/interface_detector.h"
#include <fstream>
#include <vector>
#include <cstring>
#include <arpa/inet.h>

using namespace callflow;

/**
 * Integration test fixture for multi-interface PCAPNG correlation
 */
class MultiInterfacePcapngIntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        test_file_ = "/tmp/test_multi_interface_integration.pcapng";
        createMultiInterfacePcapngWithPackets();
    }

    void TearDown() override {
        std::remove(test_file_.c_str());
    }

    /**
     * Create a PCAPNG file with multiple interfaces and realistic packets
     */
    void createMultiInterfacePcapngWithPackets() {
        std::ofstream file(test_file_, std::ios::binary);

        // Section Header Block
        writeSectionHeader(file);

        // Interface 0: S1-MME (SCTP)
        writeInterfaceDescription(file, 1, 65535, "eth0-S1-MME", "S1-MME Control Plane");

        // Interface 1: S1-U (GTP-U)
        writeInterfaceDescription(file, 1, 65535, "eth1-S1-U", "S1-U User Plane");

        // Interface 2: SGi (Internet)
        writeInterfaceDescription(file, 1, 65535, "eth2-SGi", "SGi to PDN");

        // Add some Enhanced Packet Blocks on different interfaces

        // Packet 0: SCTP on S1-MME interface (interface_id = 0)
        std::vector<uint8_t> sctp_packet = createSctpPacket(36412);
        writeEnhancedPacket(file, 0, 1000000000ULL, sctp_packet);

        // Packet 1: GTP-U on S1-U interface (interface_id = 1)
        std::vector<uint8_t> gtpu_packet = createGtpUPacket(2152);
        writeEnhancedPacket(file, 1, 2000000000ULL, gtpu_packet);

        // Packet 2: HTTP on SGi interface (interface_id = 2)
        std::vector<uint8_t> http_packet = createHttpPacket(80);
        writeEnhancedPacket(file, 2, 3000000000ULL, http_packet);

        file.close();
    }

    void writeSectionHeader(std::ofstream& file) {
        uint32_t block_type = 0x0A0D0D0A;
        uint32_t block_length = 28;
        uint32_t byte_order_magic = 0x1A2B3C4D;
        uint16_t version_major = 1;
        uint16_t version_minor = 0;
        int64_t section_length = -1;

        file.write(reinterpret_cast<const char*>(&block_type), 4);
        file.write(reinterpret_cast<const char*>(&block_length), 4);
        file.write(reinterpret_cast<const char*>(&byte_order_magic), 4);
        file.write(reinterpret_cast<const char*>(&version_major), 2);
        file.write(reinterpret_cast<const char*>(&version_minor), 2);
        file.write(reinterpret_cast<const char*>(&section_length), 8);
        file.write(reinterpret_cast<const char*>(&block_length), 4);
    }

    void writeInterfaceDescription(std::ofstream& file, uint16_t link_type, uint32_t snap_len,
                                   const std::string& name, const std::string& description) {
        // Calculate total size with options
        uint32_t options_size = 0;

        // if_name option
        uint16_t name_len = static_cast<uint16_t>(name.length());
        uint16_t name_padded = (name_len + 3) & ~3;
        options_size += 4 + name_padded;  // code + length + padded value

        // if_description option
        uint16_t desc_len = static_cast<uint16_t>(description.length());
        uint16_t desc_padded = (desc_len + 3) & ~3;
        options_size += 4 + desc_padded;

        // end of options
        options_size += 4;

        uint32_t block_length = 20 + options_size;  // 8 bytes fixed + options + trailing length
        uint32_t block_type = 0x00000001;
        uint16_t reserved = 0;

        file.write(reinterpret_cast<const char*>(&block_type), 4);
        file.write(reinterpret_cast<const char*>(&block_length), 4);
        file.write(reinterpret_cast<const char*>(&link_type), 2);
        file.write(reinterpret_cast<const char*>(&reserved), 2);
        file.write(reinterpret_cast<const char*>(&snap_len), 4);

        // Write if_name option (code = 2)
        uint16_t opt_code = 2;
        file.write(reinterpret_cast<const char*>(&opt_code), 2);
        file.write(reinterpret_cast<const char*>(&name_len), 2);
        file.write(name.c_str(), name_len);
        // Write padding
        for (int i = name_len; i < name_padded; i++) {
            char pad = 0;
            file.write(&pad, 1);
        }

        // Write if_description option (code = 3)
        opt_code = 3;
        file.write(reinterpret_cast<const char*>(&opt_code), 2);
        file.write(reinterpret_cast<const char*>(&desc_len), 2);
        file.write(description.c_str(), desc_len);
        // Write padding
        for (int i = desc_len; i < desc_padded; i++) {
            char pad = 0;
            file.write(&pad, 1);
        }

        // Write end of options
        uint16_t opt_endofopt = 0;
        uint16_t opt_length = 0;
        file.write(reinterpret_cast<const char*>(&opt_endofopt), 2);
        file.write(reinterpret_cast<const char*>(&opt_length), 2);

        file.write(reinterpret_cast<const char*>(&block_length), 4);
    }

    void writeEnhancedPacket(std::ofstream& file, uint32_t interface_id,
                            uint64_t timestamp_ns, const std::vector<uint8_t>& packet_data) {
        uint32_t block_type = 0x00000006;
        uint32_t captured_length = static_cast<uint32_t>(packet_data.size());
        uint32_t original_length = captured_length;
        uint32_t padded_length = (captured_length + 3) & ~3;

        // Block length = type(4) + length(4) + iface_id(4) + timestamp(8) +
        //                captured_len(4) + original_len(4) + packet_data(padded) +
        //                options(4 for end) + trailing_length(4)
        uint32_t block_length = 12 + 20 + padded_length + 4;

        uint32_t ts_high = static_cast<uint32_t>(timestamp_ns >> 32);
        uint32_t ts_low = static_cast<uint32_t>(timestamp_ns & 0xFFFFFFFF);

        file.write(reinterpret_cast<const char*>(&block_type), 4);
        file.write(reinterpret_cast<const char*>(&block_length), 4);
        file.write(reinterpret_cast<const char*>(&interface_id), 4);
        file.write(reinterpret_cast<const char*>(&ts_high), 4);
        file.write(reinterpret_cast<const char*>(&ts_low), 4);
        file.write(reinterpret_cast<const char*>(&captured_length), 4);
        file.write(reinterpret_cast<const char*>(&original_length), 4);
        file.write(reinterpret_cast<const char*>(packet_data.data()), captured_length);

        // Write padding
        for (uint32_t i = captured_length; i < padded_length; i++) {
            char pad = 0;
            file.write(&pad, 1);
        }

        // Write end of options
        uint16_t opt_endofopt = 0;
        uint16_t opt_length = 0;
        file.write(reinterpret_cast<const char*>(&opt_endofopt), 2);
        file.write(reinterpret_cast<const char*>(&opt_length), 2);

        file.write(reinterpret_cast<const char*>(&block_length), 4);
    }

    // Create a minimal SCTP packet with port 36412 (S1-MME)
    std::vector<uint8_t> createSctpPacket(uint16_t port) {
        std::vector<uint8_t> packet(100, 0);

        // Ethernet header (14 bytes)
        packet[12] = 0x08;  // EtherType = IPv4 (0x0800)
        packet[13] = 0x00;

        // IPv4 header (20 bytes)
        packet[14] = 0x45;  // Version 4, IHL 5
        packet[15] = 0x00;  // ToS
        uint16_t total_len = htons(86);  // 20 (IP) + 12 (SCTP header min) + 54 (data)
        memcpy(&packet[16], &total_len, 2);
        packet[23] = 132;  // Protocol = SCTP

        // Source and destination IP
        packet[26] = 192; packet[27] = 168; packet[28] = 1; packet[29] = 10;  // Source IP
        packet[30] = 192; packet[31] = 168; packet[32] = 1; packet[33] = 20;  // Dest IP

        // SCTP header (starts at offset 34)
        uint16_t src_port = htons(12345);
        uint16_t dst_port = htons(port);
        memcpy(&packet[34], &src_port, 2);
        memcpy(&packet[36], &dst_port, 2);

        return packet;
    }

    // Create a minimal GTP-U packet with port 2152
    std::vector<uint8_t> createGtpUPacket(uint16_t port) {
        std::vector<uint8_t> packet(100, 0);

        // Ethernet header
        packet[12] = 0x08;
        packet[13] = 0x00;

        // IPv4 header
        packet[14] = 0x45;
        packet[23] = 17;  // Protocol = UDP

        // Source and destination IP
        packet[26] = 10; packet[27] = 0; packet[28] = 0; packet[29] = 1;
        packet[30] = 10; packet[31] = 0; packet[32] = 0; packet[33] = 2;

        // UDP header (starts at offset 34)
        uint16_t src_port = htons(54321);
        uint16_t dst_port = htons(port);
        memcpy(&packet[34], &src_port, 2);
        memcpy(&packet[36], &dst_port, 2);

        // GTP-U header (starts at offset 42)
        packet[42] = 0x30;  // GTP version 1, PT=1

        return packet;
    }

    // Create a minimal HTTP packet with port 80
    std::vector<uint8_t> createHttpPacket(uint16_t port) {
        std::vector<uint8_t> packet(100, 0);

        // Ethernet header
        packet[12] = 0x08;
        packet[13] = 0x00;

        // IPv4 header
        packet[14] = 0x45;
        packet[23] = 6;  // Protocol = TCP

        // Source and destination IP
        packet[26] = 172; packet[27] = 16; packet[28] = 0; packet[29] = 1;
        packet[30] = 8; packet[31] = 8; packet[32] = 8; packet[33] = 8;

        // TCP header (starts at offset 34)
        uint16_t src_port = htons(54321);
        uint16_t dst_port = htons(port);
        memcpy(&packet[34], &src_port, 2);
        memcpy(&packet[36], &dst_port, 2);

        return packet;
    }

    std::string test_file_;
};

// Test reading multi-interface PCAPNG file
TEST_F(MultiInterfacePcapngIntegrationTest, ReadMultiInterfaceFile) {
    PcapngReader reader;

    ASSERT_TRUE(reader.open(test_file_));

    const auto& interfaces = reader.getInterfaces();
    EXPECT_EQ(interfaces.size(), 3);

    // Check interface 0 (S1-MME)
    EXPECT_EQ(interfaces[0].interface_id, 0);
    EXPECT_EQ(interfaces[0].name.value_or(""), "eth0-S1-MME");
    EXPECT_EQ(interfaces[0].description.value_or(""), "S1-MME Control Plane");

    // Check interface 1 (S1-U)
    EXPECT_EQ(interfaces[1].interface_id, 1);
    EXPECT_EQ(interfaces[1].name.value_or(""), "eth1-S1-U");

    // Check interface 2 (SGi)
    EXPECT_EQ(interfaces[2].interface_id, 2);
    EXPECT_EQ(interfaces[2].name.value_or(""), "eth2-SGi");
}

// Test packet reading from multiple interfaces
TEST_F(MultiInterfacePcapngIntegrationTest, ReadPacketsFromDifferentInterfaces) {
    PcapngReader reader;
    ASSERT_TRUE(reader.open(test_file_));

    std::vector<uint32_t> interface_ids;

    reader.processPackets([&interface_ids](
        uint32_t interface_id,
        uint64_t timestamp_ns,
        const uint8_t* packet_data,
        uint32_t captured_length,
        uint32_t original_length,
        const PcapngPacketMetadata& metadata) {

        interface_ids.push_back(interface_id);
    });

    ASSERT_EQ(interface_ids.size(), 3);
    EXPECT_EQ(interface_ids[0], 0);  // First packet on interface 0
    EXPECT_EQ(interface_ids[1], 1);  // Second packet on interface 1
    EXPECT_EQ(interface_ids[2], 2);  // Third packet on interface 2
}

// Test interface type auto-detection from names
TEST_F(MultiInterfacePcapngIntegrationTest, AutoDetectInterfaceTypes) {
    PcapngReader reader;
    ASSERT_TRUE(reader.open(test_file_));

    const auto& interfaces = reader.getInterfaces();

    // Test detection for each interface
    for (const auto& iface : interfaces) {
        std::string name = iface.name.value_or("");
        std::string desc = iface.description.value_or("");

        auto detected_type = InterfaceDetector::detectTelecomInterface(name, desc);

        if (iface.interface_id == 0) {
            EXPECT_EQ(detected_type, PcapngInterfaceInfo::TelecomInterface::S1_MME);
        } else if (iface.interface_id == 1) {
            EXPECT_EQ(detected_type, PcapngInterfaceInfo::TelecomInterface::S1_U);
        } else if (iface.interface_id == 2) {
            EXPECT_EQ(detected_type, PcapngInterfaceInfo::TelecomInterface::SG_I);
        }
    }
}

// Test PcapngInterfaceInfo structure conversion
TEST_F(MultiInterfacePcapngIntegrationTest, ConvertToPcapngInterfaceInfo) {
    PcapngReader reader;
    ASSERT_TRUE(reader.open(test_file_));

    const auto& interfaces = reader.getInterfaces();

    for (const auto& iface : interfaces) {
        PcapngInterfaceInfo info = PcapngInterfaceInfo::fromPcapngInterface(iface);

        EXPECT_EQ(info.interface_id, iface.interface_id);
        EXPECT_EQ(info.link_type, iface.link_type);
        EXPECT_EQ(info.snap_len, iface.snap_len);
        EXPECT_EQ(info.name, iface.name.value_or(""));
        EXPECT_EQ(info.description, iface.description.value_or(""));
    }
}

// Test PcapngPacketInfo structure
TEST_F(MultiInterfacePcapngIntegrationTest, PacketInfoStructure) {
    PcapngPacketInfo packet_info;

    packet_info.interface_id = 0;
    packet_info.timestamp_high = 1;
    packet_info.timestamp_low = 1000000000;
    packet_info.captured_len = 100;
    packet_info.original_len = 100;
    packet_info.flags = 1;  // Inbound

    EXPECT_EQ(packet_info.getDirection(), PcapngPacketInfo::Direction::INBOUND);

    // Test timestamp conversion (default microsecond resolution)
    uint64_t ts_ns = packet_info.getTimestampNs(6);  // 6 = microseconds
    EXPECT_GT(ts_ns, 0);
}

// Test interface detector toString
TEST_F(MultiInterfacePcapngIntegrationTest, InterfaceDetectorToString) {
    using TI = PcapngInterfaceInfo::TelecomInterface;

    EXPECT_EQ(InterfaceDetector::toString(TI::S1_MME), "S1-MME");
    EXPECT_EQ(InterfaceDetector::toString(TI::S1_U), "S1-U");
    EXPECT_EQ(InterfaceDetector::toString(TI::SG_I), "SGi");
    EXPECT_EQ(InterfaceDetector::toString(TI::N2), "N2");
    EXPECT_EQ(InterfaceDetector::toString(TI::GX), "Gx");
    EXPECT_EQ(InterfaceDetector::toString(TI::IMS_SIP), "IMS-SIP");
}

// Test well-known ports
TEST_F(MultiInterfacePcapngIntegrationTest, WellKnownPorts) {
    using TI = PcapngInterfaceInfo::TelecomInterface;

    auto s1_mme_ports = InterfaceDetector::getWellKnownPorts(TI::S1_MME);
    ASSERT_FALSE(s1_mme_ports.empty());
    EXPECT_EQ(s1_mme_ports[0], 36412);

    auto gtpu_ports = InterfaceDetector::getWellKnownPorts(TI::S1_U);
    ASSERT_FALSE(gtpu_ports.empty());
    EXPECT_EQ(gtpu_ports[0], 2152);
}

// Test expected protocols
TEST_F(MultiInterfacePcapngIntegrationTest, ExpectedProtocols) {
    using TI = PcapngInterfaceInfo::TelecomInterface;

    auto s1_mme_protocols = InterfaceDetector::getExpectedProtocols(TI::S1_MME);
    ASSERT_FALSE(s1_mme_protocols.empty());
    EXPECT_EQ(s1_mme_protocols[0], "SCTP");

    auto sgi_protocols = InterfaceDetector::getExpectedProtocols(TI::SG_I);
    ASSERT_FALSE(sgi_protocols.empty());
}

// Test timestamp resolution handling
TEST_F(MultiInterfacePcapngIntegrationTest, TimestampResolution) {
    PcapngInterfaceInfo info;

    // Test default (microseconds)
    EXPECT_EQ(info.getTimestampResolutionNs(), 1000000ULL);

    // Test nanoseconds (resolution = 9)
    info.ts_resolution = 9;
    EXPECT_EQ(info.getTimestampResolutionNs(), 1ULL);

    // Test milliseconds (resolution = 3)
    info.ts_resolution = 3;
    EXPECT_EQ(info.getTimestampResolutionNs(), 1000000000ULL / 1000);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
