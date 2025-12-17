#include <gtest/gtest.h>
#include "pcap_ingest/pcapng_reader.h"
#include "pcap_ingest/multi_interface_reader.h"
#include "pcap_ingest/format_detector.h"
#include <fstream>
#include <vector>

using namespace callflow;

/**
 * Test fixture for PCAPNG reader tests
 */
class PcapngReaderTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create a minimal valid PCAPNG file for testing
        test_file_ = "/tmp/test_pcapng.pcapng";
        createMinimalPcapngFile(test_file_);
    }

    void TearDown() override {
        // Clean up test files
        std::remove(test_file_.c_str());
    }

    /**
     * Create a minimal valid PCAPNG file with Section Header and Interface Description
     */
    void createMinimalPcapngFile(const std::string& filename) {
        std::ofstream file(filename, std::ios::binary);

        // Section Header Block
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
        file.write(reinterpret_cast<const char*>(&block_length), 4);  // Trailing length

        // Interface Description Block
        block_type = 0x00000001;
        block_length = 20;
        uint16_t link_type = 1;  // Ethernet
        uint16_t reserved = 0;
        uint32_t snap_len = 65535;
        uint16_t opt_endofopt = 0;
        uint16_t opt_length = 0;

        file.write(reinterpret_cast<const char*>(&block_type), 4);
        file.write(reinterpret_cast<const char*>(&block_length), 4);
        file.write(reinterpret_cast<const char*>(&link_type), 2);
        file.write(reinterpret_cast<const char*>(&reserved), 2);
        file.write(reinterpret_cast<const char*>(&snap_len), 4);
        file.write(reinterpret_cast<const char*>(&opt_endofopt), 2);
        file.write(reinterpret_cast<const char*>(&opt_length), 2);
        file.write(reinterpret_cast<const char*>(&block_length), 4);  // Trailing length

        file.close();
    }

    std::string test_file_;
};

// Test PcapngBlockType enum
TEST_F(PcapngReaderTest, BlockTypeEnumValues) {
    EXPECT_EQ(static_cast<uint32_t>(PcapngBlockType::SECTION_HEADER), 0x0A0D0D0A);
    EXPECT_EQ(static_cast<uint32_t>(PcapngBlockType::INTERFACE_DESCRIPTION), 0x00000001);
    EXPECT_EQ(static_cast<uint32_t>(PcapngBlockType::ENHANCED_PACKET), 0x00000006);
    EXPECT_EQ(static_cast<uint32_t>(PcapngBlockType::NAME_RESOLUTION), 0x00000004);
    EXPECT_EQ(static_cast<uint32_t>(PcapngBlockType::INTERFACE_STATISTICS), 0x00000005);
    EXPECT_EQ(static_cast<uint32_t>(PcapngBlockType::CUSTOM_BLOCK), 0x00000BAD);
    EXPECT_EQ(static_cast<uint32_t>(PcapngBlockType::DECRYPTION_SECRETS), 0x0000000A);
    EXPECT_EQ(static_cast<uint32_t>(PcapngBlockType::SYSTEMD_JOURNAL), 0x00000009);
}

// Test PcapngInterface struct
TEST_F(PcapngReaderTest, InterfaceStruct) {
    PcapngInterface iface;
    iface.interface_id = 0;
    iface.link_type = 1;
    iface.snap_len = 65535;

    EXPECT_EQ(iface.interface_id, 0);
    EXPECT_EQ(iface.link_type, 1);
    EXPECT_EQ(iface.snap_len, 65535);

    // Test timestamp resolution (default: microseconds)
    EXPECT_EQ(iface.getTimestampResolutionNs(), 1000000ULL);

    // Test with custom resolution (nanoseconds = 9)
    iface.timestamp_resolution = 9;
    EXPECT_EQ(iface.getTimestampResolutionNs(), 1ULL);
}

// Test PcapngPacketMetadata struct
TEST_F(PcapngReaderTest, PacketMetadataStruct) {
    PcapngPacketMetadata metadata;

    // Test direction flags
    metadata.flags = 1;  // Inbound
    EXPECT_EQ(metadata.getDirection(), PcapngPacketMetadata::INFO_INBOUND);

    metadata.flags = 2;  // Outbound
    EXPECT_EQ(metadata.getDirection(), PcapngPacketMetadata::INFO_OUTBOUND);

    // Test reception type
    metadata.flags = 0x04;  // Multicast
    EXPECT_EQ(metadata.getReceptionType(), PcapngPacketMetadata::RECEPTION_MULTICAST);
}

// Test PcapngReader open and close
TEST_F(PcapngReaderTest, OpenClose) {
    PcapngReader reader;

    EXPECT_FALSE(reader.isOpen());

    EXPECT_TRUE(reader.open(test_file_));
    EXPECT_TRUE(reader.isOpen());

    reader.close();
    EXPECT_FALSE(reader.isOpen());
}

// Test PcapngReader file validation
TEST_F(PcapngReaderTest, ValidateFile) {
    EXPECT_TRUE(PcapngReader::validate(test_file_));
    EXPECT_FALSE(PcapngReader::validate("/nonexistent/file.pcapng"));
}

// Test PcapngReader section header parsing
TEST_F(PcapngReaderTest, ParseSectionHeader) {
    PcapngReader reader;
    ASSERT_TRUE(reader.open(test_file_));

    const auto& section_header = reader.getSectionHeader();
    EXPECT_EQ(section_header.major_version, 1);
    EXPECT_EQ(section_header.minor_version, 0);
    EXPECT_EQ(section_header.section_length, -1);
}

// Test PcapngReader interface parsing
TEST_F(PcapngReaderTest, ParseInterfaceDescription) {
    PcapngReader reader;
    ASSERT_TRUE(reader.open(test_file_));

    // Read the next block (Interface Description)
    ASSERT_TRUE(reader.readNextBlock());

    const auto& interfaces = reader.getInterfaces();
    ASSERT_EQ(interfaces.size(), 1);

    const auto& iface = interfaces[0];
    EXPECT_EQ(iface.interface_id, 0);
    EXPECT_EQ(iface.link_type, 1);
    EXPECT_EQ(iface.snap_len, 65535);
}

// Test PcapngReader statistics
TEST_F(PcapngReaderTest, Statistics) {
    PcapngReader reader;
    ASSERT_TRUE(reader.open(test_file_));

    const auto& stats = reader.getStats();
    EXPECT_EQ(stats.section_headers, 1);
    EXPECT_GT(stats.total_blocks, 0);
}

/**
 * Test fixture for MultiInterfacePcapReader
 */
class MultiInterfaceReaderTest : public ::testing::Test {
protected:
    void SetUp() override {
        test_file_ = "/tmp/test_multi_interface.pcapng";
        createMultiInterfacePcapngFile(test_file_);
    }

    void TearDown() override {
        std::remove(test_file_.c_str());
    }

    void createMultiInterfacePcapngFile(const std::string& filename) {
        std::ofstream file(filename, std::ios::binary);

        // Section Header Block
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

        // Create 3 interfaces
        for (int i = 0; i < 3; i++) {
            block_type = 0x00000001;
            block_length = 20;
            uint16_t link_type = 1;
            uint16_t reserved = 0;
            uint32_t snap_len = 65535;
            uint16_t opt_endofopt = 0;
            uint16_t opt_length = 0;

            file.write(reinterpret_cast<const char*>(&block_type), 4);
            file.write(reinterpret_cast<const char*>(&block_length), 4);
            file.write(reinterpret_cast<const char*>(&link_type), 2);
            file.write(reinterpret_cast<const char*>(&reserved), 2);
            file.write(reinterpret_cast<const char*>(&snap_len), 4);
            file.write(reinterpret_cast<const char*>(&opt_endofopt), 2);
            file.write(reinterpret_cast<const char*>(&opt_length), 2);
            file.write(reinterpret_cast<const char*>(&block_length), 4);
        }

        file.close();
    }

    std::string test_file_;
};

// Test MultiInterfacePcapReader open
TEST_F(MultiInterfaceReaderTest, OpenMultiInterface) {
    MultiInterfacePcapReader reader;

    EXPECT_TRUE(reader.open(test_file_));
    EXPECT_TRUE(reader.isOpen());

    const auto& stats = reader.getStats();
    EXPECT_EQ(stats.total_interfaces, 3);
}

// Test MultiInterfacePcapReader interface type mapping
TEST_F(MultiInterfaceReaderTest, InterfaceTypeMapping) {
    MultiInterfacePcapReader reader;
    ASSERT_TRUE(reader.open(test_file_));

    // Manually add interface type mappings
    reader.addInterface(0, TelecomInterfaceType::S1_MME);
    reader.addInterface(1, TelecomInterfaceType::S1_U);
    reader.addInterface(2, TelecomInterfaceType::SGI);

    EXPECT_EQ(reader.getInterfaceType(0), TelecomInterfaceType::S1_MME);
    EXPECT_EQ(reader.getInterfaceType(1), TelecomInterfaceType::S1_U);
    EXPECT_EQ(reader.getInterfaceType(2), TelecomInterfaceType::SGI);
}

// Test TelecomInterfaceType to string conversion
TEST(TelecomInterfaceTypeTest, ToString) {
    EXPECT_EQ(telecomInterfaceTypeToString(TelecomInterfaceType::S1_MME), "S1-MME");
    EXPECT_EQ(telecomInterfaceTypeToString(TelecomInterfaceType::S1_U), "S1-U");
    EXPECT_EQ(telecomInterfaceTypeToString(TelecomInterfaceType::S11), "S11");
    EXPECT_EQ(telecomInterfaceTypeToString(TelecomInterfaceType::S5_S8), "S5/S8");
    EXPECT_EQ(telecomInterfaceTypeToString(TelecomInterfaceType::SGI), "SGi");
    EXPECT_EQ(telecomInterfaceTypeToString(TelecomInterfaceType::N2), "N2");
    EXPECT_EQ(telecomInterfaceTypeToString(TelecomInterfaceType::N3), "N3");
    EXPECT_EQ(telecomInterfaceTypeToString(TelecomInterfaceType::N4), "N4");
    EXPECT_EQ(telecomInterfaceTypeToString(TelecomInterfaceType::N6), "N6");
}

/**
 * Test fixture for PcapFormatDetector
 */
class FormatDetectorTest : public ::testing::Test {
protected:
    void SetUp() override {
        pcap_file_ = "/tmp/test_format.pcap";
        pcapng_file_ = "/tmp/test_format.pcapng";

        createPcapFile(pcap_file_);
        createPcapngFile(pcapng_file_);
    }

    void TearDown() override {
        std::remove(pcap_file_.c_str());
        std::remove(pcapng_file_.c_str());
    }

    void createPcapFile(const std::string& filename) {
        std::ofstream file(filename, std::ios::binary);

        // PCAP Global Header
        uint32_t magic = 0xA1B2C3D4;
        uint16_t version_major = 2;
        uint16_t version_minor = 4;
        int32_t thiszone = 0;
        uint32_t sigfigs = 0;
        uint32_t snaplen = 65535;
        uint32_t network = 1;  // Ethernet

        file.write(reinterpret_cast<const char*>(&magic), 4);
        file.write(reinterpret_cast<const char*>(&version_major), 2);
        file.write(reinterpret_cast<const char*>(&version_minor), 2);
        file.write(reinterpret_cast<const char*>(&thiszone), 4);
        file.write(reinterpret_cast<const char*>(&sigfigs), 4);
        file.write(reinterpret_cast<const char*>(&snaplen), 4);
        file.write(reinterpret_cast<const char*>(&network), 4);

        file.close();
    }

    void createPcapngFile(const std::string& filename) {
        std::ofstream file(filename, std::ios::binary);

        // Section Header Block
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

        file.close();
    }

    std::string pcap_file_;
    std::string pcapng_file_;
};

// Test format detection for PCAP classic
TEST_F(FormatDetectorTest, DetectPcapClassic) {
    auto result = PcapFormatDetector::detect(pcap_file_);

    EXPECT_TRUE(result.isValid());
    EXPECT_EQ(result.format, PcapFormat::PCAP_CLASSIC);
    EXPECT_FALSE(result.is_compressed);
    EXPECT_EQ(result.version_major.value(), 2);
    EXPECT_EQ(result.version_minor.value(), 4);
}

// Test format detection for PCAPNG
TEST_F(FormatDetectorTest, DetectPcapng) {
    auto result = PcapFormatDetector::detect(pcapng_file_);

    EXPECT_TRUE(result.isValid());
    EXPECT_EQ(result.format, PcapFormat::PCAPNG);
    EXPECT_FALSE(result.is_compressed);
    EXPECT_EQ(result.version_major.value(), 1);
    EXPECT_EQ(result.version_minor.value(), 0);
}

// Test isPcapClassic helper
TEST_F(FormatDetectorTest, IsPcapClassic) {
    EXPECT_TRUE(PcapFormatDetector::isPcapClassic(pcap_file_));
    EXPECT_FALSE(PcapFormatDetector::isPcapClassic(pcapng_file_));
}

// Test isPcapng helper
TEST_F(FormatDetectorTest, IsPcapng) {
    EXPECT_FALSE(PcapFormatDetector::isPcapng(pcap_file_));
    EXPECT_TRUE(PcapFormatDetector::isPcapng(pcapng_file_));
}

// Test format to string conversion
TEST(FormatDetectorTest, FormatToString) {
    EXPECT_EQ(PcapFormatDetector::formatToString(PcapFormat::PCAP_CLASSIC), "PCAP Classic");
    EXPECT_EQ(PcapFormatDetector::formatToString(PcapFormat::PCAPNG), "PCAPNG");
    EXPECT_EQ(PcapFormatDetector::formatToString(PcapFormat::PCAP_GZIP), "PCAP (gzip compressed)");
    EXPECT_EQ(PcapFormatDetector::formatToString(PcapFormat::PCAPNG_GZIP), "PCAPNG (gzip compressed)");
}

// Test recommended reader
TEST(FormatDetectorTest, RecommendedReader) {
    EXPECT_EQ(PcapFormatDetector::getRecommendedReader(PcapFormat::PCAP_CLASSIC), "pcap");
    EXPECT_EQ(PcapFormatDetector::getRecommendedReader(PcapFormat::PCAPNG), "pcapng");
    EXPECT_EQ(PcapFormatDetector::getRecommendedReader(PcapFormat::ERF), "");
}

// Main function
int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
