#pragma once

#include <string>
#include <optional>

namespace callflow {

/**
 * PCAP file format types
 */
enum class PcapFormat {
    UNKNOWN = 0,
    PCAP_CLASSIC,         // Classic libpcap format (.pcap)
    PCAPNG,               // PCAPNG format (.pcapng)
    PCAP_GZIP,            // Gzip compressed PCAP (.pcap.gz)
    PCAPNG_GZIP,          // Gzip compressed PCAPNG (.pcapng.gz)
    ERF,                  // Endace ERF format
    SNOOP,                // Sun Snoop format
    NTAR                  // Network Trace Archival format
};

/**
 * Format detection result
 */
struct FormatDetectionResult {
    PcapFormat format = PcapFormat::UNKNOWN;
    bool is_compressed = false;
    std::string compression_type;  // "gzip", "bzip2", etc.
    std::optional<std::string> error_message;

    // Format-specific details
    std::optional<uint32_t> version_major;
    std::optional<uint32_t> version_minor;
    std::optional<uint32_t> snaplen;
    std::optional<uint32_t> linktype;

    bool isValid() const {
        return format != PcapFormat::UNKNOWN && !error_message.has_value();
    }
};

/**
 * PCAP Format Detector
 *
 * Detects and validates various PCAP file formats including:
 * - Classic PCAP
 * - PCAPNG
 * - Compressed variants (gzip, bzip2)
 * - ERF (Endace)
 * - Snoop
 */
class PcapFormatDetector {
public:
    /**
     * Detect the format of a PCAP file
     * @param filename Path to the file
     * @return Detection result with format information
     */
    static FormatDetectionResult detect(const std::string& filename);

    /**
     * Check if file is PCAP classic format
     * @param filename Path to the file
     * @return true if classic PCAP format
     */
    static bool isPcapClassic(const std::string& filename);

    /**
     * Check if file is PCAPNG format
     * @param filename Path to the file
     * @return true if PCAPNG format
     */
    static bool isPcapng(const std::string& filename);

    /**
     * Check if file is compressed
     * @param filename Path to the file
     * @return Optional compression type ("gzip", "bzip2", etc.)
     */
    static std::optional<std::string> detectCompression(const std::string& filename);

    /**
     * Get format name as string
     * @param format The format enum
     * @return Human-readable format name
     */
    static std::string formatToString(PcapFormat format);

    /**
     * Validate file format and check readability
     * @param filename Path to the file
     * @return true if file is valid and readable
     */
    static bool validate(const std::string& filename);

    /**
     * Get recommended reader type for a format
     * @param format The detected format
     * @return "pcap" for classic PCAP, "pcapng" for PCAPNG, empty for unsupported
     */
    static std::string getRecommendedReader(PcapFormat format);

private:
    // Magic number constants
    static constexpr uint32_t PCAP_MAGIC = 0xA1B2C3D4;
    static constexpr uint32_t PCAP_MAGIC_SWAPPED = 0xD4C3B2A1;
    static constexpr uint32_t PCAP_NSEC_MAGIC = 0xA1B23C4D;
    static constexpr uint32_t PCAP_NSEC_MAGIC_SWAPPED = 0x4D3CB2A1;
    static constexpr uint32_t PCAPNG_MAGIC = 0x0A0D0D0A;
    static constexpr uint16_t GZIP_MAGIC = 0x1F8B;
    static constexpr uint16_t BZIP2_MAGIC = 0x425A;  // "BZ"
    static constexpr uint64_t ERF_TYPE_MASK = 0x7F;

    // Helper methods
    static bool readFileHeader(const std::string& filename, uint8_t* buffer, size_t size);
    static FormatDetectionResult detectPcapClassic(const uint8_t* header, size_t size);
    static FormatDetectionResult detectPcapng(const uint8_t* header, size_t size);
    static FormatDetectionResult detectErf(const uint8_t* header, size_t size);
    static FormatDetectionResult detectSnoop(const uint8_t* header, size_t size);
};

}  // namespace callflow
