#include "pcap_ingest/format_detector.h"
#include "common/logger.h"
#include <cstring>
#include <fstream>
#include <arpa/inet.h>

namespace callflow {

// Snoop magic number
static const uint32_t SNOOP_MAGIC = 0x736E6F6F;  // "snoo"

FormatDetectionResult PcapFormatDetector::detect(const std::string& filename) {
    FormatDetectionResult result;

    // Read first 64 bytes of file for magic number detection
    uint8_t header[64];
    if (!readFileHeader(filename, header, sizeof(header))) {
        result.error_message = "Failed to read file header";
        return result;
    }

    // Check for compression first
    auto compression = detectCompression(filename);
    if (compression.has_value()) {
        result.is_compressed = true;
        result.compression_type = compression.value();

        if (compression.value() == "gzip") {
            // For gzip files, we'd need to decompress to detect the actual format
            // For now, guess based on filename extension
            if (filename.find(".pcapng.gz") != std::string::npos) {
                result.format = PcapFormat::PCAPNG_GZIP;
            } else if (filename.find(".pcap.gz") != std::string::npos) {
                result.format = PcapFormat::PCAP_GZIP;
            } else {
                result.error_message = "Cannot detect format of compressed file";
            }
            return result;
        }
    }

    // Check for PCAPNG
    uint32_t magic32 = *reinterpret_cast<const uint32_t*>(header);
    if (magic32 == PCAPNG_MAGIC) {
        return detectPcapng(header, sizeof(header));
    }

    // Check for PCAP classic (both byte orders and nanosecond variant)
    if (magic32 == PCAP_MAGIC || magic32 == PCAP_MAGIC_SWAPPED ||
        magic32 == PCAP_NSEC_MAGIC || magic32 == PCAP_NSEC_MAGIC_SWAPPED) {
        return detectPcapClassic(header, sizeof(header));
    }

    // Check for Snoop
    if (ntohl(magic32) == SNOOP_MAGIC) {
        return detectSnoop(header, sizeof(header));
    }

    // Check for ERF (Endace format)
    // ERF has no fixed magic number, but has a specific header structure
    // First 8 bytes: timestamp, next byte: type/flags
    if (sizeof(header) >= 16) {
        uint8_t erf_type = header[8] & ERF_TYPE_MASK;
        // ERF types range from 0-127, common types are 1-24
        if (erf_type > 0 && erf_type < 30) {
            return detectErf(header, sizeof(header));
        }
    }

    result.error_message = "Unknown or unsupported file format";
    return result;
}

bool PcapFormatDetector::isPcapClassic(const std::string& filename) {
    uint8_t header[4];
    if (!readFileHeader(filename, header, sizeof(header))) {
        return false;
    }

    uint32_t magic = *reinterpret_cast<const uint32_t*>(header);
    return (magic == PCAP_MAGIC || magic == PCAP_MAGIC_SWAPPED ||
            magic == PCAP_NSEC_MAGIC || magic == PCAP_NSEC_MAGIC_SWAPPED);
}

bool PcapFormatDetector::isPcapng(const std::string& filename) {
    uint8_t header[4];
    if (!readFileHeader(filename, header, sizeof(header))) {
        return false;
    }

    uint32_t magic = *reinterpret_cast<const uint32_t*>(header);
    return magic == PCAPNG_MAGIC;
}

std::optional<std::string> PcapFormatDetector::detectCompression(const std::string& filename) {
    uint8_t header[2];
    if (!readFileHeader(filename, header, sizeof(header))) {
        return std::nullopt;
    }

    uint16_t magic = *reinterpret_cast<const uint16_t*>(header);

    if (magic == GZIP_MAGIC) {
        return "gzip";
    }
    if (magic == BZIP2_MAGIC) {
        return "bzip2";
    }

    return std::nullopt;
}

std::string PcapFormatDetector::formatToString(PcapFormat format) {
    switch (format) {
        case PcapFormat::UNKNOWN: return "Unknown";
        case PcapFormat::PCAP_CLASSIC: return "PCAP Classic";
        case PcapFormat::PCAPNG: return "PCAPNG";
        case PcapFormat::PCAP_GZIP: return "PCAP (gzip compressed)";
        case PcapFormat::PCAPNG_GZIP: return "PCAPNG (gzip compressed)";
        case PcapFormat::ERF: return "Endace ERF";
        case PcapFormat::SNOOP: return "Sun Snoop";
        case PcapFormat::NTAR: return "NTAR";
        default: return "Unknown";
    }
}

bool PcapFormatDetector::validate(const std::string& filename) {
    FormatDetectionResult result = detect(filename);
    return result.isValid();
}

std::string PcapFormatDetector::getRecommendedReader(PcapFormat format) {
    switch (format) {
        case PcapFormat::PCAP_CLASSIC:
        case PcapFormat::PCAP_GZIP:
            return "pcap";
        case PcapFormat::PCAPNG:
        case PcapFormat::PCAPNG_GZIP:
            return "pcapng";
        default:
            return "";
    }
}

bool PcapFormatDetector::readFileHeader(const std::string& filename,
                                        uint8_t* buffer,
                                        size_t size) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }

    file.read(reinterpret_cast<char*>(buffer), size);
    size_t bytes_read = file.gcount();
    file.close();

    return bytes_read == size;
}

FormatDetectionResult PcapFormatDetector::detectPcapClassic(const uint8_t* header, size_t size) {
    FormatDetectionResult result;

    if (size < 24) {
        result.error_message = "File too small for PCAP header";
        return result;
    }

    result.format = PcapFormat::PCAP_CLASSIC;

    uint32_t magic = *reinterpret_cast<const uint32_t*>(header);
    bool swap_bytes = (magic == PCAP_MAGIC_SWAPPED || magic == PCAP_NSEC_MAGIC_SWAPPED);

    // Read version
    uint16_t version_major = *reinterpret_cast<const uint16_t*>(header + 4);
    uint16_t version_minor = *reinterpret_cast<const uint16_t*>(header + 6);

    if (swap_bytes) {
        version_major = ntohs(version_major);
        version_minor = ntohs(version_minor);
    }

    result.version_major = version_major;
    result.version_minor = version_minor;

    // Read snaplen
    uint32_t snaplen = *reinterpret_cast<const uint32_t*>(header + 16);
    if (swap_bytes) {
        snaplen = ntohl(snaplen);
    }
    result.snaplen = snaplen;

    // Read link type
    uint32_t linktype = *reinterpret_cast<const uint32_t*>(header + 20);
    if (swap_bytes) {
        linktype = ntohl(linktype);
    }
    result.linktype = linktype;

    LOG_DEBUG("Detected PCAP Classic: version " << version_major << "." << version_minor
              << ", snaplen=" << snaplen << ", linktype=" << linktype);

    return result;
}

FormatDetectionResult PcapFormatDetector::detectPcapng(const uint8_t* header, size_t size) {
    FormatDetectionResult result;

    if (size < 28) {
        result.error_message = "File too small for PCAPNG Section Header";
        return result;
    }

    result.format = PcapFormat::PCAPNG;

    // Read Section Header Block
    uint32_t block_type = *reinterpret_cast<const uint32_t*>(header);
    if (block_type != PCAPNG_MAGIC) {
        result.error_message = "Invalid PCAPNG magic number";
        return result;
    }

    // Read block length
    uint32_t block_length = *reinterpret_cast<const uint32_t*>(header + 4);

    // Read byte order magic
    uint32_t byte_order_magic = *reinterpret_cast<const uint32_t*>(header + 8);
    bool swap_bytes = (byte_order_magic == 0x4D3C2B1A);

    if (swap_bytes) {
        block_length = ntohl(block_length);
    }

    // Read version
    uint16_t version_major = *reinterpret_cast<const uint16_t*>(header + 12);
    uint16_t version_minor = *reinterpret_cast<const uint16_t*>(header + 14);

    if (swap_bytes) {
        version_major = ntohs(version_major);
        version_minor = ntohs(version_minor);
    }

    result.version_major = version_major;
    result.version_minor = version_minor;

    LOG_DEBUG("Detected PCAPNG: version " << version_major << "." << version_minor);

    return result;
}

FormatDetectionResult PcapFormatDetector::detectErf(const uint8_t* header, size_t size) {
    FormatDetectionResult result;

    if (size < 16) {
        result.error_message = "File too small for ERF header";
        return result;
    }

    result.format = PcapFormat::ERF;

    // ERF format validation
    // Byte 8 contains type and flags
    uint8_t erf_type = header[8] & ERF_TYPE_MASK;

    LOG_DEBUG("Detected ERF format with type: " << static_cast<int>(erf_type));

    return result;
}

FormatDetectionResult PcapFormatDetector::detectSnoop(const uint8_t* header, size_t size) {
    FormatDetectionResult result;

    if (size < 16) {
        result.error_message = "File too small for Snoop header";
        return result;
    }

    result.format = PcapFormat::SNOOP;

    // Read version (bytes 4-7)
    uint32_t version = ntohl(*reinterpret_cast<const uint32_t*>(header + 4));
    result.version_major = version;

    // Read datalink type (bytes 8-11)
    uint32_t linktype = ntohl(*reinterpret_cast<const uint32_t*>(header + 8));
    result.linktype = linktype;

    LOG_DEBUG("Detected Snoop format: version " << version << ", linktype=" << linktype);

    return result;
}

}  // namespace callflow
