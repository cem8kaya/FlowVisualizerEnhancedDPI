#include "pcap_ingest/pcapng_reader.h"
#include "common/utils.h"
#include <cstring>
#include <arpa/inet.h>

namespace callflow {

// PCAPNG magic number for Section Header Block
static const uint32_t PCAPNG_MAGIC = 0x0A0D0D0A;
static const uint32_t BYTE_ORDER_MAGIC = 0x1A2B3C4D;
static const uint32_t BYTE_ORDER_MAGIC_SWAPPED = 0x4D3C2B1A;

// Option codes
static const uint16_t OPT_ENDOFOPT = 0;
static const uint16_t OPT_COMMENT = 1;

// Interface Description Block options
static const uint16_t IF_NAME = 2;
static const uint16_t IF_DESCRIPTION = 3;
static const uint16_t IF_IPV4ADDR = 4;
static const uint16_t IF_IPV6ADDR = 5;
static const uint16_t IF_MACADDR = 6;
static const uint16_t IF_EUIADDR = 7;
static const uint16_t IF_SPEED = 8;
static const uint16_t IF_TSRESOL = 9;
static const uint16_t IF_TZONE = 10;
static const uint16_t IF_FILTER = 11;
static const uint16_t IF_OS = 12;
static const uint16_t IF_FCSLEN = 13;
static const uint16_t IF_TSOFFSET = 14;
static const uint16_t IF_HARDWARE = 15;

// Section Header Block options
static const uint16_t SHB_HARDWARE = 2;
static const uint16_t SHB_OS = 3;
static const uint16_t SHB_USERAPPL = 4;

// Enhanced Packet Block options
static const uint16_t EPB_FLAGS = 2;
static const uint16_t EPB_HASH = 3;
static const uint16_t EPB_DROPCOUNT = 4;
static const uint16_t EPB_PACKETID = 5;
static const uint16_t EPB_QUEUE = 6;
static const uint16_t EPB_VERDICT = 7;

// Interface Statistics Block options
static const uint16_t ISB_STARTTIME = 2;
static const uint16_t ISB_ENDTIME = 3;
static const uint16_t ISB_IFRECV = 4;
static const uint16_t ISB_IFDROP = 5;
static const uint16_t ISB_FILTERACCEPT = 6;
static const uint16_t ISB_OSDROP = 7;
static const uint16_t ISB_USRDELIV = 8;

PcapngReader::PcapngReader()
    : file_(nullptr),
      is_open_(false),
      is_little_endian_(true),
      current_block_type_(PcapngBlockType::SECTION_HEADER) {
    stats_ = Stats{};
}

PcapngReader::~PcapngReader() {
    close();
}

bool PcapngReader::open(const std::string& filename) {
    if (is_open_) {
        LOG_WARN("PcapngReader already has an open file, closing it first");
        close();
    }

    file_ = fopen(filename.c_str(), "rb");
    if (!file_) {
        LOG_ERROR("Failed to open PCAPNG file: " << filename);
        return false;
    }

    filename_ = filename;
    is_open_ = true;
    stats_ = Stats{};

    // Read and validate Section Header Block
    if (!readNextBlock()) {
        LOG_ERROR("Failed to read Section Header Block from: " << filename);
        close();
        return false;
    }

    if (current_block_type_ != PcapngBlockType::SECTION_HEADER) {
        LOG_ERROR("First block is not a Section Header Block");
        close();
        return false;
    }

    if (!parseSectionHeader()) {
        LOG_ERROR("Failed to parse Section Header Block");
        close();
        return false;
    }

    LOG_INFO("Opened PCAPNG file: " << filename);
    return true;
}

void PcapngReader::close() {
    if (file_) {
        fclose(file_);
        file_ = nullptr;
    }

    is_open_ = false;

    if (!filename_.empty()) {
        LOG_INFO("Closed PCAPNG file: " << filename_
                 << " (processed " << stats_.enhanced_packets << " packets)");
        filename_.clear();
    }

    // Clear state
    interfaces_.clear();
    name_resolution_records_.clear();
    interface_statistics_.clear();
    current_block_data_.clear();
}

bool PcapngReader::readNextBlock() {
    if (!is_open_ || !file_) {
        LOG_ERROR("Attempting to read from closed PCAPNG file");
        return false;
    }

    uint32_t block_type, block_length;
    if (!readBlockHeader(block_type, block_length)) {
        return false;
    }

    current_block_type_ = static_cast<PcapngBlockType>(block_type);

    if (!readBlockData(block_length)) {
        return false;
    }

    stats_.total_blocks++;
    stats_.bytes_read += block_length;

    return true;
}

bool PcapngReader::readBlockHeader(uint32_t& block_type, uint32_t& block_length) {
    // Read block type
    if (fread(&block_type, sizeof(block_type), 1, file_) != 1) {
        if (feof(file_)) {
            return false;  // End of file
        }
        LOG_ERROR("Failed to read block type");
        return false;
    }

    // Special handling for Section Header Block to detect byte order
    if (block_type == PCAPNG_MAGIC) {
        // Read block total length
        if (fread(&block_length, sizeof(block_length), 1, file_) != 1) {
            LOG_ERROR("Failed to read block length");
            return false;
        }

        // Read byte order magic
        uint32_t byte_order_magic;
        if (fread(&byte_order_magic, sizeof(byte_order_magic), 1, file_) != 1) {
            LOG_ERROR("Failed to read byte order magic");
            return false;
        }

        if (byte_order_magic == BYTE_ORDER_MAGIC) {
            is_little_endian_ = true;
        } else if (byte_order_magic == BYTE_ORDER_MAGIC_SWAPPED) {
            is_little_endian_ = false;
            block_length = ntohl(block_length);
        } else {
            LOG_ERROR("Invalid byte order magic: 0x" << std::hex << byte_order_magic);
            return false;
        }

        // Seek back to read byte order magic as part of block data
        fseek(file_, -4, SEEK_CUR);
    } else {
        // Convert block type to host byte order
        block_type = toHost32(block_type);

        // Read block total length
        if (fread(&block_length, sizeof(block_length), 1, file_) != 1) {
            LOG_ERROR("Failed to read block length");
            return false;
        }
        block_length = toHost32(block_length);
    }

    // Validate block length
    if (block_length < 12) {
        LOG_ERROR("Invalid block length: " << block_length);
        return false;
    }

    return true;
}

bool PcapngReader::readBlockData(uint32_t block_length) {
    // Block length includes type (4), length (4), body, and trailing length (4)
    // We've already read type and length, so read body and trailing length
    uint32_t data_length = block_length - 12;  // Subtract type, length, and trailing length

    current_block_data_.resize(data_length);
    if (data_length > 0) {
        if (fread(current_block_data_.data(), 1, data_length, file_) != data_length) {
            LOG_ERROR("Failed to read block data");
            return false;
        }
    }

    // Read and verify trailing block length
    uint32_t trailing_length;
    if (fread(&trailing_length, sizeof(trailing_length), 1, file_) != 1) {
        LOG_ERROR("Failed to read trailing block length");
        return false;
    }
    trailing_length = toHost32(trailing_length);

    if (trailing_length != block_length) {
        LOG_ERROR("Block length mismatch: " << block_length << " vs " << trailing_length);
        return false;
    }

    return true;
}

bool PcapngReader::parseSectionHeader() {
    if (current_block_data_.size() < 12) {
        LOG_ERROR("Section Header Block too small");
        return false;
    }

    const uint8_t* data = current_block_data_.data();

    // Byte order magic already read
    section_header_.byte_order_magic = toHost32(*reinterpret_cast<const uint32_t*>(data));
    data += 4;

    // Major and minor version
    section_header_.major_version = toHost16(*reinterpret_cast<const uint16_t*>(data));
    data += 2;
    section_header_.minor_version = toHost16(*reinterpret_cast<const uint16_t*>(data));
    data += 2;

    // Section length
    section_header_.section_length = static_cast<int64_t>(toHost64(*reinterpret_cast<const uint64_t*>(data)));
    data += 8;

    // Parse options
    size_t options_offset = data - current_block_data_.data();
    size_t options_length = current_block_data_.size() - options_offset;

    parseOptions(data, options_length, [this](uint16_t code, const uint8_t* value, uint16_t length) {
        switch (code) {
            case SHB_HARDWARE:
                section_header_.hardware = extractString(value, length);
                break;
            case SHB_OS:
                section_header_.os = extractString(value, length);
                break;
            case SHB_USERAPPL:
                section_header_.user_application = extractString(value, length);
                break;
            case OPT_COMMENT:
                section_header_.comment = extractString(value, length);
                break;
        }
    });

    stats_.section_headers++;
    return true;
}

bool PcapngReader::parseInterfaceDescription() {
    if (current_block_data_.size() < 8) {
        LOG_ERROR("Interface Description Block too small");
        return false;
    }

    PcapngInterface interface;
    interface.interface_id = static_cast<uint32_t>(interfaces_.size());

    const uint8_t* data = current_block_data_.data();

    // LinkType
    interface.link_type = toHost16(*reinterpret_cast<const uint16_t*>(data));
    data += 2;

    // Reserved (2 bytes)
    data += 2;

    // SnapLen
    interface.snap_len = toHost32(*reinterpret_cast<const uint32_t*>(data));
    data += 4;

    // Parse options
    size_t options_offset = data - current_block_data_.data();
    size_t options_length = current_block_data_.size() - options_offset;

    parseOptions(data, options_length, [&interface, this](uint16_t code, const uint8_t* value, uint16_t length) {
        switch (code) {
            case IF_NAME:
                interface.name = extractString(value, length);
                break;
            case IF_DESCRIPTION:
                interface.description = extractString(value, length);
                break;
            case IF_HARDWARE:
                interface.hardware = extractString(value, length);
                break;
            case IF_TSRESOL:
                if (length >= 1) {
                    interface.timestamp_resolution = value[0];
                }
                break;
            case IF_SPEED:
                if (length >= 8) {
                    interface.speed = toHost64(*reinterpret_cast<const uint64_t*>(value));
                }
                break;
            case IF_OS:
                interface.os = extractString(value, length);
                break;
            case IF_FILTER:
                interface.filter = extractString(value, length);
                break;
            default:
                // Store custom options
                interface.custom_options[code] = std::vector<uint8_t>(value, value + length);
                break;
        }
    });

    interfaces_.push_back(interface);
    stats_.interface_descriptions++;

    LOG_DEBUG("Parsed Interface Description Block: ID=" << interface.interface_id
              << ", LinkType=" << interface.link_type
              << ", SnapLen=" << interface.snap_len);

    return true;
}

bool PcapngReader::parseEnhancedPacket() {
    stats_.enhanced_packets++;
    // Detailed parsing done in readEnhancedPacket()
    return true;
}

bool PcapngReader::readEnhancedPacket(uint32_t& interface_id,
                                      uint64_t& timestamp,
                                      std::vector<uint8_t>& packet_data,
                                      uint32_t& original_length,
                                      PcapngPacketMetadata& metadata) {
    if (current_block_type_ != PcapngBlockType::ENHANCED_PACKET) {
        LOG_ERROR("Current block is not an Enhanced Packet Block");
        return false;
    }

    if (current_block_data_.size() < 20) {
        LOG_ERROR("Enhanced Packet Block too small");
        return false;
    }

    const uint8_t* data = current_block_data_.data();

    // Interface ID
    interface_id = toHost32(*reinterpret_cast<const uint32_t*>(data));
    data += 4;

    // Timestamp (high and low)
    uint32_t ts_high = toHost32(*reinterpret_cast<const uint32_t*>(data));
    data += 4;
    uint32_t ts_low = toHost32(*reinterpret_cast<const uint32_t*>(data));
    data += 4;

    timestamp = (static_cast<uint64_t>(ts_high) << 32) | ts_low;

    // Convert timestamp to nanoseconds based on interface timestamp resolution
    const PcapngInterface* iface = getInterface(interface_id);
    if (iface) {
        uint64_t ts_resolution_ns = iface->getTimestampResolutionNs();
        timestamp = timestamp * ts_resolution_ns;
    }

    // Captured Packet Length
    uint32_t captured_length = toHost32(*reinterpret_cast<const uint32_t*>(data));
    data += 4;

    // Original Packet Length
    original_length = toHost32(*reinterpret_cast<const uint32_t*>(data));
    data += 4;

    // Packet data (padded to 32-bit boundary)
    uint32_t padded_length = (captured_length + 3) & ~3;
    if (current_block_data_.size() < 20 + padded_length) {
        LOG_ERROR("Enhanced Packet Block data truncated");
        return false;
    }

    packet_data.assign(data, data + captured_length);
    data += padded_length;

    // Parse options
    size_t options_offset = data - current_block_data_.data();
    size_t options_length = current_block_data_.size() - options_offset;

    parseOptions(data, options_length, [&metadata, this](uint16_t code, const uint8_t* value, uint16_t length) {
        switch (code) {
            case OPT_COMMENT:
                metadata.comment = extractString(value, length);
                break;
            case EPB_FLAGS:
                if (length >= 4) {
                    metadata.flags = toHost32(*reinterpret_cast<const uint32_t*>(value));
                }
                break;
            case EPB_DROPCOUNT:
                if (length >= 8) {
                    metadata.dropcount = toHost64(*reinterpret_cast<const uint64_t*>(value));
                }
                break;
            case EPB_HASH:
                if (length >= 8) {
                    metadata.hash = toHost64(*reinterpret_cast<const uint64_t*>(value));
                }
                break;
            case EPB_VERDICT:
                if (length >= 4) {
                    metadata.verdict = toHost32(*reinterpret_cast<const uint32_t*>(value));
                }
                break;
            case EPB_QUEUE:
                if (length >= 4) {
                    metadata.queue_id = toHost32(*reinterpret_cast<const uint32_t*>(value));
                }
                break;
        }
    });

    return true;
}

bool PcapngReader::parseNameResolution() {
    // Name Resolution Block contains records
    const uint8_t* data = current_block_data_.data();
    size_t offset = 0;

    while (offset + 4 <= current_block_data_.size()) {
        uint16_t record_type = toHost16(*reinterpret_cast<const uint16_t*>(data + offset));
        offset += 2;

        uint16_t record_length = toHost16(*reinterpret_cast<const uint16_t*>(data + offset));
        offset += 2;

        if (record_type == 0) {
            break;  // End of records
        }

        if (offset + record_length > current_block_data_.size()) {
            LOG_ERROR("Name Resolution record extends beyond block");
            break;
        }

        NameResolutionRecord record;
        record.type = static_cast<NameResolutionRecord::RecordType>(record_type);

        if (record_type == NameResolutionRecord::NRB_RECORD_IPV4 && record_length >= 4) {
            // IPv4 address + names
            const uint8_t* addr = data + offset;
            char addr_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, addr, addr_str, INET_ADDRSTRLEN);
            record.address = addr_str;

            // Parse null-terminated names
            size_t name_offset = 4;
            while (name_offset < record_length) {
                const char* name = reinterpret_cast<const char*>(data + offset + name_offset);
                size_t name_len = strnlen(name, record_length - name_offset);
                if (name_len > 0) {
                    record.names.push_back(std::string(name, name_len));
                    name_offset += name_len + 1;
                } else {
                    break;
                }
            }

            name_resolution_records_.push_back(record);
        } else if (record_type == NameResolutionRecord::NRB_RECORD_IPV6 && record_length >= 16) {
            // IPv6 address + names
            const uint8_t* addr = data + offset;
            char addr_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, addr, addr_str, INET6_ADDRSTRLEN);
            record.address = addr_str;

            // Parse null-terminated names
            size_t name_offset = 16;
            while (name_offset < record_length) {
                const char* name = reinterpret_cast<const char*>(data + offset + name_offset);
                size_t name_len = strnlen(name, record_length - name_offset);
                if (name_len > 0) {
                    record.names.push_back(std::string(name, name_len));
                    name_offset += name_len + 1;
                } else {
                    break;
                }
            }

            name_resolution_records_.push_back(record);
        }

        // Move to next record (with padding)
        uint32_t padded_length = (record_length + 3) & ~3;
        offset += padded_length;
    }

    stats_.name_resolution_blocks++;
    return true;
}

bool PcapngReader::parseInterfaceStatistics() {
    if (current_block_data_.size() < 12) {
        LOG_ERROR("Interface Statistics Block too small");
        return false;
    }

    InterfaceStatistics stats;

    const uint8_t* data = current_block_data_.data();

    // Interface ID
    stats.interface_id = toHost32(*reinterpret_cast<const uint32_t*>(data));
    data += 4;

    // Timestamp (high and low)
    uint32_t ts_high = toHost32(*reinterpret_cast<const uint32_t*>(data));
    data += 4;
    uint32_t ts_low = toHost32(*reinterpret_cast<const uint32_t*>(data));
    data += 4;

    stats.timestamp = (static_cast<uint64_t>(ts_high) << 32) | ts_low;

    // Parse options
    size_t options_offset = data - current_block_data_.data();
    size_t options_length = current_block_data_.size() - options_offset;

    parseOptions(data, options_length, [&stats, this](uint16_t code, const uint8_t* value, uint16_t length) {
        switch (code) {
            case ISB_IFRECV:
                if (length >= 8) {
                    stats.packets_received = toHost64(*reinterpret_cast<const uint64_t*>(value));
                }
                break;
            case ISB_IFDROP:
                if (length >= 8) {
                    stats.packets_dropped = toHost64(*reinterpret_cast<const uint64_t*>(value));
                }
                break;
            case ISB_FILTERACCEPT:
                if (length >= 8) {
                    stats.packets_accepted_by_filter = toHost64(*reinterpret_cast<const uint64_t*>(value));
                }
                break;
            case ISB_OSDROP:
                if (length >= 8) {
                    stats.packets_dropped_by_os = toHost64(*reinterpret_cast<const uint64_t*>(value));
                }
                break;
            case ISB_USRDELIV:
                if (length >= 8) {
                    stats.packets_delivered_to_user = toHost64(*reinterpret_cast<const uint64_t*>(value));
                }
                break;
            case OPT_COMMENT:
                stats.comment = extractString(value, length);
                break;
        }
    });

    interface_statistics_.push_back(stats);
    stats_.interface_statistics_blocks++;

    return true;
}

bool PcapngReader::parseOptions(const uint8_t* data, size_t length,
                                std::function<void(uint16_t, const uint8_t*, uint16_t)> callback) {
    size_t offset = 0;

    while (offset + 4 <= length) {
        uint16_t option_code = toHost16(*reinterpret_cast<const uint16_t*>(data + offset));
        offset += 2;

        uint16_t option_length = toHost16(*reinterpret_cast<const uint16_t*>(data + offset));
        offset += 2;

        if (option_code == OPT_ENDOFOPT) {
            break;
        }

        if (offset + option_length > length) {
            LOG_WARN("Option extends beyond block, truncating");
            break;
        }

        callback(option_code, data + offset, option_length);

        // Options are padded to 32-bit boundary
        uint32_t padded_length = (option_length + 3) & ~3;
        offset += padded_length;
    }

    return true;
}

size_t PcapngReader::processPackets(PacketCallback callback) {
    if (!is_open_ || !file_) {
        LOG_ERROR("Cannot process packets: PCAPNG file not open");
        return 0;
    }

    if (!callback) {
        LOG_ERROR("Cannot process packets: callback is null");
        return 0;
    }

    size_t packet_count = 0;

    while (readNextBlock()) {
        if (current_block_type_ == PcapngBlockType::INTERFACE_DESCRIPTION) {
            parseInterfaceDescription();
        } else if (current_block_type_ == PcapngBlockType::ENHANCED_PACKET) {
            uint32_t interface_id;
            uint64_t timestamp;
            std::vector<uint8_t> packet_data;
            uint32_t original_length;
            PcapngPacketMetadata metadata;

            if (readEnhancedPacket(interface_id, timestamp, packet_data, original_length, metadata)) {
                callback(interface_id, timestamp, packet_data.data(),
                        static_cast<uint32_t>(packet_data.size()), original_length, metadata);
                packet_count++;
                stats_.enhanced_packets++;  // Track enhanced packet count for close() logging

                if (packet_count % 100000 == 0) {
                    LOG_INFO("Processed " << packet_count << " packets...");
                }
            }
        } else if (current_block_type_ == PcapngBlockType::NAME_RESOLUTION) {
            parseNameResolution();
        } else if (current_block_type_ == PcapngBlockType::INTERFACE_STATISTICS) {
            parseInterfaceStatistics();
        } else if (current_block_type_ == PcapngBlockType::CUSTOM_BLOCK) {
            stats_.custom_blocks++;
        } else {
            stats_.unknown_blocks++;
        }
    }

    LOG_INFO("Finished processing " << packet_count << " packets from " << filename_);
    return packet_count;
}

bool PcapngReader::validate(const std::string& filename) {
    FILE* file = fopen(filename.c_str(), "rb");
    if (!file) {
        return false;
    }

    uint32_t block_type;
    if (fread(&block_type, sizeof(block_type), 1, file) != 1) {
        fclose(file);
        return false;
    }

    fclose(file);

    return block_type == PCAPNG_MAGIC;
}

// Byte order conversion helpers
uint16_t PcapngReader::toHost16(uint16_t value) const {
    if (is_little_endian_) {
        return value;
    }
    return ntohs(value);
}

uint32_t PcapngReader::toHost32(uint32_t value) const {
    if (is_little_endian_) {
        return value;
    }
    return ntohl(value);
}

uint64_t PcapngReader::toHost64(uint64_t value) const {
    if (is_little_endian_) {
        return value;
    }
    // Swap bytes for big endian
    return ((value & 0xFF00000000000000ULL) >> 56) |
           ((value & 0x00FF000000000000ULL) >> 40) |
           ((value & 0x0000FF0000000000ULL) >> 24) |
           ((value & 0x000000FF00000000ULL) >> 8) |
           ((value & 0x00000000FF000000ULL) << 8) |
           ((value & 0x0000000000FF0000ULL) << 24) |
           ((value & 0x000000000000FF00ULL) << 40) |
           ((value & 0x00000000000000FFULL) << 56);
}

std::string PcapngReader::extractString(const uint8_t* data, size_t length) const {
    // Find null terminator or use full length
    size_t str_len = 0;
    while (str_len < length && data[str_len] != '\0') {
        str_len++;
    }
    return std::string(reinterpret_cast<const char*>(data), str_len);
}

}  // namespace callflow
