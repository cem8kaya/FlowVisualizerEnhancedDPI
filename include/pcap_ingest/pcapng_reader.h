#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "common/logger.h"
#include "common/types.h"

namespace callflow {

/**
 * PCAPNG Block Types (as per PCAPNG specification)
 */
enum class PcapngBlockType : uint32_t {
    SECTION_HEADER = 0x0A0D0D0A,
    INTERFACE_DESCRIPTION = 0x00000001,
    SIMPLE_PACKET = 0x00000003,
    ENHANCED_PACKET = 0x00000006,
    NAME_RESOLUTION = 0x00000004,
    INTERFACE_STATISTICS = 0x00000005,
    CUSTOM_BLOCK = 0x00000BAD,
    DECRYPTION_SECRETS = 0x0000000A,
    SYSTEMD_JOURNAL = 0x00000009,
    // Legacy block types
    PACKET = 0x00000002  // Obsolete Packet Block
};

/**
 * Link types (DLT - Data Link Types)
 */
enum class LinkType : uint16_t {
    NULL_LINK = 0,
    ETHERNET = 1,
    RAW = 101,
    LINUX_SLL = 113,
    IEEE802_11 = 105,
    IEEE802_11_RADIO = 127
};

/**
 * Interface information from PCAPNG Interface Description Block
 */
struct PcapngInterface {
    uint32_t interface_id = 0;
    uint16_t link_type = 0;
    uint32_t snap_len = 65535;

    // Optional fields from options
    std::optional<std::string> name;
    std::optional<std::string> description;
    std::optional<std::string> hardware;
    std::optional<uint8_t>
        timestamp_resolution;       // Resolution of timestamps (default: 6 = microseconds)
    std::optional<uint64_t> speed;  // Interface speed in bits per second
    std::optional<std::string> os;
    std::optional<std::string> filter;

    // Custom options (option_code -> option_value)
    std::map<uint16_t, std::vector<uint8_t>> custom_options;

    /**
     * Get timestamp resolution in nanoseconds
     */
    uint64_t getTimestampResolutionNs() const {
        if (!timestamp_resolution.has_value()) {
            return 1000;  // Default: microseconds (10^-6) -> 1000 ns
        }
        uint8_t res = timestamp_resolution.value();
        if (res & 0x80) {
            // Negative power of 2
            return 1000000000ULL >> (res & 0x7F);
        } else {
            // Negative power of 10
            uint64_t divisor = 1;
            for (int i = 0; i < res; i++) {
                divisor *= 10;
            }
            return 1000000000ULL / divisor;
        }
    }
};

/**
 * Extended Interface Information with Telecom-Specific Classification
 * This structure matches the prompt requirements for enhanced telecom interface detection
 */
struct PcapngInterfaceInfo {
    uint32_t interface_id;
    uint16_t link_type;
    uint32_t snap_len;
    std::string name;
    std::string description;
    std::optional<uint8_t> ts_resolution;

    /**
     * Telecom Interface Types for Mobile Networks
     */
    enum class TelecomInterface {
        UNKNOWN,
        S1_MME,    // S1-MME (Control plane between eNodeB and MME) - SCTP port 36412
        S1_U,      // S1-U (User plane between eNodeB and S-GW) - GTP-U port 2152
        S5_S8_C,   // S5/S8 Control Plane - GTP-C port 2123
        S5_S8_U,   // S5/S8 User Plane - GTP-U port 2152
        S6A,       // S6a (MME to HSS) - Diameter port 3868
        SG_I,      // SGi (P-GW to external PDN) - HTTP/HTTPS
        GX,        // Gx (PCEF to PCRF) - Diameter port 3868
        RX,        // Rx (P-CSCF to PCRF) - Diameter port 3868
        GY,        // Gy (PCEF to OCS) - Diameter port 3868
        X2_C,      // X2 Control Plane (eNodeB to eNodeB) - SCTP port 36422
        N2,        // N2 (5G: gNB to AMF) - SCTP port 38412
        N3,        // N3 (5G: gNB to UPF) - GTP-U port 2152
        N4,        // N4 (5G: SMF to UPF) - PFCP port 8805
        N6,        // N6 (5G: UPF to Data Network) - HTTP/HTTPS
        IMS_SIP,   // IMS SIP Interface - SIP port 5060/5061
        RTP_MEDIA  // RTP Media Interface - RTP ports 10000-20000
    };

    TelecomInterface telecom_type = TelecomInterface::UNKNOWN;

    /**
     * Convert PcapngInterface to PcapngInterfaceInfo
     */
    static PcapngInterfaceInfo fromPcapngInterface(const PcapngInterface& iface) {
        PcapngInterfaceInfo info;
        info.interface_id = iface.interface_id;
        info.link_type = iface.link_type;
        info.snap_len = iface.snap_len;
        info.name = iface.name.value_or("");
        info.description = iface.description.value_or("");
        info.ts_resolution = iface.timestamp_resolution;
        info.telecom_type = TelecomInterface::UNKNOWN;
        return info;
    }

    /**
     * Get timestamp resolution in nanoseconds (same logic as PcapngInterface)
     */
    uint64_t getTimestampResolutionNs() const {
        if (!ts_resolution.has_value()) {
            return 1000000;  // Default: microseconds
        }
        uint8_t res = ts_resolution.value();
        if (res & 0x80) {
            // Negative power of 2
            return 1000000000ULL >> (res & 0x7F);
        } else {
            // Negative power of 10
            uint64_t divisor = 1;
            for (int i = 0; i < res; i++) {
                divisor *= 10;
            }
            return 1000000000ULL / divisor;
        }
    }
};

/**
 * Packet information extracted from Enhanced Packet Block
 */
struct PcapngPacketInfo {
    uint32_t interface_id;
    uint64_t timestamp_high;
    uint64_t timestamp_low;
    uint32_t captured_len;
    uint32_t original_len;
    std::vector<uint8_t> packet_data;
    std::optional<uint32_t> flags;

    enum class Direction { UNKNOWN, INBOUND, OUTBOUND };

    /**
     * Get packet direction from flags
     */
    Direction getDirection() const {
        if (!flags.has_value())
            return Direction::UNKNOWN;
        uint32_t dir = flags.value() & 0x03;
        if (dir == 1)
            return Direction::INBOUND;
        if (dir == 2)
            return Direction::OUTBOUND;
        return Direction::UNKNOWN;
    }

    /**
     * Get timestamp in nanoseconds
     * @param ts_resolution Timestamp resolution (default: 6 = microseconds)
     */
    uint64_t getTimestampNs(uint8_t ts_resolution = 6) const {
        uint64_t timestamp = (static_cast<uint64_t>(timestamp_high) << 32) | timestamp_low;

        // Convert based on resolution
        if (ts_resolution & 0x80) {
            // Negative power of 2
            uint64_t resolution_ns = 1000000000ULL >> (ts_resolution & 0x7F);
            return timestamp * resolution_ns;
        } else {
            // Negative power of 10
            uint64_t divisor = 1;
            for (int i = 0; i < ts_resolution; i++) {
                divisor *= 10;
            }
            uint64_t resolution_ns = 1000000000ULL / divisor;
            return timestamp * resolution_ns;
        }
    }
};

/**
 * Packet metadata extracted from Enhanced Packet Block options
 */
struct PcapngPacketMetadata {
    std::optional<std::string> comment;
    std::optional<uint32_t> flags;      // Direction and reception type
    std::optional<uint64_t> dropcount;  // Packets dropped since last packet
    std::optional<uint64_t> hash;       // Hash of packet data
    std::optional<uint32_t> verdict;    // Verdict (e.g., from firewall)
    std::optional<uint32_t> queue_id;   // Queue where packet was received

    // Direction flags (from flags field)
    enum Direction { INFO_UNKNOWN = 0, INFO_INBOUND = 1, INFO_OUTBOUND = 2 };

    Direction getDirection() const {
        if (!flags.has_value())
            return INFO_UNKNOWN;
        return static_cast<Direction>(flags.value() & 0x03);
    }

    // Reception type flags
    enum ReceptionType {
        RECEPTION_UNKNOWN = 0,
        RECEPTION_UNICAST = 0x00,
        RECEPTION_MULTICAST = 0x04,
        RECEPTION_BROADCAST = 0x08,
        RECEPTION_PROMISCUOUS = 0x0C
    };

    ReceptionType getReceptionType() const {
        if (!flags.has_value())
            return RECEPTION_UNKNOWN;
        return static_cast<ReceptionType>(flags.value() & 0x0C);
    }
};

/**
 * Name Resolution Record
 */
struct NameResolutionRecord {
    enum RecordType : uint16_t { NRB_RECORD_END = 0, NRB_RECORD_IPV4 = 1, NRB_RECORD_IPV6 = 2 };

    RecordType type;
    std::string address;             // IP address
    std::vector<std::string> names;  // Resolved names
};

/**
 * Interface Statistics
 */
struct InterfaceStatistics {
    uint32_t interface_id = 0;
    uint64_t timestamp = 0;

    std::optional<uint64_t> packets_received;
    std::optional<uint64_t> packets_dropped;
    std::optional<uint64_t> packets_accepted_by_filter;
    std::optional<uint64_t> packets_dropped_by_os;
    std::optional<uint64_t> packets_delivered_to_user;
    std::optional<std::string> comment;
};

/**
 * Section Header Block information
 */
struct SectionHeaderBlock {
    uint32_t byte_order_magic = 0x1A2B3C4D;
    uint16_t major_version = 1;
    uint16_t minor_version = 0;
    int64_t section_length = -1;  // -1 means unspecified

    std::optional<std::string> hardware;
    std::optional<std::string> os;
    std::optional<std::string> user_application;
    std::optional<std::string> comment;
};

/**
 * PCAPNG Reader - Advanced reader for PCAPNG files with full block support
 */
class PcapngReader {
public:
    PcapngReader();
    ~PcapngReader();

    /**
     * Open a PCAPNG file for reading
     * @param filename Path to PCAPNG file
     * @return true on success
     */
    bool open(const std::string& filename);

    /**
     * Close the PCAPNG file
     */
    void close();

    /**
     * Check if a file is currently open
     */
    bool isOpen() const { return is_open_; }

    /**
     * Read next block from file
     * @return true if block was read, false on EOF or error
     */
    bool readNextBlock();

    /**
     * Get current block type
     */
    PcapngBlockType getCurrentBlockType() const { return current_block_type_; }

    /**
     * Get section header information
     */
    const SectionHeaderBlock& getSectionHeader() const { return section_header_; }

    /**
     * Get all interfaces defined in the file
     */
    const std::vector<PcapngInterface>& getInterfaces() const { return interfaces_; }

    /**
     * Get specific interface by ID
     */
    const PcapngInterface* getInterface(uint32_t interface_id) const {
        if (interface_id < interfaces_.size()) {
            return &interfaces_[interface_id];
        }
        return nullptr;
    }

    /**
     * Get name resolution records
     */
    const std::vector<NameResolutionRecord>& getNameResolutionRecords() const {
        return name_resolution_records_;
    }

    /**
     * Get interface statistics
     */
    const std::vector<InterfaceStatistics>& getInterfaceStatistics() const {
        return interface_statistics_;
    }

    /**
     * Read enhanced packet block
     * @param interface_id Output: interface on which packet was captured
     * @param timestamp Output: packet timestamp (in nanoseconds)
     * @param packet_data Output: packet data
     * @param original_length Output: original packet length
     * @param metadata Output: packet metadata from options
     * @return true if packet was read successfully
     */
    bool readEnhancedPacket(uint32_t& interface_id, uint64_t& timestamp,
                            std::vector<uint8_t>& packet_data, uint32_t& original_length,
                            PcapngPacketMetadata& metadata);

    /**
     * Packet callback type for batch processing
     */
    using PacketCallback = std::function<void(
        uint32_t interface_id, uint64_t timestamp_ns, const uint8_t* packet_data,
        uint32_t captured_length, uint32_t original_length, const PcapngPacketMetadata& metadata)>;

    /**
     * Process all packets using callback
     * @param callback Function called for each packet
     * @return Number of packets processed
     */
    size_t processPackets(PacketCallback callback);

    /**
     * Get file statistics
     */
    struct Stats {
        size_t total_blocks = 0;
        size_t section_headers = 0;
        size_t interface_descriptions = 0;
        size_t enhanced_packets = 0;
        size_t simple_packets = 0;
        size_t name_resolution_blocks = 0;
        size_t interface_statistics_blocks = 0;
        size_t custom_blocks = 0;
        size_t unknown_blocks = 0;
        size_t bytes_read = 0;
    };

    const Stats& getStats() const { return stats_; }

    /**
     * Validate PCAPNG file format
     * @param filename Path to file to validate
     * @return true if valid PCAPNG file
     */
    static bool validate(const std::string& filename);

private:
    // File I/O
    FILE* file_;
    std::string filename_;
    bool is_open_;
    bool is_little_endian_;  // Byte order from Section Header

    // Current state
    PcapngBlockType current_block_type_;
    std::vector<uint8_t> current_block_data_;

    // File structure
    SectionHeaderBlock section_header_;
    std::vector<PcapngInterface> interfaces_;
    std::vector<NameResolutionRecord> name_resolution_records_;
    std::vector<InterfaceStatistics> interface_statistics_;

    // Statistics
    Stats stats_;

    // Block parsing helpers
    bool readBlockHeader(uint32_t& block_type, uint32_t& block_length);
    bool readBlockData(uint32_t block_length);
    bool parseSectionHeader();
    bool parseInterfaceDescription();
    bool parseEnhancedPacket();
    bool parseNameResolution();
    bool parseInterfaceStatistics();

    // Option parsing
    bool parseOptions(
        const uint8_t* data, size_t length,
        std::function<void(uint16_t code, const uint8_t* value, uint16_t value_length)> callback);

    // Byte order conversion
    uint16_t toHost16(uint16_t value) const;
    uint32_t toHost32(uint32_t value) const;
    uint64_t toHost64(uint64_t value) const;

    // Utility functions
    std::string extractString(const uint8_t* data, size_t length) const;

    // Disable copy
    PcapngReader(const PcapngReader&) = delete;
    PcapngReader& operator=(const PcapngReader&) = delete;
};

}  // namespace callflow
