#pragma once

#include "pcap_ingest/pcapng_reader.h"
#include "common/types.h"
#include <map>
#include <set>
#include <string>
#include <vector>
#include <optional>

namespace callflow {

/**
 * Telecom interface types for mobile networks
 */
enum class TelecomInterfaceType {
    UNKNOWN = 0,
    S1_MME,      // S1-MME (Control plane between eNodeB and MME)
    S1_U,        // S1-U (User plane between eNodeB and S-GW)
    S11,         // S11 (MME to S-GW control plane)
    S5_S8,       // S5/S8 (S-GW to P-GW)
    SGI,         // SGi (P-GW to external PDN)
    X2,          // X2 (eNodeB to eNodeB)
    N2,          // N2 (5G: gNB to AMF)
    N3,          // N3 (5G: gNB to UPF)
    N4,          // N4 (5G: SMF to UPF)
    N6,          // N6 (5G: UPF to Data Network)
    DIAMETER,    // Diameter interfaces (S6a, S6d, etc.)
    GENERIC      // Generic/unclassified interface
};

std::string telecomInterfaceTypeToString(TelecomInterfaceType type);

/**
 * Interface context with telecom-specific metadata
 */
struct InterfaceContext {
    uint32_t interface_id;
    PcapngInterface pcapng_interface;
    TelecomInterfaceType interface_type;

    // Statistics
    uint64_t packet_count = 0;
    uint64_t byte_count = 0;

    // Detected protocols on this interface
    std::map<ProtocolType, uint64_t> protocol_counts;

    // Port ranges detected (for heuristic classification)
    std::set<uint16_t> observed_ports;
};

/**
 * Multi-Interface PCAP Reader
 *
 * Handles PCAPNG files with multiple capture interfaces and correlates
 * them with telecom interface types based on protocol/port heuristics.
 */
class MultiInterfacePcapReader {
public:
    MultiInterfacePcapReader();
    ~MultiInterfacePcapReader();

    /**
     * Open a PCAPNG file
     * @param filename Path to PCAPNG file
     * @return true on success
     */
    bool open(const std::string& filename);

    /**
     * Close the file
     */
    void close();

    /**
     * Check if file is open
     */
    bool isOpen() const;

    /**
     * Add interface with explicit type mapping
     * @param interface_id PCAPNG interface ID
     * @param type Telecom interface type
     */
    void addInterface(uint32_t interface_id, TelecomInterfaceType type);

    /**
     * Get interface type for a given interface ID
     * @param interface_id PCAPNG interface ID
     * @return Telecom interface type (UNKNOWN if not mapped)
     */
    TelecomInterfaceType getInterfaceType(uint32_t interface_id) const;

    /**
     * Auto-detect interface types based on protocol/port heuristics
     * Should be called after reading some packets for analysis
     */
    void autoDetectInterfaceTypes();

    /**
     * Get all interface contexts
     */
    const std::map<uint32_t, InterfaceContext>& getInterfaceContexts() const {
        return interface_contexts_;
    }

    /**
     * Get interface context by ID
     */
    const InterfaceContext* getInterfaceContext(uint32_t interface_id) const {
        auto it = interface_contexts_.find(interface_id);
        return (it != interface_contexts_.end()) ? &it->second : nullptr;
    }

    /**
     * Packet callback with interface context
     */
    using PacketCallbackWithContext = std::function<void(
        const InterfaceContext& interface_ctx,
        uint64_t timestamp_ns,
        const uint8_t* packet_data,
        uint32_t captured_length,
        uint32_t original_length,
        const PcapngPacketMetadata& metadata
    )>;

    /**
     * Process all packets with interface context awareness
     * @param callback Function called for each packet with interface context
     * @param auto_detect Automatically detect interface types during processing
     * @return Number of packets processed
     */
    size_t processPackets(PacketCallbackWithContext callback, bool auto_detect = true);

    /**
     * Get overall statistics
     */
    struct Stats {
        size_t total_interfaces = 0;
        size_t total_packets = 0;
        size_t total_bytes = 0;
        std::map<TelecomInterfaceType, size_t> packets_per_interface_type;
    };

    const Stats& getStats() const { return stats_; }

    /**
     * Get the underlying PCAPNG reader
     */
    PcapngReader& getPcapngReader() { return reader_; }
    const PcapngReader& getPcapngReader() const { return reader_; }

private:
    PcapngReader reader_;
    std::map<uint32_t, InterfaceContext> interface_contexts_;
    Stats stats_;

    // Heuristic detection helpers
    TelecomInterfaceType detectInterfaceType(const InterfaceContext& ctx) const;
    void updateInterfaceStatistics(InterfaceContext& ctx,
                                   const uint8_t* packet_data,
                                   uint32_t captured_length,
                                   ProtocolType protocol);

    // Protocol detection from packet data
    ProtocolType detectProtocolFromPacket(const uint8_t* packet_data, uint32_t length) const;
    bool extractPorts(const uint8_t* packet_data, uint32_t length,
                     uint16_t& src_port, uint16_t& dst_port) const;

    // Disable copy
    MultiInterfacePcapReader(const MultiInterfacePcapReader&) = delete;
    MultiInterfacePcapReader& operator=(const MultiInterfacePcapReader&) = delete;
};

}  // namespace callflow
