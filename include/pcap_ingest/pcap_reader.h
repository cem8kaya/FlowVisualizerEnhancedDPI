#pragma once

#include "common/types.h"
#include "common/logger.h"
#include <pcap/pcap.h>
#include <string>
#include <functional>
#include <memory>

namespace callflow {

/**
 * Callback function type for packet processing
 * Parameters: packet data, packet header, user context
 */
using PacketCallback = std::function<void(const uint8_t*, const struct pcap_pkthdr*, void*)>;

/**
 * PCAP file reader using libpcap
 * Supports streaming processing of PCAP files
 */
class PcapReader {
public:
    PcapReader();
    ~PcapReader();

    /**
     * Open a PCAP file for reading
     * @param filename Path to PCAP file
     * @return true on success
     */
    bool open(const std::string& filename);

    /**
     * Close the PCAP file
     */
    void close();

    /**
     * Check if a file is currently open
     */
    bool isOpen() const;

    /**
     * Get datalink type (e.g., DLT_EN10MB for Ethernet)
     */
    int getDatalinkType() const;

    /**
     * Get snapshot length
     */
    int getSnaplen() const;

    /**
     * Read next packet from file
     * @param header Output parameter for packet header
     * @param data Output parameter for packet data
     * @return true if packet was read, false on EOF or error
     */
    bool readNextPacket(struct pcap_pkthdr& header, const uint8_t*& data);

    /**
     * Process all packets in file using callback
     * @param callback Function to call for each packet
     * @param user_context Optional user context passed to callback
     * @return Number of packets processed
     */
    size_t processPackets(PacketCallback callback, void* user_context = nullptr);

    /**
     * Get statistics about processed packets
     */
    struct Stats {
        size_t packets_processed = 0;
        size_t bytes_processed = 0;
        Timestamp start_time;
        Timestamp end_time;
    };

    const Stats& getStats() const { return stats_; }

    /**
     * Reset statistics
     */
    void resetStats();

private:
    pcap_t* pcap_handle_;
    std::string filename_;
    int datalink_type_;
    int snaplen_;
    Stats stats_;
    bool is_open_;

    // Disable copy
    PcapReader(const PcapReader&) = delete;
    PcapReader& operator=(const PcapReader&) = delete;
};

}  // namespace callflow
