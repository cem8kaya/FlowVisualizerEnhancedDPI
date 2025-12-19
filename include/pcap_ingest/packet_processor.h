#pragma once

#include <pcap/pcap.h>  // for pcap_pkthdr

#include "common/types.h"
#include "pcap_ingest/ip_reassembler.h"
#include "pcap_ingest/link_layer_parser.h"
#include "pcap_ingest/tcp_reassembler.h"
#include "session/session_correlator.h"  // Assuming this is where Correlator is

namespace callflow {

/**
 * Orchestrates packet processing:
 * 1. Link Layer Stripping
 * 2. IP Defragmentation
 * 3. TCP Reassembly
 * 4. Protocol Parsing (via EnhancedSessionCorrelator handling)
 */
class PacketProcessor {
public:
    PacketProcessor(EnhancedSessionCorrelator& correlator);

    /**
     * Process a raw packet from PCAP/PCAPNG
     * @param data Raw packet data (including Link Header)
     * @param len Packet length
     * @param ts Packet timestamp (std::chrono)
     * @param frame_number Frame number
     * @param dlt Data Link Type
     */
    void processPacket(const uint8_t* data, size_t len, Timestamp ts, uint32_t frame_number,
                       int dlt);

private:
    EnhancedSessionCorrelator& correlator_;
    LinkLayerParser link_parser_;
    IpReassembler ip_reassembler_;
    TcpReassembler tcp_reassembler_;

    void processIpPacket(const std::vector<uint8_t>& ip_packet, Timestamp ts,
                         uint32_t frame_number);
    void processTransportAndPayload(const PacketMetadata& metadata,
                                    const std::vector<uint8_t>& payload);
};

}  // namespace callflow
