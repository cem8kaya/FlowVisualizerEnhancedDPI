#include "pcap_ingest/multi_interface_reader.h"
#include "common/utils.h"
#include <arpa/inet.h>
#include <cstring>

namespace callflow {

std::string telecomInterfaceTypeToString(TelecomInterfaceType type) {
    switch (type) {
        case TelecomInterfaceType::UNKNOWN: return "UNKNOWN";
        case TelecomInterfaceType::S1_MME: return "S1-MME";
        case TelecomInterfaceType::S1_U: return "S1-U";
        case TelecomInterfaceType::S11: return "S11";
        case TelecomInterfaceType::S5_S8: return "S5/S8";
        case TelecomInterfaceType::SGI: return "SGi";
        case TelecomInterfaceType::X2: return "X2";
        case TelecomInterfaceType::N2: return "N2";
        case TelecomInterfaceType::N3: return "N3";
        case TelecomInterfaceType::N4: return "N4";
        case TelecomInterfaceType::N6: return "N6";
        case TelecomInterfaceType::DIAMETER: return "DIAMETER";
        case TelecomInterfaceType::GENERIC: return "GENERIC";
        default: return "UNKNOWN";
    }
}

MultiInterfacePcapReader::MultiInterfacePcapReader() {
    stats_ = Stats{};
}

MultiInterfacePcapReader::~MultiInterfacePcapReader() {
    close();
}

bool MultiInterfacePcapReader::open(const std::string& filename) {
    if (!reader_.open(filename)) {
        return false;
    }

    // Initialize interface contexts from PCAPNG interfaces
    const auto& interfaces = reader_.getInterfaces();
    for (const auto& iface : interfaces) {
        InterfaceContext ctx;
        ctx.interface_id = iface.interface_id;
        ctx.pcapng_interface = iface;
        ctx.interface_type = TelecomInterfaceType::UNKNOWN;
        interface_contexts_[iface.interface_id] = ctx;
    }

    stats_.total_interfaces = interfaces.size();
    LOG_INFO("Opened multi-interface PCAP with " << interfaces.size() << " interfaces");

    return true;
}

void MultiInterfacePcapReader::close() {
    reader_.close();
    interface_contexts_.clear();
    stats_ = Stats{};
}

bool MultiInterfacePcapReader::isOpen() const {
    return reader_.isOpen();
}

void MultiInterfacePcapReader::addInterface(uint32_t interface_id, TelecomInterfaceType type) {
    auto it = interface_contexts_.find(interface_id);
    if (it != interface_contexts_.end()) {
        it->second.interface_type = type;
        LOG_INFO("Mapped interface " << interface_id << " to " << telecomInterfaceTypeToString(type));
    } else {
        LOG_WARN("Attempted to add mapping for non-existent interface: " << interface_id);
    }
}

TelecomInterfaceType MultiInterfacePcapReader::getInterfaceType(uint32_t interface_id) const {
    auto it = interface_contexts_.find(interface_id);
    if (it != interface_contexts_.end()) {
        return it->second.interface_type;
    }
    return TelecomInterfaceType::UNKNOWN;
}

void MultiInterfacePcapReader::autoDetectInterfaceTypes() {
    for (auto& [interface_id, ctx] : interface_contexts_) {
        if (ctx.interface_type == TelecomInterfaceType::UNKNOWN) {
            ctx.interface_type = detectInterfaceType(ctx);
            LOG_INFO("Auto-detected interface " << interface_id << " as "
                     << telecomInterfaceTypeToString(ctx.interface_type));
        }
    }
}

TelecomInterfaceType MultiInterfacePcapReader::detectInterfaceType(const InterfaceContext& ctx) const {
    // Heuristic-based detection using protocol counts and observed ports

    // Check for GTP-C (S11, S5/S8 control plane)
    if (ctx.protocol_counts.count(ProtocolType::GTP_C) > 0) {
        // GTP-C typically uses port 2123
        if (ctx.observed_ports.count(2123) > 0) {
            // Could be S11 or S5/S8
            return TelecomInterfaceType::S11;  // Default to S11
        }
    }

    // Check for GTP-U (S1-U, S5/S8 user plane)
    if (ctx.protocol_counts.count(ProtocolType::GTP_U) > 0) {
        // GTP-U typically uses port 2152
        if (ctx.observed_ports.count(2152) > 0) {
            return TelecomInterfaceType::S1_U;
        }
    }

    // Check for SCTP (S1-MME, N2)
    if (ctx.protocol_counts.count(ProtocolType::SCTP) > 0) {
        // SCTP port 36412 is S1-MME
        if (ctx.observed_ports.count(36412) > 0) {
            return TelecomInterfaceType::S1_MME;
        }
        // SCTP port 38412 is N2 (5G)
        if (ctx.observed_ports.count(38412) > 0) {
            return TelecomInterfaceType::N2;
        }
    }

    // Check for Diameter (S6a, S6d, etc.)
    if (ctx.protocol_counts.count(ProtocolType::DIAMETER) > 0) {
        // Diameter typically uses port 3868
        if (ctx.observed_ports.count(3868) > 0) {
            return TelecomInterfaceType::DIAMETER;
        }
    }

    // Check for HTTP/HTTPS (SGi, N6)
    if (ctx.protocol_counts.count(ProtocolType::HTTP) > 0 ||
        ctx.protocol_counts.count(ProtocolType::HTTP2) > 0) {
        // Ports 80, 443 suggest internet-facing interface
        if (ctx.observed_ports.count(80) > 0 || ctx.observed_ports.count(443) > 0) {
            return TelecomInterfaceType::SGI;  // Or N6 for 5G
        }
    }

    // Check for SIP (IMS interface)
    if (ctx.protocol_counts.count(ProtocolType::SIP) > 0) {
        // SIP ports 5060, 5061
        if (ctx.observed_ports.count(5060) > 0 || ctx.observed_ports.count(5061) > 0) {
            return TelecomInterfaceType::GENERIC;  // IMS-related
        }
    }

    // If we have some traffic but can't classify, mark as GENERIC
    if (ctx.packet_count > 0) {
        return TelecomInterfaceType::GENERIC;
    }

    return TelecomInterfaceType::UNKNOWN;
}

size_t MultiInterfacePcapReader::processPackets(PacketCallbackWithContext callback, bool auto_detect) {
    if (!isOpen()) {
        LOG_ERROR("Cannot process packets: file not open");
        return 0;
    }

    if (!callback) {
        LOG_ERROR("Cannot process packets: callback is null");
        return 0;
    }

    size_t packet_count = 0;

    // Process packets using the underlying PCAPNG reader
    reader_.processPackets([this, &callback, &packet_count](
        uint32_t interface_id,
        uint64_t timestamp_ns,
        const uint8_t* packet_data,
        uint32_t captured_length,
        uint32_t original_length,
        const PcapngPacketMetadata& metadata) {

        // Get or create interface context
        auto it = interface_contexts_.find(interface_id);
        if (it == interface_contexts_.end()) {
            // Interface not seen before, create context
            InterfaceContext ctx;
            ctx.interface_id = interface_id;
            ctx.interface_type = TelecomInterfaceType::UNKNOWN;

            const PcapngInterface* iface = reader_.getInterface(interface_id);
            if (iface) {
                ctx.pcapng_interface = *iface;
            }

            interface_contexts_[interface_id] = ctx;
            it = interface_contexts_.find(interface_id);
        }

        InterfaceContext& ctx = it->second;

        // Detect protocol and update statistics
        ProtocolType protocol = detectProtocolFromPacket(packet_data, captured_length);
        updateInterfaceStatistics(ctx, packet_data, captured_length, protocol);

        // Update global statistics
        stats_.total_packets++;
        stats_.total_bytes += captured_length;

        // Call user callback with interface context
        callback(ctx, timestamp_ns, packet_data, captured_length, original_length, metadata);

        packet_count++;
    });

    // Auto-detect interface types if requested
    if (auto_detect) {
        autoDetectInterfaceTypes();
    }

    // Update interface type statistics
    for (const auto& [interface_id, ctx] : interface_contexts_) {
        stats_.packets_per_interface_type[ctx.interface_type] += ctx.packet_count;
    }

    LOG_INFO("Processed " << packet_count << " packets across "
             << interface_contexts_.size() << " interfaces");

    return packet_count;
}

void MultiInterfacePcapReader::updateInterfaceStatistics(InterfaceContext& ctx,
                                                         const uint8_t* packet_data,
                                                         uint32_t captured_length,
                                                         ProtocolType protocol) {
    ctx.packet_count++;
    ctx.byte_count += captured_length;

    if (protocol != ProtocolType::UNKNOWN) {
        ctx.protocol_counts[protocol]++;
    }

    // Extract and store observed ports
    uint16_t src_port, dst_port;
    if (extractPorts(packet_data, captured_length, src_port, dst_port)) {
        ctx.observed_ports.insert(src_port);
        ctx.observed_ports.insert(dst_port);
    }
}

ProtocolType MultiInterfacePcapReader::detectProtocolFromPacket(const uint8_t* packet_data,
                                                                 uint32_t length) const {
    if (length < 14) {
        return ProtocolType::UNKNOWN;  // Too small for Ethernet frame
    }

    // Skip Ethernet header (14 bytes)
    const uint8_t* ip_header = packet_data + 14;
    uint32_t ip_length = length - 14;

    if (ip_length < 20) {
        return ProtocolType::UNKNOWN;  // Too small for IP header
    }

    // Check IP version
    uint8_t ip_version = (ip_header[0] >> 4) & 0x0F;
    if (ip_version != 4 && ip_version != 6) {
        return ProtocolType::UNKNOWN;
    }

    uint8_t protocol;
    const uint8_t* transport_header;
    uint32_t transport_length;

    if (ip_version == 4) {
        // IPv4
        uint8_t ihl = (ip_header[0] & 0x0F) * 4;
        protocol = ip_header[9];
        transport_header = ip_header + ihl;
        transport_length = ip_length - ihl;
    } else {
        // IPv6
        protocol = ip_header[6];
        transport_header = ip_header + 40;
        transport_length = ip_length - 40;
    }

    // Detect transport protocol
    if (protocol == 6) {  // TCP
        // Check for HTTP, HTTP2
        if (transport_length >= 20) {
            uint16_t src_port = ntohs(*reinterpret_cast<const uint16_t*>(transport_header));
            uint16_t dst_port = ntohs(*reinterpret_cast<const uint16_t*>(transport_header + 2));

            if (src_port == 80 || dst_port == 80) {
                return ProtocolType::HTTP;
            }
            if (src_port == 443 || dst_port == 443) {
                return ProtocolType::HTTP2;  // Could be HTTPS/HTTP2
            }
            if (src_port == 3868 || dst_port == 3868) {
                return ProtocolType::DIAMETER;
            }
        }
        return ProtocolType::TCP;
    } else if (protocol == 17) {  // UDP
        if (transport_length >= 8) {
            uint16_t src_port = ntohs(*reinterpret_cast<const uint16_t*>(transport_header));
            uint16_t dst_port = ntohs(*reinterpret_cast<const uint16_t*>(transport_header + 2));

            // GTP-C uses port 2123
            if (src_port == 2123 || dst_port == 2123) {
                return ProtocolType::GTP_C;
            }
            // GTP-U uses port 2152
            if (src_port == 2152 || dst_port == 2152) {
                return ProtocolType::GTP_U;
            }
            // SIP uses ports 5060, 5061
            if (src_port == 5060 || dst_port == 5060 || src_port == 5061 || dst_port == 5061) {
                return ProtocolType::SIP;
            }
            // RTP uses dynamic ports (typically 10000-20000)
            if ((src_port >= 10000 && src_port <= 20000) || (dst_port >= 10000 && dst_port <= 20000)) {
                // Could be RTP, but need deeper inspection
                return ProtocolType::RTP;
            }
            // DNS uses port 53
            if (src_port == 53 || dst_port == 53) {
                return ProtocolType::DNS;
            }
        }
        return ProtocolType::UDP;
    } else if (protocol == 132) {  // SCTP
        if (transport_length >= 12) {
            uint16_t src_port = ntohs(*reinterpret_cast<const uint16_t*>(transport_header));
            uint16_t dst_port = ntohs(*reinterpret_cast<const uint16_t*>(transport_header + 2));

            // S1-MME uses SCTP port 36412
            // N2 uses SCTP port 38412
            if (src_port == 36412 || dst_port == 36412 || src_port == 38412 || dst_port == 38412) {
                return ProtocolType::SCTP;
            }
        }
        return ProtocolType::SCTP;
    }

    return ProtocolType::UNKNOWN;
}

bool MultiInterfacePcapReader::extractPorts(const uint8_t* packet_data, uint32_t length,
                                            uint16_t& src_port, uint16_t& dst_port) const {
    if (length < 14) {
        return false;  // Too small for Ethernet frame
    }

    // Skip Ethernet header (14 bytes)
    const uint8_t* ip_header = packet_data + 14;
    uint32_t ip_length = length - 14;

    if (ip_length < 20) {
        return false;  // Too small for IP header
    }

    // Check IP version
    uint8_t ip_version = (ip_header[0] >> 4) & 0x0F;
    if (ip_version != 4 && ip_version != 6) {
        return false;
    }

    uint8_t protocol;
    const uint8_t* transport_header;
    uint32_t transport_length;

    if (ip_version == 4) {
        // IPv4
        uint8_t ihl = (ip_header[0] & 0x0F) * 4;
        protocol = ip_header[9];
        transport_header = ip_header + ihl;
        transport_length = ip_length - ihl;
    } else {
        // IPv6
        protocol = ip_header[6];
        transport_header = ip_header + 40;
        transport_length = ip_length - 40;
    }

    // Extract ports for TCP, UDP, SCTP
    if ((protocol == 6 || protocol == 17 || protocol == 132) && transport_length >= 4) {
        src_port = ntohs(*reinterpret_cast<const uint16_t*>(transport_header));
        dst_port = ntohs(*reinterpret_cast<const uint16_t*>(transport_header + 2));
        return true;
    }

    return false;
}

}  // namespace callflow
