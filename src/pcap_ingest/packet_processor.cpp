#include "pcap_ingest/packet_processor.h"

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "common/logger.h"
#include "common/utils.h"
#include "protocol_parsers/diameter_parser.h"
#include "protocol_parsers/gtp_parser.h"
#include "protocol_parsers/pfcp_parser.h"
#include "protocol_parsers/rtp_parser.h"
#include "protocol_parsers/sip_parser.h"

namespace callflow {

PacketProcessor::PacketProcessor(EnhancedSessionCorrelator& correlator) : correlator_(correlator) {}

void PacketProcessor::processPacket(const uint8_t* data, size_t len, Timestamp ts,
                                    uint32_t frame_number, int dlt) {
    uint16_t eth_type = 0;
    int offset = link_parser_.parse(data, len, dlt, eth_type);

    if (offset < 0) {
        // unsupported L2 or error
        return;
    }

    if (static_cast<size_t>(offset) >= len)
        return;

    // Check EtherType to ensure it is IP
    // Common EtherTypes: 0x0800 (IPv4), 0x86DD (IPv6)
    if (eth_type != 0x0800 && eth_type != 0x86DD) {
        // Non-IP packet (ARP, etc.), ignore
        return;
    }

    // Pass to IP Reassembler
    // Note: LinkLayerParser returns offset to IP header.
    auto reassembled_opt = ip_reassembler_.processPacket(data + offset, len - offset);

    if (reassembled_opt.has_value()) {
        processIpPacket(reassembled_opt.value(), ts, frame_number);
    }
}

void PacketProcessor::processIpPacket(const std::vector<uint8_t>& ip_packet, Timestamp ts,
                                      uint32_t frame_number) {
    if (ip_packet.empty())
        return;

    PacketMetadata metadata;
    metadata.packet_id = utils::generateUuid();
    metadata.timestamp = ts;
    metadata.frame_number = frame_number;
    metadata.packet_length = ip_packet.size();  // Approximate "captured length"
    // Note: metadata.packet_length usually refers to wire length, here it's reassembled length.

    const uint8_t* ip_data = ip_packet.data();
    size_t len = ip_packet.size();

    uint8_t version = (ip_data[0] >> 4) & 0x0F;
    uint8_t protocol = 0;
    const uint8_t* trans_data = nullptr;
    size_t trans_len = 0;

    if (version == 4) {
        if (len < sizeof(struct ip))
            return;
        const struct ip* header = reinterpret_cast<const struct ip*>(ip_data);
        size_t hlen = header->ip_hl * 4;
        if (len < hlen)
            return;

        char src_str[INET_ADDRSTRLEN];
        char dst_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(header->ip_src), src_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(header->ip_dst), dst_str, INET_ADDRSTRLEN);

        metadata.five_tuple.src_ip = src_str;
        metadata.five_tuple.dst_ip = dst_str;
        metadata.five_tuple.protocol = header->ip_p;
        protocol = header->ip_p;

        trans_data = ip_data + hlen;
        trans_len = len - hlen;

    } else if (version == 6) {
        if (len < 40)
            return;
        const struct ip6_hdr* header = reinterpret_cast<const struct ip6_hdr*>(ip_data);

        char src_str[INET6_ADDRSTRLEN];
        char dst_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(header->ip6_src), src_str, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(header->ip6_dst), dst_str, INET6_ADDRSTRLEN);

        metadata.five_tuple.src_ip = src_str;
        metadata.five_tuple.dst_ip = dst_str;
        metadata.five_tuple.protocol =
            header->ip6_nxt;         // Limitation: doesn't skip ext headers here
        protocol = header->ip6_nxt;  // TODO: skip extension headers logic again?
        // IpReassembler already handled fragments, but could be other headers.
        // Assuming standard NextHeader for now.

        trans_data = ip_data + 40;
        trans_len = len - 40;
    } else {
        return;
    }

    if (!trans_data)
        return;

    // Parse Transport
    if (protocol == IPPROTO_UDP) {
        if (trans_len < 8)
            return;
        const struct udphdr* udp = reinterpret_cast<const struct udphdr*>(trans_data);
        metadata.five_tuple.src_port = ntohs(udp->uh_sport);
        metadata.five_tuple.dst_port = ntohs(udp->uh_dport);

        // Payload
        if (trans_len > 8) {
            std::vector<uint8_t> payload(trans_data + 8, trans_data + trans_len);
            metadata.raw_data = payload;

            // UDP Payload dispatch
            processTransportAndPayload(metadata, payload);
        }

    } else if (protocol == IPPROTO_TCP) {
        if (trans_len < 20)
            return;
        const struct tcphdr* tcp = reinterpret_cast<const struct tcphdr*>(trans_data);
        metadata.five_tuple.src_port = ntohs(tcp->th_sport);
        metadata.five_tuple.dst_port = ntohs(tcp->th_dport);

        size_t tcp_hlen = tcp->th_off * 4;
        if (trans_len < tcp_hlen)
            return;

        std::vector<uint8_t> payload;
        if (trans_len > tcp_hlen) {
            payload.assign(trans_data + tcp_hlen, trans_data + trans_len);
        }

        // Reassemble TCP
        uint32_t seq = ntohl(tcp->th_seq);
        bool is_syn = (tcp->th_flags & TH_SYN);
        bool is_fin = (tcp->th_flags & TH_FIN);

        auto reassembled =
            tcp_reassembler_.processSegment(metadata.five_tuple, seq, payload, is_syn, is_fin);

        if (!reassembled.empty()) {
            metadata.raw_data = reassembled;
            processTransportAndPayload(metadata, reassembled);
        }
    } else if (protocol == 132) {  // SCTP
        // Simple SCTP parsing (ports at +0 and +2)
        if (trans_len >= 12) {
            metadata.five_tuple.src_port = ntohs(*reinterpret_cast<const uint16_t*>(trans_data));
            metadata.five_tuple.dst_port =
                ntohs(*reinterpret_cast<const uint16_t*>(trans_data + 2));

            // TODO: SCTP payload extraction logic (chunks)
            // Ideally extract the DATA chunk payload.
            // For now, pass whole SCTP packet?
            // Actually existing logic in `main.cpp` just ignored SCTP payload or treated it
            // vaguely. We'll leave SCTP payload processing for future, or just pass as is.
        }
    }
}

void PacketProcessor::processTransportAndPayload(const PacketMetadata& metadata,
                                                 const std::vector<uint8_t>& payload) {
    // Protocol Detection and Parsing logic from JobManager/main.cpp

    // PFCP (UDP 8805)
    if (metadata.five_tuple.protocol == IPPROTO_UDP &&
        (metadata.five_tuple.src_port == 8805 || metadata.five_tuple.dst_port == 8805)) {
        PfcpParser parser;
        auto msg = parser.parse(payload.data(), payload.size());
        if (msg.has_value()) {
            correlator_.processPacket(metadata, ProtocolType::PFCP, msg->toJson());
            return;
        }
    }

    // GTP-C (UDP 2123)
    if (metadata.five_tuple.protocol == IPPROTO_UDP &&
        (metadata.five_tuple.src_port == 2123 || metadata.five_tuple.dst_port == 2123)) {
        GtpParser parser;
        auto msg = parser.parse(payload.data(), payload.size());
        if (msg.has_value()) {
            correlator_.processPacket(metadata, ProtocolType::GTP_C, msg->toJson());
            return;
        }
    }

    // GTP-U (UDP 2152) -> Tunnels.
    // Inner packet parsing is needed for GTP-U (Recursive?)
    // Existing logic just identified GTP-U but didn't parse inner fully/recursively in `main.cpp`.

    // Diameter (TCP/UDP 3868)
    if (metadata.five_tuple.src_port == 3868 || metadata.five_tuple.dst_port == 3868) {
        DiameterParser parser;
        auto msg = parser.parse(payload.data(), payload.size());
        if (msg.has_value()) {
            correlator_.processPacket(metadata, ProtocolType::DIAMETER, msg->toJson());
            return;
        }
    }

    // SIP (UDP/TCP 5060, 5061)
    if (metadata.five_tuple.src_port == 5060 || metadata.five_tuple.dst_port == 5060 ||
        metadata.five_tuple.src_port == 5061 || metadata.five_tuple.dst_port == 5061) {
        SipParser parser;
        auto msg = parser.parse(payload.data(), payload.size());
        if (msg.has_value()) {
            correlator_.processPacket(metadata, ProtocolType::SIP, msg->toJson());
            return;
        }
    }

    // RTP
    if (metadata.five_tuple.protocol == IPPROTO_UDP &&
        ((metadata.five_tuple.src_port >= 10000 && metadata.five_tuple.src_port % 2 == 0) ||
         (metadata.five_tuple.dst_port >= 10000 && metadata.five_tuple.dst_port % 2 == 0))) {
        RtpParser parser;
        auto header = parser.parseRtp(payload.data(), payload.size());
        if (header.has_value()) {
            correlator_.processPacket(metadata, ProtocolType::RTP, header->toJson());
            return;
        }
    }

    // HTTP/2 (Usually TCP 80, 8080, etc., but we need H2 parser)
    // TODO: Integrate Http2Parser
}

}  // namespace callflow
