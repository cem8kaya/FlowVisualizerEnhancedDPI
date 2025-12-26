#include "pcap_ingest/packet_processor.h"

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "common/logger.h"
#include "common/utils.h"
#include "ndpi_engine/protocol_detector.h"
#include "protocol_parsers/diameter_parser.h"
#include "protocol_parsers/gtp_parser.h"
#include "protocol_parsers/gtpv1_parser.h"
#include "protocol_parsers/nas5g_parser.h"
#include "protocol_parsers/nas_parser.h"
#include "protocol_parsers/ngap_parser.h"
#include "protocol_parsers/pfcp_parser.h"
#include "protocol_parsers/rtp_parser.h"
#include "protocol_parsers/s1ap/s1ap_parser.h"
#include "protocol_parsers/sip_parser.h"

namespace callflow {

PacketProcessor::PacketProcessor(EnhancedSessionCorrelator& correlator) : correlator_(correlator) {
    // Set up SCTP message callback for reassembled messages
    sctp_parser_.setMessageCallback([this](const SctpReassembledMessage& message) {
        // Create temporary metadata for SCTP message
        // Note: We need to pass proper metadata through the callback in production
        PacketMetadata metadata;
        metadata.packet_id = utils::generateUuid();
        metadata.timestamp = std::chrono::system_clock::now();
        metadata.detected_protocol = ProtocolType::SCTP;

        // Process the reassembled message
        this->processSctpMessage(message, metadata);
    });
}

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
                                      uint32_t frame_number, int recursion_depth) {
    // Prevent infinite recursion (tunnel loops)
    if (recursion_depth > 5) {
        LOG_WARN("Max recursion depth reached for packet " << frame_number);
        return;
    }
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
            processTransportAndPayload(metadata, payload, recursion_depth);
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
            processTransportAndPayload(metadata, reassembled, recursion_depth);
        }
    } else if (protocol == 132) {  // SCTP
        // Full SCTP parsing with reassembly and PPID routing
        if (trans_len < 12) {
            return;  // Invalid SCTP packet
        }

        // Extract ports from SCTP common header
        metadata.five_tuple.src_port = ntohs(*reinterpret_cast<const uint16_t*>(trans_data));
        metadata.five_tuple.dst_port = ntohs(*reinterpret_cast<const uint16_t*>(trans_data + 2));

        // Parse SCTP packet with full reassembly support
        auto sctp_packet_opt = sctp_parser_.parse(trans_data, trans_len, metadata.five_tuple);

        if (sctp_packet_opt.has_value()) {
            // Update metadata with SCTP protocol
            metadata.detected_protocol = ProtocolType::SCTP;
            metadata.raw_data.assign(trans_data, trans_data + trans_len);

            // Log association state changes
            auto assoc_ids = sctp_parser_.getAssociationIds();
            for (auto assoc_id : assoc_ids) {
                auto assoc_opt = sctp_parser_.getAssociation(assoc_id);
                if (assoc_opt.has_value()) {
                    const auto& assoc = assoc_opt.value();
                    LOG_DEBUG("SCTP association "
                              << assoc_id << " state: " << static_cast<int>(assoc.state)
                              << " streams: " << assoc.num_outbound_streams << "/"
                              << assoc.num_inbound_streams);
                }
            }

            // Note: Reassembled messages are delivered via callback set in constructor
            // See PacketProcessor constructor for callback setup
        }
    }
}

void PacketProcessor::processTransportAndPayload(const PacketMetadata& metadata,
                                                 const std::vector<uint8_t>& payload,
                                                 int recursion_depth) {
    // Protocol Detection Strategy:
    // 1. PRIORITY: Content-based SIP detection for ALL TCP/UDP (catches non-standard ports)
    // 2. Port-based detection for other protocols (fast path)
    // 3. Content-based fallback for remaining protocols
    //
    // IMS/VoLTE uses ports: 5060, 5061, 5063, 5064, 6101, 7100, 7200, and many others

    bool detected_by_port = false;
    ProtocolType detected_protocol = ProtocolType::UNKNOWN;

    // ====================================================================
    // PRIORITY: Content-based SIP detection for ALL TCP/UDP traffic
    // This catches SIP on non-standard ports (IMS, enterprise, etc.)
    // ====================================================================
    if ((metadata.five_tuple.protocol == IPPROTO_TCP ||
         metadata.five_tuple.protocol == IPPROTO_UDP) &&
        payload.size() >= 12) {
        if (ProtocolDetector::isSipPayload(payload.data(), payload.size())) {
            LOG_DEBUG("Content-based SIP detection: port " << metadata.five_tuple.src_port << "->"
                                                           << metadata.five_tuple.dst_port);

            // Register non-standard SIP ports for future fast-path detection
            sip_port_tracker_.registerSipPort(metadata.five_tuple.src_port);
            sip_port_tracker_.registerSipPort(metadata.five_tuple.dst_port);

            if (metadata.five_tuple.protocol == IPPROTO_TCP) {
                // TCP SIP - use existing TCP session handling with message boundary detection
                auto& buffer = sip_tcp_buffers_[metadata.five_tuple];
                buffer.appendData(payload.data(), payload.size());

                auto messages = buffer.extractCompleteMessages();
                for (const auto& msg_data : messages) {
                    SipParser parser;
                    auto sip_msg = parser.parse(msg_data.data(), msg_data.size());
                    if (sip_msg.has_value()) {
                        correlator_.processSipMessage(sip_msg.value(), metadata);
                    }
                }

                // Overflow protection
                if (buffer.getBufferSize() > SipTcpStreamBuffer::MAX_BUFFER_SIZE) {
                    LOG_WARN("SIP TCP buffer overflow, resetting");
                    buffer.reset();
                }
            } else {
                // UDP SIP - parse directly
                SipParser parser;
                auto msg = parser.parse(payload.data(), payload.size());
                if (msg.has_value()) {
                    correlator_.processSipMessage(msg.value(), metadata);
                }
            }
            return;
        }
    }

    // PFCP (UDP 8805)
    if (metadata.five_tuple.protocol == IPPROTO_UDP &&
        (metadata.five_tuple.src_port == 8805 || metadata.five_tuple.dst_port == 8805)) {
        detected_by_port = true;
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

    // GTP-U (UDP 2152) - User plane tunneling (GTPv1)
    // Handles SIP/signaling encapsulated in GTP-U tunnels (IMS over LTE/5G)
    if (metadata.five_tuple.protocol == IPPROTO_UDP &&
        (metadata.five_tuple.src_port == 2152 || metadata.five_tuple.dst_port == 2152)) {
        GtpV1Parser parser;
        auto msg = parser.parse(payload.data(), payload.size());
        if (msg.has_value()) {
            // Process the GTP-U packet itself
            correlator_.processPacket(metadata, ProtocolType::GTP_U, msg->toJson());

            // Process inner payload with proper 5-tuple extraction
            if (!msg->user_data.empty() && msg->user_data.size() >= 20) {
                const uint8_t* inner_ip = msg->user_data.data();
                size_t inner_len = msg->user_data.size();
                uint8_t ip_version = (inner_ip[0] >> 4) & 0x0F;

                // Create NEW metadata for inner packet with GTP context
                PacketMetadata inner_metadata;
                inner_metadata.packet_id = utils::generateUuid();
                inner_metadata.timestamp = metadata.timestamp;
                inner_metadata.frame_number = metadata.frame_number;
                inner_metadata.interface_id = metadata.interface_id;
                inner_metadata.gtp_teid = msg->header.teid;
                inner_metadata.is_gtp_encapsulated = true;
                inner_metadata.packet_length = inner_len;

                bool valid_inner = false;

                if (ip_version == 4 && inner_len >= 20) {
                    // IPv4 inner packet
                    const struct ip* iph = reinterpret_cast<const struct ip*>(inner_ip);
                    char src_str[INET_ADDRSTRLEN];
                    char dst_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &(iph->ip_src), src_str, INET_ADDRSTRLEN);
                    inet_ntop(AF_INET, &(iph->ip_dst), dst_str, INET_ADDRSTRLEN);

                    inner_metadata.five_tuple.src_ip = src_str;
                    inner_metadata.five_tuple.dst_ip = dst_str;
                    inner_metadata.five_tuple.protocol = iph->ip_p;

                    size_t ip_hdr_len = iph->ip_hl * 4;
                    if (inner_len > ip_hdr_len + 4) {
                        const uint8_t* trans = inner_ip + ip_hdr_len;
                        if (iph->ip_p == IPPROTO_TCP || iph->ip_p == IPPROTO_UDP) {
                            inner_metadata.five_tuple.src_port =
                                ntohs(*reinterpret_cast<const uint16_t*>(trans));
                            inner_metadata.five_tuple.dst_port =
                                ntohs(*reinterpret_cast<const uint16_t*>(trans + 2));
                        }
                        valid_inner = true;
                    }
                } else if (ip_version == 6 && inner_len >= 40) {
                    // IPv6 inner packet
                    const struct ip6_hdr* ip6h = reinterpret_cast<const struct ip6_hdr*>(inner_ip);
                    char src_str[INET6_ADDRSTRLEN];
                    char dst_str[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, &(ip6h->ip6_src), src_str, INET6_ADDRSTRLEN);
                    inet_ntop(AF_INET6, &(ip6h->ip6_dst), dst_str, INET6_ADDRSTRLEN);

                    inner_metadata.five_tuple.src_ip = src_str;
                    inner_metadata.five_tuple.dst_ip = dst_str;
                    inner_metadata.five_tuple.protocol = ip6h->ip6_nxt;

                    if (inner_len > 40 + 4) {
                        const uint8_t* trans = inner_ip + 40;
                        if (ip6h->ip6_nxt == IPPROTO_TCP || ip6h->ip6_nxt == IPPROTO_UDP) {
                            inner_metadata.five_tuple.src_port =
                                ntohs(*reinterpret_cast<const uint16_t*>(trans));
                            inner_metadata.five_tuple.dst_port =
                                ntohs(*reinterpret_cast<const uint16_t*>(trans + 2));
                        }
                        valid_inner = true;
                    }
                }

                if (valid_inner) {
                    LOG_DEBUG("GTP-U inner packet: TEID=" << msg->header.teid << " inner 5-tuple: "
                                                          << inner_metadata.five_tuple.src_ip << ":"
                                                          << inner_metadata.five_tuple.src_port
                                                          << " -> "
                                                          << inner_metadata.five_tuple.dst_ip << ":"
                                                          << inner_metadata.five_tuple.dst_port);

                    // Process inner IP packet with correct metadata
                    processIpPacket(msg->user_data, metadata.timestamp, metadata.frame_number,
                                    recursion_depth + 1);
                } else {
                    // Fallback to basic processing if parsing fails
                    processIpPacket(msg->user_data, metadata.timestamp, metadata.frame_number,
                                    recursion_depth + 1);
                }
            }
            return;
        }
    }

    // Diameter (TCP/UDP 3868)
    if (metadata.five_tuple.src_port == 3868 || metadata.five_tuple.dst_port == 3868) {
        if (metadata.five_tuple.protocol == IPPROTO_TCP) {
            auto& session = diameter_sessions_[metadata.five_tuple];
            session.buffer.insert(session.buffer.end(), payload.begin(), payload.end());

            while (session.buffer.size() >= 4) {
                // Diameter Header: Version(1) + Message Length(3)
                uint32_t msg_length =
                    (session.buffer[1] << 16) | (session.buffer[2] << 8) | session.buffer[3];

                if (session.buffer.size() >= msg_length) {
                    DiameterParser parser;
                    auto msg = parser.parse(session.buffer.data(), msg_length);
                    if (msg.has_value()) {
                        correlator_.processPacket(metadata, ProtocolType::DIAMETER, msg->toJson());
                    }
                    session.buffer.erase(session.buffer.begin(),
                                         session.buffer.begin() + msg_length);
                } else {
                    break;  // Wait for more data
                }
            }
        } else {
            // UDP
            DiameterParser parser;
            auto msg = parser.parse(payload.data(), payload.size());
            if (msg.has_value()) {
                correlator_.processPacket(metadata, ProtocolType::DIAMETER, msg->toJson());
            }
        }
        return;
    }

    // SIP (UDP/TCP) - Enhanced with dynamic port tracking and message boundary detection
    if (sip_port_tracker_.isSipPort(metadata.five_tuple.src_port) ||
        sip_port_tracker_.isSipPort(metadata.five_tuple.dst_port)) {
        if (metadata.five_tuple.protocol == IPPROTO_TCP) {
            // Enhanced TCP reassembly with SipTcpStreamBuffer
            auto& buffer = sip_tcp_buffers_[metadata.five_tuple];
            buffer.appendData(payload.data(), payload.size());

            // Extract all complete messages
            auto messages = buffer.extractCompleteMessages();
            for (const auto& msg_data : messages) {
                SipParser parser;
                auto sip_msg = parser.parse(msg_data.data(), msg_data.size());
                if (sip_msg.has_value()) {
                    correlator_.processSipMessage(sip_msg.value(), metadata);
                }
            }

            // Cleanup if buffer too large (overflow protection)
            if (buffer.getBufferSize() > SipTcpStreamBuffer::MAX_BUFFER_SIZE) {
                LOG_WARN("SIP TCP buffer overflow, resetting for "
                         << metadata.five_tuple.src_ip << ":" << metadata.five_tuple.src_port
                         << " -> " << metadata.five_tuple.dst_ip << ":"
                         << metadata.five_tuple.dst_port);
                buffer.reset();
            }
        } else {
            // UDP - Enhanced with fragmentation validation
            // Check for minimum SIP message size
            if (payload.size() < 10) {
                LOG_DEBUG("SIP payload too small, likely incomplete: " << payload.size());
                return;
            }

            // Validate SIP message structure before parsing
            if (!SipParser::isSipMessage(payload.data(), payload.size())) {
                LOG_DEBUG("Invalid SIP message structure, possibly incomplete fragmentation");
                return;
            }

            SipParser parser;
            auto msg = parser.parse(payload.data(), payload.size());
            if (msg.has_value()) {
                correlator_.processSipMessage(msg.value(), metadata);
            }
        }
        return;
    }

    // RTP - Check both port-based heuristics and dynamic port tracker
    if (metadata.five_tuple.protocol == IPPROTO_UDP) {
        bool is_rtp_candidate = false;

        // Check traditional port-based heuristic
        if ((metadata.five_tuple.src_port >= 10000 && metadata.five_tuple.src_port % 2 == 0) ||
            (metadata.five_tuple.dst_port >= 10000 && metadata.five_tuple.dst_port % 2 == 0)) {
            is_rtp_candidate = true;
        }

        // Check dynamic port tracker (ports learned from SDP)
        if (!is_rtp_candidate &&
            (dynamic_port_tracker_.isKnownRtpPort(metadata.five_tuple.src_port) ||
             dynamic_port_tracker_.isKnownRtpPort(metadata.five_tuple.dst_port))) {
            is_rtp_candidate = true;
            LOG_DEBUG("RTP port matched via dynamic port tracker: src="
                      << metadata.five_tuple.src_port << " dst=" << metadata.five_tuple.dst_port);
        }

        if (is_rtp_candidate) {
            RtpParser parser;
            auto header = parser.parseRtp(payload.data(), payload.size());
            if (header.has_value()) {
                correlator_.processPacket(metadata, ProtocolType::RTP, header->toJson());
                return;
            }
        }
    }

    // ============================================================================
    // Content-Based Detection Fallback
    // ============================================================================
    // If we haven't detected a protocol yet using port-based heuristics,
    // try content-based detection by inspecting the payload
    if (!detected_by_port && !payload.empty()) {
        auto content_detected = ProtocolDetector::detectFromPayload(
            payload.data(), payload.size(), metadata.five_tuple.src_port,
            metadata.five_tuple.dst_port, metadata.five_tuple.protocol);

        if (content_detected.has_value()) {
            detected_protocol = content_detected.value();
            LOG_INFO("Content-based protocol detection succeeded: "
                     << protocolTypeToString(detected_protocol)
                     << " (src_port=" << metadata.five_tuple.src_port
                     << " dst_port=" << metadata.five_tuple.dst_port << ")");

            // Route to appropriate parser based on detected protocol
            switch (detected_protocol) {
                case ProtocolType::SIP: {
                    // Validate message completeness before parsing
                    if (payload.size() >= 10 &&
                        SipParser::isSipMessage(payload.data(), payload.size())) {
                        // Register non-standard SIP ports for future fast-path detection
                        sip_port_tracker_.registerSipPort(metadata.five_tuple.src_port);
                        sip_port_tracker_.registerSipPort(metadata.five_tuple.dst_port);

                        SipParser parser;
                        auto msg = parser.parse(payload.data(), payload.size());
                        if (msg.has_value()) {
                            correlator_.processSipMessage(msg.value(), metadata);
                            return;
                        }
                    } else {
                        LOG_DEBUG("SIP detected but message incomplete or invalid");
                    }
                    break;
                }

                case ProtocolType::DIAMETER: {
                    DiameterParser parser;
                    auto msg = parser.parse(payload.data(), payload.size());
                    if (msg.has_value()) {
                        correlator_.processPacket(metadata, ProtocolType::DIAMETER, msg->toJson());
                        return;
                    }
                    break;
                }

                case ProtocolType::GTP_C: {
                    GtpParser parser;
                    auto msg = parser.parse(payload.data(), payload.size());
                    if (msg.has_value()) {
                        correlator_.processPacket(metadata, ProtocolType::GTP_C, msg->toJson());
                        return;
                    }
                    break;
                }

                case ProtocolType::GTP_U: {
                    GtpV1Parser parser;
                    auto msg = parser.parse(payload.data(), payload.size());
                    if (msg.has_value()) {
                        correlator_.processPacket(metadata, ProtocolType::GTP_U, msg->toJson());

                        // Recursive processing for inner payload
                        if (!msg->user_data.empty()) {
                            processIpPacket(msg->user_data, metadata.timestamp,
                                            metadata.frame_number, recursion_depth + 1);
                        }
                        return;
                    }
                    break;
                }

                case ProtocolType::RTP: {
                    RtpParser parser;
                    auto header = parser.parseRtp(payload.data(), payload.size());
                    if (header.has_value()) {
                        correlator_.processPacket(metadata, ProtocolType::RTP, header->toJson());
                        return;
                    }
                    break;
                }

                default:
                    LOG_DEBUG("Content-based detection returned "
                              << protocolTypeToString(detected_protocol)
                              << " but no parser available");
                    break;
            }
        }
    }

    // HTTP/2 (Usually TCP 80, 8080, etc., but we need H2 parser)

    // HTTP/2 (80, 8000, 8080, 5000-6000 for SBA)
    // 5G SBA typically uses ports like 80 (HTTP) or specific allocated ports.
    // We'll check for HTTP/2 Preface or common ports.
    bool possibly_http2 = false;
    if (metadata.five_tuple.protocol == IPPROTO_TCP) {
        uint16_t port = metadata.five_tuple.dst_port;
        uint16_t src_port = metadata.five_tuple.src_port;
        if (port == 80 || port == 8080 || port == 8000 || (port >= 2000 && port <= 10000) ||
            src_port == 80 || src_port == 8080 || src_port == 8000 ||
            (src_port >= 2000 && src_port <= 10000)) {
            possibly_http2 = true;
        }
    }

    if (possibly_http2) {
        // Get session state
        auto& connection = http2_sessions_[metadata.five_tuple];

        // Append new data to connection buffer
        connection.buffer.insert(connection.buffer.end(), payload.begin(), payload.end());

        size_t processed_offset = 0;
        bool progress = true;

        while (progress && processed_offset < connection.buffer.size()) {
            progress = false;
            size_t remaining = connection.buffer.size() - processed_offset;
            const uint8_t* data_ptr = connection.buffer.data() + processed_offset;

            // Check for Preface first if not established
            if (!connection.preface_received) {
                if (Http2Parser::isHttp2(data_ptr, remaining)) {
                    connection.preface_received = true;
                    // Skip preface length (24 bytes)
                    processed_offset += 24;
                    progress = true;
                    continue;
                } else {
                    // If buffer has < 24 bytes, wait for more. If > 24 and not Match, probably not
                    // HTTP2. But we only set progress=true if we consumed something. For now,
                    // strict check.
                    if (remaining >= 24) {
                        // Not HTTP2 preface, stop trying for this connection?
                        // Or might be mid-stream if we missed start?
                        // Let's assume we might have missed start if packet loss.
                        // But robust parser is hard. Assume start of flow.
                    }
                    break;
                }
            }

            // Parse Frame
            auto frame_opt = http2_parser_.parseFrame(data_ptr, remaining);
            if (frame_opt) {
                // Successfully parsed a frame
                http2_parser_.processFrame(*frame_opt, connection);

                // Advance offset
                // Frame size = 9 (header) + payload length
                size_t frame_total_len = 9 + frame_opt->header.length;
                processed_offset += frame_total_len;
                progress = true;
            }
        }

        // Remove processed data from buffer
        if (processed_offset > 0) {
            connection.buffer.erase(connection.buffer.begin(),
                                    connection.buffer.begin() + processed_offset);
        }

        // Check for completed streams and analyze
        auto it = connection.streams.begin();
        while (it != connection.streams.end()) {
            auto& stream = it->second;

            // If we have a full request-response cycle
            if (stream.response_complete) {
                // Check for 5G SBA (using correct parser instance)
                auto sba_event = sba_parser_.parse(stream);
                if (sba_event) {
                    correlator_.processPacket(metadata, ProtocolType::HTTP2, sba_event->toJson());

                    // Cleanup stream
                    it = connection.streams.erase(it);
                    continue;
                }
            }
            ++it;
        }
    }

    // NGAP parsing is now handled via SCTP PPID routing (see processSctpMessage)
    // Keep legacy fallback for non-SCTP NGAP (if it exists)
    if (metadata.five_tuple.protocol != 132 &&
        (metadata.five_tuple.src_port == 38412 || metadata.five_tuple.dst_port == 38412)) {
        // Try parsing as NGAP
        NgapParser ngap_parser;
        // Check heuristics first to avoid spamming logs
        if (NgapParser::isNgap(payload.data(), payload.size())) {
            auto msg_opt = ngap_parser.parse(payload.data(), payload.size());
            if (msg_opt.has_value()) {
                auto& msg = msg_opt.value();
                auto json = msg.toJson();

                // Check for NAS PDU
                if (msg.nas_pdu.has_value()) {
                    Nas5gParser nas_parser;
                    const auto& nas_data = msg.nas_pdu.value();

                    auto nas_msg_opt = nas_parser.parse(nas_data.data(), nas_data.size(), nullptr);
                    if (nas_msg_opt.has_value()) {
                        json["nas_5g"] = nas_msg_opt->toJson();
                    }
                }

                correlator_.processPacket(metadata, ProtocolType::NGAP, json);
                return;
            }
        }
    }
}

void PacketProcessor::processSctpMessage(const SctpReassembledMessage& message,
                                         const PacketMetadata& metadata) {
    LOG_DEBUG("Processing SCTP message: stream_id="
              << message.stream_id << " ssn=" << message.stream_sequence
              << " ppid=" << message.payload_protocol << " ("
              << getSctpPpidName(message.payload_protocol) << ")"
              << " length=" << message.data.size());

    // Route based on PPID (Payload Protocol Identifier)
    switch (message.payload_protocol) {
        case 0: {  // Unstructured data - could be SIP
            LOG_DEBUG("SCTP PPID 0 (unstructured) - attempting SIP detection");

            // Try SIP detection
            if (message.data.size() >= 10 &&
                SipParser::isSipMessage(message.data.data(), message.data.size())) {
                SipParser parser;
                auto sip_msg = parser.parse(message.data.data(), message.data.size());
                if (sip_msg.has_value()) {
                    LOG_INFO("SIP message detected over SCTP (PPID 0)");
                    correlator_.processSipMessage(sip_msg.value(), metadata);
                    return;
                }
            }

            // If not SIP, log and continue
            LOG_DEBUG("SCTP PPID 0 data is not SIP, length=" << message.data.size());
            break;
        }

        case 18: {  // S1AP
            LOG_DEBUG("Routing SCTP payload to S1AP parser");
            s1ap::S1APParser s1ap_parser;
            auto s1ap_msg = s1ap_parser.parse(message.data.data(), message.data.size());
            if (s1ap_msg.has_value()) {
                auto& msg = s1ap_msg.value();
                auto json = msg.toJson();

                // Check for embedded NAS PDU (LTE NAS)
                if (msg.nas_pdu.has_value()) {
                    NasParser nas_parser;
                    const auto& nas_data = msg.nas_pdu.value();

                    auto nas_msg_opt = nas_parser.parse(nas_data.data(), nas_data.size(), nullptr);
                    if (nas_msg_opt.has_value()) {
                        json["nas"] = nas_msg_opt->toJson();
                    }
                }

                correlator_.processPacket(metadata, ProtocolType::S1AP, json);
            }
            break;
        }

        case 27: {  // X2AP
            LOG_DEBUG("Routing SCTP payload to X2AP parser");
            // X2AP is already implemented, could be integrated here
            break;
        }

        case 46: {  // Diameter over SCTP
            LOG_DEBUG("Routing SCTP payload to Diameter parser");
            DiameterParser diameter_parser;
            auto diameter_msg = diameter_parser.parse(message.data.data(), message.data.size());
            if (diameter_msg.has_value()) {
                correlator_.processPacket(metadata, ProtocolType::DIAMETER, diameter_msg->toJson());
            }
            break;
        }

        case 60: {  // NGAP (5G)
            LOG_DEBUG("Routing SCTP payload to NGAP parser");
            NgapParser ngap_parser;
            auto ngap_msg = ngap_parser.parse(message.data.data(), message.data.size());
            if (ngap_msg.has_value()) {
                auto& msg = ngap_msg.value();
                auto json = msg.toJson();

                // Check for embedded NAS PDU
                if (msg.nas_pdu.has_value()) {
                    Nas5gParser nas_parser;
                    const auto& nas_data = msg.nas_pdu.value();

                    auto nas_msg_opt = nas_parser.parse(nas_data.data(), nas_data.size(), nullptr);
                    if (nas_msg_opt.has_value()) {
                        json["nas_5g"] = nas_msg_opt->toJson();
                    }
                }

                correlator_.processPacket(metadata, ProtocolType::NGAP, json);
            }
            break;
        }

        case 61: {  // XWAP
            LOG_DEBUG("Routing SCTP payload to XWAP parser (not yet implemented)");
            break;
        }

        default:
            LOG_DEBUG("Unknown SCTP PPID: " << message.payload_protocol << " ("
                                            << getSctpPpidName(message.payload_protocol) << ")");
            break;
    }
}

// ============================================================================
// DynamicPortTracker Implementation
// ============================================================================

void DynamicPortTracker::registerRtpPorts(const std::string& call_id, uint16_t local_port,
                                          uint16_t remote_port) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto now = std::chrono::system_clock::now();

    // Register local port
    if (local_port > 0) {
        port_to_call_id_[local_port] = PortEntry{call_id, now};
        LOG_DEBUG("Registered RTP port " << local_port << " for call_id=" << call_id);
    }

    // Register remote port
    if (remote_port > 0 && remote_port != local_port) {
        port_to_call_id_[remote_port] = PortEntry{call_id, now};
        LOG_DEBUG("Registered RTP port " << remote_port << " for call_id=" << call_id);
    }
}

bool DynamicPortTracker::isKnownRtpPort(uint16_t port) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return port_to_call_id_.find(port) != port_to_call_id_.end();
}

std::optional<std::string> DynamicPortTracker::getCallIdByPort(uint16_t port) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = port_to_call_id_.find(port);
    if (it != port_to_call_id_.end()) {
        return it->second.call_id;
    }
    return std::nullopt;
}

size_t DynamicPortTracker::cleanupExpired(Timestamp current_time) {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t removed = 0;

    auto it = port_to_call_id_.begin();
    while (it != port_to_call_id_.end()) {
        auto age = std::chrono::duration_cast<std::chrono::seconds>(current_time -
                                                                    it->second.registered_at);

        if (age > PORT_TTL) {
            LOG_DEBUG("Expired RTP port mapping: port=" << it->first
                                                        << " call_id=" << it->second.call_id
                                                        << " age=" << age.count() << "s");
            it = port_to_call_id_.erase(it);
            ++removed;
        } else {
            ++it;
        }
    }

    return removed;
}

// ============================================================================
// SipPortTracker Implementation
// ============================================================================

SipPortTracker::SipPortTracker() {
    // Initialize with standard SIP ports and common IMS/VoLTE ports
    known_sip_ports_.insert(5060);  // SIP (standard)
    known_sip_ports_.insert(5061);  // SIP over TLS (standard)
    known_sip_ports_.insert(5062);  // SIP (alternative)
    known_sip_ports_.insert(5063);  // SIP (alternative, IMS P-CSCF)
    known_sip_ports_.insert(5064);  // SIP (alternative, IMS S-CSCF)
    known_sip_ports_.insert(6101);  // IMS signaling port
    known_sip_ports_.insert(7100);  // IMS signaling port (Telekom)
    known_sip_ports_.insert(7200);  // IMS signaling port (Telekom)
}

void SipPortTracker::registerSipPort(uint16_t port) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (known_sip_ports_.insert(port).second) {
        LOG_INFO("Registered non-standard SIP port: " << port);
    }
}

bool SipPortTracker::isSipPort(uint16_t port) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return known_sip_ports_.count(port) > 0;
}

std::set<uint16_t> SipPortTracker::getAllSipPorts() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return known_sip_ports_;
}

// ============================================================================
// SipTcpStreamBuffer Implementation
// ============================================================================

void PacketProcessor::SipTcpStreamBuffer::appendData(const uint8_t* data, size_t len) {
    buffer_.insert(buffer_.end(), data, data + len);
}

std::vector<std::vector<uint8_t>> PacketProcessor::SipTcpStreamBuffer::extractCompleteMessages() {
    std::vector<std::vector<uint8_t>> messages;

    while (true) {
        auto boundary_opt = findMessageBoundary(0);
        if (!boundary_opt.has_value()) {
            break;  // No complete message found
        }

        size_t msg_len = boundary_opt.value();

        // Sanity check
        if (msg_len > MAX_SIP_MESSAGE_SIZE) {
            LOG_WARN("SIP message exceeds maximum size (" << msg_len << " > "
                                                          << MAX_SIP_MESSAGE_SIZE << "), skipping");
            buffer_.erase(buffer_.begin(), buffer_.begin() + msg_len);
            continue;
        }

        // Extract message
        std::vector<uint8_t> message(buffer_.begin(), buffer_.begin() + msg_len);
        messages.push_back(std::move(message));

        // Remove from buffer
        buffer_.erase(buffer_.begin(), buffer_.begin() + msg_len);
    }

    return messages;
}

void PacketProcessor::SipTcpStreamBuffer::reset() {
    buffer_.clear();
}

std::optional<size_t> PacketProcessor::SipTcpStreamBuffer::findMessageBoundary(
    size_t start_pos) const {
    if (start_pos >= buffer_.size()) {
        return std::nullopt;
    }

    // Look for "\r\n\r\n" (end of SIP headers)
    const std::string crlf2 = "\r\n\r\n";
    auto it = std::search(buffer_.begin() + start_pos, buffer_.end(), crlf2.begin(), crlf2.end());

    if (it == buffer_.end()) {
        return std::nullopt;  // Headers incomplete
    }

    // Calculate header length including double CRLF
    size_t headers_len = std::distance(buffer_.begin(), it) + 4;

    // Parse headers to find Content-Length
    std::string headers(buffer_.begin() + start_pos, buffer_.begin() + start_pos + headers_len);
    int content_len = 0;

    // Search for Content-Length header (case-insensitive)
    auto pos = headers.find("Content-Length:");
    if (pos == std::string::npos) {
        pos = headers.find("content-length:");  // lowercase
    }
    if (pos == std::string::npos) {
        pos = headers.find("l:");  // Compact form
    }
    if (pos == std::string::npos) {
        pos = headers.find("L:");  // Compact form uppercase
    }

    if (pos != std::string::npos) {
        // Extract number
        size_t val_start = headers.find_first_of("0123456789", pos);
        if (val_start != std::string::npos) {
            content_len = std::atoi(headers.c_str() + val_start);
        }
    }

    size_t total_len = headers_len + content_len;

    // Check if we have the complete message
    if (buffer_.size() >= start_pos + total_len) {
        return total_len;
    }

    return std::nullopt;  // Body incomplete
}

// ============================================================================
// Helper Methods
// ============================================================================

bool PacketProcessor::isSipPort(uint16_t port) {
    // Standard SIP ports and common IMS/VoLTE ports for static check
    // For dynamic tracking, use sip_port_tracker_ instance method
    return port == 5060 || port == 5061 || port == 5062 || port == 5063 || port == 5064 ||
           port == 6101 || port == 7100 || port == 7200;
}

PacketMetadata PacketProcessor::createMetadataFromTcp(const FiveTuple& ft, Timestamp ts) const {
    PacketMetadata metadata;
    metadata.packet_id = utils::generateUuid();
    metadata.timestamp = ts;
    metadata.five_tuple = ft;
    metadata.detected_protocol = ProtocolType::SIP;
    return metadata;
}

// ============================================================================
// PacketDeduplicator Implementation
// ============================================================================

PacketDeduplicator::PacketDeduplicator(size_t window_size) : max_window_size_(window_size) {
    LOG_DEBUG("PacketDeduplicator initialized with window_size=" << window_size);
}

bool PacketDeduplicator::isDuplicate(const PacketMetadata& meta,
                                     const std::vector<uint8_t>& payload) {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_.total_packets++;

    // Create signature for this packet
    PacketSignature sig;
    sig.src_ip_hash = hashIpAddress(meta.five_tuple.src_ip);
    sig.dst_ip_hash = hashIpAddress(meta.five_tuple.dst_ip);
    sig.src_port = meta.five_tuple.src_port;
    sig.dst_port = meta.five_tuple.dst_port;
    sig.protocol = meta.five_tuple.protocol;
    sig.payload_len = static_cast<uint16_t>(std::min(payload.size(), size_t(65535)));
    sig.timestamp_us =
        std::chrono::duration_cast<std::chrono::microseconds>(meta.timestamp.time_since_epoch())
            .count();

    // Extract seq/id from payload (TCP sequence number or UDP length)
    sig.seq_or_id = 0;
    if (!payload.empty()) {
        if (meta.five_tuple.protocol == IPPROTO_TCP && payload.size() >= 4) {
            // TCP: extract sequence number from first 4 bytes of TCP header
            // Note: This assumes payload starts at TCP header
            sig.seq_or_id =
                (payload[0] << 24) | (payload[1] << 16) | (payload[2] << 8) | payload[3];
        }
        // Calculate CRC on first 64 bytes of payload for efficiency
        size_t crc_len = std::min(payload.size(), size_t(64));
        sig.payload_crc = calculateCrc32(payload.data(), crc_len);
    } else {
        sig.payload_crc = 0;
    }

    // Check for duplicate within time window
    // We look for exact match except for timestamp (within tolerance)
    for (const auto& existing : recent_packets_) {
        // Check if signatures match (excluding timestamp)
        if (existing.src_ip_hash == sig.src_ip_hash && existing.dst_ip_hash == sig.dst_ip_hash &&
            existing.src_port == sig.src_port && existing.dst_port == sig.dst_port &&
            existing.protocol == sig.protocol && existing.payload_len == sig.payload_len &&
            existing.payload_crc == sig.payload_crc && existing.seq_or_id == sig.seq_or_id) {
            // Check timestamp within tolerance
            uint64_t time_diff = (sig.timestamp_us > existing.timestamp_us)
                                     ? (sig.timestamp_us - existing.timestamp_us)
                                     : (existing.timestamp_us - sig.timestamp_us);
            if (time_diff <= DUPLICATE_TIME_WINDOW_US) {
                stats_.duplicates_detected++;
                LOG_DEBUG("Duplicate packet detected: "
                          << meta.five_tuple.src_ip << ":" << meta.five_tuple.src_port << " -> "
                          << meta.five_tuple.dst_ip << ":" << meta.five_tuple.dst_port
                          << " time_diff=" << time_diff << "us");
                return true;
            }
        }
    }

    // Not a duplicate - add to tracking set
    recent_packets_.insert(sig);
    signature_queue_.push_back(sig);

    // Maintain window size by removing old entries
    while (signature_queue_.size() > max_window_size_) {
        recent_packets_.erase(signature_queue_.front());
        signature_queue_.pop_front();
    }

    return false;
}

PacketDeduplicator::Stats PacketDeduplicator::getStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

bool PacketDeduplicator::PacketSignature::operator==(const PacketSignature& other) const {
    return src_ip_hash == other.src_ip_hash && dst_ip_hash == other.dst_ip_hash &&
           src_port == other.src_port && dst_port == other.dst_port && protocol == other.protocol &&
           seq_or_id == other.seq_or_id && payload_len == other.payload_len &&
           payload_crc == other.payload_crc;
    // Note: timestamp not included in equality check
}

size_t PacketDeduplicator::SignatureHash::operator()(const PacketSignature& sig) const {
    size_t h = sig.src_ip_hash;
    h ^= (sig.dst_ip_hash << 1);
    h ^= (static_cast<size_t>(sig.src_port) << 2);
    h ^= (static_cast<size_t>(sig.dst_port) << 3);
    h ^= (static_cast<size_t>(sig.protocol) << 4);
    h ^= (static_cast<size_t>(sig.seq_or_id) << 5);
    h ^= (static_cast<size_t>(sig.payload_len) << 6);
    h ^= (static_cast<size_t>(sig.payload_crc) << 7);
    return h;
}

uint32_t PacketDeduplicator::hashIpAddress(const std::string& ip) {
    // Simple FNV-1a hash for IP address string
    uint32_t hash = 2166136261u;
    for (char c : ip) {
        hash ^= static_cast<uint8_t>(c);
        hash *= 16777619u;
    }
    return hash;
}

uint32_t PacketDeduplicator::calculateCrc32(const uint8_t* data, size_t len) {
    // CRC-32 (IEEE 802.3) lookup table approach
    static const uint32_t crc_table[256] = {
        0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f, 0xe963a535,
        0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988, 0x09b64c2b, 0x7eb17cbd,
        0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de, 0x1adad47d,
        0x6ddde4eb, 0xf4d4b551, 0x83d385c7, 0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec,
        0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4,
        0xa2677172, 0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
        0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59, 0x26d930ac,
        0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
        0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924, 0x2f6f7c87, 0x58684c11, 0xc1611dab,
        0xb6662d3d, 0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f,
        0x9fbfe4a5, 0xe8b8d433, 0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb,
        0x086d3d2d, 0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
        0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea,
        0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65, 0x4db26158, 0x3ab551ce,
        0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a,
        0x346ed9fc, 0xad678846, 0xda60b8d0, 0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
        0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409,
        0xce61e49f, 0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
        0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a, 0xead54739,
        0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8,
        0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1, 0xf00f9344, 0x8708a3d2, 0x1e01f268,
        0x6906c2fe, 0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0,
        0x10da7a5a, 0x67dd4acc, 0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8,
        0xa1d1937e, 0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
        0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55, 0x316e8eef,
        0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236, 0xcc0c7795, 0xbb0b4703,
        0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7,
        0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d, 0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a,
        0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae,
        0x0cb61b38, 0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
        0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777, 0x88085ae6,
        0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
        0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2, 0xa7672661, 0xd06016f7, 0x4969474d,
        0x3e6e77db, 0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5,
        0x47b2cf7f, 0x30b5ffe9, 0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605,
        0xcdd706b3, 0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
        0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d};

    uint32_t crc = 0xffffffff;
    for (size_t i = 0; i < len; i++) {
        crc = crc_table[(crc ^ data[i]) & 0xff] ^ (crc >> 8);
    }
    return crc ^ 0xffffffff;
}

}  // namespace callflow
