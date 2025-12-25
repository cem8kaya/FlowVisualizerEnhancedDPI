#include "ndpi_engine/protocol_detector.h"
#include "common/logger.h"

#include <algorithm>
#include <cstring>
#include <string_view>

namespace callflow {

std::optional<ProtocolType> ProtocolDetector::detectFromPayload(
    const uint8_t* data,
    size_t len,
    uint16_t src_port,
    uint16_t dst_port,
    uint8_t protocol)
{
    if (!data || len < 4) {
        return std::nullopt;
    }

    // Only perform content-based detection for UDP and TCP
    if (protocol != 17 && protocol != 6) {  // UDP=17, TCP=6
        return std::nullopt;
    }

    // 1. Try content-based detection first (most reliable)

    // SIP detection - check payload first
    if (isSipPayload(data, len)) {
        LOG_DEBUG("Content-based detection: SIP (payload signature match)");
        return ProtocolType::SIP;
    }

    // DIAMETER detection
    if (isDiameterPayload(data, len)) {
        LOG_DEBUG("Content-based detection: DIAMETER (header validation passed)");
        return ProtocolType::DIAMETER;
    }

    // GTP detection (works for both GTPv1 and GTPv2)
    if (isGtpPayload(data, len)) {
        ProtocolType gtp_type = getGtpProtocolType(data, len);
        LOG_DEBUG("Content-based detection: " << protocolTypeToString(gtp_type)
                  << " (GTP header validated)");
        return gtp_type;
    }

    // STUN detection
    if (isStunPayload(data, len)) {
        LOG_DEBUG("Content-based detection: STUN (magic cookie validated)");
        // STUN doesn't have a dedicated ProtocolType in the current enum
        // Return UDP for now, or could be added to the enum
        return ProtocolType::UDP;
    }

    // 2. RTP is harder to detect without context (needs SDP correlation)
    // Only check RTP if:
    // - Port is in typical RTP range (even port >= 1024)
    // - Payload matches RTP header structure
    bool port_in_rtp_range =
        (src_port >= 1024 && src_port % 2 == 0) ||
        (dst_port >= 1024 && dst_port % 2 == 0);

    if (port_in_rtp_range && isRtpPayload(data, len)) {
        LOG_DEBUG("Content-based detection: RTP (header validation + port heuristic)");
        return ProtocolType::RTP;
    }

    // 3. If content-based detection fails, return nullopt
    // The caller can decide to fall back to port-based heuristics
    return std::nullopt;
}

bool ProtocolDetector::isSipPayload(const uint8_t* data, size_t len) {
    if (!data || len < 8) {
        return false;
    }

    // Convert to string for analysis (check up to 4KB for large messages)
    size_t check_len = std::min(len, size_t(4096));
    std::string text(reinterpret_cast<const char*>(data), check_len);

    // Method 1: Check for SIP/2.0 version identifier (MUST be present in all SIP messages)
    bool has_sip_version = (text.find("SIP/2.0") != std::string::npos);
    if (!has_sip_version) {
        return false;
    }

    // Method 2: Check for SIP methods (request line)
    static const std::vector<std::string> sip_methods = {
        "INVITE ", "ACK ", "BYE ", "CANCEL ", "OPTIONS ",
        "REGISTER ", "UPDATE ", "PRACK ", "SUBSCRIBE ",
        "NOTIFY ", "PUBLISH ", "MESSAGE ", "INFO ", "REFER "
    };

    for (const auto& method : sip_methods) {
        if (text.find(method) == 0) { // Must be at start
            return true;
        }
    }

    // Method 3: Check for SIP status line (response)
    // Format: "SIP/2.0 <status-code> <reason>"
    if (text.find("SIP/2.0 ") == 0) {
        // Check if followed by 3-digit status code
        if (text.length() >= 12) {
            std::string status = text.substr(8, 3);
            if (std::isdigit(status[0]) && std::isdigit(status[1]) &&
                std::isdigit(status[2])) {
                return true;
            }
        }
    }

    // Method 4: Check for mandatory SIP headers (more reliable for fragments)
    // According to RFC 3261, these headers are mandatory in all SIP requests/responses
    static const std::vector<std::string> mandatory_headers = {
        "Call-ID:", "i:", // Call-ID (or compact form)
        "From:", "f:",    // From
        "To:", "t:",      // To
        "CSeq:",          // CSeq
        "Via:", "v:"      // Via
    };

    int header_count = 0;
    for (const auto& header : mandatory_headers) {
        if (text.find(header) != std::string::npos) {
            header_count++;
        }
    }

    // If we have SIP/2.0 + at least 2 mandatory headers, likely SIP
    // This catches fragmented messages where the request/status line might be in a different segment
    return has_sip_version && header_count >= 2;
}

bool ProtocolDetector::isDiameterPayload(const uint8_t* data, size_t len) {
    if (len < 20) {
        return false;  // Minimum Diameter header size
    }

    // Diameter Header Format (RFC 6733):
    // Byte 0: Version (should be 0x01)
    // Bytes 1-3: Message Length (24-bit, big-endian)
    // Byte 4: Flags
    // Bytes 5-7: Command Code (24-bit)

    // Check version
    uint8_t version = data[0];
    if (version != 0x01) {
        return false;
    }

    // Check message length consistency
    uint32_t msg_len = (data[1] << 16) | (data[2] << 8) | data[3];
    if (msg_len < 20 || msg_len > 65535) {
        return false;
    }

    // Check flags byte - reserved bits (lower 4 bits) must be 0
    uint8_t flags = data[4];
    if ((flags & 0x0F) != 0) {
        return false;
    }

    // Additional validation: Check if reported length matches packet length
    // Allow some tolerance for fragmentation
    if (len >= msg_len) {
        // Full message or more - valid
        return true;
    } else if (len >= 20 && len < msg_len) {
        // Partial message (fragmentation) - still valid Diameter header
        return true;
    }

    return false;
}

bool ProtocolDetector::isGtpPayload(const uint8_t* data, size_t len) {
    if (len < 8) {
        return false;
    }

    // GTP Header Format:
    // Bits 5-7 of byte 0: Version (001 for GTPv1, 010 for GTPv2)
    // Bit 4 of byte 0: Protocol Type (1 for GTP, 0 for GTP')

    uint8_t version = (data[0] >> 5) & 0x07;
    uint8_t pt = (data[0] >> 4) & 0x01;

    // Check version: GTPv1 = 1, GTPv2 = 2
    if (version != 1 && version != 2) {
        return false;
    }

    // Protocol Type must be 1 for GTP
    if (pt != 1) {
        return false;
    }

    return true;
}

ProtocolType ProtocolDetector::getGtpProtocolType(const uint8_t* data, size_t len) {
    if (!isGtpPayload(data, len)) {
        return ProtocolType::UNKNOWN;
    }

    uint8_t version = (data[0] >> 5) & 0x07;
    uint8_t msg_type = data[1];

    if (version == 2) {
        // GTPv2-C (all GTPv2 messages are control plane)
        return ProtocolType::GTP_C;
    } else if (version == 1) {
        // GTPv1: Distinguish between GTP-C and GTP-U based on message type
        // GTP-U uses message type 0xFF (G-PDU)
        // All other message types are GTP-C
        if (msg_type == 0xFF) {
            return ProtocolType::GTP_U;
        } else {
            return ProtocolType::GTP_C;
        }
    }

    return ProtocolType::UNKNOWN;
}

bool ProtocolDetector::isStunPayload(const uint8_t* data, size_t len) {
    if (len < 20) {
        return false;  // Minimum STUN message size
    }

    // STUN Message Format (RFC 5389):
    // Bytes 0-1: Message Type
    // Bytes 2-3: Message Length
    // Bytes 4-7: Magic Cookie (0x2112A442)
    // Bytes 8-19: Transaction ID

    // Check magic cookie at bytes 4-7
    uint32_t magic = (static_cast<uint32_t>(data[4]) << 24) |
                     (static_cast<uint32_t>(data[5]) << 16) |
                     (static_cast<uint32_t>(data[6]) << 8) |
                     static_cast<uint32_t>(data[7]);

    if (magic != STUN_MAGIC_COOKIE) {
        return false;
    }

    // Additional validation: Check message type
    // STUN message types have specific bit patterns
    uint16_t msg_type = (data[0] << 8) | data[1];

    // The first two bits of message type must be 00 (RFC 5389)
    if ((msg_type & 0xC000) != 0) {
        return false;
    }

    // Check message length
    uint16_t msg_len = (data[2] << 8) | data[3];

    // Message length must be multiple of 4
    if (msg_len % 4 != 0) {
        return false;
    }

    return true;
}

bool ProtocolDetector::isRtpPayload(const uint8_t* data, size_t len) {
    if (len < 12) {
        return false;  // Minimum RTP header size
    }

    // RTP Header Format (RFC 3550):
    // Bits 6-7 of byte 0: Version (should be 2)
    // Bit 5 of byte 0: Padding
    // Bit 4 of byte 0: Extension
    // Bits 0-3 of byte 0: CSRC count
    // Bit 7 of byte 1: Marker
    // Bits 0-6 of byte 1: Payload Type

    uint8_t version = (data[0] >> 6) & 0x03;
    if (version != 2) {
        return false;
    }

    // Check payload type (0-127 for standard types, 128-255 invalid)
    uint8_t pt = data[1] & 0x7F;

    // Common RTP payload types:
    // 0-34: Audio (PCMU, GSM, G723, etc.)
    // 96-127: Dynamic (negotiated via SDP)
    // Some reserved types in between

    // Very permissive check - just ensure it's in valid range
    // A more strict check would validate against known PT values
    if (pt > 127) {
        return false;
    }

    // Check CSRC count (should be reasonable, typically 0-15)
    uint8_t csrc_count = data[0] & 0x0F;
    if (csrc_count > 15) {
        return false;
    }

    // Calculate minimum expected header size
    size_t min_size = 12 + (csrc_count * 4);
    if (len < min_size) {
        return false;
    }

    // Additional heuristic: Check sequence number isn't all zeros or all ones
    // (helps avoid false positives)
    uint16_t seq = (data[2] << 8) | data[3];
    if (seq == 0x0000 || seq == 0xFFFF) {
        // Could still be valid, but suspicious for first packet
        // Don't reject, but note this is less confident
    }

    return true;
}

} // namespace callflow
