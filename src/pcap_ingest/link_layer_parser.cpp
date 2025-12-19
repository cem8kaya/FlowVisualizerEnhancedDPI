#include "pcap_ingest/link_layer_parser.h"

#include <arpa/inet.h>

#include <cstring>

#include "common/logger.h"

namespace callflow {

// Ethernet Constants
static const uint16_t ETHERTYPE_IP = 0x0800;
static const uint16_t ETHERTYPE_IPV6 = 0x86DD;
static const uint16_t ETHERTYPE_VLAN = 0x8100;
static const uint16_t ETHERTYPE_QINQ = 0x88A8;

int LinkLayerParser::parse(const uint8_t* data, size_t len, int dlt, uint16_t& eth_type) {
    switch (dlt) {
        case DLT_EN10MB:
            return parseEthernet(data, len, eth_type);
        case DLT_LINUX_SLL:
            return parseLinuxSll(data, len, eth_type);
        case DLT_NULL:
        case 108:  // DLT_LOOP (OpenBSD)
            return parseNull(data, len, eth_type);
        case DLT_RAW:
        case 101:  // DLT_RAW (alternative)
        case DLT_IPV4:
        case DLT_IPV6:
            return parseRaw(data, len, eth_type);
        default:
            LOG_TRACE("Unsupported DLT: " << dlt);
            return -1;
    }
}

int LinkLayerParser::parseEthernet(const uint8_t* data, size_t len, uint16_t& eth_type) {
    if (len < 14)
        return -1;

    // Standard Ethernet header is 14 bytes
    int offset = 14;
    eth_type = ntohs(*reinterpret_cast<const uint16_t*>(&data[12]));

    // Handle VLAN (802.1Q and 802.1ad QinQ)
    // We loop to handle multiple tags (QinQ)
    while (eth_type == ETHERTYPE_VLAN || eth_type == ETHERTYPE_QINQ) {
        if (len < static_cast<size_t>(offset + 4))
            return -1;

        // Next EtherType is 2 bytes after the current tag Control Information (2 bytes TCI)
        // Offset is currently at start of next header (or TCI)
        // 802.1Q header: [TPID(2)][TCI(2)] -> Next Header starts after this.
        // But wait, the standard frame is: [Dst][Src][TPID][TCI][EtherType(Payload)]
        // The `eth_type` we read is the TPID (0x8100).
        // The TCI is at `offset`.
        // The next EtherType is at `offset + 2`.

        eth_type = ntohs(*reinterpret_cast<const uint16_t*>(&data[offset + 2]));
        offset += 4;  // Advance past the 4-byte VLAN tag (TPID was already passed in prev iteration
                      // logic? No.)

        // Re-verify logic:
        // Initial: Offset=14. Type Read from 12 (bytes 12-13).
        // If Type=0x8100:
        //   The bytes 12-13 were the TPID.
        //   Bytes 14-15 are TCI.
        //   Bytes 16-17 are the Next EtherType.
        //   So we skip 4 bytes relative to the original simpler frame?
        //   Yes, effectively the VLAN tag is inserted.
        //   So we read new type from offset+2 (14+2=16).
        //   And increase offset by 4 (14 -> 18).
        //   Correct.
    }

    return offset;
}

int LinkLayerParser::parseLinuxSll(const uint8_t* data, size_t len, uint16_t& eth_type) {
    // SLL header is 16 bytes:
    // Packet type (2), ARPHRD (2), Address len (2), Address (8), Protocol (2)
    if (len < 16)
        return -1;

    // Protocol is at offset 14
    eth_type = ntohs(*reinterpret_cast<const uint16_t*>(&data[14]));

    return 16;
}

int LinkLayerParser::parseNull(const uint8_t* data, size_t len, uint16_t& eth_type) {
    // DLT_NULL header is 4 bytes containing the family
    // BSD: host byte order.
    // Linux: unfortunately not always consistent, but usually we can guess.
    // Actually DLT_NULL is platform dependent (BSD Loopback).
    // The 4-byte header contains PF_INET (2), PF_INET6 (24/28/30?), etc.
    if (len < 4)
        return -1;

    uint32_t family = *reinterpret_cast<const uint32_t*>(data);

    // Simple heuristic for byte order: family usually is small < 255.
    // If we see huge number, try swap.
    if (family > 0xFF) {
        // Swap
        family = ((family & 0xFF000000) >> 24) | ((family & 0x00FF0000) >> 8) |
                 ((family & 0x0000FF00) << 8) | ((family & 0x000000FF) << 24);
    }

    if (family == 2) {  // AF_INET
        eth_type = ETHERTYPE_IP;
    } else if (family == 10 || family == 24 || family == 28 || family == 30) {
        // AF_INET6 constants vary wildly.
        // Linux AF_INET6 = 10
        // BSD AF_INET6 = 24 / 28 / 30 depending on version
        eth_type = ETHERTYPE_IPV6;
    } else {
        // Fallback: Check IP version nibble if length allows
        if (len >= 4 + 20) {  // Check version in IP header
            uint8_t ver = (data[4] >> 4) & 0x0F;
            if (ver == 4)
                eth_type = ETHERTYPE_IP;
            else if (ver == 6)
                eth_type = ETHERTYPE_IPV6;
            else
                return -1;
        } else {
            return -1;
        }
    }

    return 4;
}

int LinkLayerParser::parseRaw(const uint8_t* data, size_t len, uint16_t& eth_type) {
    if (len < 1)
        return -1;

    // Raw IP has no header or minimal.
    // Just peek at version nibble.
    uint8_t version = (data[0] >> 4) & 0x0F;
    if (version == 4) {
        eth_type = ETHERTYPE_IP;
    } else if (version == 6) {
        eth_type = ETHERTYPE_IPV6;
    } else {
        return -1;
    }

    return 0;  // Header length is 0
}

}  // namespace callflow
