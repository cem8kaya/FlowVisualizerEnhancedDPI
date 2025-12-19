#pragma once

#include <pcap/pcap.h>  // For DLT_ constants if available, otherwise we use raw values or define them

#include <cstdint>
#include <vector>

#include "common/types.h"

// Ensure constants are defined if not present
#ifndef DLT_NULL
#define DLT_NULL 0
#endif

#ifndef DLT_EN10MB
#define DLT_EN10MB 1
#endif

#ifndef DLT_RAW
#define DLT_RAW 12
#endif

#ifndef DLT_LINUX_SLL
#define DLT_LINUX_SLL 113
#endif

#ifndef DLT_IPV4
#define DLT_IPV4 228
#endif

#ifndef DLT_IPV6
#define DLT_IPV6 229
#endif

namespace callflow {

/**
 * Handles parsing of different Link Layer headers (Ethernet, Linux SLL, etc.)
 */
class LinkLayerParser {
public:
    LinkLayerParser() = default;

    /**
     * Parse the link layer header and return offset to the network layer (IP)
     * @param data Raw packet data
     * @param len Packet length
     * @param dlt Data Link Type (from pcap_datalink)
     * @param eth_type Output: Ethernet type (or equivalent protocol ID)
     * @return Offset to network layer (IP header), or -1 if failed/unsupported
     */
    int parse(const uint8_t* data, size_t len, int dlt, uint16_t& eth_type);

private:
    int parseEthernet(const uint8_t* data, size_t len, uint16_t& eth_type);
    int parseLinuxSll(const uint8_t* data, size_t len, uint16_t& eth_type);
    int parseNull(const uint8_t* data, size_t len, uint16_t& eth_type);
    int parseRaw(const uint8_t* data, size_t len, uint16_t& eth_type);
};

}  // namespace callflow
