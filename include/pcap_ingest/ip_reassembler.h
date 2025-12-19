#pragma once

#include <chrono>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "common/types.h"

namespace callflow {

/**
 * Key to identify an IP fragment series
 */
struct IpFragmentKey {
    std::string src_ip;
    std::string dst_ip;
    uint32_t id;       // Identification field
    uint8_t protocol;  // Protocol or Next Header
    bool is_ipv6;

    bool operator<(const IpFragmentKey& other) const {
        if (src_ip != other.src_ip)
            return src_ip < other.src_ip;
        if (dst_ip != other.dst_ip)
            return dst_ip < other.dst_ip;
        if (id != other.id)
            return id < other.id;
        if (protocol != other.protocol)
            return protocol < other.protocol;
        return is_ipv6 < other.is_ipv6;
    }
};

/**
 * Stores fragments for a specific packet
 */
struct FragmentList {
    std::map<uint32_t, std::vector<uint8_t>> fragments;  // Offset -> Data
    uint32_t total_length = 0;
    bool seen_last_fragment = false;
    std::chrono::steady_clock::time_point last_update;

    // For IPv6, we need to preserve the unfragmentable part (first packet's header info)
    // We will just reconstruct based on the first fragment (offset 0) header + reassembled payload.
};

class IpReassembler {
public:
    IpReassembler(uint32_t timeout_sec = 30);

    /**
     * Process an IP packet and attempt reassembly.
     * @param timestamp Packet timestamp
     * @param ip_data Pointer to start of IP header
     * @param len Total length of IP packet (header + payload)
     * @return Optional containing the FULL reassembled IP packet (including header).
     *         If not fragmented, returns a copy of input.
     *         If fragment but incomplete, returns std::nullopt.
     */
    std::optional<std::vector<uint8_t>> processPacket(const uint8_t* ip_data, size_t len);

    /**
     * Clean up timed out fragment lists
     */
    void cleanup();

private:
    std::map<IpFragmentKey, FragmentList> active_reassemblies_;
    uint32_t timeout_sec_;

    // Helper for IPv4
    std::optional<std::vector<uint8_t>> handleIpv4(const uint8_t* ip_data, size_t len);

    // Helper for IPv6
    std::optional<std::vector<uint8_t>> handleIpv6(const uint8_t* ip_data, size_t len);
};

}  // namespace callflow
