#include "pcap_ingest/ip_reassembler.h"

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include <cstring>

#include "common/logger.h"
#include "common/utils.h"

namespace callflow {

IpReassembler::IpReassembler(uint32_t timeout_sec) : timeout_sec_(timeout_sec) {}

void IpReassembler::cleanup() {
    auto now = std::chrono::steady_clock::now();
    for (auto it = active_reassemblies_.begin(); it != active_reassemblies_.end();) {
        if (std::chrono::duration_cast<std::chrono::seconds>(now - it->second.last_update).count() >
            timeout_sec_) {
            // Timed out
            it = active_reassemblies_.erase(it);
        } else {
            ++it;
        }
    }
}

std::optional<std::vector<uint8_t>> IpReassembler::processPacket(const uint8_t* ip_data,
                                                                 size_t len) {
    if (len < 1)
        return std::nullopt;

    uint8_t version = (ip_data[0] >> 4) & 0x0F;
    if (version == 4) {
        return handleIpv4(ip_data, len);
    } else if (version == 6) {
        return handleIpv6(ip_data, len);
    }

    // Unknown version or not handled
    return std::vector<uint8_t>(ip_data, ip_data + len);
}

std::optional<std::vector<uint8_t>> IpReassembler::handleIpv4(const uint8_t* ip_data, size_t len) {
    if (len < sizeof(struct ip))
        return std::nullopt;

    const struct ip* ip_hdr = reinterpret_cast<const struct ip*>(ip_data);
    uint16_t off_field = ntohs(ip_hdr->ip_off);
    bool mf = (off_field & IP_MF);
    uint16_t offset = (off_field & IP_OFFMASK) * 8;

    if (!mf && offset == 0) {
        // Not fragmented
        return std::vector<uint8_t>(ip_data, ip_data + len);
    }

    // Is fragmented
    IpFragmentKey key;
    char src_str[INET_ADDRSTRLEN];
    char dst_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_hdr->ip_src), src_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_str, INET_ADDRSTRLEN);

    key.src_ip = src_str;
    key.dst_ip = dst_str;
    key.id = ntohs(ip_hdr->ip_id);
    key.protocol = ip_hdr->ip_p;
    key.is_ipv6 = false;

    // Get payload
    uint8_t hlen = ip_hdr->ip_hl * 4;
    if (len < hlen)
        return std::nullopt;

    size_t payload_len = len - hlen;

    auto& list = active_reassemblies_[key];
    list.last_update = std::chrono::steady_clock::now();

    std::vector<uint8_t> payload(ip_data + hlen, ip_data + len);
    list.fragments[offset] = std::move(payload);

    if (!mf) {
        list.seen_last_fragment = true;
        list.total_length = offset + payload_len;
    }

    if (list.seen_last_fragment) {
        uint32_t current_len = 0;
        bool complete = true;

        for (const auto& frag : list.fragments) {
            if (frag.first != current_len) {
                complete = false;
                break;
            }
            current_len += frag.second.size();
        }

        if (complete && current_len == list.total_length) {
            // Reconstruct
            std::vector<uint8_t> reassembled;
            reassembled.reserve(hlen + list.total_length);

            struct ip new_hdr;
            std::memset(&new_hdr, 0, sizeof(new_hdr));
            new_hdr.ip_v = 4;
            new_hdr.ip_hl = 5;
            new_hdr.ip_len = htons(sizeof(struct ip) + list.total_length);
            new_hdr.ip_id = htons(key.id);
            new_hdr.ip_off = 0;
            new_hdr.ip_ttl = 64;
            new_hdr.ip_p = key.protocol;
            inet_pton(AF_INET, key.src_ip.c_str(), &(new_hdr.ip_src));
            inet_pton(AF_INET, key.dst_ip.c_str(), &(new_hdr.ip_dst));

            const uint8_t* hptr = reinterpret_cast<const uint8_t*>(&new_hdr);
            reassembled.insert(reassembled.end(), hptr, hptr + sizeof(struct ip));

            for (const auto& frag : list.fragments) {
                reassembled.insert(reassembled.end(), frag.second.begin(), frag.second.end());
            }

            active_reassemblies_.erase(key);
            return reassembled;
        }
    }

    return std::nullopt;
}

std::optional<std::vector<uint8_t>> IpReassembler::handleIpv6(const uint8_t* ip_data, size_t len) {
    if (len < 40)
        return std::nullopt;

    const struct ip6_hdr* ip6 = reinterpret_cast<const struct ip6_hdr*>(ip_data);

    uint8_t next_header = ip6->ip6_nxt;
    const uint8_t* ptr = ip_data + 40;
    size_t left = len - 40;

    const struct ip6_frag* frag_hdr = nullptr;

    int headers_checked = 0;
    while (headers_checked < 10) {
        if (next_header == IPPROTO_FRAGMENT) {
            if (left < sizeof(struct ip6_frag))
                break;
            frag_hdr = reinterpret_cast<const struct ip6_frag*>(ptr);
            break;
        } else if (next_header == IPPROTO_HOPOPTS || next_header == IPPROTO_ROUTING ||
                   next_header == IPPROTO_DSTOPTS) {
            if (left < 2)
                break;
            uint8_t hdr_len = (ptr[1] + 1) * 8;
            if (left < hdr_len)
                break;

            next_header = ptr[0];
            ptr += hdr_len;
            left -= hdr_len;
        } else {
            break;
        }
        headers_checked++;
    }

    if (!frag_hdr) {
        return std::vector<uint8_t>(ip_data, ip_data + len);
    }

    uint16_t frag_off_flag = ntohs(frag_hdr->ip6f_offlg);
    uint16_t offset = (frag_off_flag & IP6F_OFF_MASK);
    bool mf = (frag_off_flag & IP6F_MORE_FRAG);
    uint32_t id = ntohl(frag_hdr->ip6f_ident);

    size_t header_len_total = (const uint8_t*)(frag_hdr + 1) - ip_data;
    if (len < header_len_total)
        return std::nullopt;

    size_t payload_len = len - header_len_total;

    IpFragmentKey key;
    char src_str[INET6_ADDRSTRLEN];
    char dst_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &(ip6->ip6_src), src_str, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(ip6->ip6_dst), dst_str, INET6_ADDRSTRLEN);

    key.src_ip = src_str;
    key.dst_ip = dst_str;
    key.id = id;
    key.protocol = frag_hdr->ip6f_nxt;
    key.is_ipv6 = true;

    auto& list = active_reassemblies_[key];
    list.last_update = std::chrono::steady_clock::now();

    std::vector<uint8_t> payload((const uint8_t*)(frag_hdr + 1), ip_data + len);
    list.fragments[offset] = std::move(payload);

    if (!mf) {
        list.seen_last_fragment = true;
        list.total_length = offset + payload_len;
    }

    if (list.seen_last_fragment) {
        uint32_t current_len = 0;
        bool complete = true;
        for (const auto& frag : list.fragments) {
            if (frag.first != current_len) {
                complete = false;
                break;
            }
            current_len += frag.second.size();
        }

        if (complete && current_len == list.total_length) {
            std::vector<uint8_t> reassembled;
            reassembled.reserve(40 + list.total_length);

            struct ip6_hdr new_hdr;
            std::memcpy(&new_hdr, ip6, 40);
            new_hdr.ip6_plen = htons(list.total_length);
            new_hdr.ip6_nxt = frag_hdr->ip6f_nxt;

            const uint8_t* hptr = reinterpret_cast<const uint8_t*>(&new_hdr);
            reassembled.insert(reassembled.end(), hptr, hptr + 40);

            for (const auto& frag : list.fragments) {
                reassembled.insert(reassembled.end(), frag.second.begin(), frag.second.end());
            }

            active_reassemblies_.erase(key);
            return reassembled;
        }
    }

    return std::nullopt;
}

}  // namespace callflow
