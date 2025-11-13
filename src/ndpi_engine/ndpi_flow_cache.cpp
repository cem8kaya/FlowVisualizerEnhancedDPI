#include "ndpi_engine/ndpi_flow_cache.h"
#include "common/logger.h"
#include <cstring>
#include <cstdlib>
#include <algorithm>
#include <vector>

// Only include nDPI if available
#ifdef NDPI_INCLUDE_DIR
#include <ndpi_api.h>
#include <ndpi_typedefs.h>
#endif

namespace callflow {

// ============================================================================
// NdpiCachedFlow Implementation
// ============================================================================

NdpiCachedFlow::NdpiCachedFlow()
    : flow(nullptr, [](ndpi_flow_struct* p) { if (p) free(p); }),
      src_id(nullptr, [](ndpi_id_struct* p) { if (p) free(p); }),
      dst_id(nullptr, [](ndpi_id_struct* p) { if (p) free(p); }),
      last_seen(std::chrono::system_clock::now()),
      packet_count(0) {
#ifdef NDPI_INCLUDE_DIR
    // Allocate nDPI structures
    auto* flow_ptr = static_cast<ndpi_flow_struct*>(calloc(1, sizeof(ndpi_flow_struct)));
    auto* src_ptr = static_cast<ndpi_id_struct*>(calloc(1, sizeof(ndpi_id_struct)));
    auto* dst_ptr = static_cast<ndpi_id_struct*>(calloc(1, sizeof(ndpi_id_struct)));

    if (!flow_ptr || !src_ptr || !dst_ptr) {
        LOG_ERROR("Failed to allocate nDPI flow structures");
        if (flow_ptr) free(flow_ptr);
        if (src_ptr) free(src_ptr);
        if (dst_ptr) free(dst_ptr);
        return;
    }

    flow.reset(flow_ptr);
    src_id.reset(src_ptr);
    dst_id.reset(dst_ptr);
#endif
}

// ============================================================================
// NdpiFlowCache Implementation
// ============================================================================

NdpiFlowCache::NdpiFlowCache(int timeout_sec, size_t max_flows)
    : timeout_sec_(timeout_sec), max_flows_(max_flows) {
    stats_.total_flows = 0;
    stats_.cache_hits = 0;
    stats_.cache_misses = 0;
    stats_.evictions_timeout = 0;
    stats_.evictions_lru = 0;

    LOG_INFO("NdpiFlowCache initialized: timeout=" << timeout_sec
             << "s, max_flows=" << (max_flows == 0 ? "unlimited" : std::to_string(max_flows)));
}

NdpiCachedFlow* NdpiFlowCache::getOrCreateFlow(const FiveTuple& ft) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string key = makeFlowKey(ft);

    auto it = flows_.find(key);
    if (it != flows_.end()) {
        // Cache hit - update last seen and packet count
        it->second.last_seen = std::chrono::system_clock::now();
        it->second.packet_count++;
        stats_.cache_hits++;
        return &it->second;
    }

    // Cache miss - create new flow
    stats_.cache_misses++;

    // Check if we need to evict flows
    if (max_flows_ > 0 && flows_.size() >= max_flows_) {
        evictOldestFlows();
    }

    // Create new cached flow
    auto [new_it, inserted] = flows_.emplace(key, NdpiCachedFlow());
    if (!inserted) {
        LOG_ERROR("Failed to insert new flow into cache");
        return nullptr;
    }

    stats_.total_flows++;
    LOG_TRACE("Created new flow cache entry: " << key);

    return &new_it->second;
}

size_t NdpiFlowCache::cleanupExpiredFlows(const Timestamp& now) {
    std::lock_guard<std::mutex> lock(mutex_);

    size_t evicted = 0;
    auto timeout_duration = std::chrono::seconds(timeout_sec_);

    auto it = flows_.begin();
    while (it != flows_.end()) {
        auto age = std::chrono::duration_cast<std::chrono::seconds>(
            now - it->second.last_seen);

        if (age > timeout_duration) {
            LOG_TRACE("Evicting expired flow: " << it->first
                     << " (age=" << age.count() << "s)");
            it = flows_.erase(it);
            evicted++;
            stats_.evictions_timeout++;
        } else {
            ++it;
        }
    }

    if (evicted > 0) {
        LOG_DEBUG("Cleaned up " << evicted << " expired flows");
    }

    return evicted;
}

size_t NdpiFlowCache::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return flows_.size();
}

void NdpiFlowCache::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    flows_.clear();
    LOG_INFO("Flow cache cleared");
}

NdpiFlowCache::Stats NdpiFlowCache::getStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    stats_.total_flows = flows_.size();
    return stats_;
}

void NdpiFlowCache::evictOldestFlows() {
    // Evict 10% of flows based on LRU (oldest last_seen)
    size_t to_evict = std::max(size_t(1), flows_.size() / 10);

    // Find oldest flows
    std::vector<std::pair<std::string, Timestamp>> flow_ages;
    flow_ages.reserve(flows_.size());

    for (const auto& [key, flow] : flows_) {
        flow_ages.emplace_back(key, flow.last_seen);
    }

    // Sort by timestamp (oldest first)
    std::sort(flow_ages.begin(), flow_ages.end(),
              [](const auto& a, const auto& b) {
                  return a.second < b.second;
              });

    // Evict oldest flows
    for (size_t i = 0; i < to_evict && i < flow_ages.size(); ++i) {
        flows_.erase(flow_ages[i].first);
        stats_.evictions_lru++;
    }

    LOG_DEBUG("Evicted " << to_evict << " flows via LRU");
}

std::string NdpiFlowCache::makeFlowKey(const FiveTuple& ft) {
    // Create a deterministic key from 5-tuple
    // Format: "proto:src_ip:src_port:dst_ip:dst_port"
    return std::to_string(ft.protocol) + ":" +
           ft.src_ip + ":" + std::to_string(ft.src_port) + ":" +
           ft.dst_ip + ":" + std::to_string(ft.dst_port);
}

}  // namespace callflow
