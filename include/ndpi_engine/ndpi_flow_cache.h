#pragma once

#include "common/types.h"
#include <map>
#include <memory>
#include <mutex>
#include <chrono>

// Forward declarations for nDPI structures
struct ndpi_flow_struct;
struct ndpi_id_struct;

namespace callflow {

/**
 * Cached flow entry for nDPI
 */
struct NdpiCachedFlow {
    std::unique_ptr<ndpi_flow_struct, void(*)(ndpi_flow_struct*)> flow;
    std::unique_ptr<ndpi_id_struct, void(*)(ndpi_id_struct*)> src_id;
    std::unique_ptr<ndpi_id_struct, void(*)(ndpi_id_struct*)> dst_id;
    Timestamp last_seen;
    size_t packet_count;

    // Constructor with custom deleters
    NdpiCachedFlow();
    ~NdpiCachedFlow() = default;

    // Move-only
    NdpiCachedFlow(NdpiCachedFlow&&) = default;
    NdpiCachedFlow& operator=(NdpiCachedFlow&&) = default;
    NdpiCachedFlow(const NdpiCachedFlow&) = delete;
    NdpiCachedFlow& operator=(const NdpiCachedFlow&) = delete;
};

/**
 * Flow cache for nDPI with LRU eviction
 *
 * Maintains a cache of nDPI flow structures keyed by 5-tuple to avoid
 * recreating them for every packet. Implements timeout-based eviction
 * and optional LRU-based size limits.
 */
class NdpiFlowCache {
public:
    /**
     * Construct flow cache
     * @param timeout_sec Flow timeout in seconds (default: 300)
     * @param max_flows Maximum number of cached flows (0 = unlimited)
     */
    explicit NdpiFlowCache(int timeout_sec = 300, size_t max_flows = 100000);
    ~NdpiFlowCache() = default;

    /**
     * Get or create a cached flow for the given 5-tuple
     * @param ft Five-tuple identifying the flow
     * @return Pointer to cached flow (never null)
     */
    NdpiCachedFlow* getOrCreateFlow(const FiveTuple& ft);

    /**
     * Clean up expired flows based on timeout
     * @param now Current timestamp
     * @return Number of flows evicted
     */
    size_t cleanupExpiredFlows(const Timestamp& now);

    /**
     * Get current number of cached flows
     */
    size_t size() const;

    /**
     * Clear all cached flows
     */
    void clear();

    /**
     * Get cache statistics
     */
    struct Stats {
        size_t total_flows;
        size_t cache_hits;
        size_t cache_misses;
        size_t evictions_timeout;
        size_t evictions_lru;
    };

    Stats getStats() const;

private:
    mutable std::mutex mutex_;
    int timeout_sec_;
    size_t max_flows_;

    // Flow cache: key is 5-tuple hash string
    std::map<std::string, NdpiCachedFlow> flows_;

    // Statistics
    mutable Stats stats_;

    /**
     * Evict oldest flows if cache is over limit
     */
    void evictOldestFlows();

    /**
     * Create flow key from 5-tuple
     */
    static std::string makeFlowKey(const FiveTuple& ft);
};

}  // namespace callflow
