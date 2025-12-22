#pragma once

#include "common/types.h"
#include "ndpi_engine/ndpi_flow_cache.h"
#include <memory>

namespace callflow {

/**
 * nDPI wrapper with flow caching (M2 implementation enhanced in M3)
 */
class NdpiWrapper {
public:
    NdpiWrapper();
    ~NdpiWrapper();

    /**
     * Initialize nDPI engine
     */
    bool initialize();

    /**
     * Classify a packet using cached flow state
     */
    ProtocolType classifyPacket(const uint8_t* data, size_t len, const FiveTuple& ft);

    /**
     * Clean up expired flows from cache
     */
    size_t cleanupExpiredFlows();

    /**
     * Get flow cache statistics
     */
    NdpiFlowCache::Stats getCacheStats() const;

    /**
     * Shutdown nDPI engine
     */
    void shutdown();

private:
    /**
     * Map nDPI protocol name to ProtocolType
     */
    ProtocolType mapNdpiProtocol(const std::string& ndpi_proto_name);

    /**
     * Fallback classification using port-based heuristics
     */
    ProtocolType fallbackClassification(const FiveTuple& ft);

    [[maybe_unused]] void* ndpi_struct_;  // Opaque pointer to nDPI structure
    bool initialized_;
    std::unique_ptr<NdpiFlowCache> flow_cache_;  // Flow cache for performance
};

}  // namespace callflow
