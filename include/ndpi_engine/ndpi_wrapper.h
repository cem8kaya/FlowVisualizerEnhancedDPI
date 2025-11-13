#pragma once

#include "common/types.h"
#include <memory>

namespace callflow {

/**
 * nDPI wrapper (placeholder for M1, full implementation in M2)
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
     * Classify a packet
     */
    ProtocolType classifyPacket(const uint8_t* data, size_t len, const FiveTuple& ft);

    /**
     * Shutdown nDPI engine
     */
    void shutdown();

private:
    void* ndpi_struct_;  // Opaque pointer to nDPI structure
    bool initialized_;
};

}  // namespace callflow
