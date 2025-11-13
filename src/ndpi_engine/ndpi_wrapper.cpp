#include "ndpi_engine/ndpi_wrapper.h"
#include "common/logger.h"

namespace callflow {

NdpiWrapper::NdpiWrapper() : ndpi_struct_(nullptr), initialized_(false) {}

NdpiWrapper::~NdpiWrapper() {
    shutdown();
}

bool NdpiWrapper::initialize() {
    LOG_INFO("nDPI wrapper initialized (placeholder for M1)");
    initialized_ = true;
    return true;
}

ProtocolType NdpiWrapper::classifyPacket(const uint8_t* data, size_t len, const FiveTuple& ft) {
    // TODO: Implement nDPI classification in M2
    // For now, use simple port-based heuristics
    if (ft.src_port == 5060 || ft.dst_port == 5060) {
        return ProtocolType::SIP;
    }

    return ProtocolType::UNKNOWN;
}

void NdpiWrapper::shutdown() {
    if (initialized_) {
        LOG_INFO("nDPI wrapper shutdown");
        initialized_ = false;
    }
}

}  // namespace callflow
