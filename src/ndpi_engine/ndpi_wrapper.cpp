#include "ndpi_engine/ndpi_wrapper.h"
#include "common/logger.h"

// Only include nDPI if available
#ifdef NDPI_INCLUDE_DIR
#include <ndpi_api.h>
#include <ndpi_typedefs.h>
#include <ndpi_protocol_ids.h>
#endif

#include <cstring>

namespace callflow {

NdpiWrapper::NdpiWrapper() : ndpi_struct_(nullptr), initialized_(false) {
    // Initialize flow cache (300 second timeout, 100K max flows)
    flow_cache_ = std::make_unique<NdpiFlowCache>(300, 100000);
}

NdpiWrapper::~NdpiWrapper() {
    shutdown();
}

bool NdpiWrapper::initialize() {
#ifdef NDPI_INCLUDE_DIR
    LOG_INFO("Initializing nDPI engine...");

    // Initialize nDPI detection module
    auto* ndpi_struct = ndpi_init_detection_module(nullptr);
    if (!ndpi_struct) {
        LOG_ERROR("Failed to initialize nDPI detection module");
        return false;
    }

    // Set all protocols
    NDPI_PROTOCOL_BITMASK all;
    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(ndpi_struct, &all);

    // Finalize initialization
    ndpi_finalize_initialization(ndpi_struct);

    ndpi_struct_ = static_cast<void*>(ndpi_struct);
    initialized_ = true;

    LOG_INFO("nDPI engine initialized successfully with flow caching");
    return true;
#else
    LOG_WARN("nDPI not available, using port-based heuristics");
    initialized_ = true;
    return true;
#endif
}

ProtocolType NdpiWrapper::classifyPacket(const uint8_t* data, size_t len, const FiveTuple& ft) {
    if (!initialized_) {
        return ProtocolType::UNKNOWN;
    }

#ifdef NDPI_INCLUDE_DIR
    if (ndpi_struct_ && len > 0 && flow_cache_) {
        auto* ndpi_struct = static_cast<struct ndpi_detection_module_struct*>(ndpi_struct_);

        // Get or create cached flow for this 5-tuple
        NdpiCachedFlow* cached_flow = flow_cache_->getOrCreateFlow(ft);
        if (!cached_flow || !cached_flow->flow || !cached_flow->src_id || !cached_flow->dst_id) {
            LOG_ERROR("Failed to get cached flow");
            return fallbackClassification(ft);
        }

        // Classify packet using cached flow state
        ndpi_protocol detected = ndpi_detection_process_packet(
            ndpi_struct,
            cached_flow->flow.get(),
            data, len,
            0,  // timestamp
            cached_flow->src_id.get(),
            cached_flow->dst_id.get()
        );

        ProtocolType result = ProtocolType::UNKNOWN;

        // Map nDPI protocol to our ProtocolType
        if (detected.master_protocol != NDPI_PROTOCOL_UNKNOWN) {
            const char* proto_name = ndpi_get_proto_name(ndpi_struct, detected.master_protocol);
            if (proto_name) {
                LOG_TRACE("nDPI detected (master): " << proto_name);
                result = mapNdpiProtocol(proto_name);
            }
        }

        if (result == ProtocolType::UNKNOWN && detected.app_protocol != NDPI_PROTOCOL_UNKNOWN) {
            const char* proto_name = ndpi_get_proto_name(ndpi_struct, detected.app_protocol);
            if (proto_name) {
                LOG_TRACE("nDPI detected (app): " << proto_name);
                result = mapNdpiProtocol(proto_name);
            }
        }

        if (result != ProtocolType::UNKNOWN) {
            return result;
        }
    }
#endif

    // Fallback to port-based heuristics
    return fallbackClassification(ft);
}

void NdpiWrapper::shutdown() {
    if (initialized_) {
#ifdef NDPI_INCLUDE_DIR
        if (ndpi_struct_) {
            auto* ndpi_struct = static_cast<struct ndpi_detection_module_struct*>(ndpi_struct_);
            ndpi_exit_detection_module(ndpi_struct);
            ndpi_struct_ = nullptr;
        }
        LOG_INFO("nDPI engine shutdown");
#else
        LOG_INFO("nDPI wrapper shutdown (heuristics mode)");
#endif
        initialized_ = false;
    }
}

ProtocolType NdpiWrapper::mapNdpiProtocol(const std::string& ndpi_proto_name) {
    // Map nDPI protocol names to our ProtocolType enum
    if (ndpi_proto_name == "SIP") return ProtocolType::SIP;
    if (ndpi_proto_name == "RTP") return ProtocolType::RTP;
    if (ndpi_proto_name == "RTCP") return ProtocolType::RTCP;
    if (ndpi_proto_name == "HTTP" || ndpi_proto_name == "HTTP_Proxy") return ProtocolType::HTTP;
    if (ndpi_proto_name == "HTTP2") return ProtocolType::HTTP2;
    if (ndpi_proto_name == "DNS") return ProtocolType::DNS;
    if (ndpi_proto_name == "GTP") return ProtocolType::GTP_C;
    if (ndpi_proto_name == "DIAMETER") return ProtocolType::DIAMETER;
    if (ndpi_proto_name == "SCTP") return ProtocolType::SCTP;
    if (ndpi_proto_name == "TLS" || ndpi_proto_name == "SSL") return ProtocolType::TCP;

    return ProtocolType::UNKNOWN;
}

ProtocolType NdpiWrapper::fallbackClassification(const FiveTuple& ft) {
    // Port-based heuristics as fallback
    if (ft.src_port == 5060 || ft.dst_port == 5060) {
        return ProtocolType::SIP;
    }

    // RTP typically uses even ports in range 10000-65535
    if ((ft.src_port >= 10000 && ft.src_port % 2 == 0) ||
        (ft.dst_port >= 10000 && ft.dst_port % 2 == 0)) {
        return ProtocolType::RTP;
    }

    // DNS
    if (ft.src_port == 53 || ft.dst_port == 53) {
        return ProtocolType::DNS;
    }

    // HTTP
    if (ft.src_port == 80 || ft.dst_port == 80 ||
        ft.src_port == 8080 || ft.dst_port == 8080) {
        return ProtocolType::HTTP;
    }

    // HTTPS (TLS)
    if (ft.src_port == 443 || ft.dst_port == 443) {
        return ProtocolType::TCP;  // Encrypted, can't determine application
    }

    // GTP-C
    if (ft.src_port == 2123 || ft.dst_port == 2123) {
        return ProtocolType::GTP_C;
    }

    // GTP-U
    if (ft.src_port == 2152 || ft.dst_port == 2152) {
        return ProtocolType::GTP_U;
    }

    // DIAMETER
    if (ft.src_port == 3868 || ft.dst_port == 3868) {
        return ProtocolType::DIAMETER;
    }

    return ProtocolType::UNKNOWN;
}

size_t NdpiWrapper::cleanupExpiredFlows() {
    if (flow_cache_) {
        auto now = std::chrono::system_clock::now();
        return flow_cache_->cleanupExpiredFlows(now);
    }
    return 0;
}

NdpiFlowCache::Stats NdpiWrapper::getCacheStats() const {
    if (flow_cache_) {
        return flow_cache_->getStats();
    }
    return NdpiFlowCache::Stats{};
}

}  // namespace callflow
