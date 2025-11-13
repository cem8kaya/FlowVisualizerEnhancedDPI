#include "ndpi_engine/flow_classifier.h"

namespace callflow {

ProtocolType FlowClassifier::classify(const FiveTuple& ft, const uint8_t* data, size_t len) {
    // Simple port-based classification for M1
    if (ft.src_port == 5060 || ft.dst_port == 5060) {
        return ProtocolType::SIP;
    }

    return ProtocolType::UNKNOWN;
}

}  // namespace callflow
