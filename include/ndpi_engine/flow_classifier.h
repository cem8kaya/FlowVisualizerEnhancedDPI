#pragma once

#include "common/types.h"

namespace callflow {

/**
 * Flow classifier (placeholder for M1)
 */
class FlowClassifier {
public:
    FlowClassifier() = default;
    ~FlowClassifier() = default;

    ProtocolType classify(const FiveTuple& ft, const uint8_t* data, size_t len);
};

}  // namespace callflow
