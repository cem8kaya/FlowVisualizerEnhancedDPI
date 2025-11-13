#pragma once

#include "common/types.h"
#include <optional>
#include <nlohmann/json.hpp>

namespace callflow {

/**
 * DIAMETER header structure
 */
struct DiameterHeader {
    uint8_t version;
    uint32_t message_length;
    bool request_flag;
    bool proxiable_flag;
    bool error_flag;
    uint32_t command_code;
    uint32_t application_id;
    uint32_t hop_by_hop_id;
    uint32_t end_to_end_id;

    nlohmann::json toJson() const;
};

/**
 * DIAMETER parser (placeholder for M1, full implementation in M3)
 */
class DiameterParser {
public:
    DiameterParser() = default;
    ~DiameterParser() = default;

    std::optional<DiameterHeader> parse(const uint8_t* data, size_t len);
    static bool isDiameter(const uint8_t* data, size_t len);
};

}  // namespace callflow
