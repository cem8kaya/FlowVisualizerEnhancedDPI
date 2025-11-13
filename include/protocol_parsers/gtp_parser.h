#pragma once

#include "common/types.h"
#include <optional>
#include <nlohmann/json.hpp>

namespace callflow {

/**
 * GTP message types (GTPv2-C)
 */
enum class GtpMessageType {
    ECHO_REQUEST = 1,
    ECHO_RESPONSE = 2,
    CREATE_SESSION_REQUEST = 32,
    CREATE_SESSION_RESPONSE = 33,
    DELETE_SESSION_REQUEST = 36,
    DELETE_SESSION_RESPONSE = 37,
    MODIFY_BEARER_REQUEST = 34,
    MODIFY_BEARER_RESPONSE = 35
};

/**
 * GTP header structure
 */
struct GtpHeader {
    uint8_t version;
    bool piggybacking;
    bool teid_present;
    uint8_t message_type;
    uint16_t message_length;
    uint32_t teid;  // Tunnel Endpoint Identifier
    uint32_t sequence_number;

    nlohmann::json toJson() const;
};

/**
 * GTP parser (placeholder for M1, full implementation in M3)
 */
class GtpParser {
public:
    GtpParser() = default;
    ~GtpParser() = default;

    std::optional<GtpHeader> parse(const uint8_t* data, size_t len);
    static bool isGtp(const uint8_t* data, size_t len);
};

}  // namespace callflow
