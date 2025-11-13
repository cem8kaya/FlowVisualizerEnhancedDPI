#pragma once

#include "common/types.h"
#include <optional>
#include <nlohmann/json.hpp>

namespace callflow {

/**
 * HTTP/2 frame types
 */
enum class Http2FrameType {
    DATA = 0x0,
    HEADERS = 0x1,
    PRIORITY = 0x2,
    RST_STREAM = 0x3,
    SETTINGS = 0x4,
    PUSH_PROMISE = 0x5,
    PING = 0x6,
    GOAWAY = 0x7,
    WINDOW_UPDATE = 0x8,
    CONTINUATION = 0x9
};

/**
 * HTTP/2 frame header
 */
struct Http2FrameHeader {
    uint32_t length;
    Http2FrameType type;
    uint8_t flags;
    uint32_t stream_id;

    nlohmann::json toJson() const;
};

/**
 * HTTP/2 parser (placeholder for M1, full implementation in M4)
 */
class Http2Parser {
public:
    Http2Parser() = default;
    ~Http2Parser() = default;

    std::optional<Http2FrameHeader> parse(const uint8_t* data, size_t len);
    static bool isHttp2(const uint8_t* data, size_t len);
};

}  // namespace callflow
