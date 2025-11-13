#include "protocol_parsers/http2_parser.h"
#include "common/logger.h"

namespace callflow {

nlohmann::json Http2FrameHeader::toJson() const {
    nlohmann::json j;
    j["length"] = length;
    j["type"] = static_cast<int>(type);
    j["flags"] = flags;
    j["stream_id"] = stream_id;
    return j;
}

std::optional<Http2FrameHeader> Http2Parser::parse(const uint8_t* data, size_t len) {
    // TODO: Implement HTTP/2 parsing in M4
    LOG_DEBUG("HTTP/2 parsing not yet implemented (placeholder for M1)");
    return std::nullopt;
}

bool Http2Parser::isHttp2(const uint8_t* data, size_t len) {
    if (!data || len < 24) {
        return false;
    }

    // Check for HTTP/2 connection preface: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    const char* preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    return memcmp(data, preface, 24) == 0;
}

}  // namespace callflow
