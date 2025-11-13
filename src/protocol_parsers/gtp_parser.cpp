#include "protocol_parsers/gtp_parser.h"
#include "common/logger.h"

namespace callflow {

nlohmann::json GtpHeader::toJson() const {
    nlohmann::json j;
    j["version"] = version;
    j["message_type"] = message_type;
    j["teid"] = teid;
    return j;
}

std::optional<GtpHeader> GtpParser::parse(const uint8_t* data, size_t len) {
    // TODO: Implement GTP parsing in M3
    LOG_DEBUG("GTP parsing not yet implemented (placeholder for M1)");
    return std::nullopt;
}

bool GtpParser::isGtp(const uint8_t* data, size_t len) {
    if (!data || len < 8) {
        return false;
    }

    // Check for GTPv2 (version 2) on port 2123
    uint8_t flags = data[0];
    uint8_t version = (flags >> 5) & 0x07;

    return version == 2;
}

}  // namespace callflow
