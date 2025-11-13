#include "protocol_parsers/diameter_parser.h"
#include "common/logger.h"

namespace callflow {

nlohmann::json DiameterHeader::toJson() const {
    nlohmann::json j;
    j["version"] = version;
    j["command_code"] = command_code;
    j["application_id"] = application_id;
    return j;
}

std::optional<DiameterHeader> DiameterParser::parse(const uint8_t* data, size_t len) {
    // TODO: Implement DIAMETER parsing in M3
    LOG_DEBUG("DIAMETER parsing not yet implemented (placeholder for M1)");
    return std::nullopt;
}

bool DiameterParser::isDiameter(const uint8_t* data, size_t len) {
    if (!data || len < 20) {
        return false;
    }

    // Check version (should be 1)
    uint8_t version = data[0];
    return version == 1;
}

}  // namespace callflow
