#pragma once

#include "common/types.h"
#include "protocol_parsers/http2_parser.h"
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <vector>

namespace callflow {

/**
 * 5G SBA Interaction Event
 */
struct SbaInteraction {
    std::string service_name;      // e.g., "nudm-ueau"
    std::string api_name;          // e.g., "Get"
    std::string resource;          // e.g., "ue-contexts"
    std::string nf_type;           // e.g., "UDM", "AMF" (inferred)
    nlohmann::json request_body;
    nlohmann::json response_body;
    int status_code = 0;
    double latency_ms = 0.0;
    
    nlohmann::json toJson() const;
};

/**
 * 5G Service Based Architecture (SBA) Parser
 * Analyzes HTTP/2 streams to identify 5G core network interactions.
 */
class FiveGSbaParser {
public:
    FiveGSbaParser() = default;
    ~FiveGSbaParser() = default;

    /**
     * Parse a completed HTTP/2 stream to detect 5G SBA interaction
     * @param stream Completed HTTP/2 stream
     * @return SbaInteraction if detected, nullopt otherwise
     */
    std::optional<SbaInteraction> parse(const Http2Stream& stream);

    /**
     * Check if a path corresponds to a known 5G API
     */
    static bool isSbaApi(const std::string& path);

private:
    /**
     * Detect service name from path
     */
    std::string detectService(const std::string& path);
    
    /**
     * Infer NF type from service name
     */
    std::string inferNfType(const std::string& service_name);

    /**
     * Parse JSON payload
     */
    std::optional<nlohmann::json> parseJson(const std::vector<uint8_t>& data);
};

} // namespace callflow
