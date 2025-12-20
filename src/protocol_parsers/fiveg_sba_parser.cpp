#include "protocol_parsers/fiveg_sba_parser.h"

#include <regex>

#include "common/logger.h"

namespace callflow {

nlohmann::json SbaInteraction::toJson() const {
    nlohmann::json j;
    j["service"] = service_name;
    j["api"] = api_name;
    j["resource"] = resource;
    j["nf_type"] = nf_type;
    j["status"] = status_code;
    j["latency_ms"] = latency_ms;

    if (!request_body.empty())
        j["request"] = request_body;
    if (!response_body.empty())
        j["response"] = response_body;

    return j;
}

std::optional<SbaInteraction> FiveGSbaParser::parse(const Http2Stream& stream) {
    if (stream.method.empty() || stream.path.empty()) {
        return std::nullopt;
    }

    // Check if it's a 5G API
    if (!isSbaApi(stream.path)) {
        return std::nullopt;
    }

    SbaInteraction interaction;
    interaction.service_name = detectService(stream.path);
    interaction.nf_type = inferNfType(interaction.service_name);
    interaction.api_name = stream.method;  // e.g., GET, POST, PUT
    interaction.status_code = stream.status_code;

    // Extract resource from path (simplified)
    // Path format: /<service-name>/<version>/<resource>
    size_t second_slash = stream.path.find('/', 1);
    if (second_slash != std::string::npos) {
        size_t third_slash = stream.path.find('/', second_slash + 1);
        if (third_slash != std::string::npos) {
            interaction.resource = stream.path.substr(third_slash + 1);
        }
    }

    // Parse bodies
    // NOTE: Http2Stream needs to separate request data from response data if they were interleaved
    // in the parser. However, Http2Stream structure currently has just 'data'. Usually, for a
    // specific stream ID:
    // - Client sends HEADERS (+ DATA) -> Request
    // - Server sends HEADERS (+ DATA) -> Response
    // We need to differentiate direction.
    // The current Http2Stream struct stores "data" as a single vector.
    // We need to modify Http2Stream to store request_data and response_data separately logic wise,
    // OR we assume the parser separates them.
    // **CRITICAL**: The current Http2Stream implementation in `http2_parser.h` provides
    // `std::vector<uint8_t> data`. We will assume "data" contains the RESPONSE data because
    // typically we capture the response for analysis, OR better, we need to fix Http2Stream to
    // separate them.
    //
    // For now, let's assume `stream.data` *is* the body of the message that just finished (Response
    // usually). If we want both request and response bodies, we need to track them separately in
    // Http2Stream. I will implement separation in Http2Parser changes. I will assume
    // `stream.request_data` and `stream.response_data` exist in the modified `Http2Stream`.

    // Logic for now (will compile error until we fix Http2Stream):
    // I will assume I add `request_data` and `response_data` to Http2Stream.

    // Wait, let's stick to what we have or plan to modify.
    // Plan said: "Ensure `data` accumulates all DATA frames payloads."
    // If I want full SBA interaction, I need both.
    // I will access `stream.request_data` and `stream.response_data`.

    // Fallback if I can't modify `Http2Stream` right now (I can, I am in EXECUTION).
    // I will write this assuming `request_data` and `response_data` members.

    if (!stream.request_data.empty()) {
        auto json = parseJson(stream.request_data);
        if (json)
            interaction.request_body = *json;
    }

    if (!stream.response_data.empty()) {
        auto json = parseJson(stream.response_data);
        if (json)
            interaction.response_body = *json;
    }

    return interaction;
}

bool FiveGSbaParser::isSbaApi(const std::string& path) {
    // 5G APIs typically start with /n<name>/...
    // e.g., /namf-comm/, /nudm-ueau/, /nrf-nfmanagement/, /nnrf-nfm/
    return path.size() > 2 && path[0] == '/' && path[1] == 'n';
}

std::string FiveGSbaParser::detectService(const std::string& path) {
    // Extract first segment after /
    // /namf-comm/v1/... -> namf-comm
    size_t start = 1;
    size_t end = path.find('/', start);
    if (end == std::string::npos)
        return path.substr(start);
    return path.substr(start, end - start);
}

std::string FiveGSbaParser::inferNfType(const std::string& service_name) {
    if (service_name.find("namf") == 0)
        return "AMF";
    if (service_name.find("nudm") == 0)
        return "UDM";
    if (service_name.find("nsmf") == 0)
        return "SMF";
    if (service_name.find("nausf") == 0)
        return "AUSF";
    if (service_name.find("nnrf") == 0)
        return "NRF";
    if (service_name.find("nnef") == 0)
        return "NEF";
    if (service_name.find("npcf") == 0)
        return "PCF";
    if (service_name.find("nupf") == 0)
        return "UPF";  // Rare via SBI control
    if (service_name.find("nslcef") == 0)
        return "SLC";
    return "Unknown-NF";
}

std::optional<nlohmann::json> FiveGSbaParser::parseJson(const std::vector<uint8_t>& data) {
    try {
        return nlohmann::json::parse(data.begin(), data.end());
    } catch (...) {
        return std::nullopt;
    }
}

}  // namespace callflow
