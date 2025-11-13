#include "protocol_parsers/sip_parser.h"
#include "common/logger.h"
#include "common/utils.h"
#include <algorithm>
#include <sstream>
#include <cctype>

namespace callflow {

nlohmann::json SipMessage::toJson() const {
    nlohmann::json j;

    j["is_request"] = is_request;

    if (is_request) {
        j["method"] = method;
        j["request_uri"] = request_uri;
    } else {
        j["status_code"] = status_code;
        j["reason_phrase"] = reason_phrase;
    }

    j["call_id"] = call_id;
    j["from"] = from;
    j["to"] = to;
    j["via"] = via;
    j["contact"] = contact;
    j["cseq"] = cseq;

    if (!content_type.empty()) {
        j["content_type"] = content_type;
    }

    if (!headers.empty()) {
        j["headers"] = headers;
    }

    if (sdp.has_value()) {
        nlohmann::json sdp_json;
        sdp_json["session_name"] = sdp->session_name;
        sdp_json["connection_address"] = sdp->connection_address;
        sdp_json["rtp_port"] = sdp->rtp_port;
        sdp_json["rtcp_port"] = sdp->rtcp_port;
        sdp_json["media_descriptions"] = sdp->media_descriptions;
        sdp_json["attributes"] = sdp->attributes;
        j["sdp"] = sdp_json;
    }

    return j;
}

std::optional<SipMessage> SipParser::parse(const uint8_t* data, size_t len) {
    if (!data || len == 0) {
        return std::nullopt;
    }

    // Convert to string
    std::string text(reinterpret_cast<const char*>(data), len);

    // Split into lines
    auto lines = splitLines(text);
    if (lines.empty()) {
        return std::nullopt;
    }

    SipMessage msg;

    // Parse first line (request or status)
    const std::string& first_line = lines[0];
    if (first_line.find("SIP/2.0") == 0) {
        // Status line (response)
        if (!parseStatusLine(first_line, msg)) {
            return std::nullopt;
        }
        msg.is_request = false;
    } else if (first_line.find("SIP/2.0") != std::string::npos) {
        // Request line
        if (!parseRequestLine(first_line, msg)) {
            return std::nullopt;
        }
        msg.is_request = true;
    } else {
        LOG_DEBUG("Not a valid SIP message: " << first_line);
        return std::nullopt;
    }

    // Find empty line separating headers from body
    size_t body_start = 0;
    for (size_t i = 1; i < lines.size(); ++i) {
        if (lines[i].empty() || lines[i] == "\r") {
            body_start = i + 1;
            break;
        }
    }

    // Parse headers
    std::vector<std::string> header_lines(lines.begin() + 1,
                                           body_start > 0 ? lines.begin() + body_start : lines.end());
    parseHeaders(header_lines, msg);

    // Parse body if present
    if (body_start > 0 && body_start < lines.size()) {
        std::ostringstream body_stream;
        for (size_t i = body_start; i < lines.size(); ++i) {
            body_stream << lines[i] << "\n";
        }
        msg.body = body_stream.str();

        // Parse SDP if Content-Type is application/sdp
        if (msg.content_type.find("application/sdp") != std::string::npos) {
            parseSdp(msg.body, msg);
        }
    }

    return msg;
}

bool SipParser::isSipMessage(const uint8_t* data, size_t len) {
    if (!data || len < 8) {
        return false;
    }

    std::string text(reinterpret_cast<const char*>(data), std::min(len, size_t(200)));

    // Check for SIP methods or status line
    return text.find("SIP/2.0") != std::string::npos &&
           (text.find("INVITE") == 0 || text.find("ACK") == 0 ||
            text.find("BYE") == 0 || text.find("CANCEL") == 0 ||
            text.find("OPTIONS") == 0 || text.find("REGISTER") == 0 ||
            text.find("UPDATE") == 0 || text.find("PRACK") == 0 ||
            text.find("SIP/2.0") == 0);
}

std::optional<std::string> SipParser::extractCallId(const uint8_t* data, size_t len) {
    if (!data || len == 0) {
        return std::nullopt;
    }

    std::string text(reinterpret_cast<const char*>(data), len);

    // Look for Call-ID header
    size_t pos = text.find("Call-ID:");
    if (pos == std::string::npos) {
        pos = text.find("i:");  // Compact form
    }

    if (pos == std::string::npos) {
        return std::nullopt;
    }

    // Find end of line
    size_t eol = text.find('\n', pos);
    if (eol == std::string::npos) {
        eol = text.length();
    }

    std::string line = text.substr(pos, eol - pos);

    // Extract value after colon
    size_t colon = line.find(':');
    if (colon == std::string::npos) {
        return std::nullopt;
    }

    std::string call_id = line.substr(colon + 1);
    return trim(call_id);
}

MessageType SipParser::getMessageType(const SipMessage& msg) {
    if (msg.is_request) {
        if (msg.method == "INVITE") return MessageType::SIP_INVITE;
        if (msg.method == "ACK") return MessageType::SIP_ACK;
        if (msg.method == "BYE") return MessageType::SIP_BYE;
        if (msg.method == "CANCEL") return MessageType::SIP_CANCEL;
        if (msg.method == "REGISTER") return MessageType::SIP_REGISTER;
        if (msg.method == "OPTIONS") return MessageType::SIP_OPTIONS;
        if (msg.method == "UPDATE") return MessageType::SIP_UPDATE;
        if (msg.method == "PRACK") return MessageType::SIP_PRACK;
    } else {
        if (msg.status_code == 100) return MessageType::SIP_TRYING;
        if (msg.status_code == 180) return MessageType::SIP_RINGING;
        if (msg.status_code == 200) return MessageType::SIP_OK;
    }
    return MessageType::UNKNOWN;
}

bool SipParser::parseRequestLine(const std::string& line, SipMessage& msg) {
    // Format: METHOD request-URI SIP/2.0
    std::istringstream iss(line);
    std::string sip_version;

    if (!(iss >> msg.method >> msg.request_uri >> sip_version)) {
        return false;
    }

    return sip_version == "SIP/2.0";
}

bool SipParser::parseStatusLine(const std::string& line, SipMessage& msg) {
    // Format: SIP/2.0 status-code reason-phrase
    std::istringstream iss(line);
    std::string sip_version;

    if (!(iss >> sip_version >> msg.status_code)) {
        return false;
    }

    // Read rest of line as reason phrase
    std::getline(iss, msg.reason_phrase);
    msg.reason_phrase = trim(msg.reason_phrase);

    return sip_version == "SIP/2.0";
}

void SipParser::parseHeaders(const std::vector<std::string>& lines, SipMessage& msg) {
    for (const auto& line : lines) {
        if (line.empty()) continue;

        auto [name, value] = parseHeader(line);

        // Store common headers
        if (name == "Call-ID" || name == "i") {
            msg.call_id = value;
        } else if (name == "From" || name == "f") {
            msg.from = value;
        } else if (name == "To" || name == "t") {
            msg.to = value;
        } else if (name == "Via" || name == "v") {
            msg.via = value;
        } else if (name == "Contact" || name == "m") {
            msg.contact = value;
        } else if (name == "CSeq") {
            msg.cseq = value;
        } else if (name == "Content-Type" || name == "c") {
            msg.content_type = value;
        }

        // Store all headers
        msg.headers[name] = value;
    }
}

void SipParser::parseSdp(const std::string& body, SipMessage& msg) {
    SipMessage::SdpInfo sdp;

    auto lines = splitLines(body);
    for (const auto& line : lines) {
        if (line.length() < 2 || line[1] != '=') continue;

        char type = line[0];
        std::string value = line.substr(2);

        switch (type) {
            case 's':  // Session name
                sdp.session_name = value;
                break;
            case 'c':  // Connection information
                // Format: c=IN IP4 192.168.1.1
                if (value.find("IP4") != std::string::npos) {
                    size_t pos = value.rfind(' ');
                    if (pos != std::string::npos) {
                        sdp.connection_address = value.substr(pos + 1);
                    }
                }
                break;
            case 'm':  // Media description
                sdp.media_descriptions.push_back(value);
                // Extract RTP port: m=audio 49170 RTP/AVP 0
                {
                    std::istringstream iss(value);
                    std::string media_type;
                    uint16_t port;
                    if (iss >> media_type >> port) {
                        if (media_type == "audio" || media_type == "video") {
                            sdp.rtp_port = port;
                            sdp.rtcp_port = port + 1;  // RTCP typically uses next port
                        }
                    }
                }
                break;
            case 'a':  // Attribute
                {
                    size_t colon = value.find(':');
                    if (colon != std::string::npos) {
                        sdp.attributes[value.substr(0, colon)] = value.substr(colon + 1);
                    } else {
                        sdp.attributes[value] = "";
                    }
                }
                break;
        }
    }

    msg.sdp = sdp;
}

std::vector<std::string> SipParser::splitLines(const std::string& text) {
    std::vector<std::string> lines;
    std::istringstream stream(text);
    std::string line;

    while (std::getline(stream, line)) {
        // Remove \r if present
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        lines.push_back(line);
    }

    return lines;
}

std::pair<std::string, std::string> SipParser::parseHeader(const std::string& line) {
    size_t colon = line.find(':');
    if (colon == std::string::npos) {
        return {"", ""};
    }

    std::string name = trim(line.substr(0, colon));
    std::string value = trim(line.substr(colon + 1));

    return {name, value};
}

std::string SipParser::trim(const std::string& str) {
    size_t start = 0;
    size_t end = str.length();

    while (start < end && std::isspace(static_cast<unsigned char>(str[start]))) {
        ++start;
    }

    while (end > start && std::isspace(static_cast<unsigned char>(str[end - 1]))) {
        --end;
    }

    return str.substr(start, end - start);
}

}  // namespace callflow
