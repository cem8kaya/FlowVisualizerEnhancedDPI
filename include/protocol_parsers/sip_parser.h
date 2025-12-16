#pragma once

#include <map>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>

#include "common/types.h"

namespace callflow {

/**
 * SIP message structure
 */
struct SipMessage {
    // Request or response
    bool is_request;

    // Request line
    std::string method;  // INVITE, ACK, BYE, etc.
    std::string request_uri;

    // Status line
    int status_code;
    std::string reason_phrase;

    // Headers
    std::string call_id;
    std::string from;
    std::string to;
    std::string via;
    std::string contact;
    std::string cseq;
    std::string content_type;

    // Additional headers
    std::map<std::string, std::string> headers;

    // Body (SDP, etc.)
    std::string body;

    // Parsed SDP (if present)
    struct SdpInfo {
        std::string session_name;
        std::string connection_address;
        uint16_t rtp_port;
        uint16_t rtcp_port;
        std::vector<std::string> media_descriptions;
        std::map<std::string, std::string> attributes;
    };
    std::optional<SdpInfo> sdp;

    // Convert to JSON
    nlohmann::json toJson() const;
};

/**
 * SIP protocol parser
 */
class SipParser {
public:
    SipParser() = default;
    ~SipParser() = default;

    /**
     * Parse SIP message from packet payload
     * @param data Packet payload data
     * @param len Payload length
     * @return Parsed SIP message or nullopt if parsing fails
     */
    std::optional<SipMessage> parse(const uint8_t* data, size_t len);

    /**
     * Check if data appears to be a SIP message
     */
    static bool isSipMessage(const uint8_t* data, size_t len);

    /**
     * Extract Call-ID from SIP message (quick extraction without full parsing)
     */
    static std::optional<std::string> extractCallId(const uint8_t* data, size_t len);

    /**
     * Determine message type from SIP message
     */
    static MessageType getMessageType(const SipMessage& msg);

private:
    bool parseRequestLine(const std::string& line, SipMessage& msg);
    bool parseStatusLine(const std::string& line, SipMessage& msg);
    void parseHeaders(const std::vector<std::string>& lines, SipMessage& msg);
    void parseSdp(const std::string& body, SipMessage& msg);

    std::vector<std::string> splitLines(const std::string& text);
    std::pair<std::string, std::string> parseHeader(const std::string& line);
    static std::string trim(const std::string& str);
};

}  // namespace callflow
