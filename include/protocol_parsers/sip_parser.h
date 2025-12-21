#pragma once

#include <map>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <vector>

#include "common/types.h"
#include "protocol_parsers/sip_3gpp_headers.h"

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
        uint16_t rtp_port = 0;
        uint16_t rtcp_port = 0;
        std::vector<std::string> media_descriptions;
        std::map<std::string, std::string> attributes;

        // NEW: IMS QoS preconditions (RFC 3312)
        std::optional<SipSdpQosPrecondition> qos_current_local;
        std::optional<SipSdpQosPrecondition> qos_current_remote;
        std::optional<SipSdpQosPrecondition> qos_desired_local;
        std::optional<SipSdpQosPrecondition> qos_desired_remote;

        // NEW: Bandwidth information
        SipSdpBandwidth bandwidth;

        // NEW: Codec information
        std::vector<SipSdpCodec> codecs;

        // NEW: Media direction
        std::optional<std::string> media_direction;  // sendrecv, sendonly, recvonly, inactive
    };
    std::optional<SdpInfo> sdp;

    // NEW: 3GPP P-headers (RFC 7315)
    std::optional<std::vector<SipPAssertedIdentity>> p_asserted_identity;
    std::optional<SipPAccessNetworkInfo> p_access_network_info;
    std::optional<std::string> p_visited_network_id;
    std::optional<SipPChargingVector> p_charging_vector;  // CRITICAL for billing
    std::optional<SipPChargingFunctionAddresses> p_charging_function_addresses;
    std::optional<SipPServedUser> p_served_user;
    std::optional<std::string> p_preferred_identity;
    std::optional<std::string> p_early_media;

    // NEW: IMS session timers (RFC 4028)
    std::optional<SipSessionExpires> session_expires;
    std::optional<uint32_t> min_se;

    // NEW: IMS routing headers
    std::vector<std::string> path;
    std::vector<std::string> service_route;
    std::vector<std::string> record_route;
    std::optional<std::string> route;

    // NEW: Feature negotiation
    std::vector<std::string> require;
    std::vector<std::string> supported;
    std::vector<std::string> allow;

    // NEW: Security headers (RFC 3329)
    std::optional<SipSecurityInfo> security_client;
    std::optional<SipSecurityInfo> security_server;
    std::optional<SipSecurityInfo> security_verify;

    // NEW: Privacy (RFC 3323)
    std::optional<SipPrivacy> privacy;

    // NEW: Geolocation (RFC 6442)
    std::optional<std::string> geolocation;
    std::optional<std::string> geolocation_routing;
    std::optional<std::string> geolocation_error;

    // NEW: Call transfer (REFER)
    std::optional<std::string> refer_to;
    std::optional<std::string> referred_by;
    std::optional<std::string> replaces;

    // NEW: Subscriptions (RFC 3265)
    std::optional<std::string> event;
    std::optional<SipSubscriptionState> subscription_state;

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

    // NEW: 3GPP P-header parsing
    void parsePHeaders(SipMessage& msg);
    void parseImsHeaders(SipMessage& msg);
    void parseSecurityHeaders(SipMessage& msg);
    void parseRoutingHeaders(SipMessage& msg);

    // NEW: Enhanced SDP parsing for IMS
    void parseSdpQosPreconditions(SipMessage::SdpInfo& sdp, const std::vector<std::string>& lines);
    void parseSdpBandwidth(SipMessage::SdpInfo& sdp, const std::vector<std::string>& lines);
    void parseSdpCodecs(SipMessage::SdpInfo& sdp, const std::vector<std::string>& lines);
    void parseSdpMediaDirection(SipMessage::SdpInfo& sdp, const std::vector<std::string>& lines);

    std::vector<std::string> splitLines(const std::string& text);
    std::pair<std::string, std::string> parseHeader(const std::string& line);
    static std::string trim(const std::string& str);
    static std::vector<std::string> splitCommaList(const std::string& str);
};

}  // namespace callflow
