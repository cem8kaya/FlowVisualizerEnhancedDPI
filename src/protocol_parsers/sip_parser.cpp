#include "protocol_parsers/sip_parser.h"

#include <algorithm>
#include <cctype>
#include <sstream>

#include "common/logger.h"
#include "common/utils.h"

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

    // NEW: 3GPP P-headers
    if (p_asserted_identity.has_value()) {
        nlohmann::json pai_array = nlohmann::json::array();
        for (const auto& identity : p_asserted_identity.value()) {
            nlohmann::json id;
            if (!identity.display_name.empty()) {
                id["display_name"] = identity.display_name;
            }
            id["uri"] = identity.uri;

            // Extract username (potential IMSI)
            size_t sip_prefix = identity.uri.find("sip:");
            size_t at_pos = identity.uri.find('@');
            if (sip_prefix != std::string::npos && at_pos != std::string::npos) {
                id["username"] = identity.uri.substr(sip_prefix + 4, at_pos - (sip_prefix + 4));
            } else if (sip_prefix != std::string::npos) {
                id["username"] = identity.uri.substr(sip_prefix + 4);
            }

            pai_array.push_back(id);
        }
        j["p_asserted_identity"] = pai_array;
    }

    if (!p_associated_uri.empty()) {
        j["p_associated_uri"] = p_associated_uri;
    }

    if (authorization.has_value()) {
        j["authorization"] = authorization.value();

        // Extract username from Authorization header
        // Authorization: Digest username="20801...", realm="..."
        std::string auth = authorization.value();
        size_t user_pos = auth.find("username=\"");
        if (user_pos != std::string::npos) {
            size_t end_pos = auth.find("\"", user_pos + 10);
            if (end_pos != std::string::npos) {
                j["authorization_username"] = auth.substr(user_pos + 10, end_pos - (user_pos + 10));
            }
        }
    }

    if (p_access_network_info.has_value()) {
        nlohmann::json pani;
        pani["access_type"] =
            SipPAccessNetworkInfo::accessTypeToString(p_access_network_info->access_type);
        if (p_access_network_info->cell_id.has_value()) {
            pani["cell_id"] = p_access_network_info->cell_id.value();
        }
        if (!p_access_network_info->parameters.empty()) {
            pani["parameters"] = p_access_network_info->parameters;
        }
        j["p_access_network_info"] = pani;
    }

    if (p_visited_network_id.has_value()) {
        j["p_visited_network_id"] = p_visited_network_id.value();
    }

    if (p_charging_vector.has_value()) {
        nlohmann::json pcv;
        pcv["icid_value"] = p_charging_vector->icid_value;
        if (p_charging_vector->icid_generated_at.has_value()) {
            pcv["icid_generated_at"] = p_charging_vector->icid_generated_at.value();
        }
        if (p_charging_vector->orig_ioi.has_value()) {
            pcv["orig_ioi"] = p_charging_vector->orig_ioi.value();
        }
        if (p_charging_vector->term_ioi.has_value()) {
            pcv["term_ioi"] = p_charging_vector->term_ioi.value();
        }
        j["p_charging_vector"] = pcv;
    }

    if (p_charging_function_addresses.has_value()) {
        nlohmann::json pcfa;
        if (!p_charging_function_addresses->ccf_addresses.empty()) {
            pcfa["ccf"] = p_charging_function_addresses->ccf_addresses;
        }
        if (!p_charging_function_addresses->ecf_addresses.empty()) {
            pcfa["ecf"] = p_charging_function_addresses->ecf_addresses;
        }
        j["p_charging_function_addresses"] = pcfa;
    }

    if (p_served_user.has_value()) {
        nlohmann::json psu;
        psu["user_uri"] = p_served_user->user_uri;
        if (p_served_user->sescase.has_value()) {
            psu["sescase"] = p_served_user->sescase.value();
        }
        if (p_served_user->regstate.has_value()) {
            psu["regstate"] = p_served_user->regstate.value();
        }
        j["p_served_user"] = psu;
    }

    if (p_preferred_identity.has_value()) {
        j["p_preferred_identity"] = p_preferred_identity.value();
    }

    if (p_early_media.has_value()) {
        j["p_early_media"] = p_early_media.value();
    }

    // NEW: IMS session timers
    if (session_expires.has_value()) {
        nlohmann::json se;
        se["expires"] = session_expires->expires;
        if (session_expires->refresher.has_value()) {
            se["refresher"] = session_expires->refresher.value();
        }
        j["session_expires"] = se;
    }

    if (min_se.has_value()) {
        j["min_se"] = min_se.value();
    }

    // NEW: IMS routing
    if (!path.empty()) {
        j["path"] = path;
    }

    if (!service_route.empty()) {
        j["service_route"] = service_route;
    }

    if (!record_route.empty()) {
        j["record_route"] = record_route;
    }

    if (route.has_value()) {
        j["route"] = route.value();
    }

    // NEW: Feature negotiation
    if (!require.empty()) {
        j["require"] = require;
    }

    if (!supported.empty()) {
        j["supported"] = supported;
    }

    if (!allow.empty()) {
        j["allow"] = allow;
    }

    // NEW: Security headers
    if (security_client.has_value()) {
        nlohmann::json sc;
        sc["mechanism"] = security_client->mechanism;
        if (security_client->algorithm.has_value()) {
            sc["algorithm"] = security_client->algorithm.value();
        }
        if (security_client->spi_c.has_value()) {
            sc["spi_c"] = security_client->spi_c.value();
        }
        if (security_client->spi_s.has_value()) {
            sc["spi_s"] = security_client->spi_s.value();
        }
        if (security_client->port_c.has_value()) {
            sc["port_c"] = security_client->port_c.value();
        }
        if (security_client->port_s.has_value()) {
            sc["port_s"] = security_client->port_s.value();
        }
        j["security_client"] = sc;
    }

    if (security_server.has_value()) {
        nlohmann::json ss;
        ss["mechanism"] = security_server->mechanism;
        if (security_server->algorithm.has_value()) {
            ss["algorithm"] = security_server->algorithm.value();
        }
        j["security_server"] = ss;
    }

    if (security_verify.has_value()) {
        nlohmann::json sv;
        sv["mechanism"] = security_verify->mechanism;
        j["security_verify"] = sv;
    }

    // NEW: Privacy
    if (privacy.has_value()) {
        nlohmann::json priv;
        priv["id"] = privacy->id;
        priv["header"] = privacy->header;
        priv["session"] = privacy->session;
        priv["user"] = privacy->user;
        priv["none"] = privacy->none;
        priv["critical"] = privacy->critical;
        j["privacy"] = priv;
    }

    // NEW: Geolocation
    if (geolocation.has_value()) {
        j["geolocation"] = geolocation.value();
    }

    if (geolocation_routing.has_value()) {
        j["geolocation_routing"] = geolocation_routing.value();
    }

    if (geolocation_error.has_value()) {
        j["geolocation_error"] = geolocation_error.value();
    }

    // NEW: Call transfer
    if (refer_to.has_value()) {
        j["refer_to"] = refer_to.value();
    }

    if (referred_by.has_value()) {
        j["referred_by"] = referred_by.value();
    }

    if (replaces.has_value()) {
        j["replaces"] = replaces.value();
    }

    // NEW: Subscriptions
    if (event.has_value()) {
        j["event"] = event.value();
    }

    if (subscription_state.has_value()) {
        nlohmann::json ss;
        ss["state"] = SipSubscriptionState::stateToString(subscription_state->state);
        if (subscription_state->expires.has_value()) {
            ss["expires"] = subscription_state->expires.value();
        }
        if (subscription_state->reason.has_value()) {
            ss["reason"] = subscription_state->reason.value();
        }
        if (subscription_state->retry_after.has_value()) {
            ss["retry_after"] = subscription_state->retry_after.value();
        }
        j["subscription_state"] = ss;
    }

    // NEW: Correlation & Context headers
    if (reason.has_value()) {
        j["reason_header"] = reason.value();
    }

    if (!diversion.empty()) {
        j["diversion"] = diversion;
    }

    if (!history_info.empty()) {
        j["history_info"] = history_info;
    }

    // SDP (enhanced for IMS)
    if (sdp.has_value()) {
        nlohmann::json sdp_json;
        sdp_json["session_name"] = sdp->session_name;
        sdp_json["connection_address"] = sdp->connection_address;
        sdp_json["rtp_port"] = sdp->rtp_port;
        sdp_json["rtcp_port"] = sdp->rtcp_port;
        sdp_json["media_descriptions"] = sdp->media_descriptions;
        sdp_json["attributes"] = sdp->attributes;

        // NEW: QoS preconditions
        if (sdp->qos_current_local.has_value()) {
            nlohmann::json qos;
            qos["direction"] =
                SipSdpQosPrecondition::directionToString(sdp->qos_current_local->direction);
            qos["status"] = SipSdpQosPrecondition::statusToString(sdp->qos_current_local->status);
            sdp_json["qos_current_local"] = qos;
        }

        if (sdp->qos_current_remote.has_value()) {
            nlohmann::json qos;
            qos["direction"] =
                SipSdpQosPrecondition::directionToString(sdp->qos_current_remote->direction);
            qos["status"] = SipSdpQosPrecondition::statusToString(sdp->qos_current_remote->status);
            sdp_json["qos_current_remote"] = qos;
        }

        if (sdp->qos_desired_local.has_value()) {
            nlohmann::json qos;
            qos["strength"] =
                SipSdpQosPrecondition::strengthToString(sdp->qos_desired_local->strength);
            qos["direction"] =
                SipSdpQosPrecondition::directionToString(sdp->qos_desired_local->direction);
            qos["status"] = SipSdpQosPrecondition::statusToString(sdp->qos_desired_local->status);
            sdp_json["qos_desired_local"] = qos;
        }

        if (sdp->qos_desired_remote.has_value()) {
            nlohmann::json qos;
            qos["strength"] =
                SipSdpQosPrecondition::strengthToString(sdp->qos_desired_remote->strength);
            qos["direction"] =
                SipSdpQosPrecondition::directionToString(sdp->qos_desired_remote->direction);
            qos["status"] = SipSdpQosPrecondition::statusToString(sdp->qos_desired_remote->status);
            sdp_json["qos_desired_remote"] = qos;
        }

        // NEW: Bandwidth
        nlohmann::json bw;
        if (sdp->bandwidth.as.has_value()) {
            bw["as"] = sdp->bandwidth.as.value();
        }
        if (sdp->bandwidth.tias.has_value()) {
            bw["tias"] = sdp->bandwidth.tias.value();
        }
        if (sdp->bandwidth.rs.has_value()) {
            bw["rs"] = sdp->bandwidth.rs.value();
        }
        if (sdp->bandwidth.rr.has_value()) {
            bw["rr"] = sdp->bandwidth.rr.value();
        }
        if (!bw.empty()) {
            sdp_json["bandwidth"] = bw;
        }

        // NEW: Codecs
        if (!sdp->codecs.empty()) {
            nlohmann::json codecs_array = nlohmann::json::array();
            for (const auto& codec : sdp->codecs) {
                nlohmann::json codec_json;
                codec_json["payload_type"] = codec.payload_type;
                codec_json["encoding_name"] = codec.encoding_name;
                codec_json["clock_rate"] = codec.clock_rate;
                if (codec.channels.has_value()) {
                    codec_json["channels"] = codec.channels.value();
                }
                if (!codec.format_parameters.empty()) {
                    codec_json["format_parameters"] = codec.format_parameters;
                }
                codecs_array.push_back(codec_json);
            }
            sdp_json["codecs"] = codecs_array;
        }

        // NEW: Media direction
        if (sdp->media_direction.has_value()) {
            sdp_json["media_direction"] = sdp->media_direction.value();
        }

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
    std::vector<std::string> header_lines(
        lines.begin() + 1, body_start > 0 ? lines.begin() + body_start : lines.end());
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

    // NEW: Parse 3GPP P-headers
    parsePHeaders(msg);

    // NEW: Parse IMS-specific headers
    parseImsHeaders(msg);

    // NEW: Parse security headers
    parseSecurityHeaders(msg);

    // NEW: Parse routing headers
    parseRoutingHeaders(msg);

    return msg;
}

bool SipParser::isSipMessage(const uint8_t* data, size_t len) {
    if (!data || len < 8) {
        return false;
    }

    std::string text(reinterpret_cast<const char*>(data), std::min(len, size_t(200)));

    // Check for SIP methods or status line
    return text.find("SIP/2.0") != std::string::npos &&
           (text.find("INVITE") == 0 || text.find("ACK") == 0 || text.find("BYE") == 0 ||
            text.find("CANCEL") == 0 || text.find("OPTIONS") == 0 || text.find("REGISTER") == 0 ||
            text.find("UPDATE") == 0 || text.find("PRACK") == 0 || text.find("SIP/2.0") == 0);
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
        if (msg.method == "INVITE")
            return MessageType::SIP_INVITE;
        if (msg.method == "ACK")
            return MessageType::SIP_ACK;
        if (msg.method == "BYE")
            return MessageType::SIP_BYE;
        if (msg.method == "CANCEL")
            return MessageType::SIP_CANCEL;
        if (msg.method == "REGISTER")
            return MessageType::SIP_REGISTER;
        if (msg.method == "OPTIONS")
            return MessageType::SIP_OPTIONS;
        if (msg.method == "UPDATE")
            return MessageType::SIP_UPDATE;
        if (msg.method == "PRACK")
            return MessageType::SIP_PRACK;
    } else {
        if (msg.status_code == 100)
            return MessageType::SIP_TRYING;
        if (msg.status_code == 180)
            return MessageType::SIP_RINGING;
        if (msg.status_code == 200)
            return MessageType::SIP_OK;
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
        if (line.empty())
            continue;

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
        } else if (name == "Authorization") {
            msg.authorization = value;
        } else if (name == "Reason") {
            msg.reason = value;
        } else if (name == "Diversion") {
            msg.diversion.push_back(value);
        } else if (name == "History-Info") {
            msg.history_info.push_back(value);
        }

        // Store all headers
        msg.headers[name] = value;
    }
}

void SipParser::parseSdp(const std::string& body, SipMessage& msg) {
    SipMessage::SdpInfo sdp;

    auto lines = splitLines(body);
    for (const auto& line : lines) {
        if (line.length() < 2 || line[1] != '=')
            continue;

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
            } break;
        }
    }

    // NEW: Parse IMS-specific SDP features
    parseSdpQosPreconditions(sdp, lines);
    parseSdpBandwidth(sdp, lines);
    parseSdpCodecs(sdp, lines);
    parseSdpMediaDirection(sdp, lines);

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

std::vector<std::string> SipParser::splitCommaList(const std::string& str) {
    std::vector<std::string> result;
    std::istringstream iss(str);
    std::string item;

    while (std::getline(iss, item, ',')) {
        item = trim(item);
        if (!item.empty()) {
            result.push_back(item);
        }
    }

    return result;
}

// ============================================================================
// 3GPP P-header parsing
// ============================================================================

void SipParser::parsePHeaders(SipMessage& msg) {
    // P-Asserted-Identity
    auto it = msg.headers.find("P-Asserted-Identity");
    if (it != msg.headers.end()) {
        msg.p_asserted_identity = SipPAssertedIdentity::parse(it->second);
    }

    // P-Access-Network-Info
    it = msg.headers.find("P-Access-Network-Info");
    if (it != msg.headers.end()) {
        msg.p_access_network_info = SipPAccessNetworkInfo::parse(it->second);
    }

    // P-Visited-Network-ID
    it = msg.headers.find("P-Visited-Network-ID");
    if (it != msg.headers.end()) {
        msg.p_visited_network_id = it->second;
    }

    // P-Charging-Vector (CRITICAL for billing)
    it = msg.headers.find("P-Charging-Vector");
    if (it != msg.headers.end()) {
        msg.p_charging_vector = SipPChargingVector::parse(it->second);
    }

    // P-Charging-Function-Addresses
    it = msg.headers.find("P-Charging-Function-Addresses");
    if (it != msg.headers.end()) {
        msg.p_charging_function_addresses = SipPChargingFunctionAddresses::parse(it->second);
    }

    // P-Served-User
    it = msg.headers.find("P-Served-User");
    if (it != msg.headers.end()) {
        msg.p_served_user = SipPServedUser::parse(it->second);
    }

    // P-Preferred-Identity
    it = msg.headers.find("P-Preferred-Identity");
    if (it != msg.headers.end()) {
        msg.p_preferred_identity = it->second;
    }

    // P-Early-Media
    it = msg.headers.find("P-Early-Media");
    if (it != msg.headers.end()) {
        msg.p_early_media = it->second;
    }

    // P-Associated-URI
    it = msg.headers.find("P-Associated-URI");
    if (it != msg.headers.end()) {
        msg.p_associated_uri = splitCommaList(it->second);
    }
}

void SipParser::parseImsHeaders(SipMessage& msg) {
    // Session-Expires
    auto it = msg.headers.find("Session-Expires");
    if (it != msg.headers.end()) {
        msg.session_expires = SipSessionExpires::parse(it->second);
    }

    // Min-SE
    it = msg.headers.find("Min-SE");
    if (it != msg.headers.end()) {
        try {
            msg.min_se = std::stoul(it->second);
        } catch (...) {
        }
    }

    // Require
    it = msg.headers.find("Require");
    if (it != msg.headers.end()) {
        msg.require = splitCommaList(it->second);
    }

    // Supported
    it = msg.headers.find("Supported");
    if (it != msg.headers.end()) {
        msg.supported = splitCommaList(it->second);
    }

    // Allow
    it = msg.headers.find("Allow");
    if (it != msg.headers.end()) {
        msg.allow = splitCommaList(it->second);
    }

    // Privacy
    it = msg.headers.find("Privacy");
    if (it != msg.headers.end()) {
        msg.privacy = SipPrivacy::parse(it->second);
    }

    // Geolocation
    it = msg.headers.find("Geolocation");
    if (it != msg.headers.end()) {
        msg.geolocation = it->second;
    }

    // Geolocation-Routing
    it = msg.headers.find("Geolocation-Routing");
    if (it != msg.headers.end()) {
        msg.geolocation_routing = it->second;
    }

    // Geolocation-Error
    it = msg.headers.find("Geolocation-Error");
    if (it != msg.headers.end()) {
        msg.geolocation_error = it->second;
    }

    // Refer-To
    it = msg.headers.find("Refer-To");
    if (it != msg.headers.end()) {
        msg.refer_to = it->second;
    }

    // Referred-By
    it = msg.headers.find("Referred-By");
    if (it != msg.headers.end()) {
        msg.referred_by = it->second;
    }

    // Replaces
    it = msg.headers.find("Replaces");
    if (it != msg.headers.end()) {
        msg.replaces = it->second;
    }

    // Event
    it = msg.headers.find("Event");
    if (it != msg.headers.end()) {
        msg.event = it->second;
    }

    // Subscription-State
    it = msg.headers.find("Subscription-State");
    if (it != msg.headers.end()) {
        msg.subscription_state = SipSubscriptionState::parse(it->second);
    }
}

void SipParser::parseSecurityHeaders(SipMessage& msg) {
    // Security-Client
    auto it = msg.headers.find("Security-Client");
    if (it != msg.headers.end()) {
        msg.security_client = SipSecurityInfo::parse(it->second);
    }

    // Security-Server
    it = msg.headers.find("Security-Server");
    if (it != msg.headers.end()) {
        msg.security_server = SipSecurityInfo::parse(it->second);
    }

    // Security-Verify
    it = msg.headers.find("Security-Verify");
    if (it != msg.headers.end()) {
        msg.security_verify = SipSecurityInfo::parse(it->second);
    }
}

void SipParser::parseRoutingHeaders(SipMessage& msg) {
    // Path
    auto it = msg.headers.find("Path");
    if (it != msg.headers.end()) {
        msg.path = splitCommaList(it->second);
    }

    // Service-Route
    it = msg.headers.find("Service-Route");
    if (it != msg.headers.end()) {
        msg.service_route = splitCommaList(it->second);
    }

    // Record-Route
    it = msg.headers.find("Record-Route");
    if (it != msg.headers.end()) {
        msg.record_route = splitCommaList(it->second);
    }

    // Route
    it = msg.headers.find("Route");
    if (it != msg.headers.end()) {
        msg.route = it->second;
    }
}

// ============================================================================
// Enhanced SDP parsing for IMS
// ============================================================================

void SipParser::parseSdpQosPreconditions(SipMessage::SdpInfo& sdp,
                                         const std::vector<std::string>& lines) {
    for (const auto& line : lines) {
        if (line.find("a=curr:qos") == 0) {
            std::string value = line.substr(2);  // Remove 'a='
            if (value.find("local") != std::string::npos) {
                sdp.qos_current_local = SipSdpQosPrecondition::parseCurrent(value);
            } else if (value.find("remote") != std::string::npos) {
                sdp.qos_current_remote = SipSdpQosPrecondition::parseCurrent(value);
            }
        } else if (line.find("a=des:qos") == 0) {
            std::string value = line.substr(2);  // Remove 'a='
            if (value.find("local") != std::string::npos) {
                sdp.qos_desired_local = SipSdpQosPrecondition::parseDesired(value);
            } else if (value.find("remote") != std::string::npos) {
                sdp.qos_desired_remote = SipSdpQosPrecondition::parseDesired(value);
            }
        }
    }
}

void SipParser::parseSdpBandwidth(SipMessage::SdpInfo& sdp, const std::vector<std::string>& lines) {
    for (const auto& line : lines) {
        if (line.length() >= 2 && line[0] == 'b' && line[1] == '=') {
            SipSdpBandwidth::parseLine(line, sdp.bandwidth);
        }
    }
}

void SipParser::parseSdpCodecs(SipMessage::SdpInfo& sdp, const std::vector<std::string>& lines) {
    std::map<uint8_t, size_t> payload_to_index;

    for (const auto& line : lines) {
        if (line.find("a=rtpmap:") == 0) {
            std::string value = line.substr(9);  // Remove 'a=rtpmap:'
            auto codec = SipSdpCodec::parseRtpmap(value);
            if (codec.has_value()) {
                payload_to_index[codec->payload_type] = sdp.codecs.size();
                sdp.codecs.push_back(codec.value());
            }
        }
    }

    // Parse fmtp attributes
    for (const auto& line : lines) {
        if (line.find("a=fmtp:") == 0) {
            std::string value = line.substr(7);  // Remove 'a=fmtp:'

            // Extract payload type
            size_t space = value.find(' ');
            if (space != std::string::npos) {
                try {
                    uint8_t pt = static_cast<uint8_t>(std::stoul(value.substr(0, space)));
                    auto it = payload_to_index.find(pt);
                    if (it != payload_to_index.end()) {
                        sdp.codecs[it->second].parseFmtp(value);
                    }
                } catch (...) {
                }
            }
        }
    }
}

void SipParser::parseSdpMediaDirection(SipMessage::SdpInfo& sdp,
                                       const std::vector<std::string>& lines) {
    for (const auto& line : lines) {
        if (line == "a=sendrecv") {
            sdp.media_direction = "sendrecv";
        } else if (line == "a=sendonly") {
            sdp.media_direction = "sendonly";
        } else if (line == "a=recvonly") {
            sdp.media_direction = "recvonly";
        } else if (line == "a=inactive") {
            sdp.media_direction = "inactive";
        }
    }
}

}  // namespace callflow
