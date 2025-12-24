#include "correlation/sip/sip_call_detector.h"
#include <regex>
#include <algorithm>
#include <sstream>

namespace callflow {
namespace correlation {

SipSessionType SipCallDetector::detectSessionType(const std::vector<SipMessage>& messages) {
    if (messages.empty()) {
        return SipSessionType::UNKNOWN;
    }

    // Find the first request
    const SipMessage* first_request = nullptr;
    for (const auto& msg : messages) {
        if (msg.isRequest()) {
            first_request = &msg;
            break;
        }
    }

    if (!first_request) {
        return SipSessionType::UNKNOWN;
    }

    std::string method = first_request->getMethod();

    // REGISTER -> check if registration or deregistration
    if (method == "REGISTER") {
        // Check Contact header for expires=0
        auto contact = first_request->getContactHeader();
        if (contact.has_value() && contact->expires.has_value() &&
            contact->expires.value() == 0) {
            return SipSessionType::DEREGISTRATION;
        }
        // Check Expires header
        auto expires_header = first_request->getHeader("Expires");
        if (expires_header.has_value() && expires_header.value() == "0") {
            return SipSessionType::DEREGISTRATION;
        }
        return SipSessionType::REGISTRATION;
    }

    // MESSAGE -> SMS
    if (method == "MESSAGE") {
        return SipSessionType::SMS_MESSAGE;
    }

    // SUBSCRIBE/NOTIFY -> presence/event subscription
    if (method == "SUBSCRIBE" || method == "NOTIFY") {
        return SipSessionType::SUBSCRIBE_NOTIFY;
    }

    // OPTIONS -> keepalive
    if (method == "OPTIONS") {
        return SipSessionType::OPTIONS;
    }

    // REFER -> call transfer
    if (method == "REFER") {
        return SipSessionType::REFER;
    }

    // INFO -> mid-call signaling
    if (method == "INFO") {
        return SipSessionType::INFO;
    }

    // INVITE -> analyze media
    if (method == "INVITE") {
        // Check for emergency call
        if (isEmergencyCall(messages)) {
            return SipSessionType::EMERGENCY_CALL;
        }

        // Check media type
        if (isVideoCall(messages)) {
            return SipSessionType::VIDEO_CALL;
        } else if (isVoiceCall(messages)) {
            return SipSessionType::VOICE_CALL;
        }

        // Default to voice call if INVITE but no media detected
        return SipSessionType::VOICE_CALL;
    }

    return SipSessionType::UNKNOWN;
}

CallPartyInfo SipCallDetector::extractCallParties(const std::vector<SipMessage>& messages) {
    CallPartyInfo info;

    if (messages.empty()) {
        return info;
    }

    // Find the first request to extract caller/callee
    const SipMessage* first_request = nullptr;
    for (const auto& msg : messages) {
        if (msg.isRequest()) {
            first_request = &msg;
            break;
        }
    }

    if (!first_request) {
        return info;
    }

    // Extract caller identity
    info.caller_msisdn = getBestCallerIdentity(*first_request);

    // Extract callee identity
    info.callee_msisdn = getBestCalleeIdentity(*first_request);

    // Extract IPs from Contact headers and SDP
    for (const auto& msg : messages) {
        if (msg.isRequest() && msg.isInvite()) {
            // Caller IP from INVITE
            auto ip = extractIpFromContact(msg);
            if (ip.has_value() && info.caller_ip.empty()) {
                info.caller_ip = ip.value();
            }
            auto sdp = msg.getSdpBody();
            if (sdp.has_value()) {
                auto sdp_ip = extractIpFromSdp(sdp.value());
                if (sdp_ip.has_value() && info.caller_ip.empty()) {
                    info.caller_ip = sdp_ip.value();
                }
            }
        } else if (msg.isResponse() && msg.isSuccess() &&
                   msg.getCSeqMethod() == "INVITE") {
            // Callee IP from 200 OK
            auto ip = extractIpFromContact(msg);
            if (ip.has_value() && info.callee_ip.empty()) {
                info.callee_ip = ip.value();
            }
            auto sdp = msg.getSdpBody();
            if (sdp.has_value()) {
                auto sdp_ip = extractIpFromSdp(sdp.value());
                if (sdp_ip.has_value() && info.callee_ip.empty()) {
                    info.callee_ip = sdp_ip.value();
                }
            }
        }
    }

    // Detect call direction
    info.direction = detectCallDirection(messages);

    return info;
}

std::vector<SipMediaInfo> SipCallDetector::extractMediaInfo(
    const std::vector<SipMessage>& messages) {

    std::vector<SipMediaInfo> media_list;

    for (const auto& msg : messages) {
        // Check messages with SDP
        if (msg.isRequest() && msg.isInvite()) {
            auto sdp = msg.getSdpBody();
            if (sdp.has_value()) {
                auto media = parseSdp(sdp.value());
                media_list.insert(media_list.end(), media.begin(), media.end());
            }
        } else if (msg.isResponse() && msg.isSuccess() &&
                   msg.getCSeqMethod() == "INVITE") {
            auto sdp = msg.getSdpBody();
            if (sdp.has_value()) {
                auto media = parseSdp(sdp.value());
                media_list.insert(media_list.end(), media.begin(), media.end());
            }
        }
    }

    return media_list;
}

bool SipCallDetector::isVoiceCall(const std::vector<SipMessage>& messages) {
    auto media = extractMediaInfo(messages);
    return hasAudioMedia(media) && !hasVideoMedia(media);
}

bool SipCallDetector::isVideoCall(const std::vector<SipMessage>& messages) {
    auto media = extractMediaInfo(messages);
    return hasAudioMedia(media) && hasVideoMedia(media);
}

bool SipCallDetector::isEmergencyCall(const std::vector<SipMessage>& messages) {
    for (const auto& msg : messages) {
        if (msg.isRequest() && msg.isInvite()) {
            std::string request_uri = msg.getRequestUri();
            if (isEmergencyUrn(request_uri)) {
                return true;
            }

            std::string to_uri = msg.getToUri();
            if (isEmergencyUrn(to_uri)) {
                return true;
            }
        }
    }
    return false;
}

SipDirection SipCallDetector::detectCallDirection(const std::vector<SipMessage>& messages) {
    // Simple heuristic: check Via header count in first INVITE
    // MO calls typically have fewer Via headers initially
    // More sophisticated detection would analyze network elements
    for (const auto& msg : messages) {
        if (msg.isRequest() && msg.isInvite()) {
            auto via_headers = msg.getViaHeaders();
            if (via_headers.size() == 1) {
                // Likely originating from UE
                return SipDirection::ORIGINATING;
            } else if (via_headers.size() > 2) {
                // Likely terminating towards UE
                return SipDirection::TERMINATING;
            }
            break;
        }
    }
    return SipDirection::ORIGINATING;
}

std::string SipCallDetector::extractMsisdn(const std::string& uri_or_header) {
    // Extract user part from SIP URI
    std::string user = extractUser(uri_or_header);
    if (user.empty()) {
        return "";
    }

    // Normalize phone number (remove non-digits except +)
    return normalizePhoneNumber(user);
}

std::string SipCallDetector::extractUser(const std::string& uri) {
    if (uri.empty()) {
        return "";
    }

    // Strip delimiters like <> and quotes
    std::string clean_uri = stripUriDelimiters(uri);

    // Pattern: sip:user@host or sip:user@host:port
    std::regex uri_regex(R"(sip:([^@]+)@)");
    std::smatch match;

    if (std::regex_search(clean_uri, match, uri_regex)) {
        return match[1].str();
    }

    return "";
}

std::string SipCallDetector::extractHost(const std::string& uri) {
    if (uri.empty()) {
        return "";
    }

    std::string clean_uri = stripUriDelimiters(uri);

    // Pattern: sip:user@host or sip:user@host:port
    std::regex uri_regex(R"(sip:[^@]+@([^:;>]+))");
    std::smatch match;

    if (std::regex_search(clean_uri, match, uri_regex)) {
        return match[1].str();
    }

    return "";
}

bool SipCallDetector::isEmergencyUrn(const std::string& uri) {
    return uri.find("urn:service:sos") != std::string::npos;
}

std::vector<SipMediaInfo> SipCallDetector::parseSdp(const std::string& sdp) {
    std::vector<SipMediaInfo> media_list;

    // Simple SDP parsing
    // Format:
    // m=audio 49170 RTP/AVP 0 8 97
    // c=IN IP4 192.168.1.100
    // a=rtpmap:0 PCMU/8000
    // a=rtpmap:8 PCMA/8000

    std::istringstream iss(sdp);
    std::string line;
    SipMediaInfo current_media;
    std::string connection_ip;

    while (std::getline(iss, line)) {
        if (line.empty()) continue;

        // Remove trailing \r
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }

        if (line[0] == 'm' && line[1] == '=') {
            // Save previous media if any
            if (!current_media.media_type.empty()) {
                media_list.push_back(current_media);
            }

            // Parse media line: m=<media> <port> <proto> <fmt> ...
            current_media = SipMediaInfo();
            std::istringstream mline(line.substr(2));
            mline >> current_media.media_type >> current_media.port;
            current_media.connection_ip = connection_ip;

        } else if (line[0] == 'c' && line[1] == '=') {
            // Connection line: c=IN IP4 <address>
            std::istringstream cline(line.substr(2));
            std::string net_type, addr_type;
            cline >> net_type >> addr_type >> connection_ip;
            if (!current_media.media_type.empty()) {
                current_media.connection_ip = connection_ip;
            }

        } else if (line[0] == 'a' && line[1] == '=') {
            // Attribute line
            std::string attr = line.substr(2);

            // Check for direction attributes
            if (attr == "sendrecv" || attr == "sendonly" ||
                attr == "recvonly" || attr == "inactive") {
                current_media.direction = attr;
            }

            // Parse rtpmap for codec information
            if (attr.find("rtpmap:") == 0) {
                // rtpmap:<payload> <encoding>/<clock>
                size_t space_pos = attr.find(' ');
                if (space_pos != std::string::npos) {
                    std::string codec = attr.substr(space_pos + 1);
                    current_media.codecs.push_back(codec);
                }
            }
        }
    }

    // Save last media
    if (!current_media.media_type.empty()) {
        media_list.push_back(current_media);
    }

    return media_list;
}

bool SipCallDetector::hasAudioMedia(const std::vector<SipMediaInfo>& media) {
    return std::any_of(media.begin(), media.end(),
                       [](const SipMediaInfo& m) { return m.media_type == "audio"; });
}

bool SipCallDetector::hasVideoMedia(const std::vector<SipMediaInfo>& media) {
    return std::any_of(media.begin(), media.end(),
                       [](const SipMediaInfo& m) { return m.media_type == "video"; });
}

std::string SipCallDetector::getBestCallerIdentity(const SipMessage& msg) {
    // Priority: P-Asserted-Identity > P-Preferred-Identity > From
    auto pai = msg.getPAssertedIdentity();
    if (pai.has_value() && !pai.value().empty()) {
        return extractMsisdn(pai.value());
    }

    auto ppi = msg.getPPreferredIdentity();
    if (ppi.has_value() && !ppi.value().empty()) {
        return extractMsisdn(ppi.value());
    }

    return extractMsisdn(msg.getFromUri());
}

std::string SipCallDetector::getBestCalleeIdentity(const SipMessage& msg) {
    // Use To header
    return extractMsisdn(msg.getToUri());
}

std::optional<std::string> SipCallDetector::extractIpFromContact(const SipMessage& msg) {
    auto contact = msg.getContactHeader();
    if (contact.has_value() && !contact->host.empty()) {
        // Check if host is an IP address (simple check)
        if (contact->host.find('.') != std::string::npos ||
            contact->host.find(':') != std::string::npos) {
            return contact->host;
        }
    }
    return std::nullopt;
}

std::optional<std::string> SipCallDetector::extractIpFromSdp(const std::string& sdp) {
    // Extract IP from c= line in SDP
    std::istringstream iss(sdp);
    std::string line;

    while (std::getline(iss, line)) {
        if (line.empty()) continue;

        if (line[0] == 'c' && line[1] == '=') {
            // c=IN IP4 <address>
            std::istringstream cline(line.substr(2));
            std::string net_type, addr_type, address;
            cline >> net_type >> addr_type >> address;
            if (!address.empty()) {
                return address;
            }
        }
    }

    return std::nullopt;
}

std::string SipCallDetector::stripUriDelimiters(const std::string& uri) {
    std::string result = uri;

    // Remove leading/trailing whitespace
    size_t start = result.find_first_not_of(" \t\r\n");
    if (start != std::string::npos) {
        result = result.substr(start);
    }

    size_t end = result.find_last_not_of(" \t\r\n");
    if (end != std::string::npos) {
        result = result.substr(0, end + 1);
    }

    // Remove angle brackets: <sip:...> -> sip:...
    if (!result.empty() && result.front() == '<') {
        result = result.substr(1);
    }
    if (!result.empty() && result.back() == '>') {
        result = result.substr(0, result.length() - 1);
    }

    // Remove display name: "Name" <sip:...> -> sip:...
    size_t bracket_pos = result.find('<');
    if (bracket_pos != std::string::npos) {
        result = result.substr(bracket_pos + 1);
        if (!result.empty() && result.back() == '>') {
            result = result.substr(0, result.length() - 1);
        }
    }

    return result;
}

std::string SipCallDetector::normalizePhoneNumber(const std::string& number) {
    std::string result;

    // Keep only digits and leading +
    bool first_char = true;
    for (char c : number) {
        if (std::isdigit(c)) {
            result += c;
            first_char = false;
        } else if (c == '+' && first_char) {
            // Keep leading +, but don't add to result (we'll strip it below)
            first_char = false;
        }
    }

    // Remove leading + for storage (normalized form is digits only)
    if (!result.empty() && result[0] == '+') {
        result = result.substr(1);
    }

    return result;
}

} // namespace correlation
} // namespace callflow
