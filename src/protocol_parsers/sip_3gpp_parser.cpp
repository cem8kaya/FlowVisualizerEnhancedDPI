#include "protocol_parsers/sip_3gpp_headers.h"
#include "common/logger.h"
#include <algorithm>
#include <cctype>
#include <sstream>

namespace callflow {

// ============================================================================
// P-Asserted-Identity parsing
// ============================================================================

std::optional<std::vector<SipPAssertedIdentity>> SipPAssertedIdentity::parse(const std::string& value) {
    std::vector<SipPAssertedIdentity> identities;

    // P-Asserted-Identity can have multiple identities separated by commas
    // Format: "Display Name" <sip:user@domain>, <tel:+1234567890>

    size_t pos = 0;
    while (pos < value.length()) {
        SipPAssertedIdentity identity;

        // Skip whitespace
        while (pos < value.length() && std::isspace(static_cast<unsigned char>(value[pos]))) {
            pos++;
        }

        if (pos >= value.length()) break;

        // Check for display name in quotes
        if (value[pos] == '"') {
            pos++;
            size_t end_quote = value.find('"', pos);
            if (end_quote != std::string::npos) {
                identity.display_name = value.substr(pos, end_quote - pos);
                pos = end_quote + 1;
            }
        }

        // Find URI in angle brackets
        size_t uri_start = value.find('<', pos);
        if (uri_start == std::string::npos) break;

        size_t uri_end = value.find('>', uri_start);
        if (uri_end == std::string::npos) break;

        identity.uri = value.substr(uri_start + 1, uri_end - uri_start - 1);
        identities.push_back(identity);

        pos = uri_end + 1;

        // Skip comma if present
        size_t comma = value.find(',', pos);
        if (comma != std::string::npos) {
            pos = comma + 1;
        } else {
            break;
        }
    }

    return identities.empty() ? std::nullopt : std::make_optional(identities);
}

// ============================================================================
// P-Access-Network-Info parsing
// ============================================================================

std::optional<SipPAccessNetworkInfo> SipPAccessNetworkInfo::parse(const std::string& value) {
    SipPAccessNetworkInfo info;

    // Format: 3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=234150999999999
    // Format: 3GPP-NR; nrcgi=001010000000001

    std::istringstream iss(value);
    std::string access_str;
    std::getline(iss, access_str, ';');

    // Trim
    access_str.erase(0, access_str.find_first_not_of(" \t"));
    access_str.erase(access_str.find_last_not_of(" \t") + 1);

    // Parse access type
    if (access_str == "3GPP-E-UTRAN-FDD") {
        info.access_type = AccessType::THREEGPP_E_UTRAN_FDD;
    } else if (access_str == "3GPP-E-UTRAN-TDD") {
        info.access_type = AccessType::THREEGPP_E_UTRAN_TDD;
    } else if (access_str == "3GPP-NR") {
        info.access_type = AccessType::THREEGPP_NR;
    } else if (access_str == "IEEE-802.11") {
        info.access_type = AccessType::IEEE_802_11;
    } else if (access_str == "3GPP-GERAN") {
        info.access_type = AccessType::THREEGPP_GERAN;
    } else if (access_str == "3GPP-UTRAN-FDD") {
        info.access_type = AccessType::THREEGPP_UTRAN_FDD;
    } else if (access_str == "3GPP-UTRAN-TDD") {
        info.access_type = AccessType::THREEGPP_UTRAN_TDD;
    } else {
        info.access_type = AccessType::UNKNOWN;
    }

    // Parse parameters
    std::string param;
    while (std::getline(iss, param, ';')) {
        size_t eq = param.find('=');
        if (eq != std::string::npos) {
            std::string key = param.substr(0, eq);
            std::string val = param.substr(eq + 1);

            // Trim
            key.erase(0, key.find_first_not_of(" \t"));
            key.erase(key.find_last_not_of(" \t") + 1);
            val.erase(0, val.find_first_not_of(" \t"));
            val.erase(val.find_last_not_of(" \t") + 1);

            // Store cell ID
            if (key == "utran-cell-id-3gpp" || key == "nrcgi" || key == "cgi-3gpp") {
                info.cell_id = val;
            }

            info.parameters[key] = val;
        }
    }

    return info;
}

std::string SipPAccessNetworkInfo::accessTypeToString(AccessType type) {
    switch (type) {
        case AccessType::THREEGPP_E_UTRAN_FDD: return "3GPP-E-UTRAN-FDD";
        case AccessType::THREEGPP_E_UTRAN_TDD: return "3GPP-E-UTRAN-TDD";
        case AccessType::THREEGPP_NR: return "3GPP-NR";
        case AccessType::IEEE_802_11: return "IEEE-802.11";
        case AccessType::THREEGPP_GERAN: return "3GPP-GERAN";
        case AccessType::THREEGPP_UTRAN_FDD: return "3GPP-UTRAN-FDD";
        case AccessType::THREEGPP_UTRAN_TDD: return "3GPP-UTRAN-TDD";
        default: return "UNKNOWN";
    }
}

// ============================================================================
// P-Charging-Vector parsing
// ============================================================================

std::optional<SipPChargingVector> SipPChargingVector::parse(const std::string& value) {
    SipPChargingVector charging;

    // Format: icid-value=1234567890; icid-generated-at=192.0.2.1; orig-ioi=home1.net; term-ioi=home2.net

    std::istringstream iss(value);
    std::string param;

    while (std::getline(iss, param, ';')) {
        size_t eq = param.find('=');
        if (eq != std::string::npos) {
            std::string key = param.substr(0, eq);
            std::string val = param.substr(eq + 1);

            // Trim
            key.erase(0, key.find_first_not_of(" \t"));
            key.erase(key.find_last_not_of(" \t") + 1);
            val.erase(0, val.find_first_not_of(" \t"));
            val.erase(val.find_last_not_of(" \t") + 1);

            if (key == "icid-value") {
                charging.icid_value = val;
            } else if (key == "icid-generated-at") {
                charging.icid_generated_at = val;
            } else if (key == "orig-ioi") {
                charging.orig_ioi = val;
            } else if (key == "term-ioi") {
                charging.term_ioi = val;
            }
        }
    }

    // ICID value is mandatory
    if (charging.icid_value.empty()) {
        return std::nullopt;
    }

    return charging;
}

// ============================================================================
// P-Charging-Function-Addresses parsing
// ============================================================================

std::optional<SipPChargingFunctionAddresses> SipPChargingFunctionAddresses::parse(
    const std::string& value) {
    SipPChargingFunctionAddresses addresses;

    // Format: ccf=192.0.2.10; ccf=192.0.2.11; ecf=192.0.2.20

    std::istringstream iss(value);
    std::string param;

    while (std::getline(iss, param, ';')) {
        size_t eq = param.find('=');
        if (eq != std::string::npos) {
            std::string key = param.substr(0, eq);
            std::string val = param.substr(eq + 1);

            // Trim
            key.erase(0, key.find_first_not_of(" \t"));
            key.erase(key.find_last_not_of(" \t") + 1);
            val.erase(0, val.find_first_not_of(" \t"));
            val.erase(val.find_last_not_of(" \t") + 1);

            if (key == "ccf") {
                addresses.ccf_addresses.push_back(val);
            } else if (key == "ecf") {
                addresses.ecf_addresses.push_back(val);
            }
        }
    }

    if (addresses.ccf_addresses.empty() && addresses.ecf_addresses.empty()) {
        return std::nullopt;
    }

    return addresses;
}

// ============================================================================
// P-Served-User parsing
// ============================================================================

std::optional<SipPServedUser> SipPServedUser::parse(const std::string& value) {
    SipPServedUser served_user;

    // Format: <sip:user@example.com>; sescase=orig; regstate=reg

    // Extract URI
    size_t uri_start = value.find('<');
    size_t uri_end = value.find('>');
    if (uri_start != std::string::npos && uri_end != std::string::npos) {
        served_user.user_uri = value.substr(uri_start + 1, uri_end - uri_start - 1);
    } else {
        // No angle brackets, take up to first semicolon
        size_t semi = value.find(';');
        if (semi != std::string::npos) {
            served_user.user_uri = value.substr(0, semi);
        } else {
            served_user.user_uri = value;
        }
        // Trim
        served_user.user_uri.erase(0, served_user.user_uri.find_first_not_of(" \t"));
        served_user.user_uri.erase(served_user.user_uri.find_last_not_of(" \t") + 1);
    }

    // Parse parameters
    std::istringstream iss(value);
    std::string param;
    while (std::getline(iss, param, ';')) {
        size_t eq = param.find('=');
        if (eq != std::string::npos) {
            std::string key = param.substr(0, eq);
            std::string val = param.substr(eq + 1);

            // Trim
            key.erase(0, key.find_first_not_of(" \t"));
            key.erase(key.find_last_not_of(" \t") + 1);
            val.erase(0, val.find_first_not_of(" \t"));
            val.erase(val.find_last_not_of(" \t") + 1);

            if (key == "sescase") {
                served_user.sescase = val;
            } else if (key == "regstate") {
                served_user.regstate = val;
            }
        }
    }

    return served_user;
}

// ============================================================================
// Security-Client/Server/Verify parsing
// ============================================================================

std::optional<SipSecurityInfo> SipSecurityInfo::parse(const std::string& value) {
    SipSecurityInfo security;

    // Format: ipsec-3gpp; alg=hmac-sha-1-96; spi-c=1234; spi-s=5678; port-c=5062; port-s=5064

    std::istringstream iss(value);
    std::string token;

    // First token is the mechanism
    std::getline(iss, token, ';');
    token.erase(0, token.find_first_not_of(" \t"));
    token.erase(token.find_last_not_of(" \t") + 1);
    security.mechanism = token;

    // Parse remaining parameters
    std::string param;
    while (std::getline(iss, param, ';')) {
        size_t eq = param.find('=');
        if (eq != std::string::npos) {
            std::string key = param.substr(0, eq);
            std::string val = param.substr(eq + 1);

            // Trim
            key.erase(0, key.find_first_not_of(" \t"));
            key.erase(key.find_last_not_of(" \t") + 1);
            val.erase(0, val.find_first_not_of(" \t"));
            val.erase(val.find_last_not_of(" \t") + 1);

            if (key == "alg" || key == "algorithm") {
                security.algorithm = val;
            } else if (key == "spi-c") {
                try {
                    security.spi_c = std::stoul(val);
                } catch (...) {
                }
            } else if (key == "spi-s") {
                try {
                    security.spi_s = std::stoul(val);
                } catch (...) {
                }
            } else if (key == "port-c") {
                try {
                    security.port_c = static_cast<uint16_t>(std::stoul(val));
                } catch (...) {
                }
            } else if (key == "port-s") {
                try {
                    security.port_s = static_cast<uint16_t>(std::stoul(val));
                } catch (...) {
                }
            }

            security.parameters[key] = val;
        }
    }

    return security;
}

// ============================================================================
// Session-Expires parsing
// ============================================================================

std::optional<SipSessionExpires> SipSessionExpires::parse(const std::string& value) {
    SipSessionExpires session_expires;

    // Format: 1800; refresher=uac

    std::istringstream iss(value);
    if (!(iss >> session_expires.expires)) {
        return std::nullopt;
    }

    // Check for refresher parameter
    size_t refresher_pos = value.find("refresher=");
    if (refresher_pos != std::string::npos) {
        session_expires.refresher = value.substr(refresher_pos + 10, 3);
    }

    return session_expires;
}

// ============================================================================
// SDP QoS Precondition parsing
// ============================================================================

std::optional<SipSdpQosPrecondition> SipSdpQosPrecondition::parseCurrent(const std::string& value) {
    // Format: a=curr:qos local sendrecv
    SipSdpQosPrecondition precondition;
    precondition.strength = Strength::NONE;

    std::istringstream iss(value);
    std::string qos_str, direction_str, status_str;

    if (!(iss >> qos_str >> direction_str >> status_str)) {
        return std::nullopt;
    }

    // Parse direction
    if (direction_str == "local") {
        precondition.direction = Direction::LOCAL;
    } else if (direction_str == "remote") {
        precondition.direction = Direction::REMOTE;
    } else {
        precondition.direction = Direction::UNKNOWN;
    }

    // Parse status
    if (status_str == "none") {
        precondition.status = Status::NONE;
    } else if (status_str == "send") {
        precondition.status = Status::SEND;
    } else if (status_str == "recv") {
        precondition.status = Status::RECV;
    } else if (status_str == "sendrecv") {
        precondition.status = Status::SENDRECV;
    } else {
        precondition.status = Status::UNKNOWN;
    }

    return precondition;
}

std::optional<SipSdpQosPrecondition> SipSdpQosPrecondition::parseDesired(const std::string& value) {
    // Format: a=des:qos mandatory local sendrecv
    SipSdpQosPrecondition precondition;

    std::istringstream iss(value);
    std::string qos_str, strength_str, direction_str, status_str;

    if (!(iss >> qos_str >> strength_str >> direction_str >> status_str)) {
        return std::nullopt;
    }

    // Parse strength
    if (strength_str == "mandatory") {
        precondition.strength = Strength::MANDATORY;
    } else if (strength_str == "optional") {
        precondition.strength = Strength::OPTIONAL;
    } else if (strength_str == "none") {
        precondition.strength = Strength::NONE;
    } else if (strength_str == "failure") {
        precondition.strength = Strength::FAILURE;
    } else {
        precondition.strength = Strength::UNKNOWN;
    }

    // Parse direction
    if (direction_str == "local") {
        precondition.direction = Direction::LOCAL;
    } else if (direction_str == "remote") {
        precondition.direction = Direction::REMOTE;
    } else {
        precondition.direction = Direction::UNKNOWN;
    }

    // Parse status
    if (status_str == "none") {
        precondition.status = Status::NONE;
    } else if (status_str == "send") {
        precondition.status = Status::SEND;
    } else if (status_str == "recv") {
        precondition.status = Status::RECV;
    } else if (status_str == "sendrecv") {
        precondition.status = Status::SENDRECV;
    } else {
        precondition.status = Status::UNKNOWN;
    }

    return precondition;
}

std::string SipSdpQosPrecondition::strengthToString(Strength s) {
    switch (s) {
        case Strength::NONE: return "none";
        case Strength::MANDATORY: return "mandatory";
        case Strength::OPTIONAL: return "optional";
        case Strength::FAILURE: return "failure";
        default: return "unknown";
    }
}

std::string SipSdpQosPrecondition::directionToString(Direction d) {
    switch (d) {
        case Direction::LOCAL: return "local";
        case Direction::REMOTE: return "remote";
        default: return "unknown";
    }
}

std::string SipSdpQosPrecondition::statusToString(Status s) {
    switch (s) {
        case Status::NONE: return "none";
        case Status::SEND: return "send";
        case Status::RECV: return "recv";
        case Status::SENDRECV: return "sendrecv";
        default: return "unknown";
    }
}

// ============================================================================
// SDP Bandwidth parsing
// ============================================================================

void SipSdpBandwidth::parseLine(const std::string& line, SipSdpBandwidth& bandwidth) {
    // Format: b=AS:64 or b=TIAS:64000
    if (line.length() < 4 || line[0] != 'b' || line[1] != '=') {
        return;
    }

    std::string value = line.substr(2);
    size_t colon = value.find(':');
    if (colon == std::string::npos) {
        return;
    }

    std::string type = value.substr(0, colon);
    std::string bw_str = value.substr(colon + 1);

    try {
        uint32_t bw = std::stoul(bw_str);
        if (type == "AS") {
            bandwidth.as = bw;
        } else if (type == "TIAS") {
            bandwidth.tias = bw;
        } else if (type == "RS") {
            bandwidth.rs = bw;
        } else if (type == "RR") {
            bandwidth.rr = bw;
        }
    } catch (...) {
    }
}

// ============================================================================
// SDP Codec parsing
// ============================================================================

std::optional<SipSdpCodec> SipSdpCodec::parseRtpmap(const std::string& value) {
    // Format: a=rtpmap:97 AMR/8000/1
    SipSdpCodec codec;

    std::istringstream iss(value);
    std::string pt_str;
    std::getline(iss, pt_str, ' ');

    try {
        codec.payload_type = static_cast<uint8_t>(std::stoul(pt_str));
    } catch (...) {
        return std::nullopt;
    }

    std::string encoding_info;
    std::getline(iss, encoding_info);

    // Parse encoding_name/clock_rate/channels
    std::istringstream encoding_iss(encoding_info);
    std::string part;

    // Encoding name
    if (std::getline(encoding_iss, part, '/')) {
        codec.encoding_name = part;
    }

    // Clock rate
    if (std::getline(encoding_iss, part, '/')) {
        try {
            codec.clock_rate = std::stoul(part);
        } catch (...) {
            codec.clock_rate = 0;
        }
    }

    // Channels (optional)
    if (std::getline(encoding_iss, part, '/')) {
        try {
            codec.channels = std::stoul(part);
        } catch (...) {
        }
    }

    return codec;
}

void SipSdpCodec::parseFmtp(const std::string& value) {
    // Format: a=fmtp:97 mode-set=0,2,4,7; mode-change-period=2

    // Skip payload type
    size_t space = value.find(' ');
    if (space == std::string::npos) {
        return;
    }

    std::string params = value.substr(space + 1);

    // Parse semicolon-separated parameters
    std::istringstream iss(params);
    std::string param;
    while (std::getline(iss, param, ';')) {
        size_t eq = param.find('=');
        if (eq != std::string::npos) {
            std::string key = param.substr(0, eq);
            std::string val = param.substr(eq + 1);

            // Trim
            key.erase(0, key.find_first_not_of(" \t"));
            key.erase(key.find_last_not_of(" \t") + 1);
            val.erase(0, val.find_first_not_of(" \t"));
            val.erase(val.find_last_not_of(" \t") + 1);

            format_parameters[key] = val;
        }
    }
}

// ============================================================================
// Privacy parsing
// ============================================================================

SipPrivacy SipPrivacy::parse(const std::string& value) {
    SipPrivacy privacy{};

    // Convert to lowercase for comparison
    std::string lower_value = value;
    std::transform(lower_value.begin(), lower_value.end(), lower_value.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    // Check for each privacy type
    privacy.id = lower_value.find("id") != std::string::npos;
    privacy.header = lower_value.find("header") != std::string::npos;
    privacy.session = lower_value.find("session") != std::string::npos;
    privacy.user = lower_value.find("user") != std::string::npos;
    privacy.none = lower_value.find("none") != std::string::npos;
    privacy.critical = lower_value.find("critical") != std::string::npos;

    return privacy;
}

// ============================================================================
// Subscription-State parsing
// ============================================================================

std::optional<SipSubscriptionState> SipSubscriptionState::parse(const std::string& value) {
    SipSubscriptionState sub_state;

    // Format: active;expires=3600 or terminated;reason=timeout

    std::istringstream iss(value);
    std::string state_str;
    std::getline(iss, state_str, ';');

    // Trim
    state_str.erase(0, state_str.find_first_not_of(" \t"));
    state_str.erase(state_str.find_last_not_of(" \t") + 1);

    // Parse state
    if (state_str == "active") {
        sub_state.state = State::ACTIVE;
    } else if (state_str == "pending") {
        sub_state.state = State::PENDING;
    } else if (state_str == "terminated") {
        sub_state.state = State::TERMINATED;
    } else {
        sub_state.state = State::UNKNOWN;
    }

    // Parse parameters
    std::string param;
    while (std::getline(iss, param, ';')) {
        size_t eq = param.find('=');
        if (eq != std::string::npos) {
            std::string key = param.substr(0, eq);
            std::string val = param.substr(eq + 1);

            // Trim
            key.erase(0, key.find_first_not_of(" \t"));
            key.erase(key.find_last_not_of(" \t") + 1);
            val.erase(0, val.find_first_not_of(" \t"));
            val.erase(val.find_last_not_of(" \t") + 1);

            if (key == "expires") {
                try {
                    sub_state.expires = std::stoul(val);
                } catch (...) {
                }
            } else if (key == "reason") {
                sub_state.reason = val;
            } else if (key == "retry-after") {
                try {
                    sub_state.retry_after = std::stoul(val);
                } catch (...) {
                }
            }
        }
    }

    return sub_state;
}

std::string SipSubscriptionState::stateToString(State s) {
    switch (s) {
        case State::ACTIVE: return "active";
        case State::PENDING: return "pending";
        case State::TERMINATED: return "terminated";
        default: return "unknown";
    }
}

}  // namespace callflow
