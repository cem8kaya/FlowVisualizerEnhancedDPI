#pragma once

#include <optional>
#include <string>
#include <vector>

#include "correlation/sip/sip_message.h"
#include "correlation/sip/sip_types.h"

namespace callflow {
namespace correlation {

// Forward declaration
class SipSession;

/**
 * @brief Call party information extracted from SIP session
 */
struct CallPartyInfo {
    std::string caller_msisdn;
    std::string caller_imsi;  // Added IMSI field
    std::string caller_ip;
    std::string caller_ipv6_prefix;

    std::string callee_msisdn;
    std::string callee_imsi;  // Added IMSI field
    std::string callee_ip;
    std::string callee_ipv6_prefix;

    std::optional<std::string> forward_target_msisdn;
    std::optional<std::string> forward_target_imsi;  // Added IMSI field

    SipDirection direction = SipDirection::ORIGINATING;
};

/**
 * @brief Detects SIP call types and extracts call party information
 *
 * This class analyzes SIP sessions to:
 * - Detect session type (registration, voice call, video call, SMS, etc.)
 * - Extract caller/callee MSISDNs from headers (PAI, PPI, From, To)
 * - Detect call forwarding scenarios
 * - Extract UE IP addresses from Contact and SDP
 * - Determine call direction (MO vs MT)
 */
class SipCallDetector {
public:
    /**
     * @brief Detect session type from messages
     */
    static SipSessionType detectSessionType(const std::vector<SipMessage>& messages);

    /**
     * @brief Extract call party information from session
     */
    static CallPartyInfo extractCallParties(const std::vector<SipMessage>& messages);

    /**
     * @brief Extract media information from SDP in messages
     */
    static std::vector<SipMediaInfo> extractMediaInfo(const std::vector<SipMessage>& messages);

    /**
     * @brief Detect if this is a voice call
     */
    static bool isVoiceCall(const std::vector<SipMessage>& messages);

    /**
     * @brief Detect if this is a video call
     */
    static bool isVideoCall(const std::vector<SipMessage>& messages);

    /**
     * @brief Detect if this is an emergency call
     */
    static bool isEmergencyCall(const std::vector<SipMessage>& messages);

    /**
     * @brief Detect call direction (MO/MT) based on Via headers
     */
    static SipDirection detectCallDirection(const std::vector<SipMessage>& messages);

    /**
     * @brief Extract MSISDN from SIP URI or header value
     *
     * Examples:
     *   sip:+14155551234@ims.example.com -> 14155551234
     *   <sip:14155551234@example.com> -> 14155551234
     *   "User Name" <sip:+1-415-555-1234@example.com> -> 14155551234
     */
    static std::string extractMsisdn(const std::string& uri_or_header);

    /**
     * @brief Extract user part from SIP URI
     *
     * Examples:
     *   sip:user@host -> user
     *   sip:+14155551234@host:5060 -> +14155551234
     */
    static std::string extractUser(const std::string& uri);

    /**
     * @brief Extract host part from SIP URI
     */
    static std::string extractHost(const std::string& uri);

    /**
     * @brief Check if URI is an emergency URN
     *
     * Examples:
     *   urn:service:sos -> true
     *   urn:service:sos.police -> true
     *   urn:service:sos.fire -> true
     */
    static bool isEmergencyUrn(const std::string& uri);

private:
    // Helper methods for media detection
    static std::vector<SipMediaInfo> parseSdp(const std::string& sdp);
    static bool hasAudioMedia(const std::vector<SipMediaInfo>& media);
    static bool hasVideoMedia(const std::vector<SipMediaInfo>& media);

    // Helper methods for party extraction
    static std::string getBestCallerIdentity(const SipMessage& msg);
    static std::string getBestCalleeIdentity(const SipMessage& msg);
    static std::optional<std::string> extractIpFromContact(const SipMessage& msg);
    static std::optional<std::string> extractIpFromSdp(const std::string& sdp);

    // URI parsing helpers
    static std::string stripUriDelimiters(const std::string& uri);
    static std::string normalizePhoneNumber(const std::string& number);
};

}  // namespace correlation
}  // namespace callflow
