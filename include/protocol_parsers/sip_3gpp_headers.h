#pragma once

#include <map>
#include <optional>
#include <string>
#include <vector>
#include <cstdint>

namespace callflow {

/**
 * 3GPP P-Asserted-Identity header (RFC 7315)
 * Used for network-asserted caller ID in IMS/VoLTE
 * Format: "Display Name" <sip:user@domain>, <tel:+1234567890>
 */
struct SipPAssertedIdentity {
    std::string display_name;
    std::string uri;  // SIP URI or Tel URI

    /**
     * Parse P-Asserted-Identity header value
     * Can contain multiple identities separated by commas
     */
    static std::optional<std::vector<SipPAssertedIdentity>> parse(const std::string& value);
};

/**
 * 3GPP P-Access-Network-Info header (RFC 7315)
 * Critical for QoS, roaming, and location tracking
 * Indicates access network type and cell ID for LTE/5G
 */
struct SipPAccessNetworkInfo {
    enum class AccessType {
        THREEGPP_E_UTRAN_FDD,  // LTE FDD
        THREEGPP_E_UTRAN_TDD,  // LTE TDD
        THREEGPP_NR,            // 5G NR
        IEEE_802_11,            // WiFi
        THREEGPP_GERAN,         // 2G GSM/EDGE
        THREEGPP_UTRAN_FDD,     // 3G UMTS FDD
        THREEGPP_UTRAN_TDD,     // 3G UMTS TDD
        UNKNOWN
    };

    AccessType access_type;
    std::optional<std::string> cell_id;  // ECGI (LTE) or NCGI (5G)
    std::map<std::string, std::string> parameters;

    /**
     * Parse P-Access-Network-Info header value
     * Example: "3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=234150999999999"
     * Example: "3GPP-NR; nrcgi=001010000000001"
     */
    static std::optional<SipPAccessNetworkInfo> parse(const std::string& value);

    /**
     * Convert AccessType enum to string
     */
    static std::string accessTypeToString(AccessType type);
};

/**
 * 3GPP P-Charging-Vector header (RFC 7315)
 * CRITICAL for billing correlation with Diameter Ro/Rf
 * Contains IMS Charging ID (ICID) and Inter-Operator Identifiers (IOI)
 */
struct SipPChargingVector {
    std::string icid_value;  // IMS Charging ID - CRITICAL for billing
    std::optional<std::string> icid_generated_at;  // IP address
    std::optional<std::string> orig_ioi;  // Originating IOI
    std::optional<std::string> term_ioi;  // Terminating IOI

    /**
     * Parse P-Charging-Vector header value
     * Format: "icid-value=AyretyU0dm+6O2IrT5tAFrbHLso=; icid-generated-at=192.0.2.1; orig-ioi=home1.net"
     */
    static std::optional<SipPChargingVector> parse(const std::string& value);
};

/**
 * 3GPP P-Charging-Function-Addresses header (RFC 7315)
 * Contains addresses of charging functions for offline/online charging
 */
struct SipPChargingFunctionAddresses {
    std::vector<std::string> ccf_addresses;  // Charging Collection Function (offline)
    std::vector<std::string> ecf_addresses;  // Event Charging Function (online)

    /**
     * Parse P-Charging-Function-Addresses header value
     * Format: "ccf=192.0.2.10; ccf=192.0.2.11; ecf=192.0.2.20"
     */
    static std::optional<SipPChargingFunctionAddresses> parse(const std::string& value);
};

/**
 * 3GPP P-Served-User header (RFC 5502)
 * Used on ISC interface between S-CSCF and AS
 */
struct SipPServedUser {
    std::string user_uri;
    std::optional<std::string> sescase;   // "orig" or "term"
    std::optional<std::string> regstate;  // "reg" or "unreg"

    /**
     * Parse P-Served-User header value
     * Format: "<sip:user@example.com>; sescase=orig; regstate=reg"
     */
    static std::optional<SipPServedUser> parse(const std::string& value);
};

/**
 * IPSec/TLS Security negotiation headers
 * Security-Client, Security-Server, Security-Verify (RFC 3329)
 */
struct SipSecurityInfo {
    std::string mechanism;  // "ipsec-3gpp", "tls"
    std::optional<std::string> algorithm;  // "hmac-sha-1-96", "hmac-md5-96"
    std::optional<uint32_t> spi_c;  // SPI client
    std::optional<uint32_t> spi_s;  // SPI server
    std::optional<uint16_t> port_c;  // Port client
    std::optional<uint16_t> port_s;  // Port server
    std::map<std::string, std::string> parameters;

    /**
     * Parse Security-Client/Server/Verify header value
     * Format: "ipsec-3gpp; alg=hmac-sha-1-96; spi-c=1234; spi-s=5678; port-c=5062; port-s=5064"
     */
    static std::optional<SipSecurityInfo> parse(const std::string& value);
};

/**
 * IMS Session Timer information
 * Session-Expires header (RFC 4028)
 */
struct SipSessionExpires {
    uint32_t expires;  // Session expiration time in seconds
    std::optional<std::string> refresher;  // "uac" or "uas"

    /**
     * Parse Session-Expires header value
     * Format: "1800; refresher=uac"
     */
    static std::optional<SipSessionExpires> parse(const std::string& value);
};

/**
 * SDP QoS Precondition (RFC 3312)
 * Current or desired QoS state
 */
struct SipSdpQosPrecondition {
    enum class Strength {
        NONE,
        MANDATORY,
        OPTIONAL,
        FAILURE,
        UNKNOWN
    };

    enum class Direction {
        LOCAL,
        REMOTE,
        UNKNOWN
    };

    enum class Status {
        NONE,
        SEND,
        RECV,
        SENDRECV,
        UNKNOWN
    };

    Strength strength;
    Direction direction;
    Status status;

    /**
     * Parse current QoS precondition
     * Format: "a=curr:qos local sendrecv"
     */
    static std::optional<SipSdpQosPrecondition> parseCurrent(const std::string& value);

    /**
     * Parse desired QoS precondition
     * Format: "a=des:qos mandatory local sendrecv"
     */
    static std::optional<SipSdpQosPrecondition> parseDesired(const std::string& value);

    /**
     * Convert enums to strings
     */
    static std::string strengthToString(Strength s);
    static std::string directionToString(Direction d);
    static std::string statusToString(Status s);
};

/**
 * SDP Bandwidth information
 */
struct SipSdpBandwidth {
    std::optional<uint32_t> as;    // Application-Specific (kbps)
    std::optional<uint32_t> tias;  // Transport Independent Application Specific (bps)
    std::optional<uint32_t> rs;    // RTCP bandwidth for senders (bps)
    std::optional<uint32_t> rr;    // RTCP bandwidth for receivers (bps)

    /**
     * Parse bandwidth line
     * Format: "b=AS:64" or "b=TIAS:64000"
     */
    static void parseLine(const std::string& line, SipSdpBandwidth& bandwidth);
};

/**
 * SDP Codec information (rtpmap + fmtp)
 */
struct SipSdpCodec {
    uint8_t payload_type;
    std::string encoding_name;  // "AMR", "EVS", "telephone-event"
    uint32_t clock_rate;
    std::optional<uint32_t> channels;
    std::map<std::string, std::string> format_parameters;  // From fmtp

    /**
     * Parse rtpmap attribute
     * Format: "a=rtpmap:97 AMR/8000/1"
     */
    static std::optional<SipSdpCodec> parseRtpmap(const std::string& value);

    /**
     * Parse fmtp attribute into existing codec
     * Format: "a=fmtp:97 mode-set=0,2,4,7; mode-change-period=2"
     */
    void parseFmtp(const std::string& value);
};

/**
 * Privacy header values (RFC 3323)
 */
struct SipPrivacy {
    bool id;        // Identity privacy
    bool header;    // Header privacy
    bool session;   // Session privacy
    bool user;      // User-level privacy
    bool none;      // No privacy requested
    bool critical;  // Privacy is critical

    /**
     * Parse Privacy header value
     * Format: "Privacy: id; header; user"
     */
    static SipPrivacy parse(const std::string& value);
};

/**
 * Subscription-State header (RFC 3265)
 */
struct SipSubscriptionState {
    enum class State {
        ACTIVE,
        PENDING,
        TERMINATED,
        UNKNOWN
    };

    State state;
    std::optional<uint32_t> expires;
    std::optional<std::string> reason;  // For terminated state
    std::optional<uint32_t> retry_after;

    /**
     * Parse Subscription-State header value
     * Format: "active;expires=3600" or "terminated;reason=timeout"
     */
    static std::optional<SipSubscriptionState> parse(const std::string& value);

    static std::string stateToString(State s);
};

}  // namespace callflow
