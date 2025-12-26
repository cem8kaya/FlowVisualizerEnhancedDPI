#pragma once

#include <cstdint>
#include <cstring>
#include <optional>
#include <string>

#include "common/types.h"

namespace callflow {

/**
 * ProtocolDetector - Content-based protocol detection
 *
 * Provides deep packet inspection for protocol identification when:
 * - nDPI detection fails
 * - Non-standard ports are used
 * - Port-based heuristics are unreliable
 *
 * Uses protocol-specific signatures and header validation to accurately
 * identify protocols like SIP, DIAMETER, GTP, STUN, and RTP regardless
 * of the transport port being used.
 */
class ProtocolDetector {
public:
    /**
     * Content-based detection (called when nDPI fails or for validation)
     *
     * @param data Payload data to inspect
     * @param len Length of payload
     * @param src_port Source port (for additional context)
     * @param dst_port Destination port (for additional context)
     * @param protocol IP protocol (UDP=17, TCP=6, etc.)
     * @return Detected protocol type or nullopt if unknown
     */
    static std::optional<ProtocolType> detectFromPayload(const uint8_t* data, size_t len,
                                                         uint16_t src_port, uint16_t dst_port,
                                                         uint8_t protocol);

    /**
     * Detect SIP protocol from payload
     * Checks for SIP request methods (INVITE, ACK, etc.) and response signatures
     */
    static bool isSipPayload(const uint8_t* data, size_t len);

private:
    // Protocol signature matchers

    /**
     * Detect DIAMETER protocol from payload
     * Validates DIAMETER header structure (version, length, flags)
     */
    static bool isDiameterPayload(const uint8_t* data, size_t len);

    /**
     * Detect GTP protocol from payload and determine version
     * Returns true for both GTPv1 and GTPv2
     */
    static bool isGtpPayload(const uint8_t* data, size_t len);

    /**
     * Determine specific GTP protocol type (GTP-C vs GTP-U)
     *
     * @param data GTP packet data
     * @param len Length of data
     * @return GTP_C or GTP_U based on message type and version
     */
    static ProtocolType getGtpProtocolType(const uint8_t* data, size_t len);

    /**
     * Detect STUN protocol from payload
     * Checks for STUN magic cookie (0x2112A442)
     */
    static bool isStunPayload(const uint8_t* data, size_t len);

    /**
     * Detect RTP protocol from payload
     * Validates RTP header (version=2, payload type range)
     */
    static bool isRtpPayload(const uint8_t* data, size_t len);

    // SIP method signatures (requests)
    static constexpr const char* SIP_METHODS[] = {
        "INVITE", "ACK",   "BYE",       "CANCEL", "REGISTER", "OPTIONS", "INFO",
        "UPDATE", "PRACK", "SUBSCRIBE", "NOTIFY", "REFER",    "MESSAGE", "PUBLISH"};

    // SIP response signature
    static constexpr const char* SIP_RESPONSE_PREFIX = "SIP/2.0 ";

    // STUN magic cookie (RFC 5389)
    static constexpr uint32_t STUN_MAGIC_COOKIE = 0x2112A442;

    // Standard port definitions (for context)
    static constexpr uint16_t PORT_SIP = 5060;
    static constexpr uint16_t PORT_SIP_TLS = 5061;
    static constexpr uint16_t PORT_DIAMETER = 3868;
    static constexpr uint16_t PORT_GTP_C = 2123;
    static constexpr uint16_t PORT_GTP_U = 2152;
    static constexpr uint16_t PORT_PFCP = 8805;
};

}  // namespace callflow
