#pragma once

#include "correlation/gtpv2/gtpv2_types.h"
#include "protocol_parsers/gtp/gtpv2_types.h"
#include "protocol_parsers/gtp/gtpv2_ie_parser.h"
#include <memory>
#include <string>
#include <optional>
#include <vector>

namespace callflow {
namespace correlation {

/**
 * @brief GTPv2 message wrapper for correlation
 *
 * Wraps GTPv2 protocol message and adds correlation-specific
 * information like frame number, timestamp, and extracted IEs.
 */
class Gtpv2Message {
public:
    Gtpv2Message() = default;
    ~Gtpv2Message() = default;

    // ========================================================================
    // Message Identification
    // ========================================================================

    void setMessageType(GtpV2MessageType type) { message_type_ = type; }
    GtpV2MessageType getMessageType() const { return message_type_; }

    void setTeid(uint32_t teid) { teid_ = teid; }
    uint32_t getTeid() const { return teid_; }

    void setSequence(uint32_t sequence) { sequence_ = sequence; }
    uint32_t getSequence() const { return sequence_; }

    // ========================================================================
    // Message Type
    // ========================================================================

    bool isRequest() const { return correlation::isRequest(message_type_); }
    bool isResponse() const { return correlation::isResponse(message_type_); }
    Gtpv2Direction getDirection() const { return correlation::getDirection(message_type_); }
    std::string getMessageTypeName() const { return correlation::getMessageTypeName(message_type_); }

    // ========================================================================
    // Response Information
    // ========================================================================

    void setCause(const GtpV2Cause& cause) { cause_ = cause; }
    std::optional<GtpV2Cause> getCause() const { return cause_; }
    bool isSuccess() const;
    bool isError() const;

    // ========================================================================
    // Frame and Timing
    // ========================================================================

    void setFrameNumber(uint32_t frame) { frame_number_ = frame; }
    uint32_t getFrameNumber() const { return frame_number_; }

    void setTimestamp(double timestamp) { timestamp_ = timestamp; }
    double getTimestamp() const { return timestamp_; }

    void setSourceIp(const std::string& ip) { source_ip_ = ip; }
    std::string getSourceIp() const { return source_ip_; }

    void setDestIp(const std::string& ip) { dest_ip_ = ip; }
    std::string getDestIp() const { return dest_ip_; }

    void setSourcePort(uint16_t port) { source_port_ = port; }
    uint16_t getSourcePort() const { return source_port_; }

    void setDestPort(uint16_t port) { dest_port_ = port; }
    uint16_t getDestPort() const { return dest_port_; }

    // ========================================================================
    // Information Element Storage
    // ========================================================================

    void setIEs(const std::vector<gtp::GtpV2IE>& ies) { ies_ = ies; }
    const std::vector<gtp::GtpV2IE>& getIEs() const { return ies_; }

    /**
     * @brief Find IE by type
     */
    std::optional<gtp::GtpV2IE> findIE(GtpV2IEType type) const;

    /**
     * @brief Find all IEs with given type
     */
    std::vector<gtp::GtpV2IE> findAllIEs(GtpV2IEType type) const;

    // ========================================================================
    // Subscriber Identity Extraction
    // ========================================================================

    /**
     * @brief Extract IMSI from IMSI IE
     */
    std::optional<std::string> extractImsi() const;

    /**
     * @brief Extract MSISDN from MSISDN IE
     */
    std::optional<std::string> extractMsisdn() const;

    /**
     * @brief Extract MEI (IMEI) from MEI IE
     */
    std::optional<std::string> extractMei() const;

    // ========================================================================
    // Network Information Extraction
    // ========================================================================

    /**
     * @brief Extract APN from APN IE
     */
    std::optional<std::string> extractApn() const;

    /**
     * @brief Extract PDN Address Allocation
     */
    std::optional<GtpV2PDNAddressAllocation> extractPdnAddress() const;

    /**
     * @brief Extract RAT Type
     */
    std::optional<RATType> extractRatType() const;

    /**
     * @brief Extract Serving Network
     */
    std::optional<gtp::GtpV2ServingNetwork> extractServingNetwork() const;

    // ========================================================================
    // Bearer Context Extraction
    // ========================================================================

    /**
     * @brief Extract all Bearer Contexts from message
     */
    std::vector<gtp::GtpV2BearerContext> extractBearerContexts() const;

    /**
     * @brief Extract EPS Bearer ID (from top-level IE)
     */
    std::optional<uint8_t> extractEpsBearerId() const;

    // ========================================================================
    // F-TEID Extraction
    // ========================================================================

    /**
     * @brief Extract all F-TEIDs from message (including nested in Bearer Contexts)
     */
    std::vector<GtpV2FTEID> extractAllFteids() const;

    /**
     * @brief Extract F-TEID by interface type
     */
    std::optional<GtpV2FTEID> extractFteidByInterface(FTEIDInterfaceType type) const;

    // ========================================================================
    // Request/Response Matching
    // ========================================================================

    /**
     * @brief Check if this message matches a request (by sequence)
     */
    bool matchesRequest(const Gtpv2Message& request) const;

private:
    GtpV2MessageType message_type_ = static_cast<GtpV2MessageType>(0);
    uint32_t teid_ = 0;
    uint32_t sequence_ = 0;

    // Frame and timing information
    uint32_t frame_number_ = 0;
    double timestamp_ = 0.0;
    std::string source_ip_;
    std::string dest_ip_;
    uint16_t source_port_ = 0;
    uint16_t dest_port_ = 0;

    // Information Elements
    std::vector<gtp::GtpV2IE> ies_;

    // Cached extracted values
    std::optional<GtpV2Cause> cause_;
};

} // namespace correlation
} // namespace callflow
