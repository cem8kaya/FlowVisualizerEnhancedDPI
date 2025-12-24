#pragma once

#include "correlation/diameter/diameter_types.h"
#include "protocol_parsers/diameter/diameter_base.h"
#include <memory>
#include <string>
#include <optional>

namespace callflow {
namespace correlation {

/**
 * @brief Diameter message wrapper for correlation
 *
 * Wraps protocol_parsers::diameter::DiameterMessage and adds
 * correlation-specific information like frame number and timestamp.
 */
class DiameterMessage {
public:
    DiameterMessage() = default;
    explicit DiameterMessage(std::shared_ptr<diameter::DiameterMessage> msg);
    ~DiameterMessage() = default;

    // ========================================================================
    // Message Identification
    // ========================================================================

    std::string getSessionId() const;
    uint32_t getHopByHopId() const;
    uint32_t getEndToEndId() const;
    uint32_t getCommandCode() const;
    uint32_t getApplicationId() const;

    // ========================================================================
    // Message Type
    // ========================================================================

    bool isRequest() const;
    bool isAnswer() const;
    DiameterDirection getDirection() const;
    DiameterInterface getInterface() const;
    std::string getCommandName() const;

    // ========================================================================
    // Result Information (for answers)
    // ========================================================================

    std::optional<uint32_t> getResultCode() const;
    std::optional<DiameterResultCode> getParsedResultCode() const;
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
    // Common AVP Access
    // ========================================================================

    std::optional<std::string> getOriginHost() const;
    std::optional<std::string> getOriginRealm() const;
    std::optional<std::string> getDestinationHost() const;
    std::optional<std::string> getDestinationRealm() const;

    // ========================================================================
    // Subscriber Identity Extraction
    // ========================================================================

    /**
     * @brief Extract IMSI from various AVPs
     * Checks: User-Name, Subscription-Id, 3GPP-IMSI
     */
    std::optional<std::string> extractImsi() const;

    /**
     * @brief Extract MSISDN from various AVPs
     * Checks: Subscription-Id, 3GPP-MSISDN
     */
    std::optional<std::string> extractMsisdn() const;

    /**
     * @brief Extract Framed-IP-Address (IPv4)
     */
    std::optional<std::string> extractFramedIp() const;

    /**
     * @brief Extract Framed-IPv6-Prefix
     */
    std::optional<std::string> extractFramedIpv6Prefix() const;

    /**
     * @brief Extract Called-Station-Id (APN)
     */
    std::optional<std::string> extractApn() const;

    /**
     * @brief Extract Public-Identity (for Cx/Sh)
     */
    std::optional<std::string> extractPublicIdentity() const;

    // ========================================================================
    // Gx-Specific Extraction
    // ========================================================================

    /**
     * @brief Extract CC-Request-Type (INITIAL, UPDATE, TERMINATION, EVENT)
     */
    std::optional<DiameterCCRequestType> extractCCRequestType() const;

    /**
     * @brief Extract CC-Request-Number
     */
    std::optional<uint32_t> extractCCRequestNumber() const;

    /**
     * @brief Extract QCI (QoS Class Identifier)
     */
    std::optional<uint8_t> extractQci() const;

    /**
     * @brief Extract Charging-Rule-Names
     */
    std::vector<std::string> extractChargingRuleNames() const;

    /**
     * @brief Extract Bearer-Identifier
     */
    std::optional<uint32_t> extractBearerIdentifier() const;

    // ========================================================================
    // Rx-Specific Extraction
    // ========================================================================

    /**
     * @brief Extract AF-Application-Identifier
     */
    std::optional<std::string> extractAfApplicationId() const;

    /**
     * @brief Extract Media-Type
     */
    std::optional<uint32_t> extractMediaType() const;

    // ========================================================================
    // S6a-Specific Extraction
    // ========================================================================

    /**
     * @brief Extract Visited-PLMN-Id
     */
    std::optional<std::string> extractVisitedPlmnId() const;

    /**
     * @brief Extract RAT-Type
     */
    std::optional<RatType> extractRatType() const;

    // ========================================================================
    // AVP Access
    // ========================================================================

    /**
     * @brief Find AVP by code
     */
    std::shared_ptr<diameter::DiameterAVP> findAVP(uint32_t code) const;

    /**
     * @brief Find AVP by code and vendor ID
     */
    std::shared_ptr<diameter::DiameterAVP> findAVP(uint32_t code, uint32_t vendor_id) const;

    /**
     * @brief Get all AVPs with given code
     */
    std::vector<std::shared_ptr<diameter::DiameterAVP>> findAllAVPs(uint32_t code) const;

    /**
     * @brief Get underlying protocol message
     */
    std::shared_ptr<diameter::DiameterMessage> getProtocolMessage() const {
        return protocol_msg_;
    }

private:
    std::shared_ptr<diameter::DiameterMessage> protocol_msg_;

    // Frame and timing information
    uint32_t frame_number_ = 0;
    double timestamp_ = 0.0;
    std::string source_ip_;
    std::string dest_ip_;
    uint16_t source_port_ = 0;
    uint16_t dest_port_ = 0;

    // Helper methods
    std::optional<std::string> extractFromSubscriptionId(SubscriptionIdType type) const;
    std::optional<std::string> extractIpAddressFromAVP(uint32_t code) const;
};

} // namespace correlation
} // namespace callflow
