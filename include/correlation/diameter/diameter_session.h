#pragma once

#include "correlation/diameter/diameter_message.h"
#include "correlation/diameter/diameter_types.h"
#include "correlation/identity/subscriber_identity.h"
#include <vector>
#include <optional>
#include <string>

namespace callflow {
namespace correlation {

/**
 * @brief Represents a Diameter session for correlation
 *
 * A session is identified by Session-ID and contains:
 * - All request/answer pairs
 * - Interface type (S6a, Gx, Rx, Cx, Sh, etc.)
 * - Subscriber information (IMSI, MSISDN, Framed-IP)
 * - PDN connection info (for Gx)
 * - Time window and frame range
 */
class DiameterSession {
public:
    explicit DiameterSession(const std::string& session_id);
    ~DiameterSession() = default;

    // ========================================================================
    // Session Identification
    // ========================================================================

    std::string getSessionId() const { return session_id_; }
    DiameterInterface getInterface() const { return interface_; }
    std::string getInterfaceName() const;
    uint32_t getApplicationId() const { return application_id_; }

    // ========================================================================
    // Message Management
    // ========================================================================

    /**
     * @brief Add message to session
     */
    void addMessage(const DiameterMessage& msg);

    /**
     * @brief Get all messages in chronological order
     */
    const std::vector<DiameterMessage>& getMessages() const { return messages_; }

    /**
     * @brief Get message count
     */
    size_t getMessageCount() const { return messages_.size(); }

    // ========================================================================
    // Request/Answer Linking
    // ========================================================================

    /**
     * @brief Find answer for a request by Hop-by-Hop-ID
     */
    const DiameterMessage* findAnswer(const DiameterMessage& request) const;

    /**
     * @brief Find request for an answer by Hop-by-Hop-ID
     */
    const DiameterMessage* findRequest(const DiameterMessage& answer) const;

    /**
     * @brief Find message by Hop-by-Hop-ID
     */
    const DiameterMessage* findByHopByHop(uint32_t hop_by_hop_id) const;

    // ========================================================================
    // Subscriber Information
    // ========================================================================

    std::optional<std::string> getImsi() const { return imsi_; }
    std::optional<std::string> getMsisdn() const { return msisdn_; }
    std::optional<std::string> getPublicIdentity() const { return public_identity_; }

    void setImsi(const std::string& imsi) { imsi_ = imsi; }
    void setMsisdn(const std::string& msisdn) { msisdn_ = msisdn; }
    void setPublicIdentity(const std::string& identity) { public_identity_ = identity; }

    // ========================================================================
    // Network Information
    // ========================================================================

    std::optional<std::string> getFramedIpAddress() const { return framed_ip_; }
    std::optional<std::string> getFramedIpv6Prefix() const { return framed_ipv6_prefix_; }
    std::optional<std::string> getCalledStationId() const { return called_station_id_; }  // APN
    std::optional<RatType> getRatType() const { return rat_type_; }

    void setFramedIpAddress(const std::string& ip) { framed_ip_ = ip; }
    void setFramedIpv6Prefix(const std::string& prefix) { framed_ipv6_prefix_ = prefix; }
    void setCalledStationId(const std::string& apn) { called_station_id_ = apn; }
    void setRatType(RatType rat) { rat_type_ = rat; }

    // ========================================================================
    // Gx-Specific Information
    // ========================================================================

    std::optional<DiameterCCRequestType> getCCRequestType() const { return ccr_type_; }
    std::vector<std::string> getChargingRuleNames() const { return charging_rules_; }
    std::optional<uint8_t> getQci() const { return qci_; }
    std::optional<uint32_t> getBearerIdentifier() const { return bearer_id_; }

    void setCCRequestType(DiameterCCRequestType type) { ccr_type_ = type; }
    void addChargingRule(const std::string& rule);
    void setQci(uint8_t qci) { qci_ = qci; }
    void setBearerIdentifier(uint32_t bearer_id) { bearer_id_ = bearer_id; }

    // ========================================================================
    // Rx-Specific Information
    // ========================================================================

    std::optional<std::string> getAfApplicationId() const { return af_application_id_; }
    std::optional<uint32_t> getMediaType() const { return media_type_; }

    void setAfApplicationId(const std::string& af_app_id) { af_application_id_ = af_app_id; }
    void setMediaType(uint32_t media_type) { media_type_ = media_type; }

    // ========================================================================
    // Time Window
    // ========================================================================

    double getStartTime() const { return start_time_; }
    double getEndTime() const { return end_time_; }
    uint32_t getStartFrame() const { return start_frame_; }
    uint32_t getEndFrame() const { return end_frame_; }
    double getDuration() const;

    // ========================================================================
    // Correlation IDs
    // ========================================================================

    /**
     * @brief Set intra-protocol correlator ID
     * For Diameter, this is typically the Session-ID
     */
    void setIntraCorrelator(const std::string& id) { intra_correlator_ = id; }
    std::string getIntraCorrelator() const { return intra_correlator_; }

    /**
     * @brief Set inter-protocol correlator ID
     * Links to VoLTE Call, PDN Session, etc.
     */
    void setInterCorrelator(const std::string& id) { inter_correlator_ = id; }
    std::string getInterCorrelator() const { return inter_correlator_; }

    // ========================================================================
    // Result Tracking
    // ========================================================================

    /**
     * @brief Check if session has any error responses
     */
    bool hasErrors() const { return has_errors_; }

    /**
     * @brief Get all result codes from answers
     */
    std::vector<DiameterResultCode> getResultCodes() const { return result_codes_; }

    /**
     * @brief Add result code
     */
    void addResultCode(const DiameterResultCode& rc);

    // ========================================================================
    // Session State
    // ========================================================================

    /**
     * @brief Check if session is finalized
     */
    bool isFinalized() const { return finalized_; }

    /**
     * @brief Finalize session (extract all information, no more messages expected)
     */
    void finalize();

private:
    std::string session_id_;
    DiameterInterface interface_ = DiameterInterface::UNKNOWN;
    uint32_t application_id_ = 0;

    std::vector<DiameterMessage> messages_;

    // Subscriber info
    std::optional<std::string> imsi_;
    std::optional<std::string> msisdn_;
    std::optional<std::string> public_identity_;

    // Network info
    std::optional<std::string> framed_ip_;
    std::optional<std::string> framed_ipv6_prefix_;
    std::optional<std::string> called_station_id_;  // APN
    std::optional<RatType> rat_type_;

    // Gx-specific
    std::optional<DiameterCCRequestType> ccr_type_;
    std::vector<std::string> charging_rules_;
    std::optional<uint8_t> qci_;
    std::optional<uint32_t> bearer_id_;

    // Rx-specific
    std::optional<std::string> af_application_id_;
    std::optional<uint32_t> media_type_;

    // Time window
    double start_time_ = 0.0;
    double end_time_ = 0.0;
    uint32_t start_frame_ = 0;
    uint32_t end_frame_ = 0;

    // Correlation
    std::string intra_correlator_;
    std::string inter_correlator_;

    // Result tracking
    bool has_errors_ = false;
    std::vector<DiameterResultCode> result_codes_;

    // State
    bool finalized_ = false;

    // Internal methods
    void detectInterface();
    void extractSubscriberInfo();
    void extractNetworkInfo();
    void extractGxInfo();
    void extractRxInfo();
    void updateTimeWindow(const DiameterMessage& msg);
    void updateFromMessage(const DiameterMessage& msg);
};

} // namespace correlation
} // namespace callflow
