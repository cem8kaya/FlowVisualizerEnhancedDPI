#pragma once

#include "correlation/gtpv2/gtpv2_types.h"
#include "correlation/gtpv2/gtpv2_bearer.h"
#include "correlation/gtpv2/gtpv2_message.h"
#include <vector>
#include <memory>
#include <optional>
#include <string>

namespace callflow {
namespace correlation {

/**
 * @brief Represents a GTPv2-C session (PDN Connection)
 *
 * A session is identified by Control TEID and contains:
 * - Default bearer and all dedicated bearers
 * - Subscriber information (IMSI, MSISDN, MEI)
 * - PDN address (UE IP)
 * - F-TEIDs for all interfaces
 */
class Gtpv2Session {
public:
    Gtpv2Session(uint32_t control_teid, uint32_t sequence);
    ~Gtpv2Session() = default;

    // ========================================================================
    // Session Identification
    // ========================================================================

    uint32_t getControlTeid() const { return control_teid_; }
    uint32_t getSequence() const { return sequence_; }
    std::string getSessionKey() const;  // TEID + Sequence hash

    // ========================================================================
    // PDN Type
    // ========================================================================

    PdnClass getPdnClass() const { return pdn_class_; }
    void setPdnClass(PdnClass pdn_class) { pdn_class_ = pdn_class; }
    bool isIms() const { return pdn_class_ == PdnClass::IMS; }
    bool isEmergency() const { return pdn_class_ == PdnClass::EMERGENCY; }

    // ========================================================================
    // Message Management
    // ========================================================================

    /**
     * @brief Add message to session
     */
    void addMessage(const Gtpv2Message& msg);

    /**
     * @brief Get all messages
     */
    const std::vector<Gtpv2Message>& getMessages() const { return messages_; }

    /**
     * @brief Get message count
     */
    size_t getMessageCount() const { return messages_.size(); }

    /**
     * @brief Find response for a request
     */
    const Gtpv2Message* findResponse(const Gtpv2Message& request) const;

    // ========================================================================
    // Bearer Management
    // ========================================================================

    /**
     * @brief Add bearer to session
     */
    void addBearer(const GtpBearer& bearer);

    /**
     * @brief Get default bearer (EBI == LBI)
     */
    GtpBearer* getDefaultBearer();
    const GtpBearer* getDefaultBearer() const;

    /**
     * @brief Get bearer by EBI
     */
    GtpBearer* getBearer(uint8_t ebi);
    const GtpBearer* getBearer(uint8_t ebi) const;

    /**
     * @brief Get all bearers
     */
    std::vector<GtpBearer*> getBearers();
    std::vector<const GtpBearer*> getBearers() const;

    /**
     * @brief Get dedicated bearers (linked via LBI)
     */
    std::vector<GtpBearer*> getDedicatedBearers();
    std::vector<const GtpBearer*> getDedicatedBearers() const;

    /**
     * @brief Check if session has dedicated bearers
     */
    bool hasDedicatedBearers() const;

    // ========================================================================
    // Subscriber Information
    // ========================================================================

    std::optional<std::string> getImsi() const { return imsi_; }
    void setImsi(const std::string& imsi) { imsi_ = imsi; }

    std::optional<std::string> getMsisdn() const { return msisdn_; }
    void setMsisdn(const std::string& msisdn) { msisdn_ = msisdn; }

    std::optional<std::string> getMei() const { return mei_; }
    void setMei(const std::string& mei) { mei_ = mei; }

    // ========================================================================
    // Network Information
    // ========================================================================

    std::string getApn() const { return apn_; }
    void setApn(const std::string& apn);

    std::optional<std::string> getPdnAddressV4() const { return pdn_addr_v4_; }
    void setPdnAddressV4(const std::string& addr) { pdn_addr_v4_ = addr; }

    std::optional<std::string> getPdnAddressV6() const { return pdn_addr_v6_; }
    void setPdnAddressV6(const std::string& addr) { pdn_addr_v6_ = addr; }

    std::optional<RATType> getRatType() const { return rat_type_; }
    void setRatType(RATType rat) { rat_type_ = rat; }

    std::optional<std::string> getServingNetwork() const { return serving_network_; }
    void setServingNetwork(const std::string& network) { serving_network_ = network; }

    // ========================================================================
    // F-TEIDs
    // ========================================================================

    /**
     * @brief Get all F-TEIDs
     */
    const std::vector<GtpV2FTEID>& getFteids() const { return fteids_; }

    /**
     * @brief Add F-TEID
     */
    void addFteid(const GtpV2FTEID& fteid);

    /**
     * @brief Find F-TEID by interface type
     */
    std::optional<GtpV2FTEID> getFteidByInterface(FTEIDInterfaceType iface_type) const;

    // ========================================================================
    // Time Window
    // ========================================================================

    double getStartTime() const { return start_time_; }
    double getEndTime() const { return end_time_; }
    uint32_t getStartFrame() const { return start_frame_; }
    uint32_t getEndFrame() const { return end_frame_; }
    double getDuration() const { return end_time_ - start_time_; }

    // ========================================================================
    // Session State
    // ========================================================================

    enum class State {
        CREATING,       // Create Session Request sent
        ACTIVE,         // Create Session Response (accepted) received
        MODIFYING,      // Modify/Update in progress
        DELETING,       // Delete Session Request sent
        DELETED         // Delete Session Response received
    };

    State getState() const { return state_; }
    void setState(State state) { state_ = state; }

    /**
     * @brief Check if session is active
     */
    bool isActive() const { return state_ == State::ACTIVE; }

    // ========================================================================
    // Subsession Tracking
    // ========================================================================

    struct Subsession {
        std::string type;         // "dflt_ebi", "ded_ebi"
        std::string idx;          // e.g., "5", "6"
        uint32_t start_frame;
        uint32_t end_frame;
    };

    const std::vector<Subsession>& getSubsessions() const { return subsessions_; }
    void addSubsession(const Subsession& subsession) { subsessions_.push_back(subsession); }

    // ========================================================================
    // Correlation
    // ========================================================================

    void setIntraCorrelator(const std::string& id) { intra_correlator_ = id; }
    std::string getIntraCorrelator() const { return intra_correlator_; }

    void setInterCorrelator(const std::string& id) { inter_correlator_ = id; }
    std::string getInterCorrelator() const { return inter_correlator_; }

    // ========================================================================
    // Finalize
    // ========================================================================

    /**
     * @brief Finalize session (extract all information)
     */
    void finalize();

    /**
     * @brief Check if session is finalized
     */
    bool isFinalized() const { return finalized_; }

private:
    uint32_t control_teid_;
    uint32_t sequence_;

    PdnClass pdn_class_ = PdnClass::OTHER;
    State state_ = State::CREATING;

    std::vector<Gtpv2Message> messages_;
    std::vector<GtpBearer> bearers_;
    std::vector<GtpV2FTEID> fteids_;
    std::vector<Subsession> subsessions_;

    // Subscriber info
    std::optional<std::string> imsi_;
    std::optional<std::string> msisdn_;
    std::optional<std::string> mei_;

    // Network info
    std::string apn_;
    std::optional<std::string> pdn_addr_v4_;
    std::optional<std::string> pdn_addr_v6_;
    std::optional<RATType> rat_type_;
    std::optional<std::string> serving_network_;

    // Time window
    double start_time_ = 0.0;
    double end_time_ = 0.0;
    uint32_t start_frame_ = 0;
    uint32_t end_frame_ = 0;

    // Correlation
    std::string intra_correlator_;
    std::string inter_correlator_;

    bool finalized_ = false;

    // Internal methods
    void extractSubscriberInfo(const Gtpv2Message& msg);
    void extractNetworkInfo(const Gtpv2Message& msg);
    void extractBearerInfo(const Gtpv2Message& msg);
    void extractFteids(const Gtpv2Message& msg);
    void detectPdnClass();
    void updateTimeWindow(const Gtpv2Message& msg);
    void updateState(const Gtpv2Message& msg);
    void linkDedicatedBearers();
};

} // namespace correlation
} // namespace callflow
