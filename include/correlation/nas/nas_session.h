#pragma once

#include "correlation/nas/nas_types.h"
#include "correlation/nas/nas_message.h"
#include "correlation/identity/subscriber_identity.h"
#include "correlation/gtpv2/gtpv2_types.h"
#include <vector>
#include <optional>

namespace callflow {
namespace correlation {

/**
 * @brief NAS session types
 */
enum class NasSessionType {
    EMM,        // Mobility management (attach, TAU, detach)
    ESM,        // Session management (PDN, bearer)
    UNKNOWN
};

/**
 * @brief Represents a NAS session
 *
 * A NAS session tracks:
 * - EMM procedures (Attach, TAU, Detach, Auth, Security)
 * - ESM procedures (PDN Connectivity, Bearer activation)
 * - Subscriber identifiers (IMSI, IMEI, GUTI, TMSI)
 */
class NasSession {
public:
    NasSession();
    ~NasSession() = default;

    // Add message
    void addMessage(const NasMessage& msg);

    // Messages
    const std::vector<NasMessage>& getMessages() const { return messages_; }
    size_t getMessageCount() const { return messages_.size(); }

    // Session type
    NasSessionType getType() const { return type_; }

    // Subscriber identifiers
    std::optional<std::string> getImsi() const { return imsi_; }
    std::optional<std::string> getImei() const { return imei_; }
    std::optional<std::string> getImeisv() const { return imeisv_; }
    std::optional<Guti4G> getGuti() const { return guti_; }
    std::optional<uint32_t> getTmsi() const { return tmsi_; }

    // PDN information (from ESM)
    std::optional<std::string> getApn() const { return apn_; }
    std::optional<std::string> getPdnAddress() const { return pdn_address_; }
    std::optional<uint8_t> getEpsBearerId() const { return eps_bearer_id_; }
    std::optional<uint8_t> getLinkedBearerId() const { return linked_bearer_id_; }

    // QoS (from ESM)
    std::optional<uint8_t> getQci() const { return qci_; }

    // PDN Class (IMS detection)
    PdnClass getPdnClass() const { return pdn_class_; }
    bool isIms() const { return pdn_class_ == PdnClass::IMS; }

    // EMM state
    enum class EmmState {
        DEREGISTERED,
        REGISTERED_INITIATED,
        REGISTERED,
        DEREGISTERED_INITIATED,
        TAU_INITIATED,
        SERVICE_REQUEST_INITIATED
    };
    EmmState getEmmState() const { return emm_state_; }

    // Security state
    bool isSecurityActivated() const { return security_activated_; }

    // Time window
    double getStartTime() const { return start_time_; }
    double getEndTime() const { return end_time_; }
    uint32_t getStartFrame() const { return start_frame_; }
    uint32_t getEndFrame() const { return end_frame_; }

    // Correlation
    void setIntraCorrelator(const std::string& id) { intra_correlator_ = id; }
    std::string getIntraCorrelator() const { return intra_correlator_; }

    void setInterCorrelator(const std::string& id) { inter_correlator_ = id; }
    std::string getInterCorrelator() const { return inter_correlator_; }

    // Link to S1AP context
    void setS1apContext(uint32_t mme_ue_id, uint32_t enb_ue_id);
    std::optional<uint32_t> getMmeUeS1apId() const { return mme_ue_s1ap_id_; }
    std::optional<uint32_t> getEnbUeS1apId() const { return enb_ue_s1ap_id_; }

    // Finalize
    void finalize();

    // String representation
    std::string toString() const;

private:
    NasSessionType type_ = NasSessionType::UNKNOWN;
    EmmState emm_state_ = EmmState::DEREGISTERED;

    std::vector<NasMessage> messages_;

    // Subscriber identifiers
    std::optional<std::string> imsi_;
    std::optional<std::string> imei_;
    std::optional<std::string> imeisv_;
    std::optional<Guti4G> guti_;
    std::optional<uint32_t> tmsi_;

    // PDN info
    std::optional<std::string> apn_;
    std::optional<std::string> pdn_address_;
    std::optional<uint8_t> eps_bearer_id_;
    std::optional<uint8_t> linked_bearer_id_;
    std::optional<uint8_t> qci_;
    PdnClass pdn_class_ = PdnClass::OTHER;

    // Security
    bool security_activated_ = false;

    // S1AP context
    std::optional<uint32_t> mme_ue_s1ap_id_;
    std::optional<uint32_t> enb_ue_s1ap_id_;

    // Time window
    double start_time_ = 0.0;
    double end_time_ = 0.0;
    uint32_t start_frame_ = 0;
    uint32_t end_frame_ = 0;

    // Correlation
    std::string intra_correlator_;
    std::string inter_correlator_;

    // Internal methods
    void extractIdentifiers(const NasMessage& msg);
    void extractPdnInfo(const NasMessage& msg);
    void updateEmmState(const NasMessage& msg);
    void updateTimeWindow(const NasMessage& msg);
    void detectPdnClass();
};

} // namespace correlation
} // namespace callflow
