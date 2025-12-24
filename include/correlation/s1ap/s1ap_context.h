#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "correlation/nas/nas_message.h"
#include "correlation/s1ap/s1ap_message.h"

namespace callflow {
namespace correlation {

/**
 * @brief S1AP UE Context
 *
 * Tracks the S1AP signalling connection for a specific UE,
 * identified by the pair (MME-UE-S1AP-ID, eNB-UE-S1AP-ID).
 *
 * This context contains all S1AP messages and embedded NAS messages
 * for this UE's S1 connection.
 */
class S1apContext {
public:
    S1apContext();
    explicit S1apContext(uint32_t mme_ue_id, uint32_t enb_ue_id);
    ~S1apContext() = default;

    // Add S1AP message
    void addMessage(const S1apMessage& msg);

    // UE S1AP IDs
    uint32_t getMmeUeS1apId() const { return mme_ue_s1ap_id_; }
    uint32_t getEnbUeS1apId() const { return enb_ue_s1ap_id_; }

    // Messages
    const std::vector<S1apMessage>& getMessages() const { return messages_; }
    size_t getMessageCount() const { return messages_.size(); }

    // Get all NAS messages from this context
    std::vector<NasMessage> getNasMessages() const;

    // E-RAB tracking
    struct ErabState {
        uint8_t erab_id;
        bool active = false;
        std::optional<uint8_t> qci;
        std::optional<std::string> transport_layer_address;
        std::optional<uint32_t> gtp_teid;
        double setup_time = 0.0;
        double release_time = 0.0;
    };
    const std::vector<ErabState>& getErabs() const { return erabs_; }

    // Location tracking
    std::optional<S1apMessage::TrackingAreaIdentity> getCurrentTai() const { return current_tai_; }
    std::optional<S1apMessage::EcgiInfo> getCurrentEcgi() const { return current_ecgi_; }

    // Context state
    enum class State {
        INITIAL,          // Initial UE Message received
        CONTEXT_SETUP,    // Initial Context Setup in progress
        ACTIVE,           // Context active (setup complete)
        RELEASE_PENDING,  // UE Context Release requested
        RELEASED          // Context released
    };
    State getState() const { return state_; }

    // Release cause
    std::optional<S1apCauseType> getReleaseCauseType() const { return release_cause_type_; }
    std::optional<uint8_t> getReleaseCauseValue() const { return release_cause_value_; }

    // Time window
    double getStartTime() const { return start_time_; }
    double getEndTime() const { return end_time_; }
    uint32_t getStartFrame() const { return start_frame_; }
    uint32_t getEndFrame() const { return end_frame_; }

    // Subscriber identifiers (extracted from NAS messages)
    std::optional<std::string> getImsi() const { return imsi_; }
    std::optional<std::string> getImei() const { return imei_; }
    std::optional<uint32_t> getTmsi() const { return tmsi_; }

    // Correlation
    void setIntraCorrelator(const std::string& id) { intra_correlator_ = id; }
    std::string getIntraCorrelator() const { return intra_correlator_; }

    void setInterCorrelator(const std::string& id) { inter_correlator_ = id; }
    std::string getInterCorrelator() const { return inter_correlator_; }

    // Finalize
    void finalize();

    // String representation
    std::string toString() const;

private:
    uint32_t mme_ue_s1ap_id_ = 0;
    uint32_t enb_ue_s1ap_id_ = 0;

    State state_ = State::INITIAL;

    std::vector<S1apMessage> messages_;
    std::vector<ErabState> erabs_;

    // Location
    std::optional<S1apMessage::TrackingAreaIdentity> current_tai_;
    std::optional<S1apMessage::EcgiInfo> current_ecgi_;

    // Release cause
    std::optional<S1apCauseType> release_cause_type_;
    std::optional<uint8_t> release_cause_value_;

    // Time window
    double start_time_ = 0.0;
    double end_time_ = 0.0;
    uint32_t start_frame_ = 0;
    uint32_t end_frame_ = 0;

    // Subscriber identifiers (from NAS)
    std::optional<std::string> imsi_;
    std::optional<std::string> imei_;
    std::optional<uint32_t> tmsi_;

    // Correlation
    std::string intra_correlator_;
    std::string inter_correlator_;

    // Internal methods
    void updateErabState(const S1apMessage& msg);
    void updateLocation(const S1apMessage& msg);
    void updateState(const S1apMessage& msg);
    void updateTimeWindow(const S1apMessage& msg);
    void extractIdentifiers(const S1apMessage& msg);
};

}  // namespace correlation
}  // namespace callflow
