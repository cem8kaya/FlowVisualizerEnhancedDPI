#pragma once

#include "correlation/nas/nas_session.h"
#include "correlation/identity/subscriber_context_manager.h"
#include <unordered_map>
#include <memory>
#include <mutex>

namespace callflow {
namespace correlation {

/**
 * @brief NAS intra-protocol correlator
 *
 * Groups NAS messages into sessions by:
 * - IMSI (when available)
 * - GUTI/TMSI (for temporary identity)
 * - S1AP context (MME-UE-S1AP-ID + eNB-UE-S1AP-ID)
 */
class NasCorrelator {
public:
    NasCorrelator();
    explicit NasCorrelator(SubscriberContextManager* ctx_manager);
    ~NasCorrelator() = default;

    /**
     * @brief Add a parsed NAS message
     * @param msg NAS message
     * @param mme_ue_id MME-UE-S1AP-ID from S1AP (optional)
     * @param enb_ue_id eNB-UE-S1AP-ID from S1AP (optional)
     */
    void addMessage(const NasMessage& msg,
                    std::optional<uint32_t> mme_ue_id = std::nullopt,
                    std::optional<uint32_t> enb_ue_id = std::nullopt);

    /**
     * @brief Finalize all sessions
     */
    void finalize();

    /**
     * @brief Get all sessions
     */
    std::vector<NasSession*> getSessions();

    /**
     * @brief Get EMM sessions only
     */
    std::vector<NasSession*> getEmmSessions();

    /**
     * @brief Get ESM sessions only
     */
    std::vector<NasSession*> getEsmSessions();

    /**
     * @brief Get IMS ESM sessions (for VoLTE)
     */
    std::vector<NasSession*> getImsEsmSessions();

    /**
     * @brief Find session by IMSI
     */
    std::vector<NasSession*> findByImsi(const std::string& imsi);

    /**
     * @brief Find session by TMSI
     */
    NasSession* findByTmsi(uint32_t tmsi);

    /**
     * @brief Find session by S1AP context
     */
    NasSession* findByS1apContext(uint32_t mme_ue_id, uint32_t enb_ue_id);

    /**
     * @brief Get statistics
     */
    struct Stats {
        size_t total_messages = 0;
        size_t total_sessions = 0;
        size_t emm_sessions = 0;
        size_t esm_sessions = 0;
        size_t ims_esm_sessions = 0;
        size_t attach_procedures = 0;
        size_t tau_procedures = 0;
        size_t detach_procedures = 0;
    };
    Stats getStats() const;

private:
    std::mutex mutex_;
    std::vector<std::unique_ptr<NasSession>> sessions_;

    // Index by IMSI
    std::unordered_map<std::string, NasSession*> imsi_index_;
    // Index by TMSI
    std::unordered_map<uint32_t, NasSession*> tmsi_index_;
    // Index by S1AP context
    std::unordered_map<std::string, NasSession*> s1ap_context_index_;

    SubscriberContextManager* ctx_manager_ = nullptr;

    Stats stats_;

    NasSession* findOrCreateSession(const NasMessage& msg,
                                    std::optional<uint32_t> mme_ue_id,
                                    std::optional<uint32_t> enb_ue_id);
    std::string makeS1apContextKey(uint32_t mme_ue_id, uint32_t enb_ue_id);
    void updateSubscriberContext(const NasSession& session);
};

} // namespace correlation
} // namespace callflow
