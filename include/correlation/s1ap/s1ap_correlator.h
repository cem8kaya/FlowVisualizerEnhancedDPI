#pragma once

#include "correlation/s1ap/s1ap_context.h"
#include "correlation/nas/nas_correlator.h"
#include "correlation/identity/subscriber_context_manager.h"
#include <unordered_map>
#include <memory>
#include <mutex>

namespace callflow {
namespace correlation {

/**
 * @brief S1AP intra-protocol correlator
 *
 * Groups S1AP messages into UE contexts based on:
 * - MME-UE-S1AP-ID + eNB-UE-S1AP-ID pair
 *
 * Also extracts and correlates embedded NAS messages.
 */
class S1apCorrelator {
public:
    S1apCorrelator();
    explicit S1apCorrelator(SubscriberContextManager* ctx_manager,
                            NasCorrelator* nas_correlator = nullptr);
    ~S1apCorrelator() = default;

    /**
     * @brief Add a parsed S1AP message
     * @param msg S1AP message
     */
    void addMessage(const S1apMessage& msg);

    /**
     * @brief Finalize all contexts
     */
    void finalize();

    /**
     * @brief Get all UE contexts
     */
    std::vector<S1apContext*> getContexts();

    /**
     * @brief Get active UE contexts
     */
    std::vector<S1apContext*> getActiveContexts();

    /**
     * @brief Get released UE contexts
     */
    std::vector<S1apContext*> getReleasedContexts();

    /**
     * @brief Find context by UE S1AP IDs
     */
    S1apContext* findContext(uint32_t mme_ue_id, uint32_t enb_ue_id);

    /**
     * @brief Find context by MME-UE-S1AP-ID only
     *
     * Note: This may return multiple contexts if the MME-UE-S1AP-ID
     * was reused across different eNBs. Returns the most recent.
     */
    S1apContext* findContextByMmeUeId(uint32_t mme_ue_id);

    /**
     * @brief Find context by eNB-UE-S1AP-ID only
     *
     * Note: eNB-UE-S1AP-ID is only unique within an eNB.
     * Returns the most recent context.
     */
    S1apContext* findContextByEnbUeId(uint32_t enb_ue_id);

    /**
     * @brief Get statistics
     */
    struct Stats {
        size_t total_messages = 0;
        size_t total_contexts = 0;
        size_t active_contexts = 0;
        size_t released_contexts = 0;
        size_t initial_ue_messages = 0;
        size_t context_setups = 0;
        size_t context_releases = 0;
        size_t handovers = 0;
        size_t nas_messages = 0;
    };
    Stats getStats() const;

    /**
     * @brief Get embedded NAS correlator
     */
    NasCorrelator* getNasCorrelator() { return nas_correlator_; }

private:
    std::mutex mutex_;
    std::vector<std::unique_ptr<S1apContext>> contexts_;

    // Index by (MME-UE-S1AP-ID, eNB-UE-S1AP-ID) pair
    std::unordered_map<std::string, S1apContext*> context_index_;

    // Index by MME-UE-S1AP-ID (for quick lookup)
    std::unordered_map<uint32_t, S1apContext*> mme_ue_id_index_;

    // Index by eNB-UE-S1AP-ID (for quick lookup)
    std::unordered_map<uint32_t, S1apContext*> enb_ue_id_index_;

    SubscriberContextManager* ctx_manager_ = nullptr;
    NasCorrelator* nas_correlator_ = nullptr;
    bool owns_nas_correlator_ = false;

    Stats stats_;

    S1apContext* findOrCreateContext(const S1apMessage& msg);
    std::string makeContextKey(uint32_t mme_ue_id, uint32_t enb_ue_id);
    void updateSubscriberContext(const S1apContext& context);
    void handleNasPdu(const S1apMessage& msg, S1apContext* context);
};

} // namespace correlation
} // namespace callflow
