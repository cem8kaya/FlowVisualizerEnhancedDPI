#include "correlation/s1ap/s1ap_correlator.h"
#include <sstream>

namespace callflow {
namespace correlation {

S1apCorrelator::S1apCorrelator() {
    nas_correlator_ = new NasCorrelator();
    owns_nas_correlator_ = true;
}

S1apCorrelator::S1apCorrelator(SubscriberContextManager* ctx_manager,
                               NasCorrelator* nas_correlator)
    : ctx_manager_(ctx_manager), nas_correlator_(nas_correlator) {
    if (!nas_correlator_) {
        nas_correlator_ = new NasCorrelator(ctx_manager);
        owns_nas_correlator_ = true;
    }
}

void S1apCorrelator::addMessage(const S1apMessage& msg) {
    std::lock_guard<std::mutex> lock(mutex_);

    stats_.total_messages++;

    // Find or create context
    S1apContext* context = findOrCreateContext(msg);
    if (context) {
        context->addMessage(msg);

        // Handle embedded NAS-PDU
        if (msg.hasNasPdu()) {
            handleNasPdu(msg, context);
            stats_.nas_messages++;
        }

        // Update statistics
        switch (msg.getMessageType()) {
            case S1apMessageType::INITIAL_UE_MESSAGE:
                stats_.initial_ue_messages++;
                break;
            case S1apMessageType::INITIAL_CONTEXT_SETUP_REQUEST:
                stats_.context_setups++;
                break;
            case S1apMessageType::UE_CONTEXT_RELEASE_COMPLETE:
                stats_.context_releases++;
                break;
            case S1apMessageType::HANDOVER_NOTIFY:
            case S1apMessageType::PATH_SWITCH_REQUEST:
                stats_.handovers++;
                break;
            default:
                break;
        }
    }
}

void S1apCorrelator::finalize() {
    std::lock_guard<std::mutex> lock(mutex_);

    for (auto& context : contexts_) {
        context->finalize();
        updateSubscriberContext(*context);
    }

    // Finalize NAS correlator if we own it
    if (owns_nas_correlator_ && nas_correlator_) {
        nas_correlator_->finalize();
    }

    // Update statistics
    stats_.total_contexts = contexts_.size();
    stats_.active_contexts = 0;
    stats_.released_contexts = 0;

    for (const auto& context : contexts_) {
        auto state = context->getState();
        if (state == S1apContext::State::ACTIVE || state == S1apContext::State::CONTEXT_SETUP) {
            stats_.active_contexts++;
        } else if (state == S1apContext::State::RELEASED) {
            stats_.released_contexts++;
        }
    }
}

std::vector<S1apContext*> S1apCorrelator::getContexts() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<S1apContext*> result;
    result.reserve(contexts_.size());
    for (auto& context : contexts_) {
        result.push_back(context.get());
    }
    return result;
}

std::vector<S1apContext*> S1apCorrelator::getActiveContexts() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<S1apContext*> result;
    for (auto& context : contexts_) {
        auto state = context->getState();
        if (state == S1apContext::State::ACTIVE || state == S1apContext::State::CONTEXT_SETUP) {
            result.push_back(context.get());
        }
    }
    return result;
}

std::vector<S1apContext*> S1apCorrelator::getReleasedContexts() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<S1apContext*> result;
    for (auto& context : contexts_) {
        if (context->getState() == S1apContext::State::RELEASED) {
            result.push_back(context.get());
        }
    }
    return result;
}

S1apContext* S1apCorrelator::findContext(uint32_t mme_ue_id, uint32_t enb_ue_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string key = makeContextKey(mme_ue_id, enb_ue_id);
    auto it = context_index_.find(key);
    return (it != context_index_.end()) ? it->second : nullptr;
}

S1apContext* S1apCorrelator::findContextByMmeUeId(uint32_t mme_ue_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = mme_ue_id_index_.find(mme_ue_id);
    return (it != mme_ue_id_index_.end()) ? it->second : nullptr;
}

S1apContext* S1apCorrelator::findContextByEnbUeId(uint32_t enb_ue_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = enb_ue_id_index_.find(enb_ue_id);
    return (it != enb_ue_id_index_.end()) ? it->second : nullptr;
}

S1apCorrelator::Stats S1apCorrelator::getStats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

S1apContext* S1apCorrelator::findOrCreateContext(const S1apMessage& msg) {
    // Get UE S1AP IDs from message
    auto mme_ue_id = msg.getMmeUeS1apId();
    auto enb_ue_id = msg.getEnbUeS1apId();

    // For Initial UE Message, only eNB-UE-S1AP-ID is present
    if (msg.getMessageType() == S1apMessageType::INITIAL_UE_MESSAGE && enb_ue_id) {
        // Create new context (MME-UE-S1AP-ID will be assigned later)
        auto context = std::make_unique<S1apContext>(0, *enb_ue_id);
        S1apContext* context_ptr = context.get();

        enb_ue_id_index_[*enb_ue_id] = context_ptr;
        contexts_.push_back(std::move(context));
        return context_ptr;
    }

    // For other messages, both IDs should be present
    if (!mme_ue_id || !enb_ue_id) {
        return nullptr;
    }

    // Try to find existing context
    std::string key = makeContextKey(*mme_ue_id, *enb_ue_id);
    auto it = context_index_.find(key);
    if (it != context_index_.end()) {
        return it->second;
    }

    // Check if we have a context with only eNB-UE-S1AP-ID (from Initial UE Message)
    auto enb_it = enb_ue_id_index_.find(*enb_ue_id);
    if (enb_it != enb_ue_id_index_.end() && enb_it->second->getMmeUeS1apId() == 0) {
        // Update the context with MME-UE-S1AP-ID
        S1apContext* context_ptr = enb_it->second;
        // Note: In a full implementation, we'd update the internal MME UE ID

        // Index by full key
        context_index_[key] = context_ptr;
        mme_ue_id_index_[*mme_ue_id] = context_ptr;
        return context_ptr;
    }

    // Create new context
    auto context = std::make_unique<S1apContext>(*mme_ue_id, *enb_ue_id);
    S1apContext* context_ptr = context.get();

    context_index_[key] = context_ptr;
    mme_ue_id_index_[*mme_ue_id] = context_ptr;
    enb_ue_id_index_[*enb_ue_id] = context_ptr;

    contexts_.push_back(std::move(context));
    return context_ptr;
}

std::string S1apCorrelator::makeContextKey(uint32_t mme_ue_id, uint32_t enb_ue_id) {
    std::ostringstream oss;
    oss << mme_ue_id << ":" << enb_ue_id;
    return oss.str();
}

void S1apCorrelator::updateSubscriberContext(const S1apContext& context) {
    if (!ctx_manager_) {
        return;
    }

    // Update subscriber context based on S1AP context
    if (auto imsi = context.getImsi()) {
        auto ctx = ctx_manager_->getOrCreateByImsi(*imsi);

        if (auto imei = context.getImei()) {
            ctx_manager_->linkImsiImei(*imsi, *imei);
        }
    }
}

void S1apCorrelator::handleNasPdu(const S1apMessage& msg, S1apContext* context) {
    if (!nas_correlator_ || !msg.hasNasPdu()) {
        return;
    }

    auto nas_pdu = msg.getNasPdu();
    if (nas_pdu) {
        auto mme_ue_id = msg.getMmeUeS1apId();
        auto enb_ue_id = msg.getEnbUeS1apId();

        nas_correlator_->addMessage(*nas_pdu, mme_ue_id, enb_ue_id);
    }
}

} // namespace correlation
} // namespace callflow
