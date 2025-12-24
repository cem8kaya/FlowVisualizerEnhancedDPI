#include "correlation/sip/sip_transaction.h"

namespace callflow {
namespace correlation {

SipTransaction::SipTransaction(const std::string& transaction_id,
                               const SipMessage& request)
    : transaction_id_(transaction_id),
      method_(request.getMethod()),
      cseq_(request.getCSeq()),
      request_(request),
      start_time_(request.getTimestamp()),
      end_time_(request.getTimestamp()),
      start_frame_(request.getFrameNumber()),
      end_frame_(request.getFrameNumber()) {

    // Extract branch from Via header
    auto top_via = request.getTopVia();
    if (top_via.has_value()) {
        branch_ = top_via->branch;
    }

    // Set initial state
    if (request.isInvite()) {
        state_ = SipTransactionState::TRYING;
    } else {
        state_ = SipTransactionState::TRYING;
    }
}

void SipTransaction::addResponse(const SipMessage& response) {
    responses_.push_back(response);

    // Update end time and frame
    end_time_ = response.getTimestamp();
    end_frame_ = response.getFrameNumber();

    // Update state
    updateState(response);
}

void SipTransaction::updateState(const SipMessage& response) {
    int status_code = response.getStatusCode();

    if (status_code >= 100 && status_code < 200) {
        // Provisional response
        if (state_ == SipTransactionState::TRYING ||
            state_ == SipTransactionState::INIT) {
            state_ = SipTransactionState::PROCEEDING;
        }
    } else if (status_code >= 200) {
        // Final response
        if (method_ == "INVITE") {
            if (status_code >= 200 && status_code < 300) {
                // 2xx for INVITE - transaction continues until ACK
                state_ = SipTransactionState::COMPLETED;
            } else {
                // 3xx, 4xx, 5xx, 6xx for INVITE
                state_ = SipTransactionState::COMPLETED;
            }
        } else {
            // Non-INVITE transaction
            state_ = SipTransactionState::COMPLETED;
        }
    }
}

bool SipTransaction::hasProvisionalResponse() const {
    for (const auto& resp : responses_) {
        if (resp.isProvisional()) {
            return true;
        }
    }
    return false;
}

bool SipTransaction::hasFinalResponse() const {
    for (const auto& resp : responses_) {
        if (resp.getStatusCode() >= 200) {
            return true;
        }
    }
    return false;
}

std::optional<SipMessage> SipTransaction::getFinalResponse() const {
    // Return the last final response
    for (auto it = responses_.rbegin(); it != responses_.rend(); ++it) {
        if (it->getStatusCode() >= 200) {
            return *it;
        }
    }
    return std::nullopt;
}

int SipTransaction::getFinalStatusCode() const {
    auto final = getFinalResponse();
    if (final.has_value()) {
        return final->getStatusCode();
    }
    return 0;
}

double SipTransaction::getDuration() const {
    return end_time_ - start_time_;
}

} // namespace correlation
} // namespace callflow
