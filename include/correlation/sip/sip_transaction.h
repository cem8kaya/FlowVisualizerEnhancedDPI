#pragma once

#include "correlation/sip/sip_message.h"
#include <memory>
#include <vector>
#include <string>

namespace callflow {
namespace correlation {

/**
 * @brief SIP transaction state
 *
 * Represents the state of a SIP transaction (client or server).
 * Based on RFC 3261 transaction state machines.
 */
enum class SipTransactionState {
    INIT,           // Initial state
    TRYING,         // Request sent/received (INVITE client)
    PROCEEDING,     // 1xx received (client) / sent (server)
    COMPLETED,      // Final response received/sent
    CONFIRMED,      // ACK received (INVITE server only)
    TERMINATED      // Transaction terminated
};

/**
 * @brief Represents a SIP transaction
 *
 * A transaction consists of a request and its responses.
 * Identified by branch parameter in Via header + CSeq method.
 *
 * RFC 3261:
 * - Client transaction: generates request, receives responses
 * - Server transaction: receives request, generates responses
 */
class SipTransaction {
public:
    SipTransaction(const std::string& transaction_id,
                   const SipMessage& request);
    ~SipTransaction() = default;

    // Transaction identification
    std::string getTransactionId() const { return transaction_id_; }
    std::string getBranch() const { return branch_; }
    std::string getMethod() const { return method_; }
    uint32_t getCSeq() const { return cseq_; }

    // State
    SipTransactionState getState() const { return state_; }
    void setState(SipTransactionState state) { state_ = state; }

    // Messages
    const SipMessage& getRequest() const { return request_; }
    const std::vector<SipMessage>& getResponses() const { return responses_; }

    void addResponse(const SipMessage& response);

    // Response queries
    bool hasProvisionalResponse() const;
    bool hasFinalResponse() const;
    std::optional<SipMessage> getFinalResponse() const;
    int getFinalStatusCode() const;

    // Timing
    double getStartTime() const { return start_time_; }
    double getEndTime() const { return end_time_; }
    double getDuration() const;

    // Frame range
    uint32_t getStartFrame() const { return start_frame_; }
    uint32_t getEndFrame() const { return end_frame_; }

    // Update state based on response
    void updateState(const SipMessage& response);

private:
    std::string transaction_id_;
    std::string branch_;
    std::string method_;
    uint32_t cseq_;

    SipTransactionState state_ = SipTransactionState::INIT;

    SipMessage request_;
    std::vector<SipMessage> responses_;

    double start_time_ = 0.0;
    double end_time_ = 0.0;
    uint32_t start_frame_ = 0;
    uint32_t end_frame_ = 0;
};

} // namespace correlation
} // namespace callflow
