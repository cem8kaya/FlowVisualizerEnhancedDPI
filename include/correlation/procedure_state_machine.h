#pragma once

#include <chrono>
#include <memory>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <vector>

#include "common/types.h"
#include "session/session_types.h"

namespace callflow {
namespace correlation {

/**
 * Procedure Step - represents one step in a procedure flow
 */
struct ProcedureStep {
    std::string step_name;
    MessageType message_type;
    std::chrono::system_clock::time_point timestamp;
    std::optional<std::chrono::milliseconds> latency_from_previous;
    bool expected;  // Was this message expected at this step?

    nlohmann::json toJson() const;
};

/**
 * Base class for all procedure state machines
 *
 * State machines track the progress of standard 3GPP telecommunication
 * procedures (e.g., LTE Attach, VoLTE Call Setup, X2 Handover).
 *
 * Each state machine:
 * - Detects procedure start
 * - Tracks state transitions through message sequence
 * - Calculates timing metrics
 * - Detects failures and deviations
 */
class ProcedureStateMachine {
public:
    virtual ~ProcedureStateMachine() = default;

    /**
     * Process a new message and update state
     * @param msg Message to process
     * @return true if state changed, false otherwise
     */
    virtual bool processMessage(const SessionMessageRef& msg) = 0;

    /**
     * Check if procedure is complete (all expected messages received)
     */
    virtual bool isComplete() const = 0;

    /**
     * Check if procedure failed (unexpected error or timeout)
     */
    virtual bool isFailed() const = 0;

    /**
     * Get procedure type
     */
    virtual ProcedureType getProcedureType() const = 0;

    /**
     * Get procedure start time
     */
    virtual std::chrono::system_clock::time_point getStartTime() const = 0;

    /**
     * Get procedure end time (if complete)
     */
    virtual std::optional<std::chrono::system_clock::time_point> getEndTime() const = 0;

    /**
     * Get total procedure duration in milliseconds (if complete)
     */
    virtual std::optional<std::chrono::milliseconds> getDuration() const = 0;

    /**
     * Get all procedure steps in chronological order
     */
    virtual std::vector<ProcedureStep> getSteps() const = 0;

    /**
     * Get procedure metrics as JSON
     */
    virtual nlohmann::json getMetrics() const = 0;

    /**
     * Export complete procedure state as JSON
     */
    virtual nlohmann::json toJson() const = 0;

    /**
     * Get human-readable procedure state description
     */
    virtual std::string getStateDescription() const = 0;
};

/**
 * Helper function to extract NAS message type from S1AP/NGAP message
 */
std::optional<MessageType> extractNasMessageType(const nlohmann::json& parsed_data);

/**
 * Helper function to check if message contains specific NAS PDU type
 */
bool hasNasMessageType(const nlohmann::json& parsed_data, MessageType expected_type);

/**
 * Helper function to extract IMSI from parsed data
 */
std::optional<std::string> extractImsi(const nlohmann::json& parsed_data);

/**
 * Helper function to extract TEID from GTP message
 */
std::optional<uint32_t> extractTeid(const nlohmann::json& parsed_data,
                                    const std::string& interface_type);

}  // namespace correlation
}  // namespace callflow
