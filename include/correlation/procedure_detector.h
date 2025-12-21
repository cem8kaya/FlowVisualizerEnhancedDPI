#pragma once

#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "correlation/fiveg_registration_machine.h"
#include "correlation/lte_attach_machine.h"
#include "correlation/procedure_state_machine.h"
#include "correlation/volte_call_machine.h"
#include "correlation/x2_handover_machine.h"
#include "session/session_types.h"

namespace callflow {
namespace correlation {

/**
 * Procedure Detector
 *
 * Automatically detects and tracks telecommunication procedures from message streams.
 * Manages state machine lifecycle and correlates messages across multiple procedures.
 */
class ProcedureDetector {
public:
    ProcedureDetector();
    ~ProcedureDetector() = default;

    /**
     * Process a message and update relevant procedure state machines
     * @param msg Message to process
     * @return List of procedures that changed state
     */
    std::vector<std::string> processMessage(const SessionMessageRef& msg);

    /**
     * Get all active (not complete/failed) procedures
     */
    std::vector<std::shared_ptr<ProcedureStateMachine>> getActiveProcedures() const;

    /**
     * Get all completed procedures
     */
    std::vector<std::shared_ptr<ProcedureStateMachine>> getCompletedProcedures() const;

    /**
     * Get all failed procedures
     */
    std::vector<std::shared_ptr<ProcedureStateMachine>> getFailedProcedures() const;

    /**
     * Get procedure by ID
     */
    std::shared_ptr<ProcedureStateMachine> getProcedure(const std::string& procedure_id) const;

    /**
     * Get all procedures (active, completed, and failed)
     */
    std::vector<std::shared_ptr<ProcedureStateMachine>> getAllProcedures() const;

    /**
     * Get statistics
     */
    nlohmann::json getStatistics() const;

    /**
     * Clean up old completed/failed procedures (older than retention period)
     * @param retention_seconds How long to keep completed procedures
     */
    void cleanup(int retention_seconds = 3600);

private:
    // Active procedures indexed by procedure ID
    std::unordered_map<std::string, std::shared_ptr<ProcedureStateMachine>> procedures_;

    // Correlation keys to procedure IDs (for matching messages to procedures)
    std::unordered_map<std::string, std::vector<std::string>> imsi_to_procedures_;
    std::unordered_map<std::string, std::vector<std::string>> sip_call_id_to_procedures_;
    std::unordered_map<uint32_t, std::vector<std::string>> mme_ue_id_to_procedures_;

    // Statistics
    struct Statistics {
        uint64_t total_procedures_detected = 0;
        uint64_t procedures_completed = 0;
        uint64_t procedures_failed = 0;
        std::map<ProcedureType, uint64_t> by_type;
    };
    Statistics stats_;

    /**
     * Try to start a new procedure based on message type
     * @return procedure ID if started, empty string otherwise
     */
    std::string tryStartProcedure(const SessionMessageRef& msg);

    /**
     * Try to match message to existing procedures
     * @return List of matching procedure IDs
     */
    std::vector<std::string> findMatchingProcedures(const SessionMessageRef& msg);

    /**
     * Generate unique procedure ID
     */
    std::string generateProcedureId(ProcedureType type);

    /**
     * Add correlation keys for procedure
     */
    void addCorrelationKeys(const std::string& procedure_id,
                            const SessionCorrelationKey& key);

    /**
     * Remove procedure from correlation maps
     */
    void removeCorrelationKeys(const std::string& procedure_id);
};

} // namespace correlation
} // namespace callflow
