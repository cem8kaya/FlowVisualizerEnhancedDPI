#include "correlation/procedure_detector.h"

#include <algorithm>
#include <sstream>

#include "common/logger.h"

namespace callflow {
namespace correlation {

ProcedureDetector::ProcedureDetector() {
    LOG_INFO("Procedure Detector initialized");
}

std::vector<std::string> ProcedureDetector::processMessage(const SessionMessageRef& msg) {
    std::vector<std::string> changed_procedures;

    // First, try to match message to existing procedures
    auto matching_procedure_ids = findMatchingProcedures(msg);

    // Process message on all matching procedures
    for (const auto& proc_id : matching_procedure_ids) {
        auto it = procedures_.find(proc_id);
        if (it != procedures_.end()) {
            bool state_changed = it->second->processMessage(msg);
            if (state_changed) {
                changed_procedures.push_back(proc_id);

                // Update statistics if procedure completed or failed
                if (it->second->isComplete()) {
                    stats_.procedures_completed++;
                    LOG_DEBUG("Procedure {} completed", proc_id);
                } else if (it->second->isFailed()) {
                    stats_.procedures_failed++;
                    LOG_DEBUG("Procedure {} failed", proc_id);
                }
            }
        }
    }

    // If no matching procedures, try to start a new one
    if (matching_procedure_ids.empty()) {
        std::string new_proc_id = tryStartProcedure(msg);
        if (!new_proc_id.empty()) {
            changed_procedures.push_back(new_proc_id);
        }
    }

    return changed_procedures;
}

std::string ProcedureDetector::tryStartProcedure(const SessionMessageRef& msg) {
    std::shared_ptr<ProcedureStateMachine> machine;
    ProcedureType type = ProcedureType::UNKNOWN;

    // LTE Attach - starts with Initial UE Message + NAS Attach Request
    if (msg.message_type == MessageType::S1AP_INITIAL_UE_MESSAGE &&
        hasNasMessageType(msg.parsed_data, MessageType::NAS_ATTACH_REQUEST)) {
        machine = std::make_shared<LteAttachMachine>();
        type = ProcedureType::LTE_ATTACH;
    }
    // X2 Handover - starts with X2AP Handover Request
    else if (msg.message_type == MessageType::X2AP_HANDOVER_REQUEST) {
        machine = std::make_shared<X2HandoverMachine>();
        type = ProcedureType::LTE_HANDOVER_X2;
    }
    // VoLTE Call - starts with SIP INVITE
    else if (msg.message_type == MessageType::SIP_INVITE) {
        machine = std::make_shared<VoLteCallMachine>();
        type = ProcedureType::VOLTE_CALL_SETUP;
    }
    // 5G Registration - starts with Initial UE Message + NAS Registration Request
    else if (msg.message_type == MessageType::NGAP_INITIAL_UE_MESSAGE &&
             hasNasMessageType(msg.parsed_data, MessageType::NAS5G_REGISTRATION_REQUEST)) {
        machine = std::make_shared<FiveGRegistrationMachine>();
        type = ProcedureType::FIVEG_REGISTRATION;
    }

    if (machine) {
        // Generate unique procedure ID
        std::string proc_id = generateProcedureId(type);

        // Process the initial message
        machine->processMessage(msg);

        // Store the procedure
        procedures_[proc_id] = machine;

        // Add correlation keys
        addCorrelationKeys(proc_id, msg.correlation_key);

        // Update statistics
        stats_.total_procedures_detected++;
        stats_.by_type[type]++;

        LOG_INFO("New procedure detected: {} ({})", proc_id, procedureTypeToString(type));

        return proc_id;
    }

    return "";
}

std::vector<std::string> ProcedureDetector::findMatchingProcedures(const SessionMessageRef& msg) {
    std::vector<std::string> matching_ids;
    std::unordered_map<std::string, bool> seen;  // Avoid duplicates

    // Match by IMSI (most common for LTE/5G procedures)
    if (msg.correlation_key.imsi.has_value()) {
        const auto& imsi = msg.correlation_key.imsi.value();
        auto it = imsi_to_procedures_.find(imsi);
        if (it != imsi_to_procedures_.end()) {
            for (const auto& proc_id : it->second) {
                if (!seen[proc_id]) {
                    matching_ids.push_back(proc_id);
                    seen[proc_id] = true;
                }
            }
        }
    }

    // Match by SUPI (5G)
    if (msg.correlation_key.supi.has_value()) {
        const auto& supi = msg.correlation_key.supi.value();
        auto it = imsi_to_procedures_.find(supi);  // Use same map for SUPI
        if (it != imsi_to_procedures_.end()) {
            for (const auto& proc_id : it->second) {
                if (!seen[proc_id]) {
                    matching_ids.push_back(proc_id);
                    seen[proc_id] = true;
                }
            }
        }
    }

    // Match by SIP Call-ID (for VoLTE)
    if (msg.correlation_key.sip_call_id.has_value()) {
        const auto& call_id = msg.correlation_key.sip_call_id.value();
        auto it = sip_call_id_to_procedures_.find(call_id);
        if (it != sip_call_id_to_procedures_.end()) {
            for (const auto& proc_id : it->second) {
                if (!seen[proc_id]) {
                    matching_ids.push_back(proc_id);
                    seen[proc_id] = true;
                }
            }
        }
    }

    // Match by MME UE S1AP ID (for LTE)
    if (msg.correlation_key.mme_ue_s1ap_id.has_value()) {
        uint32_t mme_id = msg.correlation_key.mme_ue_s1ap_id.value();
        auto it = mme_ue_id_to_procedures_.find(mme_id);
        if (it != mme_ue_id_to_procedures_.end()) {
            for (const auto& proc_id : it->second) {
                if (!seen[proc_id]) {
                    matching_ids.push_back(proc_id);
                    seen[proc_id] = true;
                }
            }
        }
    }

    // Filter out completed/failed procedures for most message types
    // (unless it's a message that could belong to multiple procedures)
    matching_ids.erase(
        std::remove_if(matching_ids.begin(), matching_ids.end(),
                       [this](const std::string& id) {
                           auto it = procedures_.find(id);
                           if (it == procedures_.end())
                               return true;
                           // Keep active procedures
                           return it->second->isComplete() || it->second->isFailed();
                       }),
        matching_ids.end());

    return matching_ids;
}

std::string ProcedureDetector::generateProcedureId(ProcedureType type) {
    static uint64_t counter = 0;
    std::ostringstream oss;
    oss << procedureTypeToString(type) << "_" << ++counter;
    return oss.str();
}

void ProcedureDetector::addCorrelationKeys(const std::string& procedure_id,
                                            const SessionCorrelationKey& key) {
    // Add IMSI mapping
    if (key.imsi.has_value()) {
        imsi_to_procedures_[key.imsi.value()].push_back(procedure_id);
    }

    // Add SUPI mapping (5G)
    if (key.supi.has_value()) {
        imsi_to_procedures_[key.supi.value()].push_back(procedure_id);
    }

    // Add SIP Call-ID mapping
    if (key.sip_call_id.has_value()) {
        sip_call_id_to_procedures_[key.sip_call_id.value()].push_back(procedure_id);
    }

    // Add MME UE S1AP ID mapping
    if (key.mme_ue_s1ap_id.has_value()) {
        mme_ue_id_to_procedures_[key.mme_ue_s1ap_id.value()].push_back(procedure_id);
    }
}

void ProcedureDetector::removeCorrelationKeys(const std::string& procedure_id) {
    // Remove from all correlation maps
    // This is a simple implementation - could be optimized with reverse mapping

    for (auto& [key, procs] : imsi_to_procedures_) {
        procs.erase(std::remove(procs.begin(), procs.end(), procedure_id), procs.end());
    }

    for (auto& [key, procs] : sip_call_id_to_procedures_) {
        procs.erase(std::remove(procs.begin(), procs.end(), procedure_id), procs.end());
    }

    for (auto& [key, procs] : mme_ue_id_to_procedures_) {
        procs.erase(std::remove(procs.begin(), procs.end(), procedure_id), procs.end());
    }
}

std::vector<std::shared_ptr<ProcedureStateMachine>> ProcedureDetector::getActiveProcedures()
    const {
    std::vector<std::shared_ptr<ProcedureStateMachine>> active;
    for (const auto& [id, proc] : procedures_) {
        if (!proc->isComplete() && !proc->isFailed()) {
            active.push_back(proc);
        }
    }
    return active;
}

std::vector<std::shared_ptr<ProcedureStateMachine>> ProcedureDetector::getCompletedProcedures()
    const {
    std::vector<std::shared_ptr<ProcedureStateMachine>> completed;
    for (const auto& [id, proc] : procedures_) {
        if (proc->isComplete()) {
            completed.push_back(proc);
        }
    }
    return completed;
}

std::vector<std::shared_ptr<ProcedureStateMachine>> ProcedureDetector::getFailedProcedures()
    const {
    std::vector<std::shared_ptr<ProcedureStateMachine>> failed;
    for (const auto& [id, proc] : procedures_) {
        if (proc->isFailed()) {
            failed.push_back(proc);
        }
    }
    return failed;
}

std::shared_ptr<ProcedureStateMachine> ProcedureDetector::getProcedure(
    const std::string& procedure_id) const {
    auto it = procedures_.find(procedure_id);
    if (it != procedures_.end()) {
        return it->second;
    }
    return nullptr;
}

std::vector<std::shared_ptr<ProcedureStateMachine>> ProcedureDetector::getAllProcedures() const {
    std::vector<std::shared_ptr<ProcedureStateMachine>> all;
    for (const auto& [id, proc] : procedures_) {
        all.push_back(proc);
    }
    return all;
}

nlohmann::json ProcedureDetector::getStatistics() const {
    nlohmann::json j;
    j["total_procedures_detected"] = stats_.total_procedures_detected;
    j["procedures_completed"] = stats_.procedures_completed;
    j["procedures_failed"] = stats_.procedures_failed;
    j["active_procedures"] = getActiveProcedures().size();

    nlohmann::json by_type = nlohmann::json::object();
    for (const auto& [type, count] : stats_.by_type) {
        by_type[procedureTypeToString(type)] = count;
    }
    j["by_type"] = by_type;

    return j;
}

void ProcedureDetector::cleanup(int retention_seconds) {
    auto now = std::chrono::system_clock::now();
    std::vector<std::string> to_remove;

    for (const auto& [id, proc] : procedures_) {
        if (proc->isComplete() || proc->isFailed()) {
            auto end_time = proc->getEndTime();
            if (end_time.has_value()) {
                auto age = std::chrono::duration_cast<std::chrono::seconds>(now - end_time.value());
                if (age.count() > retention_seconds) {
                    to_remove.push_back(id);
                }
            }
        }
    }

    // Remove old procedures
    for (const auto& id : to_remove) {
        removeCorrelationKeys(id);
        procedures_.erase(id);
    }

    if (!to_remove.empty()) {
        LOG_INFO("Cleaned up {} old procedures", to_remove.size());
    }
}

} // namespace correlation
} // namespace callflow
