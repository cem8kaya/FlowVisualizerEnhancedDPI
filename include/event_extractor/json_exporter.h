#pragma once

#include <nlohmann/json.hpp>
#include <string>
#include <vector>

#include "common/types.h"
#include "flow_manager/session_correlator.h"

namespace callflow {

/**
 * JSON exporter - exports sessions and events to JSON format
 */
class JsonExporter {
public:
    JsonExporter() = default;
    ~JsonExporter() = default;

    /**
     * Export a single session to JSON
     */
    std::string exportSession(const FlowSession& session, bool include_events = true);

    /**
     * Export multiple sessions to JSON array
     */
    std::string exportSessions(const std::vector<std::shared_ptr<FlowSession>>& sessions,
                               bool include_events = false);

    /**
     * Export session summary (without events)
     */
    std::string exportSessionSummary(const FlowSession& session);

    /**
     * Export all sessions to a file
     */
    bool exportToFile(const std::string& filename,
                      const std::vector<std::shared_ptr<FlowSession>>& sessions,
                      bool pretty_print = true);

    /**
     * Export job result with metadata
     */
    std::string exportJobResult(const JobId& job_id,
                                const std::vector<std::shared_ptr<FlowSession>>& sessions,
                                const nlohmann::json& metadata);

private:
    std::string formatJson(const nlohmann::json& j, bool pretty_print = true);
};

}  // namespace callflow
