#include "event_extractor/json_exporter.h"
#include "common/logger.h"
#include "common/utils.h"
#include <fstream>

namespace callflow {

std::string JsonExporter::exportSession(const Session& session, bool include_events) {
    nlohmann::json j = session.toJson(include_events);
    return formatJson(j, true);
}

std::string JsonExporter::exportSessions(const std::vector<std::shared_ptr<Session>>& sessions,
                                        bool include_events) {
    nlohmann::json j = nlohmann::json::array();

    for (const auto& session : sessions) {
        if (session) {
            j.push_back(session->toJson(include_events));
        }
    }

    return formatJson(j, true);
}

std::string JsonExporter::exportSessionSummary(const Session& session) {
    nlohmann::json j = session.toSummaryJson();
    return formatJson(j, true);
}

bool JsonExporter::exportToFile(const std::string& filename,
                               const std::vector<std::shared_ptr<Session>>& sessions,
                               bool pretty_print) {
    try {
        nlohmann::json j = nlohmann::json::array();

        for (const auto& session : sessions) {
            if (session) {
                j.push_back(session->toJson(true));
            }
        }

        std::ofstream file(filename);
        if (!file.is_open()) {
            LOG_ERROR("Failed to open file for writing: " << filename);
            return false;
        }

        if (pretty_print) {
            file << j.dump(2);
        } else {
            file << j.dump();
        }

        file.close();

        LOG_INFO("Exported " << sessions.size() << " sessions to " << filename);
        return true;

    } catch (const std::exception& e) {
        LOG_ERROR("Failed to export sessions to file: " << e.what());
        return false;
    }
}

std::string JsonExporter::exportJobResult(const JobId& job_id,
                                         const std::vector<std::shared_ptr<Session>>& sessions,
                                         const nlohmann::json& metadata) {
    nlohmann::json result;

    result["job_id"] = job_id;
    result["status"] = "completed";
    result["timestamp"] = utils::timestampToIso8601(utils::now());
    result["metadata"] = metadata;

    // Session summaries
    nlohmann::json sessions_json = nlohmann::json::array();
    for (const auto& session : sessions) {
        if (session) {
            sessions_json.push_back(session->toSummaryJson());
        }
    }
    result["sessions"] = sessions_json;

    result["summary"] = {
        {"total_sessions", sessions.size()},
        {"total_events", std::accumulate(sessions.begin(), sessions.end(), 0ULL,
                                        [](size_t sum, const auto& s) {
                                            return sum + (s ? s->events.size() : 0);
                                        })}
    };

    return formatJson(result, true);
}

std::string JsonExporter::formatJson(const nlohmann::json& j, bool pretty_print) {
    if (pretty_print) {
        return j.dump(2);
    } else {
        return j.dump();
    }
}

}  // namespace callflow
