#include "common/config_loader.h"

#include <cstdlib>
#include <fstream>

#include "common/logger.h"

namespace callflow {

bool ConfigLoader::loadFromFile(const std::string& config_file, Config& config) {
    try {
        std::ifstream infile(config_file);
        if (!infile) {
            LOG_ERROR("Failed to open config file: " << config_file);
            return false;
        }

        nlohmann::json j;
        infile >> j;

        parseConfig(j, config);

        LOG_INFO("Configuration loaded from: " << config_file);
        return true;

    } catch (const std::exception& e) {
        LOG_ERROR("Failed to load config: " << e.what());
        return false;
    }
}

bool ConfigLoader::loadFromJson(const std::string& json_str, Config& config) {
    try {
        nlohmann::json j = nlohmann::json::parse(json_str);
        parseConfig(j, config);
        return true;
    } catch (const std::exception& e) {
        LOG_ERROR("Failed to parse JSON config: " << e.what());
        return false;
    }
}

void ConfigLoader::applyEnvOverrides(Config& config) {
    // Server settings
    const char* port = std::getenv("CALLFLOW_PORT");
    if (port) {
        config.api_port = static_cast<uint16_t>(std::atoi(port));
        LOG_INFO("Environment override: PORT=" << config.api_port);
    }

    const char* bind_addr = std::getenv("CALLFLOW_BIND_ADDR");
    if (bind_addr) {
        config.api_bind_address = bind_addr;
        LOG_INFO("Environment override: BIND_ADDR=" << config.api_bind_address);
    }

    const char* workers = std::getenv("CALLFLOW_WORKERS");
    if (workers) {
        config.worker_threads = std::atoi(workers);
        LOG_INFO("Environment override: WORKERS=" << config.worker_threads);
    }

    const char* upload_dir = std::getenv("CALLFLOW_UPLOAD_DIR");
    if (upload_dir) {
        config.upload_dir = upload_dir;
        LOG_INFO("Environment override: UPLOAD_DIR=" << config.upload_dir);
    }

    const char* results_dir = std::getenv("CALLFLOW_RESULTS_DIR");
    if (results_dir) {
        config.results_dir = results_dir;
        LOG_INFO("Environment override: RESULTS_DIR=" << config.results_dir);
    }

    const char* enable_ndpi = std::getenv("CALLFLOW_ENABLE_NDPI");
    if (enable_ndpi) {
        config.enable_ndpi =
            (std::string(enable_ndpi) == "true" || std::string(enable_ndpi) == "1");
        LOG_INFO("Environment override: ENABLE_NDPI=" << (config.enable_ndpi ? "true" : "false"));
    }
}

bool ConfigLoader::saveToFile(const std::string& config_file, const Config& config) {
    try {
        nlohmann::json j = configToJson(config);

        std::ofstream outfile(config_file);
        if (!outfile) {
            LOG_ERROR("Failed to open config file for writing: " << config_file);
            return false;
        }

        outfile << j.dump(2);  // Pretty print with 2-space indent

        LOG_INFO("Configuration saved to: " << config_file);
        return true;

    } catch (const std::exception& e) {
        LOG_ERROR("Failed to save config: " << e.what());
        return false;
    }
}

std::string ConfigLoader::getDefaultConfigJson() {
    Config default_config;
    ConfigLoader loader;
    return loader.configToJson(default_config).dump(2);
}

void ConfigLoader::parseConfig(const nlohmann::json& j, Config& config) {
    // Server settings
    if (j.contains("server")) {
        const auto& server = j["server"];
        if (server.contains("bind_address")) {
            config.api_bind_address = server["bind_address"];
        }
        if (server.contains("port")) {
            config.api_port = server["port"];
        }
        if (server.contains("workers")) {
            config.api_worker_threads = server["workers"];
        }
        if (server.contains("max_upload_size_mb")) {
            config.max_upload_size_mb = server["max_upload_size_mb"];
        }
    }

    // Processing settings
    if (j.contains("processing")) {
        const auto& processing = j["processing"];
        if (processing.contains("worker_threads")) {
            config.worker_threads = processing["worker_threads"];
        }
        if (processing.contains("packet_queue_size")) {
            config.max_packet_queue_size = processing["packet_queue_size"];
        }
        if (processing.contains("flow_timeout_sec")) {
            config.flow_timeout_sec = processing["flow_timeout_sec"];
        }
    }

    // Storage settings
    if (j.contains("storage")) {
        const auto& storage = j["storage"];
        if (storage.contains("upload_dir")) {
            config.upload_dir = storage["upload_dir"];
        }
        if (storage.contains("output_dir")) {
            config.results_dir = storage["output_dir"];
        }
        if (storage.contains("retention_hours")) {
            config.retention_hours = storage["retention_hours"];
        }
    }

    // nDPI settings
    if (j.contains("ndpi")) {
        const auto& ndpi = j["ndpi"];
        if (ndpi.contains("enable")) {
            config.enable_ndpi = ndpi["enable"];
        }
        if (ndpi.contains("protocols") && ndpi["protocols"].is_array()) {
            config.ndpi_protocols.clear();
            for (const auto& proto : ndpi["protocols"]) {
                config.ndpi_protocols.push_back(proto);
            }
        }
    }

    // WebSocket settings
    if (j.contains("websocket")) {
        const auto& ws = j["websocket"];
        if (ws.contains("heartbeat_interval_sec")) {
            config.ws_heartbeat_interval_sec = ws["heartbeat_interval_sec"];
        }
        if (ws.contains("event_queue_max")) {
            config.ws_event_queue_max = ws["event_queue_max"];
        }
    }

    // Database settings
    if (j.contains("database")) {
        const auto& db = j["database"];
        if (db.contains("enabled")) {
            config.database.enabled = db["enabled"];
        }
        if (db.contains("path")) {
            config.database.path = db["path"];
        }
        if (db.contains("retention_days")) {
            config.database.retention_days = db["retention_days"];
        }
    }
}

nlohmann::json ConfigLoader::configToJson(const Config& config) {
    nlohmann::json j;

    // Server settings
    j["server"] = {{"bind_address", config.api_bind_address},
                   {"port", config.api_port},
                   {"workers", config.api_worker_threads},
                   {"max_upload_size_mb", config.max_upload_size_mb}};

    // Processing settings
    j["processing"] = {{"worker_threads", config.worker_threads},
                       {"packet_queue_size", config.max_packet_queue_size},
                       {"flow_timeout_sec", config.flow_timeout_sec}};

    // Storage settings
    j["storage"] = {{"upload_dir", config.upload_dir},
                    {"output_dir", config.results_dir},
                    {"retention_hours", config.retention_hours}};

    // nDPI settings
    j["ndpi"] = {{"enable", config.enable_ndpi}, {"protocols", config.ndpi_protocols}};

    // WebSocket settings
    j["websocket"] = {{"heartbeat_interval_sec", config.ws_heartbeat_interval_sec},
                      {"event_queue_max", config.ws_event_queue_max}};

    // Database settings
    j["database"] = {{"enabled", config.database.enabled},
                     {"path", config.database.path},
                     {"retention_days", config.database.retention_days}};

    return j;
}

}  // namespace callflow
