#include "config/config_manager.h"

#include <fstream>
#include <sstream>
#include <stdexcept>

#include "common/logger.h"
#include <yaml-cpp/yaml.h>

namespace callflow {

// Helper function to convert YAML::Node to nlohmann::json
static nlohmann::json yamlToJson(const YAML::Node& node) {
    nlohmann::json result;

    switch (node.Type()) {
        case YAML::NodeType::Null:
            result = nullptr;
            break;
        case YAML::NodeType::Scalar:
            // Try to parse as different types
            try {
                result = node.as<bool>();
            } catch (...) {
                try {
                    result = node.as<int>();
                } catch (...) {
                    try {
                        result = node.as<double>();
                    } catch (...) {
                        result = node.as<std::string>();
                    }
                }
            }
            break;
        case YAML::NodeType::Sequence:
            result = nlohmann::json::array();
            for (const auto& item : node) {
                result.push_back(yamlToJson(item));
            }
            break;
        case YAML::NodeType::Map:
            result = nlohmann::json::object();
            for (const auto& pair : node) {
                result[pair.first.as<std::string>()] = yamlToJson(pair.second);
            }
            break;
        default:
            result = nullptr;
            break;
    }

    return result;
}

ConfigManager& ConfigManager::getInstance() {
    static ConfigManager instance;
    return instance;
}

bool ConfigManager::loadFromFile(const std::string& filepath) {
    std::lock_guard<std::mutex> lock(mutex_);

    try {
        LOG_INFO("Loading protocol configuration from: " << filepath);

        // Read file content
        std::ifstream file(filepath);
        if (!file.is_open()) {
            LOG_ERROR("Failed to open configuration file: " << filepath);
            return false;
        }

        std::stringstream buffer;
        buffer << file.rdbuf();
        std::string yaml_content = buffer.str();

        // Parse YAML
        YAML::Node config = YAML::Load(yaml_content);

        // Clear existing configurations
        protocols_.clear();

        // Parse protocol configurations
        std::vector<std::string> protocol_names = {
            "gtpv1", "gtpv2", "s1ap", "x2ap", "ngap", "pfcp", "diameter", "nas"
        };

        for (const auto& proto_name : protocol_names) {
            if (config[proto_name]) {
                nlohmann::json proto_json = yamlToJson(config[proto_name]);
                protocols_[proto_name] = parseProtocolConfig(proto_name, proto_json);
                LOG_INFO("Loaded configuration for protocol: " << proto_name);
            }
        }

        // Parse SCTP configuration
        if (config["sctp"]) {
            auto sctp_node = config["sctp"];
            sctp_config_.reassemble_streams = sctp_node["reassemble_streams"].as<bool>(true);
            sctp_config_.max_associations = sctp_node["max_associations"].as<int>(10000);
            sctp_config_.association_timeout_sec = sctp_node["association_timeout_sec"].as<int>(300);
            sctp_config_.validate_chunks = sctp_node["validate_chunks"].as<bool>(true);
            LOG_INFO("Loaded SCTP configuration");
        }

        // Parse PCAPNG configuration
        if (config["pcapng"]) {
            auto pcapng_node = config["pcapng"];
            pcapng_config_.extract_comments = pcapng_node["extract_comments"].as<bool>(true);
            pcapng_config_.extract_interface_stats = pcapng_node["extract_interface_stats"].as<bool>(true);
            pcapng_config_.max_interfaces = pcapng_node["max_interfaces"].as<int>(256);
            pcapng_config_.process_custom_blocks = pcapng_node["process_custom_blocks"].as<bool>(false);
            LOG_INFO("Loaded PCAPNG configuration");
        }

        // Parse Correlation configuration
        if (config["correlation"]) {
            auto corr_node = config["correlation"];
            correlation_config_.enabled = corr_node["enabled"].as<bool>(true);
            correlation_config_.timeout_sec = corr_node["timeout_sec"].as<int>(60);
            correlation_config_.max_correlated_sessions = corr_node["max_correlated_sessions"].as<int>(100000);

            if (corr_node["strategies"]) {
                correlation_config_.strategies.clear();
                for (const auto& strategy : corr_node["strategies"]) {
                    correlation_config_.strategies.push_back(strategy.as<std::string>());
                }
            }
            LOG_INFO("Loaded correlation configuration");
        }

        // Parse Performance configuration
        if (config["performance"]) {
            auto perf_node = config["performance"];
            performance_config_.worker_threads = perf_node["worker_threads"].as<int>(4);
            performance_config_.packet_batch_size = perf_node["packet_batch_size"].as<int>(1000);
            performance_config_.parallel_processing = perf_node["parallel_processing"].as<bool>(true);
            performance_config_.packet_buffer_pool_mb = perf_node["packet_buffer_pool_mb"].as<int>(512);
            LOG_INFO("Loaded performance configuration");
        }

        // Parse Logging configuration
        if (config["logging"]) {
            auto log_node = config["logging"];
            logging_config_.protocol_parse_level = log_node["protocol_parse_level"].as<std::string>("INFO");
            logging_config_.log_correlation = log_node["log_correlation"].as<bool>(false);
            logging_config_.log_sessions = log_node["log_sessions"].as<bool>(true);
            LOG_INFO("Loaded logging configuration");
        }

        // Store filepath for reload
        config_filepath_ = filepath;

        LOG_INFO("Successfully loaded configuration from: " << filepath);
        return true;

    } catch (const YAML::Exception& e) {
        LOG_ERROR("YAML parsing error: " << e.what());
        return false;
    } catch (const std::exception& e) {
        LOG_ERROR("Error loading configuration: " << e.what());
        return false;
    }
}

bool ConfigManager::reload() {
    if (config_filepath_.empty()) {
        LOG_ERROR("Cannot reload: no configuration file loaded");
        return false;
    }

    LOG_INFO("Reloading configuration from: " << config_filepath_);
    return loadFromFile(config_filepath_);
}

ProtocolConfig ConfigManager::getProtocolConfig(const std::string& protocol_name) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = protocols_.find(protocol_name);
    if (it == protocols_.end()) {
        throw std::runtime_error("Protocol not found: " + protocol_name);
    }

    return it->second;
}

bool ConfigManager::isProtocolEnabled(const std::string& protocol_name) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = protocols_.find(protocol_name);
    if (it == protocols_.end()) {
        return false;
    }

    return it->second.enabled;
}

std::vector<std::string> ConfigManager::getSupportedProtocols() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<std::string> protocols;
    for (const auto& [name, config] : protocols_) {
        protocols.push_back(name);
    }

    return protocols;
}

std::vector<std::string> ConfigManager::getEnabledProtocols() const {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<std::string> protocols;
    for (const auto& [name, config] : protocols_) {
        if (config.enabled) {
            protocols.push_back(name);
        }
    }

    return protocols;
}

SctpConfig ConfigManager::getSctpConfig() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return sctp_config_;
}

PcapngConfig ConfigManager::getPcapngConfig() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return pcapng_config_;
}

CorrelationConfig ConfigManager::getCorrelationConfig() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return correlation_config_;
}

PerformanceConfig ConfigManager::getPerformanceConfig() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return performance_config_;
}

LoggingConfig ConfigManager::getLoggingConfig() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return logging_config_;
}

nlohmann::json ConfigManager::exportToJson() const {
    std::lock_guard<std::mutex> lock(mutex_);

    nlohmann::json result;
    result["protocols"] = nlohmann::json::array();

    auto version_map = getProtocolVersionMap();

    for (const auto& [name, config] : protocols_) {
        nlohmann::json proto_info;
        proto_info["name"] = name;
        proto_info["enabled"] = config.enabled;
        proto_info["version"] = version_map.count(name) ? version_map.at(name) : "N/A";

        // Add ports if available
        if (!config.ports.empty()) {
            proto_info["ports"] = config.ports;
        }
        if (!config.sctp_ports.empty()) {
            proto_info["sctp_ports"] = config.sctp_ports;
        }
        if (!config.udp_ports.empty()) {
            proto_info["udp_ports"] = config.udp_ports;
        }

        result["protocols"].push_back(proto_info);
    }

    return result;
}

std::string ConfigManager::getProtocolVersion(const std::string& protocol_name) const {
    auto version_map = getProtocolVersionMap();
    auto it = version_map.find(protocol_name);
    return (it != version_map.end()) ? it->second : "N/A";
}

ProtocolConfig ConfigManager::parseProtocolConfig(const std::string& protocol_name,
                                                  const nlohmann::json& protocol_json) const {
    ProtocolConfig config;
    config.protocol_name = protocol_name;
    config.raw_config = protocol_json;

    // Parse common fields
    if (protocol_json.contains("enabled")) {
        config.enabled = protocol_json["enabled"].get<bool>();
    }

    if (protocol_json.contains("ports")) {
        config.ports = protocol_json["ports"].get<std::vector<int>>();
    }

    if (protocol_json.contains("sctp_ports")) {
        config.sctp_ports = protocol_json["sctp_ports"].get<std::vector<int>>();
    }

    if (protocol_json.contains("udp_ports")) {
        config.udp_ports = protocol_json["udp_ports"].get<std::vector<int>>();
    }

    if (protocol_json.contains("decode_user_plane")) {
        config.decode_user_plane = protocol_json["decode_user_plane"].get<bool>();
    }

    if (protocol_json.contains("decode_ies")) {
        config.decode_ies = protocol_json["decode_ies"].get<bool>();
    }

    if (protocol_json.contains("decode_nas")) {
        config.decode_nas = protocol_json["decode_nas"].get<bool>();
    }

    if (protocol_json.contains("asn1_validation")) {
        config.asn1_validation = protocol_json["asn1_validation"].get<bool>();
    }

    if (protocol_json.contains("track_sessions")) {
        config.track_sessions = protocol_json["track_sessions"].get<bool>();
    }

    if (protocol_json.contains("max_sessions")) {
        config.max_sessions = protocol_json["max_sessions"].get<int>();
    }

    if (protocol_json.contains("max_tunnels")) {
        config.max_tunnels = protocol_json["max_tunnels"].get<int>();
    }

    return config;
}

std::unordered_map<std::string, std::string> ConfigManager::getProtocolVersionMap() const {
    return {
        {"gtpv1", "29.060"},
        {"gtpv2", "29.274"},
        {"s1ap", "36.413"},
        {"x2ap", "36.423"},
        {"ngap", "38.413"},
        {"pfcp", "29.244"},
        {"diameter", "29.272"},
        {"nas", "24.301/24.501"}
    };
}

}  // namespace callflow
