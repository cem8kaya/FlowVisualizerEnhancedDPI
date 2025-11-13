#pragma once

#include "common/types.h"
#include <string>

namespace callflow {

/**
 * Configuration loader for JSON/YAML config files
 */
class ConfigLoader {
public:
    ConfigLoader() = default;
    ~ConfigLoader() = default;

    /**
     * Load configuration from file
     * @param config_file Path to config file (JSON format)
     * @param config Output configuration
     * @return true on success
     */
    bool loadFromFile(const std::string& config_file, Config& config);

    /**
     * Load configuration from JSON string
     * @param json_str JSON string
     * @param config Output configuration
     * @return true on success
     */
    bool loadFromJson(const std::string& json_str, Config& config);

    /**
     * Apply environment variable overrides
     * Environment variables: CALLFLOW_PORT, CALLFLOW_BIND_ADDR, etc.
     * @param config Configuration to modify
     */
    void applyEnvOverrides(Config& config);

    /**
     * Save configuration to file
     * @param config_file Path to output file
     * @param config Configuration to save
     * @return true on success
     */
    bool saveToFile(const std::string& config_file, const Config& config);

    /**
     * Get default configuration as JSON string
     * @return JSON string
     */
    static std::string getDefaultConfigJson();

private:
    /**
     * Parse config from JSON object
     */
    void parseConfig(const nlohmann::json& j, Config& config);

    /**
     * Convert config to JSON object
     */
    nlohmann::json configToJson(const Config& config);
};

}  // namespace callflow
