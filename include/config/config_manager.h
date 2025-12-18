#pragma once

#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <string>
#include <unordered_map>
#include <vector>

namespace callflow {

/**
 * Protocol Configuration
 * Represents configuration for a specific protocol
 */
struct ProtocolConfig {
    std::string protocol_name;
    bool enabled = true;
    std::vector<int> ports;
    nlohmann::json raw_config;  // Full YAML config as JSON

    // Common fields (can be extended per protocol)
    bool decode_user_plane = false;
    bool decode_ies = true;
    bool decode_nas = true;
    bool asn1_validation = true;
    bool track_sessions = true;
    int max_sessions = 100000;
    int max_tunnels = 100000;
    std::vector<int> sctp_ports;
    std::vector<int> udp_ports;
};

/**
 * SCTP Configuration
 */
struct SctpConfig {
    bool reassemble_streams = true;
    int max_associations = 10000;
    int association_timeout_sec = 300;
    bool validate_chunks = true;
};

/**
 * PCAPNG Configuration
 */
struct PcapngConfig {
    bool extract_comments = true;
    bool extract_interface_stats = true;
    int max_interfaces = 256;
    bool process_custom_blocks = false;
};

/**
 * Session Correlation Configuration
 */
struct CorrelationConfig {
    bool enabled = true;
    int timeout_sec = 60;
    std::vector<std::string> strategies;
    int max_correlated_sessions = 100000;
};

/**
 * Performance Configuration
 */
struct PerformanceConfig {
    int worker_threads = 4;
    int packet_batch_size = 1000;
    bool parallel_processing = true;
    int packet_buffer_pool_mb = 512;
};

/**
 * Logging Configuration
 */
struct LoggingConfig {
    std::string protocol_parse_level = "INFO";
    bool log_correlation = false;
    bool log_sessions = true;
};

/**
 * Protocol Configuration Manager
 *
 * Manages protocol-specific configurations loaded from YAML files.
 * Provides thread-safe access to protocol settings and supports
 * hot reload via SIGHUP signal.
 *
 * Example usage:
 *   auto& config_mgr = ConfigManager::getInstance();
 *   config_mgr.loadFromFile("config/protocols.yaml");
 *
 *   if (config_mgr.isProtocolEnabled("gtpv2")) {
 *       auto gtpv2_config = config_mgr.getProtocolConfig("gtpv2");
 *       // Use configuration...
 *   }
 */
class ConfigManager {
public:
    /**
     * Get singleton instance
     */
    static ConfigManager& getInstance();

    /**
     * Load protocol configuration from YAML file
     *
     * @param filepath Path to protocols.yaml file
     * @return true on success, false on failure
     */
    bool loadFromFile(const std::string& filepath);

    /**
     * Reload configuration from the same file
     * Used for hot reload (SIGHUP handler)
     *
     * @return true on success, false on failure
     */
    bool reload();

    /**
     * Get protocol configuration by name
     *
     * @param protocol_name Protocol name (e.g., "gtpv1", "s1ap", "ngap")
     * @return Protocol configuration
     * @throws std::runtime_error if protocol not found
     */
    ProtocolConfig getProtocolConfig(const std::string& protocol_name) const;

    /**
     * Check if a protocol is enabled
     *
     * @param protocol_name Protocol name
     * @return true if enabled, false otherwise
     */
    bool isProtocolEnabled(const std::string& protocol_name) const;

    /**
     * Get list of all supported protocols
     *
     * @return Vector of protocol names
     */
    std::vector<std::string> getSupportedProtocols() const;

    /**
     * Get list of all enabled protocols
     *
     * @return Vector of enabled protocol names
     */
    std::vector<std::string> getEnabledProtocols() const;

    /**
     * Get SCTP configuration
     */
    SctpConfig getSctpConfig() const;

    /**
     * Get PCAPNG configuration
     */
    PcapngConfig getPcapngConfig() const;

    /**
     * Get correlation configuration
     */
    CorrelationConfig getCorrelationConfig() const;

    /**
     * Get performance configuration
     */
    PerformanceConfig getPerformanceConfig() const;

    /**
     * Get logging configuration
     */
    LoggingConfig getLoggingConfig() const;

    /**
     * Export all configurations as JSON
     * Used for REST API /api/v1/protocols/supported
     *
     * @return JSON representation of all protocol configs
     */
    nlohmann::json exportToJson() const;

    /**
     * Get protocol version information
     *
     * @param protocol_name Protocol name
     * @return 3GPP specification version (e.g., "29.060" for GTPv1)
     */
    std::string getProtocolVersion(const std::string& protocol_name) const;

private:
    ConfigManager() = default;
    ~ConfigManager() = default;

    // Delete copy/move constructors and assignment operators
    ConfigManager(const ConfigManager&) = delete;
    ConfigManager& operator=(const ConfigManager&) = delete;
    ConfigManager(ConfigManager&&) = delete;
    ConfigManager& operator=(ConfigManager&&) = delete;

    /**
     * Parse YAML configuration
     *
     * @param yaml_content YAML content as string
     * @return true on success, false on failure
     */
    bool parseYaml(const std::string& yaml_content);

    /**
     * Parse protocol-specific configuration
     */
    ProtocolConfig parseProtocolConfig(const std::string& protocol_name,
                                       const nlohmann::json& protocol_json) const;

    /**
     * Protocol version mapping (protocol name -> 3GPP spec version)
     */
    std::unordered_map<std::string, std::string> getProtocolVersionMap() const;

    // Configuration storage
    std::unordered_map<std::string, ProtocolConfig> protocols_;
    SctpConfig sctp_config_;
    PcapngConfig pcapng_config_;
    CorrelationConfig correlation_config_;
    PerformanceConfig performance_config_;
    LoggingConfig logging_config_;

    // Configuration file path (for reload)
    std::string config_filepath_;

    // Thread safety
    mutable std::mutex mutex_;
};

}  // namespace callflow
