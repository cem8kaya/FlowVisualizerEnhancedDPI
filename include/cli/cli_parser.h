#pragma once

#include "common/types.h"
#include <string>
#include <vector>

namespace callflow {

/**
 * Command line arguments
 */
struct CliArgs {
    std::string input_file;
    std::string output_file;
    std::string output_dir = "./output";
    int worker_threads = 4;
    bool verbose = false;
    bool export_pcap_subsets = false;
    LogLevel log_level = LogLevel::INFO;

    // API server options
    bool enable_api_server = false;
    uint16_t api_port = 8080;
    std::string api_bind_address = "0.0.0.0";
    std::string config_file;  // Configuration file path
};

/**
 * CLI argument parser
 */
class CliParser {
public:
    CliParser() = default;
    ~CliParser() = default;

    /**
     * Parse command line arguments
     */
    bool parse(int argc, char** argv, CliArgs& args);

    /**
     * Print usage information
     */
    void printUsage(const char* program_name);

    /**
     * Print version information
     */
    void printVersion();

private:
    bool validateArgs(const CliArgs& args);
};

}  // namespace callflow
