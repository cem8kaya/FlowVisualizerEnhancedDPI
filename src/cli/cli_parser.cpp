#include "cli/cli_parser.h"
#include "common/logger.h"
#include <iostream>
#include <cstring>

namespace callflow {

bool CliParser::parse(int argc, char** argv, CliArgs& args) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            printUsage(argv[0]);
            return false;
        } else if (arg == "-v" || arg == "--version") {
            printVersion();
            return false;
        } else if (arg == "--input" || arg == "-i") {
            if (i + 1 < argc) {
                args.input_file = argv[++i];
            } else {
                std::cerr << "Error: --input requires an argument" << std::endl;
                return false;
            }
        } else if (arg == "--output" || arg == "-o") {
            if (i + 1 < argc) {
                args.output_file = argv[++i];
            } else {
                std::cerr << "Error: --output requires an argument" << std::endl;
                return false;
            }
        } else if (arg == "--output-dir") {
            if (i + 1 < argc) {
                args.output_dir = argv[++i];
            } else {
                std::cerr << "Error: --output-dir requires an argument" << std::endl;
                return false;
            }
        } else if (arg == "--workers" || arg == "-w") {
            if (i + 1 < argc) {
                args.worker_threads = std::atoi(argv[++i]);
            } else {
                std::cerr << "Error: --workers requires an argument" << std::endl;
                return false;
            }
        } else if (arg == "--verbose") {
            args.verbose = true;
            args.log_level = LogLevel::DEBUG;
        } else if (arg == "--debug") {
            args.log_level = LogLevel::DEBUG;
        } else if (arg == "--trace") {
            args.log_level = LogLevel::TRACE;
        } else if (arg == "--export-pcap") {
            args.export_pcap_subsets = true;
        } else if (arg == "--api-server") {
            args.enable_api_server = true;
        } else if (arg == "--api-port") {
            if (i + 1 < argc) {
                args.api_port = std::atoi(argv[++i]);
            } else {
                std::cerr << "Error: --api-port requires an argument" << std::endl;
                return false;
            }
        } else if (arg == "--api-bind") {
            if (i + 1 < argc) {
                args.api_bind_address = argv[++i];
            } else {
                std::cerr << "Error: --api-bind requires an argument" << std::endl;
                return false;
            }
        } else {
            std::cerr << "Error: Unknown argument: " << arg << std::endl;
            return false;
        }
    }

    return validateArgs(args);
}

void CliParser::printUsage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [OPTIONS]\n"
              << "\n"
              << "Callflow Visualizer - Telecom Protocol Analysis Tool\n"
              << "\n"
              << "Options:\n"
              << "  -i, --input FILE        Input PCAP file (required)\n"
              << "  -o, --output FILE       Output JSON file (optional, default: auto-generated)\n"
              << "  --output-dir DIR        Output directory (default: ./output)\n"
              << "  -w, --workers N         Number of worker threads (default: 4)\n"
              << "  --verbose               Enable verbose output\n"
              << "  --debug                 Enable debug logging\n"
              << "  --trace                 Enable trace logging\n"
              << "  --export-pcap           Export PCAP subsets per session\n"
              << "\n"
              << "API Server Options:\n"
              << "  --api-server            Enable REST API server\n"
              << "  --api-port PORT         API server port (default: 8080)\n"
              << "  --api-bind ADDR         API bind address (default: 0.0.0.0)\n"
              << "\n"
              << "Examples:\n"
              << "  " << program_name << " --input capture.pcap\n"
              << "  " << program_name << " -i capture.pcap -o results.json --workers 8\n"
              << "  " << program_name << " -i capture.pcap --api-server --api-port 8080\n"
              << "\n"
              << "For more information, visit: https://github.com/yourusername/callflow-visualizer\n";
}

void CliParser::printVersion() {
    std::cout << "Callflow Visualizer v0.1.0 (Milestone 1)\n"
              << "Build: " << __DATE__ << " " << __TIME__ << "\n"
              << "C++ Standard: C++" << __cplusplus / 100 % 100 << "\n";
}

bool CliParser::validateArgs(const CliArgs& args) {
    if (args.input_file.empty() && !args.enable_api_server) {
        std::cerr << "Error: --input is required when not running API server\n";
        return false;
    }

    if (args.worker_threads < 1 || args.worker_threads > 64) {
        std::cerr << "Error: --workers must be between 1 and 64\n";
        return false;
    }

    return true;
}

}  // namespace callflow
