#include "cli/cli_parser.h"
#include "common/config_loader.h"
#include "common/logger.h"
#include "common/types.h"
#include "common/utils.h"
#include "event_extractor/json_exporter.h"
#include "pcap_ingest/packet_processor.h"
#include "pcap_ingest/pcap_reader.h"
#include "pcap_ingest/pcapng_reader.h"
#include "persistence/database.h"  // Moved out of ifdef as it's used in main now
#include "session/session_correlator.h"

#ifdef BUILD_API_SERVER
#include "api_server/http_server.h"
#include "api_server/job_manager.h"
#include "api_server/websocket_handler.h"
#include "config/config_manager.h"
#endif

#include <atomic>
#include <csignal>
#include <fstream>  // Added for std::ifstream
#include <iostream>
#include <map>
#include <thread>
#include <vector>

using namespace callflow;

std::atomic<bool> running(true);

void signalHandler(int signum) {
    LOG_INFO("Interrupt signal (" << signum << ") received.");
    running = false;
}

void processPcap(const std::string& input_file, const std::string& output_file, bool is_pcapng,
                 Config& config) {
    LOG_INFO("Processing " << (is_pcapng ? "PCAPNG" : "PCAP") << " file: " << input_file);

    EnhancedSessionCorrelator correlator;  // New correlator
    PacketProcessor processor(correlator);

    size_t packet_count = 0;
    size_t total_bytes = 0;

    // Setup file reader
    // We reuse logic from JobManager partly, but simpler.

    auto process_start = utils::now();

    if (is_pcapng) {
        PcapngReader reader;
        if (!reader.open(input_file)) {
            LOG_ERROR("Failed to open PCAPNG file: " << input_file);
            return;
        }

        auto callback = [&](uint32_t interface_id, uint64_t timestamp_ns, const uint8_t* data,
                            uint32_t cap_len, uint32_t orig_len, const PcapngPacketMetadata& meta) {
            if (!running)
                return;

            auto ts = std::chrono::system_clock::time_point(
                std::chrono::duration_cast<std::chrono::system_clock::duration>(
                    std::chrono::nanoseconds(timestamp_ns)));

            const PcapngInterface* iface = reader.getInterface(interface_id);
            int dlt = iface ? iface->link_type : 1;

            processor.processPacket(data, cap_len, ts, packet_count, dlt);

            packet_count++;
            total_bytes += cap_len;

            if (packet_count % 10000 == 0) {
                std::cout << "\rProcessed " << packet_count << " packets..." << std::flush;
            }
        };

        reader.processPackets(callback);

    } else {
        PcapReader reader;
        if (!reader.open(input_file)) {
            LOG_ERROR("Failed to open PCAP file: " << input_file);
            return;
        }

        int dlt = reader.getDatalinkType();

        auto callback = [&](const uint8_t* data, const struct pcap_pkthdr* header, void* user) {
            if (!running)
                return;

            auto ts = std::chrono::system_clock::from_time_t(header->ts.tv_sec) +
                      std::chrono::microseconds(header->ts.tv_usec);

            processor.processPacket(data, header->caplen, ts, packet_count, dlt);

            packet_count++;
            total_bytes += header->caplen;

            if (packet_count % 10000 == 0) {
                std::cout << "\rProcessed " << packet_count << " packets..." << std::flush;
            }
        };

        reader.processPackets(callback);
        reader.close();
    }

    auto process_end = utils::now();
    auto duration_ms = utils::timeDiffMs(process_start, process_end);

    std::cout << "\nFinalizing sessions..." << std::endl;
    correlator.finalizeSessions();

    auto sessions = correlator.getAllSessions();
    LOG_INFO("Total sessions: " << sessions.size());

    JsonExporter exporter;
    // Export results
    if (exporter.exportToFile(output_file, sessions, true)) {
        LOG_INFO("Results exported to " << output_file);
    } else {
        LOG_ERROR("Failed to export results");
    }

    // Print summary
    std::cout << "\n=== Processing Summary ===\n";
    std::cout << "Total packets: " << packet_count << "\n";
    std::cout << "Total sessions: " << sessions.size() << "\n";
    std::cout << "Processing time: " << duration_ms << "ms\n";
    std::cout << "Throughput: " << (packet_count * 1000.0 / duration_ms) << " pps\n";
    std::cout << "Output file: " << output_file << "\n";

    // Session breakdown
    std::map<EnhancedSessionType, size_t> session_types;
    for (const auto& session : sessions) {
        session_types[session->session_type]++;
    }

    std::cout << "\nSession breakdown:\n";
    for (const auto& [type, count] : session_types) {
        std::cout << "  " << enhancedSessionTypeToString(type) << ": " << count << "\n";
    }
}

/**
 * Run API server mode
 */
int runApiServer(const CliArgs& args) {
#ifdef BUILD_API_SERVER
    // Load configuration
    Config config;
    config.worker_threads = args.worker_threads;

    if (!args.config_file.empty()) {
        ConfigLoader loader;
        if (!loader.loadFromFile(args.config_file, config)) {
            LOG_ERROR("Failed to load config file: " << args.config_file);
            return 1;
        }
        LOG_INFO("Loaded configuration from: " << args.config_file);
    }

    // Apply environment overrides
    ConfigLoader loader;
    loader.applyEnvOverrides(config);

    config.enable_api_server = true;

    LOG_INFO("Starting API server mode...");
    LOG_INFO("Bind address: " << config.api_bind_address);
    LOG_INFO("Port: " << config.api_port);
    LOG_INFO("Worker threads: " << config.api_worker_threads);
    LOG_INFO("Upload directory: " << config.upload_dir);
    LOG_INFO("Results directory: " << config.results_dir);

    // Load protocol configuration
    auto& config_mgr = ConfigManager::getInstance();
    std::string protocols_config = "config/protocols.yaml";
    if (config_mgr.loadFromFile(protocols_config)) {
        LOG_INFO("Loaded protocol configuration from: " << protocols_config);
        auto enabled_protocols = config_mgr.getEnabledProtocols();
        LOG_INFO("Enabled protocols (" << enabled_protocols.size() << "): ");
        for (const auto& proto : enabled_protocols) {
            LOG_INFO("  - " << proto);
        }
    } else {
        LOG_WARN("Failed to load protocol configuration, using defaults");
    }

    // Initialize database
    auto db_manager = std::make_shared<DatabaseManager>(config.database);
    if (!db_manager->initialize()) {
        LOG_WARN("Failed to initialize database, persistence will be disabled");
        db_manager.reset();
    }

    // Create components
    auto job_manager = std::make_shared<JobManager>(config, db_manager);
    auto ws_handler = std::make_shared<WebSocketHandler>(config);
    auto http_server = std::make_shared<HttpServer>(config, job_manager, ws_handler);

    // Set callbacks
    job_manager->setProgressCallback([ws_handler](const JobId& job_id, int progress,
                                                  const std::string& msg) {
        ws_handler->broadcastEvent(job_id, "progress", {{"progress", progress}, {"message", msg}});
    });

    job_manager->setEventCallback([ws_handler](const JobId& job_id, const std::string& event_type,
                                               const nlohmann::json& data) {
        ws_handler->broadcastEvent(job_id, event_type, data);
    });

    // Start services
    if (!job_manager->start()) {
        LOG_ERROR("Failed to start job manager");
        return 1;
    }

    if (!ws_handler->start()) {
        LOG_ERROR("Failed to start WebSocket handler");
        job_manager->stop();
        return 1;
    }

    if (!http_server->start()) {
        LOG_ERROR("Failed to start HTTP server");
        ws_handler->stop();
        job_manager->stop();
        return 1;
    }

    LOG_INFO("API server started successfully");
    LOG_INFO("API endpoint: http://" << config.api_bind_address << ":" << config.api_port);
    LOG_INFO("Health check: http://" << config.api_bind_address << ":" << config.api_port
                                     << "/health");
    LOG_INFO("Press Ctrl+C to stop");

    // Placeholder - waiting for viewrmination signal
    std::signal(SIGINT, [](int) {
        LOG_INFO("Received SIGINT, shutting down...");
        exit(0);
    });

    std::signal(SIGTERM, [](int) {
        LOG_INFO("Received SIGTERM, shutting down...");
        exit(0);
    });

    // Keep running
    while (http_server->isRunning()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    // Cleanup
    http_server->stop();
    ws_handler->stop();
    job_manager->stop();
    if (db_manager) {
        db_manager->close();
    }

    LOG_INFO("API server stopped");
    return 0;
#else
    LOG_ERROR("API server support not compiled. Build with -DBUILD_API_SERVER=ON");
    return 1;
#endif
}

int main(int argc, char** argv) {
    CliParser parser;
    CliArgs args;

    if (!parser.parse(argc, argv, args)) {
        return 1;
    }

    // Configure logging
    Logger::getInstance().setLevel(args.log_level);

    try {
        // Check if running in API server mode
        if (args.enable_api_server) {
            return runApiServer(args);
        } else {
            // Traditional CLI mode
            std::string input_file = args.input_file;
            std::string output_file = args.output_file;
            if (output_file.empty()) {
                output_file = "output.json";
            }
            // Load config similarly to API mode so we have settings
            Config config;
            if (!args.config_file.empty()) {
                ConfigLoader loader;
                if (!loader.loadFromFile(args.config_file, config)) {
                    LOG_ERROR("Failed to load config file: " << args.config_file);
                    return 1;
                }
            } else {
                // Default config
                ConfigLoader loader;
                // Check if config.json exists using standard I/O to avoid filesystem dependency
                // issues
                std::ifstream f("config.json");
                if (f.good()) {
                    loader.loadFromFile("config.json", config);
                }
            }

            bool is_pcapng = PcapngReader::validate(input_file);
            processPcap(input_file, output_file, is_pcapng, config);
            return 0;
        }
    } catch (const std::exception& e) {
        LOG_FATAL("Fatal error: " << e.what());
        return 1;
    }
}
