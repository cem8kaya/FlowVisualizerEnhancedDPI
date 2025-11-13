#include "common/logger.h"
#include "common/types.h"
#include "common/utils.h"
#include "common/config_loader.h"
#include "cli/cli_parser.h"
#include "pcap_ingest/pcap_reader.h"
#include "pcap_ingest/packet_queue.h"
#include "protocol_parsers/sip_parser.h"
#include "protocol_parsers/rtp_parser.h"
#include "flow_manager/flow_tracker.h"
#include "flow_manager/session_correlator.h"
#include "event_extractor/json_exporter.h"

#ifdef BUILD_API_SERVER
#include "api_server/http_server.h"
#include "api_server/job_manager.h"
#include "api_server/websocket_handler.h"
#endif

#include <iostream>
#include <thread>
#include <vector>
#include <atomic>
#include <csignal>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

using namespace callflow;

/**
 * Packet processor worker
 */
class PacketProcessor {
public:
    PacketProcessor(Config& config, SessionCorrelator& correlator)
        : config_(config), correlator_(correlator) {}

    void processPacket(const PacketMetadata& packet) {
        // Try to parse as SIP
        if (packet.five_tuple.protocol == 17) {  // UDP
            // Check if likely SIP (port 5060)
            if (packet.five_tuple.src_port == 5060 || packet.five_tuple.dst_port == 5060) {
                SipParser sip_parser;
                auto sip_msg = sip_parser.parse(packet.raw_data.data(), packet.raw_data.size());

                if (sip_msg.has_value()) {
                    LOG_DEBUG("Parsed SIP message: " << sip_msg->call_id);
                    correlator_.processPacket(packet, ProtocolType::SIP, sip_msg->toJson());
                    return;
                }
            }

            // Check if likely RTP (even ports 10000-65535)
            if ((packet.five_tuple.src_port >= 10000 && packet.five_tuple.src_port % 2 == 0) ||
                (packet.five_tuple.dst_port >= 10000 && packet.five_tuple.dst_port % 2 == 0)) {
                RtpParser rtp_parser;
                auto rtp_header = rtp_parser.parseRtp(packet.raw_data.data(),
                                                      packet.raw_data.size());

                if (rtp_header.has_value()) {
                    LOG_TRACE("Parsed RTP packet: SSRC=" << rtp_header->ssrc
                              << " seq=" << rtp_header->sequence_number);
                    correlator_.processPacket(packet, ProtocolType::RTP, rtp_header->toJson());
                    return;
                }
            }
        }

        // If not identified, still track as generic flow
        LOG_TRACE("Unidentified packet: " << packet.five_tuple.toString());
    }

private:
    Config& config_;
    SessionCorrelator& correlator_;
};

/**
 * Parse Ethernet/IP/UDP packet
 */
bool parsePacket(const uint8_t* data, size_t len, PacketMetadata& packet) {
    if (len < 42) {  // Min: Ethernet(14) + IP(20) + UDP(8)
        return false;
    }

    // Skip Ethernet header (14 bytes)
    const uint8_t* ip_header = data + 14;
    size_t ip_len = len - 14;

    // Parse IP header
    if (ip_len < 20) {
        return false;
    }

    uint8_t version = (ip_header[0] >> 4) & 0x0F;
    if (version != 4) {
        return false;  // Only IPv4 for M1
    }

    uint8_t ihl = (ip_header[0] & 0x0F) * 4;
    uint8_t protocol = ip_header[9];
    uint32_t src_ip = ntohl(*reinterpret_cast<const uint32_t*>(&ip_header[12]));
    uint32_t dst_ip = ntohl(*reinterpret_cast<const uint32_t*>(&ip_header[16]));

    packet.five_tuple.src_ip = utils::ipToString(src_ip);
    packet.five_tuple.dst_ip = utils::ipToString(dst_ip);
    packet.five_tuple.protocol = protocol;

    // Parse transport layer (UDP/TCP)
    const uint8_t* transport_header = ip_header + ihl;
    size_t transport_len = ip_len - ihl;

    if (protocol == 17 && transport_len >= 8) {  // UDP
        packet.five_tuple.src_port = ntohs(*reinterpret_cast<const uint16_t*>(&transport_header[0]));
        packet.five_tuple.dst_port = ntohs(*reinterpret_cast<const uint16_t*>(&transport_header[2]));

        // Copy payload
        const uint8_t* payload = transport_header + 8;
        size_t payload_len = transport_len - 8;

        if (payload_len > 0) {
            packet.raw_data.assign(payload, payload + payload_len);
        }

        return true;
    } else if (protocol == 6 && transport_len >= 20) {  // TCP
        packet.five_tuple.src_port = ntohs(*reinterpret_cast<const uint16_t*>(&transport_header[0]));
        packet.five_tuple.dst_port = ntohs(*reinterpret_cast<const uint16_t*>(&transport_header[2]));

        uint8_t data_offset = (transport_header[12] >> 4) * 4;
        const uint8_t* payload = transport_header + data_offset;
        size_t payload_len = transport_len - data_offset;

        if (payload_len > 0) {
            packet.raw_data.assign(payload, payload + payload_len);
        }

        return true;
    }

    return false;
}

/**
 * Main processing function
 */
int processPcap(const CliArgs& args) {
    // Configure logging
    Logger::getInstance().setLevel(args.log_level);

    LOG_INFO("Starting Callflow Visualizer (Milestone 1)");
    LOG_INFO("Input PCAP: " << args.input_file);
    LOG_INFO("Worker threads: " << args.worker_threads);

    // Create configuration
    Config config;
    config.worker_threads = args.worker_threads;
    config.output_dir = args.output_dir;
    config.export_pcap_subsets = args.export_pcap_subsets;

    // Create components
    PcapReader pcap_reader;
    SessionCorrelator correlator(config);
    PacketProcessor processor(config, correlator);

    // Open PCAP file
    if (!pcap_reader.open(args.input_file)) {
        LOG_ERROR("Failed to open PCAP file");
        return 1;
    }

    LOG_INFO("Processing packets...");

    // Process packets
    size_t packet_count = 0;
    auto process_start = utils::now();

    auto callback = [&](const uint8_t* data, const struct pcap_pkthdr* header, void* user) {
        PacketMetadata packet;
        packet.packet_id = utils::generateUuid();
        packet.timestamp = std::chrono::system_clock::from_time_t(header->ts.tv_sec) +
                          std::chrono::microseconds(header->ts.tv_usec);
        packet.frame_number = packet_count;
        packet.packet_length = header->caplen;

        // Parse packet
        if (parsePacket(data, header->caplen, packet)) {
            processor.processPacket(packet);
        }

        packet_count++;

        if (packet_count % 10000 == 0) {
            LOG_INFO("Processed " << packet_count << " packets, "
                     << correlator.getSessionCount() << " sessions...");
        }
    };

    pcap_reader.processPackets(callback);
    pcap_reader.close();

    auto process_end = utils::now();
    auto duration_ms = utils::timeDiffMs(process_start, process_end);

    LOG_INFO("Processed " << packet_count << " packets in "
             << duration_ms << "ms (" << (packet_count * 1000.0 / duration_ms) << " pps)");

    // Finalize sessions
    LOG_INFO("Finalizing sessions...");
    correlator.finalizeSessions();

    // Export results
    LOG_INFO("Exporting results...");

    auto sessions = correlator.getAllSessions();
    LOG_INFO("Found " << sessions.size() << " sessions");

    // Generate output filename
    std::string output_file = args.output_file;
    if (output_file.empty()) {
        std::string job_id = utils::generateUuid();
        output_file = args.output_dir + "/job-" + job_id + ".json";
    }

    JsonExporter exporter;
    if (exporter.exportToFile(output_file, sessions, true)) {
        LOG_INFO("Results exported to: " << output_file);
    } else {
        LOG_ERROR("Failed to export results");
        return 1;
    }

    // Print summary
    std::cout << "\n=== Processing Summary ===\n";
    std::cout << "Total packets: " << packet_count << "\n";
    std::cout << "Total sessions: " << sessions.size() << "\n";
    std::cout << "Processing time: " << duration_ms << "ms\n";
    std::cout << "Throughput: " << (packet_count * 1000.0 / duration_ms) << " pps\n";
    std::cout << "Output file: " << output_file << "\n";

    // Session breakdown
    std::map<SessionType, size_t> session_types;
    for (const auto& session : sessions) {
        session_types[session->type]++;
    }

    std::cout << "\nSession breakdown:\n";
    for (const auto& [type, count] : session_types) {
        std::cout << "  " << sessionTypeToString(type) << ": " << count << "\n";
    }

    return 0;
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

    // Create components
    auto job_manager = std::make_shared<JobManager>(config);
    auto ws_handler = std::make_shared<WebSocketHandler>(config);
    auto http_server = std::make_shared<HttpServer>(config, job_manager, ws_handler);

    // Set callbacks
    job_manager->setProgressCallback([ws_handler](const JobId& job_id, int progress, const std::string& msg) {
        ws_handler->broadcastEvent(job_id, "progress", {
            {"progress", progress},
            {"message", msg}
        });
    });

    job_manager->setEventCallback([ws_handler](const JobId& job_id, const std::string& event_type, const nlohmann::json& data) {
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
    LOG_INFO("Health check: http://" << config.api_bind_address << ":" << config.api_port << "/health");
    LOG_INFO("Press Ctrl+C to stop");

    // Wait for termination signal
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
            return processPcap(args);
        }
    } catch (const std::exception& e) {
        LOG_FATAL("Fatal error: " << e.what());
        return 1;
    }
}
