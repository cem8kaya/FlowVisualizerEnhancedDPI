#include "api_server/job_manager.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include <filesystem>

#include "common/utils.h"
#include "event_extractor/json_exporter.h"
#include "pcap_ingest/pcap_reader.h"
#include "persistence/database.h"
#include "protocol_parsers/diameter_parser.h"
#include "protocol_parsers/gtp_parser.h"
#include "protocol_parsers/pfcp_parser.h"
#include "protocol_parsers/rtp_parser.h"
#include "protocol_parsers/sip_parser.h"
#include "session/session_correlator.h"

namespace callflow {

JobManager::JobManager(const Config& config, std::shared_ptr<DatabaseManager> db)
    : config_(config), db_(db), running_(false) {}

JobManager::~JobManager() {
    stop();
}

bool JobManager::start() {
    if (running_.load()) {
        LOG_WARN("JobManager already running");
        return false;
    }

    LOG_INFO("Starting JobManager with " << config_.api_worker_threads << " workers");

    // Create upload and results directories
    try {
        std::filesystem::create_directories(config_.upload_dir);
        std::filesystem::create_directories(config_.results_dir);
    } catch (const std::exception& e) {
        LOG_ERROR("Failed to create directories: " << e.what());
        return false;
    }

    running_.store(true);

    // Start worker threads
    for (int i = 0; i < config_.api_worker_threads; ++i) {
        workers_.emplace_back(&JobManager::workerThread, this);
    }

    LOG_INFO("JobManager started successfully");
    return true;
}

void JobManager::stop() {
    if (!running_.load()) {
        return;
    }

    LOG_INFO("Stopping JobManager...");
    running_.store(false);

    // Wake up all workers
    queue_cv_.notify_all();

    // Wait for all workers to finish
    for (auto& worker : workers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }

    workers_.clear();
    LOG_INFO("JobManager stopped");
}

JobId JobManager::submitJob(const std::string& input_file, const std::string& output_file) {
    if (!running_.load()) {
        LOG_ERROR("JobManager not running");
        return "";
    }

    // Generate job ID
    JobId job_id = utils::generateUuid();

    // Create job info
    auto job_info = std::make_shared<JobInfo>();
    job_info->job_id = job_id;
    job_info->input_filename = input_file;
    job_info->output_filename =
        output_file.empty() ? config_.results_dir + "/job-" + job_id + ".json" : output_file;
    job_info->status = JobStatus::QUEUED;
    job_info->progress = 0;
    job_info->created_at = utils::now();

    // Store job info
    {
        std::lock_guard<std::mutex> lock(jobs_mutex_);
        jobs_[job_id] = job_info;
    }

    // Persist job to database
    if (db_) {
        db_->insertJob(*job_info);
    }

    // Queue job task
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        job_queue_.push({job_id, input_file, job_info->output_filename});
    }

    queue_cv_.notify_one();

    LOG_INFO("Job " << job_id << " submitted (input: " << input_file << ")");
    return job_id;
}

std::shared_ptr<JobInfo> JobManager::getJobInfo(const JobId& job_id) {
    std::lock_guard<std::mutex> lock(jobs_mutex_);
    auto it = jobs_.find(job_id);
    if (it != jobs_.end()) {
        return it->second;
    }
    return nullptr;
}

std::vector<std::shared_ptr<JobInfo>> JobManager::getAllJobs() {
    std::lock_guard<std::mutex> lock(jobs_mutex_);

    // If we have DB, load from DB first
    if (db_) {
        auto db_jobs = db_->getAllJobs();
        for (const auto& job : db_jobs) {
            auto job_ptr = std::make_shared<JobInfo>(job);
            // If not already in memory (or to update state), add/update it
            if (jobs_.find(job.job_id) == jobs_.end()) {
                jobs_[job.job_id] = job_ptr;
            }
        }
    }

    std::vector<std::shared_ptr<JobInfo>> result;
    for (const auto& [job_id, job_info] : jobs_) {
        result.push_back(job_info);
    }
    return result;
}

bool JobManager::deleteJob(const JobId& job_id) {
    std::lock_guard<std::mutex> lock(jobs_mutex_);
    auto it = jobs_.find(job_id);
    if (it == jobs_.end()) {
        return false;
    }

    // Don't delete running jobs
    if (it->second->status == JobStatus::RUNNING) {
        LOG_WARN("Cannot delete running job: " << job_id);
        return false;
    }

    // Delete output file
    try {
        if (std::filesystem::exists(it->second->output_filename)) {
            std::filesystem::remove(it->second->output_filename);
        }
    } catch (const std::exception& e) {
        LOG_WARN("Failed to delete output file: " << e.what());
    }

    jobs_.erase(it);

    // Delete from database
    if (db_) {
        db_->deleteJob(job_id);
    }

    LOG_INFO("Job " << job_id << " deleted");
    return true;
}

std::vector<SessionId> JobManager::getJobSessions(const JobId& job_id) {
    std::lock_guard<std::mutex> lock(jobs_mutex_);
    auto it = jobs_.find(job_id);
    if (it != jobs_.end()) {
        return it->second->session_ids;
    }
    return {};
}

void JobManager::cleanupOldJobs() {
    auto now = utils::now();
    auto retention_duration = std::chrono::hours(config_.retention_hours);

    std::lock_guard<std::mutex> lock(jobs_mutex_);
    for (auto it = jobs_.begin(); it != jobs_.end();) {
        const auto& job = it->second;

        // Only cleanup completed or failed jobs
        if (job->status != JobStatus::COMPLETED && job->status != JobStatus::FAILED) {
            ++it;
            continue;
        }

        auto age = now - job->completed_at;
        if (age > retention_duration) {
            LOG_INFO("Cleaning up old job: " << job->job_id);

            // Delete output file
            try {
                if (std::filesystem::exists(job->output_filename)) {
                    std::filesystem::remove(job->output_filename);
                }
            } catch (const std::exception& e) {
                LOG_WARN("Failed to delete output file: " << e.what());
            }

            it = jobs_.erase(it);
        } else {
            ++it;
        }
    }
}

void JobManager::workerThread() {
    LOG_DEBUG("Worker thread started");

    while (running_.load()) {
        JobTask task;

        // Wait for a job
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            queue_cv_.wait(lock, [this] { return !running_.load() || !job_queue_.empty(); });

            if (!running_.load() && job_queue_.empty()) {
                break;
            }

            if (job_queue_.empty()) {
                continue;
            }

            task = job_queue_.front();
            job_queue_.pop();
        }

        // Process the job
        try {
            processJob(task);
        } catch (const std::exception& e) {
            LOG_ERROR("Job " << task.job_id << " failed with exception: " << e.what());

            // Mark job as failed
            {
                std::lock_guard<std::mutex> lock(jobs_mutex_);
                auto it = jobs_.find(task.job_id);
                if (it != jobs_.end()) {
                    it->second->status = JobStatus::FAILED;
                    it->second->error_message = e.what();
                    it->second->completed_at = utils::now();

                    // Update database
                    if (db_) {
                        db_->updateJob(task.job_id, *it->second);
                    }
                }
            }

            sendEvent(task.job_id, "status", {{"status", "failed"}, {"error", e.what()}});
        }
    }

    LOG_DEBUG("Worker thread stopped");
}

void JobManager::processJob(const JobTask& task) {
    LOG_INFO("Processing job: " << task.job_id);

    // Update job status to running
    {
        std::lock_guard<std::mutex> lock(jobs_mutex_);
        auto it = jobs_.find(task.job_id);
        if (it != jobs_.end()) {
            it->second->status = JobStatus::RUNNING;
            it->second->started_at = utils::now();

            // Update database
            if (db_) {
                db_->updateJob(task.job_id, *it->second);
            }
        }
    }

    updateProgress(task.job_id, 0, "Starting PCAP processing");
    sendEvent(task.job_id, "status", {{"status", "running"}});

    // Create PCAP reader and session correlator
    PcapReader pcap_reader;
    SessionCorrelator correlator(config_);

    // Open PCAP file
    if (!pcap_reader.open(task.input_file)) {
        throw std::runtime_error("Failed to open PCAP file: " + task.input_file);
    }

    updateProgress(task.job_id, 10, "PCAP file opened");

    // Process packets
    size_t packet_count = 0;
    size_t total_bytes = 0;

    auto callback = [&](const uint8_t* data, const struct pcap_pkthdr* header, void* user) {
        PacketMetadata packet;
        packet.packet_id = utils::generateUuid();
        packet.timestamp = std::chrono::system_clock::from_time_t(header->ts.tv_sec) +
                           std::chrono::microseconds(header->ts.tv_usec);
        packet.frame_number = packet_count;
        packet.packet_length = header->caplen;

        // Parse packet (simplified version from main.cpp)
        // Determine Link Header Length and Type
        int link_header_len = 14;
        uint16_t eth_type = 0;

        // Check Datalink Type
        if (pcap_reader.getDatalinkType() == 113) {  // DLT_LINUX_SLL
            link_header_len = 16;
            if (header->caplen >= 16) {
                eth_type = ntohs(*reinterpret_cast<const uint16_t*>(&data[14]));
            }
        } else {  // Ethernet
            if (header->caplen >= 14) {
                eth_type = ntohs(*reinterpret_cast<const uint16_t*>(&data[12]));
            }
        }

        // Handle VLAN (802.1Q)
        if (eth_type == 0x8100 && header->caplen >= link_header_len + 4) {
            link_header_len += 4;
            // Read inner type (at offset 16 for Ethernet, 18 for SLL?? No, relative to new offset)
            // VLAN tag is 4 bytes. Original type field was at link_header_len - 2.
            // After VLAN, new type is at link_header_len - 2 + 4 = link_header_len + 2.
            // Wait, for Ethernet:
            // 0-11: MACs
            // 12-13: 0x8100
            // 14-15: VLAN ID
            // 16-17: EtherType
            // So new type is at 16. New header len is 18.
            eth_type = ntohs(
                *reinterpret_cast<const uint16_t*>(&data[link_header_len - 2]));  // Is this right?
            // Before increment: len=14. Type at 12.
            // VLAN: len becomes 18. Type at 16.
            // So if I increment len by 4, type is at len-2. Yes.
        }

        if (header->caplen >= static_cast<bpf_u_int32>(link_header_len + 20)) {  // IP(20)
            const uint8_t* ip_header = data + link_header_len;
            size_t ip_len = header->caplen - link_header_len;

            if (ip_len >= 20) {
                uint8_t version = (ip_header[0] >> 4) & 0x0F;
                if (version == 4) {
                    uint8_t ihl = (ip_header[0] & 0x0F) * 4;
                    uint8_t protocol = ip_header[9];
                    uint32_t src_ip = ntohl(*reinterpret_cast<const uint32_t*>(&ip_header[12]));
                    uint32_t dst_ip = ntohl(*reinterpret_cast<const uint32_t*>(&ip_header[16]));

                    packet.five_tuple.src_ip = utils::ipToString(src_ip);
                    packet.five_tuple.dst_ip = utils::ipToString(dst_ip);
                    packet.five_tuple.protocol = protocol;

                    const uint8_t* transport_header = ip_header + ihl;
                    size_t transport_len = ip_len - ihl;

                    if (protocol == 17 && transport_len >= 8) {  // UDP
                        packet.five_tuple.src_port =
                            ntohs(*reinterpret_cast<const uint16_t*>(&transport_header[0]));
                        packet.five_tuple.dst_port =
                            ntohs(*reinterpret_cast<const uint16_t*>(&transport_header[2]));

                        const uint8_t* payload = transport_header + 8;
                        size_t payload_len = transport_len - 8;

                        if (payload_len > 0) {
                            packet.raw_data.assign(payload, payload + payload_len);

                            // Try PFCP parsing (UDP port 8805)
                            if (packet.five_tuple.src_port == 8805 ||
                                packet.five_tuple.dst_port == 8805) {
                                PfcpParser pfcp_parser;
                                auto pfcp_msg = pfcp_parser.parse(packet.raw_data.data(),
                                                                  packet.raw_data.size());
                                if (pfcp_msg.has_value()) {
                                    correlator.processPacket(packet, ProtocolType::PFCP,
                                                             pfcp_msg->toJson());
                                }
                            }
                            // Try GTP-C parsing (UDP port 2123)
                            else if (packet.five_tuple.src_port == 2123 ||
                                     packet.five_tuple.dst_port == 2123) {
                                GtpParser gtp_parser;
                                auto gtp_msg = gtp_parser.parse(packet.raw_data.data(),
                                                                packet.raw_data.size());
                                if (gtp_msg.has_value()) {
                                    correlator.processPacket(packet, ProtocolType::GTP_C,
                                                             gtp_msg->toJson());
                                }
                            }
                            // Try DIAMETER parsing (TCP/UDP port 3868)
                            else if (packet.five_tuple.src_port == 3868 ||
                                     packet.five_tuple.dst_port == 3868) {
                                DiameterParser diameter_parser;
                                auto diameter_msg = diameter_parser.parse(packet.raw_data.data(),
                                                                          packet.raw_data.size());
                                if (diameter_msg.has_value()) {
                                    correlator.processPacket(packet, ProtocolType::DIAMETER,
                                                             diameter_msg->toJson());
                                }
                            }
                            // Try SIP parsing
                            else if (packet.five_tuple.src_port == 5060 ||
                                     packet.five_tuple.dst_port == 5060) {
                                SipParser sip_parser;
                                auto sip_msg = sip_parser.parse(packet.raw_data.data(),
                                                                packet.raw_data.size());
                                if (sip_msg.has_value()) {
                                    correlator.processPacket(packet, ProtocolType::SIP,
                                                             sip_msg->toJson());
                                }
                            }
                            // Try RTP parsing
                            else if ((packet.five_tuple.src_port >= 10000 &&
                                      packet.five_tuple.src_port % 2 == 0) ||
                                     (packet.five_tuple.dst_port >= 10000 &&
                                      packet.five_tuple.dst_port % 2 == 0)) {
                                RtpParser rtp_parser;
                                auto rtp_header = rtp_parser.parseRtp(packet.raw_data.data(),
                                                                      packet.raw_data.size());
                                if (rtp_header.has_value()) {
                                    correlator.processPacket(packet, ProtocolType::RTP,
                                                             rtp_header->toJson());
                                }
                            }
                        }
                    }
                }
            }
        }

        packet_count++;
        total_bytes += header->caplen;

        // Update progress every 1000 packets
        if (packet_count % 1000 == 0) {
            int progress = 10 + (packet_count % 10000) * 60 / 10000;  // 10-70%
            updateProgress(task.job_id, progress,
                           "Processed " + std::to_string(packet_count) + " packets");
        }

        // Send event every 100 packets
        if (packet_count % 100 == 0) {
            sendEvent(task.job_id, "progress", {{"packets", packet_count}, {"bytes", total_bytes}});
        }
    };

    pcap_reader.processPackets(callback);
    pcap_reader.close();

    updateProgress(task.job_id, 70, "Finalizing sessions");

    // Finalize sessions
    correlator.finalizeSessions();
    auto sessions = correlator.getAllSessions();

    updateProgress(task.job_id, 80, "Exporting results");

    // Export to JSON
    JsonExporter exporter;
    if (!exporter.exportToFile(task.output_file, sessions, true)) {
        throw std::runtime_error("Failed to export results to: " + task.output_file);
    }

    updateProgress(task.job_id, 100, "Completed");

    // Update job info
    {
        std::lock_guard<std::mutex> lock(jobs_mutex_);
        auto it = jobs_.find(task.job_id);
        if (it != jobs_.end()) {
            it->second->status = JobStatus::COMPLETED;
            it->second->progress = 100;
            it->second->completed_at = utils::now();
            it->second->total_packets = packet_count;
            it->second->total_bytes = total_bytes;
            it->second->session_count = sessions.size();

            // Store session IDs
            it->second->session_ids.clear();
            for (const auto& session : sessions) {
                it->second->session_ids.push_back(session->session_id);
            }

            // Update database
            if (db_) {
                db_->updateJob(task.job_id, *it->second);

                // Also insert sessions
                for (const auto& session : sessions) {
                    SessionRecord record;
                    record.session_id = session->session_id;
                    record.job_id = task.job_id;
                    record.session_type = sessionTypeToString(session->type);
                    record.session_key = session->session_key;

                    // Convert Timestamps
                    record.start_time = std::chrono::duration_cast<std::chrono::milliseconds>(
                                            session->start_time.time_since_epoch())
                                            .count();
                    record.end_time = std::chrono::duration_cast<std::chrono::milliseconds>(
                                          session->end_time.time_since_epoch())
                                          .count();
                    record.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                             session->end_time - session->start_time)
                                             .count();

                    // Metrics
                    record.packet_count = session->metrics.total_packets;
                    record.byte_count = session->metrics.total_bytes;

                    // Convert participants
                    nlohmann::json participants_json = nlohmann::json::array();
                    for (const auto& p : session->participants) {
                        participants_json.push_back({{"ip", p.ip}, {"port", p.port}});
                    }
                    record.participant_ips = participants_json.dump();

                    // Metadata
                    record.metadata = session->toSummaryJson().dump();

                    db_->insertSession(record);
                }
            }
        }
    }

    sendEvent(task.job_id, "status",
              {{"status", "completed"},
               {"sessions", sessions.size()},
               {"packets", packet_count},
               {"bytes", total_bytes}});

    LOG_INFO("Job " << task.job_id << " completed: " << packet_count << " packets, "
                    << sessions.size() << " sessions");
}

void JobManager::updateProgress(const JobId& job_id, int progress, const std::string& message) {
    {
        std::lock_guard<std::mutex> lock(jobs_mutex_);
        auto it = jobs_.find(job_id);
        if (it != jobs_.end()) {
            it->second->progress = progress;

            if (db_ && (progress % 10 == 0 || progress == 100)) {  // Don't update DB too often
                db_->updateJob(job_id, *it->second);
            }
        }
    }

    if (progress_callback_) {
        progress_callback_(job_id, progress, message);
    }
}

void JobManager::sendEvent(const JobId& job_id, const std::string& event_type,
                           const nlohmann::json& data) {
    if (event_callback_) {
        event_callback_(job_id, event_type, data);
    }
}

}  // namespace callflow
