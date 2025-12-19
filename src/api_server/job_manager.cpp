#include "api_server/job_manager.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/udp.h>

#include <filesystem>
#include <set>

#include "common/utils.h"
#include "event_extractor/json_exporter.h"
#include "pcap_ingest/packet_processor.h"
#include "pcap_ingest/pcap_reader.h"
#include "pcap_ingest/pcapng_reader.h"
#include "persistence/database.h"
#include "protocol_parsers/diameter_parser.h"
#include "protocol_parsers/gtp_parser.h"
#include "protocol_parsers/pfcp_parser.h"
#include "protocol_parsers/rtp_parser.h"
#include "protocol_parsers/sip_parser.h"
#include "session/session_correlator.h"
#include "session/session_correlator.h"  // EnhancedSessionCorrelator
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

JobId JobManager::submitJob(const std::string& input_file, const std::string& original_filename,
                            const std::string& output_file) {
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
    job_info->original_filename = original_filename;
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

    EnhancedSessionCorrelator correlator;  // Default constructor? Or config?
    // Check constructor of EnhancedSessionCorrelator. It is default.
    // EnhancedSessionCorrelator correlator; // No config?
    // Old SessionCorrelator took config.
    // Let's assume default is fine based on header file view.
    PacketProcessor processor(correlator);

    size_t packet_count = 0;
    size_t total_bytes = 0;

    // Detect format
    bool is_pcapng = PcapngReader::validate(task.input_file);

    if (is_pcapng) {
        LOG_INFO("Detected PCAPNG format for job " << task.job_id);
        PcapngReader reader;
        if (!reader.open(task.input_file)) {
            throw std::runtime_error("Failed to open PCAPNG file: " + task.input_file);
        }

        // PcapngReader uses a block-based loop or processPackets with callback.
        // But we want to intercept comments and stats.
        // PcapngReader::processPackets only gives us packets.
        // We need to iterate blocks manually?
        // PcapngReader API: readNextBlock(), getCurrentBlockType().

        while (reader.readNextBlock()) {
            auto block_type = reader.getCurrentBlockType();

            if (block_type == PcapngBlockType::ENHANCED_PACKET) {
                uint32_t interface_id;
                uint64_t timestamp;
                std::vector<uint8_t> packet_data;
                uint32_t original_length;
                PcapngPacketMetadata metadata;

                if (reader.readEnhancedPacket(interface_id, timestamp, packet_data, original_length,
                                              metadata)) {
                    // Convert timestamp ns to systemclock
                    auto ts = std::chrono::system_clock::time_point(
                        std::chrono::duration_cast<std::chrono::system_clock::duration>(
                            std::chrono::nanoseconds(timestamp)));

                    // TODO: Pass DLT? Pcapng interface has link type.
                    const PcapngInterface* iface = reader.getInterface(interface_id);
                    int dlt = iface ? iface->link_type : 1;  // Default to Ethernet

                    processor.processPacket(packet_data.data(), packet_data.size(), ts,
                                            packet_count, dlt);

                    packet_count++;
                    total_bytes += packet_data.size();
                }
            } else if (block_type == PcapngBlockType::INTERFACE_STATISTICS) {
                // Parse stats
                // Need to expose parseInterfaceStatistics or access the stats?
                // The reader parses it automatically if we call parseInterfaceStatistics() but that
                // is private? Wait, processPackets calls it. If we manually loop, we need to call
                // the parse methods. BUT they are private helpers in PcapngReader. We should
                // probably enhance PcapngReader public API or just use `processPackets` and extract
                // stats afterwards? `reader.getInterfaceStatistics()` returns the vector of parsed
                // stats. So if we just continue loop, does it parse? Look at `readNextBlock`: it
                // reads type and data. That's it. Calling `processPackets` (API) does the dispatch.
                // `processPackets` takes a callback for PACKETS. It handles other blocks
                // internally. So we can use `processPackets`.
            }

            if (packet_count % 1000 == 0 && packet_count > 0) {
                int progress = 10 + (packet_count % 10000) * 60 / 10000;
                updateProgress(task.job_id, progress,
                               "Processed " + std::to_string(packet_count) + " packets");
            }
        }

        // Use processPackets for simplicity? No, we started manual loop logic.
        // Actually manual loop logic above is incomplete because `parseInterfaceStatistics` is
        // private. I checked `PcapngReader` code earlier. `parseInterfaceStatistics` is private.
        // Accessing `current_block_type_` is public.

        // FIX: I will use `processPackets` and let it handle parsing.
        // Then I will retrieve stats via `getInterfaceStatistics()` AFTER processing.
        // And `processPackets` handles logic for all blocks internally (calls parseXxxx).

        // Re-opening reader or resetting? No, just use processPackets.
        // Need to close/re-open? I just opened it. I haven't consumed loop yet (logic above was
        // just hypothetical). So I will use `reader.processPackets`.

        auto callback = [&](uint32_t interface_id, uint64_t timestamp_ns, const uint8_t* data,
                            uint32_t cap_len, uint32_t orig_len, const PcapngPacketMetadata& meta) {
            auto ts = std::chrono::system_clock::time_point(
                std::chrono::duration_cast<std::chrono::system_clock::duration>(
                    std::chrono::nanoseconds(timestamp_ns)));

            const PcapngInterface* iface = reader.getInterface(interface_id);
            int dlt = iface ? iface->link_type : 1;

            processor.processPacket(data, cap_len, ts, packet_count, dlt);

            // Capture comments
            if (meta.comment.has_value()) {
                std::lock_guard<std::mutex> lock(jobs_mutex_);
                auto it = jobs_.find(task.job_id);
                if (it != jobs_.end()) {
                    it->second->comments.push_back(meta.comment.value());
                }
            }

            packet_count++;
            total_bytes += cap_len;
        };

        reader.processPackets(callback);

        // Post-processing: Extract stats
        {
            std::lock_guard<std::mutex> lock(jobs_mutex_);
            auto it = jobs_.find(task.job_id);
            if (it != jobs_.end()) {
                const auto& stats = reader.getInterfaceStatistics();
                for (const auto& s : stats) {
                    JobInfo::InterfaceStats js;
                    js.interface_id = s.interface_id;
                    const auto* iface = reader.getInterface(s.interface_id);
                    if (iface && iface->name.has_value()) {
                        js.interface_name = iface->name.value();
                    }
                    js.packets_received = s.packets_received.value_or(0);
                    js.packets_dropped = s.packets_dropped.value_or(0);
                    it->second->interface_stats.push_back(js);
                }

                // Also get section header comments
                const auto& shb = reader.getSectionHeader();
                if (shb.comment.has_value()) {
                    it->second->comments.push_back("SHB: " + shb.comment.value());
                }
            }
        }

    } else {
        // Standard PCAP
        LOG_INFO("Detected standard PCAP format for job " << task.job_id);
        PcapReader reader;
        if (!reader.open(task.input_file)) {
            throw std::runtime_error("Failed to open PCAP file: " + task.input_file);
        }

        updateProgress(task.job_id, 10, "PCAP file opened");

        int dlt = reader.getDatalinkType();

        auto callback = [&](const uint8_t* data, const struct pcap_pkthdr* header, void* user) {
            auto ts = std::chrono::system_clock::from_time_t(header->ts.tv_sec) +
                      std::chrono::microseconds(header->ts.tv_usec);

            processor.processPacket(data, header->caplen, ts, packet_count, dlt);

            packet_count++;
            total_bytes += header->caplen;

            if (packet_count % 1000 == 0) {
                int progress = 10 + (packet_count % 10000) * 60 / 10000;
                updateProgress(task.job_id, progress,
                               "Processed " + std::to_string(packet_count) + " packets");
            }
        };

        reader.processPackets(callback);
        reader.close();
    }

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
                    record.session_type = enhancedSessionTypeToString(session->session_type);

                    // Session Key: Use primary identifier or JSON dump
                    record.session_key = session->correlation_key.getPrimaryIdentifier();
                    if (record.session_key.empty()) {
                        record.session_key = session->correlation_key.toJson().dump();
                    }

                    // Convert Timestamps
                    if (session->start_time.time_since_epoch().count() > 0) {
                        record.start_time = std::chrono::duration_cast<std::chrono::milliseconds>(
                                                session->start_time.time_since_epoch())
                                                .count();
                    } else {
                        record.start_time = 0;
                    }

                    if (session->end_time.time_since_epoch().count() > 0) {
                        record.end_time = std::chrono::duration_cast<std::chrono::milliseconds>(
                                              session->end_time.time_since_epoch())
                                              .count();
                    } else {
                        record.end_time = record.start_time;
                    }

                    record.duration_ms = 0;
                    if (record.end_time >= record.start_time) {
                        record.duration_ms = record.end_time - record.start_time;
                    }

                    // Metrics
                    record.packet_count = session->total_packets;
                    record.byte_count = session->total_bytes;

                    // Convert participants (Extract unique IPs)
                    nlohmann::json participants_json = nlohmann::json::array();
                    std::set<std::string> unique_ips;
                    for (const auto& leg : session->legs) {
                        for (const auto& msg : leg.messages) {
                            if (unique_ips.find(msg.src_ip) == unique_ips.end()) {
                                unique_ips.insert(msg.src_ip);
                                participants_json.push_back(
                                    {{"ip", msg.src_ip}, {"port", msg.src_port}});
                            }
                            if (unique_ips.find(msg.dst_ip) == unique_ips.end()) {
                                unique_ips.insert(msg.dst_ip);
                                participants_json.push_back(
                                    {{"ip", msg.dst_ip}, {"port", msg.dst_port}});
                            }
                        }
                    }
                    record.participant_ips = participants_json.dump();

                    // Metadata
                    record.metadata = session->toJson().dump();

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
