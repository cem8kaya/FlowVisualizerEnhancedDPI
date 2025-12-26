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
        } catch (...) {
            LOG_ERROR("Job " << task.job_id << " failed with unknown exception");

            // Mark job as failed
            {
                std::lock_guard<std::mutex> lock(jobs_mutex_);
                auto it = jobs_.find(task.job_id);
                if (it != jobs_.end()) {
                    it->second->status = JobStatus::FAILED;
                    it->second->error_message = "Unknown exception during job processing";
                    it->second->completed_at = utils::now();

                    // Update database
                    if (db_) {
                        db_->updateJob(task.job_id, *it->second);
                    }
                }
            }

            sendEvent(task.job_id, "status", {{"status", "failed"}, {"error", "Unknown exception"}});
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

        updateProgress(task.job_id, 10, "PCAPNG file opened");

        // Use processPackets to handle all block types and parse packets
        auto callback = [&](uint32_t interface_id, uint64_t timestamp_ns, const uint8_t* data,
                            uint32_t cap_len, uint32_t /*orig_len*/,
                            const PcapngPacketMetadata& meta) {
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

            if (packet_count % 1000 == 0) {
                int progress = 10 + (packet_count % 10000) * 60 / 10000;
                updateProgress(task.job_id, progress,
                               "Processed " + std::to_string(packet_count) + " packets");
            }
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

        auto callback = [&](const uint8_t* data, const struct pcap_pkthdr* header, void* /*user*/) {
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

    LOG_INFO("Job " << task.job_id << ": Starting post-processing after " << packet_count << " packets");
    updateProgress(task.job_id, 70, "Finalizing sessions");

    // Finalize sessions with detailed error handling
    LOG_INFO("Job " << task.job_id << ": Calling finalizeSessions()");
    try {
        correlator.finalizeSessions();
        LOG_INFO("Job " << task.job_id << ": finalizeSessions() completed successfully");
    } catch (const std::exception& e) {
        LOG_ERROR("Job " << task.job_id << ": finalizeSessions() failed: " << e.what());
        throw;
    }

    // Get raw sessions for stats
    LOG_INFO("Job " << task.job_id << ": Calling getAllSessions()");
    std::vector<std::shared_ptr<Session>> sessions;
    try {
        sessions = correlator.getAllSessions();
        LOG_INFO("Job " << task.job_id << ": getAllSessions() returned " << sessions.size() << " sessions");
    } catch (const std::exception& e) {
        LOG_ERROR("Job " << task.job_id << ": getAllSessions() failed: " << e.what());
        throw;
    }

    // Get master sessions for export
    LOG_INFO("Job " << task.job_id << ": Calling getAllMasterSessions()");
    std::unordered_map<std::string, VolteMasterSession> master_sessions;
    try {
        master_sessions = correlator.getAllMasterSessions();
        LOG_INFO("Job " << task.job_id << ": getAllMasterSessions() returned " << master_sessions.size() << " master sessions");
    } catch (const std::exception& e) {
        LOG_ERROR("Job " << task.job_id << ": getAllMasterSessions() failed: " << e.what());
        throw;
    }

    updateProgress(task.job_id, 80, "Exporting results");

    // Export all sessions including SIP-only (standalone SIP sessions without GTP correlation)
    // This ensures SIP traffic is visible even when there's no GTP anchor for correlation
    LOG_INFO("Job " << task.job_id << ": Calling exportAllSessionsWithSipOnly()");
    JsonExporter exporter;
    std::string all_sessions_json_str;
    try {
        all_sessions_json_str = exporter.exportAllSessionsWithSipOnly(correlator);
        LOG_INFO("Job " << task.job_id << ": exportAllSessionsWithSipOnly() returned " << all_sessions_json_str.size() << " bytes");
    } catch (const std::exception& e) {
        LOG_ERROR("Job " << task.job_id << ": exportAllSessionsWithSipOnly() failed: " << e.what());
        throw;
    }

    // Wrap in object structure
    LOG_INFO("Job " << task.job_id << ": Parsing JSON output");
    nlohmann::json final_output;
    try {
        final_output["sessions"] = nlohmann::json::parse(all_sessions_json_str);
        final_output["metadata"] = {{"job_id", task.job_id},
                                    {"timestamp", utils::timestampToIso8601(utils::now())},
                                    {"exporter", "VolteMasterSessionWithSipOnly"}};
        LOG_INFO("Job " << task.job_id << ": JSON parsing completed successfully");
    } catch (const std::exception& e) {
        LOG_ERROR("Job " << task.job_id << ": JSON parsing failed: " << e.what());
        throw;
    }

    // Write to file
    LOG_INFO("Job " << task.job_id << ": Writing output to " << task.output_file);
    try {
        std::ofstream out(task.output_file);
        if (!out) {
            throw std::runtime_error("Failed to open output file: " + task.output_file);
        }
        out << final_output.dump(4);  // Pretty print
        out.close();
        LOG_INFO("Job " << task.job_id << ": Output file written successfully");
    } catch (const std::exception& e) {
        LOG_ERROR("Job " << task.job_id << ": File write failed: " << e.what());
        throw;
    }

    updateProgress(task.job_id, 100, "Completed");

    // Update job info with error handling
    LOG_INFO("Job " << task.job_id << ": Updating job status and database");
    try {
        std::lock_guard<std::mutex> lock(jobs_mutex_);
        auto it = jobs_.find(task.job_id);
        if (it != jobs_.end()) {
            it->second->status = JobStatus::COMPLETED;
            it->second->progress = 100;
            it->second->completed_at = utils::now();
            it->second->total_packets = packet_count;
            it->second->total_bytes = total_bytes;
            // Include both master sessions and SIP-only sessions in the count
            size_t sip_only_count = correlator.getSipOnlySessionCount();
            it->second->session_count = master_sessions.size() + sip_only_count;

            // Store Master Session IDs
            it->second->session_ids.clear();
            for (const auto& [imsi, ms] : master_sessions) {
                it->second->session_ids.push_back(ms.master_uuid);
            }

            LOG_INFO("Job " << task.job_id << ": Job info updated, session_count=" << it->second->session_count);

            // Update database
            if (db_) {
                LOG_INFO("Job " << task.job_id << ": Updating database");
                db_->updateJob(task.job_id, *it->second);

                // Insert Master Sessions into DB
                // Mapping VolteMasterSession to SessionRecord (best effort)
                std::set<std::string> inserted_ids;
                size_t db_insert_count = 0;
                for (const auto& [imsi, ms] : master_sessions) {
                    if (inserted_ids.count(ms.master_uuid)) {
                        continue;
                    }
                    inserted_ids.insert(ms.master_uuid);

                    SessionRecord record;
                    record.session_id = ms.master_uuid;
                    record.job_id = task.job_id;
                    record.session_type = "VoLTE Call";  // Master session type

                    // Key: IMSI or MSISDN
                    std::string key = "IMSI: " + ms.imsi;
                    if (!ms.msisdn.empty())
                        key += ", MSISDN: " + ms.msisdn;
                    record.session_key = key;

                    // Times: Use start/end from object
                    auto start_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                        ms.start_time.time_since_epoch())
                                        .count();
                    auto last_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                       ms.last_update_time.time_since_epoch())
                                       .count();

                    record.start_time = (start_ms > 0) ? start_ms : 0;
                    record.end_time = (last_ms > 0) ? last_ms : record.start_time;
                    record.duration_ms = (record.end_time >= record.start_time)
                                             ? (record.end_time - record.start_time)
                                             : 0;

                    record.packet_count = 0;
                    record.byte_count = 0;

                    // Participants and Metadata
                    record.participant_ips = "[]";
                    record.metadata = "{}";

                    db_->insertSession(record);
                    db_insert_count++;
                }
                LOG_INFO("Job " << task.job_id << ": Inserted " << db_insert_count << " sessions into database");
            }
        }
    } catch (const std::exception& e) {
        LOG_ERROR("Job " << task.job_id << ": Database update failed: " << e.what());
        throw;
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
