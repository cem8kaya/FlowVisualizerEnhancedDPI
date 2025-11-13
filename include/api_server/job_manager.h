#pragma once

#include "common/types.h"
#include "common/logger.h"
#include <memory>
#include <unordered_map>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <functional>
#include <atomic>

namespace callflow {

// Forward declarations
class SessionCorrelator;

/**
 * Progress callback function
 * Parameters: job_id, progress (0-100), message
 */
using ProgressCallback = std::function<void(const JobId&, int, const std::string&)>;

/**
 * Event callback function for WebSocket streaming
 * Parameters: job_id, event_type, event_data
 */
using EventCallback = std::function<void(const JobId&, const std::string&, const nlohmann::json&)>;

/**
 * Job Manager - manages background PCAP processing jobs
 */
class JobManager {
public:
    explicit JobManager(const Config& config);
    ~JobManager();

    /**
     * Start the job manager and worker threads
     */
    bool start();

    /**
     * Stop the job manager and wait for all workers
     */
    void stop();

    /**
     * Submit a new job
     * @param input_file Path to input PCAP file
     * @param output_file Path to output JSON file (optional)
     * @return Job ID on success, empty string on failure
     */
    JobId submitJob(const std::string& input_file, const std::string& output_file = "");

    /**
     * Get job info
     * @param job_id Job ID
     * @return Job info if found, nullptr otherwise
     */
    std::shared_ptr<JobInfo> getJobInfo(const JobId& job_id);

    /**
     * Get all jobs
     * @return Vector of all job infos
     */
    std::vector<std::shared_ptr<JobInfo>> getAllJobs();

    /**
     * Delete a job and its results
     * @param job_id Job ID
     * @return true on success, false if job not found or still running
     */
    bool deleteJob(const JobId& job_id);

    /**
     * Set progress callback
     */
    void setProgressCallback(ProgressCallback callback) {
        progress_callback_ = callback;
    }

    /**
     * Set event callback for WebSocket streaming
     */
    void setEventCallback(EventCallback callback) {
        event_callback_ = callback;
    }

    /**
     * Get session IDs for a job
     * @param job_id Job ID
     * @return Vector of session IDs
     */
    std::vector<SessionId> getJobSessions(const JobId& job_id);

    /**
     * Clean up old completed jobs
     */
    void cleanupOldJobs();

private:
    struct JobTask {
        JobId job_id;
        std::string input_file;
        std::string output_file;
    };

    /**
     * Worker thread function
     */
    void workerThread();

    /**
     * Process a single job
     */
    void processJob(const JobTask& task);

    /**
     * Update job progress
     */
    void updateProgress(const JobId& job_id, int progress, const std::string& message = "");

    /**
     * Send event notification
     */
    void sendEvent(const JobId& job_id, const std::string& event_type, const nlohmann::json& data);

    Config config_;

    // Job storage
    std::unordered_map<JobId, std::shared_ptr<JobInfo>> jobs_;
    std::mutex jobs_mutex_;

    // Job queue
    std::queue<JobTask> job_queue_;
    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;

    // Worker threads
    std::vector<std::thread> workers_;
    std::atomic<bool> running_;

    // Callbacks
    ProgressCallback progress_callback_;
    EventCallback event_callback_;
};

}  // namespace callflow
