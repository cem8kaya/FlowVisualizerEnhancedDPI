#include "api_server/http_server.h"

#include "api_server/routes.h"
#include "common/logger.h"
#include "common/utils.h"
#include "event_extractor/json_exporter.h"

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <httplib.h>

#include <filesystem>
#include <fstream>

namespace callflow {

HttpServer::HttpServer(const Config& config, std::shared_ptr<JobManager> job_manager,
                       std::shared_ptr<WebSocketHandler> ws_handler)
    : config_(config),
      job_manager_(job_manager),
      ws_handler_(ws_handler),
      server_impl_(nullptr),
      running_(false) {}

HttpServer::~HttpServer() {
    stop();
}

bool HttpServer::start() {
    if (running_.load()) {
        LOG_WARN("HTTP server already running");
        return false;
    }

    LOG_INFO("Starting HTTP server on " << config_.api_bind_address << ":" << config_.api_port);

    // Create httplib server
    server_impl_ = new httplib::Server();
    auto* server = static_cast<httplib::Server*>(server_impl_);

    // Set server options
    server->set_payload_max_length(config_.max_upload_size_mb * 1024 * 1024);
    server->set_read_timeout(300);  // 5 minutes for large uploads
    server->set_write_timeout(300);

    // Setup routes
    setupRoutes();

    // Start server in background thread
    running_.store(true);
    server_thread_ = std::thread(&HttpServer::serverThread, this);

    LOG_INFO("HTTP server started successfully");
    return true;
}

void HttpServer::stop() {
    if (!running_.load()) {
        return;
    }

    LOG_INFO("Stopping HTTP server...");
    running_.store(false);

    if (server_impl_) {
        auto* server = static_cast<httplib::Server*>(server_impl_);
        server->stop();
    }

    if (server_thread_.joinable()) {
        server_thread_.join();
    }

    if (server_impl_) {
        delete static_cast<httplib::Server*>(server_impl_);
        server_impl_ = nullptr;
    }

    LOG_INFO("HTTP server stopped");
}

void HttpServer::setupRoutes() {
    auto* server = static_cast<httplib::Server*>(server_impl_);

    // Enable CORS
    server->set_pre_routing_handler([](const httplib::Request& req, httplib::Response& res) {
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization");

        if (req.method == "OPTIONS") {
            res.status = 204;  // No Content
            return httplib::Server::HandlerResponse::Handled;
        }
        return httplib::Server::HandlerResponse::Unhandled;
    });

    // Health check
    server->Get("/health", [](const httplib::Request&, httplib::Response& res) {
        nlohmann::json response = {{"status", "healthy"},
                                   {"timestamp", utils::timestampToIso8601(utils::now())}};
        res.set_content(response.dump(), "application/json");
    });

    // POST /api/v1/upload - Upload PCAP file
    server->Post("/api/v1/upload", [this](const httplib::Request& req, httplib::Response& res) {
        try {
            // Check if file was uploaded
            auto file_it = req.files.find("file");
            if (file_it == req.files.end()) {
                nlohmann::json error = {{"error", "No file uploaded"}, {"code", "NO_FILE"}};
                res.status = 400;
                res.set_content(error.dump(), "application/json");
                return;
            }

            const auto& file = file_it->second;
            LOG_INFO("Received upload: " << file.filename << " (" << file.content.size()
                                         << " bytes)");

            // Check file size
            if (file.content.size() > config_.max_upload_size_mb * 1024 * 1024) {
                nlohmann::json error = {{"error", "File too large"},
                                        {"code", "FILE_TOO_LARGE"},
                                        {"max_size_mb", config_.max_upload_size_mb}};
                res.status = 413;
                res.set_content(error.dump(), "application/json");
                return;
            }

            // Save file
            JobId job_id = utils::generateUuid();
            std::string saved_path = config_.upload_dir + "/upload-" + job_id + ".pcap";

            std::ofstream outfile(saved_path, std::ios::binary);
            if (!outfile) {
                throw std::runtime_error("Failed to save uploaded file");
            }
            outfile.write(file.content.data(), file.content.size());
            outfile.close();

            // Submit job
            job_id = job_manager_->submitJob(saved_path);
            if (job_id.empty()) {
                throw std::runtime_error("Failed to submit job");
            }

            nlohmann::json response = {{"job_id", job_id}, {"status", "queued"}};
            res.status = 201;
            res.set_content(response.dump(), "application/json");

        } catch (const std::exception& e) {
            LOG_ERROR("Upload failed: " << e.what());
            nlohmann::json error = {{"error", e.what()}, {"code", "INTERNAL_ERROR"}};
            res.status = 500;
            res.set_content(error.dump(), "application/json");
        }
    });

    // GET /api/v1/jobs/{job_id}/status - Get job status
    server->Get("/api/v1/jobs/:job_id/status", [this](const httplib::Request& req,
                                                      httplib::Response& res) {
        try {
            std::string job_id = req.path_params.at("job_id");
            auto job_info = job_manager_->getJobInfo(job_id);

            if (!job_info) {
                nlohmann::json error = {{"error", "Job not found"}, {"code", "JOB_NOT_FOUND"}};
                res.status = 404;
                res.set_content(error.dump(), "application/json");
                return;
            }

            nlohmann::json response = {
                {"job_id", job_info->job_id},
                {"status", jobStatusToString(job_info->status)},
                {"progress", job_info->progress},
                {"created_at", utils::timestampToIso8601(job_info->created_at)}};

            if (job_info->status == JobStatus::RUNNING) {
                response["started_at"] = utils::timestampToIso8601(job_info->started_at);
            }

            if (job_info->status == JobStatus::COMPLETED || job_info->status == JobStatus::FAILED) {
                response["completed_at"] = utils::timestampToIso8601(job_info->completed_at);
            }

            if (job_info->status == JobStatus::FAILED) {
                response["error"] = job_info->error_message;
            }

            if (job_info->status == JobStatus::COMPLETED) {
                response["total_packets"] = job_info->total_packets;
                response["total_bytes"] = job_info->total_bytes;
                response["session_count"] = job_info->session_ids.size();
            }

            res.set_content(response.dump(), "application/json");

        } catch (const std::exception& e) {
            LOG_ERROR("Get status failed: " << e.what());
            nlohmann::json error = {{"error", e.what()}, {"code", "INTERNAL_ERROR"}};
            res.status = 500;
            res.set_content(error.dump(), "application/json");
        }
    });

    // GET /api/v1/jobs/{job_id}/sessions - Get job sessions (paginated)
    server->Get("/api/v1/jobs/:job_id/sessions", [this](const httplib::Request& req,
                                                        httplib::Response& res) {
        try {
            std::string job_id = req.path_params.at("job_id");
            auto job_info = job_manager_->getJobInfo(job_id);

            if (!job_info) {
                nlohmann::json error = {{"error", "Job not found"}, {"code", "JOB_NOT_FOUND"}};
                res.status = 404;
                res.set_content(error.dump(), "application/json");
                return;
            }

            if (job_info->status != JobStatus::COMPLETED) {
                nlohmann::json error = {{"error", "Job not completed yet"},
                                        {"code", "JOB_NOT_COMPLETED"},
                                        {"current_status", jobStatusToString(job_info->status)}};
                res.status = 400;
                res.set_content(error.dump(), "application/json");
                return;
            }

            // Pagination parameters
            int page = 1;
            int limit = 50;
            if (req.has_param("page")) {
                page = std::stoi(req.get_param_value("page"));
            }
            if (req.has_param("limit")) {
                limit = std::stoi(req.get_param_value("limit"));
            }

            // Load sessions from output file
            std::ifstream infile(job_info->output_filename);
            if (!infile) {
                throw std::runtime_error("Failed to read results file");
            }

            nlohmann::json full_results;
            infile >> full_results;

            // Extract sessions array
            if (!full_results.contains("sessions") || !full_results["sessions"].is_array()) {
                throw std::runtime_error("Invalid results format");
            }

            auto sessions = full_results["sessions"];
            size_t total_count = sessions.size();

            // Apply pagination
            size_t start_idx = (page - 1) * limit;
            size_t end_idx = std::min(start_idx + limit, total_count);

            nlohmann::json paginated_sessions = nlohmann::json::array();
            for (size_t i = start_idx; i < end_idx; ++i) {
                paginated_sessions.push_back(sessions[i]);
            }

            nlohmann::json response = {{"job_id", job_id},
                                       {"page", page},
                                       {"limit", limit},
                                       {"total", total_count},
                                       {"sessions", paginated_sessions}};

            res.set_content(response.dump(), "application/json");

        } catch (const std::exception& e) {
            LOG_ERROR("Get sessions failed: " << e.what());
            nlohmann::json error = {{"error", e.what()}, {"code", "INTERNAL_ERROR"}};
            res.status = 500;
            res.set_content(error.dump(), "application/json");
        }
    });

    // GET /api/v1/sessions/{session_id} - Get session detail
    server->Get("/api/v1/sessions/:session_id", [this](const httplib::Request& req,
                                                       httplib::Response& res) {
        try {
            std::string session_id = req.path_params.at("session_id");

            // Search through all completed jobs for this session
            auto all_jobs = job_manager_->getAllJobs();
            for (const auto& job : all_jobs) {
                if (job->status != JobStatus::COMPLETED) {
                    continue;
                }

                // Check if session is in this job
                auto it = std::find(job->session_ids.begin(), job->session_ids.end(), session_id);
                if (it == job->session_ids.end()) {
                    continue;
                }

                // Load sessions from output file
                std::ifstream infile(job->output_filename);
                if (!infile) {
                    continue;
                }

                nlohmann::json full_results;
                infile >> full_results;

                // Find the session
                if (full_results.contains("sessions") && full_results["sessions"].is_array()) {
                    for (const auto& session : full_results["sessions"]) {
                        if (session["session_id"] == session_id) {
                            res.set_content(session.dump(), "application/json");
                            return;
                        }
                    }
                }
            }

            // Session not found
            nlohmann::json error = {{"error", "Session not found"}, {"code", "SESSION_NOT_FOUND"}};
            res.status = 404;
            res.set_content(error.dump(), "application/json");

        } catch (const std::exception& e) {
            LOG_ERROR("Get session failed: " << e.what());
            nlohmann::json error = {{"error", e.what()}, {"code", "INTERNAL_ERROR"}};
            res.status = 500;
            res.set_content(error.dump(), "application/json");
        }
    });

    // DELETE /api/v1/jobs/{job_id} - Delete job
    server->Delete("/api/v1/jobs/:job_id",
                   [this](const httplib::Request& req, httplib::Response& res) {
                       try {
                           std::string job_id = req.path_params.at("job_id");

                           if (job_manager_->deleteJob(job_id)) {
                               nlohmann::json response = {{"message", "Job deleted successfully"},
                                                          {"job_id", job_id}};
                               res.set_content(response.dump(), "application/json");
                           } else {
                               nlohmann::json error = {{"error", "Job not found or still running"},
                                                       {"code", "CANNOT_DELETE_JOB"}};
                               res.status = 400;
                               res.set_content(error.dump(), "application/json");
                           }

                       } catch (const std::exception& e) {
                           LOG_ERROR("Delete job failed: " << e.what());
                           nlohmann::json error = {{"error", e.what()}, {"code", "INTERNAL_ERROR"}};
                           res.status = 500;
                           res.set_content(error.dump(), "application/json");
                       }
                   });

    // GET /api/v1/jobs - Get all jobs
    server->Get("/api/v1/jobs", [this](const httplib::Request&, httplib::Response& res) {
        try {
            auto all_jobs = job_manager_->getAllJobs();

            nlohmann::json jobs_array = nlohmann::json::array();
            for (const auto& job : all_jobs) {
                nlohmann::json job_summary = {
                    {"job_id", job->job_id},
                    {"status", jobStatusToString(job->status)},
                    {"progress", job->progress},
                    {"created_at", utils::timestampToIso8601(job->created_at)}};

                if (job->status == JobStatus::COMPLETED) {
                    job_summary["session_count"] = job->session_ids.size();
                    job_summary["total_packets"] = job->total_packets;
                }

                jobs_array.push_back(job_summary);
            }

            nlohmann::json response = {{"jobs", jobs_array}, {"total", all_jobs.size()}};

            res.set_content(response.dump(), "application/json");

        } catch (const std::exception& e) {
            LOG_ERROR("Get all jobs failed: " << e.what());
            nlohmann::json error = {{"error", e.what()}, {"code", "INTERNAL_ERROR"}};
            res.status = 500;
            res.set_content(error.dump(), "application/json");
        }
    });

    LOG_INFO("HTTP routes configured");
}

void HttpServer::serverThread() {
    auto* server = static_cast<httplib::Server*>(server_impl_);

    try {
        if (!server->listen(config_.api_bind_address.c_str(), config_.api_port)) {
            LOG_ERROR("Failed to start HTTP server on " << config_.api_bind_address << ":"
                                                        << config_.api_port);
            running_.store(false);
        }
    } catch (const std::exception& e) {
        LOG_ERROR("HTTP server error: " << e.what());
        running_.store(false);
    }
}

}  // namespace callflow
