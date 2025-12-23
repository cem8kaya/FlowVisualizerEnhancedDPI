#include "api_server/http_server.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <thread>
#include <vector>

#include "common/logger.h"
#include "common/utils.h"  // Needed for timestampToIso8601
#include "config/config_manager.h"

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <httplib.h>

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

    // Serve static files (Web UI)
    // The Dockerfile copies ui/static to /app/ui/static
    auto ret = server->set_mount_point("/", "/app/ui/static");
    if (!ret) {
        LOG_WARN("Failed to mount static files directory: /app/ui/static");
    } else {
        LOG_INFO("Serving static files from /app/ui/static");
    }

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
            job_id = job_manager_->submitJob(saved_path, file.filename);
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
                {"input_filename",
                 job_info->original_filename.empty()
                     ? std::filesystem::path(job_info->input_filename).filename().string()
                     : job_info->original_filename},
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

            // Apply filtering
            std::string filter_imsi = req.has_param("imsi") ? req.get_param_value("imsi") : "";
            std::string filter_msisdn =
                req.has_param("msisdn") ? req.get_param_value("msisdn") : "";

            nlohmann::json filtered_sessions = nlohmann::json::array();
            for (const auto& session : sessions) {
                bool match = true;
                if (!filter_imsi.empty()) {
                    if (session.value("imsi", "") != filter_imsi)
                        match = false;
                }
                if (!filter_msisdn.empty()) {
                    if (session.value("msisdn", "") != filter_msisdn)
                        match = false;
                }
                if (match) {
                    filtered_sessions.push_back(session);
                }
            }

            size_t total_count = filtered_sessions.size();

            // Apply pagination
            size_t start_idx = (page - 1) * limit;
            size_t end_idx = std::min(start_idx + limit, total_count);

            nlohmann::json paginated_sessions = nlohmann::json::array();
            for (size_t i = start_idx; i < end_idx; ++i) {
                paginated_sessions.push_back(filtered_sessions[i]);
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
            std::string filter_job_id =
                req.has_param("job_id") ? req.get_param_value("job_id") : "";

            std::vector<std::shared_ptr<JobInfo>> jobs_to_search;
            if (!filter_job_id.empty()) {
                auto job = job_manager_->getJobInfo(filter_job_id);
                if (job) {
                    jobs_to_search.push_back(job);
                } else {
                    LOG_ERROR("Requested job_id " << filter_job_id << " not found in JobManager");
                }
            } else {
                jobs_to_search = job_manager_->getAllJobs();
            }

            if (jobs_to_search.empty()) {
                LOG_ERROR("No jobs to search for session " << session_id);
            }

            for (const auto& job : jobs_to_search) {
                if (job->status != JobStatus::COMPLETED) {
                    continue;
                }

                // If searching globally (no job_id), use index optimization
                if (filter_job_id.empty()) {
                    auto it =
                        std::find(job->session_ids.begin(), job->session_ids.end(), session_id);
                    if (it == job->session_ids.end()) {
                        continue;
                    }
                }

                LOG_DEBUG("Looking up session: Job=" << job->job_id
                                                     << " File=" << job->output_filename
                                                     << " TargetSession=" << session_id);

                // Load sessions from output file
                if (!std::filesystem::exists(job->output_filename)) {
                    LOG_ERROR("Output file does not exist: " << job->output_filename);
                    continue;
                }

                std::ifstream infile(job->output_filename);
                if (!infile) {
                    LOG_ERROR("Failed to open output file: " << job->output_filename);
                    continue;
                }

                nlohmann::json full_results;
                try {
                    infile >> full_results;
                } catch (const std::exception& e) {
                    LOG_ERROR("Failed to parse JSON file: " << e.what());
                    continue;
                }

                // Find the session
                if (full_results.contains("sessions") && full_results["sessions"].is_array()) {
                    int count = 0;
                    for (const auto& session : full_results["sessions"]) {
                        // Check for master_id (VoLTE) or fallback to session_id
                        std::string current_master_id = session.value("master_id", "");
                        std::string current_session_id = session.value("session_id", "");

                        // Try matching either Key
                        if (current_master_id == session_id || current_session_id == session_id) {
                            LOG_INFO("Found session " << session_id);
                            res.set_content(session.dump(), "application/json");
                            return;
                        }
                        count++;
                    }

                    // Debug: Dump available IDs
                    int dump_limit = 0;
                    for (const auto& session : full_results["sessions"]) {
                        if (dump_limit++ >= 10)
                            break;
                        LOG_ERROR("Available ID: " << session.value(
                                      "session_id", session.value("master_id", "MISSING")));
                    }

                    LOG_ERROR("Scanned " << count << " sessions in job " << job->job_id
                                         << ", no match found.");
                } else {
                    LOG_ERROR("JSON file for job " << job->job_id << " has no sessions array.");
                }
            }

            // Session not found
            LOG_ERROR("Session " << session_id << " not found in any checked jobs.");
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
                    {"input_filename",
                     job->original_filename.empty()
                         ? std::filesystem::path(job->input_filename).filename().string()
                         : job->original_filename},
                    {"status", jobStatusToString(job->status)},
                    {"progress", job->progress},
                    {"created_at", utils::timestampToIso8601(job->created_at)}};

                if (job->status == JobStatus::COMPLETED) {
                    job_summary["session_count"] = job->session_count;
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

    // GET /api/v1/protocols/supported - Get supported protocols and versions
    server->Get("/api/v1/protocols/supported", [](const httplib::Request&, httplib::Response& res) {
        try {
            auto& config_mgr = ConfigManager::getInstance();
            nlohmann::json response = config_mgr.exportToJson();
            res.set_content(response.dump(), "application/json");
        } catch (const std::exception& e) {
            LOG_ERROR("Get protocols failed: " << e.what());
            nlohmann::json error = {{"error", e.what()}, {"code", "INTERNAL_ERROR"}};
            res.status = 500;
            res.set_content(error.dump(), "application/json");
        }
    });

    // GET /api/v1/sessions/{session_id}/legs - Get all session legs across interfaces
    server->Get("/api/v1/sessions/:session_id/legs", [this](const httplib::Request& req,
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

                if (full_results.contains("sessions") && full_results["sessions"].is_array()) {
                    for (const auto& session : full_results["sessions"]) {
                        std::string id =
                            session.value("master_id", session.value("session_id", ""));
                        if (id == session_id) {
                            nlohmann::json legs_response;
                            legs_response["session_id"] = session_id;
                            legs_response["legs"] = nlohmann::json::array();

                            // Extract messages grouped by interface
                            if (session.contains("messages") && session["messages"].is_array()) {
                                std::map<std::string, nlohmann::json> interface_legs;

                                for (const auto& msg : session["messages"]) {
                                    std::string interface_type = msg.value("interface", "UNKNOWN");

                                    if (interface_legs.find(interface_type) ==
                                        interface_legs.end()) {
                                        interface_legs[interface_type] = {
                                            {"interface_type", interface_type},
                                            {"protocol", msg.value("protocol", "UNKNOWN")},
                                            {"message_count", 0},
                                            {"first_timestamp", msg.value("timestamp", "")},
                                            {"last_timestamp", msg.value("timestamp", "")}};
                                    }

                                    interface_legs[interface_type]["message_count"] =
                                        interface_legs[interface_type]["message_count"].get<int>() +
                                        1;
                                    interface_legs[interface_type]["last_timestamp"] =
                                        msg.value("timestamp", "");
                                }

                                for (const auto& [iface, leg] : interface_legs) {
                                    legs_response["legs"].push_back(leg);
                                }
                            }

                            res.set_content(legs_response.dump(), "application/json");
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
            LOG_ERROR("Get session legs failed: " << e.what());
            nlohmann::json error = {{"error", e.what()}, {"code", "INTERNAL_ERROR"}};
            res.status = 500;
            res.set_content(error.dump(), "application/json");
        }
    });

    // GET /api/v1/sessions/search - Search sessions by correlation identifiers
    server->Get(
        "/api/v1/sessions/search", [this](const httplib::Request& req, httplib::Response& res) {
            try {
                nlohmann::json search_results = nlohmann::json::array();

                // Extract query parameters
                std::string imsi = req.has_param("imsi") ? req.get_param_value("imsi") : "";
                std::string supi = req.has_param("supi") ? req.get_param_value("supi") : "";
                std::string teid_str = req.has_param("teid") ? req.get_param_value("teid") : "";
                std::string time_range =
                    req.has_param("time_range") ? req.get_param_value("time_range") : "";

                // Search through all completed jobs
                auto all_jobs = job_manager_->getAllJobs();
                for (const auto& job : all_jobs) {
                    if (job->status != JobStatus::COMPLETED) {
                        continue;
                    }

                    // Load sessions from output file
                    std::ifstream infile(job->output_filename);
                    if (!infile) {
                        continue;
                    }

                    nlohmann::json full_results;
                    infile >> full_results;

                    if (full_results.contains("sessions") && full_results["sessions"].is_array()) {
                        for (const auto& session : full_results["sessions"]) {
                            bool matches = false;

                            // Match by IMSI
                            if (!imsi.empty()) {
                                // Check both top-level imsi and legacy correlation_keys
                                if (session.value("imsi", "") == imsi) {
                                    matches = true;
                                } else if (session.contains("correlation_keys") &&
                                           session["correlation_keys"].value("imsi", "") == imsi) {
                                    matches = true;
                                }
                            }

                            // Match by SUPI
                            if (!supi.empty() && session.contains("correlation_keys")) {
                                if (session["correlation_keys"].contains("supi") &&
                                    session["correlation_keys"]["supi"] == supi) {
                                    matches = true;
                                }
                            }

                            // Match by TEID
                            if (!teid_str.empty() && session.contains("correlation_keys")) {
                                uint32_t teid = std::stoul(teid_str);
                                if (session["correlation_keys"].contains("teid_s1u") &&
                                    session["correlation_keys"]["teid_s1u"] == teid) {
                                    matches = true;
                                }
                            }

                            if (matches) {
                                nlohmann::json summary = {
                                    {"session_id",
                                     session.value("session_id", session.value("master_id", ""))},
                                    {"job_id", job->job_id},
                                    {"session_type", session.value("session_type", "UNKNOWN")},
                                    {"correlation_keys",
                                     session.value("correlation_keys", nlohmann::json::object())}};
                                search_results.push_back(summary);
                            }
                        }
                    }
                }

                nlohmann::json response = {{"total", search_results.size()},
                                           {"sessions", search_results}};

                res.set_content(response.dump(), "application/json");

            } catch (const std::exception& e) {
                LOG_ERROR("Search sessions failed: " << e.what());
                nlohmann::json error = {{"error", e.what()}, {"code", "INTERNAL_ERROR"}};
                res.status = 500;
                res.set_content(error.dump(), "application/json");
            }
        });

    // GET /api/v1/interfaces - List captured interfaces from PCAPNG file
    server->Get("/api/v1/interfaces", [this](const httplib::Request& req, httplib::Response& res) {
        try {
            std::string job_id = req.has_param("job_id") ? req.get_param_value("job_id") : "";

            if (job_id.empty()) {
                nlohmann::json error = {{"error", "job_id parameter required"},
                                        {"code", "MISSING_PARAMETER"}};
                res.status = 400;
                res.set_content(error.dump(), "application/json");
                return;
            }

            auto job_info = job_manager_->getJobInfo(job_id);
            if (!job_info) {
                nlohmann::json error = {{"error", "Job not found"}, {"code", "JOB_NOT_FOUND"}};
                res.status = 404;
                res.set_content(error.dump(), "application/json");
                return;
            }

            // For now, return a placeholder response
            // In a full implementation, this would parse the PCAPNG file's interface blocks
            nlohmann::json response = {
                {"job_id", job_id},
                {"interfaces",
                 nlohmann::json::array({{{"interface_id", 0},
                                         {"name", "eth0"},
                                         {"description", "Ethernet adapter"},
                                         {"packet_count", job_info->total_packets}}})}};

            res.set_content(response.dump(), "application/json");

        } catch (const std::exception& e) {
            LOG_ERROR("Get interfaces failed: " << e.what());
            nlohmann::json error = {{"error", e.what()}, {"code", "INTERNAL_ERROR"}};
            res.status = 500;
            res.set_content(error.dump(), "application/json");
        }
    });

    // POST /api/v1/jobs/{job_id}/filter - Apply post-capture filter
    server->Post(
        "/api/v1/jobs/:job_id/filter", [this](const httplib::Request& req, httplib::Response& res) {
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
                                            {"code", "JOB_NOT_COMPLETED"}};
                    res.status = 400;
                    res.set_content(error.dump(), "application/json");
                    return;
                }

                // Parse filter criteria from request body
                nlohmann::json filter_request = nlohmann::json::parse(req.body);

                std::string imsi = filter_request.value("imsi", "");
                std::string teid_str = filter_request.value("teid", "");
                std::string ip = filter_request.value("ip", "");
                std::string protocol = filter_request.value("protocol", "");

                // Load sessions from output file
                std::ifstream infile(job_info->output_filename);
                if (!infile) {
                    throw std::runtime_error("Failed to read results file");
                }

                nlohmann::json full_results;
                infile >> full_results;

                // Apply filters
                nlohmann::json filtered_sessions = nlohmann::json::array();

                if (full_results.contains("sessions") && full_results["sessions"].is_array()) {
                    for (const auto& session : full_results["sessions"]) {
                        bool include = true;

                        // Filter by IMSI
                        if (!imsi.empty() && session.contains("correlation_keys")) {
                            if (!session["correlation_keys"].contains("imsi") ||
                                session["correlation_keys"]["imsi"] != imsi) {
                                include = false;
                            }
                        }

                        // Filter by TEID
                        if (!teid_str.empty() && session.contains("correlation_keys")) {
                            uint32_t teid = std::stoul(teid_str);
                            if (!session["correlation_keys"].contains("teid_s1u") ||
                                session["correlation_keys"]["teid_s1u"] != teid) {
                                include = false;
                            }
                        }

                        // Filter by IP
                        if (!ip.empty() && session.contains("correlation_keys")) {
                            if ((!session["correlation_keys"].contains("ue_ipv4") ||
                                 session["correlation_keys"]["ue_ipv4"] != ip) &&
                                (!session["correlation_keys"].contains("ue_ipv6") ||
                                 session["correlation_keys"]["ue_ipv6"] != ip)) {
                                include = false;
                            }
                        }

                        // Filter by protocol
                        if (!protocol.empty() && session.contains("messages")) {
                            bool has_protocol = false;
                            for (const auto& msg : session["messages"]) {
                                if (msg.value("protocol", "") == protocol) {
                                    has_protocol = true;
                                    break;
                                }
                            }
                            if (!has_protocol) {
                                include = false;
                            }
                        }

                        if (include) {
                            filtered_sessions.push_back(session);
                        }
                    }
                }

                nlohmann::json response = {{"job_id", job_id},
                                           {"filter", filter_request},
                                           {"total_sessions", filtered_sessions.size()},
                                           {"sessions", filtered_sessions}};

                res.set_content(response.dump(), "application/json");

            } catch (const std::exception& e) {
                LOG_ERROR("Apply filter failed: " << e.what());
                nlohmann::json error = {{"error", e.what()}, {"code", "INTERNAL_ERROR"}};
                res.status = 500;
                res.set_content(error.dump(), "application/json");
            }
        });

    // GET /api/v1/statistics/protocols - Get protocol distribution statistics
    server->Get("/api/v1/statistics/protocols", [this](const httplib::Request& req,
                                                       httplib::Response& res) {
        try {
            std::string job_id = req.has_param("job_id") ? req.get_param_value("job_id") : "";

            if (job_id.empty()) {
                nlohmann::json error = {{"error", "job_id parameter required"},
                                        {"code", "MISSING_PARAMETER"}};
                res.status = 400;
                res.set_content(error.dump(), "application/json");
                return;
            }

            auto job_info = job_manager_->getJobInfo(job_id);
            if (!job_info) {
                nlohmann::json error = {{"error", "Job not found"}, {"code", "JOB_NOT_FOUND"}};
                res.status = 404;
                res.set_content(error.dump(), "application/json");
                return;
            }

            if (job_info->status != JobStatus::COMPLETED) {
                nlohmann::json error = {{"error", "Job not completed yet"},
                                        {"code", "JOB_NOT_COMPLETED"}};
                res.status = 400;
                res.set_content(error.dump(), "application/json");
                return;
            }

            // Load sessions from output file
            std::ifstream infile(job_info->output_filename);
            if (!infile) {
                throw std::runtime_error("Failed to read results file");
            }

            nlohmann::json full_results;
            infile >> full_results;

            // Calculate protocol statistics
            std::map<std::string, int> protocol_counts;
            int total_messages = 0;

            if (full_results.contains("sessions") && full_results["sessions"].is_array()) {
                for (const auto& session : full_results["sessions"]) {
                    if (session.contains("messages") && session["messages"].is_array()) {
                        for (const auto& msg : session["messages"]) {
                            std::string protocol = msg.value("protocol", "UNKNOWN");
                            protocol_counts[protocol]++;
                            total_messages++;
                        }
                    }
                }
            }

            // Build response with percentages
            nlohmann::json protocol_stats = nlohmann::json::array();
            for (const auto& [protocol, count] : protocol_counts) {
                double percentage = total_messages > 0 ? (count * 100.0 / total_messages) : 0.0;
                protocol_stats.push_back(
                    {{"protocol", protocol}, {"count", count}, {"percentage", percentage}});
            }

            nlohmann::json response = {{"job_id", job_id},
                                       {"total_messages", total_messages},
                                       {"protocols", protocol_stats}};

            res.set_content(response.dump(), "application/json");

        } catch (const std::exception& e) {
            LOG_ERROR("Get protocol statistics failed: " << e.what());
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
