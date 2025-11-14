#include "api_server/analytics_routes.h"
#include "api_server/analytics_manager.h"
#include "api_server/auth_middleware.h"
#include "common/logger.h"
#include <nlohmann/json.hpp>

namespace callflow {

using json = nlohmann::json;

// Helper function to send JSON response
static void sendJson(httplib::Response& res, int status, const json& data) {
    res.status = status;
    res.set_content(data.dump(), "application/json");
}

// Helper function to send error response
static void sendError(httplib::Response& res, int status, const std::string& message) {
    json error = {
        {"error", message},
        {"status", status}
    };
    sendJson(res, status, error);
}

void setupAnalyticsRoutes(
    httplib::Server& server,
    AnalyticsManager* analytics_manager,
    AuthMiddleware* auth_middleware
) {
    // ========================================================================
    // GET /api/v1/analytics/summary - Get overall summary statistics
    // ========================================================================
    server.Get("/api/v1/analytics/summary", [analytics_manager, auth_middleware](
        const httplib::Request& req, httplib::Response& res) {

        // Require authentication
        if (!auth_middleware->requireAuth(req, res)) {
            return;
        }

        try {
            // Parse optional date filters
            std::optional<int64_t> start_date;
            std::optional<int64_t> end_date;

            if (req.has_param("start_date")) {
                start_date = std::stoll(req.get_param_value("start_date"));
            }

            if (req.has_param("end_date")) {
                end_date = std::stoll(req.get_param_value("end_date"));
            }

            // Get summary
            auto summary = analytics_manager->getSummary(start_date, end_date);

            // Build protocol distribution JSON
            json proto_dist = json::object();
            for (const auto& [protocol, percentage] : summary.protocol_distribution) {
                proto_dist[protocol] = percentage;
            }

            json response = {
                {"total_jobs", summary.total_jobs},
                {"completed_jobs", summary.completed_jobs},
                {"failed_jobs", summary.failed_jobs},
                {"active_jobs", summary.active_jobs},
                {"total_sessions", summary.total_sessions},
                {"total_packets", summary.total_packets},
                {"total_bytes", summary.total_bytes},
                {"avg_session_duration_ms", summary.avg_session_duration_ms},
                {"avg_packets_per_session", summary.avg_packets_per_session},
                {"protocol_distribution", proto_dist}
            };

            sendJson(res, 200, response);

        } catch (const std::exception& e) {
            LOG_ERROR("Error getting analytics summary: {}", e.what());
            sendError(res, 500, "Internal server error");
        }
    });

    // ========================================================================
    // GET /api/v1/analytics/protocols - Get protocol statistics
    // ========================================================================
    server.Get("/api/v1/analytics/protocols", [analytics_manager, auth_middleware](
        const httplib::Request& req, httplib::Response& res) {

        // Require authentication
        if (!auth_middleware->requireAuth(req, res)) {
            return;
        }

        try {
            // Parse optional job_id filter
            std::optional<std::string> job_id;
            if (req.has_param("job_id")) {
                job_id = req.get_param_value("job_id");
            }

            // Get protocol stats
            auto stats = analytics_manager->getProtocolStats(job_id);

            // Build JSON array
            json stats_json = json::array();
            for (const auto& s : stats) {
                stats_json.push_back({
                    {"protocol", s.protocol},
                    {"session_count", s.session_count},
                    {"packet_count", s.packet_count},
                    {"byte_count", s.byte_count},
                    {"percentage", s.percentage}
                });
            }

            json response = {
                {"protocols", stats_json}
            };

            sendJson(res, 200, response);

        } catch (const std::exception& e) {
            LOG_ERROR("Error getting protocol stats: {}", e.what());
            sendError(res, 500, "Internal server error");
        }
    });

    // ========================================================================
    // GET /api/v1/analytics/top-talkers - Get top talkers
    // ========================================================================
    server.Get("/api/v1/analytics/top-talkers", [analytics_manager, auth_middleware](
        const httplib::Request& req, httplib::Response& res) {

        // Require authentication
        if (!auth_middleware->requireAuth(req, res)) {
            return;
        }

        try {
            // Parse parameters
            int limit = 10;
            if (req.has_param("limit")) {
                limit = std::stoi(req.get_param_value("limit"));
            }

            std::optional<std::string> job_id;
            if (req.has_param("job_id")) {
                job_id = req.get_param_value("job_id");
            }

            // Get top talkers
            auto talkers = analytics_manager->getTopTalkers(limit, job_id);

            // Build JSON array
            json talkers_json = json::array();
            for (const auto& t : talkers) {
                talkers_json.push_back({
                    {"ip_address", t.ip_address},
                    {"packet_count", t.packet_count},
                    {"byte_count", t.byte_count},
                    {"session_count", t.session_count}
                });
            }

            json response = {
                {"top_talkers", talkers_json},
                {"limit", limit}
            };

            sendJson(res, 200, response);

        } catch (const std::exception& e) {
            LOG_ERROR("Error getting top talkers: {}", e.what());
            sendError(res, 500, "Internal server error");
        }
    });

    // ========================================================================
    // GET /api/v1/analytics/performance - Get performance metrics
    // ========================================================================
    server.Get("/api/v1/analytics/performance", [analytics_manager, auth_middleware](
        const httplib::Request& req, httplib::Response& res) {

        // Require authentication
        if (!auth_middleware->requireAuth(req, res)) {
            return;
        }

        try {
            // Get performance metrics
            auto metrics = analytics_manager->getPerformanceMetrics();

            json response = {
                {"avg_parsing_throughput_mbps", metrics.avg_parsing_throughput_mbps},
                {"avg_job_completion_time_sec", metrics.avg_job_completion_time_sec},
                {"cache_hit_rate", metrics.cache_hit_rate},
                {"memory_usage_mb", metrics.memory_usage_mb},
                {"active_jobs", metrics.active_jobs},
                {"queued_jobs", metrics.queued_jobs},
                {"total_api_requests", metrics.total_api_requests},
                {"avg_api_response_time_ms", metrics.avg_api_response_time_ms}
            };

            sendJson(res, 200, response);

        } catch (const std::exception& e) {
            LOG_ERROR("Error getting performance metrics: {}", e.what());
            sendError(res, 500, "Internal server error");
        }
    });

    // ========================================================================
    // GET /api/v1/analytics/timeseries - Get time series data
    // ========================================================================
    server.Get("/api/v1/analytics/timeseries", [analytics_manager, auth_middleware](
        const httplib::Request& req, httplib::Response& res) {

        // Require authentication
        if (!auth_middleware->requireAuth(req, res)) {
            return;
        }

        try {
            // Parse parameters
            if (!req.has_param("start") || !req.has_param("end")) {
                sendError(res, 400, "Missing required parameters: start, end");
                return;
            }

            int64_t start = std::stoll(req.get_param_value("start"));
            int64_t end = std::stoll(req.get_param_value("end"));
            std::string interval = req.get_param_value("interval", "1h");
            std::string metric = req.get_param_value("metric", "jobs");

            // Get time series data
            std::vector<TimeSeriesPoint> points;
            if (metric == "jobs") {
                points = analytics_manager->getJobsOverTime(start, end, interval);
            } else if (metric == "sessions") {
                points = analytics_manager->getSessionsOverTime(start, end, interval);
            } else {
                sendError(res, 400, "Invalid metric. Use 'jobs' or 'sessions'");
                return;
            }

            // Build JSON array
            json points_json = json::array();
            for (const auto& p : points) {
                points_json.push_back({
                    {"timestamp", p.timestamp},
                    {"value", p.value}
                });
            }

            json response = {
                {"metric", metric},
                {"interval", interval},
                {"data", points_json}
            };

            sendJson(res, 200, response);

        } catch (const std::exception& e) {
            LOG_ERROR("Error getting time series: {}", e.what());
            sendError(res, 500, "Internal server error");
        }
    });

    // ========================================================================
    // POST /api/v1/analytics/cache/clear - Clear analytics cache (admin only)
    // ========================================================================
    server.Post("/api/v1/analytics/cache/clear", [analytics_manager, auth_middleware](
        const httplib::Request& req, httplib::Response& res) {

        // Require admin role
        if (!auth_middleware->requireRole(req, res, "admin")) {
            return;
        }

        analytics_manager->clearCache();

        json response = {
            {"message", "Analytics cache cleared successfully"}
        };

        sendJson(res, 200, response);
    });

    // ========================================================================
    // GET /metrics - Prometheus metrics endpoint (public, no auth)
    // ========================================================================
    server.Get("/metrics", [analytics_manager](const httplib::Request& req, httplib::Response& res) {
        try {
            // Export Prometheus metrics
            std::string metrics = analytics_manager->exportPrometheusMetrics();

            res.status = 200;
            res.set_content(metrics, "text/plain; version=0.0.4");

        } catch (const std::exception& e) {
            LOG_ERROR("Error exporting Prometheus metrics: {}", e.what());
            res.status = 500;
            res.set_content("# Error exporting metrics\n", "text/plain");
        }
    });

    LOG_INFO("Analytics routes configured");
}

}  // namespace callflow
