#pragma once

#include <atomic>
#include <memory>
#include <string>
#include <thread>

#include "api_server/analytics_service.h"
#include "api_server/job_manager.h"
#include "api_server/websocket_handler.h"
#include "common/types.h"

namespace callflow {

class DatabaseManager;

/**
 * HTTP server with REST API and WebSocket support
 */
class HttpServer {
public:
    HttpServer(const Config& config, std::shared_ptr<JobManager> job_manager,
               std::shared_ptr<WebSocketHandler> ws_handler,
               std::shared_ptr<DatabaseManager> db_manager = nullptr);
    ~HttpServer();

    /**
     * Start the HTTP server
     */
    bool start();

    /**
     * Stop the HTTP server
     */
    void stop();

    /**
     * Check if server is running
     */
    bool isRunning() const { return running_.load(); }

private:
    /**
     * Setup REST API routes
     */
    void setupRoutes();

    /**
     * Server thread function
     */
    void serverThread();

    Config config_;
    std::shared_ptr<JobManager> job_manager_;
    std::shared_ptr<WebSocketHandler> ws_handler_;
    std::shared_ptr<AnalyticsService> analytics_service_;

    void* server_impl_;  // Opaque pointer to httplib::Server
    std::thread server_thread_;
    std::atomic<bool> running_;
};

}  // namespace callflow
