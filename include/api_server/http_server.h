#pragma once

#include "common/types.h"
#include "api_server/job_manager.h"
#include "api_server/websocket_handler.h"
#include <string>
#include <memory>
#include <thread>
#include <atomic>

namespace callflow {

/**
 * HTTP server with REST API and WebSocket support
 */
class HttpServer {
public:
    HttpServer(const Config& config, std::shared_ptr<JobManager> job_manager,
               std::shared_ptr<WebSocketHandler> ws_handler);
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

    void* server_impl_;  // Opaque pointer to httplib::Server
    std::thread server_thread_;
    std::atomic<bool> running_;
};

}  // namespace callflow
