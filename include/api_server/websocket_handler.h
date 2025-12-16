#pragma once

#include <atomic>
#include <deque>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <set>
#include <string>
#include <thread>
#include <unordered_map>

#include "common/types.h"

namespace callflow {

/**
 * WebSocket connection info
 */
struct WebSocketConnection {
    int connection_id;
    JobId job_id;
    std::chrono::system_clock::time_point last_heartbeat;
};

/**
 * WebSocket event
 */
struct WebSocketEvent {
    std::string type;
    Timestamp timestamp;
    nlohmann::json data;
};

/**
 * WebSocket handler for real-time event streaming
 */
class WebSocketHandler {
public:
    explicit WebSocketHandler(const Config& config);
    ~WebSocketHandler();

    /**
     * Start the WebSocket handler
     */
    bool start();

    /**
     * Stop the WebSocket handler
     */
    void stop();

    /**
     * Send event to all connections for a job
     * @param job_id Job ID
     * @param event_type Event type (event|progress|status)
     * @param data Event data
     */
    void broadcastEvent(const JobId& job_id, const std::string& event_type,
                        const nlohmann::json& data);

    /**
     * Get connection count for a job
     */
    size_t getConnectionCount(const JobId& job_id);

private:
    /**
     * Heartbeat thread function
     */
    void heartbeatThread();

    /**
     * Add connection
     */
    void addConnection(int conn_id, const JobId& job_id);

    /**
     * Remove connection
     */
    void removeConnection(int conn_id);

    /**
     * Cleanup stale connections
     */
    void cleanupStaleConnections();

    Config config_;

    // Event queues per job
    std::unordered_map<JobId, std::deque<WebSocketEvent>> event_queues_;
    std::mutex queues_mutex_;

    // Active connections
    std::unordered_map<int, WebSocketConnection> connections_;
    std::mutex connections_mutex_;

    // Connection ID counter
    std::atomic<int> next_conn_id_;

    // Heartbeat thread
    std::thread heartbeat_thread_;
    std::atomic<bool> running_;

    friend class HttpServer;
};

}  // namespace callflow
