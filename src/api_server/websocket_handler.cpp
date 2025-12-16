#include "api_server/websocket_handler.h"

#include <chrono>

#include "common/logger.h"
#include "common/utils.h"

namespace callflow {

WebSocketHandler::WebSocketHandler(const Config& config)
    : config_(config), next_conn_id_(0), running_(false) {}

WebSocketHandler::~WebSocketHandler() {
    stop();
}

bool WebSocketHandler::start() {
    if (running_.load()) {
        LOG_WARN("WebSocket handler already running");
        return false;
    }

    LOG_INFO("Starting WebSocket handler");
    running_.store(true);

    // Start heartbeat thread
    heartbeat_thread_ = std::thread(&WebSocketHandler::heartbeatThread, this);

    LOG_INFO("WebSocket handler started");
    return true;
}

void WebSocketHandler::stop() {
    if (!running_.load()) {
        return;
    }

    LOG_INFO("Stopping WebSocket handler...");
    running_.store(false);

    if (heartbeat_thread_.joinable()) {
        heartbeat_thread_.join();
    }

    LOG_INFO("WebSocket handler stopped");
}

void WebSocketHandler::broadcastEvent(const JobId& job_id, const std::string& event_type,
                                      const nlohmann::json& data) {
    if (!running_.load()) {
        return;
    }

    // Create event
    WebSocketEvent event;
    event.type = event_type;
    event.timestamp = utils::now();
    event.data = data;

    // Add timestamp to data
    nlohmann::json enriched_data = data;
    enriched_data["timestamp"] = utils::timestampToIso8601(event.timestamp);

    // Store in event queue (with max size limit)
    {
        std::lock_guard<std::mutex> lock(queues_mutex_);
        auto& queue = event_queues_[job_id];
        queue.push_back(event);

        // Limit queue size
        while (queue.size() > config_.ws_event_queue_max) {
            queue.pop_front();
        }
    }

    LOG_DEBUG("Broadcasted event for job " << job_id << ": " << event_type);

    // Note: In a full implementation, this would actually send the message to
    // connected WebSocket clients. cpp-httplib doesn't have full WebSocket
    // server support, so we're using a simplified in-memory event queue.
    // For production, consider using uWebSockets or another full WebSocket library.
}

size_t WebSocketHandler::getConnectionCount(const JobId& job_id) {
    std::lock_guard<std::mutex> lock(connections_mutex_);
    size_t count = 0;
    for (const auto& [conn_id, conn] : connections_) {
        if (conn.job_id == job_id) {
            ++count;
        }
    }
    return count;
}

void WebSocketHandler::addConnection(int conn_id, const JobId& job_id) {
    std::lock_guard<std::mutex> lock(connections_mutex_);
    WebSocketConnection conn;
    conn.connection_id = conn_id;
    conn.job_id = job_id;
    conn.last_heartbeat = utils::now();
    connections_[conn_id] = conn;

    LOG_INFO("WebSocket connection added: " << conn_id << " for job " << job_id);
}

void WebSocketHandler::removeConnection(int conn_id) {
    std::lock_guard<std::mutex> lock(connections_mutex_);
    auto it = connections_.find(conn_id);
    if (it != connections_.end()) {
        LOG_INFO("WebSocket connection removed: " << conn_id);
        connections_.erase(it);
    }
}

void WebSocketHandler::cleanupStaleConnections() {
    auto now = utils::now();
    auto timeout = std::chrono::seconds(config_.ws_heartbeat_interval_sec * 3);

    std::lock_guard<std::mutex> lock(connections_mutex_);
    for (auto it = connections_.begin(); it != connections_.end();) {
        auto age = now - it->second.last_heartbeat;
        if (age > timeout) {
            LOG_INFO("Removing stale WebSocket connection: " << it->first);
            it = connections_.erase(it);
        } else {
            ++it;
        }
    }
}

void WebSocketHandler::heartbeatThread() {
    LOG_DEBUG("WebSocket heartbeat thread started");

    while (running_.load()) {
        // Sleep for heartbeat interval
        std::this_thread::sleep_for(std::chrono::seconds(config_.ws_heartbeat_interval_sec));

        if (!running_.load()) {
            break;
        }

        // Cleanup stale connections
        cleanupStaleConnections();

        // Send heartbeat to all connections (in a full implementation)
        // For now, just log active connection count
        {
            std::lock_guard<std::mutex> lock(connections_mutex_);
            if (!connections_.empty()) {
                LOG_DEBUG("Active WebSocket connections: " << connections_.size());
            }
        }
    }

    LOG_DEBUG("WebSocket heartbeat thread stopped");
}

}  // namespace callflow
