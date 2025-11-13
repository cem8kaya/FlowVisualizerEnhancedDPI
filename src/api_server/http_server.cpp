#include "api_server/http_server.h"
#include "common/logger.h"

namespace callflow {

HttpServer::HttpServer(const std::string& bind_addr, uint16_t port)
    : bind_addr_(bind_addr), port_(port) {}

HttpServer::~HttpServer() {
    stop();
}

bool HttpServer::start() {
    LOG_INFO("HTTP server placeholder (will be implemented in M2)");
    return false;
}

void HttpServer::stop() {
    LOG_INFO("HTTP server stopped");
}

}  // namespace callflow
