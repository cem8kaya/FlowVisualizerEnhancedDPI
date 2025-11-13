#pragma once

#include "common/types.h"
#include <string>

namespace callflow {

/**
 * HTTP server (placeholder for M2)
 */
class HttpServer {
public:
    HttpServer(const std::string& bind_addr, uint16_t port);
    ~HttpServer();

    bool start();
    void stop();

private:
    std::string bind_addr_;
    uint16_t port_;
};

}  // namespace callflow
