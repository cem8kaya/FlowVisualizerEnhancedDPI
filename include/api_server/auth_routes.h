#pragma once

#include <httplib.h>
#include <memory>

namespace callflow {

// Forward declarations
class AuthManager;
class AuthMiddleware;

/**
 * Setup authentication routes on HTTP server
 * @param server HTTP server instance
 * @param auth_manager Authentication manager
 * @param auth_middleware Authentication middleware
 */
void setupAuthRoutes(
    httplib::Server& server,
    AuthManager* auth_manager,
    AuthMiddleware* auth_middleware
);

}  // namespace callflow
