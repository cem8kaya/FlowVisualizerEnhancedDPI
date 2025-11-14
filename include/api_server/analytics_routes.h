#pragma once

#include <httplib.h>
#include <memory>

namespace callflow {

// Forward declarations
class AnalyticsManager;
class AuthMiddleware;

/**
 * Setup analytics routes on HTTP server
 * @param server HTTP server instance
 * @param analytics_manager Analytics manager
 * @param auth_middleware Authentication middleware
 */
void setupAnalyticsRoutes(
    httplib::Server& server,
    AnalyticsManager* analytics_manager,
    AuthMiddleware* auth_middleware
);

}  // namespace callflow
