#pragma once

#include "api_server/auth_manager.h"
#include <httplib.h>
#include <string>
#include <optional>
#include <functional>

namespace callflow {

/**
 * AuthMiddleware - Middleware for HTTP request authentication and authorization
 */
class AuthMiddleware {
public:
    /**
     * Constructor
     * @param auth_manager Pointer to AuthManager
     */
    explicit AuthMiddleware(AuthManager* auth_manager);

    /**
     * Destructor
     */
    ~AuthMiddleware();

    /**
     * Require authentication for request
     * Sets 401 response if authentication fails
     * @param req HTTP request
     * @param res HTTP response
     * @return true if authenticated, false otherwise
     */
    bool requireAuth(const httplib::Request& req, httplib::Response& res);

    /**
     * Require specific role for request
     * Sets 403 response if user doesn't have required role
     * @param req HTTP request
     * @param res HTTP response
     * @param role Required role name
     * @return true if user has role, false otherwise
     */
    bool requireRole(
        const httplib::Request& req,
        httplib::Response& res,
        const std::string& role
    );

    /**
     * Require specific permission for request
     * Sets 403 response if user doesn't have required permission
     * @param req HTTP request
     * @param res HTTP response
     * @param resource Resource name
     * @param action Action name
     * @return true if user has permission, false otherwise
     */
    bool requirePermission(
        const httplib::Request& req,
        httplib::Response& res,
        const std::string& resource,
        const std::string& action
    );

    /**
     * Get authenticated user from request
     * Extracts and validates token, returns user if valid
     * @param req HTTP request
     * @return User object or nullopt if not authenticated
     */
    std::optional<User> getRequestUser(const httplib::Request& req);

    /**
     * Extract token from request headers
     * Supports both "Authorization: Bearer <token>" and "X-API-Key: <key>"
     * @param req HTTP request
     * @return Token string or nullopt if not found
     */
    std::optional<std::string> extractToken(const httplib::Request& req);

    /**
     * Set user in request context (for access in handlers)
     * @param req HTTP request
     * @param user User object
     */
    void setRequestUser(httplib::Request& req, const User& user);

    /**
     * Create HTTP middleware handler function
     * Returns a httplib handler that can be used with server.set_pre_routing_handler
     * @return Middleware handler function
     */
    httplib::Server::Handler createPreRoutingHandler();

private:
    AuthManager* auth_manager_;

    /**
     * Send JSON error response
     * @param res HTTP response
     * @param status HTTP status code
     * @param message Error message
     */
    void sendError(httplib::Response& res, int status, const std::string& message);
};

}  // namespace callflow
