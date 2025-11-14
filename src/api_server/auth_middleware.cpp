#include "api_server/auth_middleware.h"
#include "common/logger.h"
#include <nlohmann/json.hpp>

namespace callflow {

// Key for storing user in request context
static const char* REQUEST_USER_KEY = "_auth_user";

// ============================================================================
// Constructor / Destructor
// ============================================================================

AuthMiddleware::AuthMiddleware(AuthManager* auth_manager)
    : auth_manager_(auth_manager) {
    if (!auth_manager_) {
        throw std::runtime_error("AuthManager cannot be null");
    }
}

AuthMiddleware::~AuthMiddleware() = default;

// ============================================================================
// Authentication / Authorization
// ============================================================================

bool AuthMiddleware::requireAuth(const httplib::Request& req, httplib::Response& res) {
    auto user = getRequestUser(req);
    if (!user) {
        sendError(res, 401, "Authentication required");
        return false;
    }

    return true;
}

bool AuthMiddleware::requireRole(
    const httplib::Request& req,
    httplib::Response& res,
    const std::string& role
) {
    auto user = getRequestUser(req);
    if (!user) {
        sendError(res, 401, "Authentication required");
        return false;
    }

    if (!auth_manager_->hasRole(user->user_id, role)) {
        LOG_WARN("User {} lacks required role: {}", user->username, role);
        sendError(res, 403, "Insufficient permissions");
        return false;
    }

    return true;
}

bool AuthMiddleware::requirePermission(
    const httplib::Request& req,
    httplib::Response& res,
    const std::string& resource,
    const std::string& action
) {
    auto user = getRequestUser(req);
    if (!user) {
        sendError(res, 401, "Authentication required");
        return false;
    }

    if (!auth_manager_->hasPermission(user->user_id, resource, action)) {
        LOG_WARN("User {} lacks permission: {} on {}",
                 user->username, action, resource);
        sendError(res, 403, "Insufficient permissions");
        return false;
    }

    return true;
}

std::optional<User> AuthMiddleware::getRequestUser(const httplib::Request& req) {
    // Check if user is already set in context (cached)
    if (req.has_param(REQUEST_USER_KEY)) {
        // User was already authenticated and stored in context
        // Note: This is a simplified approach. In production, you might
        // want to use a more robust context storage mechanism.
    }

    // Extract token from headers
    auto token = extractToken(req);
    if (!token) {
        return std::nullopt;
    }

    // Validate token
    std::optional<User> user;

    // Check if it's an API key (starts with "cfv_")
    if (token->starts_with("cfv_")) {
        user = auth_manager_->validateApiKey(*token);
        if (user) {
            LOG_DEBUG("Authenticated via API key: {}", user->username);
        }
    } else {
        // It's a JWT token
        user = auth_manager_->validateToken(*token);
        if (user) {
            LOG_DEBUG("Authenticated via JWT: {}", user->username);
        }
    }

    return user;
}

std::optional<std::string> AuthMiddleware::extractToken(const httplib::Request& req) {
    // Try Authorization header with Bearer token
    if (req.has_header("Authorization")) {
        std::string auth = req.get_header_value("Authorization");

        // Handle "Bearer <token>" format
        if (auth.starts_with("Bearer ") && auth.length() > 7) {
            return auth.substr(7);
        }

        // Handle "Basic <token>" (for API keys encoded in Basic auth)
        if (auth.starts_with("Basic ") && auth.length() > 6) {
            // In a full implementation, you would decode the Base64
            // For now, we'll skip Basic auth support
        }
    }

    // Try X-API-Key header
    if (req.has_header("X-API-Key")) {
        std::string api_key = req.get_header_value("X-API-Key");
        if (!api_key.empty()) {
            return api_key;
        }
    }

    // Try query parameter (not recommended for production, but useful for testing)
    if (req.has_param("token")) {
        return req.get_param_value("token");
    }

    if (req.has_param("api_key")) {
        return req.get_param_value("api_key");
    }

    return std::nullopt;
}

void AuthMiddleware::setRequestUser(httplib::Request& req, const User& user) {
    // Store user ID in request parameters
    // Note: This is a simplified approach. cpp-httplib doesn't have built-in
    // context storage, so we use params (which is not ideal but works).
    // In production, you might want to extend httplib or use a different approach.
    req.set_header(REQUEST_USER_KEY, user.user_id);
}

httplib::Server::Handler AuthMiddleware::createPreRoutingHandler() {
    return [this](const httplib::Request& req, httplib::Response& res) {
        // This is a pre-routing handler that runs before route matching
        // For authentication, we typically want to handle it per-route
        // So we return true (continue processing)

        // However, we can do some basic checks here
        // For example, check if the path requires authentication

        // Skip authentication for public endpoints
        std::string path = req.path;

        // Public endpoints that don't require authentication
        if (path == "/api/v1/auth/login" ||
            path == "/api/v1/auth/register" ||
            path == "/api/v1/auth/forgot-password" ||
            path == "/api/v1/auth/reset-password" ||
            path == "/metrics" ||  // Prometheus endpoint
            path == "/" ||
            path.starts_with("/static/") ||
            path.starts_with("/ui/")) {
            return httplib::Server::HandlerResponse::Unhandled;
        }

        // For all other endpoints, try to authenticate
        // But don't block the request - let individual handlers decide
        auto user = getRequestUser(req);
        if (user) {
            // User is authenticated, log it
            LOG_DEBUG("Authenticated request: {} {} (user: {})",
                     req.method, path, user->username);
        }

        // Continue processing
        return httplib::Server::HandlerResponse::Unhandled;
    };
}

// ============================================================================
// Private Helper Methods
// ============================================================================

void AuthMiddleware::sendError(httplib::Response& res, int status, const std::string& message) {
    nlohmann::json error_json = {
        {"error", message},
        {"status", status}
    };

    res.status = status;
    res.set_content(error_json.dump(), "application/json");
    res.set_header("WWW-Authenticate", "Bearer realm=\"callflowd\"");
}

}  // namespace callflow
