#include "api_server/auth_routes.h"

#include <nlohmann/json.hpp>

#include "api_server/auth_manager.h"
#include "api_server/auth_middleware.h"
#include "common/logger.h"

namespace callflow {

using json = nlohmann::json;

// Helper function to send JSON response
static void sendJson(httplib::Response& res, int status, const json& data) {
    res.status = status;
    res.set_content(data.dump(), "application/json");
}

// Helper function to send error response
static void sendError(httplib::Response& res, int status, const std::string& message) {
    json error = {{"error", message}, {"status", status}};
    sendJson(res, status, error);
}

// Helper function to serialize user to JSON
static json userToJson(const User& user) {
    return {{"user_id", user.user_id},
            {"username", user.username},
            {"email", user.email},
            {"roles", user.roles},
            {"is_active", user.is_active},
            {"created_at",
             std::chrono::duration_cast<std::chrono::seconds>(user.created_at.time_since_epoch())
                 .count()}};
}

void setupAuthRoutes(httplib::Server& server, AuthManager* auth_manager,
                     AuthMiddleware* auth_middleware) {
    // ========================================================================
    // POST /api/v1/auth/register - Register new user
    // ========================================================================
    server.Post("/api/v1/auth/register", [auth_manager](const httplib::Request& req,
                                                        httplib::Response& res) {
        try {
            json body = json::parse(req.body);

            // Validate required fields
            if (!body.contains("username") || !body.contains("password")) {
                sendError(res, 400, "Missing required fields: username, password");
                return;
            }

            std::string username = body["username"];
            std::string password = body["password"];
            std::string email = body.value("email", "");

            // Create user
            auto user = auth_manager->createUser(username, password, email);
            if (!user) {
                sendError(res, 400, "Failed to create user (username may already exist)");
                return;
            }

            LOG_INFO("User registered: {}", username);

            json response = {{"message", "User created successfully"}, {"user", userToJson(*user)}};

            sendJson(res, 201, response);

        } catch (const json::exception& e) {
            sendError(res, 400, "Invalid JSON: " + std::string(e.what()));
        } catch (const std::exception& e) {
            LOG_ERROR("Registration error: {}", e.what());
            sendError(res, 500, "Internal server error");
        }
    });

    // ========================================================================
    // POST /api/v1/auth/login - Login user
    // ========================================================================
    server.Post("/api/v1/auth/login",
                [auth_manager](const httplib::Request& req, httplib::Response& res) {
                    try {
                        json body = json::parse(req.body);

                        // Validate required fields
                        if (!body.contains("username") || !body.contains("password")) {
                            sendError(res, 400, "Missing required fields: username, password");
                            return;
                        }

                        std::string username = body["username"];
                        std::string password = body["password"];

                        // Authenticate user
                        auto token = auth_manager->login(username, password);
                        if (!token) {
                            sendError(res, 401, "Invalid username or password");
                            return;
                        }

                        LOG_INFO("User logged in: {}", username);

                        json response = {{"token", token->token},
                                         {"refresh_token", token->refresh_token},
                                         {"expires_in", token->expires_in},
                                         {"user", userToJson(token->user)}};

                        sendJson(res, 200, response);

                    } catch (const json::exception& e) {
                        sendError(res, 400, "Invalid JSON: " + std::string(e.what()));
                    } catch (const std::exception& e) {
                        LOG_ERROR("Login error: {}", e.what());
                        sendError(res, 500, "Internal server error");
                    }
                });

    // ========================================================================
    // POST /api/v1/auth/refresh - Refresh access token
    // ========================================================================
    server.Post("/api/v1/auth/refresh",
                [auth_manager](const httplib::Request& req, httplib::Response& res) {
                    try {
                        json body = json::parse(req.body);

                        // Validate required fields
                        if (!body.contains("refresh_token")) {
                            sendError(res, 400, "Missing required field: refresh_token");
                            return;
                        }

                        std::string refresh_token = body["refresh_token"];

                        // Refresh token
                        auto token = auth_manager->refreshToken(refresh_token);
                        if (!token) {
                            sendError(res, 401, "Invalid or expired refresh token");
                            return;
                        }

                        json response = {{"token", token->token},
                                         {"refresh_token", token->refresh_token},
                                         {"expires_in", token->expires_in},
                                         {"user", userToJson(token->user)}};

                        sendJson(res, 200, response);

                    } catch (const json::exception& e) {
                        sendError(res, 400, "Invalid JSON: " + std::string(e.what()));
                    } catch (const std::exception& e) {
                        LOG_ERROR("Token refresh error: {}", e.what());
                        sendError(res, 500, "Internal server error");
                    }
                });

    // ========================================================================
    // POST /api/v1/auth/logout - Logout user (blacklist token)
    // ========================================================================
    server.Post("/api/v1/auth/logout", [auth_manager, auth_middleware](const httplib::Request& req,
                                                                       httplib::Response& res) {
        // Require authentication
        if (!auth_middleware->requireAuth(req, res)) {
            return;
        }

        // Extract token
        auto token = auth_middleware->extractToken(req);
        if (!token) {
            sendError(res, 400, "No token provided");
            return;
        }

        // Blacklist token
        if (auth_manager->logout(*token)) {
            json response = {{"message", "Logged out successfully"}};
            sendJson(res, 200, response);
        } else {
            sendError(res, 500, "Failed to logout");
        }
    });

    // ========================================================================
    // GET /api/v1/auth/me - Get current user info
    // ========================================================================
    server.Get("/api/v1/auth/me",
               [auth_middleware](const httplib::Request& req, httplib::Response& res) {
                   // Require authentication
                   auto user = auth_middleware->getRequestUser(req);
                   if (!user) {
                       sendError(res, 401, "Authentication required");
                       return;
                   }

                   json response = {{"user", userToJson(*user)}};

                   sendJson(res, 200, response);
               });

    // ========================================================================
    // POST /api/v1/auth/change-password - Change password
    // ========================================================================
    server.Post(
        "/api/v1/auth/change-password",
        [auth_manager, auth_middleware](const httplib::Request& req, httplib::Response& res) {
            // Require authentication
            auto user = auth_middleware->getRequestUser(req);
            if (!user) {
                sendError(res, 401, "Authentication required");
                return;
            }

            try {
                json body = json::parse(req.body);

                // Validate required fields
                if (!body.contains("old_password") || !body.contains("new_password")) {
                    sendError(res, 400, "Missing required fields: old_password, new_password");
                    return;
                }

                std::string old_password = body["old_password"];
                std::string new_password = body["new_password"];

                // Change password
                if (auth_manager->changePassword(user->user_id, old_password, new_password)) {
                    json response = {{"message", "Password changed successfully"}};
                    sendJson(res, 200, response);
                } else {
                    sendError(res, 400, "Failed to change password (check old password)");
                }

            } catch (const json::exception& e) {
                sendError(res, 400, "Invalid JSON: " + std::string(e.what()));
            }
        });

    // ========================================================================
    // POST /api/v1/auth/forgot-password - Create password reset token
    // ========================================================================
    server.Post("/api/v1/auth/forgot-password", [auth_manager](const httplib::Request& req,
                                                               httplib::Response& res) {
        try {
            json body = json::parse(req.body);

            // Validate required fields
            if (!body.contains("email")) {
                sendError(res, 400, "Missing required field: email");
                return;
            }

            std::string email = body["email"];

            // Create reset token
            std::string token = auth_manager->createPasswordResetToken(email);
            if (token.empty()) {
                // Don't reveal if email exists or not (security best practice)
                json response = {
                    {"message", "If the email exists, a password reset link will be sent"}};
                sendJson(res, 200, response);
                return;
            }

            // In production, you would send this token via email
            // For now, we'll return it in the response (for testing only!)
            LOG_WARN("Password reset token generated (should be sent via email): {}", token);

            json response = {
                {"message", "Password reset token created"},
                {"token", token}  // Remove this in production!
            };

            sendJson(res, 200, response);

        } catch (const json::exception& e) {
            sendError(res, 400, "Invalid JSON: " + std::string(e.what()));
        }
    });

    // ========================================================================
    // POST /api/v1/auth/reset-password - Reset password with token
    // ========================================================================
    server.Post("/api/v1/auth/reset-password",
                [auth_manager](const httplib::Request& req, httplib::Response& res) {
                    try {
                        json body = json::parse(req.body);

                        // Validate required fields
                        if (!body.contains("token") || !body.contains("new_password")) {
                            sendError(res, 400, "Missing required fields: token, new_password");
                            return;
                        }

                        std::string token = body["token"];
                        std::string new_password = body["new_password"];

                        // Reset password
                        if (auth_manager->resetPassword(token, new_password)) {
                            json response = {{"message", "Password reset successfully"}};
                            sendJson(res, 200, response);
                        } else {
                            sendError(res, 400, "Invalid or expired reset token");
                        }

                    } catch (const json::exception& e) {
                        sendError(res, 400, "Invalid JSON: " + std::string(e.what()));
                    }
                });

    // ========================================================================
    // API Key Management Routes
    // ========================================================================

    // POST /api/v1/auth/apikeys - Create API key
    server.Post("/api/v1/auth/apikeys", [auth_manager, auth_middleware](const httplib::Request& req,
                                                                        httplib::Response& res) {
        // Require authentication
        auto user = auth_middleware->getRequestUser(req);
        if (!user) {
            sendError(res, 401, "Authentication required");
            return;
        }

        try {
            json body = json::parse(req.body);

            std::string description = body.value("description", "");
            std::vector<std::string> scopes =
                body.value("scopes", std::vector<std::string>{"read"});
            int ttl_days = body.value("ttl_days", 365);

            // Create API key
            auto result = auth_manager->createApiKey(user->user_id, description, scopes, ttl_days);
            if (result.key_id.empty()) {
                sendError(res, 500, "Failed to create API key");
                return;
            }

            json response = {
                {"key_id", result.key_id},
                {"api_key", result.api_key},
                {"message",
                 "API key created successfully. Save it securely - it won't be shown again!"}};

            sendJson(res, 201, response);

        } catch (const json::exception& e) {
            sendError(res, 400, "Invalid JSON: " + std::string(e.what()));
        }
    });

    // GET /api/v1/auth/apikeys - List API keys
    server.Get("/api/v1/auth/apikeys", [auth_manager, auth_middleware](const httplib::Request& req,
                                                                       httplib::Response& res) {
        // Require authentication
        auto user = auth_middleware->getRequestUser(req);
        if (!user) {
            sendError(res, 401, "Authentication required");
            return;
        }

        // List API keys
        auto keys = auth_manager->listApiKeys(user->user_id);

        json keys_json = json::array();
        for (const auto& key : keys) {
            keys_json.push_back({{"key_id", key.key_id},
                                 {"description", key.description},
                                 {"scopes", key.scopes},
                                 {"created_at", std::chrono::duration_cast<std::chrono::seconds>(
                                                    key.created_at.time_since_epoch())
                                                    .count()},
                                 {"expires_at", std::chrono::duration_cast<std::chrono::seconds>(
                                                    key.expires_at.time_since_epoch())
                                                    .count()},
                                 {"is_active", key.is_active}});
        }

        json response = {{"api_keys", keys_json}};

        sendJson(res, 200, response);
    });

    // DELETE /api/v1/auth/apikeys/:key_id - Revoke API key
    server.Delete(
        R"(/api/v1/auth/apikeys/([^/]+))",
        [auth_manager, auth_middleware](const httplib::Request& req, httplib::Response& res) {
            // Require authentication
            auto user = auth_middleware->getRequestUser(req);
            if (!user) {
                sendError(res, 401, "Authentication required");
                return;
            }

            std::string key_id = req.matches[1];

            // Revoke API key
            if (auth_manager->revokeApiKey(key_id)) {
                json response = {{"message", "API key revoked successfully"}};
                sendJson(res, 200, response);
            } else {
                sendError(res, 404, "API key not found");
            }
        });

    // ========================================================================
    // Admin Routes (User Management)
    // ========================================================================

    // GET /api/v1/users - List all users (admin only)
    server.Get("/api/v1/users", [auth_manager, auth_middleware](const httplib::Request& req,
                                                                httplib::Response& res) {
        // Require admin role
        if (!auth_middleware->requireRole(req, res, "admin")) {
            return;
        }

        int page = std::stoi(req.has_param("page") ? req.get_param_value("page") : "1");
        int limit = std::stoi(req.has_param("limit") ? req.get_param_value("limit") : "20");

        // List users
        auto users = auth_manager->listUsers(page, limit);
        int total = auth_manager->getUserCount();

        json users_json = json::array();
        for (const auto& user : users) {
            users_json.push_back(userToJson(user));
        }

        json response = {{"users", users_json}, {"total", total}, {"page", page}, {"limit", limit}};

        sendJson(res, 200, response);
    });

    // POST /api/v1/users - Create user (admin only)
    server.Post("/api/v1/users", [auth_manager, auth_middleware](const httplib::Request& req,
                                                                 httplib::Response& res) {
        // Require admin role
        if (!auth_middleware->requireRole(req, res, "admin")) {
            return;
        }

        try {
            json body = json::parse(req.body);

            // Validate required fields
            if (!body.contains("username") || !body.contains("password")) {
                sendError(res, 400, "Missing required fields: username, password");
                return;
            }

            std::string username = body["username"];
            std::string password = body["password"];
            std::string email = body.value("email", "");
            std::vector<std::string> roles = body.value("roles", std::vector<std::string>{"user"});

            // Create user
            auto user = auth_manager->createUser(username, password, email, roles);
            if (!user) {
                sendError(res, 400, "Failed to create user");
                return;
            }

            json response = {{"message", "User created successfully"}, {"user", userToJson(*user)}};

            sendJson(res, 201, response);

        } catch (const json::exception& e) {
            sendError(res, 400, "Invalid JSON: " + std::string(e.what()));
        }
    });

    // PUT /api/v1/users/:user_id - Update user (admin only)
    server.Put(
        R"(/api/v1/users/([^/]+))",
        [auth_manager, auth_middleware](const httplib::Request& req, httplib::Response& res) {
            // Require admin role
            if (!auth_middleware->requireRole(req, res, "admin")) {
                return;
            }

            std::string user_id = req.matches[1];

            try {
                json body = json::parse(req.body);

                // Get existing user
                auto user = auth_manager->getUser(user_id);
                if (!user) {
                    sendError(res, 404, "User not found");
                    return;
                }

                // Update fields
                if (body.contains("email")) {
                    user->email = body["email"];
                }
                if (body.contains("roles")) {
                    user->roles = body["roles"].get<std::vector<std::string>>();
                }
                if (body.contains("is_active")) {
                    user->is_active = body["is_active"];
                }

                // Update user
                if (auth_manager->updateUser(user_id, *user)) {
                    json response = {{"message", "User updated successfully"},
                                     {"user", userToJson(*user)}};
                    sendJson(res, 200, response);
                } else {
                    sendError(res, 500, "Failed to update user");
                }

            } catch (const json::exception& e) {
                sendError(res, 400, "Invalid JSON: " + std::string(e.what()));
            }
        });

    // DELETE /api/v1/users/:user_id - Delete user (admin only)
    server.Delete(
        R"(/api/v1/users/([^/]+))",
        [auth_manager, auth_middleware](const httplib::Request& req, httplib::Response& res) {
            // Require admin role
            if (!auth_middleware->requireRole(req, res, "admin")) {
                return;
            }

            std::string user_id = req.matches[1];

            // Delete user
            if (auth_manager->deleteUser(user_id)) {
                json response = {{"message", "User deleted successfully"}};
                sendJson(res, 200, response);
            } else {
                sendError(res, 404, "User not found");
            }
        });

    LOG_INFO("Authentication routes configured");
}

}  // namespace callflow
