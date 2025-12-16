#include "api_server/auth_manager.h"

#include <jwt-cpp/jwt.h>
#include <jwt-cpp/traits/nlohmann-json/defaults.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <chrono>
#include <iomanip>
#include <nlohmann/json.hpp>
#include <regex>
#include <sstream>

#include "common/logger.h"
#include "common/utils.h"

namespace callflow {

// ============================================================================
// Constructor / Destructor
// ============================================================================

AuthManager::AuthManager(DatabaseManager* db, const AuthConfig& config) : db_(db), config_(config) {
    if (!db_) {
        throw std::runtime_error("DatabaseManager cannot be null");
    }

    LOG_INFO("AuthManager initialized with JWT expiry: {} hours", config_.jwt_expiry_hours);
}

AuthManager::~AuthManager() = default;

// ============================================================================
// User Management
// ============================================================================

std::optional<User> AuthManager::createUser(const std::string& username,
                                            const std::string& password, const std::string& email,
                                            const std::vector<std::string>& roles) {
    // Validate username
    if (username.empty() || username.length() > 50) {
        LOG_ERROR("Invalid username length: {}", username.length());
        return std::nullopt;
    }

    // Check if username exists
    if (usernameExists(username)) {
        LOG_ERROR("Username already exists: {}", username);
        return std::nullopt;
    }

    // Validate password
    std::string password_error = validatePassword(password);
    if (!password_error.empty()) {
        LOG_ERROR("Password validation failed: {}", password_error);
        return std::nullopt;
    }

    // Hash password
    std::string password_hash = hashPassword(password);

    // Generate user ID
    std::string user_id = generateUserId();

    // Use default roles if none provided
    std::vector<std::string> user_roles = roles.empty() ? config_.default_roles : roles;

    // Create user object
    User user;
    user.user_id = user_id;
    user.username = username;
    user.email = email;
    user.roles = user_roles;
    user.is_active = true;
    user.created_at = utils::now();

    // Store in database
    nlohmann::json roles_json = user_roles;
    std::string sql = R"(
        INSERT INTO users (user_id, username, password_hash, email, roles, is_active, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    )";

    try {
        db_->execute("BEGIN TRANSACTION");

        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(static_cast<sqlite3*>(db_->getHandle()), sql.c_str(), -1, &stmt,
                               nullptr) != SQLITE_OK) {
            db_->execute("ROLLBACK");
            return std::nullopt;
        }

        sqlite3_bind_text(stmt, 1, user_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, username.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, password_hash.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, email.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 5, roles_json.dump().c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 6, user.is_active ? 1 : 0);
        sqlite3_bind_int64(
            stmt, 7,
            std::chrono::duration_cast<std::chrono::seconds>(user.created_at.time_since_epoch())
                .count());

        int rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        if (rc != SQLITE_DONE) {
            db_->execute("ROLLBACK");
            LOG_ERROR("Failed to insert user: {}",
                      sqlite3_errmsg(static_cast<sqlite3*>(db_->getHandle())));
            return std::nullopt;
        }

        db_->execute("COMMIT");

        LOG_INFO("Created user: {} (ID: {})", username, user_id);
        return user;

    } catch (const std::exception& e) {
        db_->execute("ROLLBACK");
        LOG_ERROR("Exception creating user: {}", e.what());
        return std::nullopt;
    }
}

std::optional<User> AuthManager::getUser(const std::string& user_id) {
    std::string sql =
        "SELECT user_id, username, email, roles, is_active, created_at, last_login "
        "FROM users WHERE user_id = ?";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(static_cast<sqlite3*>(db_->getHandle()), sql.c_str(), -1, &stmt,
                           nullptr) != SQLITE_OK) {
        return std::nullopt;
    }

    sqlite3_bind_text(stmt, 1, user_id.c_str(), -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        User user;
        user.user_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        user.username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));

        const char* email_str = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        if (email_str)
            user.email = email_str;

        // Parse roles JSON
        const char* roles_json = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        if (roles_json) {
            try {
                user.roles = nlohmann::json::parse(roles_json).get<std::vector<std::string>>();
            } catch (...) {
                user.roles = config_.default_roles;
            }
        }

        user.is_active = sqlite3_column_int(stmt, 4) != 0;
        user.created_at = std::chrono::system_clock::from_time_t(sqlite3_column_int64(stmt, 5));

        if (sqlite3_column_type(stmt, 6) != SQLITE_NULL) {
            user.last_login = std::chrono::system_clock::from_time_t(sqlite3_column_int64(stmt, 6));
        }

        sqlite3_finalize(stmt);
        return user;
    }

    sqlite3_finalize(stmt);
    return std::nullopt;
}

std::optional<User> AuthManager::getUserByUsername(const std::string& username) {
    std::string sql = "SELECT user_id FROM users WHERE username = ?";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(static_cast<sqlite3*>(db_->getHandle()), sql.c_str(), -1, &stmt,
                           nullptr) != SQLITE_OK) {
        return std::nullopt;
    }

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        std::string user_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        sqlite3_finalize(stmt);
        return getUser(user_id);
    }

    sqlite3_finalize(stmt);
    return std::nullopt;
}

bool AuthManager::updateUser(const std::string& user_id, const User& user) {
    nlohmann::json roles_json = user.roles;

    std::string sql = R"(
        UPDATE users
        SET email = ?, roles = ?, is_active = ?
        WHERE user_id = ?
    )";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(static_cast<sqlite3*>(db_->getHandle()), sql.c_str(), -1, &stmt,
                           nullptr) != SQLITE_OK) {
        return false;
    }

    sqlite3_bind_text(stmt, 1, user.email.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, roles_json.dump().c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, user.is_active ? 1 : 0);
    sqlite3_bind_text(stmt, 4, user_id.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return rc == SQLITE_DONE;
}

bool AuthManager::deleteUser(const std::string& user_id) {
    std::string sql = "DELETE FROM users WHERE user_id = ?";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(static_cast<sqlite3*>(db_->getHandle()), sql.c_str(), -1, &stmt,
                           nullptr) != SQLITE_OK) {
        return false;
    }

    sqlite3_bind_text(stmt, 1, user_id.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc == SQLITE_DONE) {
        LOG_INFO("Deleted user: {}", user_id);
        return true;
    }

    return false;
}

std::vector<User> AuthManager::listUsers(int page, int limit) {
    std::vector<User> users;
    int offset = (page - 1) * limit;

    std::string sql = R"(
        SELECT user_id FROM users
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
    )";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(static_cast<sqlite3*>(db_->getHandle()), sql.c_str(), -1, &stmt,
                           nullptr) != SQLITE_OK) {
        return users;
    }

    sqlite3_bind_int(stmt, 1, limit);
    sqlite3_bind_int(stmt, 2, offset);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        std::string user_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        auto user = getUser(user_id);
        if (user) {
            users.push_back(*user);
        }
    }

    sqlite3_finalize(stmt);
    return users;
}

int AuthManager::getUserCount() {
    std::string sql = "SELECT COUNT(*) FROM users";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(static_cast<sqlite3*>(db_->getHandle()), sql.c_str(), -1, &stmt,
                           nullptr) != SQLITE_OK) {
        return 0;
    }

    int count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int(stmt, 0);
    }

    sqlite3_finalize(stmt);
    return count;
}

// ============================================================================
// Authentication
// ============================================================================

std::optional<JwtToken> AuthManager::login(const std::string& username,
                                           const std::string& password) {
    // Get user by username
    auto user = getUserByUsername(username);
    if (!user) {
        LOG_WARN("Login failed: user not found: {}", username);
        return std::nullopt;
    }

    // Check if user is active
    if (!user->is_active) {
        LOG_WARN("Login failed: user inactive: {}", username);
        return std::nullopt;
    }

    // Get password hash from database
    std::string sql = "SELECT password_hash FROM users WHERE user_id = ?";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(static_cast<sqlite3*>(db_->getHandle()), sql.c_str(), -1, &stmt,
                           nullptr) != SQLITE_OK) {
        return std::nullopt;
    }

    sqlite3_bind_text(stmt, 1, user->user_id.c_str(), -1, SQLITE_TRANSIENT);

    std::string password_hash;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        password_hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
    }
    sqlite3_finalize(stmt);

    if (password_hash.empty()) {
        return std::nullopt;
    }

    // Verify password
    if (!verifyPassword(password, password_hash)) {
        LOG_WARN("Login failed: invalid password: {}", username);
        return std::nullopt;
    }

    // Generate JWT tokens
    std::string access_token = generateJwt(*user, config_.jwt_expiry_hours);
    std::string refresh_token = generateJwt(*user, config_.refresh_token_expiry_days * 24);

    // Update last login
    updateLastLogin(user->user_id);

    LOG_INFO("User logged in: {}", username);

    return JwtToken{access_token, refresh_token,
                    static_cast<int64_t>(config_.jwt_expiry_hours * 3600), *user};
}

std::optional<JwtToken> AuthManager::refreshToken(const std::string& refresh_token) {
    // Validate refresh token
    auto user = validateToken(refresh_token);
    if (!user) {
        return std::nullopt;
    }

    // Generate new tokens
    std::string new_access_token = generateJwt(*user, config_.jwt_expiry_hours);
    std::string new_refresh_token = generateJwt(*user, config_.refresh_token_expiry_days * 24);

    return JwtToken{new_access_token, new_refresh_token,
                    static_cast<int64_t>(config_.jwt_expiry_hours * 3600), *user};
}

bool AuthManager::logout(const std::string& token) {
    // Hash the token
    std::string token_hash = hashToken(token);

    // Add to blacklist (auth_sessions table with revoked=1)
    std::string sql = R"(
        INSERT INTO auth_sessions (session_id, user_id, token_hash, expires_at, created_at, revoked)
        VALUES (?, '', ?, ?, ?, 1)
    )";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(static_cast<sqlite3*>(db_->getHandle()), sql.c_str(), -1, &stmt,
                           nullptr) != SQLITE_OK) {
        return false;
    }

    std::string session_id = "sess_" + generateSecureToken(16);
    int64_t now =
        std::chrono::duration_cast<std::chrono::seconds>(utils::now().time_since_epoch()).count();
    int64_t expires = now + (config_.jwt_expiry_hours * 3600);

    sqlite3_bind_text(stmt, 1, session_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, token_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, expires);
    sqlite3_bind_int64(stmt, 4, now);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return rc == SQLITE_DONE;
}

std::optional<User> AuthManager::validateToken(const std::string& token) {
    try {
        // Check if token is blacklisted
        if (isTokenBlacklisted(hashToken(token))) {
            return std::nullopt;
        }

        // Verify JWT signature and decode
        auto verifier = jwt::verify<jwt::traits::nlohmann_json>()
                            .allow_algorithm(jwt::algorithm::hs256{config_.jwt_secret})
                            .with_issuer("callflowd");

        auto decoded = jwt::decode<jwt::traits::nlohmann_json>(token);
        verifier.verify(decoded);

        // Get user ID from subject claim
        std::string user_id = decoded.get_subject();

        // Get user from database
        return getUser(user_id);

    } catch (const std::exception& e) {
        LOG_DEBUG("Token validation failed: {}", e.what());
        return std::nullopt;
    }
}

bool AuthManager::isTokenBlacklisted(const std::string& token_hash) {
    std::string sql = "SELECT 1 FROM auth_sessions WHERE token_hash = ? AND revoked = 1";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(static_cast<sqlite3*>(db_->getHandle()), sql.c_str(), -1, &stmt,
                           nullptr) != SQLITE_OK) {
        return false;
    }

    sqlite3_bind_text(stmt, 1, token_hash.c_str(), -1, SQLITE_TRANSIENT);

    bool blacklisted = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);

    return blacklisted;
}

// ============================================================================
// Authorization (RBAC)
// ============================================================================

bool AuthManager::hasRole(const std::string& user_id, const std::string& role) {
    auto user = getUser(user_id);
    if (!user) {
        return false;
    }

    return std::find(user->roles.begin(), user->roles.end(), role) != user->roles.end();
}

bool AuthManager::hasPermission(const std::string& user_id, const std::string& resource,
                                const std::string& action) {
    auto user = getUser(user_id);
    if (!user) {
        return false;
    }

    // Admin has all permissions
    if (hasRole(user_id, "admin")) {
        return true;
    }

    // Simple RBAC: users can read, admins can write/delete
    if (action == "read") {
        return hasRole(user_id, "user") || hasRole(user_id, "admin");
    } else if (action == "write" || action == "delete") {
        return hasRole(user_id, "admin");
    }

    return false;
}

bool AuthManager::addRole(const std::string& user_id, const std::string& role) {
    auto user = getUser(user_id);
    if (!user) {
        return false;
    }

    // Check if role already exists
    if (std::find(user->roles.begin(), user->roles.end(), role) != user->roles.end()) {
        return true;  // Already has role
    }

    user->roles.push_back(role);
    return updateUser(user_id, *user);
}

bool AuthManager::removeRole(const std::string& user_id, const std::string& role) {
    auto user = getUser(user_id);
    if (!user) {
        return false;
    }

    auto it = std::find(user->roles.begin(), user->roles.end(), role);
    if (it == user->roles.end()) {
        return true;  // Role not found, nothing to remove
    }

    user->roles.erase(it);
    return updateUser(user_id, *user);
}

// ============================================================================
// API Keys
// ============================================================================

ApiKeyResult AuthManager::createApiKey(const std::string& user_id, const std::string& description,
                                       const std::vector<std::string>& scopes, int ttl_days) {
    // Generate API key
    std::string api_key = "cfv_" + generateSecureToken(32);
    std::string key_hash = hashToken(api_key);
    std::string key_id = generateKeyId();

    // Calculate expiry
    int64_t now =
        std::chrono::duration_cast<std::chrono::seconds>(utils::now().time_since_epoch()).count();
    int64_t expires = now + (ttl_days * 24 * 3600);

    // Store in database
    nlohmann::json scopes_json = scopes;
    std::string sql = R"(
        INSERT INTO api_keys (key_id, key_hash, user_id, description, scopes, expires_at, created_at, is_active)
        VALUES (?, ?, ?, ?, ?, ?, ?, 1)
    )";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(static_cast<sqlite3*>(db_->getHandle()), sql.c_str(), -1, &stmt,
                           nullptr) != SQLITE_OK) {
        return {"", ""};
    }

    sqlite3_bind_text(stmt, 1, key_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, key_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, user_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, description.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, scopes_json.dump().c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 6, expires);
    sqlite3_bind_int64(stmt, 7, now);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        return {"", ""};
    }

    LOG_INFO("Created API key for user {}: {}", user_id, key_id);

    return {key_id, api_key};
}

std::optional<User> AuthManager::validateApiKey(const std::string& api_key) {
    // Check format
    if (api_key.rfind("cfv_", 0) != 0) {
        return std::nullopt;
    }

    std::string key_hash = hashToken(api_key);

    std::string sql = R"(
        SELECT user_id, key_id, expires_at, is_active
        FROM api_keys
        WHERE key_hash = ?
    )";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(static_cast<sqlite3*>(db_->getHandle()), sql.c_str(), -1, &stmt,
                           nullptr) != SQLITE_OK) {
        return std::nullopt;
    }

    sqlite3_bind_text(stmt, 1, key_hash.c_str(), -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        std::string user_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        std::string key_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        int64_t expires_at = sqlite3_column_int64(stmt, 2);
        bool is_active = sqlite3_column_int(stmt, 3) != 0;

        sqlite3_finalize(stmt);

        // Check if expired
        int64_t now =
            std::chrono::duration_cast<std::chrono::seconds>(utils::now().time_since_epoch())
                .count();
        if (now > expires_at) {
            LOG_WARN("API key expired: {}", key_id);
            return std::nullopt;
        }

        // Check if active
        if (!is_active) {
            LOG_WARN("API key revoked: {}", key_id);
            return std::nullopt;
        }

        // Update last used
        updateApiKeyLastUsed(key_id);

        // Return user
        return getUser(user_id);
    }

    sqlite3_finalize(stmt);
    return std::nullopt;
}

bool AuthManager::revokeApiKey(const std::string& key_id) {
    std::string sql = "UPDATE api_keys SET is_active = 0 WHERE key_id = ?";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(static_cast<sqlite3*>(db_->getHandle()), sql.c_str(), -1, &stmt,
                           nullptr) != SQLITE_OK) {
        return false;
    }

    sqlite3_bind_text(stmt, 1, key_id.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc == SQLITE_DONE) {
        LOG_INFO("Revoked API key: {}", key_id);
        return true;
    }

    return false;
}

std::vector<ApiKey> AuthManager::listApiKeys(const std::string& user_id) {
    std::vector<ApiKey> keys;

    std::string sql = R"(
        SELECT key_id, user_id, description, scopes, created_at, expires_at, last_used, is_active
        FROM api_keys
        WHERE user_id = ?
        ORDER BY created_at DESC
    )";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(static_cast<sqlite3*>(db_->getHandle()), sql.c_str(), -1, &stmt,
                           nullptr) != SQLITE_OK) {
        return keys;
    }

    sqlite3_bind_text(stmt, 1, user_id.c_str(), -1, SQLITE_TRANSIENT);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        ApiKey key;
        key.key_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        key.user_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));

        const char* desc = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        if (desc)
            key.description = desc;

        const char* scopes_json = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        if (scopes_json) {
            try {
                key.scopes = nlohmann::json::parse(scopes_json).get<std::vector<std::string>>();
            } catch (...) {
            }
        }

        key.created_at = std::chrono::system_clock::from_time_t(sqlite3_column_int64(stmt, 4));
        key.expires_at = std::chrono::system_clock::from_time_t(sqlite3_column_int64(stmt, 5));

        if (sqlite3_column_type(stmt, 6) != SQLITE_NULL) {
            key.last_used = std::chrono::system_clock::from_time_t(sqlite3_column_int64(stmt, 6));
        }

        key.is_active = sqlite3_column_int(stmt, 7) != 0;

        keys.push_back(key);
    }

    sqlite3_finalize(stmt);
    return keys;
}

void AuthManager::updateApiKeyLastUsed(const std::string& key_id) {
    std::string sql = "UPDATE api_keys SET last_used = ? WHERE key_id = ?";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(static_cast<sqlite3*>(db_->getHandle()), sql.c_str(), -1, &stmt,
                           nullptr) != SQLITE_OK) {
        return;
    }

    int64_t now =
        std::chrono::duration_cast<std::chrono::seconds>(utils::now().time_since_epoch()).count();
    sqlite3_bind_int64(stmt, 1, now);
    sqlite3_bind_text(stmt, 2, key_id.c_str(), -1, SQLITE_TRANSIENT);

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

// ============================================================================
// Password Management
// ============================================================================

bool AuthManager::changePassword(const std::string& user_id, const std::string& old_password,
                                 const std::string& new_password) {
    // Get current password hash
    std::string sql = "SELECT password_hash FROM users WHERE user_id = ?";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(static_cast<sqlite3*>(db_->getHandle()), sql.c_str(), -1, &stmt,
                           nullptr) != SQLITE_OK) {
        return false;
    }

    sqlite3_bind_text(stmt, 1, user_id.c_str(), -1, SQLITE_TRANSIENT);

    std::string password_hash;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        password_hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
    }
    sqlite3_finalize(stmt);

    if (password_hash.empty()) {
        return false;
    }

    // Verify old password
    if (!verifyPassword(old_password, password_hash)) {
        LOG_WARN("Password change failed: incorrect old password");
        return false;
    }

    // Validate new password
    std::string error = validatePassword(new_password);
    if (!error.empty()) {
        LOG_WARN("Password change failed: {}", error);
        return false;
    }

    // Update password
    std::string new_hash = hashPassword(new_password);
    sql = "UPDATE users SET password_hash = ? WHERE user_id = ?";

    if (sqlite3_prepare_v2(static_cast<sqlite3*>(db_->getHandle()), sql.c_str(), -1, &stmt,
                           nullptr) != SQLITE_OK) {
        return false;
    }

    sqlite3_bind_text(stmt, 1, new_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, user_id.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc == SQLITE_DONE) {
        LOG_INFO("Password changed for user: {}", user_id);
        return true;
    }

    return false;
}

std::string AuthManager::createPasswordResetToken(const std::string& email) {
    // Get user by email
    std::string sql = "SELECT user_id FROM users WHERE email = ?";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(static_cast<sqlite3*>(db_->getHandle()), sql.c_str(), -1, &stmt,
                           nullptr) != SQLITE_OK) {
        return "";
    }

    sqlite3_bind_text(stmt, 1, email.c_str(), -1, SQLITE_TRANSIENT);

    std::string user_id;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        user_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
    }
    sqlite3_finalize(stmt);

    if (user_id.empty()) {
        return "";
    }

    // Generate reset token
    std::string token = generateSecureToken(32);
    std::string token_hash = hashToken(token);
    std::string token_id = "rst_" + generateSecureToken(16);

    // Store in database (expires in 1 hour)
    int64_t now =
        std::chrono::duration_cast<std::chrono::seconds>(utils::now().time_since_epoch()).count();
    int64_t expires = now + 3600;

    sql = R"(
        INSERT INTO password_reset_tokens (token_id, user_id, token_hash, expires_at, created_at)
        VALUES (?, ?, ?, ?, ?)
    )";

    if (sqlite3_prepare_v2(static_cast<sqlite3*>(db_->getHandle()), sql.c_str(), -1, &stmt,
                           nullptr) != SQLITE_OK) {
        return "";
    }

    sqlite3_bind_text(stmt, 1, token_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, user_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, token_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 4, expires);
    sqlite3_bind_int64(stmt, 5, now);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc == SQLITE_DONE) {
        LOG_INFO("Created password reset token for user: {}", user_id);
        return token;
    }

    return "";
}

bool AuthManager::resetPassword(const std::string& token, const std::string& new_password) {
    std::string token_hash = hashToken(token);

    // Get reset token record
    std::string sql = R"(
        SELECT user_id, expires_at, used
        FROM password_reset_tokens
        WHERE token_hash = ?
    )";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(static_cast<sqlite3*>(db_->getHandle()), sql.c_str(), -1, &stmt,
                           nullptr) != SQLITE_OK) {
        return false;
    }

    sqlite3_bind_text(stmt, 1, token_hash.c_str(), -1, SQLITE_TRANSIENT);

    std::string user_id;
    int64_t expires_at = 0;
    bool used = false;

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        user_id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        expires_at = sqlite3_column_int64(stmt, 1);
        used = sqlite3_column_int(stmt, 2) != 0;
    }
    sqlite3_finalize(stmt);

    if (user_id.empty()) {
        LOG_WARN("Password reset failed: invalid token");
        return false;
    }

    // Check if expired
    int64_t now =
        std::chrono::duration_cast<std::chrono::seconds>(utils::now().time_since_epoch()).count();
    if (now > expires_at) {
        LOG_WARN("Password reset failed: token expired");
        return false;
    }

    // Check if already used
    if (used) {
        LOG_WARN("Password reset failed: token already used");
        return false;
    }

    // Validate new password
    std::string error = validatePassword(new_password);
    if (!error.empty()) {
        LOG_WARN("Password reset failed: {}", error);
        return false;
    }

    // Update password
    std::string new_hash = hashPassword(new_password);
    sql = "UPDATE users SET password_hash = ? WHERE user_id = ?";

    if (sqlite3_prepare_v2(static_cast<sqlite3*>(db_->getHandle()), sql.c_str(), -1, &stmt,
                           nullptr) != SQLITE_OK) {
        return false;
    }

    sqlite3_bind_text(stmt, 1, new_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, user_id.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        return false;
    }

    // Mark token as used
    sql = "UPDATE password_reset_tokens SET used = 1 WHERE token_hash = ?";

    if (sqlite3_prepare_v2(static_cast<sqlite3*>(db_->getHandle()), sql.c_str(), -1, &stmt,
                           nullptr) != SQLITE_OK) {
        return false;
    }

    sqlite3_bind_text(stmt, 1, token_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    LOG_INFO("Password reset successfully for user: {}", user_id);
    return true;
}

std::string AuthManager::validatePassword(const std::string& password) const {
    const auto& policy = config_.password_policy;

    if (password.length() < static_cast<size_t>(policy.min_length)) {
        return "Password must be at least " + std::to_string(policy.min_length) + " characters";
    }

    if (password.length() > 128) {
        return "Password must not exceed 128 characters";
    }

    if (policy.require_uppercase) {
        if (!std::any_of(password.begin(), password.end(), ::isupper)) {
            return "Password must contain at least one uppercase letter";
        }
    }

    if (policy.require_lowercase) {
        if (!std::any_of(password.begin(), password.end(), ::islower)) {
            return "Password must contain at least one lowercase letter";
        }
    }

    if (policy.require_digit) {
        if (!std::any_of(password.begin(), password.end(), ::isdigit)) {
            return "Password must contain at least one digit";
        }
    }

    if (policy.require_special) {
        std::string special = "!@#$%^&*()_+-=[]{}|;:,.<>?";
        if (password.find_first_of(special) == std::string::npos) {
            return "Password must contain at least one special character";
        }
    }

    return "";  // Valid
}

// ============================================================================
// Private Helper Methods
// ============================================================================

std::string AuthManager::hashPassword(const std::string& password) {
    // Use PBKDF2-HMAC-SHA256 via OpenSSL
    unsigned char salt[16];
    unsigned char hash[32];

    // Generate random salt
    if (RAND_bytes(salt, sizeof(salt)) != 1) {
        throw std::runtime_error("Failed to generate salt");
    }

    // Derive key using PBKDF2
    int iterations = 1 << config_.bcrypt_rounds;  // 2^bcrypt_rounds iterations
    if (PKCS5_PBKDF2_HMAC(password.c_str(), password.length(), salt, sizeof(salt), iterations,
                          EVP_sha256(), sizeof(hash), hash) != 1) {
        throw std::runtime_error("Failed to hash password");
    }

    // Encode as: $pbkdf2$rounds$salt$hash (hex)
    std::ostringstream oss;
    oss << "$pbkdf2$" << iterations << "$";

    for (size_t i = 0; i < sizeof(salt); ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(salt[i]);
    }

    oss << "$";

    for (size_t i = 0; i < sizeof(hash); ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }

    return oss.str();
}

bool AuthManager::verifyPassword(const std::string& password, const std::string& stored_hash) {
    // Parse stored hash: $pbkdf2$rounds$salt$hash
    if (stored_hash.rfind("$pbkdf2$", 0) != 0) {
        return false;
    }

    std::regex re(R"(\$pbkdf2\$(\d+)\$([0-9a-f]+)\$([0-9a-f]+))");
    std::smatch match;
    if (!std::regex_match(stored_hash, match, re)) {
        return false;
    }

    int iterations = std::stoi(match[1].str());
    std::string salt_hex = match[2].str();
    std::string hash_hex = match[3].str();

    // Decode salt from hex
    unsigned char salt[16];
    for (size_t i = 0; i < sizeof(salt); ++i) {
        salt[i] = std::stoi(salt_hex.substr(i * 2, 2), nullptr, 16);
    }

    // Compute hash with same parameters
    unsigned char hash[32];
    if (PKCS5_PBKDF2_HMAC(password.c_str(), password.length(), salt, sizeof(salt), iterations,
                          EVP_sha256(), sizeof(hash), hash) != 1) {
        return false;
    }

    // Encode computed hash as hex
    std::ostringstream oss;
    for (size_t i = 0; i < sizeof(hash); ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }

    // Constant-time comparison
    return oss.str() == hash_hex;
}

std::string AuthManager::generateJwt(const User& user, int expiry_hours) {
    auto now = std::chrono::system_clock::now();
    auto expiry = now + std::chrono::hours(expiry_hours);

    // Convert roles to JSON array
    nlohmann::json roles_json = user.roles;

    return jwt::create<jwt::traits::nlohmann_json>()
        .set_issuer("callflowd")
        .set_type("JWS")
        .set_issued_at(std::chrono::system_clock::now())
        .set_expires_at(std::chrono::system_clock::now() + std::chrono::hours(expiry_hours))
        .set_subject(user.user_id)
        .set_payload_claim("username", user.username)
        .set_payload_claim("roles", roles_json.dump())
        .sign(jwt::algorithm::hs256{config_.jwt_secret});
}

std::string AuthManager::generateSecureToken(size_t length) {
    unsigned char buffer[64];
    if (length > sizeof(buffer)) {
        length = sizeof(buffer);
    }

    if (RAND_bytes(buffer, length) != 1) {
        throw std::runtime_error("Failed to generate secure token");
    }

    // Encode as hex
    std::ostringstream oss;
    for (size_t i = 0; i < length; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(buffer[i]);
    }

    return oss.str();
}

std::string AuthManager::hashToken(const std::string& token) {
    unsigned char hash[SHA256_DIGEST_LENGTH];

    SHA256(reinterpret_cast<const unsigned char*>(token.c_str()), token.length(), hash);

    // Encode as hex
    std::ostringstream oss;
    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }

    return oss.str();
}

std::string AuthManager::generateUserId() {
    return "usr_" + generateSecureToken(16);
}

std::string AuthManager::generateKeyId() {
    return "key_" + generateSecureToken(16);
}

bool AuthManager::usernameExists(const std::string& username) {
    std::string sql = "SELECT 1 FROM users WHERE username = ?";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(static_cast<sqlite3*>(db_->getHandle()), sql.c_str(), -1, &stmt,
                           nullptr) != SQLITE_OK) {
        return false;
    }

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_TRANSIENT);

    bool exists = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);

    return exists;
}

void AuthManager::updateLastLogin(const std::string& user_id) {
    std::string sql = "UPDATE users SET last_login = ? WHERE user_id = ?";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(static_cast<sqlite3*>(db_->getHandle()), sql.c_str(), -1, &stmt,
                           nullptr) != SQLITE_OK) {
        return;
    }

    int64_t now =
        std::chrono::duration_cast<std::chrono::seconds>(utils::now().time_since_epoch()).count();
    sqlite3_bind_int64(stmt, 1, now);
    sqlite3_bind_text(stmt, 2, user_id.c_str(), -1, SQLITE_TRANSIENT);

    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

}  // namespace callflow
