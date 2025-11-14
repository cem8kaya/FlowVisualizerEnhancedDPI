#pragma once

#include "common/types.h"
#include "persistence/database.h"
#include <string>
#include <vector>
#include <optional>
#include <chrono>
#include <memory>

namespace callflow {

// Forward declaration
class DatabaseManager;

/**
 * User representation
 */
struct User {
    std::string user_id;
    std::string username;
    std::string email;
    std::vector<std::string> roles;
    bool is_active = true;
    Timestamp created_at;
    std::optional<Timestamp> last_login;
};

/**
 * JWT token pair
 */
struct JwtToken {
    std::string token;              // Access token
    std::string refresh_token;       // Refresh token
    int64_t expires_in;             // Token expiry in seconds
    User user;                       // Associated user
};

/**
 * API key representation
 */
struct ApiKey {
    std::string key_id;
    std::string key_hash;
    std::string user_id;
    std::string description;
    std::vector<std::string> scopes;
    Timestamp created_at;
    Timestamp expires_at;
    std::optional<Timestamp> last_used;
    bool is_active = true;
};

/**
 * API key creation result (contains plain key only once)
 */
struct ApiKeyResult {
    std::string key_id;
    std::string api_key;  // Plain text key (shown only once)
};

/**
 * Password policy configuration
 */
struct PasswordPolicy {
    int min_length = 8;
    bool require_uppercase = true;
    bool require_lowercase = true;
    bool require_digit = true;
    bool require_special = false;
};

/**
 * Authentication manager configuration
 */
struct AuthConfig {
    std::string jwt_secret;
    int jwt_expiry_hours = 24;
    int refresh_token_expiry_days = 30;
    int bcrypt_rounds = 12;
    PasswordPolicy password_policy;
    bool allow_registration = true;
    std::vector<std::string> default_roles = {"user"};
};

/**
 * AuthManager - Handles user authentication, authorization, and API keys
 */
class AuthManager {
public:
    /**
     * Constructor
     * @param db Database manager for persistence
     * @param config Authentication configuration
     */
    explicit AuthManager(DatabaseManager* db, const AuthConfig& config);

    /**
     * Destructor
     */
    ~AuthManager();

    // ========================================================================
    // User Management
    // ========================================================================

    /**
     * Create a new user
     * @param username Username (must be unique)
     * @param password Plain text password (will be hashed)
     * @param email Email address (optional)
     * @param roles User roles
     * @return User object or nullopt on failure
     */
    std::optional<User> createUser(
        const std::string& username,
        const std::string& password,
        const std::string& email = "",
        const std::vector<std::string>& roles = {}
    );

    /**
     * Get user by ID
     * @param user_id User ID
     * @return User object or nullopt if not found
     */
    std::optional<User> getUser(const std::string& user_id);

    /**
     * Get user by username
     * @param username Username
     * @return User object or nullopt if not found
     */
    std::optional<User> getUserByUsername(const std::string& username);

    /**
     * Update user information
     * @param user_id User ID
     * @param user Updated user data
     * @return true on success
     */
    bool updateUser(const std::string& user_id, const User& user);

    /**
     * Delete user
     * @param user_id User ID
     * @return true on success
     */
    bool deleteUser(const std::string& user_id);

    /**
     * List all users (paginated)
     * @param page Page number (1-based)
     * @param limit Items per page
     * @return List of users
     */
    std::vector<User> listUsers(int page = 1, int limit = 20);

    /**
     * Get total user count
     * @return Number of users
     */
    int getUserCount();

    // ========================================================================
    // Authentication
    // ========================================================================

    /**
     * Authenticate user with username/password
     * @param username Username
     * @param password Plain text password
     * @return JWT token pair or nullopt on failure
     */
    std::optional<JwtToken> login(
        const std::string& username,
        const std::string& password
    );

    /**
     * Refresh access token using refresh token
     * @param refresh_token Refresh token
     * @return New JWT token pair or nullopt on failure
     */
    std::optional<JwtToken> refreshToken(const std::string& refresh_token);

    /**
     * Logout (blacklist token)
     * @param token Access token to blacklist
     * @return true on success
     */
    bool logout(const std::string& token);

    /**
     * Validate JWT token
     * @param token JWT token
     * @return User object or nullopt if invalid
     */
    std::optional<User> validateToken(const std::string& token);

    /**
     * Check if token is blacklisted
     * @param token_hash SHA256 hash of token
     * @return true if blacklisted
     */
    bool isTokenBlacklisted(const std::string& token_hash);

    // ========================================================================
    // Authorization (RBAC)
    // ========================================================================

    /**
     * Check if user has specific role
     * @param user_id User ID
     * @param role Role name
     * @return true if user has role
     */
    bool hasRole(const std::string& user_id, const std::string& role);

    /**
     * Check if user has permission for resource/action
     * @param user_id User ID
     * @param resource Resource name (e.g., "jobs", "sessions")
     * @param action Action name (e.g., "read", "write", "delete")
     * @return true if user has permission
     */
    bool hasPermission(
        const std::string& user_id,
        const std::string& resource,
        const std::string& action
    );

    /**
     * Add role to user
     * @param user_id User ID
     * @param role Role name
     * @return true on success
     */
    bool addRole(const std::string& user_id, const std::string& role);

    /**
     * Remove role from user
     * @param user_id User ID
     * @param role Role name
     * @return true on success
     */
    bool removeRole(const std::string& user_id, const std::string& role);

    // ========================================================================
    // API Keys
    // ========================================================================

    /**
     * Create API key for user
     * @param user_id User ID
     * @param description Key description
     * @param scopes Permission scopes
     * @param ttl_days Time to live in days
     * @return API key result with plain key (shown only once)
     */
    ApiKeyResult createApiKey(
        const std::string& user_id,
        const std::string& description,
        const std::vector<std::string>& scopes,
        int ttl_days = 365
    );

    /**
     * Validate API key and return associated user
     * @param api_key Plain text API key
     * @return User object or nullopt if invalid
     */
    std::optional<User> validateApiKey(const std::string& api_key);

    /**
     * Revoke API key
     * @param key_id Key ID
     * @return true on success
     */
    bool revokeApiKey(const std::string& key_id);

    /**
     * List API keys for user
     * @param user_id User ID
     * @return List of API keys (without key_hash)
     */
    std::vector<ApiKey> listApiKeys(const std::string& user_id);

    /**
     * Update API key last used timestamp
     * @param key_id Key ID
     */
    void updateApiKeyLastUsed(const std::string& key_id);

    // ========================================================================
    // Password Management
    // ========================================================================

    /**
     * Change user password
     * @param user_id User ID
     * @param old_password Old password (for verification)
     * @param new_password New password
     * @return true on success
     */
    bool changePassword(
        const std::string& user_id,
        const std::string& old_password,
        const std::string& new_password
    );

    /**
     * Create password reset token
     * @param email User email
     * @return Reset token or empty string on failure
     */
    std::string createPasswordResetToken(const std::string& email);

    /**
     * Reset password using reset token
     * @param token Reset token
     * @param new_password New password
     * @return true on success
     */
    bool resetPassword(
        const std::string& token,
        const std::string& new_password
    );

    /**
     * Validate password against policy
     * @param password Password to validate
     * @return Error message or empty string if valid
     */
    std::string validatePassword(const std::string& password) const;

private:
    DatabaseManager* db_;
    AuthConfig config_;

    /**
     * Hash password using bcrypt (via OpenSSL PBKDF2)
     * @param password Plain text password
     * @return Hashed password
     */
    std::string hashPassword(const std::string& password);

    /**
     * Verify password against hash
     * @param password Plain text password
     * @param hash Stored password hash
     * @return true if password matches
     */
    bool verifyPassword(const std::string& password, const std::string& hash);

    /**
     * Generate JWT token for user
     * @param user User object
     * @param expiry_hours Token expiry in hours
     * @return JWT token string
     */
    std::string generateJwt(const User& user, int expiry_hours);

    /**
     * Generate secure random token
     * @param length Token length in bytes
     * @return Hex-encoded token
     */
    std::string generateSecureToken(size_t length = 32);

    /**
     * Hash token (SHA256)
     * @param token Plain token
     * @return SHA256 hash (hex)
     */
    std::string hashToken(const std::string& token);

    /**
     * Generate unique user ID
     * @return User ID with "usr_" prefix
     */
    std::string generateUserId();

    /**
     * Generate unique key ID
     * @return Key ID with "key_" prefix
     */
    std::string generateKeyId();

    /**
     * Check if username exists
     * @param username Username
     * @return true if exists
     */
    bool usernameExists(const std::string& username);

    /**
     * Update user last login timestamp
     * @param user_id User ID
     */
    void updateLastLogin(const std::string& user_id);
};

}  // namespace callflow
