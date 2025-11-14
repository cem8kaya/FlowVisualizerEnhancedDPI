#include "persistence/database.h"
#include "api_server/auth_manager.h"
#include "common/logger.h"
#include <iostream>
#include <fstream>

using namespace callflow;

void printUsage(const char* program_name) {
    std::cerr << "Usage: " << program_name << " <db_path> <username> <password> [email]" << std::endl;
    std::cerr << std::endl;
    std::cerr << "Creates an admin user for the CallFlow Visualizer." << std::endl;
    std::cerr << std::endl;
    std::cerr << "Arguments:" << std::endl;
    std::cerr << "  db_path   Path to SQLite database file" << std::endl;
    std::cerr << "  username  Admin username" << std::endl;
    std::cerr << "  password  Admin password (min 8 chars, must meet policy requirements)" << std::endl;
    std::cerr << "  email     Admin email address (optional)" << std::endl;
    std::cerr << std::endl;
    std::cerr << "Password Policy:" << std::endl;
    std::cerr << "  - Minimum 8 characters" << std::endl;
    std::cerr << "  - At least one uppercase letter" << std::endl;
    std::cerr << "  - At least one lowercase letter" << std::endl;
    std::cerr << "  - At least one digit" << std::endl;
    std::cerr << std::endl;
    std::cerr << "Example:" << std::endl;
    std::cerr << "  " << program_name << " ./callflowd.db admin SecurePass123! admin@example.com" << std::endl;
}

int main(int argc, char* argv[]) {
    // Parse arguments
    if (argc < 4 || argc > 5) {
        printUsage(argv[0]);
        return 1;
    }

    std::string db_path = argv[1];
    std::string username = argv[2];
    std::string password = argv[3];
    std::string email = (argc == 5) ? argv[4] : "";

    // Initialize logger
    initLogger(LogLevel::INFO, true, false, "");

    std::cout << "==================================================" << std::endl;
    std::cout << "  CallFlow Visualizer - Admin User Creator" << std::endl;
    std::cout << "==================================================" << std::endl;
    std::cout << std::endl;

    // Check if database exists
    bool db_exists = std::ifstream(db_path).good();
    if (db_exists) {
        std::cout << "Database exists: " << db_path << std::endl;
    } else {
        std::cout << "Creating new database: " << db_path << std::endl;
    }

    // Initialize database
    DatabaseConfig db_config;
    db_config.enabled = true;
    db_config.path = db_path;

    DatabaseManager db(db_config);
    if (!db.initialize()) {
        std::cerr << "ERROR: Failed to initialize database" << std::endl;
        return 1;
    }

    std::cout << "✓ Database initialized successfully" << std::endl;

    // Initialize auth manager
    AuthConfig auth_config;
    auth_config.jwt_secret = "admin_tool_temp_secret";  // Not used for user creation
    auth_config.bcrypt_rounds = 12;
    auth_config.password_policy = {
        .min_length = 8,
        .require_uppercase = true,
        .require_lowercase = true,
        .require_digit = true,
        .require_special = false
    };

    AuthManager auth(&db, auth_config);

    // Validate username
    if (username.empty() || username.length() > 50) {
        std::cerr << "ERROR: Username must be between 1 and 50 characters" << std::endl;
        return 1;
    }

    // Check if username already exists
    auto existing_user = auth.getUserByUsername(username);
    if (existing_user) {
        std::cerr << "ERROR: Username '" << username << "' already exists" << std::endl;
        std::cerr << "       User ID: " << existing_user->user_id << std::endl;
        std::cerr << "       Created: " << existing_user->created_at.seconds << std::endl;
        std::cerr << "       Roles: ";
        for (size_t i = 0; i < existing_user->roles.size(); ++i) {
            if (i > 0) std::cerr << ", ";
            std::cerr << existing_user->roles[i];
        }
        std::cerr << std::endl;
        return 1;
    }

    // Validate password
    std::string password_error = auth.validatePassword(password);
    if (!password_error.empty()) {
        std::cerr << "ERROR: " << password_error << std::endl;
        return 1;
    }

    std::cout << "✓ Password meets policy requirements" << std::endl;

    // Create admin user
    std::cout << std::endl;
    std::cout << "Creating admin user..." << std::endl;
    std::cout << "  Username: " << username << std::endl;
    if (!email.empty()) {
        std::cout << "  Email:    " << email << std::endl;
    }
    std::cout << "  Roles:    admin, user" << std::endl;

    auto user = auth.createUser(
        username,
        password,
        email,
        {"admin", "user"}  // Admin role + user role
    );

    if (!user) {
        std::cerr << std::endl;
        std::cerr << "ERROR: Failed to create admin user" << std::endl;
        return 1;
    }

    // Success!
    std::cout << std::endl;
    std::cout << "==================================================" << std::endl;
    std::cout << "  ✓ Admin User Created Successfully!" << std::endl;
    std::cout << "==================================================" << std::endl;
    std::cout << std::endl;
    std::cout << "User Details:" << std::endl;
    std::cout << "  User ID:   " << user->user_id << std::endl;
    std::cout << "  Username:  " << user->username << std::endl;
    if (!user->email.empty()) {
        std::cout << "  Email:     " << user->email << std::endl;
    }
    std::cout << "  Roles:     ";
    for (size_t i = 0; i < user->roles.size(); ++i) {
        if (i > 0) std::cout << ", ";
        std::cout << user->roles[i];
    }
    std::cout << std::endl;
    std::cout << "  Active:    " << (user->is_active ? "Yes" : "No") << std::endl;
    std::cout << "  Created:   " << user->created_at.seconds << std::endl;
    std::cout << std::endl;
    std::cout << "You can now login with these credentials:" << std::endl;
    std::cout << "  curl -X POST http://localhost:8080/api/v1/auth/login \\" << std::endl;
    std::cout << "    -H \"Content-Type: application/json\" \\" << std::endl;
    std::cout << "    -d '{\"username\":\"" << username << "\",\"password\":\"YOUR_PASSWORD\"}'" << std::endl;
    std::cout << std::endl;

    return 0;
}
