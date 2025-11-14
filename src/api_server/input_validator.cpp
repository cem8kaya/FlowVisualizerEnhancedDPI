/**
 * @file input_validator.cpp
 * @brief Implementation of input validation
 */

#include "api_server/input_validator.h"
#include "common/logger.h"

#include <algorithm>
#include <cctype>
#include <regex>

namespace callflow {

const std::vector<std::string> InputValidator::ALLOWED_EXTENSIONS = {
    ".pcap", ".pcapng", ".cap"};

bool InputValidator::isValidPcapFile(const std::string& filename) {
  // Check if filename ends with allowed extension
  for (const auto& ext : ALLOWED_EXTENSIONS) {
    if (filename.size() >= ext.size() &&
        filename.compare(filename.size() - ext.size(), ext.size(), ext) == 0) {
      return true;
    }
  }
  return false;
}

bool InputValidator::isValidFileSize(size_t size, size_t max_size) {
  return size > 0 && size <= max_size;
}

bool InputValidator::hasValidPcapMagicNumber(const uint8_t* data, size_t len) {
  if (len < 4) {
    return false;
  }

  uint32_t magic;
  std::memcpy(&magic, data, sizeof(magic));

  return magic == PCAP_MAGIC_NUMBER || magic == PCAP_MAGIC_NUMBER_SWAPPED ||
         magic == PCAPNG_MAGIC_NUMBER;
}

bool InputValidator::isValidUsername(const std::string& username) {
  if (username.empty() || username.length() > MAX_USERNAME_LENGTH) {
    return false;
  }

  // Username must contain only alphanumeric, underscore, hyphen, dot
  static const std::regex username_regex("^[a-zA-Z0-9_.-]+$");
  return std::regex_match(username, username_regex);
}

bool InputValidator::isValidEmail(const std::string& email) {
  if (email.empty() || email.length() > MAX_EMAIL_LENGTH) {
    return false;
  }

  // Basic email validation
  static const std::regex email_regex(
      R"(^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$)");
  return std::regex_match(email, email_regex);
}

bool InputValidator::isValidPassword(const std::string& password) {
  if (password.length() < MIN_PASSWORD_LENGTH ||
      password.length() > MAX_PASSWORD_LENGTH) {
    return false;
  }

  // Password policy: at least one uppercase, one lowercase, one digit
  bool has_upper = false;
  bool has_lower = false;
  bool has_digit = false;

  for (char c : password) {
    if (std::isupper(c))
      has_upper = true;
    if (std::islower(c))
      has_lower = true;
    if (std::isdigit(c))
      has_digit = true;
  }

  return has_upper && has_lower && has_digit;
}

bool InputValidator::isValidJobId(const std::string& job_id) {
  if (job_id.empty() || job_id.length() > 64) {
    return false;
  }

  // Job ID should be alphanumeric with hyphens
  static const std::regex job_id_regex("^[a-zA-Z0-9-]+$");
  return std::regex_match(job_id, job_id_regex);
}

bool InputValidator::isValidSessionId(const std::string& session_id) {
  if (session_id.empty() || session_id.length() > 128) {
    return false;
  }

  // Session ID can be alphanumeric with some special chars
  static const std::regex session_id_regex("^[a-zA-Z0-9@._-]+$");
  return std::regex_match(session_id, session_id_regex);
}

bool InputValidator::isValidUUID(const std::string& uuid) {
  static const std::regex uuid_regex(
      "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");
  return std::regex_match(uuid, uuid_regex);
}

std::string InputValidator::sanitizeFilename(const std::string& filename) {
  std::string sanitized;
  sanitized.reserve(filename.size());

  for (char c : filename) {
    // Allow alphanumeric, underscore, hyphen, dot
    if (std::isalnum(c) || c == '_' || c == '-' || c == '.') {
      sanitized += c;
    } else {
      sanitized += '_';
    }
  }

  return sanitized;
}

std::string InputValidator::sanitizeString(const std::string& input) {
  std::string sanitized;
  sanitized.reserve(input.size());

  for (char c : input) {
    // Remove control characters
    if (std::iscntrl(c) && c != '\n' && c != '\r' && c != '\t') {
      continue;
    }
    sanitized += c;
  }

  return sanitized;
}

std::string InputValidator::escapeJson(const std::string& input) {
  std::string escaped;
  escaped.reserve(input.size() * 2);

  for (char c : input) {
    switch (c) {
      case '"':
        escaped += "\\\"";
        break;
      case '\\':
        escaped += "\\\\";
        break;
      case '\b':
        escaped += "\\b";
        break;
      case '\f':
        escaped += "\\f";
        break;
      case '\n':
        escaped += "\\n";
        break;
      case '\r':
        escaped += "\\r";
        break;
      case '\t':
        escaped += "\\t";
        break;
      default:
        if (std::iscntrl(c)) {
          // Escape other control characters
          char buf[8];
          snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned char>(c));
          escaped += buf;
        } else {
          escaped += c;
        }
        break;
    }
  }

  return escaped;
}

bool InputValidator::isValidPath(const std::string& path) {
  if (path.empty()) {
    return false;
  }

  // Check for path traversal
  if (containsPathTraversal(path)) {
    return false;
  }

  // Path should not contain null bytes or other dangerous characters
  for (char c : path) {
    if (c == '\0' || std::iscntrl(c)) {
      return false;
    }
  }

  return true;
}

bool InputValidator::containsPathTraversal(const std::string& path) {
  // Check for .. path traversal sequences
  return path.find("..") != std::string::npos ||
         path.find("/../") != std::string::npos ||
         path.find("\\..\\") != std::string::npos;
}

bool InputValidator::isValidPort(int port) {
  return port > 0 && port <= 65535;
}

bool InputValidator::isValidPagination(int page, int limit) {
  return page >= 0 && limit > 0 && limit <= 1000;
}

std::optional<InputValidator::ValidationError>
InputValidator::validateUploadRequest(const std::string& filename,
                                       size_t file_size,
                                       const uint8_t* file_data,
                                       size_t data_len) {
  // Validate filename
  if (filename.empty()) {
    return ValidationError{"filename", "Filename cannot be empty"};
  }

  if (containsPathTraversal(filename)) {
    return ValidationError{"filename",
                           "Filename contains path traversal sequences"};
  }

  if (!isValidPcapFile(filename)) {
    return ValidationError{
        "filename", "Invalid file extension. Allowed: .pcap, .pcapng, .cap"};
  }

  // Validate file size (10GB max)
  if (!isValidFileSize(file_size, 10ULL * 1024 * 1024 * 1024)) {
    return ValidationError{"file_size",
                           "File size must be > 0 and <= 10GB"};
  }

  // Validate magic number if data provided
  if (file_data != nullptr && data_len > 0) {
    if (!hasValidPcapMagicNumber(file_data, data_len)) {
      return ValidationError{"file_content",
                             "Invalid PCAP file format (magic number check failed)"};
    }
  }

  return std::nullopt;
}

std::optional<InputValidator::ValidationError>
InputValidator::validateRegistration(const std::string& username,
                                      const std::string& password,
                                      const std::string& email) {
  // Validate username
  if (!isValidUsername(username)) {
    return ValidationError{
        "username",
        "Username must be 1-50 characters and contain only alphanumeric, "
        "underscore, hyphen, or dot"};
  }

  // Validate password
  if (!isValidPassword(password)) {
    return ValidationError{
        "password",
        "Password must be 8-128 characters with at least one uppercase, "
        "lowercase, and digit"};
  }

  // Validate email
  if (!email.empty() && !isValidEmail(email)) {
    return ValidationError{"email", "Invalid email format"};
  }

  return std::nullopt;
}

}  // namespace callflow
