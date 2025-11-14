/**
 * @file input_validator.h
 * @brief Input validation and sanitization for security
 *
 * Prevents path traversal, SQL injection, XSS, and validates file uploads.
 * Milestone 5: Production Hardening
 */

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace callflow {

/**
 * @brief Input validation utilities
 *
 * Provides static methods for validating and sanitizing various input types
 * to prevent security vulnerabilities.
 */
class InputValidator {
 public:
  // File validation
  static bool isValidPcapFile(const std::string& filename);
  static bool isValidFileSize(size_t size,
                               size_t max_size = 10ULL * 1024 * 1024 * 1024);
  static bool hasValidPcapMagicNumber(const uint8_t* data, size_t len);

  // String validation
  static bool isValidUsername(const std::string& username);
  static bool isValidEmail(const std::string& email);
  static bool isValidPassword(const std::string& password);
  static bool isValidJobId(const std::string& job_id);
  static bool isValidSessionId(const std::string& session_id);
  static bool isValidUUID(const std::string& uuid);

  // Sanitization
  static std::string sanitizeFilename(const std::string& filename);
  static std::string sanitizeString(const std::string& input);
  static std::string escapeJson(const std::string& input);

  // Path validation (prevent path traversal)
  static bool isValidPath(const std::string& path);
  static bool containsPathTraversal(const std::string& path);

  // Numeric validation
  static bool isValidPort(int port);
  static bool isValidPagination(int page, int limit);

  /**
   * @brief Validation error
   */
  struct ValidationError {
    std::string field;
    std::string message;
  };

  /**
   * @brief Validate upload request
   * @param filename Upload filename
   * @param file_size File size in bytes
   * @param file_data Optional file data for magic number check
   * @param data_len Length of file data
   * @return Validation error if invalid, nullopt if valid
   */
  static std::optional<ValidationError> validateUploadRequest(
      const std::string& filename, size_t file_size,
      const uint8_t* file_data = nullptr, size_t data_len = 0);

  /**
   * @brief Validate registration request
   */
  static std::optional<ValidationError> validateRegistration(
      const std::string& username, const std::string& password,
      const std::string& email);

 private:
  static const size_t MAX_USERNAME_LENGTH = 50;
  static const size_t MAX_PASSWORD_LENGTH = 128;
  static const size_t MIN_PASSWORD_LENGTH = 8;
  static const size_t MAX_EMAIL_LENGTH = 255;
  static const std::vector<std::string> ALLOWED_EXTENSIONS;

  // PCAP magic numbers
  static const uint32_t PCAP_MAGIC_NUMBER = 0xa1b2c3d4;
  static const uint32_t PCAP_MAGIC_NUMBER_SWAPPED = 0xd4c3b2a1;
  static const uint32_t PCAPNG_MAGIC_NUMBER = 0x0a0d0d0a;
};

}  // namespace callflow
