#pragma once

#include <chrono>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

namespace callflow {
namespace utils {

/**
 * Generate a UUID (v4)
 */
std::string generateUuid();

/**
 * Convert timestamp to ISO 8601 string
 */
std::string timestampToIso8601(const std::chrono::system_clock::time_point& tp);

/**
 * Parse ISO 8601 string to timestamp
 */
std::chrono::system_clock::time_point iso8601ToTimestamp(const std::string& str);

/**
 * Convert IP address from uint32_t to string (for IPv4)
 */
std::string ipToString(uint32_t ip);

/**
 * Convert IP address from string to uint32_t (for IPv4)
 */
uint32_t stringToIp(const std::string& ip_str);

/**
 * Convert bytes to hex string
 */
std::string bytesToHex(const uint8_t* data, size_t len);

/**
 * Convert hex string to bytes
 */
std::vector<uint8_t> hexToBytes(const std::string& hex);

/**
 * Convert BCD to string
 * @param data Buffer containing BCD data
 * @param len Length of buffer
 * @param skip_first_nibble If true, skip the lower nibble of the first byte (used for identities)
 */
std::string bcdToString(const uint8_t* data, size_t len, bool skip_first_nibble = false);

/**
 * Convert integer to hex string
 */
template <typename T>
std::string toHexString(T val) {
    std::stringstream ss;
    ss << std::hex << std::uppercase << std::setfill('0') << std::setw(sizeof(T) * 2)
       << (uint64_t)val;
    return ss.str();
}

/**
 * Convert bytes to base64
 */
std::string bytesToBase64(const uint8_t* data, size_t len);

/**
 * Decode base64 to bytes
 */
std::vector<uint8_t> base64ToBytes(const std::string& base64);

/**
 * Calculate hash of a buffer
 */
uint64_t hashBuffer(const void* data, size_t len);

/**
 * Get current timestamp
 */
std::chrono::system_clock::time_point now();

/**
 * Calculate time difference in milliseconds
 */
int64_t timeDiffMs(const std::chrono::system_clock::time_point& start,
                   const std::chrono::system_clock::time_point& end);

/**
 * Sanitize string for JSON output (escape special characters)
 */
std::string sanitizeString(const std::string& str);

}  // namespace utils
}  // namespace callflow
