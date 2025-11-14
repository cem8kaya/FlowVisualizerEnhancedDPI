/**
 * @file rate_limiter.h
 * @brief Rate limiting for API endpoints to prevent abuse
 *
 * Implements token bucket algorithm with per-client tracking.
 * Milestone 5: Production Hardening
 */

#pragma once

#include <chrono>
#include <deque>
#include <map>
#include <mutex>
#include <string>

namespace callflow {

/**
 * @brief Rate limiter using sliding window algorithm
 *
 * Tracks request timestamps per client and enforces configurable
 * rate limits with burst support.
 */
class RateLimiter {
 public:
  /**
   * @brief Configuration for rate limiting
   */
  struct Config {
    int requests_per_minute = 60;  ///< Max requests per minute
    int burst_size = 10;            ///< Max burst requests (in 10 seconds)
    int cleanup_interval_sec = 300; ///< Cleanup interval for old entries
  };

  /**
   * @brief Construct rate limiter with configuration
   * @param config Rate limiting configuration
   */
  explicit RateLimiter(const Config& config);

  /**
   * @brief Destructor
   */
  ~RateLimiter();

  /**
   * @brief Check if a request from a client is allowed
   * @param client_id Unique identifier for the client (IP address, user ID)
   * @return true if request is allowed, false if rate limited
   */
  bool allowRequest(const std::string& client_id);

  /**
   * @brief Get rate limit information for a client
   * @param client_id Client identifier
   * @return Rate limit information
   */
  struct RateLimitInfo {
    int limit;           ///< Max requests per minute
    int remaining;       ///< Remaining requests in current window
    int reset_seconds;   ///< Seconds until rate limit resets
  };
  RateLimitInfo getRateLimitInfo(const std::string& client_id);

  /**
   * @brief Reset all rate limit data
   *
   * Useful for testing or manual reset.
   */
  void reset();

  /**
   * @brief Cleanup expired entries
   *
   * Removes client entries that haven't made requests recently.
   */
  void cleanup();

 private:
  Config config_;

  /**
   * @brief Per-client state
   */
  struct ClientState {
    std::deque<std::chrono::steady_clock::time_point> request_times;
    std::chrono::steady_clock::time_point last_request;
  };

  std::map<std::string, ClientState> clients_;
  std::mutex mutex_;

  /**
   * @brief Check if a client is rate limited
   * @param state Client state
   * @return true if rate limited
   */
  bool isRateLimited(ClientState& state);
};

}  // namespace callflow
