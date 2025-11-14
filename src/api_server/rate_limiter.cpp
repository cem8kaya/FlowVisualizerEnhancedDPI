/**
 * @file rate_limiter.cpp
 * @brief Implementation of rate limiting
 */

#include "api_server/rate_limiter.h"
#include "common/logger.h"

namespace callflow {

RateLimiter::RateLimiter(const Config& config) : config_(config) {
  LOG_INFO("Rate limiter initialized: {} req/min, burst {}",
           config_.requests_per_minute, config_.burst_size);
}

RateLimiter::~RateLimiter() = default;

bool RateLimiter::allowRequest(const std::string& client_id) {
  std::lock_guard<std::mutex> lock(mutex_);

  auto now = std::chrono::steady_clock::now();
  auto& state = clients_[client_id];

  // Remove requests older than 1 minute (sliding window)
  auto cutoff = now - std::chrono::minutes(1);
  while (!state.request_times.empty() &&
         state.request_times.front() < cutoff) {
    state.request_times.pop_front();
  }

  // Check per-minute rate limit
  if (static_cast<int>(state.request_times.size()) >=
      config_.requests_per_minute) {
    LOG_WARN("Rate limit exceeded for client: {} ({} req/min)",
             client_id, state.request_times.size());
    return false;
  }

  // Check burst limit (requests in last 10 seconds)
  auto burst_cutoff = now - std::chrono::seconds(10);
  int burst_count = 0;
  for (const auto& time : state.request_times) {
    if (time > burst_cutoff) {
      burst_count++;
    }
  }

  if (burst_count >= config_.burst_size) {
    LOG_WARN("Burst limit exceeded for client: {} ({} req/10s)",
             client_id, burst_count);
    return false;
  }

  // Allow request
  state.request_times.push_back(now);
  state.last_request = now;
  return true;
}

RateLimiter::RateLimitInfo RateLimiter::getRateLimitInfo(
    const std::string& client_id) {
  std::lock_guard<std::mutex> lock(mutex_);

  auto now = std::chrono::steady_clock::now();
  auto& state = clients_[client_id];

  // Remove expired requests
  auto cutoff = now - std::chrono::minutes(1);
  while (!state.request_times.empty() &&
         state.request_times.front() < cutoff) {
    state.request_times.pop_front();
  }

  RateLimitInfo info;
  info.limit = config_.requests_per_minute;
  info.remaining = config_.requests_per_minute -
                   static_cast<int>(state.request_times.size());

  if (!state.request_times.empty()) {
    auto oldest = state.request_times.front();
    auto reset_time = oldest + std::chrono::minutes(1);
    info.reset_seconds = std::chrono::duration_cast<std::chrono::seconds>(
                             reset_time - now)
                             .count();
  } else {
    info.reset_seconds = 60;
  }

  return info;
}

void RateLimiter::reset() {
  std::lock_guard<std::mutex> lock(mutex_);
  clients_.clear();
  LOG_INFO("Rate limiter reset");
}

void RateLimiter::cleanup() {
  std::lock_guard<std::mutex> lock(mutex_);

  auto now = std::chrono::steady_clock::now();
  auto cleanup_cutoff =
      now - std::chrono::seconds(config_.cleanup_interval_sec);

  size_t removed = 0;
  for (auto it = clients_.begin(); it != clients_.end();) {
    if (it->second.last_request < cleanup_cutoff) {
      it = clients_.erase(it);
      removed++;
    } else {
      ++it;
    }
  }

  if (removed > 0) {
    LOG_DEBUG("Rate limiter cleanup: removed {} idle clients", removed);
  }
}

bool RateLimiter::isRateLimited(ClientState& state) {
  auto now = std::chrono::steady_clock::now();
  auto cutoff = now - std::chrono::minutes(1);

  // Remove old requests
  while (!state.request_times.empty() &&
         state.request_times.front() < cutoff) {
    state.request_times.pop_front();
  }

  return static_cast<int>(state.request_times.size()) >=
         config_.requests_per_minute;
}

}  // namespace callflow
