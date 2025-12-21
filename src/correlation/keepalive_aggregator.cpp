#include "correlation/keepalive_aggregator.h"
#include "common/logger.h"
#include <algorithm>
#include <cmath>

namespace callflow {

void KeepAliveAggregator::addEchoRequest(uint32_t teid,
                                          const std::chrono::system_clock::time_point& ts) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto& data = tunnel_data_[teid];

    EchoRecord record;
    record.request_time = ts;
    record.show_individually = false;

    data.echoes.push_back(record);

    LOG_TRACE("Echo Request for TEID 0x{:08x}, count={}", teid, data.echoes.size());
}

void KeepAliveAggregator::addEchoResponse(uint32_t teid,
                                           const std::chrono::system_clock::time_point& ts) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = tunnel_data_.find(teid);
    if (it == tunnel_data_.end()) {
        LOG_WARN("Echo Response for unknown TEID 0x{:08x}", teid);
        return;
    }

    auto& data = it->second;

    // Find the most recent request without a response
    for (auto rit = data.echoes.rbegin(); rit != data.echoes.rend(); ++rit) {
        if (!rit->response_time.has_value()) {
            rit->response_time = ts;

            // Calculate interval
            if (data.echoes.size() > 1) {
                auto prev_it = std::prev(rit.base());
                if (prev_it != data.echoes.begin()) {
                    auto prev_prev_it = std::prev(prev_it);
                    auto interval = std::chrono::duration_cast<std::chrono::seconds>(
                        rit->request_time - prev_prev_it->request_time);

                    // Update current interval
                    if (data.current_interval.count() == 0) {
                        data.current_interval = interval;
                    } else {
                        // Check for significant change
                        if (isSignificantIntervalChange(data.current_interval, interval)) {
                            LOG_DEBUG("Interval change for TEID 0x{:08x}: {}s -> {}s",
                                     teid, data.current_interval.count(), interval.count());
                            rit->show_individually = true;
                            data.current_interval = interval;
                        }
                    }
                }
            }

            LOG_TRACE("Echo Response for TEID 0x{:08x}", teid);
            return;
        }
    }

    LOG_WARN("Echo Response for TEID 0x{:08x} without matching request", teid);
}

std::vector<AggregatedKeepalive> KeepAliveAggregator::getAggregatedKeepalives(
    uint32_t teid) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = tunnel_data_.find(teid);
    if (it == tunnel_data_.end()) {
        return {};
    }

    const auto& data = it->second;

    // Return cached result if finalized
    if (data.is_finalized) {
        return data.aggregated_cache;
    }

    // Generate aggregations on-the-fly
    return generateAggregations(data.echoes);
}

bool KeepAliveAggregator::shouldShowEcho(uint32_t teid,
                                          const std::chrono::system_clock::time_point& ts) const {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = tunnel_data_.find(teid);
    if (it == tunnel_data_.end()) {
        return true;  // Unknown tunnel, show it
    }

    const auto& data = it->second;

    // Find the echo at this timestamp
    for (const auto& echo : data.echoes) {
        if (echo.request_time == ts) {
            return echo.show_individually || echo.is_timeout;
        }
    }

    return false;
}

void KeepAliveAggregator::finalizeTunnel(uint32_t teid) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = tunnel_data_.find(teid);
    if (it == tunnel_data_.end()) {
        return;
    }

    auto& data = it->second;

    // Mark echoes for visualization
    markEchoesForVisualization(data);

    // Generate and cache aggregations
    data.aggregated_cache = generateAggregations(data.echoes);
    data.is_finalized = true;

    LOG_DEBUG("Finalized tunnel 0x{:08x}: {} echoes, {} aggregations",
             teid, data.echoes.size(), data.aggregated_cache.size());
}

KeepAliveAggregator::EchoStats KeepAliveAggregator::getEchoStats(uint32_t teid) const {
    std::lock_guard<std::mutex> lock(mutex_);

    EchoStats stats;

    auto it = tunnel_data_.find(teid);
    if (it == tunnel_data_.end()) {
        return stats;
    }

    const auto& data = it->second;
    stats.request_count = data.echoes.size();

    for (const auto& echo : data.echoes) {
        if (echo.response_time.has_value()) {
            stats.response_count++;
        }
        if (echo.is_timeout) {
            stats.timeout_count++;
        }
    }

    if (!data.echoes.empty()) {
        stats.last_request = data.echoes.back().request_time;

        for (auto rit = data.echoes.rbegin(); rit != data.echoes.rend(); ++rit) {
            if (rit->response_time.has_value()) {
                stats.last_response = *rit->response_time;
                break;
            }
        }
    }

    stats.avg_interval = calculateAverageInterval(data.echoes);

    return stats;
}

void KeepAliveAggregator::clearTunnel(uint32_t teid) {
    std::lock_guard<std::mutex> lock(mutex_);
    tunnel_data_.erase(teid);
}

void KeepAliveAggregator::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    tunnel_data_.clear();
}

std::chrono::seconds KeepAliveAggregator::calculateAverageInterval(
    const std::vector<EchoRecord>& echoes) const {
    if (echoes.size() < 2) {
        return std::chrono::seconds{0};
    }

    std::vector<std::chrono::seconds> intervals;
    for (size_t i = 1; i < echoes.size(); ++i) {
        auto interval = std::chrono::duration_cast<std::chrono::seconds>(
            echoes[i].request_time - echoes[i-1].request_time);
        intervals.push_back(interval);
    }

    if (intervals.empty()) {
        return std::chrono::seconds{0};
    }

    int64_t total = 0;
    for (const auto& interval : intervals) {
        total += interval.count();
    }

    return std::chrono::seconds{total / static_cast<int64_t>(intervals.size())};
}

bool KeepAliveAggregator::isSignificantIntervalChange(
    std::chrono::seconds old_interval,
    std::chrono::seconds new_interval) const {

    if (old_interval.count() == 0) {
        return false;
    }

    double change_ratio = std::abs(static_cast<double>(new_interval.count()) -
                                    static_cast<double>(old_interval.count())) /
                          static_cast<double>(old_interval.count());

    return change_ratio > 0.20;  // 20% threshold
}

std::vector<AggregatedKeepalive> KeepAliveAggregator::generateAggregations(
    const std::vector<EchoRecord>& echoes) const {

    std::vector<AggregatedKeepalive> aggregations;

    if (echoes.empty()) {
        return aggregations;
    }

    AggregatedKeepalive current;
    current.start_time = echoes[0].request_time;
    current.echo_count = 0;
    current.all_successful = true;

    std::vector<std::chrono::seconds> intervals;

    for (size_t i = 0; i < echoes.size(); ++i) {
        const auto& echo = echoes[i];

        // Check if we should break aggregation
        bool should_break = false;

        if (echo.show_individually || echo.is_timeout) {
            should_break = true;
        }

        // First and last echo shown individually
        if (i == 0 || i == echoes.size() - 1) {
            should_break = true;
        }

        if (should_break && current.echo_count > 0) {
            // Finalize current aggregation
            current.end_time = echoes[i - 1].request_time;
            if (!intervals.empty()) {
                int64_t total = 0;
                for (const auto& interval : intervals) {
                    total += interval.count();
                }
                current.avg_interval = std::chrono::seconds{
                    total / static_cast<int64_t>(intervals.size())};
            }
            aggregations.push_back(current);

            // Reset for next aggregation
            current = AggregatedKeepalive();
            current.start_time = echo.request_time;
            current.echo_count = 0;
            current.all_successful = true;
            intervals.clear();
        }

        // Add to current aggregation
        if (!should_break) {
            current.echo_count++;
            if (!echo.response_time.has_value()) {
                current.all_successful = false;
            }

            if (i > 0) {
                auto interval = std::chrono::duration_cast<std::chrono::seconds>(
                    echo.request_time - echoes[i-1].request_time);
                intervals.push_back(interval);
            }
        }
    }

    // Finalize last aggregation
    if (current.echo_count > 0) {
        current.end_time = echoes.back().request_time;
        if (!intervals.empty()) {
            int64_t total = 0;
            for (const auto& interval : intervals) {
                total += interval.count();
            }
            current.avg_interval = std::chrono::seconds{
                total / static_cast<int64_t>(intervals.size())};
        }
        aggregations.push_back(current);
    }

    return aggregations;
}

void KeepAliveAggregator::markEchoesForVisualization(TunnelEchoData& data) {
    if (data.echoes.empty()) {
        return;
    }

    // First echo always shown
    data.echoes[0].show_individually = true;

    // Last echo always shown
    if (data.echoes.size() > 1) {
        data.echoes.back().show_individually = true;
    }

    // Check for timeouts
    auto timeout_threshold = std::chrono::seconds{900};  // 15 minutes
    if (data.current_interval.count() > 0) {
        timeout_threshold = data.current_interval * 3;
    }

    for (size_t i = 0; i < data.echoes.size(); ++i) {
        auto& echo = data.echoes[i];

        if (!echo.response_time.has_value()) {
            // Check if this is a timeout
            if (i < data.echoes.size() - 1) {
                auto next_request = data.echoes[i + 1].request_time;
                auto wait_time = std::chrono::duration_cast<std::chrono::seconds>(
                    next_request - echo.request_time);

                if (wait_time > timeout_threshold) {
                    echo.is_timeout = true;
                    echo.show_individually = true;
                    LOG_DEBUG("Echo timeout detected: waited {}s", wait_time.count());
                }
            }
        }
    }
}

} // namespace callflow
