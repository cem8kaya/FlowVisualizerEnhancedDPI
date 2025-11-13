#include "common/logger.h"
#include <iostream>
#include <iomanip>
#include <ctime>
#include <chrono>

namespace callflow {

Logger& Logger::getInstance() {
    static Logger instance;
    return instance;
}

Logger::Logger() : level_(LogLevel::INFO) {}

void Logger::setLevel(LogLevel level) {
    std::lock_guard<std::mutex> lock(mutex_);
    level_ = level;
}

LogLevel Logger::getLevel() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return level_;
}

void Logger::log(LogLevel level, const std::string& file, int line, const std::string& message) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (level < level_) {
        return;
    }

    // Extract filename from path
    std::string filename = file;
    size_t pos = filename.find_last_of("/\\");
    if (pos != std::string::npos) {
        filename = filename.substr(pos + 1);
    }

    // Format: [timestamp] [LEVEL] [file:line] message
    std::cerr << "[" << getTimestamp() << "] "
              << "[" << levelToString(level) << "] "
              << "[" << filename << ":" << line << "] "
              << message << std::endl;

    if (level == LogLevel::FATAL) {
        std::cerr.flush();
        std::exit(1);
    }
}

std::string Logger::levelToString(LogLevel level) const {
    switch (level) {
        case LogLevel::TRACE: return "TRACE";
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO:  return "INFO ";
        case LogLevel::WARN:  return "WARN ";
        case LogLevel::ERROR: return "ERROR";
        case LogLevel::FATAL: return "FATAL";
        default: return "?????";
    }
}

std::string Logger::getTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto now_time_t = std::chrono::system_clock::to_time_t(now);
    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;

    std::tm tm_buf;
    localtime_r(&now_time_t, &tm_buf);

    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S")
        << '.' << std::setfill('0') << std::setw(3) << now_ms.count();
    return oss.str();
}

}  // namespace callflow
