#pragma once

#include <string>
#include <memory>
#include <sstream>
#include <mutex>

namespace callflow {

enum class LogLevel {
    TRACE = 0,
    DEBUG = 1,
    INFO = 2,
    WARN = 3,
    ERROR = 4,
    FATAL = 5
};

/**
 * Simple thread-safe logger
 */
class Logger {
public:
    static Logger& getInstance();

    void setLevel(LogLevel level);
    LogLevel getLevel() const;

    void log(LogLevel level, const std::string& file, int line, const std::string& message);

    // Disable copy/move
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

private:
    Logger();
    ~Logger() = default;

    LogLevel level_;
    mutable std::mutex mutex_;

    std::string levelToString(LogLevel level) const;
    std::string getTimestamp() const;
};

// Helper macros for logging
#define LOG_TRACE(msg) do { \
    std::ostringstream oss; \
    oss << msg; \
    callflow::Logger::getInstance().log(callflow::LogLevel::TRACE, __FILE__, __LINE__, oss.str()); \
} while(0)

#define LOG_DEBUG(msg) do { \
    std::ostringstream oss; \
    oss << msg; \
    callflow::Logger::getInstance().log(callflow::LogLevel::DEBUG, __FILE__, __LINE__, oss.str()); \
} while(0)

#define LOG_INFO(msg) do { \
    std::ostringstream oss; \
    oss << msg; \
    callflow::Logger::getInstance().log(callflow::LogLevel::INFO, __FILE__, __LINE__, oss.str()); \
} while(0)

#define LOG_WARN(msg) do { \
    std::ostringstream oss; \
    oss << msg; \
    callflow::Logger::getInstance().log(callflow::LogLevel::WARN, __FILE__, __LINE__, oss.str()); \
} while(0)

#define LOG_ERROR(msg) do { \
    std::ostringstream oss; \
    oss << msg; \
    callflow::Logger::getInstance().log(callflow::LogLevel::ERROR, __FILE__, __LINE__, oss.str()); \
} while(0)

#define LOG_FATAL(msg) do { \
    std::ostringstream oss; \
    oss << msg; \
    callflow::Logger::getInstance().log(callflow::LogLevel::FATAL, __FILE__, __LINE__, oss.str()); \
} while(0)

}  // namespace callflow
