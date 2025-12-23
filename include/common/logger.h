#pragma once

// Suppress GNU extension warning for variadic macros
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
#endif

#include <fmt/core.h>
#include <fmt/ostream.h>

#include <memory>
#include <mutex>
#include <sstream>
#include <string>

namespace callflow {

enum class LogLevel { TRACE = 0, DEBUG = 1, INFO = 2, WARN = 3, ERROR = 4, FATAL = 5 };

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
#define LOG_MACRO_CHOOSER(_1, _2, _3, _4, _5, _6, _7, _8, NAME, ...) NAME

#define LOG_STREAM(level, msg)                                                     \
    do {                                                                           \
        std::ostringstream oss;                                                    \
        oss << msg;                                                                \
        callflow::Logger::getInstance().log(level, __FILE__, __LINE__, oss.str()); \
    } while (0)

#define LOG_FMT(level, msg, ...)                                              \
    do {                                                                      \
        callflow::Logger::getInstance().log(level, __FILE__, __LINE__,        \
                                            fmt::format(msg, ##__VA_ARGS__)); \
    } while (0)

#define LOG_TRACE(...)                                                                            \
    LOG_MACRO_CHOOSER(__VA_ARGS__, LOG_FMT, LOG_FMT, LOG_FMT, LOG_FMT, LOG_FMT, LOG_FMT, LOG_FMT, \
                      LOG_STREAM, DUMMY_ARG)(callflow::LogLevel::TRACE, __VA_ARGS__)
#define LOG_DEBUG(...)                                                                            \
    LOG_MACRO_CHOOSER(__VA_ARGS__, LOG_FMT, LOG_FMT, LOG_FMT, LOG_FMT, LOG_FMT, LOG_FMT, LOG_FMT, \
                      LOG_STREAM, DUMMY_ARG)(callflow::LogLevel::DEBUG, __VA_ARGS__)
#define LOG_INFO(...)                                                                             \
    LOG_MACRO_CHOOSER(__VA_ARGS__, LOG_FMT, LOG_FMT, LOG_FMT, LOG_FMT, LOG_FMT, LOG_FMT, LOG_FMT, \
                      LOG_STREAM, DUMMY_ARG)(callflow::LogLevel::INFO, __VA_ARGS__)
#define LOG_WARN(...)                                                                             \
    LOG_MACRO_CHOOSER(__VA_ARGS__, LOG_FMT, LOG_FMT, LOG_FMT, LOG_FMT, LOG_FMT, LOG_FMT, LOG_FMT, \
                      LOG_STREAM, DUMMY_ARG)(callflow::LogLevel::WARN, __VA_ARGS__)
#define LOG_ERROR(...)                                                                            \
    LOG_MACRO_CHOOSER(__VA_ARGS__, LOG_FMT, LOG_FMT, LOG_FMT, LOG_FMT, LOG_FMT, LOG_FMT, LOG_FMT, \
                      LOG_STREAM, DUMMY_ARG)(callflow::LogLevel::ERROR, __VA_ARGS__)
#define LOG_FATAL(...)                                                                            \
    LOG_MACRO_CHOOSER(__VA_ARGS__, LOG_FMT, LOG_FMT, LOG_FMT, LOG_FMT, LOG_FMT, LOG_FMT, LOG_FMT, \
                      LOG_STREAM, DUMMY_ARG)(callflow::LogLevel::FATAL, __VA_ARGS__)

}  // namespace callflow

#if defined(__clang__)
#pragma clang diagnostic pop
#endif
