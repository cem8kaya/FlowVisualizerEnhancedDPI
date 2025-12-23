#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace callflow {

/**
 * Base class for protocol framers
 * Handles message boundary detection for stream-based protocols
 */
class ProtocolFramer {
public:
    using MessageCallback = std::function<void(const uint8_t*, size_t)>;

    virtual ~ProtocolFramer() = default;

    /**
     * Process incoming stream data and extract complete messages
     * @param data Pointer to data
     * @param len Length of data
     * @return Number of bytes consumed
     */
    virtual size_t processData(const uint8_t* data, size_t len) = 0;

    /**
     * Set callback for complete messages
     */
    void setMessageCallback(MessageCallback cb) { message_callback_ = std::move(cb); }

    /**
     * Flush any pending data (e.g., on connection close)
     * @return True if data was flushed
     */
    virtual bool flush() = 0;

    /**
     * Reset framer state
     */
    virtual void reset() = 0;

protected:
    MessageCallback message_callback_;
};

/**
 * SIP Protocol Framer
 * Detects SIP message boundaries using \r\n\r\n and Content-Length
 */
class SipFramer : public ProtocolFramer {
public:
    SipFramer();
    ~SipFramer() override = default;

    size_t processData(const uint8_t* data, size_t len) override;
    bool flush() override;
    void reset() override;

private:
    std::vector<uint8_t> buffer_;

    /**
     * Find Content-Length header value
     * @param headers Headers section (up to \r\n\r\n)
     * @return Content-Length value or 0 if not found
     */
    int findContentLength(const std::string& headers);

    /**
     * Check if buffer contains a complete SIP message
     * @return Size of complete message, or 0 if incomplete
     */
    size_t findCompleteMessage();
};

/**
 * DIAMETER Protocol Framer
 * Detects DIAMETER message boundaries using 4-byte length field
 */
class DiameterFramer : public ProtocolFramer {
public:
    DiameterFramer();
    ~DiameterFramer() override = default;

    size_t processData(const uint8_t* data, size_t len) override;
    bool flush() override;
    void reset() override;

private:
    std::vector<uint8_t> buffer_;

    /**
     * Parse DIAMETER header to get message length
     * @param data Pointer to at least 4 bytes
     * @return Message length from header
     */
    uint32_t parseMessageLength(const uint8_t* data);
};

/**
 * HTTP/2 Protocol Framer
 * Detects HTTP/2 frames using connection preface and frame headers
 */
class Http2Framer : public ProtocolFramer {
public:
    Http2Framer();
    ~Http2Framer() override = default;

    size_t processData(const uint8_t* data, size_t len) override;
    bool flush() override;
    void reset() override;

    /**
     * Check if data starts with HTTP/2 connection preface
     * @param data Pointer to data
     * @param len Length of data
     * @return True if preface detected
     */
    static bool detectPreface(const uint8_t* data, size_t len);

private:
    std::vector<uint8_t> buffer_;
    bool preface_received_ = false;

    /**
     * Parse HTTP/2 frame header to get frame length
     * @param data Pointer to at least 9 bytes (frame header size)
     * @return Frame payload length
     */
    uint32_t parseFrameLength(const uint8_t* data);
};

}  // namespace callflow
