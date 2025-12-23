#include <algorithm>
#include <cstdlib>
#include <cstring>

#include "pcap_ingest/protocol_framer.h"

namespace callflow {

SipFramer::SipFramer() {
    buffer_.reserve(65536);  // Reserve 64KB for typical SIP messages
}

size_t SipFramer::processData(const uint8_t* data, size_t len) {
    if (!data || len == 0) {
        return 0;
    }

    // Append to buffer
    buffer_.insert(buffer_.end(), data, data + len);

    size_t total_consumed = 0;

    // Process all complete messages in buffer
    while (true) {
        size_t msg_size = findCompleteMessage();
        if (msg_size == 0) {
            break;  // No complete message
        }

        // Deliver complete message
        if (message_callback_) {
            message_callback_(buffer_.data(), msg_size);
        }

        // Remove processed message from buffer
        buffer_.erase(buffer_.begin(), buffer_.begin() + msg_size);
        total_consumed += msg_size;
    }

    return total_consumed;
}

bool SipFramer::flush() {
    if (buffer_.empty()) {
        return false;
    }

    // Deliver any remaining data as-is
    if (message_callback_) {
        message_callback_(buffer_.data(), buffer_.size());
    }

    buffer_.clear();
    return true;
}

void SipFramer::reset() {
    buffer_.clear();
}

int SipFramer::findContentLength(const std::string& headers) {
    // Find Content-Length header (case-insensitive)
    const char* patterns[] = {"Content-Length:", "content-length:", "CONTENT-LENGTH:", "l:"};

    for (const char* pattern : patterns) {
        size_t pos = headers.find(pattern);
        if (pos != std::string::npos) {
            // Find first digit after the colon
            size_t val_start = headers.find_first_of("0123456789", pos + strlen(pattern));
            if (val_start != std::string::npos) {
                return std::atoi(headers.c_str() + val_start);
            }
        }
    }

    return 0;
}

size_t SipFramer::findCompleteMessage() {
    if (buffer_.size() < 4) {
        return 0;  // Need at least \r\n\r\n
    }

    // Find double CRLF (end of headers)
    const char* crlf2 = "\r\n\r\n";
    auto it = std::search(buffer_.begin(), buffer_.end(), crlf2, crlf2 + 4);

    if (it == buffer_.end()) {
        // Headers not complete yet
        // Check if buffer is getting too large without finding headers
        if (buffer_.size() > 65536) {
            // Likely not SIP, or malformed - reset
            buffer_.clear();
        }
        return 0;
    }

    // Calculate header length (including \r\n\r\n)
    size_t headers_len = std::distance(buffer_.begin(), it) + 4;

    // Extract headers as string to parse Content-Length
    std::string headers(buffer_.begin(), buffer_.begin() + headers_len);
    int content_len = findContentLength(headers);

    // Total message size
    size_t total_len = headers_len + content_len;

    // Check if we have the complete message
    if (buffer_.size() >= total_len) {
        return total_len;
    }

    // Still waiting for body
    return 0;
}

}  // namespace callflow
