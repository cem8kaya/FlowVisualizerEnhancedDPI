#include "pcap_ingest/protocol_framer.h"

#include <cstring>

namespace callflow {

// HTTP/2 connection preface
static const char HTTP2_PREFACE[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
static const size_t HTTP2_PREFACE_LEN = 24;

Http2Framer::Http2Framer() {
    buffer_.reserve(65536);  // Reserve 64KB
}

size_t Http2Framer::processData(const uint8_t* data, size_t len) {
    if (!data || len == 0) {
        return 0;
    }

    // Append to buffer
    buffer_.insert(buffer_.end(), data, data + len);

    size_t total_consumed = 0;

    // Check for connection preface if not yet received
    if (!preface_received_) {
        if (buffer_.size() >= HTTP2_PREFACE_LEN) {
            if (detectPreface(buffer_.data(), buffer_.size())) {
                preface_received_ = true;
                // Consume preface
                buffer_.erase(buffer_.begin(), buffer_.begin() + HTTP2_PREFACE_LEN);
                total_consumed += HTTP2_PREFACE_LEN;
            } else {
                // Not HTTP/2, reset
                buffer_.clear();
                return 0;
            }
        } else {
            // Wait for more data
            return 0;
        }
    }

    // Process HTTP/2 frames
    while (buffer_.size() >= 9) {  // Frame header is 9 bytes
        uint32_t frame_length = parseFrameLength(buffer_.data());

        // Sanity check (max frame size is 16MB - 1)
        if (frame_length > 16777215) {
            // Invalid frame length
            buffer_.clear();
            return total_consumed;
        }

        // Total frame size = 9 (header) + payload
        size_t total_frame_size = 9 + frame_length;

        // Check if we have the complete frame
        if (buffer_.size() >= total_frame_size) {
            // Deliver complete frame
            if (message_callback_) {
                message_callback_(buffer_.data(), total_frame_size);
            }

            // Remove processed frame from buffer
            buffer_.erase(buffer_.begin(), buffer_.begin() + total_frame_size);
            total_consumed += total_frame_size;
        } else {
            // Waiting for more data
            break;
        }
    }

    return total_consumed;
}

bool Http2Framer::flush() {
    if (buffer_.empty()) {
        return false;
    }

    // For HTTP/2, we don't flush incomplete frames
    buffer_.clear();
    return false;
}

void Http2Framer::reset() {
    buffer_.clear();
    preface_received_ = false;
}

bool Http2Framer::detectPreface(const uint8_t* data, size_t len) {
    if (len < HTTP2_PREFACE_LEN) {
        return false;
    }

    return memcmp(data, HTTP2_PREFACE, HTTP2_PREFACE_LEN) == 0;
}

uint32_t Http2Framer::parseFrameLength(const uint8_t* data) {
    // Frame length is first 3 bytes (24-bit big-endian)
    return (static_cast<uint32_t>(data[0]) << 16) | (static_cast<uint32_t>(data[1]) << 8) |
           static_cast<uint32_t>(data[2]);
}

}  // namespace callflow
