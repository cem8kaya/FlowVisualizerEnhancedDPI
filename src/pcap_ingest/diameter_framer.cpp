#include "pcap_ingest/protocol_framer.h"

namespace callflow {

DiameterFramer::DiameterFramer() {
    buffer_.reserve(65536);  // Reserve 64KB for typical DIAMETER messages
}

size_t DiameterFramer::processData(const uint8_t* data, size_t len) {
    if (!data || len == 0) {
        return 0;
    }

    // Append to buffer
    buffer_.insert(buffer_.end(), data, data + len);

    size_t total_consumed = 0;

    // Process all complete messages in buffer
    while (buffer_.size() >= 4) {
        // DIAMETER header format:
        // Byte 0: Version (1)
        // Bytes 1-3: Message Length (24-bit, big-endian)
        uint32_t msg_length = parseMessageLength(buffer_.data());

        // Sanity check
        if (msg_length < 20 || msg_length > 16777215) {  // Min 20 bytes, max ~16MB
            // Invalid length, likely not DIAMETER
            buffer_.clear();
            return total_consumed;
        }

        // Check if we have the complete message
        if (buffer_.size() >= msg_length) {
            // Deliver complete message
            if (message_callback_) {
                message_callback_(buffer_.data(), msg_length);
            }

            // Remove processed message from buffer
            buffer_.erase(buffer_.begin(), buffer_.begin() + msg_length);
            total_consumed += msg_length;
        } else {
            // Waiting for more data
            break;
        }
    }

    return total_consumed;
}

bool DiameterFramer::flush() {
    if (buffer_.empty()) {
        return false;
    }

    // For DIAMETER, we don't flush incomplete messages
    // as they would be unparseable
    buffer_.clear();
    return false;
}

void DiameterFramer::reset() {
    buffer_.clear();
}

uint32_t DiameterFramer::parseMessageLength(const uint8_t* data) {
    // Message length is in bytes 1-3 (24-bit big-endian)
    // Byte 0 is version, bytes 1-3 are length
    return (static_cast<uint32_t>(data[1]) << 16) | (static_cast<uint32_t>(data[2]) << 8) |
           static_cast<uint32_t>(data[3]);
}

}  // namespace callflow
