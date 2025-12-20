#include "protocol_parsers/http2_parser.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <sstream>

#include "common/logger.h"

namespace callflow {

// HTTP/2 connection preface
static const char* HTTP2_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
static const size_t HTTP2_PREFACE_LEN = 24;

// Frame header size
static const size_t FRAME_HEADER_SIZE = 9;

// ============================================================================
// Helper Functions
// ============================================================================

std::string http2FrameTypeToString(Http2FrameType type) {
    switch (type) {
        case Http2FrameType::DATA:
            return "DATA";
        case Http2FrameType::HEADERS:
            return "HEADERS";
        case Http2FrameType::PRIORITY:
            return "PRIORITY";
        case Http2FrameType::RST_STREAM:
            return "RST_STREAM";
        case Http2FrameType::SETTINGS:
            return "SETTINGS";
        case Http2FrameType::PUSH_PROMISE:
            return "PUSH_PROMISE";
        case Http2FrameType::PING:
            return "PING";
        case Http2FrameType::GOAWAY:
            return "GOAWAY";
        case Http2FrameType::WINDOW_UPDATE:
            return "WINDOW_UPDATE";
        case Http2FrameType::CONTINUATION:
            return "CONTINUATION";
        default:
            return "UNKNOWN";
    }
}

// ============================================================================
// JSON Serialization
// ============================================================================

nlohmann::json Http2FrameHeader::toJson() const {
    nlohmann::json j;
    j["length"] = length;
    j["type"] = http2FrameTypeToString(type);
    j["flags"] = flags;
    j["stream_id"] = stream_id;
    return j;
}

nlohmann::json Http2Frame::toJson() const {
    nlohmann::json j;
    j["header"] = header.toJson();
    j["payload_size"] = payload.size();
    return j;
}

nlohmann::json Http2Stream::toJson() const {
    nlohmann::json j;
    j["stream_id"] = stream_id;
    if (!method.empty())
        j["method"] = method;
    if (!path.empty())
        j["path"] = path;
    if (!authority.empty())
        j["authority"] = authority;
    if (!scheme.empty())
        j["scheme"] = scheme;
    if (status_code > 0)
        j["status"] = status_code;

    if (!request_headers.empty())
        j["request_headers"] = request_headers;
    if (!response_headers.empty())
        j["response_headers"] = response_headers;

    j["request_complete"] = request_complete;
    j["response_complete"] = response_complete;

    if (!request_data.empty())
        j["request_data_size"] = request_data.size();
    if (!response_data.empty())
        j["response_data_size"] = response_data.size();

    // Calculate latency if both available
    if (start_time.time_since_epoch().count() > 0 && end_time.time_since_epoch().count() > 0) {
        auto duration =
            std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count();
        j["latency_us"] = duration;
    }

    return j;
}

nlohmann::json Http2Connection::toJson() const {
    nlohmann::json j;
    j["preface_received"] = preface_received;
    j["stream_count"] = streams.size();
    j["frame_count"] = frames.size();

    nlohmann::json settings;
    settings["header_table_size"] = header_table_size;
    settings["enable_push"] = enable_push;
    settings["max_concurrent_streams"] = max_concurrent_streams;
    settings["initial_window_size"] = initial_window_size;
    settings["max_frame_size"] = max_frame_size;
    settings["max_header_list_size"] = max_header_list_size;
    j["settings"] = settings;

    nlohmann::json streams_json = nlohmann::json::array();
    for (const auto& [id, stream] : streams) {
        streams_json.push_back(stream.toJson());
    }
    j["streams"] = streams_json;

    return j;
}

// ============================================================================
// HPACK Decoder Implementation
// ============================================================================

// HPACK static table (RFC 7541 Appendix A)
const std::vector<std::pair<std::string, std::string>> HpackDecoder::static_table_ =
    HpackDecoder::initStaticTable();

std::vector<std::pair<std::string, std::string>> HpackDecoder::initStaticTable() {
    return {{"", ""},
            {":authority", ""},
            {":method", "GET"},
            {":method", "POST"},
            {":path", "/"},
            {":path", "/index.html"},
            {":scheme", "http"},
            {":scheme", "https"},
            {":status", "200"},
            {":status", "204"},
            {":status", "206"},
            {":status", "304"},
            {":status", "400"},
            {":status", "404"},
            {":status", "500"},
            {"accept-charset", ""},
            {"accept-encoding", "gzip, deflate"},
            {"accept-language", ""},
            {"accept-ranges", ""},
            {"accept", ""},
            {"access-control-allow-origin", ""},
            {"age", ""},
            {"allow", ""},
            {"authorization", ""},
            {"cache-control", ""},
            {"content-disposition", ""},
            {"content-encoding", ""},
            {"content-language", ""},
            {"content-length", ""},
            {"content-location", ""},
            {"content-range", ""},
            {"content-type", ""},
            {"cookie", ""},
            {"date", ""},
            {"etag", ""},
            {"expect", ""},
            {"expires", ""},
            {"from", ""},
            {"host", ""},
            {"if-match", ""},
            {"if-modified-since", ""},
            {"if-none-match", ""},
            {"if-range", ""},
            {"if-unmodified-since", ""},
            {"last-modified", ""},
            {"link", ""},
            {"location", ""},
            {"max-forwards", ""},
            {"proxy-authenticate", ""},
            {"proxy-authorization", ""},
            {"range", ""},
            {"referer", ""},
            {"refresh", ""},
            {"retry-after", ""},
            {"server", ""},
            {"set-cookie", ""},
            {"strict-transport-security", ""},
            {"transfer-encoding", ""},
            {"user-agent", ""},
            {"vary", ""},
            {"via", ""},
            {"www-authenticate", ""}};
}

HpackDecoder::HpackDecoder() {
    // Initialize with default max size
}

void HpackDecoder::setMaxDynamicTableSize(size_t size) {
    max_dynamic_table_size_ = size;
    evictDynamicTable();
}

void HpackDecoder::reset() {
    dynamic_table_.clear();
    current_dynamic_table_size_ = 0;
}

std::optional<std::pair<std::string, std::string>> HpackDecoder::getTableEntry(size_t index) {
    if (index == 0) {
        LOG_ERROR("HPACK: Invalid table index 0");
        return std::nullopt;
    }

    // Static table (1 to static_table_.size()-1)
    if (index < static_table_.size()) {
        return static_table_[index];
    }

    // Dynamic table
    size_t dynamic_index = index - static_table_.size();
    if (dynamic_index < dynamic_table_.size()) {
        return dynamic_table_[dynamic_index];
    }

    LOG_ERROR("HPACK: Table index {} out of range", index);
    return std::nullopt;
}

void HpackDecoder::addToDynamicTable(const std::string& name, const std::string& value) {
    size_t entry_size = calculateEntrySize(name, value);

    // Check if entry is larger than max table size
    if (entry_size > max_dynamic_table_size_) {
        LOG_DEBUG("HPACK: Entry size {} exceeds max table size {}", entry_size,
                  max_dynamic_table_size_);
        dynamic_table_.clear();
        current_dynamic_table_size_ = 0;
        return;
    }

    // Add to front of dynamic table
    dynamic_table_.push_front({name, value});
    current_dynamic_table_size_ += entry_size;

    // Evict old entries if needed
    evictDynamicTable();

    LOG_TRACE("HPACK: Added to dynamic table: {}={} (size={})", name, value, entry_size);
}

void HpackDecoder::evictDynamicTable() {
    while (current_dynamic_table_size_ > max_dynamic_table_size_ && !dynamic_table_.empty()) {
        const auto& entry = dynamic_table_.back();
        size_t entry_size = calculateEntrySize(entry.first, entry.second);
        current_dynamic_table_size_ -= entry_size;
        dynamic_table_.pop_back();
        LOG_TRACE("HPACK: Evicted from dynamic table (size={})", entry_size);
    }
}

size_t HpackDecoder::calculateEntrySize(const std::string& name, const std::string& value) const {
    // RFC 7541 Section 4.1: entry size = name_len + value_len + 32
    return name.length() + value.length() + 32;
}

uint64_t HpackDecoder::decodeInteger(const uint8_t*& data, const uint8_t* end,
                                     uint8_t prefix_bits) {
    if (data >= end) {
        return 0;
    }

    uint8_t prefix_mask = (1 << prefix_bits) - 1;
    uint64_t value = (*data) & prefix_mask;
    data++;

    if (value < prefix_mask) {
        return value;
    }

    // Multi-byte integer
    uint8_t m = 0;
    while (data < end) {
        uint8_t byte = *data++;
        value += (byte & 0x7F) * (1ULL << m);
        m += 7;

        if ((byte & 0x80) == 0) {
            break;
        }

        if (m > 63) {
            LOG_ERROR("HPACK: Integer too large");
            return 0;
        }
    }

    return value;
}

std::string HpackDecoder::decodeString(const uint8_t*& data, const uint8_t* end) {
    if (data >= end) {
        return "";
    }

    bool huffman = ((*data) & 0x80) != 0;
    uint64_t length = decodeInteger(data, end, 7);

    if (data + length > end) {
        LOG_ERROR("HPACK: String length {} exceeds available data", length);
        return "";
    }

    std::string result;
    if (huffman) {
        result = decodeHuffman(data, length);
    } else {
        result = std::string(reinterpret_cast<const char*>(data), length);
    }

    data += length;
    return result;
}

std::string HpackDecoder::decodeHuffman(const uint8_t* data, size_t len) {
    // Simplified Huffman decoder - in production, use full Huffman table
    // For now, return raw string (assumes non-Huffman encoding)
    LOG_DEBUG("HPACK: Huffman decoding not fully implemented, returning raw string");
    return std::string(reinterpret_cast<const char*>(data), len);
}

std::vector<HpackDecoder::DecodedHeader> HpackDecoder::decode(const uint8_t* data, size_t len) {
    std::vector<DecodedHeader> headers;
    const uint8_t* ptr = data;
    const uint8_t* end = data + len;

    while (ptr < end) {
        uint8_t first_byte = *ptr;

        // Indexed Header Field (pattern: 1xxxxxxx)
        if ((first_byte & 0x80) != 0) {
            uint64_t index = decodeInteger(ptr, end, 7);
            auto entry = getTableEntry(index);
            if (entry) {
                headers.push_back({entry->first, entry->second});
                LOG_TRACE("HPACK: Indexed header [{}]: {}={}", index, entry->first, entry->second);
            }
        }
        // Literal Header Field with Incremental Indexing (pattern: 01xxxxxx)
        else if ((first_byte & 0xC0) == 0x40) {
            uint64_t index = decodeInteger(ptr, end, 6);
            std::string name;

            if (index == 0) {
                // New name
                name = decodeString(ptr, end);
            } else {
                // Name from table
                auto entry = getTableEntry(index);
                if (entry) {
                    name = entry->first;
                }
            }

            std::string value = decodeString(ptr, end);
            headers.push_back({name, value});
            addToDynamicTable(name, value);
            LOG_TRACE("HPACK: Literal with indexing: {}={}", name, value);
        }
        // Literal Header Field without Indexing (pattern: 0000xxxx)
        else if ((first_byte & 0xF0) == 0x00) {
            uint64_t index = decodeInteger(ptr, end, 4);
            std::string name;

            if (index == 0) {
                name = decodeString(ptr, end);
            } else {
                auto entry = getTableEntry(index);
                if (entry) {
                    name = entry->first;
                }
            }

            std::string value = decodeString(ptr, end);
            headers.push_back({name, value});
            LOG_TRACE("HPACK: Literal without indexing: {}={}", name, value);
        }
        // Literal Header Field Never Indexed (pattern: 0001xxxx)
        else if ((first_byte & 0xF0) == 0x10) {
            uint64_t index = decodeInteger(ptr, end, 4);
            std::string name;

            if (index == 0) {
                name = decodeString(ptr, end);
            } else {
                auto entry = getTableEntry(index);
                if (entry) {
                    name = entry->first;
                }
            }

            std::string value = decodeString(ptr, end);
            headers.push_back({name, value});
            LOG_TRACE("HPACK: Literal never indexed: {}={}", name, value);
        }
        // Dynamic Table Size Update (pattern: 001xxxxx)
        else if ((first_byte & 0xE0) == 0x20) {
            uint64_t max_size = decodeInteger(ptr, end, 5);
            setMaxDynamicTableSize(max_size);
            LOG_DEBUG("HPACK: Dynamic table size update: {}", max_size);
        } else {
            LOG_ERROR("HPACK: Unknown header encoding: 0x{:02x}", first_byte);
            break;
        }
    }

    return headers;
}

// ============================================================================
// HTTP/2 Parser Implementation
// ============================================================================

Http2Parser::Http2Parser() {
    // Initialize parser
}

bool Http2Parser::isHttp2(const uint8_t* data, size_t len) {
    if (!data || len < HTTP2_PREFACE_LEN) {
        return false;
    }

    return memcmp(data, HTTP2_PREFACE, HTTP2_PREFACE_LEN) == 0;
}

std::optional<Http2FrameHeader> Http2Parser::parseFrameHeader(const uint8_t* data, size_t len) {
    if (!data || len < FRAME_HEADER_SIZE) {
        LOG_DEBUG("HTTP/2: Insufficient data for frame header (need {}, got {})", FRAME_HEADER_SIZE,
                  len);
        return std::nullopt;
    }

    Http2FrameHeader header;

    // Length (3 bytes, big-endian)
    header.length = (static_cast<uint32_t>(data[0]) << 16) | (static_cast<uint32_t>(data[1]) << 8) |
                    static_cast<uint32_t>(data[2]);

    // Type (1 byte)
    header.type = static_cast<Http2FrameType>(data[3]);

    // Flags (1 byte)
    header.flags = data[4];

    // Stream ID (4 bytes, big-endian, first bit reserved)
    header.stream_id = (static_cast<uint32_t>(data[5] & 0x7F) << 24) |
                       (static_cast<uint32_t>(data[6]) << 16) |
                       (static_cast<uint32_t>(data[7]) << 8) | static_cast<uint32_t>(data[8]);

    LOG_TRACE("HTTP/2: Parsed frame header: type={}, len={}, stream={}, flags=0x{:02x}",
              http2FrameTypeToString(header.type), header.length, header.stream_id, header.flags);

    return header;
}

std::optional<Http2Frame> Http2Parser::parseFrame(const uint8_t* data, size_t len) {
    auto header = parseFrameHeader(data, len);
    if (!header) {
        return std::nullopt;
    }

    // Check if we have complete frame
    size_t frame_size = FRAME_HEADER_SIZE + header->length;
    if (len < frame_size) {
        LOG_DEBUG("HTTP/2: Incomplete frame (need {}, got {})", frame_size, len);
        return std::nullopt;
    }

    Http2Frame frame;
    frame.header = *header;

    // Copy payload
    if (header->length > 0) {
        frame.payload.resize(header->length);
        memcpy(frame.payload.data(), data + FRAME_HEADER_SIZE, header->length);
    }

    return frame;
}

std::optional<Http2Connection> Http2Parser::parseConnection(const uint8_t* data, size_t len) {
    Http2Connection connection;
    const uint8_t* ptr = data;
    size_t remaining = len;

    // Check for connection preface
    if (len >= HTTP2_PREFACE_LEN && isHttp2(data, len)) {
        connection.preface_received = true;
        ptr += HTTP2_PREFACE_LEN;
        remaining -= HTTP2_PREFACE_LEN;
        LOG_DEBUG("HTTP/2: Connection preface detected");
    }

    // Parse frames
    while (remaining >= FRAME_HEADER_SIZE) {
        auto frame = parseFrame(ptr, remaining);
        if (!frame) {
            break;
        }

        size_t frame_size = FRAME_HEADER_SIZE + frame->header.length;
        processFrame(*frame, connection);
        connection.frames.push_back(*frame);

        ptr += frame_size;
        remaining -= frame_size;
    }

    LOG_INFO("HTTP/2: Parsed connection with {} frames and {} streams", connection.frames.size(),
             connection.streams.size());

    return connection;
}

Http2Stream& Http2Parser::getOrCreateStream(Http2Connection& connection, uint32_t stream_id) {
    auto it = connection.streams.find(stream_id);
    if (it != connection.streams.end()) {
        return it->second;
    }

    Http2Stream stream;
    stream.stream_id = stream_id;
    connection.streams[stream_id] = stream;
    return connection.streams[stream_id];
}

bool Http2Parser::processFrame(const Http2Frame& frame, Http2Connection& connection) {
    switch (frame.header.type) {
        case Http2FrameType::HEADERS:
            return processHeadersFrame(frame, connection);
        case Http2FrameType::DATA:
            return processDataFrame(frame, connection);
        case Http2FrameType::SETTINGS:
            return processSettingsFrame(frame, connection);
        case Http2FrameType::PRIORITY:
            return processPriorityFrame(frame, connection);
        case Http2FrameType::RST_STREAM:
            return processRstStreamFrame(frame, connection);
        case Http2FrameType::PING:
            return processPingFrame(frame, connection);
        case Http2FrameType::GOAWAY:
            return processGoawayFrame(frame, connection);
        case Http2FrameType::WINDOW_UPDATE:
            return processWindowUpdateFrame(frame, connection);
        default:
            LOG_DEBUG("HTTP/2: Unhandled frame type: {}",
                      http2FrameTypeToString(frame.header.type));
            return true;
    }
}

bool Http2Parser::processHeadersFrame(const Http2Frame& frame, Http2Connection& connection) {
    if (frame.header.stream_id == 0) {
        LOG_ERROR("HTTP/2: HEADERS frame with stream_id 0");
        return false;
    }

    auto& stream = getOrCreateStream(connection, frame.header.stream_id);

    // Handle padding
    size_t padding_length = 0;
    size_t header_block_offset = 0;

    if (frame.header.flags & Http2Flags::PADDED) {
        if (frame.payload.empty()) {
            return false;
        }
        padding_length = frame.payload[0];
        header_block_offset = 1;
    }

    // Handle priority
    if (frame.header.flags & Http2Flags::PRIORITY) {
        header_block_offset += 5;  // 4 bytes stream dependency + 1 byte weight
    }

    // Decode header block
    if (header_block_offset < frame.payload.size()) {
        size_t header_block_len = frame.payload.size() - header_block_offset - padding_length;
        auto headers =
            hpack_decoder_.decode(frame.payload.data() + header_block_offset, header_block_len);

        // Determine interaction phase based on headers
        bool is_request = false;
        bool is_response = false;

        for (const auto& header : headers) {
            if (header.name == ":method")
                is_request = true;
            if (header.name == ":status")
                is_response = true;
        }

        if (is_request) {
            if (stream.start_time.time_since_epoch().count() == 0) {
                stream.start_time = std::chrono::system_clock::now();
            }
        }

        // Process decoded headers
        for (const auto& header : headers) {
            // Update semantic fields
            if (header.name == ":method") {
                stream.method = header.value;
            } else if (header.name == ":path") {
                stream.path = header.value;
            } else if (header.name == ":authority") {
                stream.authority = header.value;
            } else if (header.name == ":scheme") {
                stream.scheme = header.value;
            } else if (header.name == ":status") {
                stream.status_code = std::stoi(header.value);
            }

            // Store in appropriate map
            // Note: If we received a request earlier, and now getting response headers, status_code
            // logic handles it. But here we rely on the specific flags found in *this* header
            // block.
            if (is_response || stream.status_code > 0) {
                stream.response_headers[header.name] = header.value;
            } else {
                stream.request_headers[header.name] = header.value;
            }
        }
    }

    // Check if headers are complete
    if (frame.header.flags & Http2Flags::END_HEADERS) {
        stream.headers_complete = true;
    }

    // Check if stream is complete
    if (frame.header.flags & Http2Flags::END_STREAM) {
        if (stream.status_code > 0) {
            stream.response_complete = true;
        } else {
            stream.request_complete = true;
        }
    }

    LOG_DEBUG("HTTP/2: HEADERS frame processed for stream {}", stream.stream_id);
    return true;
}

bool Http2Parser::processDataFrame(const Http2Frame& frame, Http2Connection& connection) {
    if (frame.header.stream_id == 0) {
        LOG_ERROR("HTTP/2: DATA frame with stream_id 0");
        return false;
    }

    auto& stream = getOrCreateStream(connection, frame.header.stream_id);

    // Handle padding
    size_t padding_length = 0;
    size_t data_offset = 0;

    if (frame.header.flags & Http2Flags::PADDED) {
        if (frame.payload.empty()) {
            return false;
        }
        padding_length = frame.payload[0];
        data_offset = 1;
    }

    // Append data
    if (data_offset < frame.payload.size()) {
        size_t data_len = frame.payload.size() - data_offset - padding_length;

        // Append to appropriate buffer
        if (stream.status_code > 0) {
            stream.response_data.insert(stream.response_data.end(),
                                        frame.payload.begin() + data_offset,
                                        frame.payload.begin() + data_offset + data_len);
        } else {
            stream.request_data.insert(stream.request_data.end(),
                                       frame.payload.begin() + data_offset,
                                       frame.payload.begin() + data_offset + data_len);
        }
    }

    // Check if stream is complete
    if (frame.header.flags & Http2Flags::END_STREAM) {
        if (stream.status_code > 0) {
            stream.response_complete = true;
            stream.end_time = std::chrono::system_clock::now();
        } else {
            stream.request_complete = true;
        }
    }

    LOG_DEBUG("HTTP/2: DATA frame processed for stream {} (req_size={}, resp_size={})",
              stream.stream_id, stream.request_data.size(), stream.response_data.size());
    return true;
}

bool Http2Parser::processSettingsFrame(const Http2Frame& frame, Http2Connection& connection) {
    if (frame.header.stream_id != 0) {
        LOG_ERROR("HTTP/2: SETTINGS frame with non-zero stream_id");
        return false;
    }

    // ACK flag
    if (frame.header.flags & Http2Flags::ACK) {
        LOG_DEBUG("HTTP/2: SETTINGS ACK received");
        return true;
    }

    // Parse settings (6 bytes per setting)
    for (size_t i = 0; i + 6 <= frame.payload.size(); i += 6) {
        uint16_t id = (static_cast<uint16_t>(frame.payload[i]) << 8) | frame.payload[i + 1];
        uint32_t value = (static_cast<uint32_t>(frame.payload[i + 2]) << 24) |
                         (static_cast<uint32_t>(frame.payload[i + 3]) << 16) |
                         (static_cast<uint32_t>(frame.payload[i + 4]) << 8) | frame.payload[i + 5];

        switch (id) {
            case 1:  // SETTINGS_HEADER_TABLE_SIZE
                connection.header_table_size = value;
                hpack_decoder_.setMaxDynamicTableSize(value);
                break;
            case 2:  // SETTINGS_ENABLE_PUSH
                connection.enable_push = (value != 0);
                break;
            case 3:  // SETTINGS_MAX_CONCURRENT_STREAMS
                connection.max_concurrent_streams = value;
                break;
            case 4:  // SETTINGS_INITIAL_WINDOW_SIZE
                connection.initial_window_size = value;
                break;
            case 5:  // SETTINGS_MAX_FRAME_SIZE
                connection.max_frame_size = value;
                break;
            case 6:  // SETTINGS_MAX_HEADER_LIST_SIZE
                connection.max_header_list_size = value;
                break;
            default:
                LOG_DEBUG("HTTP/2: Unknown setting: {}={}", id, value);
                break;
        }
    }

    LOG_DEBUG("HTTP/2: SETTINGS frame processed");
    return true;
}

bool Http2Parser::processPriorityFrame(const Http2Frame& frame, Http2Connection& connection) {
    LOG_DEBUG("HTTP/2: PRIORITY frame for stream {}", frame.header.stream_id);
    return true;
}

bool Http2Parser::processRstStreamFrame(const Http2Frame& frame, Http2Connection& connection) {
    LOG_DEBUG("HTTP/2: RST_STREAM frame for stream {}", frame.header.stream_id);
    return true;
}

bool Http2Parser::processPingFrame(const Http2Frame& frame, Http2Connection& connection) {
    LOG_DEBUG("HTTP/2: PING frame");
    return true;
}

bool Http2Parser::processGoawayFrame(const Http2Frame& frame, Http2Connection& connection) {
    LOG_DEBUG("HTTP/2: GOAWAY frame");
    return true;
}

bool Http2Parser::processWindowUpdateFrame(const Http2Frame& frame, Http2Connection& connection) {
    LOG_DEBUG("HTTP/2: WINDOW_UPDATE frame for stream {}", frame.header.stream_id);
    return true;
}

std::string Http2Parser::extractSessionKey(const Http2Stream& stream) {
    return "HTTP2-" + std::to_string(stream.stream_id);
}

MessageType Http2Parser::getMessageType(const Http2Frame& frame) {
    switch (frame.header.type) {
        case Http2FrameType::HEADERS:
            return MessageType::HTTP2_HEADERS;
        case Http2FrameType::DATA:
            return MessageType::HTTP2_DATA;
        case Http2FrameType::SETTINGS:
            return MessageType::HTTP2_SETTINGS;
        case Http2FrameType::PING:
            return MessageType::HTTP2_PING;
        case Http2FrameType::GOAWAY:
            return MessageType::HTTP2_GOAWAY;
        default:
            return MessageType::UNKNOWN;
    }
}

}  // namespace callflow
