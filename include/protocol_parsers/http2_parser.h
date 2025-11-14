#pragma once

#include "common/types.h"
#include <optional>
#include <vector>
#include <map>
#include <string>
#include <deque>
#include <nlohmann/json.hpp>

namespace callflow {

/**
 * HTTP/2 frame types (RFC 7540)
 */
enum class Http2FrameType : uint8_t {
    DATA = 0x0,
    HEADERS = 0x1,
    PRIORITY = 0x2,
    RST_STREAM = 0x3,
    SETTINGS = 0x4,
    PUSH_PROMISE = 0x5,
    PING = 0x6,
    GOAWAY = 0x7,
    WINDOW_UPDATE = 0x8,
    CONTINUATION = 0x9
};

std::string http2FrameTypeToString(Http2FrameType type);

/**
 * HTTP/2 frame flags
 */
namespace Http2Flags {
    constexpr uint8_t END_STREAM = 0x1;
    constexpr uint8_t ACK = 0x1;
    constexpr uint8_t END_HEADERS = 0x4;
    constexpr uint8_t PADDED = 0x8;
    constexpr uint8_t PRIORITY = 0x20;
}

/**
 * HTTP/2 frame header (9 bytes)
 */
struct Http2FrameHeader {
    uint32_t length;           // 24-bit frame length
    Http2FrameType type;       // Frame type
    uint8_t flags;             // Frame-specific flags
    uint32_t stream_id;        // 31-bit stream identifier (R bit reserved)

    nlohmann::json toJson() const;
};

/**
 * HTTP/2 frame structure
 */
struct Http2Frame {
    Http2FrameHeader header;
    std::vector<uint8_t> payload;

    nlohmann::json toJson() const;
};

/**
 * HTTP/2 stream state
 */
struct Http2Stream {
    uint32_t stream_id;
    std::string method;           // :method pseudo-header
    std::string path;             // :path pseudo-header
    std::string authority;        // :authority pseudo-header
    std::string scheme;           // :scheme pseudo-header (http or https)
    int status_code = 0;          // :status pseudo-header (response)

    std::map<std::string, std::string> headers;
    std::vector<uint8_t> data;    // Assembled DATA frames

    bool request_complete = false;
    bool response_complete = false;
    bool headers_complete = false;

    nlohmann::json toJson() const;
};

/**
 * HTTP/2 connection state
 */
struct Http2Connection {
    bool preface_received = false;
    std::map<uint32_t, Http2Stream> streams;
    std::vector<Http2Frame> frames;

    // Connection settings
    uint32_t header_table_size = 4096;
    bool enable_push = true;
    uint32_t max_concurrent_streams = 100;
    uint32_t initial_window_size = 65535;
    uint32_t max_frame_size = 16384;
    uint32_t max_header_list_size = 8192;

    nlohmann::json toJson() const;
};

/**
 * HPACK decoder (RFC 7541)
 */
class HpackDecoder {
public:
    struct DecodedHeader {
        std::string name;
        std::string value;
    };

    HpackDecoder();
    ~HpackDecoder() = default;

    /**
     * Decode HPACK-encoded header block
     * @param data Header block data
     * @param len Data length
     * @return Decoded headers
     */
    std::vector<DecodedHeader> decode(const uint8_t* data, size_t len);

    /**
     * Set maximum dynamic table size
     */
    void setMaxDynamicTableSize(size_t size);

    /**
     * Get current dynamic table size
     */
    size_t getDynamicTableSize() const { return current_dynamic_table_size_; }

    /**
     * Reset decoder state
     */
    void reset();

private:
    // Static table (RFC 7541 Appendix A)
    static const std::vector<std::pair<std::string, std::string>> static_table_;

    // Dynamic table
    std::deque<std::pair<std::string, std::string>> dynamic_table_;
    size_t max_dynamic_table_size_ = 4096;
    size_t current_dynamic_table_size_ = 0;

    /**
     * Get entry from static or dynamic table
     * @param index Table index (1-based)
     * @return Header name and value
     */
    std::optional<std::pair<std::string, std::string>> getTableEntry(size_t index);

    /**
     * Add entry to dynamic table
     */
    void addToDynamicTable(const std::string& name, const std::string& value);

    /**
     * Evict entries from dynamic table to maintain size limit
     */
    void evictDynamicTable();

    /**
     * Calculate entry size (RFC 7541 Section 4.1)
     */
    size_t calculateEntrySize(const std::string& name, const std::string& value) const;

    /**
     * Decode integer from HPACK encoding (RFC 7541 Section 5.1)
     * @param data Data pointer (will be advanced)
     * @param prefix_bits Number of prefix bits
     * @return Decoded integer
     */
    uint64_t decodeInteger(const uint8_t*& data, const uint8_t* end, uint8_t prefix_bits);

    /**
     * Decode string from HPACK encoding (RFC 7541 Section 5.2)
     * @param data Data pointer (will be advanced)
     * @return Decoded string
     */
    std::string decodeString(const uint8_t*& data, const uint8_t* end);

    /**
     * Decode Huffman-encoded string (RFC 7541 Appendix B)
     * @param data Huffman-encoded data
     * @param len Data length
     * @return Decoded string
     */
    std::string decodeHuffman(const uint8_t* data, size_t len);

    /**
     * Initialize static table
     */
    static std::vector<std::pair<std::string, std::string>> initStaticTable();
};

/**
 * HTTP/2 protocol parser
 */
class Http2Parser {
public:
    Http2Parser();
    ~Http2Parser() = default;

    /**
     * Parse HTTP/2 frame from packet payload
     * @param data Packet payload data
     * @param len Payload length
     * @return Parsed HTTP/2 frame or nullopt if parsing fails
     */
    std::optional<Http2Frame> parseFrame(const uint8_t* data, size_t len);

    /**
     * Parse HTTP/2 connection from complete stream
     * @param data Stream data
     * @param len Data length
     * @return Parsed HTTP/2 connection state or nullopt if parsing fails
     */
    std::optional<Http2Connection> parseConnection(const uint8_t* data, size_t len);

    /**
     * Check if data appears to be HTTP/2
     * @param data Data to check
     * @param len Data length
     * @return true if HTTP/2 connection preface detected
     */
    static bool isHttp2(const uint8_t* data, size_t len);

    /**
     * Process frame and update connection state
     * @param frame Frame to process
     * @param connection Connection state to update
     * @return true if frame processed successfully
     */
    bool processFrame(const Http2Frame& frame, Http2Connection& connection);

    /**
     * Extract session key from HTTP/2 stream
     * @param stream HTTP/2 stream
     * @return Session key (format: "HTTP2-{stream_id}")
     */
    static std::string extractSessionKey(const Http2Stream& stream);

    /**
     * Get message type from HTTP/2 frame
     */
    static MessageType getMessageType(const Http2Frame& frame);

private:
    HpackDecoder hpack_decoder_;

    /**
     * Parse frame header (9 bytes)
     * @param data Frame data
     * @param len Data length
     * @return Parsed frame header or nullopt if parsing fails
     */
    std::optional<Http2FrameHeader> parseFrameHeader(const uint8_t* data, size_t len);

    /**
     * Process HEADERS frame
     */
    bool processHeadersFrame(const Http2Frame& frame, Http2Connection& connection);

    /**
     * Process DATA frame
     */
    bool processDataFrame(const Http2Frame& frame, Http2Connection& connection);

    /**
     * Process SETTINGS frame
     */
    bool processSettingsFrame(const Http2Frame& frame, Http2Connection& connection);

    /**
     * Process PRIORITY frame
     */
    bool processPriorityFrame(const Http2Frame& frame, Http2Connection& connection);

    /**
     * Process RST_STREAM frame
     */
    bool processRstStreamFrame(const Http2Frame& frame, Http2Connection& connection);

    /**
     * Process PING frame
     */
    bool processPingFrame(const Http2Frame& frame, Http2Connection& connection);

    /**
     * Process GOAWAY frame
     */
    bool processGoawayFrame(const Http2Frame& frame, Http2Connection& connection);

    /**
     * Process WINDOW_UPDATE frame
     */
    bool processWindowUpdateFrame(const Http2Frame& frame, Http2Connection& connection);

    /**
     * Get or create stream in connection
     */
    Http2Stream& getOrCreateStream(Http2Connection& connection, uint32_t stream_id);
};

}  // namespace callflow
