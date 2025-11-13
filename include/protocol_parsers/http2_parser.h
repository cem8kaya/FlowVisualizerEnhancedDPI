#pragma once

#include "common/types.h"
#include <optional>
#include <vector>
#include <map>
#include <string>
#include <memory>
#include <nlohmann/json.hpp>

namespace callflow {

/**
 * HTTP/2 frame types (RFC 7540)
 */
enum class Http2FrameType {
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

/**
 * HTTP/2 frame flags
 */
enum Http2FrameFlags {
    FLAG_NONE = 0x0,
    FLAG_END_STREAM = 0x1,    // DATA, HEADERS
    FLAG_END_HEADERS = 0x4,   // HEADERS, PUSH_PROMISE, CONTINUATION
    FLAG_PADDED = 0x8,        // DATA, HEADERS, PUSH_PROMISE
    FLAG_PRIORITY = 0x20,     // HEADERS
    FLAG_ACK = 0x1            // SETTINGS, PING
};

/**
 * HTTP/2 error codes
 */
enum class Http2ErrorCode {
    NO_ERROR = 0x0,
    PROTOCOL_ERROR = 0x1,
    INTERNAL_ERROR = 0x2,
    FLOW_CONTROL_ERROR = 0x3,
    SETTINGS_TIMEOUT = 0x4,
    STREAM_CLOSED = 0x5,
    FRAME_SIZE_ERROR = 0x6,
    REFUSED_STREAM = 0x7,
    CANCEL = 0x8,
    COMPRESSION_ERROR = 0x9,
    CONNECT_ERROR = 0xa,
    ENHANCE_YOUR_CALM = 0xb,
    INADEQUATE_SECURITY = 0xc,
    HTTP_1_1_REQUIRED = 0xd
};

/**
 * HTTP/2 frame header (9 bytes)
 */
struct Http2FrameHeader {
    uint32_t length;          // 24-bit payload length
    Http2FrameType type;      // Frame type
    uint8_t flags;            // Frame-specific flags
    uint32_t stream_id;       // 31-bit stream identifier (bit 0 reserved)

    nlohmann::json toJson() const;
};

/**
 * HTTP/2 frame
 */
struct Http2Frame {
    Http2FrameHeader header;
    std::vector<uint8_t> payload;

    nlohmann::json toJson() const;
};

/**
 * HTTP/2 SETTINGS parameter
 */
struct Http2Setting {
    uint16_t id;
    uint32_t value;
};

/**
 * HTTP/2 stream priority
 */
struct Http2Priority {
    bool exclusive;
    uint32_t stream_dependency;
    uint8_t weight;
};

/**
 * HTTP/2 stream state
 */
enum class Http2StreamState {
    IDLE,
    RESERVED_LOCAL,
    RESERVED_REMOTE,
    OPEN,
    HALF_CLOSED_LOCAL,
    HALF_CLOSED_REMOTE,
    CLOSED
};

/**
 * HTTP/2 stream
 */
struct Http2Stream {
    uint32_t stream_id;
    Http2StreamState state;

    // Request pseudo-headers
    std::string method;           // :method
    std::string scheme;           // :scheme
    std::string authority;        // :authority
    std::string path;             // :path

    // Response pseudo-headers
    int status_code;              // :status

    // Regular headers
    std::map<std::string, std::string> headers;

    // Data
    std::vector<uint8_t> data;

    // Priority
    std::optional<Http2Priority> priority;

    // Flags
    bool request_complete;
    bool response_complete;
    bool end_stream_received;

    nlohmann::json toJson() const;
};

/**
 * HTTP/2 message (connection-level)
 */
struct Http2Message {
    // Connection preface (for h2c)
    bool preface_seen;

    // Frames
    std::vector<Http2Frame> frames;

    // Streams (indexed by stream ID)
    std::map<uint32_t, Http2Stream> streams;

    // Connection settings
    std::map<uint16_t, uint32_t> local_settings;
    std::map<uint16_t, uint32_t> remote_settings;

    // GOAWAY info
    bool goaway_sent;
    bool goaway_received;
    uint32_t last_stream_id;
    Http2ErrorCode error_code;

    nlohmann::json toJson() const;
};

/**
 * HPACK decoder for HTTP/2 header compression (RFC 7541)
 */
class HpackDecoder {
public:
    HpackDecoder();
    ~HpackDecoder() = default;

    /**
     * Decoded header field
     */
    struct DecodedHeader {
        std::string name;
        std::string value;
    };

    /**
     * Decode HPACK-compressed header block
     * @param data Header block data
     * @param len Header block length
     * @return Vector of decoded headers
     */
    std::vector<DecodedHeader> decode(const uint8_t* data, size_t len);

    /**
     * Set maximum dynamic table size
     */
    void setMaxDynamicTableSize(size_t size);

    /**
     * Reset decoder state
     */
    void reset();

private:
    // Static table (RFC 7541 Appendix A)
    static const std::vector<std::pair<std::string, std::string>> STATIC_TABLE;

    // Dynamic table
    std::vector<std::pair<std::string, std::string>> dynamic_table_;
    size_t dynamic_table_size_;
    size_t max_dynamic_table_size_;

    // Decoding methods
    DecodedHeader decodeIndexed(const uint8_t*& data, size_t& remaining);
    DecodedHeader decodeLiteralWithIndexing(const uint8_t*& data, size_t& remaining);
    DecodedHeader decodeLiteralWithoutIndexing(const uint8_t*& data, size_t& remaining);
    DecodedHeader decodeLiteralNeverIndexed(const uint8_t*& data, size_t& remaining);
    void decodeDynamicTableSizeUpdate(const uint8_t*& data, size_t& remaining);

    // Helper methods
    uint32_t decodeInteger(const uint8_t*& data, size_t& remaining, uint8_t prefix_bits);
    std::string decodeString(const uint8_t*& data, size_t& remaining);
    std::string decodeHuffman(const uint8_t* data, size_t len);

    // Dynamic table management
    void addToDynamicTable(const std::string& name, const std::string& value);
    void evictFromDynamicTable();
    std::pair<std::string, std::string> getTableEntry(size_t index);
    size_t calculateEntrySize(const std::string& name, const std::string& value);
};

/**
 * HTTP/2 protocol parser
 */
class Http2Parser {
public:
    Http2Parser();
    ~Http2Parser() = default;

    /**
     * Parse HTTP/2 data from packet payload
     * @param data Packet payload data
     * @param len Payload length
     * @return Parsed HTTP/2 message or nullopt if parsing fails
     */
    std::optional<Http2Message> parse(const uint8_t* data, size_t len);

    /**
     * Parse a single HTTP/2 frame
     * @param data Frame data (including 9-byte header)
     * @param len Data length
     * @return Parsed frame or nullopt if parsing fails
     */
    std::optional<Http2Frame> parseFrame(const uint8_t* data, size_t len);

    /**
     * Check if data appears to be HTTP/2
     * @param data Packet data
     * @param len Data length
     * @return true if likely HTTP/2, false otherwise
     */
    static bool isHttp2(const uint8_t* data, size_t len);

    /**
     * Extract session key for correlation
     * (Uses stream ID within TCP 5-tuple context)
     */
    static std::string getSessionKey(const Http2Message& msg, uint32_t stream_id);

    /**
     * Get message type for a stream
     */
    static MessageType getMessageType(const Http2Stream& stream);

    /**
     * Reset parser state
     */
    void reset();

private:
    // HPACK decoder instance
    std::unique_ptr<HpackDecoder> hpack_decoder_;

    // Connection state
    bool preface_seen_;
    std::map<uint16_t, uint32_t> settings_;

    // Frame parsing methods
    bool parseFrameHeader(const uint8_t* data, size_t len, Http2FrameHeader& header);
    bool parseDataFrame(const Http2Frame& frame, Http2Message& msg);
    bool parseHeadersFrame(const Http2Frame& frame, Http2Message& msg);
    bool parsePriorityFrame(const Http2Frame& frame, Http2Message& msg);
    bool parseRstStreamFrame(const Http2Frame& frame, Http2Message& msg);
    bool parseSettingsFrame(const Http2Frame& frame, Http2Message& msg);
    bool parsePushPromiseFrame(const Http2Frame& frame, Http2Message& msg);
    bool parsePingFrame(const Http2Frame& frame, Http2Message& msg);
    bool parseGoawayFrame(const Http2Frame& frame, Http2Message& msg);
    bool parseWindowUpdateFrame(const Http2Frame& frame, Http2Message& msg);
    bool parseContinuationFrame(const Http2Frame& frame, Http2Message& msg);

    // Helper methods
    void processHeaders(const std::vector<HpackDecoder::DecodedHeader>& headers,
                       Http2Stream& stream);
    bool checkPreface(const uint8_t* data, size_t len);

    // Continuation frame handling (multi-frame HEADERS)
    uint32_t continuation_stream_id_;
    std::vector<uint8_t> continuation_buffer_;
};

}  // namespace callflow
