#include <chrono>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

// Mock dependencies
namespace callflow {
struct Timestamp {
    std::chrono::system_clock::time_point time_point;
    // Mocking implicit conversion if needed, but usually it's just a typedef
};
}  // namespace callflow
using Timestamp = std::chrono::system_clock::time_point;

struct FiveTuple {
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
};

struct PacketMetadata {
    Timestamp timestamp;
    FiveTuple five_tuple;
    uint32_t frame_number;
    size_t packet_length;
};

// Mock SipMessage (Parser)
namespace callflow {
struct Codec {
    std::string encoding_name;
};
struct SDP {
    std::string connection_address;
    uint16_t rtp_port;
    std::optional<std::string> media_direction;
    std::vector<Codec> codecs;
};
struct PAI {
    std::string uri;
};

struct SipMessage {
    bool is_request = true;
    std::string method = "INVITE";
    std::string request_uri = "sip:bob@example.com";
    int status_code = 0;
    std::string reason_phrase;
    std::string call_id = "test-call-id";
    std::string from = "sip:alice@example.com";
    std::string from_tag = "tag123";
    std::string to = "sip:bob@example.com";
    std::string to_tag;
    std::string cseq = "1 INVITE";
    std::optional<std::string> body;
    std::optional<std::vector<PAI>> p_asserted_identity;
    std::optional<std::string> p_preferred_identity;
    std::optional<SDP> sdp;
};
}  // namespace callflow

// Mock SipMessage (Correlation)
namespace callflow {
namespace correlation {
struct SipMediaInfo {
    std::string media_type;
    std::string connection_ip;
    uint16_t port;
    std::string direction;
    std::vector<std::string> codecs;
};

class SipMessage {
public:
    void setRequest(bool b) {}
    void setMethod(std::string s) {}
    void setRequestUri(std::string s) {}
    void setStatusCode(int i) {}
    void setReasonPhrase(std::string s) {}
    void setCallId(std::string s) {}
    void setFromUri(std::string s) {}
    void setFromTag(std::string s) {}
    void setToUri(std::string s) {}
    void setToTag(std::string s) {}
    void setCSeq(uint32_t i) {}
    void setCSeqMethod(std::string s) {}
    void setPAssertedIdentity(std::string s) {}
    void setPPreferredIdentity(std::string s) {}
    void setSdpBody(std::string s) {}
    void setSourceIp(std::string s) {}
    void setDestIp(std::string s) {}
    void setSourcePort(uint16_t i) {}
    void setDestPort(uint16_t i) {}
    void setFrameNumber(uint32_t i) {}

    // CRITICAL PART
    void setTimestamp(double ts) { timestamp_ = ts; }
    double getTimestamp() const { return timestamp_; }

    // Helper
    void addMediaInfo(SipMediaInfo m) {}

private:
    double timestamp_ = 0.0;
};
}  // namespace correlation
}  // namespace callflow

// THE TEST
int main() {
    std::cout << "Starting Timestamp Reproduction Test..." << std::endl;

    // 1. Create packet metadata with known timestamp
    // Date: 2024-01-01 12:00:00 UTC
    // Epoch: 1704110400 seconds
    auto tp = std::chrono::system_clock::from_time_t(1704110400);

    PacketMetadata packet;
    packet.timestamp = tp;
    packet.five_tuple = {"1.1.1.1", "2.2.2.2", 5060, 5060, 17};
    packet.frame_number = 100;

    std::cout << "Input Timestamp (seconds): " << 1704110400 << std::endl;
    std::cout << "Input Timestamp (double): " << std::fixed << std::setprecision(6)
              << std::chrono::duration<double>(tp.time_since_epoch()).count() << std::endl;

    // 2. Logic from convertToCorrelationSipMessage
    callflow::correlation::SipMessage corr_msg;

    // ... (lines like 1570 in session_correlator.cpp)
    double timestamp_seconds =
        std::chrono::duration<double>(packet.timestamp.time_since_epoch()).count();
    corr_msg.setTimestamp(timestamp_seconds);

    // 3. Verify
    double result = corr_msg.getTimestamp();
    std::cout << "Result Timestamp: " << result << std::endl;

    if (std::abs(result - 1704110400.0) < 0.001) {
        std::cout << "SUCCESS: Timestamp matched!" << std::endl;
    } else {
        std::cout << "FAILURE: Timestamp mismatch!" << std::endl;
        std::cout << "Difference: " << (result - 1704110400.0) << std::endl;
        return 1;
    }

    // 4. Test with 0 timestamp (1970)
    auto tp0 = std::chrono::system_clock::from_time_t(0);
    packet.timestamp = tp0;
    double ts0 = std::chrono::duration<double>(packet.timestamp.time_since_epoch()).count();
    std::cout << "Zero Expectation: " << ts0 << std::endl;

    // 5. Test with 2004 timestamp (1084665600)
    auto tp2004 = std::chrono::system_clock::from_time_t(1084665600);
    packet.timestamp = tp2004;
    double ts2004 = std::chrono::duration<double>(packet.timestamp.time_since_epoch()).count();
    std::cout << "2004 Expectation: " << ts2004 << std::endl;

    return 0;
}
