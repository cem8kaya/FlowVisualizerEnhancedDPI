#include "common/utils.h"

#include <arpa/inet.h>

#include <cstring>
#include <iomanip>
#include <random>
#include <sstream>

namespace callflow {
namespace utils {

std::string generateUuid() {
    static std::random_device rd;
    static auto seed = rd() ^ std::chrono::high_resolution_clock::now().time_since_epoch().count();
    static std::mt19937_64 gen(seed);
    static std::uniform_int_distribution<uint64_t> dis;

    uint64_t part1 = dis(gen);
    uint64_t part2 = dis(gen);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0') << std::setw(8) << (part1 >> 32) << "-" << std::setw(4)
        << ((part1 >> 16) & 0xFFFF) << "-" << std::setw(4) << (part1 & 0xFFFF) << "-"
        << std::setw(4) << (part2 >> 48) << "-" << std::setw(12) << (part2 & 0xFFFFFFFFFFFF);
    return oss.str();
}

std::string timestampToIso8601(const std::chrono::system_clock::time_point& tp) {
    auto time_t_val = std::chrono::system_clock::to_time_t(tp);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch()) % 1000;

    std::tm tm_buf;
    gmtime_r(&time_t_val, &tm_buf);

    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%S") << '.' << std::setfill('0') << std::setw(3)
        << ms.count() << 'Z';
    return oss.str();
}

std::chrono::system_clock::time_point iso8601ToTimestamp(const std::string& str) {
    // Simplified parser - expects format: YYYY-MM-DDTHH:MM:SS.sssZ
    std::tm tm = {};
    std::istringstream ss(str);
    ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");

    auto tp = std::chrono::system_clock::from_time_t(std::mktime(&tm));

    // Parse milliseconds if present
    size_t dot_pos = str.find('.');
    if (dot_pos != std::string::npos) {
        std::string ms_str = str.substr(dot_pos + 1, 3);
        int ms = std::stoi(ms_str);
        tp += std::chrono::milliseconds(ms);
    }

    return tp;
}

std::string ipToString(uint32_t ip) {
    struct in_addr addr;
    addr.s_addr = htonl(ip);
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    return std::string(buf);
}

uint32_t stringToIp(const std::string& ip_str) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str.c_str(), &addr) != 1) {
        return 0;
    }
    return ntohl(addr.s_addr);
}

std::string bytesToHex(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        oss << std::setw(2) << static_cast<int>(data[i]);
    }
    return oss.str();
}

std::string bytesToBase64(const uint8_t* data, size_t len) {
    static const char* base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string result;
    result.reserve(((len + 2) / 3) * 4);

    for (size_t i = 0; i < len; i += 3) {
        uint32_t val = (data[i] << 16);
        if (i + 1 < len)
            val |= (data[i + 1] << 8);
        if (i + 2 < len)
            val |= data[i + 2];

        result += base64_chars[(val >> 18) & 0x3F];
        result += base64_chars[(val >> 12) & 0x3F];
        result += (i + 1 < len) ? base64_chars[(val >> 6) & 0x3F] : '=';
        result += (i + 2 < len) ? base64_chars[val & 0x3F] : '=';
    }

    return result;
}

std::vector<uint8_t> base64ToBytes(const std::string& base64) {
    // Simplified implementation - assumes valid base64 input
    (void)base64;  // TODO: Implement full base64 decoding
    std::vector<uint8_t> result;
    return result;
}

uint64_t hashBuffer(const void* data, size_t len) {
    // FNV-1a hash
    const uint64_t FNV_PRIME = 0x100000001b3;
    const uint64_t FNV_OFFSET = 0xcbf29ce484222325;

    uint64_t hash = FNV_OFFSET;
    const uint8_t* bytes = static_cast<const uint8_t*>(data);

    for (size_t i = 0; i < len; ++i) {
        hash ^= bytes[i];
        hash *= FNV_PRIME;
    }

    return hash;
}

std::chrono::system_clock::time_point now() {
    return std::chrono::system_clock::now();
}

int64_t timeDiffMs(const std::chrono::system_clock::time_point& start,
                   const std::chrono::system_clock::time_point& end) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
}

std::string sanitizeString(const std::string& str) {
    std::ostringstream oss;
    for (char c : str) {
        switch (c) {
            case '"':
                oss << "\\\"";
                break;
            case '\\':
                oss << "\\\\";
                break;
            case '\b':
                oss << "\\b";
                break;
            case '\f':
                oss << "\\f";
                break;
            case '\n':
                oss << "\\n";
                break;
            case '\r':
                oss << "\\r";
                break;
            case '\t':
                oss << "\\t";
                break;
            default:
                if (c < 0x20) {
                    oss << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                        << static_cast<int>(c);
                } else {
                    oss << c;
                }
        }
    }
    return oss.str();
}

std::string bcdToString(const uint8_t* data, size_t len, bool skip_first_nibble) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; ++i) {
        uint8_t byte = data[i];

        // Lower nibble checks
        if (!skip_first_nibble || i > 0) {
            uint8_t digit1 = byte & 0x0F;
            if (digit1 <= 9)
                oss << digit1;
        }

        // Upper nibble
        uint8_t digit2 = (byte >> 4) & 0x0F;
        if (digit2 <= 9)
            oss << digit2;
    }
    return oss.str();
}

std::vector<uint8_t> hexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = (uint8_t)strtol(byteString.c_str(), nullptr, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

}  // namespace utils
}  // namespace callflow
