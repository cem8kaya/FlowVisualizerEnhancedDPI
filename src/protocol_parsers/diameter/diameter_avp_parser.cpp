#include "protocol_parsers/diameter/diameter_avp_parser.h"
#include "common/logger.h"
#include <arpa/inet.h>
#include <cstring>
#include <sstream>
#include <iomanip>

namespace callflow {
namespace diameter {

// ============================================================================
// Helper Functions
// ============================================================================

uint32_t DiameterAVPParser::readUint32(const uint8_t* data) {
    uint32_t value;
    std::memcpy(&value, data, 4);
    return ntohl(value);
}

uint64_t DiameterAVPParser::readUint64(const uint8_t* data) {
    uint64_t value;
    std::memcpy(&value, data, 8);
    return be64toh(value);
}

uint32_t DiameterAVPParser::readUint24(const uint8_t* data) {
    return (static_cast<uint32_t>(data[0]) << 16) |
           (static_cast<uint32_t>(data[1]) << 8) |
           static_cast<uint32_t>(data[2]);
}

size_t DiameterAVPParser::calculatePadding(size_t length) {
    size_t remainder = length % 4;
    return remainder == 0 ? 0 : (4 - remainder);
}

// ============================================================================
// AVP Parsing
// ============================================================================

std::shared_ptr<DiameterAVP> DiameterAVPParser::parseAVP(const uint8_t* data, size_t length, size_t& offset) {
    // AVP header is at least 8 bytes (without vendor ID)
    if (offset + DIAMETER_AVP_HEADER_MIN_SIZE > length) {
        LOG_DEBUG("Not enough data for AVP header at offset " << offset);
        return nullptr;
    }

    auto avp = std::make_shared<DiameterAVP>();

    // Bytes 0-3: AVP Code
    avp->code = readUint32(data + offset);

    // Byte 4: Flags
    uint8_t flags = data[offset + 4];
    avp->vendor_specific = (flags & 0x80) != 0;  // V bit
    avp->mandatory = (flags & 0x40) != 0;        // M bit
    avp->protected_ = (flags & 0x20) != 0;       // P bit

    // Bytes 5-7: AVP Length (24 bits)
    avp->length = readUint24(data + offset + 5);

    if (avp->length < DIAMETER_AVP_HEADER_MIN_SIZE) {
        LOG_ERROR("Invalid AVP length: " << avp->length);
        return nullptr;
    }

    size_t header_len = DIAMETER_AVP_HEADER_MIN_SIZE;

    // Bytes 8-11: Vendor ID (if V flag set)
    if (avp->vendor_specific) {
        if (offset + DIAMETER_AVP_HEADER_VENDOR_SIZE > length) {
            LOG_DEBUG("Not enough data for vendor ID at offset " << offset);
            return nullptr;
        }
        avp->vendor_id = readUint32(data + offset + 8);
        header_len = DIAMETER_AVP_HEADER_VENDOR_SIZE;
    }

    // Calculate data length
    if (avp->length < header_len) {
        LOG_ERROR("AVP length " << avp->length << " is less than header length " << header_len);
        return nullptr;
    }

    size_t data_len = avp->length - header_len;

    // Check if we have enough data
    if (offset + header_len + data_len > length) {
        LOG_DEBUG("Not enough data for AVP data at offset " << offset);
        return nullptr;
    }

    // Copy AVP data
    avp->data.resize(data_len);
    std::memcpy(avp->data.data(), data + offset + header_len, data_len);

    // Get data type and decode
    DiameterAVPDataType data_type = getAVPDataType(avp->code, avp->vendor_id);
    decodeAVPData(avp, data_type);

    // Calculate padding (AVPs are padded to 4-byte boundaries)
    size_t padding = calculatePadding(avp->length);
    offset += avp->length + padding;

    return avp;
}

std::vector<std::shared_ptr<DiameterAVP>> DiameterAVPParser::parseAVPs(const uint8_t* data, size_t length, size_t offset) {
    std::vector<std::shared_ptr<DiameterAVP>> avps;

    while (offset < length) {
        auto avp = parseAVP(data, length, offset);
        if (!avp) {
            // Failed to parse AVP, stop parsing
            LOG_WARN("Failed to parse AVP at offset " << offset);
            break;
        }
        avps.push_back(avp);
    }

    return avps;
}

// ============================================================================
// Data Type Decoding
// ============================================================================

bool DiameterAVPParser::decodeAVPData(std::shared_ptr<DiameterAVP> avp, DiameterAVPDataType type) {
    if (!avp) {
        return false;
    }

    switch (type) {
        case DiameterAVPDataType::INTEGER32: {
            auto val = parseInt32(avp->data);
            if (val.has_value()) {
                avp->decoded_value = val.value();
                return true;
            }
            break;
        }
        case DiameterAVPDataType::INTEGER64: {
            auto val = parseInt64(avp->data);
            if (val.has_value()) {
                avp->decoded_value = val.value();
                return true;
            }
            break;
        }
        case DiameterAVPDataType::UNSIGNED32:
        case DiameterAVPDataType::ENUMERATED: {
            auto val = parseUnsigned32(avp->data);
            if (val.has_value()) {
                avp->decoded_value = val.value();
                return true;
            }
            break;
        }
        case DiameterAVPDataType::UNSIGNED64: {
            auto val = parseUnsigned64(avp->data);
            if (val.has_value()) {
                avp->decoded_value = val.value();
                return true;
            }
            break;
        }
        case DiameterAVPDataType::FLOAT32: {
            auto val = parseFloat32(avp->data);
            if (val.has_value()) {
                avp->decoded_value = val.value();
                return true;
            }
            break;
        }
        case DiameterAVPDataType::FLOAT64: {
            auto val = parseFloat64(avp->data);
            if (val.has_value()) {
                avp->decoded_value = val.value();
                return true;
            }
            break;
        }
        case DiameterAVPDataType::UTF8STRING:
        case DiameterAVPDataType::DIAMETER_IDENTITY:
        case DiameterAVPDataType::DIAMETER_URI: {
            auto val = parseUTF8String(avp->data);
            if (val.has_value()) {
                avp->decoded_value = val.value();
                return true;
            }
            break;
        }
        case DiameterAVPDataType::IP_ADDRESS: {
            auto val = parseIPAddress(avp->data);
            if (val.has_value()) {
                avp->decoded_value = val.value();
                return true;
            }
            break;
        }
        case DiameterAVPDataType::GROUPED: {
            auto val = parseGrouped(avp->data);
            if (val.has_value()) {
                avp->decoded_value = val.value();
                return true;
            }
            break;
        }
        case DiameterAVPDataType::TIME: {
            // Store as uint32 for time values
            auto val = parseUnsigned32(avp->data);
            if (val.has_value()) {
                avp->decoded_value = val.value();
                return true;
            }
            break;
        }
        case DiameterAVPDataType::OCTET_STRING:
        default:
            // For octet string, just store the raw data
            avp->decoded_value = avp->data;
            return true;
    }

    return false;
}

// ============================================================================
// Data Type Parsers
// ============================================================================

std::optional<int32_t> DiameterAVPParser::parseInt32(const std::vector<uint8_t>& data) {
    if (data.size() != 4) {
        return std::nullopt;
    }

    int32_t value;
    std::memcpy(&value, data.data(), 4);
    return static_cast<int32_t>(ntohl(static_cast<uint32_t>(value)));
}

std::optional<int64_t> DiameterAVPParser::parseInt64(const std::vector<uint8_t>& data) {
    if (data.size() != 8) {
        return std::nullopt;
    }

    int64_t value;
    std::memcpy(&value, data.data(), 8);
    return static_cast<int64_t>(be64toh(static_cast<uint64_t>(value)));
}

std::optional<uint32_t> DiameterAVPParser::parseUnsigned32(const std::vector<uint8_t>& data) {
    if (data.size() != 4) {
        return std::nullopt;
    }

    uint32_t value;
    std::memcpy(&value, data.data(), 4);
    return ntohl(value);
}

std::optional<uint64_t> DiameterAVPParser::parseUnsigned64(const std::vector<uint8_t>& data) {
    if (data.size() != 8) {
        return std::nullopt;
    }

    uint64_t value;
    std::memcpy(&value, data.data(), 8);
    return be64toh(value);
}

std::optional<float> DiameterAVPParser::parseFloat32(const std::vector<uint8_t>& data) {
    if (data.size() != 4) {
        return std::nullopt;
    }

    uint32_t int_val;
    std::memcpy(&int_val, data.data(), 4);
    int_val = ntohl(int_val);

    float value;
    std::memcpy(&value, &int_val, 4);
    return value;
}

std::optional<double> DiameterAVPParser::parseFloat64(const std::vector<uint8_t>& data) {
    if (data.size() != 8) {
        return std::nullopt;
    }

    uint64_t int_val;
    std::memcpy(&int_val, data.data(), 8);
    int_val = be64toh(int_val);

    double value;
    std::memcpy(&value, &int_val, 8);
    return value;
}

std::optional<std::string> DiameterAVPParser::parseUTF8String(const std::vector<uint8_t>& data) {
    if (data.empty()) {
        return std::string();
    }

    // Validate UTF-8 (basic validation)
    if (!isPrintableUTF8(data)) {
        return std::nullopt;
    }

    return std::string(reinterpret_cast<const char*>(data.data()), data.size());
}

std::optional<std::string> DiameterAVPParser::parseDiameterIdentity(const std::vector<uint8_t>& data) {
    // DiameterIdentity is just a UTF8String containing an FQDN
    return parseUTF8String(data);
}

std::optional<std::string> DiameterAVPParser::parseDiameterURI(const std::vector<uint8_t>& data) {
    // DiameterURI is just a UTF8String in URI format
    return parseUTF8String(data);
}

std::optional<std::vector<std::shared_ptr<DiameterAVP>>> DiameterAVPParser::parseGrouped(const std::vector<uint8_t>& data) {
    if (data.empty()) {
        return std::vector<std::shared_ptr<DiameterAVP>>();
    }

    // Parse nested AVPs recursively
    std::vector<std::shared_ptr<DiameterAVP>> grouped_avps = parseAVPs(data.data(), data.size(), 0);
    return grouped_avps;
}

std::optional<std::array<uint8_t, 4>> DiameterAVPParser::parseIPv4Address(const std::vector<uint8_t>& data) {
    // IPv4 address format: 2 bytes address family + 4 bytes address
    if (data.size() != 6) {
        return std::nullopt;
    }

    // Check address family (1 = IPv4)
    uint16_t af;
    std::memcpy(&af, data.data(), 2);
    af = ntohs(af);

    if (af != 1) {
        return std::nullopt;
    }

    std::array<uint8_t, 4> addr;
    std::memcpy(addr.data(), data.data() + 2, 4);
    return addr;
}

std::optional<std::array<uint8_t, 16>> DiameterAVPParser::parseIPv6Address(const std::vector<uint8_t>& data) {
    // IPv6 address format: 2 bytes address family + 16 bytes address
    if (data.size() != 18) {
        return std::nullopt;
    }

    // Check address family (2 = IPv6)
    uint16_t af;
    std::memcpy(&af, data.data(), 2);
    af = ntohs(af);

    if (af != 2) {
        return std::nullopt;
    }

    std::array<uint8_t, 16> addr;
    std::memcpy(addr.data(), data.data() + 2, 16);
    return addr;
}

std::optional<std::string> DiameterAVPParser::parseIPAddress(const std::vector<uint8_t>& data) {
    if (data.size() < 2) {
        return std::nullopt;
    }

    // Read address family
    uint16_t af;
    std::memcpy(&af, data.data(), 2);
    af = ntohs(af);

    if (af == 1 && data.size() == 6) {
        // IPv4
        std::ostringstream oss;
        oss << static_cast<int>(data[2]) << "."
            << static_cast<int>(data[3]) << "."
            << static_cast<int>(data[4]) << "."
            << static_cast<int>(data[5]);
        return oss.str();
    } else if (af == 2 && data.size() == 18) {
        // IPv6
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (size_t i = 2; i < 18; i += 2) {
            if (i > 2) oss << ":";
            oss << std::setw(2) << static_cast<int>(data[i])
                << std::setw(2) << static_cast<int>(data[i + 1]);
        }
        return oss.str();
    }

    return std::nullopt;
}

std::optional<std::chrono::system_clock::time_point> DiameterAVPParser::parseTime(const std::vector<uint8_t>& data) {
    auto ntp_time = parseUnsigned32(data);
    if (!ntp_time.has_value()) {
        return std::nullopt;
    }

    // NTP epoch is 1900-01-01 00:00:00 UTC
    // Unix epoch is 1970-01-01 00:00:00 UTC
    // Difference is 2208988800 seconds
    const uint32_t NTP_TO_UNIX_OFFSET = 2208988800U;

    uint32_t unix_time = ntp_time.value() - NTP_TO_UNIX_OFFSET;
    return std::chrono::system_clock::from_time_t(unix_time);
}

std::vector<uint8_t> DiameterAVPParser::parseOctetString(const std::vector<uint8_t>& data) {
    return data;
}

// ============================================================================
// AVP Data Type Mapping
// ============================================================================

DiameterAVPDataType DiameterAVPParser::getAVPDataType(uint32_t code, std::optional<uint32_t> vendor_id) {
    // Base protocol AVPs
    if (!vendor_id.has_value() || vendor_id.value() == 0) {
        switch (static_cast<DiameterAVPCode>(code)) {
            // Unsigned32
            case DiameterAVPCode::RESULT_CODE:
            case DiameterAVPCode::AUTH_APPLICATION_ID:
            case DiameterAVPCode::ACCT_APPLICATION_ID:
            case DiameterAVPCode::VENDOR_ID:
            case DiameterAVPCode::FIRMWARE_REVISION:
            case DiameterAVPCode::ORIGIN_STATE_ID:
            case DiameterAVPCode::SESSION_TIMEOUT:
            case DiameterAVPCode::REDIRECT_HOST_USAGE:
            case DiameterAVPCode::REDIRECT_MAX_CACHE_TIME:
            case DiameterAVPCode::SESSION_BINDING:
            case DiameterAVPCode::SESSION_SERVER_FAILOVER:
            case DiameterAVPCode::MULTI_ROUND_TIME_OUT:
            case DiameterAVPCode::DISCONNECT_CAUSE:
            case DiameterAVPCode::AUTH_REQUEST_TYPE:
            case DiameterAVPCode::AUTH_GRACE_PERIOD:
            case DiameterAVPCode::AUTH_SESSION_STATE:
            case DiameterAVPCode::RE_AUTH_REQUEST_TYPE:
            case DiameterAVPCode::TERMINATION_CAUSE:
            case DiameterAVPCode::EXPERIMENTAL_RESULT_CODE:
            case DiameterAVPCode::INBAND_SECURITY_ID:
            case DiameterAVPCode::CC_REQUEST_TYPE:
            case DiameterAVPCode::CC_REQUEST_NUMBER:
            case DiameterAVPCode::CC_SESSION_FAILOVER:
            case DiameterAVPCode::ACCT_INTERIM_INTERVAL:
            case DiameterAVPCode::QOS_CLASS_IDENTIFIER:
            case DiameterAVPCode::MAX_REQUESTED_BANDWIDTH_UL:
            case DiameterAVPCode::MAX_REQUESTED_BANDWIDTH_DL:
            case DiameterAVPCode::GUARANTEED_BITRATE_UL:
            case DiameterAVPCode::GUARANTEED_BITRATE_DL:
            case DiameterAVPCode::RAT_TYPE:
                return DiameterAVPDataType::UNSIGNED32;

            // Unsigned64
            case DiameterAVPCode::CC_SUB_SESSION_ID:
            case DiameterAVPCode::CC_CORRELATION_ID:
                return DiameterAVPDataType::UNSIGNED64;

            // UTF8String / DiameterIdentity
            case DiameterAVPCode::SESSION_ID:
            case DiameterAVPCode::ORIGIN_HOST:
            case DiameterAVPCode::ORIGIN_REALM:
            case DiameterAVPCode::DESTINATION_HOST:
            case DiameterAVPCode::DESTINATION_REALM:
            case DiameterAVPCode::USER_NAME:
            case DiameterAVPCode::PRODUCT_NAME:
            case DiameterAVPCode::ERROR_MESSAGE:
            case DiameterAVPCode::ROUTE_RECORD:
            case DiameterAVPCode::PROXY_HOST:
            case DiameterAVPCode::ERROR_REPORTING_HOST:
            case DiameterAVPCode::SERVICE_SELECTION:
                return DiameterAVPDataType::UTF8STRING;

            // IP Address
            case DiameterAVPCode::HOST_IP_ADDRESS:
                return DiameterAVPDataType::IP_ADDRESS;

            // Time
            case DiameterAVPCode::EVENT_TIMESTAMP:
                return DiameterAVPDataType::TIME;

            // Grouped
            case DiameterAVPCode::VENDOR_SPECIFIC_APPLICATION_ID:
            case DiameterAVPCode::FAILED_AVP:
            case DiameterAVPCode::PROXY_INFO:
            case DiameterAVPCode::EXPERIMENTAL_RESULT:
                return DiameterAVPDataType::GROUPED;

            // OctetString
            case DiameterAVPCode::CLASS:
            case DiameterAVPCode::PROXY_STATE:
            case DiameterAVPCode::ACCOUNTING_SESSION_ID:
            case DiameterAVPCode::ACCT_MULTI_SESSION_ID:
            default:
                return DiameterAVPDataType::OCTET_STRING;
        }
    }

    // 3GPP vendor-specific AVPs (vendor ID 10415)
    if (vendor_id.has_value() && vendor_id.value() == DIAMETER_VENDOR_3GPP) {
        // Add 3GPP-specific AVP type mappings here
        // For now, default to OctetString
        return DiameterAVPDataType::OCTET_STRING;
    }

    // Default to OctetString for unknown AVPs
    return DiameterAVPDataType::OCTET_STRING;
}

// ============================================================================
// Validation and Helper Functions
// ============================================================================

bool DiameterAVPParser::validateAVP(const DiameterAVP& avp) {
    // Check minimum length
    size_t min_header_size = avp.vendor_specific ? DIAMETER_AVP_HEADER_VENDOR_SIZE : DIAMETER_AVP_HEADER_MIN_SIZE;
    if (avp.length < min_header_size) {
        return false;
    }

    // Check data size matches length
    size_t expected_data_size = avp.length - min_header_size;
    if (avp.data.size() != expected_data_size) {
        return false;
    }

    return true;
}

bool DiameterAVPParser::isPrintableUTF8(const std::vector<uint8_t>& data) {
    for (auto byte : data) {
        // Allow printable ASCII and extended UTF-8
        if (byte < 0x20 && byte != 0x09 && byte != 0x0A && byte != 0x0D) {
            return false;  // Non-printable control character
        }
    }
    return true;
}

}  // namespace diameter
}  // namespace callflow
