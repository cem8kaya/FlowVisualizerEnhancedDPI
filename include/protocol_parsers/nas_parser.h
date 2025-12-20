#pragma once

#include <cstdint>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <vector>

#include "common/types.h"
#include "common/utils.h"

namespace callflow {

/**
 * NAS Security Header Type (TS 24.301 Section 9.3.1)
 */
enum class NasSecurityHeaderType : uint8_t {
    PLAIN_NAS_MESSAGE = 0,
    INTEGRITY_PROTECTED = 1,
    INTEGRITY_PROTECTED_CIPHERED = 2,
    INTEGRITY_PROTECTED_NEW_EPS_CONTEXT = 3,
    INTEGRITY_PROTECTED_CIPHERED_NEW_EPS_CONTEXT = 4,
    SECURITY_HEADER_FOR_SERVICE_REQUEST = 12,
    UNKNOWN = 0xFF
};

/**
 * NAS Protocol Discriminator (TS 24.007)
 */
enum class NasProtocolDiscriminator : uint8_t {
    EPS_SESSION_MANAGEMENT = 0x02,
    EPS_MOBILITY_MANAGEMENT = 0x07,
    UNKNOWN = 0xFF
};

/**
 * EMM Message Types (EPS Mobility Management - TS 24.301)
 */
enum class EmmMessageType : uint8_t {
    ATTACH_REQUEST = 0x41,                 // 65
    ATTACH_ACCEPT = 0x42,                  // 66
    ATTACH_COMPLETE = 0x43,                // 67
    ATTACH_REJECT = 0x44,                  // 68
    DETACH_REQUEST = 0x45,                 // 69
    DETACH_ACCEPT = 0x46,                  // 70
    TRACKING_AREA_UPDATE_REQUEST = 0x48,   // 72
    TRACKING_AREA_UPDATE_ACCEPT = 0x49,    // 73
    TRACKING_AREA_UPDATE_COMPLETE = 0x4A,  // 74
    TRACKING_AREA_UPDATE_REJECT = 0x4B,    // 75
    EXTENDED_SERVICE_REQUEST = 0x4C,       // 76
    SERVICE_REQUEST = 0x4E,                // 78
    SERVICE_REJECT = 0x4F,                 // 79
    GUTI_REALLOCATION_COMMAND = 0x50,      // 80
    GUTI_REALLOCATION_COMPLETE = 0x51,     // 81
    AUTHENTICATION_REQUEST = 0x52,         // 82
    AUTHENTICATION_RESPONSE = 0x53,        // 83
    AUTHENTICATION_REJECT = 0x54,          // 84
    AUTHENTICATION_FAILURE = 0x5C,         // 92
    IDENTITY_REQUEST = 0x55,               // 85
    IDENTITY_RESPONSE = 0x56,              // 86
    SECURITY_MODE_COMMAND = 0x5D,          // 93
    SECURITY_MODE_COMPLETE = 0x5E,         // 94
    SECURITY_MODE_REJECT = 0x5F,           // 95
    EMM_STATUS = 0x60,                     // 96
    EMM_INFORMATION = 0x61,                // 97
    DOWNLINK_NAS_TRANSPORT = 0x62,         // 98
    UPLINK_NAS_TRANSPORT = 0x63,           // 99
    CS_SERVICE_NOTIFICATION = 0x64,        // 100
    UNKNOWN = 0xFF
};

/**
 * ESM Message Types (EPS Session Management - TS 24.301)
 */
enum class EsmMessageType : uint8_t {
    ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REQUEST = 0xC1,    // 193
    ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_ACCEPT = 0xC2,     // 194
    ACTIVATE_DEFAULT_EPS_BEARER_CONTEXT_REJECT = 0xC3,     // 195
    ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_REQUEST = 0xC5,  // 197
    ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_ACCEPT = 0xC6,   // 198
    ACTIVATE_DEDICATED_EPS_BEARER_CONTEXT_REJECT = 0xC7,   // 199
    MODIFY_EPS_BEARER_CONTEXT_REQUEST = 0xC9,              // 201
    MODIFY_EPS_BEARER_CONTEXT_ACCEPT = 0xCA,               // 202
    MODIFY_EPS_BEARER_CONTEXT_REJECT = 0xCB,               // 203
    DEACTIVATE_EPS_BEARER_CONTEXT_REQUEST = 0xCD,          // 205
    DEACTIVATE_EPS_BEARER_CONTEXT_ACCEPT = 0xCE,           // 206
    PDN_CONNECTIVITY_REQUEST = 0xD0,                       // 208
    PDN_CONNECTIVITY_REJECT = 0xD1,                        // 209
    PDN_DISCONNECT_REQUEST = 0xD2,                         // 210
    PDN_DISCONNECT_REJECT = 0xD3,                          // 211
    BEARER_RESOURCE_ALLOCATION_REQUEST = 0xD4,             // 212
    BEARER_RESOURCE_ALLOCATION_REJECT = 0xD5,              // 213
    BEARER_RESOURCE_MODIFICATION_REQUEST = 0xD6,           // 214
    BEARER_RESOURCE_MODIFICATION_REJECT = 0xD7,            // 215
    ESM_INFORMATION_REQUEST = 0xD9,                        // 217
    ESM_INFORMATION_RESPONSE = 0xDA,                       // 218
    ESM_STATUS = 0xE8,                                     // 232
    UNKNOWN = 0xFF
};

/**
 * NAS Information Element Types
 */
enum class NasIeType : uint8_t {
    EPS_MOBILE_IDENTITY = 0x23,
    EPS_ATTACH_RESULT = 0x27,
    ESM_MESSAGE_CONTAINER = 0x78,
    ACCESS_POINT_NAME = 0x28,
    PDN_ADDRESS = 0x29,
    PDN_TYPE = 0x0D,
    EPS_QUALITY_OF_SERVICE = 0x30,
    ESM_CAUSE = 0x58,
    PROTOCOL_CONFIGURATION_OPTIONS = 0x27,
    TRACKING_AREA_IDENTITY = 0x54,
    GUTI = 0x50,
    UNKNOWN = 0xFF
};

// Forward declaration
class NasSecurityContext;

/**
 * Generic NAS Information Element
 */
struct LteNasIe {
    uint8_t iei;
    std::string name;
    std::vector<uint8_t> raw_data;
    std::string decoded_value;

    nlohmann::json toJson() const {
        return {{"iei", iei},
                {"name", name},
                {"hex_value", utils::bytesToHex(raw_data.data(), raw_data.size())},
                {"decoded_value", decoded_value}};
    }
};

/**
 * LTE NAS Message Structure
 */
struct LteNasMessage {
    NasSecurityHeaderType security_header_type;
    NasProtocolDiscriminator protocol_discriminator;
    uint8_t message_type;  // EMM or ESM message type

    // Security context (if protected)
    std::optional<uint32_t> message_authentication_code;
    std::optional<uint8_t> sequence_number;

    // UE identity fields
    std::optional<std::string> imsi;
    std::optional<std::string> guti;
    std::optional<uint32_t> tmsi;

    // Decoded IEs (common fields)
    std::optional<std::string> apn;
    std::optional<uint8_t> pdn_type;
    std::optional<uint8_t> esm_cause;

    // Recursive IEs
    std::vector<LteNasIe> ies;

    // Raw message bytes (for further processing)
    std::vector<uint8_t> raw_data;

    /**
     * Get message type name
     */
    std::string getMessageTypeName() const;

    /**
     * Check if message is EMM
     */
    bool isEmm() const;

    /**
     * Check if message is ESM
     */
    bool isEsm() const;

    /**
     * Check if message is security protected
     */
    bool isProtected() const;

    /**
     * Convert to JSON
     */
    nlohmann::json toJson() const;
};

/**
 * NAS Protocol Parser (EMM/ESM)
 */
class NasParser {
public:
    NasParser() = default;
    ~NasParser() = default;

    /**
     * Parse NAS message from buffer
     * @param data NAS message data
     * @param len Message length
     * @param context Optional security context for decryption
     * @return Parsed NAS message or nullopt if parsing fails
     */
    std::optional<LteNasMessage> parse(const uint8_t* data, size_t len,
                                       NasSecurityContext* context = nullptr);

    /**
     * Check if data appears to be a NAS message
     */
    static bool isNas(const uint8_t* data, size_t len);

private:
    /**
     * Parse security header
     */
    bool parseSecurityHeader(const uint8_t* data, size_t len, LteNasMessage& msg, size_t& offset);

    /**
     * Parse plain NAS message (no security)
     */
    bool parsePlainMessage(const uint8_t* data, size_t len, LteNasMessage& msg);

    // Helpers to extract IEs
    void extractIEs(LteNasMessage& msg);

    // Decoding helpers
    std::optional<std::string> decodeMobileIdentity(const uint8_t* data, size_t len);
    std::string decodeApn(const uint8_t* data, size_t len);

    // Legacy helpers (can be deprecated or used by extractIEs)
    bool parseEmmMessage(const uint8_t* data, size_t len, size_t offset, LteNasMessage& msg);
    bool parseEsmMessage(const uint8_t* data, size_t len, size_t offset, LteNasMessage& msg);
    std::optional<std::string> extractImsi(const uint8_t* data, size_t len);
    std::optional<std::string> extractGuti(const uint8_t* data, size_t len);
};

/**
 * Convert NAS enums to strings
 */
std::string nasSecurityHeaderTypeToString(NasSecurityHeaderType type);
std::string nasProtocolDiscriminatorToString(NasProtocolDiscriminator pd);
std::string emmMessageTypeToString(EmmMessageType type);
std::string esmMessageTypeToString(EsmMessageType type);

}  // namespace callflow
