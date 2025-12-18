#pragma once

#include "common/types.h"
#include <optional>
#include <vector>
#include <nlohmann/json.hpp>

namespace callflow {

/**
 * 5G NAS Message Types (3GPP TS 24.501)
 */
enum class Nas5gMessageType : uint8_t {
    // 5GMM (Mobility Management) messages
    REGISTRATION_REQUEST = 0x41,
    REGISTRATION_ACCEPT = 0x42,
    REGISTRATION_COMPLETE = 0x43,
    REGISTRATION_REJECT = 0x44,
    DEREGISTRATION_REQUEST_UE_ORIGINATING = 0x45,
    DEREGISTRATION_ACCEPT_UE_ORIGINATING = 0x46,
    DEREGISTRATION_REQUEST_UE_TERMINATED = 0x47,
    DEREGISTRATION_ACCEPT_UE_TERMINATED = 0x48,
    SERVICE_REQUEST = 0x4c,
    SERVICE_REJECT = 0x4d,
    SERVICE_ACCEPT = 0x4e,
    CONFIGURATION_UPDATE_COMMAND = 0x54,
    CONFIGURATION_UPDATE_COMPLETE = 0x55,
    AUTHENTICATION_REQUEST = 0x56,
    AUTHENTICATION_RESPONSE = 0x57,
    AUTHENTICATION_REJECT = 0x58,
    AUTHENTICATION_FAILURE = 0x59,
    AUTHENTICATION_RESULT = 0x5a,
    IDENTITY_REQUEST = 0x5b,
    IDENTITY_RESPONSE = 0x5c,
    SECURITY_MODE_COMMAND = 0x5d,
    SECURITY_MODE_COMPLETE = 0x5e,
    SECURITY_MODE_REJECT = 0x5f,
    // 5GSM (Session Management) messages
    PDU_SESSION_ESTABLISHMENT_REQUEST = 0xc1,
    PDU_SESSION_ESTABLISHMENT_ACCEPT = 0xc2,
    PDU_SESSION_ESTABLISHMENT_REJECT = 0xc3,
    PDU_SESSION_AUTHENTICATION_COMMAND = 0xc5,
    PDU_SESSION_AUTHENTICATION_COMPLETE = 0xc6,
    PDU_SESSION_AUTHENTICATION_RESULT = 0xc7,
    PDU_SESSION_MODIFICATION_REQUEST = 0xc9,
    PDU_SESSION_MODIFICATION_REJECT = 0xca,
    PDU_SESSION_MODIFICATION_COMMAND = 0xcb,
    PDU_SESSION_MODIFICATION_COMPLETE = 0xcc,
    PDU_SESSION_MODIFICATION_COMMAND_REJECT = 0xcd,
    PDU_SESSION_RELEASE_REQUEST = 0xd1,
    PDU_SESSION_RELEASE_REJECT = 0xd2,
    PDU_SESSION_RELEASE_COMMAND = 0xd3,
    PDU_SESSION_RELEASE_COMPLETE = 0xd4
};

/**
 * 5G NAS Security Header Type
 */
enum class Nas5gSecurityHeaderType : uint8_t {
    PLAIN_NAS_MESSAGE = 0x00,
    INTEGRITY_PROTECTED = 0x01,
    INTEGRITY_PROTECTED_AND_CIPHERED = 0x02,
    INTEGRITY_PROTECTED_WITH_NEW_5G_SECURITY_CONTEXT = 0x03,
    INTEGRITY_PROTECTED_AND_CIPHERED_WITH_NEW_5G_SECURITY_CONTEXT = 0x04
};

/**
 * 5G Mobile Identity Type
 */
enum class Nas5gMobileIdentityType : uint8_t {
    NO_IDENTITY = 0,
    SUCI = 1,      // Subscription Concealed Identifier
    FIVE_G_GUTI = 2, // 5G Globally Unique Temporary Identifier
    IMEI = 3,
    FIVE_G_S_TMSI = 4, // 5G S-Temporary Mobile Subscriber Identity
    IMEISV = 5,
    MAC_ADDRESS = 6
};

/**
 * 5G NAS message structure
 */
struct Nas5gMessage {
    Nas5gSecurityHeaderType security_header_type;
    uint8_t message_type;
    std::vector<uint8_t> payload;

    // Decoded common fields
    std::optional<std::string> supi;       // SUPI (from SUCI or 5G-GUTI)
    std::optional<std::string> five_g_guti; // 5G-GUTI
    std::optional<uint8_t> pdu_session_id;
    std::optional<uint8_t> pti;            // Procedure Transaction Identifier
    std::optional<uint8_t> request_type;
    std::optional<std::string> dnn;        // Data Network Name (like APN in 4G)
    std::optional<std::string> s_nssai;    // Single Network Slice Selection Assistance Info

    nlohmann::json toJson() const;

    /**
     * Get message type for session correlation
     */
    MessageType getMessageType() const;

    /**
     * Get human-readable message type name
     */
    std::string getMessageTypeName() const;

    /**
     * Check if this is a 5GMM (Mobility Management) message
     */
    bool is5gmm() const;

    /**
     * Check if this is a 5GSM (Session Management) message
     */
    bool is5gsm() const;
};

/**
 * 5G NAS protocol parser (3GPP TS 24.501)
 * Handles 5G Non-Access Stratum messages
 */
class Nas5gParser {
public:
    Nas5gParser() = default;
    ~Nas5gParser() = default;

    /**
     * Parse 5G NAS message from NAS PDU
     * @param data NAS PDU data
     * @param len PDU length
     * @return Parsed 5G NAS message or nullopt if parsing fails
     */
    std::optional<Nas5gMessage> parse(const uint8_t* data, size_t len);

    /**
     * Check if data appears to be a 5G NAS message
     */
    static bool isNas5g(const uint8_t* data, size_t len);

private:
    /**
     * Parse 5G NAS header
     */
    std::optional<Nas5gMessage> parseHeader(const uint8_t* data, size_t len);

    /**
     * Parse 5GMM message body
     */
    void parse5gmmMessage(Nas5gMessage& msg);

    /**
     * Parse 5GSM message body
     */
    void parse5gsmMessage(Nas5gMessage& msg);

    /**
     * Extract Information Elements from payload
     */
    void extractIEs(Nas5gMessage& msg);

    /**
     * Decode Mobile Identity (SUCI, 5G-GUTI, etc.)
     */
    static std::optional<std::string> decodeMobileIdentity(const uint8_t* data, size_t len);

    /**
     * Decode SUCI (Subscription Concealed Identifier)
     */
    static std::optional<std::string> decodeSupci(const uint8_t* data, size_t len);

    /**
     * Decode 5G-GUTI
     */
    static std::optional<std::string> decode5gGuti(const uint8_t* data, size_t len);

    /**
     * Decode DNN (Data Network Name)
     */
    static std::optional<std::string> decodeDnn(const uint8_t* data, size_t len);

    /**
     * Decode S-NSSAI
     */
    static std::optional<std::string> decodeSNssai(const uint8_t* data, size_t len);
};

}  // namespace callflow
