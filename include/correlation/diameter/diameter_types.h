#pragma once

#include "protocol_parsers/diameter/diameter_types.h"
#include <cstdint>
#include <string>
#include <unordered_map>
#include <optional>

namespace callflow {
namespace correlation {

// Re-export protocol parser types for convenience
using diameter::DiameterInterface;
using diameter::DiameterCommandCode;
using diameter::DiameterApplicationID;

/**
 * @brief CC-Request-Type values for Gx/Gy sessions (RFC 4006)
 */
enum class DiameterCCRequestType : uint32_t {
    INITIAL = 1,      // Session establishment (CCR-I)
    UPDATE = 2,       // Session modification (CCR-U)
    TERMINATION = 3,  // Session termination (CCR-T)
    EVENT = 4         // Event-based charging (one-time)
};

/**
 * @brief Diameter message direction for correlation
 */
enum class DiameterDirection {
    REQUEST,
    ANSWER
};

/**
 * @brief Result code analysis
 */
struct DiameterResultCode {
    uint32_t code;
    bool is_success;        // 2xxx codes
    bool is_protocol_error; // 3xxx codes
    bool is_transient;      // 4xxx codes
    bool is_permanent;      // 5xxx codes
    std::string description;

    /**
     * @brief Parse standard Diameter result code
     */
    static DiameterResultCode parse(uint32_t result_code);

    /**
     * @brief Parse experimental result code (3GPP-specific)
     */
    static DiameterResultCode parseExperimental(uint32_t vendor_id,
                                                 uint32_t result_code);
};

// ============================================================================
// 3GPP Vendor-Specific AVP Codes
// ============================================================================

namespace AVPCode3GPP {
    constexpr uint32_t SUBSCRIPTION_ID = 443;           // Subscription-Id (grouped)
    constexpr uint32_t SUBSCRIPTION_ID_TYPE = 450;     // Subscription-Id-Type
    constexpr uint32_t SUBSCRIPTION_ID_DATA = 444;     // Subscription-Id-Data (IMSI, MSISDN)

    constexpr uint32_t FRAMED_IP_ADDRESS = 8;          // Framed-IP-Address (RADIUS)
    constexpr uint32_t FRAMED_IPV6_PREFIX = 97;        // Framed-IPv6-Prefix (RADIUS)
    constexpr uint32_t CALLED_STATION_ID = 30;         // Called-Station-Id (APN)

    // 3GPP Vendor-Specific (Vendor-ID 10415)
    constexpr uint32_t TGPP_IMSI = 1;                  // 3GPP-IMSI
    constexpr uint32_t TGPP_MSISDN = 701;              // 3GPP-MSISDN
    constexpr uint32_t TGPP_CHARGING_ID = 2;           // 3GPP-Charging-Id
    constexpr uint32_t TGPP_GGSN_ADDRESS = 7;          // 3GPP-GGSN-Address
    constexpr uint32_t TGPP_SGSN_ADDRESS = 6;          // 3GPP-SGSN-Address
    constexpr uint32_t TGPP_RAT_TYPE = 21;             // 3GPP-RAT-Type
    constexpr uint32_t TGPP_USER_LOCATION_INFO = 22;   // 3GPP-User-Location-Info

    // Gx-specific
    constexpr uint32_t CHARGING_RULE_INSTALL = 1001;   // Charging-Rule-Install
    constexpr uint32_t CHARGING_RULE_REMOVE = 1002;    // Charging-Rule-Remove
    constexpr uint32_t CHARGING_RULE_NAME = 1005;      // Charging-Rule-Name
    constexpr uint32_t QOS_INFORMATION = 1016;         // QoS-Information
    constexpr uint32_t QOS_CLASS_IDENTIFIER = 1028;    // QCI
    constexpr uint32_t BEARER_IDENTIFIER = 1020;       // Bearer-Identifier
    constexpr uint32_t BEARER_OPERATION = 1021;        // Bearer-Operation

    // Rx-specific
    constexpr uint32_t MEDIA_COMPONENT_DESCRIPTION = 517;  // Media-Component-Description
    constexpr uint32_t MEDIA_TYPE = 520;                   // Media-Type
    constexpr uint32_t FLOW_STATUS = 511;                  // Flow-Status
    constexpr uint32_t AF_APPLICATION_IDENTIFIER = 504;    // AF-Application-Identifier
    constexpr uint32_t FRAMED_IP_ADDRESS_V6 = 8;           // Framed-IP-Address (for IPv6)

    // S6a-specific
    constexpr uint32_t ULR_FLAGS = 1405;               // ULR-Flags
    constexpr uint32_t ULA_FLAGS = 1406;               // ULA-Flags
    constexpr uint32_t VISITED_PLMN_ID = 1407;         // Visited-PLMN-Id
    constexpr uint32_t AUTHENTICATION_INFO = 1413;     // Authentication-Info
    constexpr uint32_t SUBSCRIPTION_DATA = 1400;       // Subscription-Data

    // Cx-specific
    constexpr uint32_t PUBLIC_IDENTITY = 601;          // Public-Identity (IMS)
    constexpr uint32_t SERVER_NAME = 602;              // Server-Name (S-CSCF)
    constexpr uint32_t SIP_AUTH_DATA_ITEM = 612;       // SIP-Auth-Data-Item
    constexpr uint32_t USER_DATA_SH = 606;             // User-Data (Sh interface)
}

// ============================================================================
// Subscription-Id-Type values (RFC 4006)
// ============================================================================

enum class SubscriptionIdType : uint32_t {
    END_USER_E164 = 0,      // MSISDN (E.164)
    END_USER_IMSI = 1,      // IMSI
    END_USER_SIP_URI = 2,   // SIP URI
    END_USER_NAI = 3,       // Network Access Identifier
    END_USER_PRIVATE = 4    // Private identity
};

// ============================================================================
// RAT-Type values (3GPP TS 29.212)
// ============================================================================

enum class RatType : uint32_t {
    WLAN = 0,
    VIRTUAL = 1,
    UTRAN = 1000,           // 3G
    GERAN = 1001,           // 2G
    GAN = 1002,
    HSPA_EVOLUTION = 1003,
    EUTRAN = 1004,          // 4G LTE
    CDMA2000_1X = 2000,
    HRPD = 2001,
    UMB = 2002,
    EHRPD = 2003,
    NR = 1005               // 5G (if applicable)
};

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * @brief Get interface from Application-ID
 */
DiameterInterface getInterfaceFromAppId(uint32_t application_id);

/**
 * @brief Get interface name string
 */
std::string interfaceToString(DiameterInterface iface);

/**
 * @brief Get command description
 */
std::string getCommandDescription(uint32_t command_code);

/**
 * @brief Get CC-Request-Type name
 */
std::string getCCRequestTypeName(DiameterCCRequestType type);

/**
 * @brief Get RAT-Type name
 */
std::string getRatTypeName(RatType rat);

/**
 * @brief Check if command code is for session establishment
 */
bool isSessionEstablishment(uint32_t command_code, DiameterInterface iface);

/**
 * @brief Check if command code is for session termination
 */
bool isSessionTermination(uint32_t command_code, DiameterInterface iface);

} // namespace correlation
} // namespace callflow
