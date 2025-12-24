#pragma once

#include "protocol_parsers/gtp/gtpv2_types.h"
#include <cstdint>
#include <string>
#include <optional>

namespace callflow {
namespace correlation {

// Re-export protocol parser types for convenience
using gtp::GtpV2MessageType;
using gtp::GtpV2IEType;
using gtp::CauseValue;
using gtp::PDNType;
using gtp::RATType;
using gtp::FTEIDInterfaceType;
using gtp::GtpV2FTEID;
using gtp::GtpV2BearerQoS;
using gtp::GtpV2PDNAddressAllocation;
using gtp::GtpV2Cause;

/**
 * @brief PDN Type classification (from APN)
 */
enum class PdnClass {
    IMS,        // IMS APN for VoLTE
    INTERNET,   // Default internet APN
    EMERGENCY,  // Emergency services
    MMS,        // MMS APN
    OTHER       // Other APNs
};

/**
 * @brief Bearer types
 */
enum class BearerType {
    DEFAULT,     // Default EPS bearer (EBI = LBI)
    DEDICATED    // Dedicated bearer (linked to default via LBI)
};

/**
 * @brief GTPv2 message direction for correlation
 */
enum class Gtpv2Direction {
    REQUEST,
    RESPONSE
};

/**
 * @brief Helper Functions
 */

/**
 * @brief Get message type name
 */
std::string getMessageTypeName(GtpV2MessageType type);

/**
 * @brief Check if message is a request
 */
bool isRequest(GtpV2MessageType type);

/**
 * @brief Check if message is a response
 */
bool isResponse(GtpV2MessageType type);

/**
 * @brief Get direction of message
 */
Gtpv2Direction getDirection(GtpV2MessageType type);

/**
 * @brief Classify PDN type from APN string
 */
PdnClass classifyPdnFromApn(const std::string& apn);

/**
 * @brief Check if cause is success
 */
bool isSuccessCause(CauseValue cause);

/**
 * @brief Check if message is session establishment
 */
bool isSessionEstablishment(GtpV2MessageType type);

/**
 * @brief Check if message is session termination
 */
bool isSessionTermination(GtpV2MessageType type);

/**
 * @brief Check if message is bearer creation
 */
bool isBearerCreation(GtpV2MessageType type);

/**
 * @brief Check if message is bearer modification
 */
bool isBearerModification(GtpV2MessageType type);

/**
 * @brief Check if message is bearer deletion
 */
bool isBearerDeletion(GtpV2MessageType type);

/**
 * @brief Get F-TEID interface type name
 */
std::string getFteidInterfaceName(FTEIDInterfaceType type);

/**
 * @brief Get RAT type name
 */
std::string getRatTypeName(RATType rat);

/**
 * @brief Get PDN type name
 */
std::string getPdnTypeName(PDNType pdn);

/**
 * @brief Get PDN class name
 */
std::string getPdnClassName(PdnClass pdn_class);

/**
 * @brief Get cause value name
 */
std::string getCauseValueName(CauseValue cause);

} // namespace correlation
} // namespace callflow
