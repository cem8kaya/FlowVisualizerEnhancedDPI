#include "pcap_ingest/interface_detector.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <regex>

#include "common/logger.h"

namespace callflow {

// Static definitions for linker
constexpr uint16_t InterfaceDetector::PORT_S1_MME;
constexpr uint16_t InterfaceDetector::PORT_N2;
constexpr uint16_t InterfaceDetector::PORT_X2_C;
constexpr uint16_t InterfaceDetector::PORT_GTP_C;
constexpr uint16_t InterfaceDetector::PORT_GTP_U;
constexpr uint16_t InterfaceDetector::PORT_PFCP;
constexpr uint16_t InterfaceDetector::PORT_DIAMETER;
constexpr uint16_t InterfaceDetector::PORT_SIP;
constexpr uint16_t InterfaceDetector::PORT_SIP_TLS;
constexpr uint16_t InterfaceDetector::PORT_HTTP;
constexpr uint16_t InterfaceDetector::PORT_HTTPS;
constexpr uint16_t InterfaceDetector::PORT_DNS;
constexpr uint16_t InterfaceDetector::PORT_RTP_MIN;
constexpr uint16_t InterfaceDetector::PORT_RTP_MAX;

// Helper function for case-insensitive string search
bool InterfaceDetector::containsIgnoreCase(const std::string& haystack, const std::string& needle) {
    auto it =
        std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end(),
                    [](char ch1, char ch2) { return std::toupper(ch1) == std::toupper(ch2); });
    return (it != haystack.end());
}

// Helper function for pattern matching
bool InterfaceDetector::matchesPattern(const std::string& text, const std::string& pattern) {
    try {
        std::regex regex(pattern, std::regex_constants::icase);
        return std::regex_search(text, regex);
    } catch (const std::regex_error& e) {
        LOG_WARN("Regex error in pattern matching: " << e.what());
        return false;
    }
}

PcapngInterfaceInfo::TelecomInterface InterfaceDetector::detectTelecomInterface(
    const std::string& name, const std::string& description) {
    using TI = PcapngInterfaceInfo::TelecomInterface;

    // Combine name and description for pattern matching
    std::string combined = name + " " + description;

    // LTE/4G Interface Detection

    // S1-MME: Control plane between eNodeB and MME
    if (matchesPattern(combined, R"(S1[-_]?MME|S1[-_]?AP|S1[-_]?CP)") ||
        containsIgnoreCase(combined, "S1-MME") || containsIgnoreCase(combined, "S1AP") ||
        matchesPattern(combined, R"(\bS1\b.*MME)")) {
        return TI::S1_MME;
    }

    // S1-U: User plane between eNodeB and S-GW
    if (matchesPattern(combined, R"(S1[-_]?U\b|S1[-_]?UP)") ||
        containsIgnoreCase(combined, "S1-U") || matchesPattern(combined, R"(\bS1\b.*user)")) {
        return TI::S1_U;
    }

    // X2-C: X2 Control Plane (eNodeB to eNodeB)
    if (matchesPattern(combined, R"(X2[-_]?C\b|X2[-_]?CP|X2[-_]?AP)") ||
        containsIgnoreCase(combined, "X2-C") || containsIgnoreCase(combined, "X2AP")) {
        return TI::X2_C;
    }

    // S5/S8 Control Plane
    if (matchesPattern(combined, R"(S[58][-_]?C\b|S[58][-_]?CP)") ||
        containsIgnoreCase(combined, "S5-C") || containsIgnoreCase(combined, "S8-C") ||
        matchesPattern(combined, R"((S5|S8).*control)")) {
        return TI::S5_S8_C;
    }

    // S5/S8 User Plane
    if (matchesPattern(combined, R"(S[58][-_]?U\b|S[58][-_]?UP)") ||
        containsIgnoreCase(combined, "S5-U") || containsIgnoreCase(combined, "S8-U") ||
        matchesPattern(combined, R"((S5|S8).*user)")) {
        return TI::S5_S8_U;
    }

    // S6a: MME to HSS (Diameter)
    if (matchesPattern(combined, R"(S6a|S6d)") || containsIgnoreCase(combined, "S6a") ||
        matchesPattern(combined, R"(\bS6\b.*HSS)")) {
        return TI::S6A;
    }

    // Gx: PCEF to PCRF (Diameter)
    if (matchesPattern(combined, R"(\bGx\b)") || containsIgnoreCase(combined, "Gx") ||
        matchesPattern(combined, R"(PCRF.*PCEF|PCEF.*PCRF)")) {
        return TI::GX;
    }

    // Rx: P-CSCF to PCRF (Diameter)
    if (matchesPattern(combined, R"(\bRx\b)") || containsIgnoreCase(combined, "Rx") ||
        matchesPattern(combined, R"(P-CSCF.*PCRF)")) {
        return TI::RX;
    }

    // Gy: PCEF to OCS (Diameter)
    if (matchesPattern(combined, R"(\bGy\b)") || containsIgnoreCase(combined, "Gy") ||
        matchesPattern(combined, R"(OCS|online.*charging)")) {
        return TI::GY;
    }

    // SGi: P-GW to external PDN
    if (matchesPattern(combined, R"(SGi|SGI|Gi)") || containsIgnoreCase(combined, "SGi") ||
        containsIgnoreCase(combined, "internet") ||
        matchesPattern(combined, R"(PDN|external|internet.*gateway)")) {
        return TI::SG_I;
    }

    // 5G/NR Interface Detection

    // N2: gNB to AMF (5G control plane)
    if (matchesPattern(combined, R"(\bN2\b)") || containsIgnoreCase(combined, "N2") ||
        matchesPattern(combined, R"(NGAP|AMF.*gNB|gNB.*AMF)")) {
        return TI::N2;
    }

    // N3: gNB to UPF (5G user plane)
    if (matchesPattern(combined, R"(\bN3\b)") || containsIgnoreCase(combined, "N3") ||
        matchesPattern(combined, R"(gNB.*UPF.*user)")) {
        return TI::N3;
    }

    // N4: SMF to UPF (PFCP)
    if (matchesPattern(combined, R"(\bN4\b)") || containsIgnoreCase(combined, "N4") ||
        matchesPattern(combined, R"(PFCP|SMF.*UPF)")) {
        return TI::N4;
    }

    // N6: UPF to Data Network (5G SGi equivalent)
    if (matchesPattern(combined, R"(\bN6\b)") || containsIgnoreCase(combined, "N6") ||
        matchesPattern(combined, R"(5G.*internet|5G.*PDN)")) {
        return TI::N6;
    }

    // IMS Interface Detection

    // IMS SIP Interface
    if (matchesPattern(combined, R"(IMS|SIP|P-CSCF|S-CSCF|I-CSCF)") ||
        containsIgnoreCase(combined, "SIP") || containsIgnoreCase(combined, "IMS")) {
        return TI::IMS_SIP;
    }

    // RTP Media
    if (matchesPattern(combined, R"(RTP|media|voice|video)") ||
        containsIgnoreCase(combined, "RTP") || containsIgnoreCase(combined, "media")) {
        return TI::RTP_MEDIA;
    }

    return TI::UNKNOWN;
}

PcapngInterfaceInfo::TelecomInterface InterfaceDetector::detectFromTraffic(
    const std::set<uint16_t>& observed_ports,
    const std::map<std::string, uint64_t>& protocol_hints) {
    using TI = PcapngInterfaceInfo::TelecomInterface;

    // Try SCTP-based detection first
    auto sctp_type = detectFromSctpPorts(observed_ports);
    if (sctp_type != TI::UNKNOWN) {
        return sctp_type;
    }

    // Try GTP-based detection
    auto gtp_type = detectFromGtpPorts(observed_ports);
    if (gtp_type != TI::UNKNOWN) {
        return gtp_type;
    }

    // Check for Diameter traffic
    bool has_diameter = (protocol_hints.count("DIAMETER") > 0 && protocol_hints.at("DIAMETER") > 0);
    auto diameter_type = detectFromDiameter(observed_ports, has_diameter);
    if (diameter_type != TI::UNKNOWN) {
        return diameter_type;
    }

    // Check for SIP traffic
    if (observed_ports.count(PORT_SIP) > 0 || observed_ports.count(PORT_SIP_TLS) > 0) {
        return TI::IMS_SIP;
    }

    // Check for RTP traffic (ports in range 10000-20000)
    for (uint16_t port : observed_ports) {
        if (port >= PORT_RTP_MIN && port <= PORT_RTP_MAX) {
            return TI::RTP_MEDIA;
        }
    }

    // Check for internet-facing traffic (HTTP/HTTPS)
    if (observed_ports.count(PORT_HTTP) > 0 || observed_ports.count(PORT_HTTPS) > 0) {
        // Could be SGi or N6
        bool has_5g_indicators =
            (protocol_hints.count("NGAP") > 0 || protocol_hints.count("PFCP") > 0);
        return has_5g_indicators ? TI::N6 : TI::SG_I;
    }

    return TI::UNKNOWN;
}

PcapngInterfaceInfo::TelecomInterface InterfaceDetector::detectFromSctpPorts(
    const std::set<uint16_t>& ports) {
    using TI = PcapngInterfaceInfo::TelecomInterface;

    // S1-MME uses SCTP port 36412
    if (ports.count(PORT_S1_MME) > 0) {
        return TI::S1_MME;
    }

    // N2 (5G) uses SCTP port 38412
    if (ports.count(PORT_N2) > 0) {
        return TI::N2;
    }

    // X2-C uses SCTP port 36422
    if (ports.count(PORT_X2_C) > 0) {
        return TI::X2_C;
    }

    return TI::UNKNOWN;
}

PcapngInterfaceInfo::TelecomInterface InterfaceDetector::detectFromGtpPorts(
    const std::set<uint16_t>& ports) {
    using TI = PcapngInterfaceInfo::TelecomInterface;

    // GTP-C (control plane) uses port 2123
    if (ports.count(PORT_GTP_C) > 0) {
        return TI::S5_S8_C;  // Could also be S11, but S5/S8 is more common
    }

    // GTP-U (user plane) uses port 2152
    if (ports.count(PORT_GTP_U) > 0) {
        // Could be S1-U, S5/S8-U, or N3
        // Without additional context, default to S1-U as it's most common
        return TI::S1_U;
    }

    // PFCP (N4 in 5G) uses port 8805
    if (ports.count(PORT_PFCP) > 0) {
        return TI::N4;
    }

    return TI::UNKNOWN;
}

PcapngInterfaceInfo::TelecomInterface InterfaceDetector::detectFromDiameter(
    const std::set<uint16_t>& ports, bool has_diameter_traffic) {
    using TI = PcapngInterfaceInfo::TelecomInterface;

    if (!has_diameter_traffic || ports.count(PORT_DIAMETER) == 0) {
        return TI::UNKNOWN;
    }

    // Diameter is used for S6a, Gx, Rx, Gy
    // Without deeper inspection, we can't distinguish between them
    // Default to S6A as it's the most fundamental (authentication)
    return TI::S6A;
}

std::string InterfaceDetector::toString(PcapngInterfaceInfo::TelecomInterface type) {
    using TI = PcapngInterfaceInfo::TelecomInterface;

    switch (type) {
        case TI::UNKNOWN:
            return "UNKNOWN";
        case TI::S1_MME:
            return "S1-MME";
        case TI::S1_U:
            return "S1-U";
        case TI::S5_S8_C:
            return "S5/S8-C";
        case TI::S5_S8_U:
            return "S5/S8-U";
        case TI::S6A:
            return "S6a";
        case TI::SG_I:
            return "SGi";
        case TI::GX:
            return "Gx";
        case TI::RX:
            return "Rx";
        case TI::GY:
            return "Gy";
        case TI::X2_C:
            return "X2-C";
        case TI::N2:
            return "N2";
        case TI::N3:
            return "N3";
        case TI::N4:
            return "N4";
        case TI::N6:
            return "N6";
        case TI::IMS_SIP:
            return "IMS-SIP";
        case TI::RTP_MEDIA:
            return "RTP-Media";
        default:
            return "UNKNOWN";
    }
}

std::vector<uint16_t> InterfaceDetector::getWellKnownPorts(
    PcapngInterfaceInfo::TelecomInterface type) {
    using TI = PcapngInterfaceInfo::TelecomInterface;

    switch (type) {
        case TI::S1_MME:
            return {PORT_S1_MME};
        case TI::S1_U:
        case TI::S5_S8_U:
        case TI::N3:
            return {PORT_GTP_U};
        case TI::S5_S8_C:
            return {PORT_GTP_C};
        case TI::S6A:
        case TI::GX:
        case TI::RX:
        case TI::GY:
            return {PORT_DIAMETER};
        case TI::X2_C:
            return {PORT_X2_C};
        case TI::N2:
            return {PORT_N2};
        case TI::N4:
            return {PORT_PFCP};
        case TI::SG_I:
        case TI::N6:
            return {PORT_HTTP, PORT_HTTPS, PORT_DNS};
        case TI::IMS_SIP:
            return {PORT_SIP, PORT_SIP_TLS};
        case TI::RTP_MEDIA:
            return {PORT_RTP_MIN, PORT_RTP_MAX};
        default:
            return {};
    }
}

std::vector<std::string> InterfaceDetector::getExpectedProtocols(
    PcapngInterfaceInfo::TelecomInterface type) {
    using TI = PcapngInterfaceInfo::TelecomInterface;

    switch (type) {
        case TI::S1_MME:
            return {"SCTP", "S1AP"};
        case TI::S1_U:
        case TI::S5_S8_U:
        case TI::N3:
            return {"UDP", "GTP-U", "IP"};
        case TI::S5_S8_C:
            return {"UDP", "GTP-C"};
        case TI::S6A:
        case TI::GX:
        case TI::RX:
        case TI::GY:
            return {"TCP", "SCTP", "DIAMETER"};
        case TI::X2_C:
            return {"SCTP", "X2AP"};
        case TI::N2:
            return {"SCTP", "NGAP"};
        case TI::N4:
            return {"UDP", "PFCP"};
        case TI::SG_I:
        case TI::N6:
            return {"TCP", "UDP", "HTTP", "HTTPS", "DNS", "TLS"};
        case TI::IMS_SIP:
            return {"UDP", "TCP", "SIP"};
        case TI::RTP_MEDIA:
            return {"UDP", "RTP", "RTCP"};
        default:
            return {};
    }
}

}  // namespace callflow
