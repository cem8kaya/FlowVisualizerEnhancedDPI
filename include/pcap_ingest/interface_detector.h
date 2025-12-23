#pragma once

#include "pcap_ingest/pcapng_reader.h"
#include <string>
#include <vector>
#include <map>
#include <set>
#include <cstdint>

namespace callflow {

/**
 * Interface Detector - Auto-detects telecom interface types based on heuristics
 *
 * This class provides static methods to automatically detect the type of telecom
 * interface based on various heuristics including:
 * - Interface name patterns (e.g., "S1", "Gx", "N2")
 * - Interface description patterns
 * - Observed traffic characteristics (ports, protocols)
 */
class InterfaceDetector {
public:
    /**
     * Detect telecom interface type from name and description
     *
     * This method analyzes the interface name and description to infer
     * the telecom interface type using pattern matching.
     *
     * @param name Interface name (e.g., "eth0-S1-MME", "S1", "Gx")
     * @param description Interface description (e.g., "S1-MME Control Plane")
     * @return Detected telecom interface type
     */
    static PcapngInterfaceInfo::TelecomInterface detectTelecomInterface(
        const std::string& name,
        const std::string& description);

    /**
     * Detect interface type from observed traffic patterns
     *
     * Analyzes observed ports and protocols to determine interface type.
     * This is useful when interface names/descriptions are not informative.
     *
     * @param observed_ports Set of ports seen on this interface
     * @param protocol_hints Map of protocol types to packet counts
     * @return Detected telecom interface type
     */
    static PcapngInterfaceInfo::TelecomInterface detectFromTraffic(
        const std::set<uint16_t>& observed_ports,
        const std::map<std::string, uint64_t>& protocol_hints);

    /**
     * Detect interface type from SCTP ports
     *
     * @param ports Set of observed SCTP ports
     * @return Detected interface type or UNKNOWN
     */
    static PcapngInterfaceInfo::TelecomInterface detectFromSctpPorts(
        const std::set<uint16_t>& ports);

    /**
     * Detect interface type from UDP/GTP ports
     *
     * @param ports Set of observed UDP ports
     * @return Detected interface type or UNKNOWN
     */
    static PcapngInterfaceInfo::TelecomInterface detectFromGtpPorts(
        const std::set<uint16_t>& ports);

    /**
     * Detect interface type from Diameter characteristics
     *
     * @param ports Set of observed TCP/SCTP ports
     * @param has_diameter_traffic True if Diameter traffic detected
     * @return Detected interface type or UNKNOWN
     */
    static PcapngInterfaceInfo::TelecomInterface detectFromDiameter(
        const std::set<uint16_t>& ports,
        bool has_diameter_traffic);

    /**
     * Get human-readable string for telecom interface type
     *
     * @param type Telecom interface type
     * @return String representation (e.g., "S1-MME", "S1-U")
     */
    static std::string toString(PcapngInterfaceInfo::TelecomInterface type);

    /**
     * Get well-known ports for a given interface type
     *
     * @param type Telecom interface type
     * @return Vector of well-known ports for this interface
     */
    static std::vector<uint16_t> getWellKnownPorts(
        PcapngInterfaceInfo::TelecomInterface type);

    /**
     * Get expected protocols for a given interface type
     *
     * @param type Telecom interface type
     * @return Vector of expected protocol names
     */
    static std::vector<std::string> getExpectedProtocols(
        PcapngInterfaceInfo::TelecomInterface type);

private:
    // Pattern matching helpers
    static bool containsIgnoreCase(const std::string& haystack, const std::string& needle);
    static bool matchesPattern(const std::string& text, const std::string& pattern);

    // Well-known port definitions
    static constexpr uint16_t PORT_S1_MME = 36412;      // SCTP
    static constexpr uint16_t PORT_N2 = 38412;          // SCTP (5G)
    static constexpr uint16_t PORT_X2_C = 36422;        // SCTP
    static constexpr uint16_t PORT_GTP_C = 2123;        // UDP
    static constexpr uint16_t PORT_GTP_U = 2152;        // UDP
    static constexpr uint16_t PORT_PFCP = 8805;         // UDP (N4 in 5G)
    static constexpr uint16_t PORT_DIAMETER = 3868;     // TCP/SCTP
    static constexpr uint16_t PORT_SIP = 5060;          // UDP/TCP
    static constexpr uint16_t PORT_SIP_TLS = 5061;      // TCP
    static constexpr uint16_t PORT_HTTP = 80;           // TCP
    static constexpr uint16_t PORT_HTTPS = 443;         // TCP
    static constexpr uint16_t PORT_DNS = 53;            // UDP/TCP
    static constexpr uint16_t PORT_RTP_MIN = 10000;     // UDP
    static constexpr uint16_t PORT_RTP_MAX = 20000;     // UDP
};

}  // namespace callflow
