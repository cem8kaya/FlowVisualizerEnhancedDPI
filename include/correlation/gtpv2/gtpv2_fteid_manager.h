#pragma once

#include "correlation/gtpv2/gtpv2_types.h"
#include <unordered_map>
#include <string>
#include <optional>

namespace callflow {
namespace correlation {

// Forward declaration
class Gtpv2Session;

/**
 * @brief Manages F-TEID to Session mapping for GTP-U correlation
 *
 * This component maintains a mapping from F-TEIDs (IP + TEID) to sessions,
 * allowing GTP-U user plane packets to be linked back to their control
 * plane session.
 */
class Gtpv2FteidManager {
public:
    Gtpv2FteidManager() = default;
    ~Gtpv2FteidManager() = default;

    /**
     * @brief Register F-TEID with associated session
     *
     * @param fteid F-TEID to register
     * @param session Pointer to session (must outlive this manager)
     */
    void registerFteid(const GtpV2FTEID& fteid, Gtpv2Session* session);

    /**
     * @brief Unregister F-TEID
     *
     * @param fteid F-TEID to unregister
     */
    void unregisterFteid(const GtpV2FTEID& fteid);

    /**
     * @brief Find session by F-TEID
     *
     * @param ip IP address (either IPv4 or IPv6)
     * @param teid TEID value
     * @return Pointer to session or nullptr if not found
     */
    Gtpv2Session* findSessionByFteid(const std::string& ip, uint32_t teid);

    /**
     * @brief Find session by GTP-U packet endpoints
     *
     * This method tries both directions (src->dst and dst->src) to find
     * the session, as GTP-U packets can be uplink or downlink.
     *
     * @param src_ip Source IP address
     * @param dst_ip Destination IP address
     * @param teid TEID from GTP-U header
     * @return Pointer to session or nullptr if not found
     */
    Gtpv2Session* findSessionByGtpuPacket(const std::string& src_ip,
                                           const std::string& dst_ip,
                                           uint32_t teid);

    /**
     * @brief Get IMSI for GTP-U packet (convenience method)
     *
     * @param src_ip Source IP address
     * @param dst_ip Destination IP address
     * @param teid TEID from GTP-U header
     * @return IMSI if session found, otherwise empty
     */
    std::optional<std::string> getImsiForGtpuPacket(const std::string& src_ip,
                                                     const std::string& dst_ip,
                                                     uint32_t teid);

    /**
     * @brief Get PDN address (UE IP) for GTP-U packet
     *
     * @param src_ip Source IP address
     * @param dst_ip Destination IP address
     * @param teid TEID from GTP-U header
     * @return UE IP address if session found, otherwise empty
     */
    std::optional<std::string> getPdnAddressForGtpuPacket(const std::string& src_ip,
                                                           const std::string& dst_ip,
                                                           uint32_t teid);

    /**
     * @brief Clear all F-TEID mappings
     */
    void clear();

    /**
     * @brief Get number of registered F-TEIDs
     */
    size_t getCount() const { return fteid_to_session_.size(); }

private:
    // Key: "IP:TEID" -> Session pointer
    std::unordered_map<std::string, Gtpv2Session*> fteid_to_session_;

    /**
     * @brief Make lookup key from IP and TEID
     */
    std::string makeKey(const std::string& ip, uint32_t teid) const;
};

} // namespace correlation
} // namespace callflow
