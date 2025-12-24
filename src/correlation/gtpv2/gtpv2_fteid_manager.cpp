#include "correlation/gtpv2/gtpv2_fteid_manager.h"
#include "correlation/gtpv2/gtpv2_session.h"
#include <sstream>
#include <iomanip>

namespace callflow {
namespace correlation {

std::string Gtpv2FteidManager::makeKey(const std::string& ip, uint32_t teid) const {
    std::stringstream ss;
    ss << ip << ":" << std::hex << std::setfill('0') << std::setw(8) << teid;
    return ss.str();
}

void Gtpv2FteidManager::registerFteid(const GtpV2FTEID& fteid, Gtpv2Session* session) {
    if (!session) {
        return;
    }

    // Register IPv4 address if present
    if (fteid.ipv4_address.has_value()) {
        std::string key = makeKey(fteid.ipv4_address.value(), fteid.teid);
        fteid_to_session_[key] = session;
    }

    // Register IPv6 address if present
    if (fteid.ipv6_address.has_value()) {
        std::string key = makeKey(fteid.ipv6_address.value(), fteid.teid);
        fteid_to_session_[key] = session;
    }
}

void Gtpv2FteidManager::unregisterFteid(const GtpV2FTEID& fteid) {
    if (fteid.ipv4_address.has_value()) {
        std::string key = makeKey(fteid.ipv4_address.value(), fteid.teid);
        fteid_to_session_.erase(key);
    }

    if (fteid.ipv6_address.has_value()) {
        std::string key = makeKey(fteid.ipv6_address.value(), fteid.teid);
        fteid_to_session_.erase(key);
    }
}

Gtpv2Session* Gtpv2FteidManager::findSessionByFteid(const std::string& ip, uint32_t teid) {
    std::string key = makeKey(ip, teid);
    auto it = fteid_to_session_.find(key);
    if (it != fteid_to_session_.end()) {
        return it->second;
    }
    return nullptr;
}

Gtpv2Session* Gtpv2FteidManager::findSessionByGtpuPacket(const std::string& src_ip,
                                                           const std::string& dst_ip,
                                                           uint32_t teid) {
    // Try destination IP + TEID (most common case for downlink)
    Gtpv2Session* session = findSessionByFteid(dst_ip, teid);
    if (session) {
        return session;
    }

    // Try source IP + TEID (for uplink)
    session = findSessionByFteid(src_ip, teid);
    if (session) {
        return session;
    }

    return nullptr;
}

std::optional<std::string> Gtpv2FteidManager::getImsiForGtpuPacket(const std::string& src_ip,
                                                                     const std::string& dst_ip,
                                                                     uint32_t teid) {
    auto* session = findSessionByGtpuPacket(src_ip, dst_ip, teid);
    if (session) {
        return session->getImsi();
    }
    return std::nullopt;
}

std::optional<std::string> Gtpv2FteidManager::getPdnAddressForGtpuPacket(const std::string& src_ip,
                                                                           const std::string& dst_ip,
                                                                           uint32_t teid) {
    auto* session = findSessionByGtpuPacket(src_ip, dst_ip, teid);
    if (session) {
        // Try IPv4 first
        auto pdn_v4 = session->getPdnAddressV4();
        if (pdn_v4.has_value()) {
            return pdn_v4;
        }
        // Try IPv6
        auto pdn_v6 = session->getPdnAddressV6();
        if (pdn_v6.has_value()) {
            return pdn_v6;
        }
    }
    return std::nullopt;
}

void Gtpv2FteidManager::clear() {
    fteid_to_session_.clear();
}

} // namespace correlation
} // namespace callflow
