#include "session/session_types.h"
#include <chrono>
#include <algorithm>
#include <sstream>
#include <iomanip>

namespace callflow {

// ============================================================================
// SessionCorrelationKey Methods
// ============================================================================

bool SessionCorrelationKey::matches(const SessionCorrelationKey& other) const {
    // Check IMSI/SUPI (primary identifiers)
    if (imsi.has_value() && other.imsi.has_value() && imsi.value() == other.imsi.value()) {
        return true;
    }
    if (supi.has_value() && other.supi.has_value() && supi.value() == other.supi.value()) {
        return true;
    }

    // Check GUTI
    if (guti.has_value() && other.guti.has_value() && guti.value() == other.guti.value()) {
        return true;
    }

    // Check MSISDN
    if (msisdn.has_value() && other.msisdn.has_value() && msisdn.value() == other.msisdn.value()) {
        return true;
    }

    // Check TEIDs
    if (teid_s1u.has_value() && other.teid_s1u.has_value() && teid_s1u.value() == other.teid_s1u.value()) {
        return true;
    }
    if (teid_s5u.has_value() && other.teid_s5u.has_value() && teid_s5u.value() == other.teid_s5u.value()) {
        return true;
    }

    // Check SEID (PFCP)
    if (seid_n4.has_value() && other.seid_n4.has_value() && seid_n4.value() == other.seid_n4.value()) {
        return true;
    }

    // Check PDU Session ID
    if (pdu_session_id.has_value() && other.pdu_session_id.has_value() &&
        pdu_session_id.value() == other.pdu_session_id.value()) {
        // PDU Session ID alone is not unique, check with other identifiers
        if (supi.has_value() && other.supi.has_value() && supi.value() == other.supi.value()) {
            return true;
        }
    }

    // Check UE context IDs (must match with same subscriber)
    if (mme_ue_s1ap_id.has_value() && other.mme_ue_s1ap_id.has_value() &&
        mme_ue_s1ap_id.value() == other.mme_ue_s1ap_id.value()) {
        return true;
    }
    if (amf_ue_ngap_id.has_value() && other.amf_ue_ngap_id.has_value() &&
        amf_ue_ngap_id.value() == other.amf_ue_ngap_id.value()) {
        return true;
    }

    // Check UE IP addresses
    if (ue_ipv4.has_value() && other.ue_ipv4.has_value() && ue_ipv4.value() == other.ue_ipv4.value()) {
        return true;
    }
    if (ue_ipv6.has_value() && other.ue_ipv6.has_value() && ue_ipv6.value() == other.ue_ipv6.value()) {
        return true;
    }

    // Check SIP Call-ID (for VoLTE)
    if (sip_call_id.has_value() && other.sip_call_id.has_value() &&
        sip_call_id.value() == other.sip_call_id.value()) {
        return true;
    }

    return false;
}

void SessionCorrelationKey::merge(const SessionCorrelationKey& other) {
    if (!imsi.has_value() && other.imsi.has_value()) imsi = other.imsi;
    if (!supi.has_value() && other.supi.has_value()) supi = other.supi;
    if (!guti.has_value() && other.guti.has_value()) guti = other.guti;
    if (!msisdn.has_value() && other.msisdn.has_value()) msisdn = other.msisdn;

    if (!teid_s1u.has_value() && other.teid_s1u.has_value()) teid_s1u = other.teid_s1u;
    if (!teid_s5u.has_value() && other.teid_s5u.has_value()) teid_s5u = other.teid_s5u;
    if (!seid_n4.has_value() && other.seid_n4.has_value()) seid_n4 = other.seid_n4;
    if (!pdu_session_id.has_value() && other.pdu_session_id.has_value()) pdu_session_id = other.pdu_session_id;
    if (!eps_bearer_id.has_value() && other.eps_bearer_id.has_value()) eps_bearer_id = other.eps_bearer_id;

    if (!enb_ue_s1ap_id.has_value() && other.enb_ue_s1ap_id.has_value()) enb_ue_s1ap_id = other.enb_ue_s1ap_id;
    if (!mme_ue_s1ap_id.has_value() && other.mme_ue_s1ap_id.has_value()) mme_ue_s1ap_id = other.mme_ue_s1ap_id;
    if (!ran_ue_ngap_id.has_value() && other.ran_ue_ngap_id.has_value()) ran_ue_ngap_id = other.ran_ue_ngap_id;
    if (!amf_ue_ngap_id.has_value() && other.amf_ue_ngap_id.has_value()) amf_ue_ngap_id = other.amf_ue_ngap_id;

    if (!ue_ipv4.has_value() && other.ue_ipv4.has_value()) ue_ipv4 = other.ue_ipv4;
    if (!ue_ipv6.has_value() && other.ue_ipv6.has_value()) ue_ipv6 = other.ue_ipv6;
    if (!pgw_upf_ip.has_value() && other.pgw_upf_ip.has_value()) pgw_upf_ip = other.pgw_upf_ip;

    if (!apn.has_value() && other.apn.has_value()) apn = other.apn;
    if (!dnn.has_value() && other.dnn.has_value()) dnn = other.dnn;
    if (!network_instance.has_value() && other.network_instance.has_value()) network_instance = other.network_instance;

    if (!sip_call_id.has_value() && other.sip_call_id.has_value()) sip_call_id = other.sip_call_id;
    if (!rtp_ssrc.has_value() && other.rtp_ssrc.has_value()) rtp_ssrc = other.rtp_ssrc;
}

nlohmann::json SessionCorrelationKey::toJson() const {
    nlohmann::json j;

    if (imsi.has_value()) j["imsi"] = imsi.value();
    if (supi.has_value()) j["supi"] = supi.value();
    if (guti.has_value()) j["guti"] = guti.value();
    if (msisdn.has_value()) j["msisdn"] = msisdn.value();

    if (teid_s1u.has_value()) j["teid_s1u"] = teid_s1u.value();
    if (teid_s5u.has_value()) j["teid_s5u"] = teid_s5u.value();
    if (seid_n4.has_value()) j["seid_n4"] = seid_n4.value();
    if (pdu_session_id.has_value()) j["pdu_session_id"] = pdu_session_id.value();
    if (eps_bearer_id.has_value()) j["eps_bearer_id"] = eps_bearer_id.value();

    if (enb_ue_s1ap_id.has_value()) j["enb_ue_s1ap_id"] = enb_ue_s1ap_id.value();
    if (mme_ue_s1ap_id.has_value()) j["mme_ue_s1ap_id"] = mme_ue_s1ap_id.value();
    if (ran_ue_ngap_id.has_value()) j["ran_ue_ngap_id"] = ran_ue_ngap_id.value();
    if (amf_ue_ngap_id.has_value()) j["amf_ue_ngap_id"] = amf_ue_ngap_id.value();

    if (ue_ipv4.has_value()) j["ue_ipv4"] = ue_ipv4.value();
    if (ue_ipv6.has_value()) j["ue_ipv6"] = ue_ipv6.value();
    if (pgw_upf_ip.has_value()) j["pgw_upf_ip"] = pgw_upf_ip.value();

    if (apn.has_value()) j["apn"] = apn.value();
    if (dnn.has_value()) j["dnn"] = dnn.value();
    if (network_instance.has_value()) j["network_instance"] = network_instance.value();

    if (sip_call_id.has_value()) j["sip_call_id"] = sip_call_id.value();
    if (rtp_ssrc.has_value()) j["rtp_ssrc"] = rtp_ssrc.value();

    return j;
}

size_t SessionCorrelationKey::hash() const {
    size_t h = 0;
    std::hash<std::string> string_hasher;
    std::hash<uint32_t> uint32_hasher;
    std::hash<uint64_t> uint64_hasher;

    if (imsi.has_value()) h ^= string_hasher(imsi.value());
    if (supi.has_value()) h ^= string_hasher(supi.value()) << 1;
    if (teid_s1u.has_value()) h ^= uint32_hasher(teid_s1u.value()) << 2;
    if (seid_n4.has_value()) h ^= uint64_hasher(seid_n4.value()) << 3;
    if (ue_ipv4.has_value()) h ^= string_hasher(ue_ipv4.value()) << 4;

    return h;
}

std::string SessionCorrelationKey::getPrimaryIdentifier() const {
    if (imsi.has_value()) return imsi.value();
    if (supi.has_value()) return supi.value();
    if (guti.has_value()) return guti.value();
    if (msisdn.has_value()) return msisdn.value();
    if (ue_ipv4.has_value()) return ue_ipv4.value();
    if (ue_ipv6.has_value()) return ue_ipv6.value();
    return "unknown";
}

// ============================================================================
// SessionMessageRef Methods
// ============================================================================

nlohmann::json SessionMessageRef::toJson() const {
    nlohmann::json j;
    j["message_id"] = message_id;
    j["packet_id"] = packet_id;
    j["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        timestamp.time_since_epoch()).count();
    j["interface"] = interfaceTypeToString(interface);
    j["protocol"] = protocolTypeToString(protocol);
    j["message_type"] = messageTypeToString(message_type);
    j["sequence_in_session"] = sequence_in_session;
    j["correlation_key"] = correlation_key.toJson();
    return j;
}

// ============================================================================
// SessionLeg Methods
// ============================================================================

nlohmann::json SessionLeg::toJson() const {
    nlohmann::json j;
    j["interface"] = interfaceTypeToString(interface);
    j["message_count"] = messages.size();
    j["total_bytes"] = total_bytes;
    j["start_time"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        start_time.time_since_epoch()).count();
    j["end_time"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        end_time.time_since_epoch()).count();
    j["duration_ms"] = getDurationMs();

    nlohmann::json msgs_json = nlohmann::json::array();
    for (const auto& msg : messages) {
        msgs_json.push_back(msg.toJson());
    }
    j["messages"] = msgs_json;

    return j;
}

uint64_t SessionLeg::getDurationMs() const {
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    return duration.count();
}

// ============================================================================
// Session Methods
// ============================================================================

nlohmann::json Session::toJson() const {
    nlohmann::json j;
    j["session_id"] = session_id;
    j["session_type"] = enhancedSessionTypeToString(session_type);
    j["correlation_key"] = correlation_key.toJson();
    j["start_time"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        start_time.time_since_epoch()).count();
    j["end_time"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        end_time.time_since_epoch()).count();
    j["duration_ms"] = getDurationMs();
    j["total_packets"] = total_packets;
    j["total_bytes"] = total_bytes;
    j["is_complete"] = is_complete;

    if (setup_time_ms.has_value()) {
        j["setup_time_ms"] = setup_time_ms.value();
    }

    // Add interfaces involved
    nlohmann::json ifaces_json = nlohmann::json::array();
    for (const auto& iface : interfaces_involved) {
        ifaces_json.push_back(interfaceTypeToString(iface));
    }
    j["interfaces_involved"] = ifaces_json;

    // Add legs
    nlohmann::json legs_json = nlohmann::json::array();
    for (const auto& leg : legs) {
        legs_json.push_back(leg.toJson());
    }
    j["legs"] = legs_json;
    j["leg_count"] = legs.size();

    // Add metadata
    if (!metadata.empty()) {
        j["metadata"] = metadata;
    }

    return j;
}

std::vector<SessionMessageRef> Session::getAllMessages() const {
    std::vector<SessionMessageRef> all_messages;

    for (const auto& leg : legs) {
        all_messages.insert(all_messages.end(), leg.messages.begin(), leg.messages.end());
    }

    // Sort by timestamp
    std::sort(all_messages.begin(), all_messages.end(),
              [](const SessionMessageRef& a, const SessionMessageRef& b) {
                  return a.timestamp < b.timestamp;
              });

    return all_messages;
}

std::vector<SessionMessageRef> Session::getMessagesForInterface(InterfaceType interface) const {
    for (const auto& leg : legs) {
        if (leg.interface == interface) {
            return leg.messages;
        }
    }
    return {};
}

uint64_t Session::getDurationMs() const {
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    return duration.count();
}

void Session::addMessage(const SessionMessageRef& msg) {
    // Find or create leg for this interface
    SessionLeg* target_leg = nullptr;
    for (auto& leg : legs) {
        if (leg.interface == msg.interface) {
            target_leg = &leg;
            break;
        }
    }

    if (!target_leg) {
        // Create new leg
        SessionLeg new_leg;
        new_leg.interface = msg.interface;
        new_leg.start_time = msg.timestamp;
        new_leg.end_time = msg.timestamp;
        new_leg.total_bytes = 0;
        legs.push_back(new_leg);
        target_leg = &legs.back();

        // Add to interfaces_involved if not already there
        if (std::find(interfaces_involved.begin(), interfaces_involved.end(), msg.interface) == interfaces_involved.end()) {
            interfaces_involved.push_back(msg.interface);
        }
    }

    // Add message to leg
    target_leg->messages.push_back(msg);

    // Update leg timestamps
    if (msg.timestamp < target_leg->start_time) {
        target_leg->start_time = msg.timestamp;
    }
    if (msg.timestamp > target_leg->end_time) {
        target_leg->end_time = msg.timestamp;
    }

    // Update session timestamps
    if (msg.timestamp < start_time) {
        start_time = msg.timestamp;
    }
    if (msg.timestamp > end_time) {
        end_time = msg.timestamp;
    }

    // Merge correlation keys
    correlation_key.merge(msg.correlation_key);

    total_packets++;
}

void Session::finalize() {
    // Sort messages in each leg by timestamp
    for (auto& leg : legs) {
        std::sort(leg.messages.begin(), leg.messages.end(),
                  [](const SessionMessageRef& a, const SessionMessageRef& b) {
                      return a.timestamp < b.timestamp;
                  });

        // Assign sequence numbers
        uint32_t seq = 0;
        for (auto& msg : leg.messages) {
            msg.sequence_in_session = seq++;
        }
    }

    // Calculate total bytes (this would need packet size info)
    // For now, we'll leave it as is

    // Determine if session is complete
    // A complete session should have start and end messages
    // This is a simplified check
    is_complete = !legs.empty() && (end_time > start_time);
}

// ============================================================================
// SessionStatistics Methods
// ============================================================================

nlohmann::json SessionStatistics::toJson() const {
    nlohmann::json j;
    j["total_sessions"] = total_sessions;
    j["total_messages"] = total_messages;
    j["total_bytes"] = total_bytes;
    j["average_session_duration_ms"] = average_session_duration_ms;
    j["average_setup_time_ms"] = average_setup_time_ms;

    nlohmann::json by_type = nlohmann::json::object();
    for (const auto& [type, count] : sessions_by_type) {
        by_type[enhancedSessionTypeToString(type)] = count;
    }
    j["sessions_by_type"] = by_type;

    nlohmann::json by_iface = nlohmann::json::object();
    for (const auto& [iface, count] : messages_by_interface) {
        by_iface[interfaceTypeToString(iface)] = count;
    }
    j["messages_by_interface"] = by_iface;

    return j;
}

// ============================================================================
// Helper Functions
// ============================================================================

std::string enhancedSessionTypeToString(EnhancedSessionType type) {
    switch (type) {
        case EnhancedSessionType::UNKNOWN: return "Unknown";
        case EnhancedSessionType::LTE_ATTACH: return "LTE-Attach";
        case EnhancedSessionType::LTE_PDN_CONNECT: return "LTE-PDN-Connect";
        case EnhancedSessionType::LTE_HANDOVER_X2: return "LTE-Handover-X2";
        case EnhancedSessionType::LTE_HANDOVER_S1: return "LTE-Handover-S1";
        case EnhancedSessionType::LTE_SERVICE_REQUEST: return "LTE-Service-Request";
        case EnhancedSessionType::LTE_DETACH: return "LTE-Detach";
        case EnhancedSessionType::G5_REGISTRATION: return "5G-Registration";
        case EnhancedSessionType::G5_PDU_SESSION: return "5G-PDU-Session";
        case EnhancedSessionType::G5_HANDOVER: return "5G-Handover";
        case EnhancedSessionType::G5_SERVICE_REQUEST: return "5G-Service-Request";
        case EnhancedSessionType::G5_DEREGISTRATION: return "5G-Deregistration";
        case EnhancedSessionType::VOLTE_CALL: return "VoLTE-Call";
        case EnhancedSessionType::VIDEO_STREAMING: return "Video-Streaming";
        case EnhancedSessionType::WEB_BROWSING: return "Web-Browsing";
        case EnhancedSessionType::DATA_TRANSFER: return "Data-Transfer";
        case EnhancedSessionType::MIXED: return "Mixed";
        case EnhancedSessionType::INCOMPLETE: return "Incomplete";
        default: return "Unknown";
    }
}

EnhancedSessionType stringToEnhancedSessionType(const std::string& str) {
    if (str == "LTE-Attach") return EnhancedSessionType::LTE_ATTACH;
    if (str == "LTE-PDN-Connect") return EnhancedSessionType::LTE_PDN_CONNECT;
    if (str == "LTE-Handover-X2") return EnhancedSessionType::LTE_HANDOVER_X2;
    if (str == "LTE-Handover-S1") return EnhancedSessionType::LTE_HANDOVER_S1;
    if (str == "LTE-Service-Request") return EnhancedSessionType::LTE_SERVICE_REQUEST;
    if (str == "LTE-Detach") return EnhancedSessionType::LTE_DETACH;
    if (str == "5G-Registration") return EnhancedSessionType::G5_REGISTRATION;
    if (str == "5G-PDU-Session") return EnhancedSessionType::G5_PDU_SESSION;
    if (str == "5G-Handover") return EnhancedSessionType::G5_HANDOVER;
    if (str == "5G-Service-Request") return EnhancedSessionType::G5_SERVICE_REQUEST;
    if (str == "5G-Deregistration") return EnhancedSessionType::G5_DEREGISTRATION;
    if (str == "VoLTE-Call") return EnhancedSessionType::VOLTE_CALL;
    if (str == "Video-Streaming") return EnhancedSessionType::VIDEO_STREAMING;
    if (str == "Web-Browsing") return EnhancedSessionType::WEB_BROWSING;
    if (str == "Data-Transfer") return EnhancedSessionType::DATA_TRANSFER;
    if (str == "Mixed") return EnhancedSessionType::MIXED;
    if (str == "Incomplete") return EnhancedSessionType::INCOMPLETE;
    return EnhancedSessionType::UNKNOWN;
}

std::string interfaceTypeToString(InterfaceType type) {
    switch (type) {
        case InterfaceType::UNKNOWN: return "Unknown";
        case InterfaceType::S1_MME: return "S1-MME";
        case InterfaceType::S1_U: return "S1-U";
        case InterfaceType::S11: return "S11";
        case InterfaceType::S5_S8: return "S5/S8";
        case InterfaceType::SGI: return "SGi";
        case InterfaceType::X2: return "X2";
        case InterfaceType::N1: return "N1";
        case InterfaceType::N2: return "N2";
        case InterfaceType::N3: return "N3";
        case InterfaceType::N4: return "N4";
        case InterfaceType::N6: return "N6";
        case InterfaceType::XN: return "Xn";
        case InterfaceType::IMS_SIP: return "IMS-SIP";
        case InterfaceType::IMS_RTP: return "IMS-RTP";
        case InterfaceType::DIAMETER: return "Diameter";
        case InterfaceType::HTTP_API: return "HTTP-API";
        default: return "Unknown";
    }
}

InterfaceType stringToInterfaceType(const std::string& str) {
    if (str == "S1-MME") return InterfaceType::S1_MME;
    if (str == "S1-U") return InterfaceType::S1_U;
    if (str == "S11") return InterfaceType::S11;
    if (str == "S5/S8") return InterfaceType::S5_S8;
    if (str == "SGi") return InterfaceType::SGI;
    if (str == "X2") return InterfaceType::X2;
    if (str == "N1") return InterfaceType::N1;
    if (str == "N2") return InterfaceType::N2;
    if (str == "N3") return InterfaceType::N3;
    if (str == "N4") return InterfaceType::N4;
    if (str == "N6") return InterfaceType::N6;
    if (str == "Xn") return InterfaceType::XN;
    if (str == "IMS-SIP") return InterfaceType::IMS_SIP;
    if (str == "IMS-RTP") return InterfaceType::IMS_RTP;
    if (str == "Diameter") return InterfaceType::DIAMETER;
    if (str == "HTTP-API") return InterfaceType::HTTP_API;
    return InterfaceType::UNKNOWN;
}

InterfaceType detectInterfaceType(ProtocolType protocol, uint16_t src_port, uint16_t dst_port) {
    // SCTP-based protocols
    if (protocol == ProtocolType::SCTP) {
        // S1AP uses SCTP port 36412
        if (src_port == 36412 || dst_port == 36412) {
            return InterfaceType::S1_MME;
        }
        // NGAP uses SCTP port 38412
        if (src_port == 38412 || dst_port == 38412) {
            return InterfaceType::N2;
        }
        // X2AP uses SCTP port 36422
        if (src_port == 36422 || dst_port == 36422) {
            return InterfaceType::X2;
        }
        // Diameter uses SCTP port 3868
        if (src_port == 3868 || dst_port == 3868) {
            return InterfaceType::DIAMETER;
        }
    }

    // UDP-based protocols
    if (protocol == ProtocolType::UDP) {
        // GTP-C (GTPv2) uses UDP port 2123
        if (src_port == 2123 || dst_port == 2123) {
            return InterfaceType::S11;  // Could also be S5/S8
        }
        // GTP-U uses UDP port 2152
        if (src_port == 2152 || dst_port == 2152) {
            return InterfaceType::S1_U;  // Could also be S5/S8 or N3
        }
        // PFCP uses UDP port 8805
        if (src_port == 8805 || dst_port == 8805) {
            return InterfaceType::N4;
        }
        // SIP uses UDP port 5060
        if (src_port == 5060 || dst_port == 5060) {
            return InterfaceType::IMS_SIP;
        }
        // RTP uses dynamic ports (typically 10000-65535)
        if ((src_port >= 10000 && src_port < 65000) || (dst_port >= 10000 && dst_port < 65000)) {
            // This is a heuristic - would need deeper inspection
            return InterfaceType::IMS_RTP;
        }
    }

    // TCP-based protocols
    if (protocol == ProtocolType::TCP) {
        // Diameter over TCP uses port 3868
        if (src_port == 3868 || dst_port == 3868) {
            return InterfaceType::DIAMETER;
        }
        // SIP over TCP uses port 5060
        if (src_port == 5060 || dst_port == 5060) {
            return InterfaceType::IMS_SIP;
        }
        // HTTP/HTTPS
        if (src_port == 80 || dst_port == 80 || src_port == 443 || dst_port == 443) {
            return InterfaceType::HTTP_API;
        }
    }

    return InterfaceType::UNKNOWN;
}

}  // namespace callflow
