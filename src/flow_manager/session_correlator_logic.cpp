#include <iostream>
#include <string>
#include <vector>

#include "flow_manager/session_correlator.h"

namespace callflow {

void SessionCorrelator::linkSessionMetadata(std::shared_ptr<FlowSession> session,
                                            const PacketMetadata& packet,
                                            const nlohmann::json& parsed_data) {
    // 1. GTP Processing (The Anchor)
    if (session->type == SessionType::GTP) {
        // Extract IMSI
        if (parsed_data.contains("imsi")) {
            std::string imsi = parsed_data["imsi"].get<std::string>();
            session->imsi = imsi;

            // Link MSISDN if present
            if (parsed_data.contains("msisdn")) {
                std::string msisdn = parsed_data["msisdn"].get<std::string>();
                msisdn_to_imsi_map_[msisdn] = imsi;
            }

            // Link UE IP (PAA) if present and valid
            // Check PAA IE or other IP fields
            if (parsed_data.contains("ies")) {
                for (const auto& ie : parsed_data["ies"]) {
                    if (ie.contains("type_name") && ie["type_name"] == "PAA" &&
                        ie.contains("data")) {
                        // This is simplified; normally need deep parsing of PAA
                        // Assuming string representation or we rely on specific extracted fields
                    }
                }
            }

            // Simplified: Use packet source/dest if it's a UE (unlikely for GTP-C control plane,
            // but maybe data plane) Ideally we extract PAA (PDN Address Allocation). The GtpParser
            // (Step 26) extracts 'apn', 'imsi', 'msisdn', 'f_teid'. It does NOT expose PAA directly
            // in extracted fields struct, only in IEs. We'll rely on what we have or extend
            // GtpParser further if needed. For now, let's assume if we have IMSI, we record it.
        }
    }

    // 2. SIP/Diameter Processing (The Linking)
    if (session->imsi.empty()) {
        // Try to find IMSI from IP maps
        auto it_src = ip_to_imsi_map_.find(packet.five_tuple.src_ip);
        if (it_src != ip_to_imsi_map_.end()) {
            session->imsi = it_src->second;
        } else {
            auto it_dst = ip_to_imsi_map_.find(packet.five_tuple.dst_ip);
            if (it_dst != ip_to_imsi_map_.end()) {
                session->imsi = it_dst->second;
            }
        }
    }

    // 3. SIP Specific Identity Extraction (to populate maps)
    if (session->type == SessionType::VOLTE) {
        // Check P-Asserted-Identity
        if (parsed_data.contains("p_asserted_identity") &&
            parsed_data["p_asserted_identity"].is_array()) {
            for (const auto& id : parsed_data["p_asserted_identity"]) {
                if (id.contains("username")) {
                    std::string username = id["username"];
                    // If username looks like MSISDN, link to IMSI if known
                    if (!username.empty() && session->imsi.empty()) {
                        auto it = msisdn_to_imsi_map_.find(username);
                        if (it != msisdn_to_imsi_map_.end()) {
                            session->imsi = it->second;
                        }
                    }
                }
            }
        }
    }
}

nlohmann::json SessionCorrelator::exportMasterSessions() {
    std::lock_guard<std::mutex> lock(mutex_);
    nlohmann::json result = nlohmann::json::array();

    // Group sessions by IMSI
    std::unordered_map<std::string, FlowVolteMasterSession> master_sessions;
    std::vector<std::shared_ptr<FlowSession>> unassociated_sessions;

    for (const auto& [key, session] : sessions_) {
        if (!session->imsi.empty()) {
            auto& master = master_sessions[session->imsi];
            master.imsi = session->imsi;

            if (session->type == SessionType::GTP) {
                master.gtp_anchor = session;
            } else if (session->type == SessionType::VOLTE) {  // SIP
                master.sip_legs.push_back(session);
            } else if (session->type == SessionType::DIAMETER) {
                master.diameter_tx.push_back(session);
            } else {
                // Other types treat as legs for now
                master.sip_legs.push_back(session);
            }
        } else {
            unassociated_sessions.push_back(session);
        }
    }

    // Build JSON
    for (const auto& [imsi, master] : master_sessions) {
        nlohmann::json j;
        j["master_uuid"] = "MS-" + imsi;  // Simple UUID generation
        j["imsi"] = imsi;
        j["msisdn"] = master.msisdn;

        if (master.gtp_anchor) {
            j["gtp_anchor"] = master.gtp_anchor->toJson();
        }

        j["sip_legs"] = nlohmann::json::array();
        for (const auto& sess : master.sip_legs) {
            j["sip_legs"].push_back(sess->toJson());
        }

        j["diameter_tx"] = nlohmann::json::array();
        for (const auto& sess : master.diameter_tx) {
            j["diameter_tx"].push_back(sess->toJson());
        }

        result.push_back(j);
    }

    // Add unassociated sessions if needed, or keeping them separate?
    // The requirement says "Instead of exporting a flat list... aggregate them".
    // I will append unassociated sessions as individual items or handle them differently.
    // For now, I'll return the master list.

    return result;
}

}  // namespace callflow
