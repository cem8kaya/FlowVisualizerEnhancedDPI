#include <arpa/inet.h>

#include <cstdio>
#include <cstring>
#include <nlohmann/json.hpp>

#include "common/logger.h"
#include "protocol_parsers/diameter_s6a.h"

namespace callflow {

// ============================================================================
// Structure toJson() Methods
// ============================================================================

nlohmann::json ULRFlags::toJson() const {
    nlohmann::json j;
    j["single_registration_indication"] = single_registration_indication;
    j["s6a_s6d_indicator"] = s6a_s6d_indicator;
    j["skip_subscriber_data"] = skip_subscriber_data;
    j["gprs_subscription_data_indicator"] = gprs_subscription_data_indicator;
    j["node_type_indicator"] = node_type_indicator;
    j["initial_attach_indicator"] = initial_attach_indicator;
    j["ps_lcs_not_supported_by_ue"] = ps_lcs_not_supported_by_ue;
    return j;
}

nlohmann::json ULAFlags::toJson() const {
    nlohmann::json j;
    j["separation_indication"] = separation_indication;
    return j;
}

nlohmann::json EUTRANVector::toJson() const {
    nlohmann::json j;
    j["rand"] = nlohmann::json::array();
    for (auto byte : rand) {
        j["rand"].push_back(byte);
    }
    j["xres"] = nlohmann::json::array();
    for (auto byte : xres) {
        j["xres"].push_back(byte);
    }
    j["autn"] = nlohmann::json::array();
    for (auto byte : autn) {
        j["autn"].push_back(byte);
    }
    j["kasme"] = nlohmann::json::array();
    for (auto byte : kasme) {
        j["kasme"].push_back(byte);
    }
    return j;
}

nlohmann::json AuthenticationInfo::toJson() const {
    nlohmann::json j;
    nlohmann::json vectors = nlohmann::json::array();
    for (const auto& vec : eutran_vectors) {
        vectors.push_back(vec.toJson());
    }
    j["eutran_vectors"] = vectors;
    j["vector_count"] = eutran_vectors.size();
    return j;
}

nlohmann::json AllocationRetentionPriority::toJson() const {
    nlohmann::json j;
    j["priority_level"] = priority_level;
    j["pre_emption_capability"] = pre_emption_capability;
    j["pre_emption_vulnerability"] = pre_emption_vulnerability;
    return j;
}

nlohmann::json EPSSubscribedQoSProfile::toJson() const {
    nlohmann::json j;
    j["qos_class_identifier"] = qos_class_identifier;
    j["allocation_retention_priority"] = allocation_retention_priority.toJson();
    return j;
}

nlohmann::json AMBR::toJson() const {
    nlohmann::json j;
    j["max_requested_bandwidth_ul"] = max_requested_bandwidth_ul;
    j["max_requested_bandwidth_dl"] = max_requested_bandwidth_dl;
    return j;
}

nlohmann::json APNConfiguration::toJson() const {
    nlohmann::json j;
    j["context_identifier"] = context_identifier;
    j["service_selection"] = service_selection;
    j["pdn_type"] = static_cast<uint32_t>(pdn_type);
    j["qos_profile"] = qos_profile.toJson();
    if (ambr.has_value()) {
        j["ambr"] = ambr->toJson();
    }
    if (served_party_ip_address.has_value()) {
        j["served_party_ip_address"] = served_party_ip_address.value();
    }
    if (vplmn_dynamic_address_allowed.has_value()) {
        j["vplmn_dynamic_address_allowed"] = vplmn_dynamic_address_allowed.value();
    }
    return j;
}

nlohmann::json APNConfigurationProfile::toJson() const {
    nlohmann::json j;
    j["context_identifier"] = context_identifier;
    j["all_apn_config_inc_ind"] = all_apn_config_inc_ind;
    nlohmann::json configs = nlohmann::json::array();
    for (const auto& config : apn_configs) {
        configs.push_back(config.toJson());
    }
    j["apn_configurations"] = configs;
    j["apn_count"] = apn_configs.size();
    return j;
}

nlohmann::json SubscriptionData::toJson() const {
    nlohmann::json j;
    if (subscriber_status.has_value()) {
        j["subscriber_status"] = static_cast<uint32_t>(subscriber_status.value());
    }
    if (msisdn.has_value()) {
        j["msisdn"] = msisdn.value();
    }
    if (network_access_mode.has_value()) {
        j["network_access_mode"] = static_cast<uint32_t>(network_access_mode.value());
    }
    if (operator_determined_barring.has_value()) {
        j["operator_determined_barring"] = operator_determined_barring.value();
    }
    if (ambr.has_value()) {
        j["ambr"] = ambr->toJson();
    }
    if (apn_configuration_profile.has_value()) {
        j["apn_configuration_profile"] = apn_configuration_profile->toJson();
    }
    if (access_restriction_data.has_value()) {
        j["access_restriction_data"] = access_restriction_data.value();
    }
    if (subscribed_periodic_rau_tau_timer.has_value()) {
        j["subscribed_periodic_rau_tau_timer"] = subscribed_periodic_rau_tau_timer.value();
    }
    return j;
}

nlohmann::json UpdateLocationRequest::toJson() const {
    nlohmann::json j;
    j["user_name"] = user_name;
    j["visited_plmn_id"] = visited_plmn_id;
    j["rat_type"] = static_cast<uint32_t>(rat_type);
    j["ulr_flags"] = ulr_flags.toJson();
    if (ue_srvcc_capability.has_value()) {
        j["ue_srvcc_capability"] = ue_srvcc_capability.value();
    }
    if (terminal_information.has_value()) {
        j["terminal_information"] = terminal_information.value();
    }
    return j;
}

nlohmann::json UpdateLocationAnswer::toJson() const {
    nlohmann::json j;
    j["result_code"] = result_code;
    j["result_code_name"] = getResultCodeName(result_code);
    if (ula_flags.has_value()) {
        j["ula_flags"] = ula_flags->toJson();
    }
    if (subscription_data.has_value()) {
        j["subscription_data"] = subscription_data->toJson();
    }
    return j;
}

nlohmann::json AuthenticationInformationRequest::toJson() const {
    nlohmann::json j;
    j["user_name"] = user_name;
    j["visited_plmn_id"] = visited_plmn_id;
    j["number_of_requested_vectors"] = number_of_requested_vectors;
    if (resync_info.has_value()) {
        j["resync_info"] = nlohmann::json::array();
        for (auto byte : resync_info.value()) {
            j["resync_info"].push_back(byte);
        }
    }
    if (immediate_response_preferred.has_value()) {
        j["immediate_response_preferred"] = immediate_response_preferred.value();
    }
    return j;
}

nlohmann::json AuthenticationInformationAnswer::toJson() const {
    nlohmann::json j;
    j["result_code"] = result_code;
    j["result_code_name"] = getResultCodeName(result_code);
    if (auth_info.has_value()) {
        j["authentication_info"] = auth_info->toJson();
    }
    return j;
}

nlohmann::json PurgeUERequest::toJson() const {
    nlohmann::json j;
    j["user_name"] = user_name;
    if (pur_flags.has_value()) {
        j["pur_flags"] = pur_flags.value();
    }
    return j;
}

nlohmann::json PurgeUEAnswer::toJson() const {
    nlohmann::json j;
    j["result_code"] = result_code;
    j["result_code_name"] = getResultCodeName(result_code);
    if (pua_flags.has_value()) {
        j["pua_flags"] = pua_flags.value();
    }
    return j;
}

nlohmann::json CancelLocationRequest::toJson() const {
    nlohmann::json j;
    j["user_name"] = user_name;
    j["cancellation_type"] = static_cast<uint32_t>(cancellation_type);
    if (clr_flags.has_value()) {
        j["clr_flags"] = clr_flags.value();
    }
    return j;
}

nlohmann::json CancelLocationAnswer::toJson() const {
    nlohmann::json j;
    j["result_code"] = result_code;
    j["result_code_name"] = getResultCodeName(result_code);
    return j;
}

nlohmann::json InsertSubscriberDataRequest::toJson() const {
    nlohmann::json j;
    j["user_name"] = user_name;
    j["subscription_data"] = subscription_data.toJson();
    if (idr_flags.has_value()) {
        j["idr_flags"] = idr_flags.value();
    }
    return j;
}

nlohmann::json InsertSubscriberDataAnswer::toJson() const {
    nlohmann::json j;
    j["result_code"] = result_code;
    j["result_code_name"] = getResultCodeName(result_code);
    if (ida_flags.has_value()) {
        j["ida_flags"] = ida_flags.value();
    }
    if (ims_voice_over_ps_sessions_supported.has_value()) {
        j["ims_voice_over_ps_sessions_supported"] = ims_voice_over_ps_sessions_supported.value();
    }
    return j;
}

nlohmann::json DeleteSubscriberDataRequest::toJson() const {
    nlohmann::json j;
    j["user_name"] = user_name;
    j["context_identifiers"] = context_identifiers;
    return j;
}

nlohmann::json DeleteSubscriberDataAnswer::toJson() const {
    nlohmann::json j;
    j["result_code"] = result_code;
    j["result_code_name"] = getResultCodeName(result_code);
    return j;
}

nlohmann::json DiameterS6aMessage::toJson() const {
    nlohmann::json j = base.toJson();
    j["application"] = "S6a";

    if (imsi.has_value()) {
        j["imsi"] = imsi.value();
    }
    if (visited_plmn_id.has_value()) {
        j["visited_plmn_id"] = visited_plmn_id.value();
    }

    if (ulr.has_value()) {
        j["ulr"] = ulr->toJson();
    }
    if (ula.has_value()) {
        j["ula"] = ula->toJson();
    }
    if (air.has_value()) {
        j["air"] = air->toJson();
    }
    if (aia.has_value()) {
        j["aia"] = aia->toJson();
    }
    if (pur.has_value()) {
        j["pur"] = pur->toJson();
    }
    if (pua.has_value()) {
        j["pua"] = pua->toJson();
    }
    if (clr.has_value()) {
        j["clr"] = clr->toJson();
    }
    if (cla.has_value()) {
        j["cla"] = cla->toJson();
    }
    if (idr.has_value()) {
        j["idr"] = idr->toJson();
    }
    if (ida.has_value()) {
        j["ida"] = ida->toJson();
    }
    if (dsr.has_value()) {
        j["dsr"] = dsr->toJson();
    }
    if (dsa.has_value()) {
        j["dsa"] = dsa->toJson();
    }

    return j;
}

// ============================================================================
// DiameterS6aParser Methods
// ============================================================================

bool DiameterS6aParser::isS6aMessage(const DiameterMessage& msg) {
    return msg.header.application_id == DIAMETER_S6A_APPLICATION_ID;
}

std::optional<DiameterS6aMessage> DiameterS6aParser::parse(const DiameterMessage& msg) {
    if (!isS6aMessage(msg)) {
        return std::nullopt;
    }

    DiameterS6aMessage s6a_msg;
    s6a_msg.base = msg;

    // Extract IMSI from User-Name AVP
    auto user_name_avp = findAVP(msg.avps, static_cast<uint32_t>(DiameterAvpCode::USER_NAME));
    if (user_name_avp.has_value()) {
        s6a_msg.imsi = getAVPString(user_name_avp.value());
    }

    // Extract Visited-PLMN-ID
    auto visited_plmn_avp =
        findAVP(msg.avps, static_cast<uint32_t>(DiameterS6aAvpCode::VISITED_PLMN_ID));
    if (visited_plmn_avp.has_value()) {
        auto octets = getAVPOctetString(visited_plmn_avp.value());
        if (octets.has_value()) {
            // Convert to hex string
            std::string plmn_id;
            for (auto byte : octets.value()) {
                char hex[3];
                snprintf(hex, sizeof(hex), "%02x", byte);
                plmn_id += hex;
            }
            s6a_msg.visited_plmn_id = plmn_id;
        }
    }

    // Parse message-specific content based on command code
    switch (msg.header.command_code) {
        case static_cast<uint32_t>(DiameterCommandCode::UPDATE_LOCATION):
            if (msg.header.request_flag) {
                s6a_msg.ulr = parseULR(msg);
            } else {
                s6a_msg.ula = parseULA(msg);
            }
            break;

        case static_cast<uint32_t>(DiameterCommandCode::AUTHENTICATION_INFORMATION):
            if (msg.header.request_flag) {
                s6a_msg.air = parseAIR(msg);
            } else {
                s6a_msg.aia = parseAIA(msg);
            }
            break;

        case static_cast<uint32_t>(DiameterCommandCode::PURGE_UE):
            if (msg.header.request_flag) {
                s6a_msg.pur = parsePUR(msg);
            } else {
                s6a_msg.pua = parsePUA(msg);
            }
            break;

        case static_cast<uint32_t>(DiameterCommandCode::CANCEL_LOCATION):
            if (msg.header.request_flag) {
                s6a_msg.clr = parseCLR(msg);
            } else {
                s6a_msg.cla = parseCLA(msg);
            }
            break;

        case static_cast<uint32_t>(DiameterCommandCode::INSERT_SUBSCRIBER_DATA):
            if (msg.header.request_flag) {
                s6a_msg.idr = parseIDR(msg);
            } else {
                s6a_msg.ida = parseIDA(msg);
            }
            break;

        case static_cast<uint32_t>(DiameterCommandCode::DELETE_SUBSCRIBER_DATA):
            if (msg.header.request_flag) {
                s6a_msg.dsr = parseDSR(msg);
            } else {
                s6a_msg.dsa = parseDSA(msg);
            }
            break;

        default:
            // Unknown S6a message
            LOG_WARN("Unknown S6a command code: " + std::to_string(msg.header.command_code));
            break;
    }

    return s6a_msg;
}

// ============================================================================
// Message-specific parsers (simplified implementations)
// ============================================================================

UpdateLocationRequest DiameterS6aParser::parseULR(const DiameterMessage& msg) {
    UpdateLocationRequest ulr = {};

    auto user_name = findAVP(msg.avps, static_cast<uint32_t>(DiameterAvpCode::USER_NAME));
    if (user_name.has_value()) {
        ulr.user_name = getAVPString(user_name.value()).value_or("");
    }

    auto visited_plmn =
        findAVP(msg.avps, static_cast<uint32_t>(DiameterS6aAvpCode::VISITED_PLMN_ID));
    if (visited_plmn.has_value()) {
        auto octets = getAVPOctetString(visited_plmn.value());
        if (octets.has_value()) {
            std::string plmn_id;
            for (auto byte : octets.value()) {
                char hex[3];
                snprintf(hex, sizeof(hex), "%02x", byte);
                plmn_id += hex;
            }
            ulr.visited_plmn_id = plmn_id;
        }
    }

    auto rat_type = findAVP(msg.avps, static_cast<uint32_t>(DiameterAvpCode::RAT_TYPE));
    if (rat_type.has_value()) {
        ulr.rat_type = static_cast<RATType>(getAVPUint32(rat_type.value()).value_or(0));
    }

    auto ulr_flags_avp = findAVP(msg.avps, static_cast<uint32_t>(DiameterS6aAvpCode::ULR_FLAGS));
    if (ulr_flags_avp.has_value()) {
        ulr.ulr_flags = parseULRFlags(ulr_flags_avp.value()).value_or(ULRFlags{});
    }

    return ulr;
}

UpdateLocationAnswer DiameterS6aParser::parseULA(const DiameterMessage& msg) {
    UpdateLocationAnswer ula = {};

    auto result_code = findAVP(msg.avps, static_cast<uint32_t>(DiameterAvpCode::RESULT_CODE));
    if (result_code.has_value()) {
        ula.result_code = getAVPUint32(result_code.value()).value_or(0);
    }

    auto ula_flags_avp = findAVP(msg.avps, static_cast<uint32_t>(DiameterS6aAvpCode::ULA_FLAGS));
    if (ula_flags_avp.has_value()) {
        ula.ula_flags = parseULAFlags(ula_flags_avp.value());
    }

    auto subscription_data_avp =
        findAVP(msg.avps, static_cast<uint32_t>(DiameterS6aAvpCode::SUBSCRIPTION_DATA));
    if (subscription_data_avp.has_value()) {
        ula.subscription_data = parseSubscriptionData(subscription_data_avp.value());
    }

    return ula;
}

AuthenticationInformationRequest DiameterS6aParser::parseAIR(const DiameterMessage& msg) {
    AuthenticationInformationRequest air = {};

    auto user_name = findAVP(msg.avps, static_cast<uint32_t>(DiameterAvpCode::USER_NAME));
    if (user_name.has_value()) {
        air.user_name = getAVPString(user_name.value()).value_or("");
    }

    auto visited_plmn =
        findAVP(msg.avps, static_cast<uint32_t>(DiameterS6aAvpCode::VISITED_PLMN_ID));
    if (visited_plmn.has_value()) {
        auto octets = getAVPOctetString(visited_plmn.value());
        if (octets.has_value()) {
            std::string plmn_id;
            for (auto byte : octets.value()) {
                char hex[3];
                snprintf(hex, sizeof(hex), "%02x", byte);
                plmn_id += hex;
            }
            air.visited_plmn_id = plmn_id;
        }
    }

    auto num_vectors =
        findAVP(msg.avps, static_cast<uint32_t>(DiameterS6aAvpCode::NUMBER_OF_REQUESTED_VECTORS));
    if (num_vectors.has_value()) {
        air.number_of_requested_vectors = getAVPUint32(num_vectors.value()).value_or(1);
    }

    return air;
}

AuthenticationInformationAnswer DiameterS6aParser::parseAIA(const DiameterMessage& msg) {
    AuthenticationInformationAnswer aia = {};

    auto result_code = findAVP(msg.avps, static_cast<uint32_t>(DiameterAvpCode::RESULT_CODE));
    if (result_code.has_value()) {
        aia.result_code = getAVPUint32(result_code.value()).value_or(0);
    }

    auto auth_info_avp =
        findAVP(msg.avps, static_cast<uint32_t>(DiameterS6aAvpCode::AUTHENTICATION_INFO));
    if (auth_info_avp.has_value()) {
        aia.auth_info = parseAuthenticationInfo(auth_info_avp.value());
    }

    return aia;
}

PurgeUERequest DiameterS6aParser::parsePUR(const DiameterMessage& msg) {
    PurgeUERequest pur = {};

    auto user_name = findAVP(msg.avps, static_cast<uint32_t>(DiameterAvpCode::USER_NAME));
    if (user_name.has_value()) {
        pur.user_name = getAVPString(user_name.value()).value_or("");
    }

    auto pur_flags_avp = findAVP(msg.avps, static_cast<uint32_t>(DiameterS6aAvpCode::PUR_FLAGS));
    if (pur_flags_avp.has_value()) {
        pur.pur_flags = getAVPUint32(pur_flags_avp.value());
    }

    return pur;
}

PurgeUEAnswer DiameterS6aParser::parsePUA(const DiameterMessage& msg) {
    PurgeUEAnswer pua = {};

    auto result_code = findAVP(msg.avps, static_cast<uint32_t>(DiameterAvpCode::RESULT_CODE));
    if (result_code.has_value()) {
        pua.result_code = getAVPUint32(result_code.value()).value_or(0);
    }

    auto pua_flags_avp = findAVP(msg.avps, static_cast<uint32_t>(DiameterS6aAvpCode::PUA_FLAGS));
    if (pua_flags_avp.has_value()) {
        pua.pua_flags = getAVPUint32(pua_flags_avp.value());
    }

    return pua;
}

CancelLocationRequest DiameterS6aParser::parseCLR(const DiameterMessage& msg) {
    CancelLocationRequest clr = {};

    auto user_name = findAVP(msg.avps, static_cast<uint32_t>(DiameterAvpCode::USER_NAME));
    if (user_name.has_value()) {
        clr.user_name = getAVPString(user_name.value()).value_or("");
    }

    auto cancellation_type_avp =
        findAVP(msg.avps, static_cast<uint32_t>(DiameterS6aAvpCode::CANCELLATION_TYPE));
    if (cancellation_type_avp.has_value()) {
        clr.cancellation_type =
            static_cast<CancellationType>(getAVPUint32(cancellation_type_avp.value()).value_or(0));
    }

    auto clr_flags_avp = findAVP(msg.avps, static_cast<uint32_t>(DiameterS6aAvpCode::CLR_FLAGS));
    if (clr_flags_avp.has_value()) {
        clr.clr_flags = getAVPUint32(clr_flags_avp.value());
    }

    return clr;
}

CancelLocationAnswer DiameterS6aParser::parseCLA(const DiameterMessage& msg) {
    CancelLocationAnswer cla = {};

    auto result_code = findAVP(msg.avps, static_cast<uint32_t>(DiameterAvpCode::RESULT_CODE));
    if (result_code.has_value()) {
        cla.result_code = getAVPUint32(result_code.value()).value_or(0);
    }

    return cla;
}

InsertSubscriberDataRequest DiameterS6aParser::parseIDR(const DiameterMessage& msg) {
    InsertSubscriberDataRequest idr = {};

    auto user_name = findAVP(msg.avps, static_cast<uint32_t>(DiameterAvpCode::USER_NAME));
    if (user_name.has_value()) {
        idr.user_name = getAVPString(user_name.value()).value_or("");
    }

    auto subscription_data_avp =
        findAVP(msg.avps, static_cast<uint32_t>(DiameterS6aAvpCode::SUBSCRIPTION_DATA));
    if (subscription_data_avp.has_value()) {
        auto sub_data = parseSubscriptionData(subscription_data_avp.value());
        if (sub_data.has_value()) {
            idr.subscription_data = sub_data.value();
        }
    }

    return idr;
}

InsertSubscriberDataAnswer DiameterS6aParser::parseIDA(const DiameterMessage& msg) {
    InsertSubscriberDataAnswer ida = {};

    auto result_code = findAVP(msg.avps, static_cast<uint32_t>(DiameterAvpCode::RESULT_CODE));
    if (result_code.has_value()) {
        ida.result_code = getAVPUint32(result_code.value()).value_or(0);
    }

    auto ida_flags_avp = findAVP(msg.avps, static_cast<uint32_t>(DiameterS6aAvpCode::IDA_FLAGS));
    if (ida_flags_avp.has_value()) {
        ida.ida_flags = getAVPUint32(ida_flags_avp.value());
    }

    return ida;
}

DeleteSubscriberDataRequest DiameterS6aParser::parseDSR(const DiameterMessage& msg) {
    DeleteSubscriberDataRequest dsr = {};

    auto user_name = findAVP(msg.avps, static_cast<uint32_t>(DiameterAvpCode::USER_NAME));
    if (user_name.has_value()) {
        dsr.user_name = getAVPString(user_name.value()).value_or("");
    }

    auto context_id_avps =
        findAllAVPs(msg.avps, static_cast<uint32_t>(DiameterS6aAvpCode::CONTEXT_IDENTIFIER));
    for (const auto& avp : context_id_avps) {
        auto ctx_id = getAVPUint32(avp);
        if (ctx_id.has_value()) {
            dsr.context_identifiers.push_back(ctx_id.value());
        }
    }

    return dsr;
}

DeleteSubscriberDataAnswer DiameterS6aParser::parseDSA(const DiameterMessage& msg) {
    DeleteSubscriberDataAnswer dsa = {};

    auto result_code = findAVP(msg.avps, static_cast<uint32_t>(DiameterAvpCode::RESULT_CODE));
    if (result_code.has_value()) {
        dsa.result_code = getAVPUint32(result_code.value()).value_or(0);
    }

    return dsa;
}

// ============================================================================
// AVP Parsers (simplified - implement full parsing as needed)
// ============================================================================

std::optional<SubscriptionData> DiameterS6aParser::parseSubscriptionData(const DiameterAvp& avp) {
    SubscriptionData sub_data;

    auto grouped_avps = parseGroupedAVP(avp);

    for (const auto& group_avp : grouped_avps) {
        if (group_avp.code == static_cast<uint32_t>(DiameterS6aAvpCode::SUBSCRIBER_STATUS)) {
            auto val = getAVPUint32(group_avp).value_or(0);
            sub_data.subscriber_status = static_cast<SubscriberStatus>(val);
        } else if (group_avp.code == static_cast<uint32_t>(DiameterS6aAvpCode::MSISDN)) {
            sub_data.msisdn = getAVPString(group_avp);
        } else if (group_avp.code ==
                   static_cast<uint32_t>(DiameterS6aAvpCode::NETWORK_ACCESS_MODE)) {
            auto val = getAVPUint32(group_avp).value_or(0);
            sub_data.network_access_mode = static_cast<NetworkAccessMode>(val);
        } else if (group_avp.code ==
                   static_cast<uint32_t>(DiameterS6aAvpCode::OPERATOR_DETERMINED_BARRING)) {
            sub_data.operator_determined_barring = getAVPUint32(group_avp);
        } else if (group_avp.code == static_cast<uint32_t>(DiameterS6aAvpCode::AMBR)) {
            sub_data.ambr = parseAMBR(group_avp);
        } else if (group_avp.code ==
                   static_cast<uint32_t>(DiameterS6aAvpCode::APN_CONFIGURATION_PROFILE)) {
            sub_data.apn_configuration_profile = parseAPNConfigurationProfile(group_avp);
        } else if (group_avp.code ==
                   static_cast<uint32_t>(DiameterS6aAvpCode::ACCESS_RESTRICTION_DATA)) {
            sub_data.access_restriction_data = getAVPUint32(group_avp);
        }
    }

    return sub_data;
}

std::optional<AuthenticationInfo> DiameterS6aParser::parseAuthenticationInfo(
    const DiameterAvp& avp) {
    AuthenticationInfo auth_info;

    auto grouped_avps = parseGroupedAVP(avp);

    // Find E-UTRAN-Vector AVPs
    for (const auto& group_avp : grouped_avps) {
        if (group_avp.code == static_cast<uint32_t>(DiameterS6aAvpCode::E_UTRAN_VECTOR)) {
            auto vector = parseEUTRANVector(group_avp);
            if (vector.has_value()) {
                auth_info.eutran_vectors.push_back(vector.value());
            }
        }
    }

    return auth_info;
}

std::optional<EUTRANVector> DiameterS6aParser::parseEUTRANVector(const DiameterAvp& avp) {
    EUTRANVector vector;
    vector.rand.fill(0);
    vector.xres.fill(0);
    vector.autn.fill(0);
    vector.kasme.fill(0);

    auto grouped_avps = parseGroupedAVP(avp);

    for (const auto& group_avp : grouped_avps) {
        if (group_avp.code == static_cast<uint32_t>(DiameterS6aAvpCode::RAND)) {
            auto octets = getAVPOctetString(group_avp);
            if (octets.has_value() && octets->size() == 16) {
                std::copy(octets->begin(), octets->end(), vector.rand.begin());
            }
        } else if (group_avp.code == static_cast<uint32_t>(DiameterS6aAvpCode::XRES)) {
            auto octets = getAVPOctetString(group_avp);
            if (octets.has_value() && octets->size() <= 16) {
                std::copy(octets->begin(), octets->end(), vector.xres.begin());
            }
        } else if (group_avp.code == static_cast<uint32_t>(DiameterS6aAvpCode::AUTN)) {
            auto octets = getAVPOctetString(group_avp);
            if (octets.has_value() && octets->size() == 16) {
                std::copy(octets->begin(), octets->end(), vector.autn.begin());
            }
        } else if (group_avp.code == static_cast<uint32_t>(DiameterS6aAvpCode::KASME)) {
            auto octets = getAVPOctetString(group_avp);
            if (octets.has_value() && octets->size() == 32) {
                std::copy(octets->begin(), octets->end(), vector.kasme.begin());
            }
        }
    }

    return vector;
}

std::optional<ULRFlags> DiameterS6aParser::parseULRFlags(const DiameterAvp& avp) {
    auto value = getAVPUint32(avp);
    if (!value.has_value()) {
        return std::nullopt;
    }

    ULRFlags flags;
    uint32_t val = value.value();
    flags.single_registration_indication = (val & 0x01) != 0;
    flags.s6a_s6d_indicator = (val & 0x02) != 0;
    flags.skip_subscriber_data = (val & 0x04) != 0;
    flags.gprs_subscription_data_indicator = (val & 0x08) != 0;
    flags.node_type_indicator = (val & 0x10) != 0;
    flags.initial_attach_indicator = (val & 0x20) != 0;
    flags.ps_lcs_not_supported_by_ue = (val & 0x40) != 0;

    return flags;
}

std::optional<ULAFlags> DiameterS6aParser::parseULAFlags(const DiameterAvp& avp) {
    auto value = getAVPUint32(avp);
    if (!value.has_value()) {
        return std::nullopt;
    }

    ULAFlags flags;
    uint32_t val = value.value();
    flags.separation_indication = (val & 0x01) != 0;

    return flags;
}

std::optional<EPSSubscribedQoSProfile> DiameterS6aParser::parseEPSSubscribedQoSProfile(
    const DiameterAvp& avp) {
    EPSSubscribedQoSProfile qos;
    qos.qos_class_identifier = 0;

    auto grouped_avps = parseGroupedAVP(avp);

    for (const auto& group_avp : grouped_avps) {
        if (group_avp.code == static_cast<uint32_t>(DiameterAvpCode::QOS_CLASS_IDENTIFIER)) {
            qos.qos_class_identifier = getAVPUint32(group_avp).value_or(0);
        } else if (group_avp.code ==
                   static_cast<uint32_t>(DiameterS6aAvpCode::ALLOCATION_RETENTION_PRIORITY)) {
            auto arp = parseAllocationRetentionPriority(group_avp);
            if (arp.has_value()) {
                qos.allocation_retention_priority = arp.value();
            }
        }
    }

    return qos;
}

std::optional<AMBR> DiameterS6aParser::parseAMBR(const DiameterAvp& avp) {
    AMBR ambr;
    ambr.max_requested_bandwidth_ul = 0;
    ambr.max_requested_bandwidth_dl = 0;

    auto grouped_avps = parseGroupedAVP(avp);

    for (const auto& group_avp : grouped_avps) {
        if (group_avp.code == static_cast<uint32_t>(DiameterAvpCode::MAX_REQUESTED_BANDWIDTH_UL)) {
            ambr.max_requested_bandwidth_ul = getAVPUint32(group_avp).value_or(0);
        } else if (group_avp.code ==
                   static_cast<uint32_t>(DiameterAvpCode::MAX_REQUESTED_BANDWIDTH_DL)) {
            ambr.max_requested_bandwidth_dl = getAVPUint32(group_avp).value_or(0);
        }
    }

    return ambr;
}

std::optional<AllocationRetentionPriority> DiameterS6aParser::parseAllocationRetentionPriority(
    const DiameterAvp& avp) {
    AllocationRetentionPriority arp;
    arp.priority_level = 0;
    arp.pre_emption_capability = false;
    arp.pre_emption_vulnerability = false;

    auto grouped_avps = parseGroupedAVP(avp);

    for (const auto& group_avp : grouped_avps) {
        if (group_avp.code == static_cast<uint32_t>(DiameterS6aAvpCode::PRIORITY_LEVEL)) {
            arp.priority_level = getAVPUint32(group_avp).value_or(0);
        } else if (group_avp.code ==
                   static_cast<uint32_t>(DiameterS6aAvpCode::PRE_EMPTION_CAPABILITY)) {
            auto val = getAVPUint32(group_avp).value_or(0);
            arp.pre_emption_capability = (val == 0);  // 0 = PRE-EMPTION_CAPABILITY_ENABLED
        } else if (group_avp.code ==
                   static_cast<uint32_t>(DiameterS6aAvpCode::PRE_EMPTION_VULNERABILITY)) {
            auto val = getAVPUint32(group_avp).value_or(0);
            arp.pre_emption_vulnerability = (val == 0);  // 0 = PRE-EMPTION_VULNERABILITY_ENABLED
        }
    }

    return arp;
}

std::optional<APNConfiguration> DiameterS6aParser::parseAPNConfiguration(const DiameterAvp& avp) {
    APNConfiguration apn_config;
    apn_config.context_identifier = 0;
    apn_config.pdn_type = PDNType::IPv4;
    apn_config.qos_profile = EPSSubscribedQoSProfile{};

    auto grouped_avps = parseGroupedAVP(avp);

    for (const auto& group_avp : grouped_avps) {
        if (group_avp.code == static_cast<uint32_t>(DiameterS6aAvpCode::CONTEXT_IDENTIFIER)) {
            apn_config.context_identifier = getAVPUint32(group_avp).value_or(0);
        } else if (group_avp.code == static_cast<uint32_t>(DiameterAvpCode::SERVICE_SELECTION)) {
            apn_config.service_selection = getAVPString(group_avp).value_or("");
        } else if (group_avp.code == static_cast<uint32_t>(DiameterS6aAvpCode::PDN_TYPE)) {
            auto pdn_val = getAVPUint32(group_avp).value_or(0);
            apn_config.pdn_type = static_cast<PDNType>(pdn_val);
        } else if (group_avp.code ==
                   static_cast<uint32_t>(DiameterS6aAvpCode::EPS_SUBSCRIBED_QOS_PROFILE)) {
            auto qos = parseEPSSubscribedQoSProfile(group_avp);
            if (qos.has_value()) {
                apn_config.qos_profile = qos.value();
            }
        } else if (group_avp.code == static_cast<uint32_t>(DiameterS6aAvpCode::AMBR)) {
            apn_config.ambr = parseAMBR(group_avp);
        } else if (group_avp.code ==
                   static_cast<uint32_t>(DiameterS6aAvpCode::VPLMN_DYNAMIC_ADDRESS_ALLOWED)) {
            auto val = getAVPUint32(group_avp).value_or(0);
            apn_config.vplmn_dynamic_address_allowed = (val == 0);  // 0 = NOTALLOWED, 1 = ALLOWED
        }
    }

    return apn_config;
}

std::optional<APNConfigurationProfile> DiameterS6aParser::parseAPNConfigurationProfile(
    const DiameterAvp& avp) {
    APNConfigurationProfile profile;
    profile.context_identifier = 0;
    profile.all_apn_config_inc_ind = false;

    auto grouped_avps = parseGroupedAVP(avp);

    for (const auto& group_avp : grouped_avps) {
        if (group_avp.code == static_cast<uint32_t>(DiameterS6aAvpCode::CONTEXT_IDENTIFIER)) {
            profile.context_identifier = getAVPUint32(group_avp).value_or(0);
        } else if (group_avp.code ==
                   static_cast<uint32_t>(DiameterS6aAvpCode::ALL_APN_CONFIG_INC_IND)) {
            auto val = getAVPUint32(group_avp).value_or(0);
            profile.all_apn_config_inc_ind = (val == 0);  // 0 = All_APN_CONFIGURATIONS_INCLUDED
        } else if (group_avp.code == static_cast<uint32_t>(DiameterS6aAvpCode::APN_CONFIGURATION)) {
            auto apn_config = parseAPNConfiguration(group_avp);
            if (apn_config.has_value()) {
                profile.apn_configs.push_back(apn_config.value());
            }
        }
    }

    return profile;
}

// ============================================================================
// Helper functions
// ============================================================================

std::optional<DiameterAvp> DiameterS6aParser::findAVP(const std::vector<DiameterAvp>& avps,
                                                      uint32_t code) {
    for (const auto& avp : avps) {
        if (avp.code == code) {
            return avp;
        }
    }
    return std::nullopt;
}

std::vector<DiameterAvp> DiameterS6aParser::findAllAVPs(const std::vector<DiameterAvp>& avps,
                                                        uint32_t code) {
    std::vector<DiameterAvp> result;
    for (const auto& avp : avps) {
        if (avp.code == code) {
            result.push_back(avp);
        }
    }
    return result;
}

std::optional<std::string> DiameterS6aParser::getAVPString(const DiameterAvp& avp) {
    return avp.getDataAsString();
}

std::optional<uint32_t> DiameterS6aParser::getAVPUint32(const DiameterAvp& avp) {
    return avp.getDataAsUint32();
}

std::optional<std::vector<uint8_t>> DiameterS6aParser::getAVPOctetString(const DiameterAvp& avp) {
    if (avp.data.empty()) {
        return std::nullopt;
    }
    return avp.data;
}

std::vector<DiameterAvp> DiameterS6aParser::parseGroupedAVP(const DiameterAvp& avp) {
    std::vector<DiameterAvp> result;

    if (avp.data.empty()) {
        return result;
    }

    const uint8_t* data = avp.data.data();
    size_t len = avp.data.size();
    size_t offset = 0;

    // Parse each nested AVP
    while (offset < len) {
        // AVP header is at least 8 bytes (without vendor ID)
        if (offset + 8 > len) {
            LOG_DEBUG("Not enough data for nested AVP header at offset " << offset);
            break;
        }

        DiameterAvp nested_avp;

        // Bytes 0-3: AVP Code
        uint32_t code;
        std::memcpy(&code, data + offset, 4);
        nested_avp.code = ntohl(code);

        // Byte 4: Flags
        uint8_t flags = data[offset + 4];
        nested_avp.vendor_flag = (flags & 0x80) != 0;     // V bit
        nested_avp.mandatory_flag = (flags & 0x40) != 0;  // M bit
        nested_avp.protected_flag = (flags & 0x20) != 0;  // P bit

        // Bytes 5-7: AVP Length (24 bits)
        nested_avp.length = (static_cast<uint32_t>(data[offset + 5]) << 16) |
                            (static_cast<uint32_t>(data[offset + 6]) << 8) |
                            static_cast<uint32_t>(data[offset + 7]);

        if (nested_avp.length < 8) {
            LOG_ERROR("Invalid nested AVP length: " << nested_avp.length);
            break;
        }

        size_t header_len = 8;

        // Bytes 8-11: Vendor ID (if V flag set)
        if (nested_avp.vendor_flag) {
            if (offset + 12 > len) {
                LOG_DEBUG("Not enough data for vendor ID at offset " << offset);
                break;
            }
            uint32_t vendor_id;
            std::memcpy(&vendor_id, data + offset + 8, 4);
            nested_avp.vendor_id = ntohl(vendor_id);
            header_len = 12;
        } else {
            nested_avp.vendor_id = 0;
        }

        // Calculate data length
        if (nested_avp.length < header_len) {
            LOG_ERROR("Nested AVP length " << nested_avp.length << " is less than header length "
                                           << header_len);
            break;
        }

        size_t data_len = nested_avp.length - header_len;

        // Check if we have enough data
        if (offset + header_len + data_len > len) {
            LOG_DEBUG("Not enough data for nested AVP data at offset " << offset);
            break;
        }

        // Copy nested AVP data
        nested_avp.data.resize(data_len);
        std::memcpy(nested_avp.data.data(), data + offset + header_len, data_len);

        result.push_back(nested_avp);

        // Calculate padding (AVPs are padded to 4-byte boundaries)
        size_t remainder = nested_avp.length % 4;
        size_t padding = remainder == 0 ? 0 : (4 - remainder);
        offset += nested_avp.length + padding;
    }

    LOG_DEBUG("Parsed " << result.size() << " nested AVPs from grouped AVP");
    return result;
}

}  // namespace callflow
