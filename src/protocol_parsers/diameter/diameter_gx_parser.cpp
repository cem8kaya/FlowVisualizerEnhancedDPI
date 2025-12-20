#include "protocol_parsers/diameter/diameter_gx.h"
#include "protocol_parsers/diameter/diameter_avp_parser.h"
#include "common/logger.h"
#include <arpa/inet.h>

namespace callflow {
namespace diameter {

// ============================================================================
// Structure toJson() Methods
// ============================================================================

nlohmann::json ChargingRuleDefinition::toJson() const {
    nlohmann::json j;
    j["charging_rule_name"] = charging_rule_name;

    if (service_identifier.has_value()) {
        j["service_identifier"] = service_identifier.value();
    }
    if (rating_group.has_value()) {
        j["rating_group"] = rating_group.value();
    }

    if (!flow_information.empty()) {
        nlohmann::json flows = nlohmann::json::array();
        for (const auto& flow : flow_information) {
            flows.push_back(flow.toJson());
        }
        j["flow_information"] = flows;
    }

    if (qos_information.has_value()) {
        j["qos_information"] = qos_information->toJson();
    }
    if (precedence.has_value()) {
        j["precedence"] = precedence.value();
    }
    if (flow_status.has_value()) {
        j["flow_status"] = static_cast<uint32_t>(flow_status.value());
    }
    if (metering_method.has_value()) {
        j["metering_method"] = static_cast<uint32_t>(metering_method.value());
    }
    if (reporting_level.has_value()) {
        j["reporting_level"] = static_cast<uint32_t>(reporting_level.value());
    }
    if (online.has_value()) {
        j["online"] = online.value();
    }
    if (offline.has_value()) {
        j["offline"] = offline.value();
    }

    return j;
}

nlohmann::json ChargingRuleInstall::toJson() const {
    nlohmann::json j;

    if (!charging_rule_definition.empty()) {
        nlohmann::json defs = nlohmann::json::array();
        for (const auto& def : charging_rule_definition) {
            defs.push_back(def.toJson());
        }
        j["charging_rule_definition"] = defs;
    }

    if (!charging_rule_name.empty()) {
        j["charging_rule_name"] = charging_rule_name;
    }
    if (!charging_rule_base_name.empty()) {
        j["charging_rule_base_name"] = charging_rule_base_name;
    }
    if (bearer_identifier.has_value()) {
        j["bearer_identifier"] = bearer_identifier.value();
    }
    if (bearer_operation.has_value()) {
        j["bearer_operation"] = static_cast<uint32_t>(bearer_operation.value());
    }

    return j;
}

nlohmann::json ChargingRuleRemove::toJson() const {
    nlohmann::json j;
    if (!charging_rule_name.empty()) {
        j["charging_rule_name"] = charging_rule_name;
    }
    if (!charging_rule_base_name.empty()) {
        j["charging_rule_base_name"] = charging_rule_base_name;
    }
    return j;
}

nlohmann::json UsageMonitoringInformation::toJson() const {
    nlohmann::json j;

    if (monitoring_key.has_value()) {
        j["monitoring_key"] = nlohmann::json(monitoring_key.value());
    }
    if (granted_service_unit.has_value()) {
        j["granted_service_unit"] = granted_service_unit->toJson();
    }
    if (used_service_unit.has_value()) {
        j["used_service_unit"] = used_service_unit->toJson();
    }
    if (usage_monitoring_level.has_value()) {
        j["usage_monitoring_level"] = usage_monitoring_level.value();
    }
    if (usage_monitoring_report.has_value()) {
        j["usage_monitoring_report"] = usage_monitoring_report.value();
    }
    if (usage_monitoring_support.has_value()) {
        j["usage_monitoring_support"] = usage_monitoring_support.value();
    }

    return j;
}

nlohmann::json PCCRuleStatusReport::toJson() const {
    nlohmann::json j;
    j["rule_names"] = rule_names;
    j["pcc_rule_status"] = static_cast<uint32_t>(pcc_rule_status);
    if (rule_failure_code.has_value()) {
        j["rule_failure_code"] = static_cast<uint32_t>(rule_failure_code.value());
    }
    return j;
}

nlohmann::json GxCreditControlRequest::toJson() const {
    nlohmann::json j;
    j["cc_request_type"] = getCCRequestTypeName(cc_request_type);
    j["cc_request_number"] = cc_request_number;

    if (network_request_support.has_value()) {
        j["network_request_support"] = network_request_support.value();
    }
    if (bearer_control_mode.has_value()) {
        j["bearer_control_mode"] = static_cast<uint32_t>(bearer_control_mode.value());
    }
    if (ip_can_type.has_value()) {
        j["ip_can_type"] = getIPCANTypeName(ip_can_type.value());
    }
    if (rat_type.has_value()) {
        j["rat_type"] = rat_type.value();
    }
    if (framed_ip_address.has_value()) {
        j["framed_ip_address"] = framed_ip_address.value();
    }
    if (framed_ipv6_prefix.has_value()) {
        j["framed_ipv6_prefix"] = framed_ipv6_prefix.value();
    }
    if (called_station_id.has_value()) {
        j["called_station_id"] = called_station_id.value();
    }
    if (subscription_id.has_value()) {
        j["subscription_id"] = subscription_id->toJson();
    }

    if (!event_triggers.empty()) {
        nlohmann::json triggers = nlohmann::json::array();
        for (const auto& trigger : event_triggers) {
            triggers.push_back(static_cast<uint32_t>(trigger));
        }
        j["event_triggers"] = triggers;
    }

    if (!usage_monitoring.empty()) {
        nlohmann::json monitoring = nlohmann::json::array();
        for (const auto& umi : usage_monitoring) {
            monitoring.push_back(umi.toJson());
        }
        j["usage_monitoring"] = monitoring;
    }

    if (an_gw_address.has_value()) {
        j["an_gw_address"] = an_gw_address.value();
    }
    if (tgpp_sgsn_address.has_value()) {
        j["tgpp_sgsn_address"] = tgpp_sgsn_address.value();
    }

    return j;
}

nlohmann::json GxCreditControlAnswer::toJson() const {
    nlohmann::json j;
    j["result_code"] = result_code;
    j["cc_request_type"] = getCCRequestTypeName(cc_request_type);
    j["cc_request_number"] = cc_request_number;

    if (!charging_rule_install.empty()) {
        nlohmann::json installs = nlohmann::json::array();
        for (const auto& install : charging_rule_install) {
            installs.push_back(install.toJson());
        }
        j["charging_rule_install"] = installs;
    }

    if (!charging_rule_remove.empty()) {
        nlohmann::json removes = nlohmann::json::array();
        for (const auto& remove : charging_rule_remove) {
            removes.push_back(remove.toJson());
        }
        j["charging_rule_remove"] = removes;
    }

    if (qos_information.has_value()) {
        j["qos_information"] = qos_information->toJson();
    }
    if (default_eps_bearer_qos.has_value()) {
        j["default_eps_bearer_qos"] = default_eps_bearer_qos->toJson();
    }
    if (bearer_control_mode.has_value()) {
        j["bearer_control_mode"] = static_cast<uint32_t>(bearer_control_mode.value());
    }
    if (bearer_operation.has_value()) {
        j["bearer_operation"] = static_cast<uint32_t>(bearer_operation.value());
    }

    if (!usage_monitoring.empty()) {
        nlohmann::json monitoring = nlohmann::json::array();
        for (const auto& umi : usage_monitoring) {
            monitoring.push_back(umi.toJson());
        }
        j["usage_monitoring"] = monitoring;
    }

    if (!event_triggers.empty()) {
        nlohmann::json triggers = nlohmann::json::array();
        for (const auto& trigger : event_triggers) {
            triggers.push_back(static_cast<uint32_t>(trigger));
        }
        j["event_triggers"] = triggers;
    }

    if (session_release_cause.has_value()) {
        j["session_release_cause"] = static_cast<uint32_t>(session_release_cause.value());
    }
    if (supported_features.has_value()) {
        j["supported_features"] = supported_features.value();
    }

    return j;
}

nlohmann::json GxReAuthRequest::toJson() const {
    nlohmann::json j;
    j["re_auth_request_type"] = re_auth_request_type;

    if (!charging_rule_install.empty()) {
        nlohmann::json installs = nlohmann::json::array();
        for (const auto& install : charging_rule_install) {
            installs.push_back(install.toJson());
        }
        j["charging_rule_install"] = installs;
    }

    if (!charging_rule_remove.empty()) {
        nlohmann::json removes = nlohmann::json::array();
        for (const auto& remove : charging_rule_remove) {
            removes.push_back(remove.toJson());
        }
        j["charging_rule_remove"] = removes;
    }

    if (qos_information.has_value()) {
        j["qos_information"] = qos_information->toJson();
    }
    if (default_eps_bearer_qos.has_value()) {
        j["default_eps_bearer_qos"] = default_eps_bearer_qos->toJson();
    }

    if (!event_triggers.empty()) {
        nlohmann::json triggers = nlohmann::json::array();
        for (const auto& trigger : event_triggers) {
            triggers.push_back(static_cast<uint32_t>(trigger));
        }
        j["event_triggers"] = triggers;
    }

    if (!usage_monitoring.empty()) {
        nlohmann::json monitoring = nlohmann::json::array();
        for (const auto& umi : usage_monitoring) {
            monitoring.push_back(umi.toJson());
        }
        j["usage_monitoring"] = monitoring;
    }

    return j;
}

nlohmann::json GxReAuthAnswer::toJson() const {
    nlohmann::json j;
    j["result_code"] = result_code;

    if (!pcc_rule_status_reports.empty()) {
        nlohmann::json reports = nlohmann::json::array();
        for (const auto& report : pcc_rule_status_reports) {
            reports.push_back(report.toJson());
        }
        j["pcc_rule_status_reports"] = reports;
    }

    return j;
}

nlohmann::json DiameterGxMessage::toJson() const {
    nlohmann::json j = base.toJson();
    j["interface"] = "Gx";

    if (ccr.has_value()) {
        j["ccr"] = ccr->toJson();
    }
    if (cca.has_value()) {
        j["cca"] = cca->toJson();
    }
    if (rar.has_value()) {
        j["rar"] = rar->toJson();
    }
    if (raa.has_value()) {
        j["raa"] = raa->toJson();
    }

    if (framed_ip_address.has_value()) {
        j["framed_ip_address"] = framed_ip_address.value();
    }
    if (called_station_id.has_value()) {
        j["called_station_id"] = called_station_id.value();
    }
    if (cc_request_type.has_value()) {
        j["cc_request_type"] = getCCRequestTypeName(cc_request_type.value());
    }

    return j;
}

// ============================================================================
// DiameterGxParser Implementation
// ============================================================================

bool DiameterGxParser::isGxMessage(const DiameterMessage& msg) {
    return msg.header.application_id == DIAMETER_GX_APPLICATION_ID ||
           (msg.auth_application_id.has_value() &&
            msg.auth_application_id.value() == DIAMETER_GX_APPLICATION_ID);
}

std::optional<DiameterGxMessage> DiameterGxParser::parse(const DiameterMessage& msg) {
    if (!isGxMessage(msg)) {
        return std::nullopt;
    }

    DiameterGxMessage gx_msg;
    gx_msg.base = msg;

    // Extract common fields
    auto framed_ip_avp = msg.findAVP(static_cast<uint32_t>(GxAVPCode::FRAMED_IP_ADDRESS));
    if (framed_ip_avp) {
        auto ip_str = DiameterAVPParser::parseIPAddress(framed_ip_avp->data);
        if (ip_str.has_value()) {
            gx_msg.framed_ip_address = ip_str.value();
        }
    }

    auto called_station_avp = msg.findAVP(static_cast<uint32_t>(GxAVPCode::CALLED_STATION_ID));
    if (called_station_avp) {
        gx_msg.called_station_id = called_station_avp->getDataAsString();
    }

    // Parse based on command code
    switch (static_cast<DiameterCommandCode>(msg.header.command_code)) {
        case DiameterCommandCode::CREDIT_CONTROL:
            if (msg.isRequest()) {
                gx_msg.ccr = parseCCR(msg);
                if (gx_msg.ccr.has_value()) {
                    gx_msg.cc_request_type = gx_msg.ccr->cc_request_type;
                }
            } else {
                gx_msg.cca = parseCCA(msg);
                if (gx_msg.cca.has_value()) {
                    gx_msg.cc_request_type = gx_msg.cca->cc_request_type;
                }
            }
            break;

        case DiameterCommandCode::RE_AUTH:
            if (msg.isRequest()) {
                gx_msg.rar = parseRAR(msg);
            } else {
                gx_msg.raa = parseRAA(msg);
            }
            break;

        default:
            Logger::warning("Unknown Gx command code: " +
                          std::to_string(msg.header.command_code));
            break;
    }

    return gx_msg;
}

GxCreditControlRequest DiameterGxParser::parseCCR(const DiameterMessage& msg) {
    GxCreditControlRequest ccr;

    // CC-Request-Type and CC-Request-Number
    auto cc_type_avp = msg.findAVP(static_cast<uint32_t>(DiameterAVPCode::CC_REQUEST_TYPE));
    if (cc_type_avp) {
        auto type_val = cc_type_avp->getDataAsUint32();
        if (type_val.has_value()) {
            ccr.cc_request_type = static_cast<CCRequestType>(type_val.value());
        }
    }

    auto cc_num_avp = msg.findAVP(static_cast<uint32_t>(DiameterAVPCode::CC_REQUEST_NUMBER));
    if (cc_num_avp) {
        auto num_val = cc_num_avp->getDataAsUint32();
        if (num_val.has_value()) {
            ccr.cc_request_number = num_val.value();
        }
    }

    // Network information
    auto ip_can_avp = msg.findAVP(static_cast<uint32_t>(GxAVPCode::IP_CAN_TYPE), DIAMETER_VENDOR_3GPP);
    if (ip_can_avp) {
        auto ip_can_val = ip_can_avp->getDataAsUint32();
        if (ip_can_val.has_value()) {
            ccr.ip_can_type = static_cast<IPCANType>(ip_can_val.value());
        }
    }

    auto rat_avp = msg.findAVP(static_cast<uint32_t>(GxAVPCode::RAT_TYPE), DIAMETER_VENDOR_3GPP);
    if (rat_avp) {
        ccr.rat_type = rat_avp->getDataAsUint32();
    }

    auto bearer_ctrl_avp = msg.findAVP(static_cast<uint32_t>(GxAVPCode::BEARER_CONTROL_MODE), DIAMETER_VENDOR_3GPP);
    if (bearer_ctrl_avp) {
        auto bearer_val = bearer_ctrl_avp->getDataAsUint32();
        if (bearer_val.has_value()) {
            ccr.bearer_control_mode = static_cast<BearerControlMode>(bearer_val.value());
        }
    }

    // Subscriber information
    auto framed_ip_avp = msg.findAVP(static_cast<uint32_t>(GxAVPCode::FRAMED_IP_ADDRESS));
    if (framed_ip_avp) {
        auto ip_str = DiameterAVPParser::parseIPAddress(framed_ip_avp->data);
        if (ip_str.has_value()) {
            ccr.framed_ip_address = ip_str.value();
        }
    }

    auto framed_ipv6_avp = msg.findAVP(static_cast<uint32_t>(GxAVPCode::FRAMED_IPV6_PREFIX));
    if (framed_ipv6_avp) {
        ccr.framed_ipv6_prefix = framed_ipv6_avp->getDataAsString();
    }

    auto called_station_avp = msg.findAVP(static_cast<uint32_t>(GxAVPCode::CALLED_STATION_ID));
    if (called_station_avp) {
        ccr.called_station_id = called_station_avp->getDataAsString();
    }

    // Event triggers
    ccr.event_triggers = parseEventTriggers(msg);

    // Usage monitoring
    auto usage_mon_avps = msg.findAllAVPs(static_cast<uint32_t>(GxAVPCode::USAGE_MONITORING_INFORMATION));
    for (const auto& avp : usage_mon_avps) {
        auto umi = parseUsageMonitoringInformation(avp);
        if (umi.has_value()) {
            ccr.usage_monitoring.push_back(umi.value());
        }
    }

    // Access network info
    auto an_gw_avp = msg.findAVP(static_cast<uint32_t>(GxAVPCode::AN_GW_ADDRESS), DIAMETER_VENDOR_3GPP);
    if (an_gw_avp) {
        auto ip_str = DiameterAVPParser::parseIPAddress(an_gw_avp->data);
        if (ip_str.has_value()) {
            ccr.an_gw_address = ip_str.value();
        }
    }

    return ccr;
}

GxCreditControlAnswer DiameterGxParser::parseCCA(const DiameterMessage& msg) {
    GxCreditControlAnswer cca;

    // Result code
    if (msg.result_code.has_value()) {
        cca.result_code = msg.result_code.value();
    }

    // CC-Request-Type and CC-Request-Number
    auto cc_type_avp = msg.findAVP(static_cast<uint32_t>(DiameterAVPCode::CC_REQUEST_TYPE));
    if (cc_type_avp) {
        auto type_val = cc_type_avp->getDataAsUint32();
        if (type_val.has_value()) {
            cca.cc_request_type = static_cast<CCRequestType>(type_val.value());
        }
    }

    auto cc_num_avp = msg.findAVP(static_cast<uint32_t>(DiameterAVPCode::CC_REQUEST_NUMBER));
    if (cc_num_avp) {
        auto num_val = cc_num_avp->getDataAsUint32();
        if (num_val.has_value()) {
            cca.cc_request_number = num_val.value();
        }
    }

    // Charging rule install
    auto rule_install_avps = msg.findAllAVPs(static_cast<uint32_t>(GxAVPCode::CHARGING_RULE_INSTALL));
    for (const auto& avp : rule_install_avps) {
        auto rule_install = parseChargingRuleInstall(avp);
        if (rule_install.has_value()) {
            cca.charging_rule_install.push_back(rule_install.value());
        }
    }

    // Charging rule remove
    auto rule_remove_avps = msg.findAllAVPs(static_cast<uint32_t>(GxAVPCode::CHARGING_RULE_REMOVE));
    for (const auto& avp : rule_remove_avps) {
        auto rule_remove = parseChargingRuleRemove(avp);
        if (rule_remove.has_value()) {
            cca.charging_rule_remove.push_back(rule_remove.value());
        }
    }

    // QoS information
    auto qos_avp = msg.findAVP(static_cast<uint32_t>(GxAVPCode::QOS_INFORMATION), DIAMETER_VENDOR_3GPP);
    if (qos_avp) {
        cca.qos_information = parseQoSInformation(qos_avp);
    }

    // Default EPS Bearer QoS
    auto default_qos_avp = msg.findAVP(static_cast<uint32_t>(GxAVPCode::DEFAULT_EPS_BEARER_QOS), DIAMETER_VENDOR_3GPP);
    if (default_qos_avp) {
        cca.default_eps_bearer_qos = parseDefaultEPSBearerQoS(default_qos_avp);
    }

    // Bearer control mode
    auto bearer_ctrl_avp = msg.findAVP(static_cast<uint32_t>(GxAVPCode::BEARER_CONTROL_MODE), DIAMETER_VENDOR_3GPP);
    if (bearer_ctrl_avp) {
        auto bearer_val = bearer_ctrl_avp->getDataAsUint32();
        if (bearer_val.has_value()) {
            cca.bearer_control_mode = static_cast<BearerControlMode>(bearer_val.value());
        }
    }

    // Usage monitoring
    auto usage_mon_avps = msg.findAllAVPs(static_cast<uint32_t>(GxAVPCode::USAGE_MONITORING_INFORMATION));
    for (const auto& avp : usage_mon_avps) {
        auto umi = parseUsageMonitoringInformation(avp);
        if (umi.has_value()) {
            cca.usage_monitoring.push_back(umi.value());
        }
    }

    // Event triggers
    cca.event_triggers = parseEventTriggers(msg);

    // Session release cause
    auto session_release_avp = msg.findAVP(static_cast<uint32_t>(GxAVPCode::SESSION_RELEASE_CAUSE), DIAMETER_VENDOR_3GPP);
    if (session_release_avp) {
        auto release_val = session_release_avp->getDataAsUint32();
        if (release_val.has_value()) {
            cca.session_release_cause = static_cast<SessionReleaseCause>(release_val.value());
        }
    }

    return cca;
}

GxReAuthRequest DiameterGxParser::parseRAR(const DiameterMessage& msg) {
    GxReAuthRequest rar;

    // Re-Auth-Request-Type
    auto ra_type_avp = msg.findAVP(static_cast<uint32_t>(DiameterAVPCode::RE_AUTH_REQUEST_TYPE));
    if (ra_type_avp) {
        auto type_val = ra_type_avp->getDataAsUint32();
        if (type_val.has_value()) {
            rar.re_auth_request_type = type_val.value();
        }
    }

    // Charging rule install
    auto rule_install_avps = msg.findAllAVPs(static_cast<uint32_t>(GxAVPCode::CHARGING_RULE_INSTALL));
    for (const auto& avp : rule_install_avps) {
        auto rule_install = parseChargingRuleInstall(avp);
        if (rule_install.has_value()) {
            rar.charging_rule_install.push_back(rule_install.value());
        }
    }

    // Charging rule remove
    auto rule_remove_avps = msg.findAllAVPs(static_cast<uint32_t>(GxAVPCode::CHARGING_RULE_REMOVE));
    for (const auto& avp : rule_remove_avps) {
        auto rule_remove = parseChargingRuleRemove(avp);
        if (rule_remove.has_value()) {
            rar.charging_rule_remove.push_back(rule_remove.value());
        }
    }

    // QoS updates
    auto qos_avp = msg.findAVP(static_cast<uint32_t>(GxAVPCode::QOS_INFORMATION), DIAMETER_VENDOR_3GPP);
    if (qos_avp) {
        rar.qos_information = parseQoSInformation(qos_avp);
    }

    auto default_qos_avp = msg.findAVP(static_cast<uint32_t>(GxAVPCode::DEFAULT_EPS_BEARER_QOS), DIAMETER_VENDOR_3GPP);
    if (default_qos_avp) {
        rar.default_eps_bearer_qos = parseDefaultEPSBearerQoS(default_qos_avp);
    }

    // Event triggers
    rar.event_triggers = parseEventTriggers(msg);

    // Usage monitoring
    auto usage_mon_avps = msg.findAllAVPs(static_cast<uint32_t>(GxAVPCode::USAGE_MONITORING_INFORMATION));
    for (const auto& avp : usage_mon_avps) {
        auto umi = parseUsageMonitoringInformation(avp);
        if (umi.has_value()) {
            rar.usage_monitoring.push_back(umi.value());
        }
    }

    return rar;
}

GxReAuthAnswer DiameterGxParser::parseRAA(const DiameterMessage& msg) {
    GxReAuthAnswer raa;

    // Result code
    if (msg.result_code.has_value()) {
        raa.result_code = msg.result_code.value();
    }

    return raa;
}

// ============================================================================
// AVP Parsers
// ============================================================================

std::optional<ChargingRuleInstall> DiameterGxParser::parseChargingRuleInstall(std::shared_ptr<DiameterAVP> avp) {
    auto grouped_avps = avp->getGroupedAVPs();
    if (!grouped_avps.has_value()) {
        return std::nullopt;
    }

    ChargingRuleInstall cri;

    for (const auto& sub_avp : grouped_avps.value()) {
        switch (sub_avp->code) {
            case static_cast<uint32_t>(GxAVPCode::CHARGING_RULE_DEFINITION): {
                auto rule_def = parseChargingRuleDefinition(sub_avp);
                if (rule_def.has_value()) {
                    cri.charging_rule_definition.push_back(rule_def.value());
                }
                break;
            }
            case static_cast<uint32_t>(GxAVPCode::CHARGING_RULE_NAME):
                cri.charging_rule_name.push_back(sub_avp->getDataAsString());
                break;
            case static_cast<uint32_t>(GxAVPCode::CHARGING_RULE_BASE_NAME):
                cri.charging_rule_base_name.push_back(sub_avp->getDataAsString());
                break;
            case static_cast<uint32_t>(GxAVPCode::BEARER_IDENTIFIER):
                cri.bearer_identifier = sub_avp->getDataAsUint32();
                break;
            case static_cast<uint32_t>(GxAVPCode::BEARER_OPERATION): {
                auto op_val = sub_avp->getDataAsUint32();
                if (op_val.has_value()) {
                    cri.bearer_operation = static_cast<BearerOperation>(op_val.value());
                }
                break;
            }
        }
    }

    return cri;
}

std::optional<ChargingRuleRemove> DiameterGxParser::parseChargingRuleRemove(std::shared_ptr<DiameterAVP> avp) {
    auto grouped_avps = avp->getGroupedAVPs();
    if (!grouped_avps.has_value()) {
        return std::nullopt;
    }

    ChargingRuleRemove crr;

    for (const auto& sub_avp : grouped_avps.value()) {
        switch (sub_avp->code) {
            case static_cast<uint32_t>(GxAVPCode::CHARGING_RULE_NAME):
                crr.charging_rule_name.push_back(sub_avp->getDataAsString());
                break;
            case static_cast<uint32_t>(GxAVPCode::CHARGING_RULE_BASE_NAME):
                crr.charging_rule_base_name.push_back(sub_avp->getDataAsString());
                break;
        }
    }

    return crr;
}

std::optional<ChargingRuleDefinition> DiameterGxParser::parseChargingRuleDefinition(std::shared_ptr<DiameterAVP> avp) {
    auto grouped_avps = avp->getGroupedAVPs();
    if (!grouped_avps.has_value()) {
        return std::nullopt;
    }

    ChargingRuleDefinition crd;

    for (const auto& sub_avp : grouped_avps.value()) {
        switch (sub_avp->code) {
            case static_cast<uint32_t>(GxAVPCode::CHARGING_RULE_NAME):
                crd.charging_rule_name = sub_avp->getDataAsString();
                break;
            case static_cast<uint32_t>(GxAVPCode::SERVICE_IDENTIFIER):
                crd.service_identifier = sub_avp->getDataAsUint32();
                break;
            case static_cast<uint32_t>(GxAVPCode::RATING_GROUP):
                crd.rating_group = sub_avp->getDataAsUint32();
                break;
            case static_cast<uint32_t>(GxAVPCode::FLOW_INFORMATION): {
                auto flow_info = parseFlowInformation(sub_avp);
                if (flow_info.has_value()) {
                    crd.flow_information.push_back(flow_info.value());
                }
                break;
            }
            case static_cast<uint32_t>(GxAVPCode::QOS_INFORMATION):
                crd.qos_information = parseQoSInformation(sub_avp);
                break;
            case static_cast<uint32_t>(GxAVPCode::PRECEDENCE):
                crd.precedence = sub_avp->getDataAsUint32();
                break;
            case static_cast<uint32_t>(GxAVPCode::FLOW_STATUS): {
                auto flow_status_val = sub_avp->getDataAsUint32();
                if (flow_status_val.has_value()) {
                    crd.flow_status = static_cast<FlowStatus>(flow_status_val.value());
                }
                break;
            }
            case static_cast<uint32_t>(GxAVPCode::METERING_METHOD): {
                auto metering_val = sub_avp->getDataAsUint32();
                if (metering_val.has_value()) {
                    crd.metering_method = static_cast<MeteringMethod>(metering_val.value());
                }
                break;
            }
            case static_cast<uint32_t>(GxAVPCode::REPORTING_LEVEL): {
                auto reporting_val = sub_avp->getDataAsUint32();
                if (reporting_val.has_value()) {
                    crd.reporting_level = static_cast<ReportingLevel>(reporting_val.value());
                }
                break;
            }
            case static_cast<uint32_t>(GxAVPCode::ONLINE):
                crd.online = sub_avp->getDataAsUint32();
                break;
            case static_cast<uint32_t>(GxAVPCode::OFFLINE):
                crd.offline = sub_avp->getDataAsUint32();
                break;
        }
    }

    return crd;
}

std::optional<QoSInformation> DiameterGxParser::parseQoSInformation(std::shared_ptr<DiameterAVP> avp) {
    auto grouped_avps = avp->getGroupedAVPs();
    if (!grouped_avps.has_value()) {
        return std::nullopt;
    }

    QoSInformation qos;

    for (const auto& sub_avp : grouped_avps.value()) {
        switch (sub_avp->code) {
            case static_cast<uint32_t>(GxAVPCode::QOS_CLASS_IDENTIFIER):
                qos.qos_class_identifier = sub_avp->getDataAsUint32();
                break;
            case static_cast<uint32_t>(GxAVPCode::MAX_REQUESTED_BANDWIDTH_UL):
                qos.max_requested_bandwidth_ul = sub_avp->getDataAsUint32();
                break;
            case static_cast<uint32_t>(GxAVPCode::MAX_REQUESTED_BANDWIDTH_DL):
                qos.max_requested_bandwidth_dl = sub_avp->getDataAsUint32();
                break;
            case static_cast<uint32_t>(GxAVPCode::GUARANTEED_BITRATE_UL):
                qos.guaranteed_bitrate_ul = sub_avp->getDataAsUint32();
                break;
            case static_cast<uint32_t>(GxAVPCode::GUARANTEED_BITRATE_DL):
                qos.guaranteed_bitrate_dl = sub_avp->getDataAsUint32();
                break;
            case static_cast<uint32_t>(GxAVPCode::BEARER_IDENTIFIER):
                qos.bearer_identifier = sub_avp->getDataAsUint32();
                break;
            case static_cast<uint32_t>(GxAVPCode::ALLOCATION_RETENTION_PRIORITY):
                qos.allocation_retention_priority = parseAllocationRetentionPriority(sub_avp);
                break;
        }
    }

    return qos;
}

std::optional<DefaultEPSBearerQoS> DiameterGxParser::parseDefaultEPSBearerQoS(std::shared_ptr<DiameterAVP> avp) {
    auto grouped_avps = avp->getGroupedAVPs();
    if (!grouped_avps.has_value()) {
        return std::nullopt;
    }

    DefaultEPSBearerQoS qos;
    std::optional<AllocationRetentionPriority> arp;

    for (const auto& sub_avp : grouped_avps.value()) {
        switch (sub_avp->code) {
            case static_cast<uint32_t>(GxAVPCode::QOS_CLASS_IDENTIFIER): {
                auto qci_val = sub_avp->getDataAsUint32();
                if (qci_val.has_value()) {
                    qos.qos_class_identifier = qci_val.value();
                }
                break;
            }
            case static_cast<uint32_t>(GxAVPCode::ALLOCATION_RETENTION_PRIORITY):
                arp = parseAllocationRetentionPriority(sub_avp);
                break;
        }
    }

    if (!arp.has_value()) {
        return std::nullopt;
    }

    qos.allocation_retention_priority = arp.value();
    return qos;
}

std::optional<AllocationRetentionPriority> DiameterGxParser::parseAllocationRetentionPriority(std::shared_ptr<DiameterAVP> avp) {
    auto grouped_avps = avp->getGroupedAVPs();
    if (!grouped_avps.has_value()) {
        return std::nullopt;
    }

    AllocationRetentionPriority arp;
    arp.priority_level = 15;  // Default
    arp.pre_emption_capability = PreemptionCapability::PRE_EMPTION_CAPABILITY_DISABLED;
    arp.pre_emption_vulnerability = PreemptionVulnerability::PRE_EMPTION_VULNERABILITY_ENABLED;

    for (const auto& sub_avp : grouped_avps.value()) {
        switch (sub_avp->code) {
            case static_cast<uint32_t>(GxAVPCode::PRIORITY_LEVEL): {
                auto priority_val = sub_avp->getDataAsUint32();
                if (priority_val.has_value()) {
                    arp.priority_level = priority_val.value();
                }
                break;
            }
            case static_cast<uint32_t>(GxAVPCode::PRE_EMPTION_CAPABILITY): {
                auto cap_val = sub_avp->getDataAsUint32();
                if (cap_val.has_value()) {
                    arp.pre_emption_capability = static_cast<PreemptionCapability>(cap_val.value());
                }
                break;
            }
            case static_cast<uint32_t>(GxAVPCode::PRE_EMPTION_VULNERABILITY): {
                auto vuln_val = sub_avp->getDataAsUint32();
                if (vuln_val.has_value()) {
                    arp.pre_emption_vulnerability = static_cast<PreemptionVulnerability>(vuln_val.value());
                }
                break;
            }
        }
    }

    return arp;
}

std::optional<FlowInformation> DiameterGxParser::parseFlowInformation(std::shared_ptr<DiameterAVP> avp) {
    auto grouped_avps = avp->getGroupedAVPs();
    if (!grouped_avps.has_value()) {
        return std::nullopt;
    }

    FlowInformation flow;
    flow.flow_direction = FlowDirection::UNSPECIFIED;

    for (const auto& sub_avp : grouped_avps.value()) {
        switch (sub_avp->code) {
            case static_cast<uint32_t>(GxAVPCode::FLOW_DESCRIPTION):
                flow.flow_description = sub_avp->getDataAsString();
                break;
            case static_cast<uint32_t>(GxAVPCode::TOS_TRAFFIC_CLASS):
                flow.tos_traffic_class = sub_avp->getDataAsUint32();
                break;
        }
    }

    return flow;
}

std::optional<UsageMonitoringInformation> DiameterGxParser::parseUsageMonitoringInformation(std::shared_ptr<DiameterAVP> avp) {
    auto grouped_avps = avp->getGroupedAVPs();
    if (!grouped_avps.has_value()) {
        return std::nullopt;
    }

    UsageMonitoringInformation umi;

    for (const auto& sub_avp : grouped_avps.value()) {
        switch (sub_avp->code) {
            case static_cast<uint32_t>(GxAVPCode::MONITORING_KEY):
                umi.monitoring_key = sub_avp->data;
                break;
            case static_cast<uint32_t>(GxAVPCode::GRANTED_SERVICE_UNIT):
                umi.granted_service_unit = parseServiceUnit(sub_avp);
                break;
            case static_cast<uint32_t>(GxAVPCode::USED_SERVICE_UNIT):
                umi.used_service_unit = parseUsedServiceUnit(sub_avp);
                break;
        }
    }

    return umi;
}

std::optional<ServiceUnit> DiameterGxParser::parseServiceUnit(std::shared_ptr<DiameterAVP> avp) {
    auto grouped_avps = avp->getGroupedAVPs();
    if (!grouped_avps.has_value()) {
        return std::nullopt;
    }

    ServiceUnit su;

    for (const auto& sub_avp : grouped_avps.value()) {
        switch (sub_avp->code) {
            case 420:  // CC-Time
                su.cc_time = sub_avp->getDataAsUint32();
                break;
            case 421:  // CC-Total-Octets
                su.cc_total_octets = sub_avp->getDataAsUint64();
                break;
            case 412:  // CC-Input-Octets
                su.cc_input_octets = sub_avp->getDataAsUint64();
                break;
            case 414:  // CC-Output-Octets
                su.cc_output_octets = sub_avp->getDataAsUint64();
                break;
            case 417:  // CC-Service-Specific-Units
                su.cc_service_specific_units = sub_avp->getDataAsUint32();
                break;
        }
    }

    return su;
}

std::optional<UsedServiceUnit> DiameterGxParser::parseUsedServiceUnit(std::shared_ptr<DiameterAVP> avp) {
    auto grouped_avps = avp->getGroupedAVPs();
    if (!grouped_avps.has_value()) {
        return std::nullopt;
    }

    UsedServiceUnit usu;

    for (const auto& sub_avp : grouped_avps.value()) {
        switch (sub_avp->code) {
            case 420:  // CC-Time
                usu.cc_time = sub_avp->getDataAsUint32();
                break;
            case 421:  // CC-Total-Octets
                usu.cc_total_octets = sub_avp->getDataAsUint64();
                break;
            case 412:  // CC-Input-Octets
                usu.cc_input_octets = sub_avp->getDataAsUint64();
                break;
            case 414:  // CC-Output-Octets
                usu.cc_output_octets = sub_avp->getDataAsUint64();
                break;
            case 417:  // CC-Service-Specific-Units
                usu.cc_service_specific_units = sub_avp->getDataAsUint32();
                break;
        }
    }

    return usu;
}

std::optional<PCCRuleStatusReport> DiameterGxParser::parsePCCRuleStatusReport(std::shared_ptr<DiameterAVP> avp) {
    auto grouped_avps = avp->getGroupedAVPs();
    if (!grouped_avps.has_value()) {
        return std::nullopt;
    }

    PCCRuleStatusReport report;
    report.pcc_rule_status = PCCRuleStatus::ACTIVE;

    for (const auto& sub_avp : grouped_avps.value()) {
        switch (sub_avp->code) {
            case static_cast<uint32_t>(GxAVPCode::CHARGING_RULE_NAME):
                report.rule_names.push_back(sub_avp->getDataAsString());
                break;
            case static_cast<uint32_t>(GxAVPCode::PCC_RULE_STATUS): {
                auto status_val = sub_avp->getDataAsUint32();
                if (status_val.has_value()) {
                    report.pcc_rule_status = static_cast<PCCRuleStatus>(status_val.value());
                }
                break;
            }
            case static_cast<uint32_t>(GxAVPCode::RULE_FAILURE_CODE): {
                auto failure_val = sub_avp->getDataAsUint32();
                if (failure_val.has_value()) {
                    report.rule_failure_code = static_cast<RuleFailureCode>(failure_val.value());
                }
                break;
            }
        }
    }

    return report;
}

std::vector<EventTrigger> DiameterGxParser::parseEventTriggers(const DiameterMessage& msg) {
    std::vector<EventTrigger> triggers;

    auto trigger_avps = msg.findAllAVPs(static_cast<uint32_t>(GxAVPCode::EVENT_TRIGGER));
    for (const auto& avp : trigger_avps) {
        auto trigger_val = avp->getDataAsUint32();
        if (trigger_val.has_value()) {
            triggers.push_back(static_cast<EventTrigger>(trigger_val.value()));
        }
    }

    return triggers;
}

}  // namespace diameter
}  // namespace callflow
