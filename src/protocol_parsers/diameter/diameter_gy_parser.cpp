#include <arpa/inet.h>

#include "common/logger.h"
#include "protocol_parsers/diameter/diameter_avp_parser.h"
#include "protocol_parsers/diameter/diameter_gy.h"

namespace callflow {
namespace diameter {

// ============================================================================
// Structure toJson() Methods
// ============================================================================

nlohmann::json MultipleServicesCreditControl::toJson() const {
    nlohmann::json j;

    if (granted_service_unit.has_value()) {
        j["granted_service_unit"] = granted_service_unit->toJson();
    }
    if (requested_service_unit.has_value()) {
        j["requested_service_unit"] = requested_service_unit->toJson();
    }
    if (used_service_unit.has_value()) {
        j["used_service_unit"] = used_service_unit->toJson();
    }
    if (rating_group.has_value()) {
        j["rating_group"] = rating_group.value();
    }
    if (service_identifier.has_value()) {
        j["service_identifier"] = service_identifier.value();
    }
    if (validity_time.has_value()) {
        j["validity_time"] = validity_time.value();
    }
    if (result_code.has_value()) {
        j["result_code"] = result_code.value();
    }
    if (final_unit_indication.has_value()) {
        j["final_unit_indication"] = final_unit_indication->toJson();
    }
    if (reporting_reason.has_value()) {
        j["reporting_reason"] = static_cast<uint32_t>(reporting_reason.value());
    }
    if (!triggers.empty()) {
        nlohmann::json trigger_arr = nlohmann::json::array();
        for (const auto& trigger : triggers) {
            trigger_arr.push_back(static_cast<uint32_t>(trigger));
        }
        j["triggers"] = trigger_arr;
    }

    return j;
}

nlohmann::json CostInformation::toJson() const {
    nlohmann::json j;
    j["unit_value"] = unit_value;
    j["currency_code"] = currency_code;
    if (cost_unit.has_value()) {
        j["cost_unit"] = cost_unit.value();
    }
    return j;
}

nlohmann::json PSInformation::toJson() const {
    nlohmann::json j;

    if (tgpp_charging_id.has_value()) {
        j["3gpp_charging_id"] = tgpp_charging_id.value();
    }
    if (tgpp_pdp_type.has_value()) {
        j["3gpp_pdp_type"] = tgpp_pdp_type.value();
    }
    if (tgpp_sgsn_address.has_value()) {
        j["3gpp_sgsn_address"] = tgpp_sgsn_address.value();
    }
    if (tgpp_ggsn_address.has_value()) {
        j["3gpp_ggsn_address"] = tgpp_ggsn_address.value();
    }
    if (called_station_id.has_value()) {
        j["called_station_id"] = called_station_id.value();
    }
    if (tgpp_nsapi.has_value()) {
        j["3gpp_nsapi"] = tgpp_nsapi.value();
    }
    if (tgpp_selection_mode.has_value()) {
        j["3gpp_selection_mode"] = tgpp_selection_mode.value();
    }
    if (tgpp_charging_characteristics.has_value()) {
        j["3gpp_charging_characteristics"] = tgpp_charging_characteristics.value();
    }
    if (tgpp_rat_type.has_value()) {
        j["3gpp_rat_type"] = tgpp_rat_type.value();
    }
    if (tgpp_user_location_info.has_value()) {
        j["3gpp_user_location_info"] = nlohmann::json(tgpp_user_location_info.value());
    }

    return j;
}

nlohmann::json IMSInformation::toJson() const {
    nlohmann::json j;

    if (calling_party_address.has_value()) {
        j["calling_party_address"] = calling_party_address.value();
    }
    if (called_party_address.has_value()) {
        j["called_party_address"] = called_party_address.value();
    }
    if (event_type.has_value()) {
        j["event_type"] = event_type.value();
    }
    if (role_of_node.has_value()) {
        j["role_of_node"] = role_of_node.value();
    }
    if (node_functionality.has_value()) {
        j["node_functionality"] = node_functionality.value();
    }

    return j;
}

nlohmann::json ServiceInformation::toJson() const {
    nlohmann::json j;

    if (ps_information.has_value()) {
        j["ps_information"] = ps_information->toJson();
    }
    if (ims_information.has_value()) {
        j["ims_information"] = ims_information->toJson();
    }

    return j;
}

nlohmann::json GyCreditControlRequest::toJson() const {
    nlohmann::json j;
    j["cc_request_type"] = getCCRequestTypeName(cc_request_type);
    j["cc_request_number"] = cc_request_number;

    if (service_context_id.has_value()) {
        j["service_context_id"] = service_context_id.value();
    }

    if (!subscription_ids.empty()) {
        nlohmann::json subs = nlohmann::json::array();
        for (const auto& sub_id : subscription_ids) {
            subs.push_back(sub_id.toJson());
        }
        j["subscription_ids"] = subs;
    }

    if (!mscc.empty()) {
        nlohmann::json mscc_arr = nlohmann::json::array();
        for (const auto& m : mscc) {
            mscc_arr.push_back(m.toJson());
        }
        j["mscc"] = mscc_arr;
    }

    if (user_equipment_info.has_value()) {
        j["user_equipment_info"] = user_equipment_info->toJson();
    }
    if (service_information.has_value()) {
        j["service_information"] = service_information->toJson();
    }

    return j;
}

nlohmann::json GyCreditControlAnswer::toJson() const {
    nlohmann::json j;
    j["result_code"] = result_code;
    j["cc_request_type"] = getCCRequestTypeName(cc_request_type);
    j["cc_request_number"] = cc_request_number;

    if (!mscc.empty()) {
        nlohmann::json mscc_arr = nlohmann::json::array();
        for (const auto& m : mscc) {
            mscc_arr.push_back(m.toJson());
        }
        j["mscc"] = mscc_arr;
    }

    if (cost_information.has_value()) {
        j["cost_information"] = cost_information->toJson();
    }
    if (cc_session_failover.has_value()) {
        j["cc_session_failover"] = cc_session_failover.value();
    }

    return j;
}

nlohmann::json DiameterGyMessage::toJson() const {
    nlohmann::json j = base.toJson();
    j["interface"] = "Gy";

    if (ccr.has_value()) {
        j["ccr"] = ccr->toJson();
    }
    if (cca.has_value()) {
        j["cca"] = cca->toJson();
    }

    if (cc_request_type.has_value()) {
        j["cc_request_type"] = getCCRequestTypeName(cc_request_type.value());
    }
    if (called_station_id.has_value()) {
        j["called_station_id"] = called_station_id.value();
    }

    return j;
}

// ============================================================================
// DiameterGyParser Implementation
// ============================================================================

bool DiameterGyParser::isGyMessage(const DiameterMessage& msg) {
    // Gy uses DCCA (application ID 4) with credit control command
    return (msg.header.application_id == DIAMETER_GY_APPLICATION_ID ||
            (msg.acct_application_id.has_value() &&
             msg.acct_application_id.value() == DIAMETER_GY_APPLICATION_ID)) &&
           msg.header.command_code == static_cast<uint32_t>(DiameterCommandCode::CREDIT_CONTROL);
}

std::optional<DiameterGyMessage> DiameterGyParser::parse(const DiameterMessage& msg) {
    if (!isGyMessage(msg)) {
        return std::nullopt;
    }

    DiameterGyMessage gy_msg;
    gy_msg.base = msg;

    // Extract common fields
    auto called_station_avp = msg.findAVP(static_cast<uint32_t>(GyAVPCode::CALLED_STATION_ID));
    if (called_station_avp) {
        gy_msg.called_station_id = called_station_avp->getDataAsString();
    }

    // Parse based on message direction
    if (msg.isRequest()) {
        gy_msg.ccr = parseCCR(msg);
        if (gy_msg.ccr.has_value()) {
            gy_msg.cc_request_type = gy_msg.ccr->cc_request_type;
        }
    } else {
        gy_msg.cca = parseCCA(msg);
        if (gy_msg.cca.has_value()) {
            gy_msg.cc_request_type = gy_msg.cca->cc_request_type;
        }
    }

    return gy_msg;
}

GyCreditControlRequest DiameterGyParser::parseCCR(const DiameterMessage& msg) {
    GyCreditControlRequest ccr;

    // CC-Request-Type and CC-Request-Number
    auto cc_type_avp = msg.findAVP(static_cast<uint32_t>(GyAVPCode::CC_REQUEST_TYPE));
    if (cc_type_avp) {
        auto type_val = cc_type_avp->getDataAsUint32();
        if (type_val.has_value()) {
            ccr.cc_request_type = static_cast<CCRequestType>(type_val.value());
        }
    }

    auto cc_num_avp = msg.findAVP(static_cast<uint32_t>(GyAVPCode::CC_REQUEST_NUMBER));
    if (cc_num_avp) {
        auto num_val = cc_num_avp->getDataAsUint32();
        if (num_val.has_value()) {
            ccr.cc_request_number = num_val.value();
        }
    }

    // Service context
    auto service_ctx_avp = msg.findAVP(static_cast<uint32_t>(GyAVPCode::SERVICE_CONTEXT_ID));
    if (service_ctx_avp) {
        ccr.service_context_id = service_ctx_avp->getDataAsString();
    }

    // Subscription IDs
    auto sub_id_avps = msg.findAllAVPs(static_cast<uint32_t>(GyAVPCode::SUBSCRIPTION_ID));
    for (const auto& avp : sub_id_avps) {
        auto sub_id = parseSubscriptionId(avp);
        if (sub_id.has_value()) {
            ccr.subscription_ids.push_back(sub_id.value());
        }
    }

    // Multiple Services Credit Control
    auto mscc_avps =
        msg.findAllAVPs(static_cast<uint32_t>(GyAVPCode::MULTIPLE_SERVICES_CREDIT_CONTROL));
    for (const auto& avp : mscc_avps) {
        auto mscc = parseMSCC(avp);
        if (mscc.has_value()) {
            ccr.mscc.push_back(mscc.value());
        }
    }

    // User equipment info
    auto ue_info_avp = msg.findAVP(static_cast<uint32_t>(GyAVPCode::USER_EQUIPMENT_INFO));
    if (ue_info_avp) {
        ccr.user_equipment_info = parseUserEquipmentInfo(ue_info_avp);
    }

    // Service information
    auto service_info_avp =
        msg.findAVP(static_cast<uint32_t>(GyAVPCode::SERVICE_INFORMATION), DIAMETER_VENDOR_3GPP);
    if (service_info_avp) {
        ccr.service_information = parseServiceInformation(service_info_avp);
    }

    // Event timestamp
    auto timestamp_avp = msg.findAVP(static_cast<uint32_t>(GyAVPCode::EVENT_TIMESTAMP));
    if (timestamp_avp) {
        ccr.event_timestamp = DiameterAVPParser::parseTime(timestamp_avp->data);
    }

    return ccr;
}

GyCreditControlAnswer DiameterGyParser::parseCCA(const DiameterMessage& msg) {
    GyCreditControlAnswer cca;

    // Result code
    if (msg.result_code.has_value()) {
        cca.result_code = msg.result_code.value();
    }

    // CC-Request-Type and CC-Request-Number
    auto cc_type_avp = msg.findAVP(static_cast<uint32_t>(GyAVPCode::CC_REQUEST_TYPE));
    if (cc_type_avp) {
        auto type_val = cc_type_avp->getDataAsUint32();
        if (type_val.has_value()) {
            cca.cc_request_type = static_cast<CCRequestType>(type_val.value());
        }
    }

    auto cc_num_avp = msg.findAVP(static_cast<uint32_t>(GyAVPCode::CC_REQUEST_NUMBER));
    if (cc_num_avp) {
        auto num_val = cc_num_avp->getDataAsUint32();
        if (num_val.has_value()) {
            cca.cc_request_number = num_val.value();
        }
    }

    // Multiple Services Credit Control
    auto mscc_avps =
        msg.findAllAVPs(static_cast<uint32_t>(GyAVPCode::MULTIPLE_SERVICES_CREDIT_CONTROL));
    for (const auto& avp : mscc_avps) {
        auto mscc = parseMSCC(avp);
        if (mscc.has_value()) {
            cca.mscc.push_back(mscc.value());
        }
    }

    // Cost information
    auto cost_avp = msg.findAVP(static_cast<uint32_t>(GyAVPCode::COST_INFORMATION));
    if (cost_avp) {
        cca.cost_information = parseCostInformation(cost_avp);
    }

    // CC session failover
    auto failover_avp = msg.findAVP(static_cast<uint32_t>(GyAVPCode::CC_SESSION_FAILOVER));
    if (failover_avp) {
        cca.cc_session_failover = failover_avp->getDataAsUint32();
    }

    return cca;
}

// ============================================================================
// AVP Parsers
// ============================================================================

std::optional<MultipleServicesCreditControl> DiameterGyParser::parseMSCC(
    std::shared_ptr<DiameterAVP> avp) {
    auto grouped_avps = avp->getGroupedAVPs();
    if (!grouped_avps.has_value()) {
        return std::nullopt;
    }

    MultipleServicesCreditControl mscc;

    for (const auto& sub_avp : grouped_avps.value()) {
        switch (sub_avp->code) {
            case static_cast<uint32_t>(GyAVPCode::GRANTED_SERVICE_UNIT):
                mscc.granted_service_unit = parseServiceUnit(sub_avp);
                break;
            case static_cast<uint32_t>(GyAVPCode::REQUESTED_SERVICE_UNIT):
                mscc.requested_service_unit = parseServiceUnit(sub_avp);
                break;
            case static_cast<uint32_t>(GyAVPCode::USED_SERVICE_UNIT):
                mscc.used_service_unit = parseUsedServiceUnit(sub_avp);
                break;
            case static_cast<uint32_t>(GyAVPCode::RATING_GROUP):
                mscc.rating_group = sub_avp->getDataAsUint32();
                break;
            case static_cast<uint32_t>(GyAVPCode::SERVICE_IDENTIFIER):
                mscc.service_identifier = sub_avp->getDataAsUint32();
                break;
            case static_cast<uint32_t>(GyAVPCode::VALIDITY_TIME):
                mscc.validity_time = sub_avp->getDataAsUint32();
                break;
            case static_cast<uint32_t>(GyAVPCode::RESULT_CODE):
                mscc.result_code = sub_avp->getDataAsUint32();
                break;
            case static_cast<uint32_t>(GyAVPCode::FINAL_UNIT_INDICATION):
                mscc.final_unit_indication = parseFinalUnitIndication(sub_avp);
                break;
            case static_cast<uint32_t>(GyAVPCode::REPORTING_REASON): {
                auto reason_val = sub_avp->getDataAsUint32();
                if (reason_val.has_value()) {
                    mscc.reporting_reason = static_cast<ReportingReason>(reason_val.value());
                }
                break;
            }
            case static_cast<uint32_t>(GyAVPCode::TRIGGER_TYPE): {
                auto trigger_val = sub_avp->getDataAsUint32();
                if (trigger_val.has_value()) {
                    mscc.triggers.push_back(static_cast<TriggerType>(trigger_val.value()));
                }
                break;
            }
        }
    }

    return mscc;
}

std::optional<SubscriptionId> DiameterGyParser::parseSubscriptionId(
    std::shared_ptr<DiameterAVP> avp) {
    auto grouped_avps = avp->getGroupedAVPs();
    if (!grouped_avps.has_value()) {
        return std::nullopt;
    }

    SubscriptionId sub_id;
    sub_id.subscription_id_type = SubscriptionIdType::END_USER_E164;

    for (const auto& sub_avp : grouped_avps.value()) {
        switch (sub_avp->code) {
            case static_cast<uint32_t>(GyAVPCode::SUBSCRIPTION_ID_TYPE): {
                auto type_val = sub_avp->getDataAsUint32();
                if (type_val.has_value()) {
                    sub_id.subscription_id_type = static_cast<SubscriptionIdType>(type_val.value());
                }
                break;
            }
            case static_cast<uint32_t>(GyAVPCode::SUBSCRIPTION_ID_DATA):
                sub_id.subscription_id_data = sub_avp->getDataAsString();
                break;
        }
    }

    return sub_id;
}

std::optional<ServiceUnit> DiameterGyParser::parseServiceUnit(std::shared_ptr<DiameterAVP> avp) {
    auto grouped_avps = avp->getGroupedAVPs();
    if (!grouped_avps.has_value()) {
        return std::nullopt;
    }

    ServiceUnit su;

    for (const auto& sub_avp : grouped_avps.value()) {
        switch (sub_avp->code) {
            case static_cast<uint32_t>(GyAVPCode::CC_TIME):
                su.cc_time = sub_avp->getDataAsUint32();
                break;
            case static_cast<uint32_t>(GyAVPCode::CC_TOTAL_OCTETS):
                su.cc_total_octets = sub_avp->getDataAsUint64();
                break;
            case static_cast<uint32_t>(GyAVPCode::CC_INPUT_OCTETS):
                su.cc_input_octets = sub_avp->getDataAsUint64();
                break;
            case static_cast<uint32_t>(GyAVPCode::CC_OUTPUT_OCTETS):
                su.cc_output_octets = sub_avp->getDataAsUint64();
                break;
            case static_cast<uint32_t>(GyAVPCode::CC_SERVICE_SPECIFIC_UNITS):
                su.cc_service_specific_units = sub_avp->getDataAsUint32();
                break;
        }
    }

    return su;
}

std::optional<UsedServiceUnit> DiameterGyParser::parseUsedServiceUnit(
    std::shared_ptr<DiameterAVP> avp) {
    auto grouped_avps = avp->getGroupedAVPs();
    if (!grouped_avps.has_value()) {
        return std::nullopt;
    }

    UsedServiceUnit usu;

    for (const auto& sub_avp : grouped_avps.value()) {
        switch (sub_avp->code) {
            case static_cast<uint32_t>(GyAVPCode::CC_TIME):
                usu.cc_time = sub_avp->getDataAsUint32();
                break;
            case static_cast<uint32_t>(GyAVPCode::CC_TOTAL_OCTETS):
                usu.cc_total_octets = sub_avp->getDataAsUint64();
                break;
            case static_cast<uint32_t>(GyAVPCode::CC_INPUT_OCTETS):
                usu.cc_input_octets = sub_avp->getDataAsUint64();
                break;
            case static_cast<uint32_t>(GyAVPCode::CC_OUTPUT_OCTETS):
                usu.cc_output_octets = sub_avp->getDataAsUint64();
                break;
            case static_cast<uint32_t>(GyAVPCode::CC_SERVICE_SPECIFIC_UNITS):
                usu.cc_service_specific_units = sub_avp->getDataAsUint32();
                break;
            case static_cast<uint32_t>(GyAVPCode::TARIFF_CHANGE_USAGE): {
                auto tariff_val = sub_avp->getDataAsUint32();
                if (tariff_val.has_value()) {
                    usu.tariff_change_usage = static_cast<TariffChangeUsage>(tariff_val.value());
                }
                break;
            }
            case static_cast<uint32_t>(GyAVPCode::REPORTING_REASON):
                usu.reporting_reason = sub_avp->getDataAsUint32();
                break;
        }
    }

    return usu;
}

std::optional<FinalUnitIndication> DiameterGyParser::parseFinalUnitIndication(
    std::shared_ptr<DiameterAVP> avp) {
    auto grouped_avps = avp->getGroupedAVPs();
    if (!grouped_avps.has_value()) {
        return std::nullopt;
    }

    FinalUnitIndication fui;
    fui.final_unit_action = FinalUnitAction::TERMINATE;

    for (const auto& sub_avp : grouped_avps.value()) {
        switch (sub_avp->code) {
            case static_cast<uint32_t>(GyAVPCode::FINAL_UNIT_ACTION): {
                auto action_val = sub_avp->getDataAsUint32();
                if (action_val.has_value()) {
                    fui.final_unit_action = static_cast<FinalUnitAction>(action_val.value());
                }
                break;
            }
            case static_cast<uint32_t>(GyAVPCode::RESTRICTION_FILTER_RULE):
                fui.restriction_filter_rule.push_back(sub_avp->getDataAsString());
                break;
            case static_cast<uint32_t>(GyAVPCode::FILTER_ID):
                fui.filter_id.push_back(sub_avp->getDataAsString());
                break;
            case static_cast<uint32_t>(GyAVPCode::REDIRECT_SERVER):
                fui.redirect_server = parseRedirectServer(sub_avp);
                break;
        }
    }

    return fui;
}

std::optional<RedirectServer> DiameterGyParser::parseRedirectServer(
    std::shared_ptr<DiameterAVP> avp) {
    auto grouped_avps = avp->getGroupedAVPs();
    if (!grouped_avps.has_value()) {
        return std::nullopt;
    }

    RedirectServer rs;
    rs.redirect_address_type = RedirectAddressType::IPv4_ADDRESS;

    for (const auto& sub_avp : grouped_avps.value()) {
        switch (sub_avp->code) {
            case static_cast<uint32_t>(GyAVPCode::REDIRECT_ADDRESS_TYPE): {
                auto type_val = sub_avp->getDataAsUint32();
                if (type_val.has_value()) {
                    rs.redirect_address_type = static_cast<RedirectAddressType>(type_val.value());
                }
                break;
            }
            case static_cast<uint32_t>(GyAVPCode::REDIRECT_SERVER_ADDRESS):
                rs.redirect_server_address = sub_avp->getDataAsString();
                break;
        }
    }

    return rs;
}

std::optional<UserEquipmentInfo> DiameterGyParser::parseUserEquipmentInfo(
    std::shared_ptr<DiameterAVP> avp) {
    auto grouped_avps = avp->getGroupedAVPs();
    if (!grouped_avps.has_value()) {
        return std::nullopt;
    }

    UserEquipmentInfo uei;
    uei.user_equipment_info_type = UserEquipmentInfoType::IMEISV;

    for (const auto& sub_avp : grouped_avps.value()) {
        switch (sub_avp->code) {
            case static_cast<uint32_t>(GyAVPCode::USER_EQUIPMENT_INFO_TYPE): {
                auto type_val = sub_avp->getDataAsUint32();
                if (type_val.has_value()) {
                    uei.user_equipment_info_type =
                        static_cast<UserEquipmentInfoType>(type_val.value());
                }
                break;
            }
            case static_cast<uint32_t>(GyAVPCode::USER_EQUIPMENT_INFO_VALUE):
                uei.user_equipment_info_value = sub_avp->getDataAsString();
                break;
        }
    }

    return uei;
}

std::optional<ServiceInformation> DiameterGyParser::parseServiceInformation(
    std::shared_ptr<DiameterAVP> avp) {
    auto grouped_avps = avp->getGroupedAVPs();
    if (!grouped_avps.has_value()) {
        return std::nullopt;
    }

    ServiceInformation si;

    for (const auto& sub_avp : grouped_avps.value()) {
        switch (sub_avp->code) {
            case static_cast<uint32_t>(GyAVPCode::PS_INFORMATION):
                si.ps_information = parsePSInformation(sub_avp);
                break;
            case static_cast<uint32_t>(GyAVPCode::IMS_INFORMATION):
                si.ims_information = parseIMSInformation(sub_avp);
                break;
        }
    }

    return si;
}

std::optional<PSInformation> DiameterGyParser::parsePSInformation(
    std::shared_ptr<DiameterAVP> avp) {
    auto grouped_avps = avp->getGroupedAVPs();
    if (!grouped_avps.has_value()) {
        return std::nullopt;
    }

    PSInformation psi;

    for (const auto& sub_avp : grouped_avps.value()) {
        switch (sub_avp->code) {
            case static_cast<uint32_t>(GyAVPCode::TGPP_CHARGING_ID):
                psi.tgpp_charging_id = sub_avp->getDataAsUint32();
                break;
            case static_cast<uint32_t>(GyAVPCode::TGPP_PDP_TYPE):
                psi.tgpp_pdp_type = sub_avp->getDataAsUint32();
                break;
            case static_cast<uint32_t>(GyAVPCode::TGPP_SGSN_ADDRESS):
                psi.tgpp_sgsn_address = sub_avp->getDataAsString();
                break;
            case static_cast<uint32_t>(GyAVPCode::TGPP_GGSN_ADDRESS):
                psi.tgpp_ggsn_address = sub_avp->getDataAsString();
                break;
            case static_cast<uint32_t>(GyAVPCode::CALLED_STATION_ID):
                psi.called_station_id = sub_avp->getDataAsString();
                break;
            case static_cast<uint32_t>(GyAVPCode::TGPP_NSAPI):
                psi.tgpp_nsapi = sub_avp->getDataAsUint32();
                break;
            case static_cast<uint32_t>(GyAVPCode::TGPP_SELECTION_MODE):
                psi.tgpp_selection_mode = sub_avp->getDataAsString();
                break;
            case static_cast<uint32_t>(GyAVPCode::TGPP_CHARGING_CHARACTERISTICS):
                psi.tgpp_charging_characteristics = sub_avp->getDataAsString();
                break;
            case static_cast<uint32_t>(GyAVPCode::TGPP_RAT_TYPE):
                psi.tgpp_rat_type = sub_avp->getDataAsUint32();
                break;
            case static_cast<uint32_t>(GyAVPCode::TGPP_USER_LOCATION_INFO):
                psi.tgpp_user_location_info = sub_avp->data;
                break;
        }
    }

    return psi;
}

std::optional<IMSInformation> DiameterGyParser::parseIMSInformation(
    std::shared_ptr<DiameterAVP> avp) {
    auto grouped_avps = avp->getGroupedAVPs();
    if (!grouped_avps.has_value()) {
        return std::nullopt;
    }

    IMSInformation imsi;

    // Simplified parsing - would need vendor-specific AVP codes for full implementation
    for (const auto& sub_avp : grouped_avps.value()) {
        (void)sub_avp;
        // Parse vendor-specific AVPs here
        // This is a placeholder for IMS-specific information
    }

    return imsi;
}

std::optional<CostInformation> DiameterGyParser::parseCostInformation(
    std::shared_ptr<DiameterAVP> avp) {
    auto grouped_avps = avp->getGroupedAVPs();
    if (!grouped_avps.has_value()) {
        return std::nullopt;
    }

    CostInformation ci;
    ci.unit_value = 0;
    ci.currency_code = 0;

    for (const auto& sub_avp : grouped_avps.value()) {
        switch (sub_avp->code) {
            case static_cast<uint32_t>(GyAVPCode::UNIT_VALUE): {
                auto val = sub_avp->getDataAsUint32();
                if (val.has_value()) {
                    ci.unit_value = val.value();
                }
                break;
            }
            case static_cast<uint32_t>(GyAVPCode::CURRENCY_CODE): {
                auto val = sub_avp->getDataAsUint32();
                if (val.has_value()) {
                    ci.currency_code = val.value();
                }
                break;
            }
            case static_cast<uint32_t>(GyAVPCode::COST_UNIT):
                ci.cost_unit = sub_avp->getDataAsString();
                break;
        }
    }

    return ci;
}

}  // namespace diameter
}  // namespace callflow
