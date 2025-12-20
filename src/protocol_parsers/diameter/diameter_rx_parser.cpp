#include <arpa/inet.h>

#include "common/logger.h"
#include "protocol_parsers/diameter/diameter_avp_parser.h"
#include "protocol_parsers/diameter/diameter_rx.h"

namespace callflow {
namespace diameter {

// ============================================================================
// Structure toJson() Methods
// ============================================================================

nlohmann::json MediaSubComponent::toJson() const {
    nlohmann::json j;
    j["flow_number"] = flow_number;
    j["flow_descriptions"] = flow_descriptions;
    j["flow_usage"] = getFlowUsageName(flow_usage);

    if (flow_status.has_value()) {
        j["flow_status"] = getFlowStatusName(flow_status.value());
    }
    if (tos_traffic_class.has_value()) {
        j["tos_traffic_class"] = tos_traffic_class.value();
    }

    return j;
}

nlohmann::json MediaComponentDescription::toJson() const {
    nlohmann::json j;
    j["media_component_number"] = media_component_number;

    if (!media_sub_components.empty()) {
        nlohmann::json subs = nlohmann::json::array();
        for (const auto& sub : media_sub_components) {
            subs.push_back(sub.toJson());
        }
        j["media_sub_components"] = subs;
    }

    if (media_type.has_value()) {
        j["media_type"] = getMediaTypeName(media_type.value());
    }
    if (max_requested_bandwidth_dl.has_value()) {
        j["max_requested_bandwidth_dl"] = max_requested_bandwidth_dl.value();
    }
    if (max_requested_bandwidth_ul.has_value()) {
        j["max_requested_bandwidth_ul"] = max_requested_bandwidth_ul.value();
    }
    if (min_requested_bandwidth_dl.has_value()) {
        j["min_requested_bandwidth_dl"] = min_requested_bandwidth_dl.value();
    }
    if (min_requested_bandwidth_ul.has_value()) {
        j["min_requested_bandwidth_ul"] = min_requested_bandwidth_ul.value();
    }
    if (rr_bandwidth.has_value()) {
        j["rr_bandwidth"] = rr_bandwidth.value();
    }
    if (rs_bandwidth.has_value()) {
        j["rs_bandwidth"] = rs_bandwidth.value();
    }
    if (flow_status.has_value()) {
        j["flow_status"] = getFlowStatusName(flow_status.value());
    }
    if (codec_data.has_value()) {
        j["codec_data"] = codec_data.value();
    }
    if (sharing_key_dl.has_value()) {
        j["sharing_key_dl"] = sharing_key_dl.value();
    }
    if (sharing_key_ul.has_value()) {
        j["sharing_key_ul"] = sharing_key_ul.value();
    }
    if (content_version.has_value()) {
        j["content_version"] = content_version.value();
    }

    return j;
}

nlohmann::json AccessNetworkChargingIdentifier::toJson() const {
    nlohmann::json j;
    j["access_network_charging_identifier_value"] =
        nlohmann::json(access_network_charging_identifier_value);
    if (!flows.empty()) {
        j["flows"] = flows;
    }
    return j;
}

nlohmann::json SponsoredConnectivityData::toJson() const {
    nlohmann::json j;
    if (sponsor_identity.has_value()) {
        j["sponsor_identity"] = sponsor_identity.value();
    }
    if (application_service_provider_identity.has_value()) {
        j["application_service_provider_identity"] = application_service_provider_identity.value();
    }
    return j;
}

nlohmann::json RxAARequest::toJson() const {
    nlohmann::json j;

    if (framed_ip_address.has_value()) {
        j["framed_ip_address"] = framed_ip_address.value();
    }
    if (framed_ipv6_prefix.has_value()) {
        j["framed_ipv6_prefix"] = framed_ipv6_prefix.value();
    }

    if (!media_components.empty()) {
        nlohmann::json components = nlohmann::json::array();
        for (const auto& comp : media_components) {
            components.push_back(comp.toJson());
        }
        j["media_components"] = components;
    }

    if (af_application_identifier.has_value()) {
        j["af_application_identifier"] = af_application_identifier.value();
    }
    if (af_charging_identifier.has_value()) {
        j["af_charging_identifier"] = nlohmann::json(af_charging_identifier.value());
    }
    if (service_info_status.has_value()) {
        j["service_info_status"] = static_cast<uint32_t>(service_info_status.value());
    }
    if (service_urn.has_value()) {
        j["service_urn"] = service_urn.value();
    }

    if (!specific_actions.empty()) {
        nlohmann::json actions = nlohmann::json::array();
        for (const auto& action : specific_actions) {
            actions.push_back(static_cast<uint32_t>(action));
        }
        j["specific_actions"] = actions;
    }

    if (rx_request_type.has_value()) {
        j["rx_request_type"] = static_cast<uint32_t>(rx_request_type.value());
    }
    if (sponsored_connectivity_data.has_value()) {
        j["sponsored_connectivity_data"] = sponsored_connectivity_data->toJson();
    }

    return j;
}

nlohmann::json RxAAAnswer::toJson() const {
    nlohmann::json j;
    j["result_code"] = result_code;

    if (!media_components.empty()) {
        nlohmann::json components = nlohmann::json::array();
        for (const auto& comp : media_components) {
            components.push_back(comp.toJson());
        }
        j["media_components"] = components;
    }

    if (service_authorization_info.has_value()) {
        j["service_authorization_info"] = service_authorization_info.value();
    }
    if (ip_can_type.has_value()) {
        j["ip_can_type"] = getIPCANTypeName(ip_can_type.value());
    }
    if (acceptable_service_info.has_value()) {
        j["acceptable_service_info"] = acceptable_service_info.value();
    }

    return j;
}

nlohmann::json RxReAuthRequest::toJson() const {
    nlohmann::json j;
    j["re_auth_request_type"] = re_auth_request_type;

    if (!specific_actions.empty()) {
        nlohmann::json actions = nlohmann::json::array();
        for (const auto& action : specific_actions) {
            actions.push_back(static_cast<uint32_t>(action));
        }
        j["specific_actions"] = actions;
    }

    if (abort_cause.has_value()) {
        j["abort_cause"] = static_cast<uint32_t>(abort_cause.value());
    }

    return j;
}

nlohmann::json RxReAuthAnswer::toJson() const {
    nlohmann::json j;
    j["result_code"] = result_code;

    if (!media_components.empty()) {
        nlohmann::json components = nlohmann::json::array();
        for (const auto& comp : media_components) {
            components.push_back(comp.toJson());
        }
        j["media_components"] = components;
    }

    return j;
}

nlohmann::json RxSessionTerminationRequest::toJson() const {
    nlohmann::json j;
    j["termination_cause"] = termination_cause;
    return j;
}

nlohmann::json RxSessionTerminationAnswer::toJson() const {
    nlohmann::json j;
    j["result_code"] = result_code;
    return j;
}

nlohmann::json RxAbortSessionRequest::toJson() const {
    nlohmann::json j;
    if (abort_cause.has_value()) {
        j["abort_cause"] = static_cast<uint32_t>(abort_cause.value());
    }
    return j;
}

nlohmann::json RxAbortSessionAnswer::toJson() const {
    nlohmann::json j;
    j["result_code"] = result_code;
    return j;
}

nlohmann::json DiameterRxMessage::toJson() const {
    nlohmann::json j = base.toJson();
    j["interface"] = "Rx";

    if (aar.has_value()) {
        j["aar"] = aar->toJson();
    }
    if (aaa.has_value()) {
        j["aaa"] = aaa->toJson();
    }
    if (rar.has_value()) {
        j["rar"] = rar->toJson();
    }
    if (raa.has_value()) {
        j["raa"] = raa->toJson();
    }
    if (str.has_value()) {
        j["str"] = str->toJson();
    }
    if (sta.has_value()) {
        j["sta"] = sta->toJson();
    }
    if (asr.has_value()) {
        j["asr"] = asr->toJson();
    }
    if (asa.has_value()) {
        j["asa"] = asa->toJson();
    }

    if (framed_ip_address.has_value()) {
        j["framed_ip_address"] = framed_ip_address.value();
    }
    if (af_application_identifier.has_value()) {
        j["af_application_identifier"] = af_application_identifier.value();
    }

    return j;
}

// ============================================================================
// DiameterRxParser Implementation
// ============================================================================

bool DiameterRxParser::isRxMessage(const DiameterMessage& msg) {
    return msg.header.application_id == DIAMETER_RX_APPLICATION_ID ||
           (msg.auth_application_id.has_value() &&
            msg.auth_application_id.value() == DIAMETER_RX_APPLICATION_ID);
}

std::optional<DiameterRxMessage> DiameterRxParser::parse(const DiameterMessage& msg) {
    if (!isRxMessage(msg)) {
        return std::nullopt;
    }

    DiameterRxMessage rx_msg;
    rx_msg.base = msg;

    // Extract common fields
    auto framed_ip_avp = msg.findAVP(static_cast<uint32_t>(RxAVPCode::FRAMED_IP_ADDRESS));
    if (framed_ip_avp) {
        auto ip_str = DiameterAVPParser::parseIPAddress(framed_ip_avp->data);
        if (ip_str.has_value()) {
            rx_msg.framed_ip_address = ip_str.value();
        }
    }

    auto af_app_id_avp = msg.findAVP(static_cast<uint32_t>(RxAVPCode::AF_APPLICATION_IDENTIFIER));
    if (af_app_id_avp) {
        rx_msg.af_application_identifier = af_app_id_avp->getDataAsString();
    }

    // Parse based on command code
    switch (static_cast<DiameterCommandCode>(msg.header.command_code)) {
        case DiameterCommandCode::AA_REQUEST:
            if (msg.isRequest()) {
                rx_msg.aar = parseAAR(msg);
            } else {
                rx_msg.aaa = parseAAA(msg);
            }
            break;

        case DiameterCommandCode::RE_AUTH:
            if (msg.isRequest()) {
                rx_msg.rar = parseRAR(msg);
            } else {
                rx_msg.raa = parseRAA(msg);
            }
            break;

        case DiameterCommandCode::SESSION_TERMINATION:
            if (msg.isRequest()) {
                rx_msg.str = parseSTR(msg);
            } else {
                rx_msg.sta = parseSTA(msg);
            }
            break;

        case DiameterCommandCode::ABORT_SESSION:
            if (msg.isRequest()) {
                rx_msg.asr = parseASR(msg);
            } else {
                rx_msg.asa = parseASA(msg);
            }
            break;

        default:
            LOG_WARN("Unknown Rx command code: " + std::to_string(msg.header.command_code));
            break;
    }

    return rx_msg;
}

RxAARequest DiameterRxParser::parseAAR(const DiameterMessage& msg) {
    RxAARequest aar;

    // Framed IP addresses
    auto framed_ip_avp = msg.findAVP(static_cast<uint32_t>(RxAVPCode::FRAMED_IP_ADDRESS));
    if (framed_ip_avp) {
        auto ip_str = DiameterAVPParser::parseIPAddress(framed_ip_avp->data);
        if (ip_str.has_value()) {
            aar.framed_ip_address = ip_str.value();
        }
    }

    auto framed_ipv6_avp = msg.findAVP(static_cast<uint32_t>(RxAVPCode::FRAMED_IPV6_PREFIX));
    if (framed_ipv6_avp) {
        aar.framed_ipv6_prefix = framed_ipv6_avp->getDataAsString();
    }

    // Media components
    auto media_comp_avps =
        msg.findAllAVPs(static_cast<uint32_t>(RxAVPCode::MEDIA_COMPONENT_DESCRIPTION));
    for (const auto& avp : media_comp_avps) {
        auto media_comp = parseMediaComponentDescription(avp);
        if (media_comp.has_value()) {
            aar.media_components.push_back(media_comp.value());
        }
    }

    // AF application identifier
    auto af_app_id_avp = msg.findAVP(static_cast<uint32_t>(RxAVPCode::AF_APPLICATION_IDENTIFIER));
    if (af_app_id_avp) {
        aar.af_application_identifier = af_app_id_avp->getDataAsString();
    }

    // AF charging identifier
    auto af_charging_avp = msg.findAVP(static_cast<uint32_t>(RxAVPCode::AF_CHARGING_IDENTIFIER));
    if (af_charging_avp) {
        aar.af_charging_identifier = af_charging_avp->data;
    }

    // Service info
    auto service_info_avp = msg.findAVP(static_cast<uint32_t>(RxAVPCode::SERVICE_INFO_STATUS));
    if (service_info_avp) {
        auto status_val = service_info_avp->getDataAsUint32();
        if (status_val.has_value()) {
            aar.service_info_status = static_cast<ServiceInfoStatus>(status_val.value());
        }
    }

    auto service_urn_avp = msg.findAVP(static_cast<uint32_t>(RxAVPCode::SERVICE_URN));
    if (service_urn_avp) {
        aar.service_urn = service_urn_avp->getDataAsString();
    }

    // Specific actions
    aar.specific_actions = parseSpecificActions(msg);

    // Rx request type
    auto rx_req_type_avp = msg.findAVP(static_cast<uint32_t>(RxAVPCode::RX_REQUEST_TYPE));
    if (rx_req_type_avp) {
        auto type_val = rx_req_type_avp->getDataAsUint32();
        if (type_val.has_value()) {
            aar.rx_request_type = static_cast<RxRequestType>(type_val.value());
        }
    }

    // Sponsored connectivity
    auto sponsored_avp = msg.findAVP(static_cast<uint32_t>(RxAVPCode::SPONSORED_CONNECTIVITY_DATA));
    if (sponsored_avp) {
        aar.sponsored_connectivity_data = parseSponsoredConnectivityData(sponsored_avp);
    }

    return aar;
}

RxAAAnswer DiameterRxParser::parseAAA(const DiameterMessage& msg) {
    RxAAAnswer aaa;

    // Result code
    if (msg.result_code.has_value()) {
        aaa.result_code = msg.result_code.value();
    }

    // Media components
    auto media_comp_avps =
        msg.findAllAVPs(static_cast<uint32_t>(RxAVPCode::MEDIA_COMPONENT_DESCRIPTION));
    for (const auto& avp : media_comp_avps) {
        auto media_comp = parseMediaComponentDescription(avp);
        if (media_comp.has_value()) {
            aaa.media_components.push_back(media_comp.value());
        }
    }

    // Service authorization info
    auto service_auth_avp =
        msg.findAVP(static_cast<uint32_t>(RxAVPCode::SERVICE_AUTHORIZATION_INFO));
    if (service_auth_avp) {
        aaa.service_authorization_info = service_auth_avp->getDataAsString();
    }

    // Acceptable service info
    auto acceptable_avp = msg.findAVP(static_cast<uint32_t>(RxAVPCode::ACCEPTABLE_SERVICE_INFO));
    if (acceptable_avp) {
        aaa.acceptable_service_info = acceptable_avp->getDataAsString();
    }

    return aaa;
}

RxReAuthRequest DiameterRxParser::parseRAR(const DiameterMessage& msg) {
    RxReAuthRequest rar;

    // Re-Auth-Request-Type
    auto ra_type_avp = msg.findAVP(static_cast<uint32_t>(DiameterAVPCode::RE_AUTH_REQUEST_TYPE));
    if (ra_type_avp) {
        auto type_val = ra_type_avp->getDataAsUint32();
        if (type_val.has_value()) {
            rar.re_auth_request_type = type_val.value();
        }
    }

    // Specific actions
    rar.specific_actions = parseSpecificActions(msg);

    // Abort cause
    auto abort_cause_avp = msg.findAVP(static_cast<uint32_t>(RxAVPCode::ABORT_CAUSE));
    if (abort_cause_avp) {
        auto cause_val = abort_cause_avp->getDataAsUint32();
        if (cause_val.has_value()) {
            rar.abort_cause = static_cast<AbortCause>(cause_val.value());
        }
    }

    return rar;
}

RxReAuthAnswer DiameterRxParser::parseRAA(const DiameterMessage& msg) {
    RxReAuthAnswer raa;

    // Result code
    if (msg.result_code.has_value()) {
        raa.result_code = msg.result_code.value();
    }

    // Media components
    auto media_comp_avps =
        msg.findAllAVPs(static_cast<uint32_t>(RxAVPCode::MEDIA_COMPONENT_DESCRIPTION));
    for (const auto& avp : media_comp_avps) {
        auto media_comp = parseMediaComponentDescription(avp);
        if (media_comp.has_value()) {
            raa.media_components.push_back(media_comp.value());
        }
    }

    return raa;
}

RxSessionTerminationRequest DiameterRxParser::parseSTR(const DiameterMessage& msg) {
    RxSessionTerminationRequest str;

    auto term_cause_avp = msg.findAVP(static_cast<uint32_t>(DiameterAVPCode::TERMINATION_CAUSE));
    if (term_cause_avp) {
        auto cause_val = term_cause_avp->getDataAsUint32();
        if (cause_val.has_value()) {
            str.termination_cause = cause_val.value();
        }
    }

    return str;
}

RxSessionTerminationAnswer DiameterRxParser::parseSTA(const DiameterMessage& msg) {
    RxSessionTerminationAnswer sta;

    if (msg.result_code.has_value()) {
        sta.result_code = msg.result_code.value();
    }

    return sta;
}

RxAbortSessionRequest DiameterRxParser::parseASR(const DiameterMessage& msg) {
    RxAbortSessionRequest asr;

    auto abort_cause_avp = msg.findAVP(static_cast<uint32_t>(RxAVPCode::ABORT_CAUSE));
    if (abort_cause_avp) {
        auto cause_val = abort_cause_avp->getDataAsUint32();
        if (cause_val.has_value()) {
            asr.abort_cause = static_cast<AbortCause>(cause_val.value());
        }
    }

    return asr;
}

RxAbortSessionAnswer DiameterRxParser::parseASA(const DiameterMessage& msg) {
    RxAbortSessionAnswer asa;

    if (msg.result_code.has_value()) {
        asa.result_code = msg.result_code.value();
    }

    return asa;
}

// ============================================================================
// AVP Parsers
// ============================================================================

std::optional<MediaComponentDescription> DiameterRxParser::parseMediaComponentDescription(
    std::shared_ptr<DiameterAVP> avp) {
    auto grouped_avps = avp->getGroupedAVPs();
    if (!grouped_avps.has_value()) {
        return std::nullopt;
    }

    MediaComponentDescription mcd;
    mcd.media_component_number = 0;

    for (const auto& sub_avp : grouped_avps.value()) {
        switch (sub_avp->code) {
            case static_cast<uint32_t>(RxAVPCode::MEDIA_COMPONENT_NUMBER): {
                auto num_val = sub_avp->getDataAsUint32();
                if (num_val.has_value()) {
                    mcd.media_component_number = num_val.value();
                }
                break;
            }
            case static_cast<uint32_t>(RxAVPCode::MEDIA_SUB_COMPONENT): {
                auto sub_comp = parseMediaSubComponent(sub_avp);
                if (sub_comp.has_value()) {
                    mcd.media_sub_components.push_back(sub_comp.value());
                }
                break;
            }
            case static_cast<uint32_t>(RxAVPCode::MEDIA_TYPE): {
                auto type_val = sub_avp->getDataAsUint32();
                if (type_val.has_value()) {
                    mcd.media_type = static_cast<MediaType>(type_val.value());
                }
                break;
            }
            case static_cast<uint32_t>(RxAVPCode::MAX_REQUESTED_BANDWIDTH_DL):
                mcd.max_requested_bandwidth_dl = sub_avp->getDataAsUint32();
                break;
            case static_cast<uint32_t>(RxAVPCode::MAX_REQUESTED_BANDWIDTH_UL):
                mcd.max_requested_bandwidth_ul = sub_avp->getDataAsUint32();
                break;
            case static_cast<uint32_t>(RxAVPCode::MIN_REQUESTED_BANDWIDTH_DL):
                mcd.min_requested_bandwidth_dl = sub_avp->getDataAsUint32();
                break;
            case static_cast<uint32_t>(RxAVPCode::MIN_REQUESTED_BANDWIDTH_UL):
                mcd.min_requested_bandwidth_ul = sub_avp->getDataAsUint32();
                break;
            case static_cast<uint32_t>(RxAVPCode::RR_BANDWIDTH):
                mcd.rr_bandwidth = sub_avp->getDataAsUint32();
                break;
            case static_cast<uint32_t>(RxAVPCode::RS_BANDWIDTH):
                mcd.rs_bandwidth = sub_avp->getDataAsUint32();
                break;
            case static_cast<uint32_t>(RxAVPCode::FLOW_STATUS): {
                auto status_val = sub_avp->getDataAsUint32();
                if (status_val.has_value()) {
                    mcd.flow_status = static_cast<FlowStatus>(status_val.value());
                }
                break;
            }
            case static_cast<uint32_t>(RxAVPCode::CODEC_DATA):
                mcd.codec_data = sub_avp->getDataAsString();
                break;
            case static_cast<uint32_t>(RxAVPCode::SHARING_KEY_DL):
                mcd.sharing_key_dl = sub_avp->getDataAsUint32();
                break;
            case static_cast<uint32_t>(RxAVPCode::SHARING_KEY_UL):
                mcd.sharing_key_ul = sub_avp->getDataAsUint32();
                break;
            case static_cast<uint32_t>(RxAVPCode::CONTENT_VERSION):
                mcd.content_version = sub_avp->getDataAsUint64();
                break;
        }
    }

    return mcd;
}

std::optional<MediaSubComponent> DiameterRxParser::parseMediaSubComponent(
    std::shared_ptr<DiameterAVP> avp) {
    auto grouped_avps = avp->getGroupedAVPs();
    if (!grouped_avps.has_value()) {
        return std::nullopt;
    }

    MediaSubComponent msc;
    msc.flow_number = 0;
    msc.flow_usage = FlowUsage::NO_INFORMATION;

    for (const auto& sub_avp : grouped_avps.value()) {
        switch (sub_avp->code) {
            case static_cast<uint32_t>(RxAVPCode::FLOW_NUMBER): {
                auto num_val = sub_avp->getDataAsUint32();
                if (num_val.has_value()) {
                    msc.flow_number = num_val.value();
                }
                break;
            }
            case static_cast<uint32_t>(RxAVPCode::FLOW_DESCRIPTION):
                msc.flow_descriptions.push_back(sub_avp->getDataAsString());
                break;
            case static_cast<uint32_t>(RxAVPCode::FLOW_USAGE): {
                auto usage_val = sub_avp->getDataAsUint32();
                if (usage_val.has_value()) {
                    msc.flow_usage = static_cast<FlowUsage>(usage_val.value());
                }
                break;
            }
            case static_cast<uint32_t>(RxAVPCode::FLOW_STATUS): {
                auto status_val = sub_avp->getDataAsUint32();
                if (status_val.has_value()) {
                    msc.flow_status = static_cast<FlowStatus>(status_val.value());
                }
                break;
            }
        }
    }

    return msc;
}

std::optional<AccessNetworkChargingIdentifier>
DiameterRxParser::parseAccessNetworkChargingIdentifier(std::shared_ptr<DiameterAVP> avp) {
    auto grouped_avps = avp->getGroupedAVPs();
    if (!grouped_avps.has_value()) {
        return std::nullopt;
    }

    AccessNetworkChargingIdentifier anci;

    for (const auto& sub_avp : grouped_avps.value()) {
        switch (sub_avp->code) {
            case static_cast<uint32_t>(RxAVPCode::ACCESS_NETWORK_CHARGING_IDENTIFIER_VALUE):
                anci.access_network_charging_identifier_value = sub_avp->data;
                break;
            case static_cast<uint32_t>(RxAVPCode::FLOW_DESCRIPTION):
                anci.flows.push_back(sub_avp->getDataAsString());
                break;
        }
    }

    return anci;
}

std::optional<SponsoredConnectivityData> DiameterRxParser::parseSponsoredConnectivityData(
    std::shared_ptr<DiameterAVP> avp) {
    auto grouped_avps = avp->getGroupedAVPs();
    if (!grouped_avps.has_value()) {
        return std::nullopt;
    }

    SponsoredConnectivityData scd;

    for (const auto& sub_avp : grouped_avps.value()) {
        switch (sub_avp->code) {
            case static_cast<uint32_t>(RxAVPCode::SPONSOR_IDENTITY):
                scd.sponsor_identity = sub_avp->getDataAsString();
                break;
            case static_cast<uint32_t>(RxAVPCode::APPLICATION_SERVICE_PROVIDER_IDENTITY):
                scd.application_service_provider_identity = sub_avp->getDataAsString();
                break;
        }
    }

    return scd;
}

std::vector<SpecificAction> DiameterRxParser::parseSpecificActions(const DiameterMessage& msg) {
    std::vector<SpecificAction> actions;

    auto action_avps = msg.findAllAVPs(static_cast<uint32_t>(RxAVPCode::SPECIFIC_ACTION));
    for (const auto& avp : action_avps) {
        auto action_val = avp->getDataAsUint32();
        if (action_val.has_value()) {
            actions.push_back(static_cast<SpecificAction>(action_val.value()));
        }
    }

    return actions;
}

}  // namespace diameter
}  // namespace callflow
