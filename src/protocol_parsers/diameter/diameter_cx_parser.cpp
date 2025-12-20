#include "protocol_parsers/diameter/diameter_cx.h"
#include "protocol_parsers/diameter/diameter_avp_parser.h"
#include "common/logger.h"

namespace callflow {
namespace diameter {

// ============================================================================
// Structure toJson() Methods
// ============================================================================

nlohmann::json UserAuthorizationRequest::toJson() const {
    nlohmann::json j;
    j["public_identity"] = public_identity;

    if (visited_network_identifier.has_value()) {
        j["visited_network_identifier"] = visited_network_identifier.value();
    }

    if (user_authorization_type.has_value()) {
        j["user_authorization_type"] = userAuthorizationTypeToString(user_authorization_type.value());
    }

    if (uar_flags.has_value()) {
        j["uar_flags"] = uar_flags.value();
    }

    if (user_name.has_value()) {
        j["user_name"] = user_name.value();
    }

    if (!supported_features.empty()) {
        nlohmann::json features = nlohmann::json::array();
        for (const auto& feature : supported_features) {
            features.push_back(feature.toJson());
        }
        j["supported_features"] = features;
    }

    return j;
}

nlohmann::json UserAuthorizationAnswer::toJson() const {
    nlohmann::json j;

    if (experimental_result_code.has_value()) {
        j["experimental_result_code"] = experimental_result_code.value();
        j["result_code_name"] = cxDxExperimentalResultCodeToString(
            static_cast<CxDxExperimentalResultCode>(experimental_result_code.value()));
    }

    if (server_capabilities.has_value()) {
        j["server_capabilities"] = server_capabilities->toJson();
    }

    if (server_name.has_value()) {
        j["server_name"] = server_name.value();
    }

    if (!supported_features.empty()) {
        nlohmann::json features = nlohmann::json::array();
        for (const auto& feature : supported_features) {
            features.push_back(feature.toJson());
        }
        j["supported_features"] = features;
    }

    return j;
}

nlohmann::json ServerAssignmentRequest::toJson() const {
    nlohmann::json j;
    j["public_identity"] = public_identity;
    j["server_name"] = server_name;

    if (user_name.has_value()) {
        j["user_name"] = user_name.value();
    }

    if (server_assignment_type.has_value()) {
        j["server_assignment_type"] = serverAssignmentTypeToString(server_assignment_type.value());
    }

    if (user_data_already_available.has_value()) {
        j["user_data_already_available"] = static_cast<uint32_t>(user_data_already_available.value());
    }

    if (deregistration_reason.has_value()) {
        j["deregistration_reason"] = deregistration_reason->toJson();
    }

    if (!public_identities.empty()) {
        j["public_identities"] = public_identities;
    }

    if (wildcarded_public_identity.has_value()) {
        j["wildcarded_public_identity"] = wildcarded_public_identity.value();
    }

    if (!supported_features.empty()) {
        nlohmann::json features = nlohmann::json::array();
        for (const auto& feature : supported_features) {
            features.push_back(feature.toJson());
        }
        j["supported_features"] = features;
    }

    return j;
}

nlohmann::json ServerAssignmentAnswer::toJson() const {
    nlohmann::json j;

    if (experimental_result_code.has_value()) {
        j["experimental_result_code"] = experimental_result_code.value();
        j["result_code_name"] = cxDxExperimentalResultCodeToString(
            static_cast<CxDxExperimentalResultCode>(experimental_result_code.value()));
    }

    if (user_data.has_value()) {
        j["user_data"] = user_data->toJson();
    }

    if (charging_information.has_value()) {
        j["charging_information"] = charging_information->toJson();
    }

    if (!associated_identities.empty()) {
        j["associated_identities"] = associated_identities;
    }

    if (!supported_features.empty()) {
        nlohmann::json features = nlohmann::json::array();
        for (const auto& feature : supported_features) {
            features.push_back(feature.toJson());
        }
        j["supported_features"] = features;
    }

    return j;
}

nlohmann::json LocationInfoRequest::toJson() const {
    nlohmann::json j;
    j["public_identity"] = public_identity;

    if (user_name.has_value()) {
        j["user_name"] = user_name.value();
    }

    if (originating_request.has_value()) {
        j["originating_request"] = originating_request.value();
    }

    if (!supported_features.empty()) {
        nlohmann::json features = nlohmann::json::array();
        for (const auto& feature : supported_features) {
            features.push_back(feature.toJson());
        }
        j["supported_features"] = features;
    }

    return j;
}

nlohmann::json LocationInfoAnswer::toJson() const {
    nlohmann::json j;

    if (experimental_result_code.has_value()) {
        j["experimental_result_code"] = experimental_result_code.value();
        j["result_code_name"] = cxDxExperimentalResultCodeToString(
            static_cast<CxDxExperimentalResultCode>(experimental_result_code.value()));
    }

    if (server_name.has_value()) {
        j["server_name"] = server_name.value();
    }

    if (server_capabilities.has_value()) {
        j["server_capabilities"] = server_capabilities->toJson();
    }

    if (!supported_features.empty()) {
        nlohmann::json features = nlohmann::json::array();
        for (const auto& feature : supported_features) {
            features.push_back(feature.toJson());
        }
        j["supported_features"] = features;
    }

    return j;
}

nlohmann::json MultimediaAuthRequest::toJson() const {
    nlohmann::json j;
    j["public_identity"] = public_identity;
    j["user_name"] = user_name;

    if (server_name.has_value()) {
        j["server_name"] = server_name.value();
    }

    if (sip_number_auth_items.has_value()) {
        j["sip_number_auth_items"] = sip_number_auth_items.value();
    }

    if (!supported_features.empty()) {
        nlohmann::json features = nlohmann::json::array();
        for (const auto& feature : supported_features) {
            features.push_back(feature.toJson());
        }
        j["supported_features"] = features;
    }

    return j;
}

nlohmann::json MultimediaAuthAnswer::toJson() const {
    nlohmann::json j;

    if (experimental_result_code.has_value()) {
        j["experimental_result_code"] = experimental_result_code.value();
        j["result_code_name"] = cxDxExperimentalResultCodeToString(
            static_cast<CxDxExperimentalResultCode>(experimental_result_code.value()));
    }

    if (user_name.has_value()) {
        j["user_name"] = user_name.value();
    }

    if (public_identity.has_value()) {
        j["public_identity"] = public_identity.value();
    }

    if (sip_number_auth_items.has_value()) {
        j["sip_number_auth_items"] = sip_number_auth_items->toJson();
    }

    if (!supported_features.empty()) {
        nlohmann::json features = nlohmann::json::array();
        for (const auto& feature : supported_features) {
            features.push_back(feature.toJson());
        }
        j["supported_features"] = features;
    }

    return j;
}

nlohmann::json RegistrationTerminationRequest::toJson() const {
    nlohmann::json j;

    if (deregistration_reason.has_value()) {
        j["deregistration_reason"] = deregistration_reason->toJson();
    }

    if (user_name.has_value()) {
        j["user_name"] = user_name.value();
    }

    if (!public_identities.empty()) {
        j["public_identities"] = public_identities;
    }

    if (!associated_identities.empty()) {
        j["associated_identities"] = associated_identities;
    }

    if (!supported_features.empty()) {
        nlohmann::json features = nlohmann::json::array();
        for (const auto& feature : supported_features) {
            features.push_back(feature.toJson());
        }
        j["supported_features"] = features;
    }

    return j;
}

nlohmann::json RegistrationTerminationAnswer::toJson() const {
    nlohmann::json j;

    if (experimental_result_code.has_value()) {
        j["experimental_result_code"] = experimental_result_code.value();
        j["result_code_name"] = cxDxExperimentalResultCodeToString(
            static_cast<CxDxExperimentalResultCode>(experimental_result_code.value()));
    }

    if (!associated_identities.empty()) {
        j["associated_identities"] = associated_identities;
    }

    if (!supported_features.empty()) {
        nlohmann::json features = nlohmann::json::array();
        for (const auto& feature : supported_features) {
            features.push_back(feature.toJson());
        }
        j["supported_features"] = features;
    }

    return j;
}

nlohmann::json PushProfileRequest::toJson() const {
    nlohmann::json j;

    if (user_name.has_value()) {
        j["user_name"] = user_name.value();
    }

    if (user_data.has_value()) {
        j["user_data"] = user_data->toJson();
    }

    if (charging_information.has_value()) {
        j["charging_information"] = charging_information->toJson();
    }

    if (!supported_features.empty()) {
        nlohmann::json features = nlohmann::json::array();
        for (const auto& feature : supported_features) {
            features.push_back(feature.toJson());
        }
        j["supported_features"] = features;
    }

    return j;
}

nlohmann::json PushProfileAnswer::toJson() const {
    nlohmann::json j;

    if (experimental_result_code.has_value()) {
        j["experimental_result_code"] = experimental_result_code.value();
        j["result_code_name"] = cxDxExperimentalResultCodeToString(
            static_cast<CxDxExperimentalResultCode>(experimental_result_code.value()));
    }

    if (!supported_features.empty()) {
        nlohmann::json features = nlohmann::json::array();
        for (const auto& feature : supported_features) {
            features.push_back(feature.toJson());
        }
        j["supported_features"] = features;
    }

    return j;
}

nlohmann::json DiameterCxMessage::toJson() const {
    nlohmann::json j = base.toJson();
    j["interface"] = "Cx/Dx";

    if (uar.has_value()) {
        j["uar"] = uar->toJson();
    }
    if (uaa.has_value()) {
        j["uaa"] = uaa->toJson();
    }
    if (sar.has_value()) {
        j["sar"] = sar->toJson();
    }
    if (saa.has_value()) {
        j["saa"] = saa->toJson();
    }
    if (lir.has_value()) {
        j["lir"] = lir->toJson();
    }
    if (lia.has_value()) {
        j["lia"] = lia->toJson();
    }
    if (mar.has_value()) {
        j["mar"] = mar->toJson();
    }
    if (maa.has_value()) {
        j["maa"] = maa->toJson();
    }
    if (rtr.has_value()) {
        j["rtr"] = rtr->toJson();
    }
    if (rta.has_value()) {
        j["rta"] = rta->toJson();
    }
    if (ppr.has_value()) {
        j["ppr"] = ppr->toJson();
    }
    if (ppa.has_value()) {
        j["ppa"] = ppa->toJson();
    }

    return j;
}

// ============================================================================
// DiameterCxParser Implementation
// ============================================================================

bool DiameterCxParser::isCxMessage(const DiameterMessage& msg) {
    return msg.header.application_id == DIAMETER_CX_APPLICATION_ID ||
           (msg.auth_application_id.has_value() &&
            msg.auth_application_id.value() == DIAMETER_CX_APPLICATION_ID);
}

std::optional<DiameterCxMessage> DiameterCxParser::parse(const DiameterMessage& msg) {
    if (!isCxMessage(msg)) {
        return std::nullopt;
    }

    DiameterCxMessage cx_msg;
    cx_msg.base = msg;

    // Parse based on command code
    switch (static_cast<CxDxCommandCode>(msg.header.command_code)) {
        case CxDxCommandCode::USER_AUTHORIZATION:
            if (msg.isRequest()) {
                cx_msg.uar = parseUAR(msg);
            } else {
                cx_msg.uaa = parseUAA(msg);
            }
            break;

        case CxDxCommandCode::SERVER_ASSIGNMENT:
            if (msg.isRequest()) {
                cx_msg.sar = parseSAR(msg);
            } else {
                cx_msg.saa = parseSAA(msg);
            }
            break;

        case CxDxCommandCode::LOCATION_INFO:
            if (msg.isRequest()) {
                cx_msg.lir = parseLIR(msg);
            } else {
                cx_msg.lia = parseLIA(msg);
            }
            break;

        case CxDxCommandCode::MULTIMEDIA_AUTH:
            if (msg.isRequest()) {
                cx_msg.mar = parseMAR(msg);
            } else {
                cx_msg.maa = parseMAA(msg);
            }
            break;

        case CxDxCommandCode::REGISTRATION_TERMINATION:
            if (msg.isRequest()) {
                cx_msg.rtr = parseRTR(msg);
            } else {
                cx_msg.rta = parseRTA(msg);
            }
            break;

        case CxDxCommandCode::PUSH_PROFILE:
            if (msg.isRequest()) {
                cx_msg.ppr = parsePPR(msg);
            } else {
                cx_msg.ppa = parsePPA(msg);
            }
            break;

        default:
            Logger::warning("Unknown Cx/Dx command code: " +
                          std::to_string(msg.header.command_code));
            break;
    }

    return cx_msg;
}

// ============================================================================
// Request Parsers
// ============================================================================

UserAuthorizationRequest DiameterCxParser::parseUAR(const DiameterMessage& msg) {
    UserAuthorizationRequest uar;

    // Public-Identity (Mandatory)
    auto pub_id_avp = msg.findAVP(static_cast<uint32_t>(CxDxAVPCode::PUBLIC_IDENTITY), DIAMETER_VENDOR_3GPP);
    if (pub_id_avp) {
        uar.public_identity = pub_id_avp->getDataAsString();
    }

    // Visited-Network-Identifier
    auto visited_network_avp = msg.findAVP(static_cast<uint32_t>(CxDxAVPCode::VISITED_NETWORK_IDENTIFIER), DIAMETER_VENDOR_3GPP);
    if (visited_network_avp) {
        uar.visited_network_identifier = visited_network_avp->getDataAsString();
    }

    // User-Authorization-Type
    auto auth_type_avp = msg.findAVP(static_cast<uint32_t>(CxDxAVPCode::USER_AUTHORIZATION_TYPE), DIAMETER_VENDOR_3GPP);
    if (auth_type_avp) {
        auto val = auth_type_avp->getDataAsUint32();
        if (val.has_value()) {
            uar.user_authorization_type = static_cast<UserAuthorizationType>(val.value());
        }
    }

    // UAR-Flags
    auto uar_flags_avp = msg.findAVP(static_cast<uint32_t>(CxDxAVPCode::UAR_FLAGS), DIAMETER_VENDOR_3GPP);
    if (uar_flags_avp) {
        uar.uar_flags = uar_flags_avp->getDataAsUint32();
    }

    // User-Name (Private Identity)
    auto user_name_avp = msg.findAVP(static_cast<uint32_t>(DiameterAVPCode::USER_NAME));
    if (user_name_avp) {
        uar.user_name = user_name_avp->getDataAsString();
    }

    // Supported-Features
    auto supported_features_avps = msg.findAllAVPs(static_cast<uint32_t>(CxDxAVPCode::SUPPORTED_FEATURES), DIAMETER_VENDOR_3GPP);
    for (const auto& avp : supported_features_avps) {
        auto feature = parseSupportedFeatures(avp);
        if (feature.has_value()) {
            uar.supported_features.push_back(feature.value());
        }
    }

    return uar;
}

UserAuthorizationAnswer DiameterCxParser::parseUAA(const DiameterMessage& msg) {
    UserAuthorizationAnswer uaa;

    // Experimental-Result-Code
    auto exp_result_avp = msg.findAVP(static_cast<uint32_t>(DiameterAVPCode::EXPERIMENTAL_RESULT));
    if (exp_result_avp) {
        auto grouped_avps = exp_result_avp->getGroupedAVPs();
        if (grouped_avps.has_value()) {
            for (const auto& sub_avp : grouped_avps.value()) {
                if (sub_avp->code == static_cast<uint32_t>(DiameterAVPCode::EXPERIMENTAL_RESULT_CODE)) {
                    uaa.experimental_result_code = sub_avp->getDataAsUint32();
                }
            }
        }
    }

    // Server-Name
    auto server_name_avp = msg.findAVP(static_cast<uint32_t>(CxDxAVPCode::SERVER_NAME), DIAMETER_VENDOR_3GPP);
    if (server_name_avp) {
        uaa.server_name = server_name_avp->getDataAsString();
    }

    // Server-Capabilities
    auto server_cap_avp = msg.findAVP(static_cast<uint32_t>(CxDxAVPCode::SERVER_CAPABILITIES), DIAMETER_VENDOR_3GPP);
    if (server_cap_avp) {
        uaa.server_capabilities = parseServerCapabilities(server_cap_avp);
    }

    // Supported-Features
    auto supported_features_avps = msg.findAllAVPs(static_cast<uint32_t>(CxDxAVPCode::SUPPORTED_FEATURES), DIAMETER_VENDOR_3GPP);
    for (const auto& avp : supported_features_avps) {
        auto feature = parseSupportedFeatures(avp);
        if (feature.has_value()) {
            uaa.supported_features.push_back(feature.value());
        }
    }

    return uaa;
}

ServerAssignmentRequest DiameterCxParser::parseSAR(const DiameterMessage& msg) {
    ServerAssignmentRequest sar;

    // Public-Identity
    auto pub_id_avp = msg.findAVP(static_cast<uint32_t>(CxDxAVPCode::PUBLIC_IDENTITY), DIAMETER_VENDOR_3GPP);
    if (pub_id_avp) {
        sar.public_identity = pub_id_avp->getDataAsString();
    }

    // Multiple Public-Identities
    auto pub_ids_avps = msg.findAllAVPs(static_cast<uint32_t>(CxDxAVPCode::PUBLIC_IDENTITY), DIAMETER_VENDOR_3GPP);
    for (const auto& avp : pub_ids_avps) {
        sar.public_identities.push_back(avp->getDataAsString());
    }

    // Server-Name
    auto server_name_avp = msg.findAVP(static_cast<uint32_t>(CxDxAVPCode::SERVER_NAME), DIAMETER_VENDOR_3GPP);
    if (server_name_avp) {
        sar.server_name = server_name_avp->getDataAsString();
    }

    // User-Name
    auto user_name_avp = msg.findAVP(static_cast<uint32_t>(DiameterAVPCode::USER_NAME));
    if (user_name_avp) {
        sar.user_name = user_name_avp->getDataAsString();
    }

    // Server-Assignment-Type
    auto assign_type_avp = msg.findAVP(static_cast<uint32_t>(CxDxAVPCode::SERVER_ASSIGNMENT_TYPE), DIAMETER_VENDOR_3GPP);
    if (assign_type_avp) {
        auto val = assign_type_avp->getDataAsUint32();
        if (val.has_value()) {
            sar.server_assignment_type = static_cast<ServerAssignmentType>(val.value());
        }
    }

    // User-Data-Already-Available
    auto data_avail_avp = msg.findAVP(static_cast<uint32_t>(CxDxAVPCode::USER_DATA_ALREADY_AVAILABLE), DIAMETER_VENDOR_3GPP);
    if (data_avail_avp) {
        auto val = data_avail_avp->getDataAsUint32();
        if (val.has_value()) {
            sar.user_data_already_available = static_cast<UserDataAlreadyAvailable>(val.value());
        }
    }

    // Deregistration-Reason
    auto dereg_reason_avp = msg.findAVP(static_cast<uint32_t>(CxDxAVPCode::DEREGISTRATION_REASON), DIAMETER_VENDOR_3GPP);
    if (dereg_reason_avp) {
        sar.deregistration_reason = parseDeregistrationReason(dereg_reason_avp);
    }

    // Wildcarded-Public-Identity
    auto wildcard_avp = msg.findAVP(static_cast<uint32_t>(CxDxAVPCode::WILDCARDED_PUBLIC_IDENTITY), DIAMETER_VENDOR_3GPP);
    if (wildcard_avp) {
        sar.wildcarded_public_identity = wildcard_avp->getDataAsString();
    }

    // Supported-Features
    auto supported_features_avps = msg.findAllAVPs(static_cast<uint32_t>(CxDxAVPCode::SUPPORTED_FEATURES), DIAMETER_VENDOR_3GPP);
    for (const auto& avp : supported_features_avps) {
        auto feature = parseSupportedFeatures(avp);
        if (feature.has_value()) {
            sar.supported_features.push_back(feature.value());
        }
    }

    return sar;
}

ServerAssignmentAnswer DiameterCxParser::parseSAA(const DiameterMessage& msg) {
    ServerAssignmentAnswer saa;

    // Experimental-Result-Code
    auto exp_result_avp = msg.findAVP(static_cast<uint32_t>(DiameterAVPCode::EXPERIMENTAL_RESULT));
    if (exp_result_avp) {
        auto grouped_avps = exp_result_avp->getGroupedAVPs();
        if (grouped_avps.has_value()) {
            for (const auto& sub_avp : grouped_avps.value()) {
                if (sub_avp->code == static_cast<uint32_t>(DiameterAVPCode::EXPERIMENTAL_RESULT_CODE)) {
                    saa.experimental_result_code = sub_avp->getDataAsUint32();
                }
            }
        }
    }

    // User-Data
    auto user_data_avp = msg.findAVP(static_cast<uint32_t>(CxDxAVPCode::USER_DATA), DIAMETER_VENDOR_3GPP);
    if (user_data_avp) {
        saa.user_data = parseUserData(user_data_avp);
    }

    // Charging-Information
    auto charging_info_avp = msg.findAVP(static_cast<uint32_t>(CxDxAVPCode::CHARGING_INFORMATION), DIAMETER_VENDOR_3GPP);
    if (charging_info_avp) {
        saa.charging_information = parseChargingInformation(charging_info_avp);
    }

    // Associated-Identities
    auto assoc_id_avp = msg.findAVP(static_cast<uint32_t>(CxDxAVPCode::ASSOCIATED_IDENTITIES), DIAMETER_VENDOR_3GPP);
    if (assoc_id_avp) {
        auto grouped_avps = assoc_id_avp->getGroupedAVPs();
        if (grouped_avps.has_value()) {
            for (const auto& sub_avp : grouped_avps.value()) {
                if (sub_avp->code == static_cast<uint32_t>(DiameterAVPCode::USER_NAME)) {
                    saa.associated_identities.push_back(sub_avp->getDataAsString());
                }
            }
        }
    }

    // Supported-Features
    auto supported_features_avps = msg.findAllAVPs(static_cast<uint32_t>(CxDxAVPCode::SUPPORTED_FEATURES), DIAMETER_VENDOR_3GPP);
    for (const auto& avp : supported_features_avps) {
        auto feature = parseSupportedFeatures(avp);
        if (feature.has_value()) {
            saa.supported_features.push_back(feature.value());
        }
    }

    return saa;
}

LocationInfoRequest DiameterCxParser::parseLIR(const DiameterMessage& msg) {
    LocationInfoRequest lir;

    // Public-Identity
    auto pub_id_avp = msg.findAVP(static_cast<uint32_t>(CxDxAVPCode::PUBLIC_IDENTITY), DIAMETER_VENDOR_3GPP);
    if (pub_id_avp) {
        lir.public_identity = pub_id_avp->getDataAsString();
    }

    // User-Name
    auto user_name_avp = msg.findAVP(static_cast<uint32_t>(DiameterAVPCode::USER_NAME));
    if (user_name_avp) {
        lir.user_name = user_name_avp->getDataAsString();
    }

    // Originating-Request
    auto orig_req_avp = msg.findAVP(static_cast<uint32_t>(CxDxAVPCode::ORIGINATING_REQUEST), DIAMETER_VENDOR_3GPP);
    if (orig_req_avp) {
        lir.originating_request = orig_req_avp->getDataAsUint32();
    }

    // Session-Priority
    auto session_prio_avp = msg.findAVP(static_cast<uint32_t>(CxDxAVPCode::SESSION_PRIORITY), DIAMETER_VENDOR_3GPP);
    if (session_prio_avp) {
        lir.session_priority = session_prio_avp->getDataAsUint32();
    }

    // Supported-Features
    auto supported_features_avps = msg.findAllAVPs(static_cast<uint32_t>(CxDxAVPCode::SUPPORTED_FEATURES), DIAMETER_VENDOR_3GPP);
    for (const auto& avp : supported_features_avps) {
        auto feature = parseSupportedFeatures(avp);
        if (feature.has_value()) {
            lir.supported_features.push_back(feature.value());
        }
    }

    return lir;
}

LocationInfoAnswer DiameterCxParser::parseLIA(const DiameterMessage& msg) {
    LocationInfoAnswer lia;

    // Experimental-Result-Code
    auto exp_result_avp = msg.findAVP(static_cast<uint32_t>(DiameterAVPCode::EXPERIMENTAL_RESULT));
    if (exp_result_avp) {
        auto grouped_avps = exp_result_avp->getGroupedAVPs();
        if (grouped_avps.has_value()) {
            for (const auto& sub_avp : grouped_avps.value()) {
                if (sub_avp->code == static_cast<uint32_t>(DiameterAVPCode::EXPERIMENTAL_RESULT_CODE)) {
                    lia.experimental_result_code = sub_avp->getDataAsUint32();
                }
            }
        }
    }

    // Server-Name
    auto server_name_avp = msg.findAVP(static_cast<uint32_t>(CxDxAVPCode::SERVER_NAME), DIAMETER_VENDOR_3GPP);
    if (server_name_avp) {
        lia.server_name = server_name_avp->getDataAsString();
    }

    // Server-Capabilities
    auto server_cap_avp = msg.findAVP(static_cast<uint32_t>(CxDxAVPCode::SERVER_CAPABILITIES), DIAMETER_VENDOR_3GPP);
    if (server_cap_avp) {
        lia.server_capabilities = parseServerCapabilities(server_cap_avp);
    }

    // Supported-Features
    auto supported_features_avps = msg.findAllAVPs(static_cast<uint32_t>(CxDxAVPCode::SUPPORTED_FEATURES), DIAMETER_VENDOR_3GPP);
    for (const auto& avp : supported_features_avps) {
        auto feature = parseSupportedFeatures(avp);
        if (feature.has_value()) {
            lia.supported_features.push_back(feature.value());
        }
    }

    return lia;
}

MultimediaAuthRequest DiameterCxParser::parseMAR(const DiameterMessage& msg) {
    MultimediaAuthRequest mar;

    // Public-Identity
    auto pub_id_avp = msg.findAVP(static_cast<uint32_t>(CxDxAVPCode::PUBLIC_IDENTITY), DIAMETER_VENDOR_3GPP);
    if (pub_id_avp) {
        mar.public_identity = pub_id_avp->getDataAsString();
    }

    // User-Name
    auto user_name_avp = msg.findAVP(static_cast<uint32_t>(DiameterAVPCode::USER_NAME));
    if (user_name_avp) {
        mar.user_name = user_name_avp->getDataAsString();
    }

    // Server-Name
    auto server_name_avp = msg.findAVP(static_cast<uint32_t>(CxDxAVPCode::SERVER_NAME), DIAMETER_VENDOR_3GPP);
    if (server_name_avp) {
        mar.server_name = server_name_avp->getDataAsString();
    }

    // SIP-Number-Auth-Items
    auto sip_num_auth_avp = msg.findAVP(static_cast<uint32_t>(CxDxAVPCode::SIP_NUMBER_AUTH_ITEMS), DIAMETER_VENDOR_3GPP);
    if (sip_num_auth_avp) {
        mar.sip_number_auth_items = sip_num_auth_avp->getDataAsUint32();
    }

    // Supported-Features
    auto supported_features_avps = msg.findAllAVPs(static_cast<uint32_t>(CxDxAVPCode::SUPPORTED_FEATURES), DIAMETER_VENDOR_3GPP);
    for (const auto& avp : supported_features_avps) {
        auto feature = parseSupportedFeatures(avp);
        if (feature.has_value()) {
            mar.supported_features.push_back(feature.value());
        }
    }

    return mar;
}

MultimediaAuthAnswer DiameterCxParser::parseMAA(const DiameterMessage& msg) {
    MultimediaAuthAnswer maa;

    // Experimental-Result-Code
    auto exp_result_avp = msg.findAVP(static_cast<uint32_t>(DiameterAVPCode::EXPERIMENTAL_RESULT));
    if (exp_result_avp) {
        auto grouped_avps = exp_result_avp->getGroupedAVPs();
        if (grouped_avps.has_value()) {
            for (const auto& sub_avp : grouped_avps.value()) {
                if (sub_avp->code == static_cast<uint32_t>(DiameterAVPCode::EXPERIMENTAL_RESULT_CODE)) {
                    maa.experimental_result_code = sub_avp->getDataAsUint32();
                }
            }
        }
    }

    // User-Name
    auto user_name_avp = msg.findAVP(static_cast<uint32_t>(DiameterAVPCode::USER_NAME));
    if (user_name_avp) {
        maa.user_name = user_name_avp->getDataAsString();
    }

    // Public-Identity
    auto pub_id_avp = msg.findAVP(static_cast<uint32_t>(CxDxAVPCode::PUBLIC_IDENTITY), DIAMETER_VENDOR_3GPP);
    if (pub_id_avp) {
        maa.public_identity = pub_id_avp->getDataAsString();
    }

    // SIP-Number-Auth-Items
    auto sip_num_auth_avp = msg.findAVP(static_cast<uint32_t>(CxDxAVPCode::SIP_NUMBER_AUTH_ITEMS), DIAMETER_VENDOR_3GPP);
    if (sip_num_auth_avp) {
        maa.sip_number_auth_items = parseSIPNumberAuthItems(sip_num_auth_avp);
    }

    // Supported-Features
    auto supported_features_avps = msg.findAllAVPs(static_cast<uint32_t>(CxDxAVPCode::SUPPORTED_FEATURES), DIAMETER_VENDOR_3GPP);
    for (const auto& avp : supported_features_avps) {
        auto feature = parseSupportedFeatures(avp);
        if (feature.has_value()) {
            maa.supported_features.push_back(feature.value());
        }
    }

    return maa;
}

RegistrationTerminationRequest DiameterCxParser::parseRTR(const DiameterMessage& msg) {
    RegistrationTerminationRequest rtr;

    // Deregistration-Reason
    auto dereg_reason_avp = msg.findAVP(static_cast<uint32_t>(CxDxAVPCode::DEREGISTRATION_REASON), DIAMETER_VENDOR_3GPP);
    if (dereg_reason_avp) {
        rtr.deregistration_reason = parseDeregistrationReason(dereg_reason_avp);
    }

    // User-Name
    auto user_name_avp = msg.findAVP(static_cast<uint32_t>(DiameterAVPCode::USER_NAME));
    if (user_name_avp) {
        rtr.user_name = user_name_avp->getDataAsString();
    }

    // Public-Identities
    auto pub_ids_avps = msg.findAllAVPs(static_cast<uint32_t>(CxDxAVPCode::PUBLIC_IDENTITY), DIAMETER_VENDOR_3GPP);
    for (const auto& avp : pub_ids_avps) {
        rtr.public_identities.push_back(avp->getDataAsString());
    }

    // Associated-Identities
    auto assoc_id_avp = msg.findAVP(static_cast<uint32_t>(CxDxAVPCode::ASSOCIATED_IDENTITIES), DIAMETER_VENDOR_3GPP);
    if (assoc_id_avp) {
        auto grouped_avps = assoc_id_avp->getGroupedAVPs();
        if (grouped_avps.has_value()) {
            for (const auto& sub_avp : grouped_avps.value()) {
                if (sub_avp->code == static_cast<uint32_t>(DiameterAVPCode::USER_NAME)) {
                    rtr.associated_identities.push_back(sub_avp->getDataAsString());
                }
            }
        }
    }

    // Supported-Features
    auto supported_features_avps = msg.findAllAVPs(static_cast<uint32_t>(CxDxAVPCode::SUPPORTED_FEATURES), DIAMETER_VENDOR_3GPP);
    for (const auto& avp : supported_features_avps) {
        auto feature = parseSupportedFeatures(avp);
        if (feature.has_value()) {
            rtr.supported_features.push_back(feature.value());
        }
    }

    return rtr;
}

RegistrationTerminationAnswer DiameterCxParser::parseRTA(const DiameterMessage& msg) {
    RegistrationTerminationAnswer rta;

    // Experimental-Result-Code
    auto exp_result_avp = msg.findAVP(static_cast<uint32_t>(DiameterAVPCode::EXPERIMENTAL_RESULT));
    if (exp_result_avp) {
        auto grouped_avps = exp_result_avp->getGroupedAVPs();
        if (grouped_avps.has_value()) {
            for (const auto& sub_avp : grouped_avps.value()) {
                if (sub_avp->code == static_cast<uint32_t>(DiameterAVPCode::EXPERIMENTAL_RESULT_CODE)) {
                    rta.experimental_result_code = sub_avp->getDataAsUint32();
                }
            }
        }
    }

    // Associated-Identities
    auto assoc_id_avp = msg.findAVP(static_cast<uint32_t>(CxDxAVPCode::ASSOCIATED_IDENTITIES), DIAMETER_VENDOR_3GPP);
    if (assoc_id_avp) {
        auto grouped_avps = assoc_id_avp->getGroupedAVPs();
        if (grouped_avps.has_value()) {
            for (const auto& sub_avp : grouped_avps.value()) {
                if (sub_avp->code == static_cast<uint32_t>(DiameterAVPCode::USER_NAME)) {
                    rta.associated_identities.push_back(sub_avp->getDataAsString());
                }
            }
        }
    }

    // Supported-Features
    auto supported_features_avps = msg.findAllAVPs(static_cast<uint32_t>(CxDxAVPCode::SUPPORTED_FEATURES), DIAMETER_VENDOR_3GPP);
    for (const auto& avp : supported_features_avps) {
        auto feature = parseSupportedFeatures(avp);
        if (feature.has_value()) {
            rta.supported_features.push_back(feature.value());
        }
    }

    return rta;
}

PushProfileRequest DiameterCxParser::parsePPR(const DiameterMessage& msg) {
    PushProfileRequest ppr;

    // User-Name
    auto user_name_avp = msg.findAVP(static_cast<uint32_t>(DiameterAVPCode::USER_NAME));
    if (user_name_avp) {
        ppr.user_name = user_name_avp->getDataAsString();
    }

    // User-Data
    auto user_data_avp = msg.findAVP(static_cast<uint32_t>(CxDxAVPCode::USER_DATA), DIAMETER_VENDOR_3GPP);
    if (user_data_avp) {
        ppr.user_data = parseUserData(user_data_avp);
    }

    // Charging-Information
    auto charging_info_avp = msg.findAVP(static_cast<uint32_t>(CxDxAVPCode::CHARGING_INFORMATION), DIAMETER_VENDOR_3GPP);
    if (charging_info_avp) {
        ppr.charging_information = parseChargingInformation(charging_info_avp);
    }

    // Supported-Features
    auto supported_features_avps = msg.findAllAVPs(static_cast<uint32_t>(CxDxAVPCode::SUPPORTED_FEATURES), DIAMETER_VENDOR_3GPP);
    for (const auto& avp : supported_features_avps) {
        auto feature = parseSupportedFeatures(avp);
        if (feature.has_value()) {
            ppr.supported_features.push_back(feature.value());
        }
    }

    return ppr;
}

PushProfileAnswer DiameterCxParser::parsePPA(const DiameterMessage& msg) {
    PushProfileAnswer ppa;

    // Experimental-Result-Code
    auto exp_result_avp = msg.findAVP(static_cast<uint32_t>(DiameterAVPCode::EXPERIMENTAL_RESULT));
    if (exp_result_avp) {
        auto grouped_avps = exp_result_avp->getGroupedAVPs();
        if (grouped_avps.has_value()) {
            for (const auto& sub_avp : grouped_avps.value()) {
                if (sub_avp->code == static_cast<uint32_t>(DiameterAVPCode::EXPERIMENTAL_RESULT_CODE)) {
                    ppa.experimental_result_code = sub_avp->getDataAsUint32();
                }
            }
        }
    }

    // Supported-Features
    auto supported_features_avps = msg.findAllAVPs(static_cast<uint32_t>(CxDxAVPCode::SUPPORTED_FEATURES), DIAMETER_VENDOR_3GPP);
    for (const auto& avp : supported_features_avps) {
        auto feature = parseSupportedFeatures(avp);
        if (feature.has_value()) {
            ppa.supported_features.push_back(feature.value());
        }
    }

    return ppa;
}

// ============================================================================
// AVP Parsers (Grouped/Complex Types)
// ============================================================================

std::optional<ServerCapabilities> DiameterCxParser::parseServerCapabilities(
    std::shared_ptr<DiameterAVP> avp) {

    auto grouped_avps = avp->getGroupedAVPs();
    if (!grouped_avps.has_value()) {
        return std::nullopt;
    }

    ServerCapabilities capabilities;

    for (const auto& sub_avp : grouped_avps.value()) {
        switch (sub_avp->code) {
            case static_cast<uint32_t>(CxDxAVPCode::MANDATORY_CAPABILITY): {
                auto val = sub_avp->getDataAsUint32();
                if (val.has_value()) {
                    capabilities.mandatory_capabilities.push_back(val.value());
                }
                break;
            }
            case static_cast<uint32_t>(CxDxAVPCode::OPTIONAL_CAPABILITY): {
                auto val = sub_avp->getDataAsUint32();
                if (val.has_value()) {
                    capabilities.optional_capabilities.push_back(val.value());
                }
                break;
            }
            case static_cast<uint32_t>(CxDxAVPCode::SERVER_NAME): {
                capabilities.server_names.push_back(sub_avp->getDataAsString());
                break;
            }
        }
    }

    return capabilities;
}

std::optional<SIPNumberAuthItems> DiameterCxParser::parseSIPNumberAuthItems(
    std::shared_ptr<DiameterAVP> avp) {

    auto grouped_avps = avp->getGroupedAVPs();
    if (!grouped_avps.has_value()) {
        return std::nullopt;
    }

    SIPNumberAuthItems auth_items;

    for (const auto& sub_avp : grouped_avps.value()) {
        if (sub_avp->code == static_cast<uint32_t>(CxDxAVPCode::SIP_AUTH_DATA_ITEM)) {
            auto auth_item = parseSIPAuthDataItem(sub_avp);
            if (auth_item.has_value()) {
                auth_items.auth_data_items.push_back(auth_item.value());
            }
        }
    }

    return auth_items;
}

std::optional<SIPAuthDataItem> DiameterCxParser::parseSIPAuthDataItem(
    std::shared_ptr<DiameterAVP> avp) {

    auto grouped_avps = avp->getGroupedAVPs();
    if (!grouped_avps.has_value()) {
        return std::nullopt;
    }

    SIPAuthDataItem item;
    item.sip_item_number = 0;

    for (const auto& sub_avp : grouped_avps.value()) {
        switch (sub_avp->code) {
            case static_cast<uint32_t>(CxDxAVPCode::SIP_ITEM_NUMBER): {
                auto val = sub_avp->getDataAsUint32();
                if (val.has_value()) {
                    item.sip_item_number = val.value();
                }
                break;
            }
            case static_cast<uint32_t>(CxDxAVPCode::SIP_AUTHENTICATION_SCHEME):
                item.sip_authentication_scheme = sub_avp->getDataAsString();
                break;
            case static_cast<uint32_t>(CxDxAVPCode::SIP_AUTHENTICATE):
                item.sip_authenticate = sub_avp->getDataAsString();
                break;
            case static_cast<uint32_t>(CxDxAVPCode::SIP_AUTHORIZATION):
                item.sip_authorization = sub_avp->getDataAsString();
                break;
            case static_cast<uint32_t>(CxDxAVPCode::SIP_AUTHENTICATION_CONTEXT):
                item.sip_authentication_context = sub_avp->getDataAsString();
                break;
            case static_cast<uint32_t>(CxDxAVPCode::CONFIDENTIALITY_KEY):
                item.confidentiality_key = sub_avp->getDataAsString();
                break;
            case static_cast<uint32_t>(CxDxAVPCode::INTEGRITY_KEY):
                item.integrity_key = sub_avp->getDataAsString();
                break;
            case static_cast<uint32_t>(CxDxAVPCode::LINE_IDENTIFIER): {
                // Line identifier is OctetString
                if (!sub_avp->data.empty()) {
                    item.line_identifier = sub_avp->data;
                }
                break;
            }
        }
    }

    return item;
}

std::optional<ChargingInformation> DiameterCxParser::parseChargingInformation(
    std::shared_ptr<DiameterAVP> avp) {

    auto grouped_avps = avp->getGroupedAVPs();
    if (!grouped_avps.has_value()) {
        return std::nullopt;
    }

    ChargingInformation charging_info;

    for (const auto& sub_avp : grouped_avps.value()) {
        switch (sub_avp->code) {
            case static_cast<uint32_t>(CxDxAVPCode::PRIMARY_EVENT_CHARGING_FUNCTION_NAME):
                charging_info.primary_event_charging_function_name = sub_avp->getDataAsString();
                break;
            case static_cast<uint32_t>(CxDxAVPCode::SECONDARY_EVENT_CHARGING_FUNCTION_NAME):
                charging_info.secondary_event_charging_function_name = sub_avp->getDataAsString();
                break;
            case static_cast<uint32_t>(CxDxAVPCode::PRIMARY_CHARGING_COLLECTION_FUNCTION_NAME):
                charging_info.primary_charging_collection_function_name = sub_avp->getDataAsString();
                break;
            case static_cast<uint32_t>(CxDxAVPCode::SECONDARY_CHARGING_COLLECTION_FUNCTION_NAME):
                charging_info.secondary_charging_collection_function_name = sub_avp->getDataAsString();
                break;
        }
    }

    return charging_info;
}

std::optional<DeregistrationReason> DiameterCxParser::parseDeregistrationReason(
    std::shared_ptr<DiameterAVP> avp) {

    auto grouped_avps = avp->getGroupedAVPs();
    if (!grouped_avps.has_value()) {
        return std::nullopt;
    }

    DeregistrationReason reason;
    reason.reason_code = 0;

    for (const auto& sub_avp : grouped_avps.value()) {
        switch (sub_avp->code) {
            case static_cast<uint32_t>(CxDxAVPCode::REASON_CODE): {
                auto val = sub_avp->getDataAsUint32();
                if (val.has_value()) {
                    reason.reason_code = val.value();
                }
                break;
            }
            case static_cast<uint32_t>(CxDxAVPCode::REASON_INFO):
                reason.reason_info = sub_avp->getDataAsString();
                break;
        }
    }

    return reason;
}

std::optional<SupportedFeatures> DiameterCxParser::parseSupportedFeatures(
    std::shared_ptr<DiameterAVP> avp) {

    auto grouped_avps = avp->getGroupedAVPs();
    if (!grouped_avps.has_value()) {
        return std::nullopt;
    }

    SupportedFeatures features;
    features.vendor_id = 0;
    features.feature_list_id = 0;
    features.feature_list = 0;

    for (const auto& sub_avp : grouped_avps.value()) {
        switch (sub_avp->code) {
            case static_cast<uint32_t>(DiameterAVPCode::VENDOR_ID): {
                auto val = sub_avp->getDataAsUint32();
                if (val.has_value()) {
                    features.vendor_id = val.value();
                }
                break;
            }
            case static_cast<uint32_t>(CxDxAVPCode::FEATURE_LIST_ID): {
                auto val = sub_avp->getDataAsUint32();
                if (val.has_value()) {
                    features.feature_list_id = val.value();
                }
                break;
            }
            case static_cast<uint32_t>(CxDxAVPCode::FEATURE_LIST): {
                auto val = sub_avp->getDataAsUint32();
                if (val.has_value()) {
                    features.feature_list = val.value();
                }
                break;
            }
        }
    }

    return features;
}

std::optional<UserDataSH> DiameterCxParser::parseUserData(std::shared_ptr<DiameterAVP> avp) {
    UserDataSH user_data;

    // User-Data is OctetString containing XML
    user_data.raw_xml = avp->getDataAsString();

    // TODO: Parse XML content for structured data
    // For now, just store the raw XML

    return user_data;
}

}  // namespace diameter
}  // namespace callflow
