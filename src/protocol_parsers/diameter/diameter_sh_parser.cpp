#include "common/logger.h"
#include "protocol_parsers/diameter/diameter_avp_parser.h"
#include "protocol_parsers/diameter/diameter_sh.h"

namespace callflow {
namespace diameter {

// ============================================================================
// Structure toJson() Methods
// ============================================================================

nlohmann::json UserDataRequest::toJson() const {
    nlohmann::json j;

    if (!user_identities.empty()) {
        nlohmann::json identities = nlohmann::json::array();
        for (const auto& identity : user_identities) {
            identities.push_back(identity.toJson());
        }
        j["user_identities"] = identities;
    }

    if (!data_references.empty()) {
        nlohmann::json refs = nlohmann::json::array();
        for (const auto& ref : data_references) {
            refs.push_back(dataReferenceToString(ref));
        }
        j["data_references"] = refs;
    }

    if (service_indication.has_value()) {
        j["service_indication"] = service_indication.value();
    }

    if (!identity_sets.empty()) {
        nlohmann::json sets = nlohmann::json::array();
        for (const auto& set : identity_sets) {
            sets.push_back(static_cast<uint32_t>(set));
        }
        j["identity_sets"] = sets;
    }

    if (requested_domain.has_value()) {
        j["requested_domain"] = static_cast<uint32_t>(requested_domain.value());
    }

    if (current_location.has_value()) {
        j["current_location"] = static_cast<uint32_t>(current_location.value());
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

nlohmann::json UserDataAnswer::toJson() const {
    nlohmann::json j;

    if (experimental_result_code.has_value()) {
        j["experimental_result_code"] = experimental_result_code.value();
        j["result_code_name"] = shExperimentalResultCodeToString(
            static_cast<ShExperimentalResultCode>(experimental_result_code.value()));
    }

    if (user_data.has_value()) {
        j["user_data"] = user_data->toJson();
    }

    if (!supported_features.empty()) {
        nlohmann::json features = nlohmann::json::array();
        for (const auto& feature : supported_features) {
            features.push_back(feature.toJson());
        }
        j["supported_features"] = features;
    }

    if (wildcarded_public_identity.has_value()) {
        j["wildcarded_public_identity"] = wildcarded_public_identity.value();
    }

    return j;
}

nlohmann::json ProfileUpdateRequest::toJson() const {
    nlohmann::json j;

    if (!user_identities.empty()) {
        nlohmann::json identities = nlohmann::json::array();
        for (const auto& identity : user_identities) {
            identities.push_back(identity.toJson());
        }
        j["user_identities"] = identities;
    }

    if (user_data.has_value()) {
        j["user_data"] = user_data->toJson();
    }

    if (data_reference.has_value()) {
        j["data_reference"] = dataReferenceToString(data_reference.value());
    }

    if (service_indication.has_value()) {
        j["service_indication"] = service_indication.value();
    }

    if (repository_data_id.has_value()) {
        j["repository_data_id"] = repository_data_id->toJson();
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

nlohmann::json ProfileUpdateAnswer::toJson() const {
    nlohmann::json j;

    if (experimental_result_code.has_value()) {
        j["experimental_result_code"] = experimental_result_code.value();
        j["result_code_name"] = shExperimentalResultCodeToString(
            static_cast<ShExperimentalResultCode>(experimental_result_code.value()));
    }

    if (repository_data_id.has_value()) {
        j["repository_data_id"] = repository_data_id->toJson();
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

nlohmann::json SubscribeNotificationsRequest::toJson() const {
    nlohmann::json j;

    if (!user_identities.empty()) {
        nlohmann::json identities = nlohmann::json::array();
        for (const auto& identity : user_identities) {
            identities.push_back(identity.toJson());
        }
        j["user_identities"] = identities;
    }

    if (subs_req_type.has_value()) {
        j["subs_req_type"] = subscriptionRequestTypeToString(subs_req_type.value());
    }

    if (!data_references.empty()) {
        nlohmann::json refs = nlohmann::json::array();
        for (const auto& ref : data_references) {
            refs.push_back(dataReferenceToString(ref));
        }
        j["data_references"] = refs;
    }

    if (service_indication.has_value()) {
        j["service_indication"] = service_indication.value();
    }

    if (send_data_indication.has_value()) {
        j["send_data_indication"] = static_cast<uint32_t>(send_data_indication.value());
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

    if (dsai_tags.has_value() && !dsai_tags.value().empty()) {
        j["dsai_tags"] = dsai_tags.value();
    }

    if (expiry_time.has_value()) {
        j["expiry_time"] = expiry_time.value();
    }

    return j;
}

nlohmann::json SubscribeNotificationsAnswer::toJson() const {
    nlohmann::json j;

    if (experimental_result_code.has_value()) {
        j["experimental_result_code"] = experimental_result_code.value();
        j["result_code_name"] = shExperimentalResultCodeToString(
            static_cast<ShExperimentalResultCode>(experimental_result_code.value()));
    }

    if (user_data.has_value()) {
        j["user_data"] = user_data->toJson();
    }

    if (expiry_time.has_value()) {
        j["expiry_time"] = expiry_time.value();
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

nlohmann::json PushNotificationRequest::toJson() const {
    nlohmann::json j;

    if (!user_identities.empty()) {
        nlohmann::json identities = nlohmann::json::array();
        for (const auto& identity : user_identities) {
            identities.push_back(identity.toJson());
        }
        j["user_identities"] = identities;
    }

    if (user_data.has_value()) {
        j["user_data"] = user_data->toJson();
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

nlohmann::json PushNotificationAnswer::toJson() const {
    nlohmann::json j;

    if (experimental_result_code.has_value()) {
        j["experimental_result_code"] = experimental_result_code.value();
        j["result_code_name"] = shExperimentalResultCodeToString(
            static_cast<ShExperimentalResultCode>(experimental_result_code.value()));
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

nlohmann::json DiameterShMessage::toJson() const {
    nlohmann::json j = base.toJson();
    j["interface"] = "Sh";

    if (udr.has_value()) {
        j["udr"] = udr->toJson();
    }
    if (uda.has_value()) {
        j["uda"] = uda->toJson();
    }
    if (pur.has_value()) {
        j["pur"] = pur->toJson();
    }
    if (pua.has_value()) {
        j["pua"] = pua->toJson();
    }
    if (snr.has_value()) {
        j["snr"] = snr->toJson();
    }
    if (sna.has_value()) {
        j["sna"] = sna->toJson();
    }
    if (pnr.has_value()) {
        j["pnr"] = pnr->toJson();
    }
    if (pna.has_value()) {
        j["pna"] = pna->toJson();
    }

    return j;
}

// ============================================================================
// DiameterShParser Implementation
// ============================================================================

bool DiameterShParser::isShMessage(const DiameterMessage& msg) {
    return msg.header.application_id == DIAMETER_SH_APPLICATION_ID ||
           (msg.auth_application_id.has_value() &&
            msg.auth_application_id.value() == DIAMETER_SH_APPLICATION_ID);
}

std::optional<DiameterShMessage> DiameterShParser::parse(const DiameterMessage& msg) {
    if (!isShMessage(msg)) {
        return std::nullopt;
    }

    DiameterShMessage sh_msg;
    sh_msg.base = msg;

    // Parse based on command code
    switch (static_cast<ShCommandCode>(msg.header.command_code)) {
        case ShCommandCode::USER_DATA:
            if (msg.isRequest()) {
                sh_msg.udr = parseUDR(msg);
            } else {
                sh_msg.uda = parseUDA(msg);
            }
            break;

        case ShCommandCode::PROFILE_UPDATE:
            if (msg.isRequest()) {
                sh_msg.pur = parsePUR(msg);
            } else {
                sh_msg.pua = parsePUA(msg);
            }
            break;

        case ShCommandCode::SUBSCRIBE_NOTIFICATIONS:
            if (msg.isRequest()) {
                sh_msg.snr = parseSNR(msg);
            } else {
                sh_msg.sna = parseSNA(msg);
            }
            break;

        case ShCommandCode::PUSH_NOTIFICATION:
            if (msg.isRequest()) {
                sh_msg.pnr = parsePNR(msg);
            } else {
                sh_msg.pna = parsePNA(msg);
            }
            break;

        default:
            LOG_WARN("Unknown Sh command code: {}", msg.header.command_code);
            break;
    }

    return sh_msg;
}

// ============================================================================
// Request Parsers
// ============================================================================

UserDataRequest DiameterShParser::parseUDR(const DiameterMessage& msg) {
    UserDataRequest udr;

    // User-Identity (Mandatory, can be multiple)
    auto user_id_avps =
        msg.findAllAVPs(static_cast<uint32_t>(ShAVPCode::USER_IDENTITY), DIAMETER_VENDOR_3GPP);
    for (const auto& avp : user_id_avps) {
        auto identity = parseUserIdentity(avp);
        if (identity.has_value()) {
            udr.user_identities.push_back(identity.value());
        }
    }

    // Data-Reference (Mandatory, can be multiple)
    auto data_ref_avps =
        msg.findAllAVPs(static_cast<uint32_t>(ShAVPCode::DATA_REFERENCE), DIAMETER_VENDOR_3GPP);
    for (const auto& avp : data_ref_avps) {
        auto val = avp->getDataAsUint32();
        if (val.has_value()) {
            udr.data_references.push_back(static_cast<DataReference>(val.value()));
        }
    }

    // Service-Indication
    auto service_ind_avp =
        msg.findAVP(static_cast<uint32_t>(ShAVPCode::SERVICE_INDICATION), DIAMETER_VENDOR_3GPP);
    if (service_ind_avp) {
        udr.service_indication = service_ind_avp->getDataAsString();
    }

    // Identity-Set
    auto identity_set_avps =
        msg.findAllAVPs(static_cast<uint32_t>(ShAVPCode::IDENTITY_SET), DIAMETER_VENDOR_3GPP);
    for (const auto& avp : identity_set_avps) {
        auto val = avp->getDataAsUint32();
        if (val.has_value()) {
            udr.identity_sets.push_back(static_cast<IdentitySet>(val.value()));
        }
    }

    // Requested-Domain
    auto req_domain_avp =
        msg.findAVP(static_cast<uint32_t>(ShAVPCode::REQUESTED_DOMAIN), DIAMETER_VENDOR_3GPP);
    if (req_domain_avp) {
        auto val = req_domain_avp->getDataAsUint32();
        if (val.has_value()) {
            udr.requested_domain = static_cast<RequestedDomain>(val.value());
        }
    }

    // Current-Location
    auto curr_loc_avp =
        msg.findAVP(static_cast<uint32_t>(ShAVPCode::CURRENT_LOCATION), DIAMETER_VENDOR_3GPP);
    if (curr_loc_avp) {
        auto val = curr_loc_avp->getDataAsUint32();
        if (val.has_value()) {
            udr.current_location = static_cast<CurrentLocation>(val.value());
        }
    }

    // Supported-Features
    auto supported_features_avps =
        msg.findAllAVPs(static_cast<uint32_t>(ShAVPCode::SUPPORTED_FEATURES), DIAMETER_VENDOR_3GPP);
    for (const auto& avp : supported_features_avps) {
        auto feature = parseSupportedFeatures(avp);
        if (feature.has_value()) {
            udr.supported_features.push_back(feature.value());
        }
    }

    // Requested-Nodes
    auto req_nodes_avp =
        msg.findAVP(static_cast<uint32_t>(ShAVPCode::REQUESTED_NODES), DIAMETER_VENDOR_3GPP);
    if (req_nodes_avp) {
        udr.requested_nodes = req_nodes_avp->getDataAsUint32();
    }

    // UDR-Flags
    auto udr_flags_avp =
        msg.findAVP(static_cast<uint32_t>(ShAVPCode::UDR_FLAGS), DIAMETER_VENDOR_3GPP);
    if (udr_flags_avp) {
        udr.udr_flags = udr_flags_avp->getDataAsUint32();
    }

    return udr;
}

UserDataAnswer DiameterShParser::parseUDA(const DiameterMessage& msg) {
    UserDataAnswer uda;

    // Experimental-Result-Code
    auto exp_result_avp = msg.findAVP(static_cast<uint32_t>(DiameterAVPCode::EXPERIMENTAL_RESULT));
    if (exp_result_avp) {
        auto grouped_avps = exp_result_avp->getGroupedAVPs();
        if (grouped_avps.has_value()) {
            for (const auto& sub_avp : grouped_avps.value()) {
                if (sub_avp->code ==
                    static_cast<uint32_t>(DiameterAVPCode::EXPERIMENTAL_RESULT_CODE)) {
                    uda.experimental_result_code = sub_avp->getDataAsUint32();
                }
            }
        }
    }

    // User-Data
    auto user_data_avp =
        msg.findAVP(static_cast<uint32_t>(ShAVPCode::USER_DATA), DIAMETER_VENDOR_3GPP);
    if (user_data_avp) {
        uda.user_data = parseUserData(user_data_avp);
    }

    // Supported-Features
    auto supported_features_avps =
        msg.findAllAVPs(static_cast<uint32_t>(ShAVPCode::SUPPORTED_FEATURES), DIAMETER_VENDOR_3GPP);
    for (const auto& avp : supported_features_avps) {
        auto feature = parseSupportedFeatures(avp);
        if (feature.has_value()) {
            uda.supported_features.push_back(feature.value());
        }
    }

    // Wildcarded-Public-Identity
    auto wildcard_avp = msg.findAVP(static_cast<uint32_t>(ShAVPCode::WILDCARDED_PUBLIC_IDENTITY),
                                    DIAMETER_VENDOR_3GPP);
    if (wildcard_avp) {
        uda.wildcarded_public_identity = wildcard_avp->getDataAsString();
    }

    return uda;
}

ProfileUpdateRequest DiameterShParser::parsePUR(const DiameterMessage& msg) {
    ProfileUpdateRequest pur;

    // User-Identity (Mandatory)
    auto user_id_avps =
        msg.findAllAVPs(static_cast<uint32_t>(ShAVPCode::USER_IDENTITY), DIAMETER_VENDOR_3GPP);
    for (const auto& avp : user_id_avps) {
        auto identity = parseUserIdentity(avp);
        if (identity.has_value()) {
            pur.user_identities.push_back(identity.value());
        }
    }

    // User-Data
    auto user_data_avp =
        msg.findAVP(static_cast<uint32_t>(ShAVPCode::USER_DATA), DIAMETER_VENDOR_3GPP);
    if (user_data_avp) {
        pur.user_data = parseUserData(user_data_avp);
    }

    // Data-Reference
    auto data_ref_avp =
        msg.findAVP(static_cast<uint32_t>(ShAVPCode::DATA_REFERENCE), DIAMETER_VENDOR_3GPP);
    if (data_ref_avp) {
        auto val = data_ref_avp->getDataAsUint32();
        if (val.has_value()) {
            pur.data_reference = static_cast<DataReference>(val.value());
        }
    }

    // Service-Indication
    auto service_ind_avp =
        msg.findAVP(static_cast<uint32_t>(ShAVPCode::SERVICE_INDICATION), DIAMETER_VENDOR_3GPP);
    if (service_ind_avp) {
        pur.service_indication = service_ind_avp->getDataAsString();
    }

    // Repository-Data-ID
    auto repo_data_id_avp =
        msg.findAVP(static_cast<uint32_t>(ShAVPCode::REPOSITORY_DATA_ID), DIAMETER_VENDOR_3GPP);
    if (repo_data_id_avp) {
        pur.repository_data_id = parseRepositoryDataID(repo_data_id_avp);
    }

    // Supported-Features
    auto supported_features_avps =
        msg.findAllAVPs(static_cast<uint32_t>(ShAVPCode::SUPPORTED_FEATURES), DIAMETER_VENDOR_3GPP);
    for (const auto& avp : supported_features_avps) {
        auto feature = parseSupportedFeatures(avp);
        if (feature.has_value()) {
            pur.supported_features.push_back(feature.value());
        }
    }

    // Wildcarded-Public-Identity
    auto wildcard_avp = msg.findAVP(static_cast<uint32_t>(ShAVPCode::WILDCARDED_PUBLIC_IDENTITY),
                                    DIAMETER_VENDOR_3GPP);
    if (wildcard_avp) {
        pur.wildcarded_public_identity = wildcard_avp->getDataAsString();
    }

    return pur;
}

ProfileUpdateAnswer DiameterShParser::parsePUA(const DiameterMessage& msg) {
    ProfileUpdateAnswer pua;

    // Experimental-Result-Code
    auto exp_result_avp = msg.findAVP(static_cast<uint32_t>(DiameterAVPCode::EXPERIMENTAL_RESULT));
    if (exp_result_avp) {
        auto grouped_avps = exp_result_avp->getGroupedAVPs();
        if (grouped_avps.has_value()) {
            for (const auto& sub_avp : grouped_avps.value()) {
                if (sub_avp->code ==
                    static_cast<uint32_t>(DiameterAVPCode::EXPERIMENTAL_RESULT_CODE)) {
                    pua.experimental_result_code = sub_avp->getDataAsUint32();
                }
            }
        }
    }

    // Repository-Data-ID
    auto repo_data_id_avp =
        msg.findAVP(static_cast<uint32_t>(ShAVPCode::REPOSITORY_DATA_ID), DIAMETER_VENDOR_3GPP);
    if (repo_data_id_avp) {
        pua.repository_data_id = parseRepositoryDataID(repo_data_id_avp);
    }

    // Supported-Features
    auto supported_features_avps =
        msg.findAllAVPs(static_cast<uint32_t>(ShAVPCode::SUPPORTED_FEATURES), DIAMETER_VENDOR_3GPP);
    for (const auto& avp : supported_features_avps) {
        auto feature = parseSupportedFeatures(avp);
        if (feature.has_value()) {
            pua.supported_features.push_back(feature.value());
        }
    }

    // Wildcarded-Public-Identity
    auto wildcard_avp = msg.findAVP(static_cast<uint32_t>(ShAVPCode::WILDCARDED_PUBLIC_IDENTITY),
                                    DIAMETER_VENDOR_3GPP);
    if (wildcard_avp) {
        pua.wildcarded_public_identity = wildcard_avp->getDataAsString();
    }

    return pua;
}

SubscribeNotificationsRequest DiameterShParser::parseSNR(const DiameterMessage& msg) {
    SubscribeNotificationsRequest snr;

    // User-Identity (Mandatory)
    auto user_id_avps =
        msg.findAllAVPs(static_cast<uint32_t>(ShAVPCode::USER_IDENTITY), DIAMETER_VENDOR_3GPP);
    for (const auto& avp : user_id_avps) {
        auto identity = parseUserIdentity(avp);
        if (identity.has_value()) {
            snr.user_identities.push_back(identity.value());
        }
    }

    // Subs-Req-Type
    auto subs_type_avp =
        msg.findAVP(static_cast<uint32_t>(ShAVPCode::SUBS_REQ_TYPE), DIAMETER_VENDOR_3GPP);
    if (subs_type_avp) {
        auto val = subs_type_avp->getDataAsUint32();
        if (val.has_value()) {
            snr.subs_req_type = static_cast<SubscriptionRequestType>(val.value());
        }
    }

    // Data-Reference (can be multiple)
    auto data_ref_avps =
        msg.findAllAVPs(static_cast<uint32_t>(ShAVPCode::DATA_REFERENCE), DIAMETER_VENDOR_3GPP);
    for (const auto& avp : data_ref_avps) {
        auto val = avp->getDataAsUint32();
        if (val.has_value()) {
            snr.data_references.push_back(static_cast<DataReference>(val.value()));
        }
    }

    // Service-Indication
    auto service_ind_avp =
        msg.findAVP(static_cast<uint32_t>(ShAVPCode::SERVICE_INDICATION), DIAMETER_VENDOR_3GPP);
    if (service_ind_avp) {
        snr.service_indication = service_ind_avp->getDataAsString();
    }

    // Send-Data-Indication
    auto send_data_avp =
        msg.findAVP(static_cast<uint32_t>(ShAVPCode::SEND_DATA_INDICATION), DIAMETER_VENDOR_3GPP);
    if (send_data_avp) {
        auto val = send_data_avp->getDataAsUint32();
        if (val.has_value()) {
            snr.send_data_indication = static_cast<SendDataIndication>(val.value());
        }
    }

    // Server-Name
    auto server_name_avp =
        msg.findAVP(static_cast<uint32_t>(ShAVPCode::SERVER_NAME), DIAMETER_VENDOR_3GPP);
    if (server_name_avp) {
        snr.server_name = server_name_avp->getDataAsString();
    }

    // Supported-Features
    auto supported_features_avps =
        msg.findAllAVPs(static_cast<uint32_t>(ShAVPCode::SUPPORTED_FEATURES), DIAMETER_VENDOR_3GPP);
    for (const auto& avp : supported_features_avps) {
        auto feature = parseSupportedFeatures(avp);
        if (feature.has_value()) {
            snr.supported_features.push_back(feature.value());
        }
    }

    // DSAI-Tag (can be multiple)
    auto dsai_tag_avps =
        msg.findAllAVPs(static_cast<uint32_t>(ShAVPCode::DSAI_TAG), DIAMETER_VENDOR_3GPP);
    if (!dsai_tag_avps.empty()) {
        std::vector<std::string> tags;
        for (const auto& avp : dsai_tag_avps) {
            tags.push_back(avp->getDataAsString());
        }
        snr.dsai_tags = tags;
    }

    // Expiry-Time
    auto expiry_avp =
        msg.findAVP(static_cast<uint32_t>(ShAVPCode::EXPIRY_TIME), DIAMETER_VENDOR_3GPP);
    if (expiry_avp) {
        snr.expiry_time = expiry_avp->getDataAsUint32();
    }

    // Session-Priority
    auto session_prio_avp =
        msg.findAVP(static_cast<uint32_t>(ShAVPCode::SESSION_PRIORITY), DIAMETER_VENDOR_3GPP);
    if (session_prio_avp) {
        snr.session_priority = session_prio_avp->getDataAsUint32();
    }

    return snr;
}

SubscribeNotificationsAnswer DiameterShParser::parseSNA(const DiameterMessage& msg) {
    SubscribeNotificationsAnswer sna;

    // Experimental-Result-Code
    auto exp_result_avp = msg.findAVP(static_cast<uint32_t>(DiameterAVPCode::EXPERIMENTAL_RESULT));
    if (exp_result_avp) {
        auto grouped_avps = exp_result_avp->getGroupedAVPs();
        if (grouped_avps.has_value()) {
            for (const auto& sub_avp : grouped_avps.value()) {
                if (sub_avp->code ==
                    static_cast<uint32_t>(DiameterAVPCode::EXPERIMENTAL_RESULT_CODE)) {
                    sna.experimental_result_code = sub_avp->getDataAsUint32();
                }
            }
        }
    }

    // User-Data
    auto user_data_avp =
        msg.findAVP(static_cast<uint32_t>(ShAVPCode::USER_DATA), DIAMETER_VENDOR_3GPP);
    if (user_data_avp) {
        sna.user_data = parseUserData(user_data_avp);
    }

    // Expiry-Time
    auto expiry_avp =
        msg.findAVP(static_cast<uint32_t>(ShAVPCode::EXPIRY_TIME), DIAMETER_VENDOR_3GPP);
    if (expiry_avp) {
        sna.expiry_time = expiry_avp->getDataAsUint32();
    }

    // Supported-Features
    auto supported_features_avps =
        msg.findAllAVPs(static_cast<uint32_t>(ShAVPCode::SUPPORTED_FEATURES), DIAMETER_VENDOR_3GPP);
    for (const auto& avp : supported_features_avps) {
        auto feature = parseSupportedFeatures(avp);
        if (feature.has_value()) {
            sna.supported_features.push_back(feature.value());
        }
    }

    // Wildcarded-Public-Identity
    auto wildcard_avp = msg.findAVP(static_cast<uint32_t>(ShAVPCode::WILDCARDED_PUBLIC_IDENTITY),
                                    DIAMETER_VENDOR_3GPP);
    if (wildcard_avp) {
        sna.wildcarded_public_identity = wildcard_avp->getDataAsString();
    }

    return sna;
}

PushNotificationRequest DiameterShParser::parsePNR(const DiameterMessage& msg) {
    PushNotificationRequest pnr;

    // User-Identity (Mandatory)
    auto user_id_avps =
        msg.findAllAVPs(static_cast<uint32_t>(ShAVPCode::USER_IDENTITY), DIAMETER_VENDOR_3GPP);
    for (const auto& avp : user_id_avps) {
        auto identity = parseUserIdentity(avp);
        if (identity.has_value()) {
            pnr.user_identities.push_back(identity.value());
        }
    }

    // User-Data
    auto user_data_avp =
        msg.findAVP(static_cast<uint32_t>(ShAVPCode::USER_DATA), DIAMETER_VENDOR_3GPP);
    if (user_data_avp) {
        pnr.user_data = parseUserData(user_data_avp);
    }

    // Supported-Features
    auto supported_features_avps =
        msg.findAllAVPs(static_cast<uint32_t>(ShAVPCode::SUPPORTED_FEATURES), DIAMETER_VENDOR_3GPP);
    for (const auto& avp : supported_features_avps) {
        auto feature = parseSupportedFeatures(avp);
        if (feature.has_value()) {
            pnr.supported_features.push_back(feature.value());
        }
    }

    // Wildcarded-Public-Identity
    auto wildcard_avp = msg.findAVP(static_cast<uint32_t>(ShAVPCode::WILDCARDED_PUBLIC_IDENTITY),
                                    DIAMETER_VENDOR_3GPP);
    if (wildcard_avp) {
        pnr.wildcarded_public_identity = wildcard_avp->getDataAsString();
    }

    return pnr;
}

PushNotificationAnswer DiameterShParser::parsePNA(const DiameterMessage& msg) {
    PushNotificationAnswer pna;

    // Experimental-Result-Code
    auto exp_result_avp = msg.findAVP(static_cast<uint32_t>(DiameterAVPCode::EXPERIMENTAL_RESULT));
    if (exp_result_avp) {
        auto grouped_avps = exp_result_avp->getGroupedAVPs();
        if (grouped_avps.has_value()) {
            for (const auto& sub_avp : grouped_avps.value()) {
                if (sub_avp->code ==
                    static_cast<uint32_t>(DiameterAVPCode::EXPERIMENTAL_RESULT_CODE)) {
                    pna.experimental_result_code = sub_avp->getDataAsUint32();
                }
            }
        }
    }

    // Supported-Features
    auto supported_features_avps =
        msg.findAllAVPs(static_cast<uint32_t>(ShAVPCode::SUPPORTED_FEATURES), DIAMETER_VENDOR_3GPP);
    for (const auto& avp : supported_features_avps) {
        auto feature = parseSupportedFeatures(avp);
        if (feature.has_value()) {
            pna.supported_features.push_back(feature.value());
        }
    }

    return pna;
}

// ============================================================================
// AVP Parsers (Grouped/Complex Types)
// ============================================================================

std::optional<UserIdentity> DiameterShParser::parseUserIdentity(std::shared_ptr<DiameterAVP> avp) {
    auto grouped_avps = avp->getGroupedAVPs();
    if (!grouped_avps.has_value()) {
        return std::nullopt;
    }

    UserIdentity identity;

    for (const auto& sub_avp : grouped_avps.value()) {
        switch (sub_avp->code) {
            case static_cast<uint32_t>(ShAVPCode::PUBLIC_IDENTITY):
                identity.public_identity = sub_avp->getDataAsString();
                break;
            case static_cast<uint32_t>(ShAVPCode::MSISDN):
                identity.msisdn = sub_avp->getDataAsString();
                break;
            case static_cast<uint32_t>(ShAVPCode::EXTERNAL_IDENTIFIER):
                identity.external_identifier = sub_avp->getDataAsString();
                break;
        }
    }

    return identity;
}

std::optional<RepositoryDataID> DiameterShParser::parseRepositoryDataID(
    std::shared_ptr<DiameterAVP> avp) {
    auto grouped_avps = avp->getGroupedAVPs();
    if (!grouped_avps.has_value()) {
        return std::nullopt;
    }

    RepositoryDataID repo_id;
    repo_id.sequence_number = 0;

    for (const auto& sub_avp : grouped_avps.value()) {
        switch (sub_avp->code) {
            case static_cast<uint32_t>(ShAVPCode::SERVICE_INDICATION):
                repo_id.service_indication = sub_avp->getDataAsString();
                break;
            case static_cast<uint32_t>(ShAVPCode::SEQUENCE_NUMBER): {
                auto val = sub_avp->getDataAsUint32();
                if (val.has_value()) {
                    repo_id.sequence_number = val.value();
                }
                break;
            }
        }
    }

    return repo_id;
}

std::optional<SupportedFeatures> DiameterShParser::parseSupportedFeatures(
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
            case static_cast<uint32_t>(ShAVPCode::FEATURE_LIST_ID): {
                auto val = sub_avp->getDataAsUint32();
                if (val.has_value()) {
                    features.feature_list_id = val.value();
                }
                break;
            }
            case static_cast<uint32_t>(ShAVPCode::FEATURE_LIST): {
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

std::optional<UserDataSH> DiameterShParser::parseUserData(std::shared_ptr<DiameterAVP> avp) {
    UserDataSH user_data;

    // User-Data is OctetString containing XML
    user_data.raw_xml = avp->getDataAsString();

    // TODO: Parse XML content for structured data
    // For now, just store the raw XML

    return user_data;
}

}  // namespace diameter
}  // namespace callflow
