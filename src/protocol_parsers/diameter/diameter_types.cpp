#include "protocol_parsers/diameter/diameter_types.h"

#include <sstream>

namespace callflow {
namespace diameter {

std::string getResultCodeCategory(uint32_t result_code) {
    if (result_code >= 2000 && result_code < 3000) {
        return "Success";
    } else if (result_code >= 3000 && result_code < 4000) {
        return "Protocol Error";
    } else if (result_code >= 4000 && result_code < 5000) {
        return "Transient Failure";
    } else if (result_code >= 5000 && result_code < 6000) {
        return "Permanent Failure";
    }
    return "Unknown";
}

std::string getResultCodeName(uint32_t result_code) {
    switch (static_cast<DiameterResultCode>(result_code)) {
        case DiameterResultCode::DIAMETER_SUCCESS:
            return "DIAMETER_SUCCESS";
        case DiameterResultCode::DIAMETER_LIMITED_SUCCESS:
            return "DIAMETER_LIMITED_SUCCESS";
        case DiameterResultCode::DIAMETER_COMMAND_UNSUPPORTED:
            return "DIAMETER_COMMAND_UNSUPPORTED";
        case DiameterResultCode::DIAMETER_UNABLE_TO_DELIVER:
            return "DIAMETER_UNABLE_TO_DELIVER";
        case DiameterResultCode::DIAMETER_REALM_NOT_SERVED:
            return "DIAMETER_REALM_NOT_SERVED";
        case DiameterResultCode::DIAMETER_TOO_BUSY:
            return "DIAMETER_TOO_BUSY";
        case DiameterResultCode::DIAMETER_LOOP_DETECTED:
            return "DIAMETER_LOOP_DETECTED";
        case DiameterResultCode::DIAMETER_REDIRECT_INDICATION:
            return "DIAMETER_REDIRECT_INDICATION";
        case DiameterResultCode::DIAMETER_APPLICATION_UNSUPPORTED:
            return "DIAMETER_APPLICATION_UNSUPPORTED";
        case DiameterResultCode::DIAMETER_INVALID_HDR_BITS:
            return "DIAMETER_INVALID_HDR_BITS";
        case DiameterResultCode::DIAMETER_INVALID_AVP_BITS:
            return "DIAMETER_INVALID_AVP_BITS";
        case DiameterResultCode::DIAMETER_UNKNOWN_PEER:
            return "DIAMETER_UNKNOWN_PEER";
        case DiameterResultCode::DIAMETER_AUTHENTICATION_REJECTED:
            return "DIAMETER_AUTHENTICATION_REJECTED";
        case DiameterResultCode::DIAMETER_OUT_OF_SPACE:
            return "DIAMETER_OUT_OF_SPACE";
        case DiameterResultCode::DIAMETER_ELECTION_LOST:
            return "DIAMETER_ELECTION_LOST";
        case DiameterResultCode::DIAMETER_AVP_UNSUPPORTED:
            return "DIAMETER_AVP_UNSUPPORTED";
        case DiameterResultCode::DIAMETER_UNKNOWN_SESSION_ID:
            return "DIAMETER_UNKNOWN_SESSION_ID";
        case DiameterResultCode::DIAMETER_AUTHORIZATION_REJECTED:
            return "DIAMETER_AUTHORIZATION_REJECTED";
        case DiameterResultCode::DIAMETER_INVALID_AVP_VALUE:
            return "DIAMETER_INVALID_AVP_VALUE";
        case DiameterResultCode::DIAMETER_MISSING_AVP:
            return "DIAMETER_MISSING_AVP";
        case DiameterResultCode::DIAMETER_RESOURCES_EXCEEDED:
            return "DIAMETER_RESOURCES_EXCEEDED";
        case DiameterResultCode::DIAMETER_CONTRADICTING_AVPS:
            return "DIAMETER_CONTRADICTING_AVPS";
        case DiameterResultCode::DIAMETER_AVP_NOT_ALLOWED:
            return "DIAMETER_AVP_NOT_ALLOWED";
        case DiameterResultCode::DIAMETER_AVP_OCCURS_TOO_MANY_TIMES:
            return "DIAMETER_AVP_OCCURS_TOO_MANY_TIMES";
        case DiameterResultCode::DIAMETER_NO_COMMON_APPLICATION:
            return "DIAMETER_NO_COMMON_APPLICATION";
        case DiameterResultCode::DIAMETER_UNSUPPORTED_VERSION:
            return "DIAMETER_UNSUPPORTED_VERSION";
        case DiameterResultCode::DIAMETER_UNABLE_TO_COMPLY:
            return "DIAMETER_UNABLE_TO_COMPLY";
        case DiameterResultCode::DIAMETER_INVALID_BIT_IN_HEADER:
            return "DIAMETER_INVALID_BIT_IN_HEADER";
        case DiameterResultCode::DIAMETER_INVALID_AVP_LENGTH:
            return "DIAMETER_INVALID_AVP_LENGTH";
        case DiameterResultCode::DIAMETER_INVALID_MESSAGE_LENGTH:
            return "DIAMETER_INVALID_MESSAGE_LENGTH";
        case DiameterResultCode::DIAMETER_INVALID_AVP_BIT_COMBO:
            return "DIAMETER_INVALID_AVP_BIT_COMBO";
        case DiameterResultCode::DIAMETER_NO_COMMON_SECURITY:
            return "DIAMETER_NO_COMMON_SECURITY";
        default:
            return "UNKNOWN_" + std::to_string(result_code);
    }
}

std::string getAVPDataTypeName(DiameterAVPDataType type) {
    switch (type) {
        case DiameterAVPDataType::OCTET_STRING:
            return "OctetString";
        case DiameterAVPDataType::INTEGER32:
            return "Integer32";
        case DiameterAVPDataType::INTEGER64:
            return "Integer64";
        case DiameterAVPDataType::UNSIGNED32:
            return "Unsigned32";
        case DiameterAVPDataType::UNSIGNED64:
            return "Unsigned64";
        case DiameterAVPDataType::FLOAT32:
            return "Float32";
        case DiameterAVPDataType::FLOAT64:
            return "Float64";
        case DiameterAVPDataType::GROUPED:
            return "Grouped";
        case DiameterAVPDataType::UTF8STRING:
            return "UTF8String";
        case DiameterAVPDataType::DIAMETER_IDENTITY:
            return "DiameterIdentity";
        case DiameterAVPDataType::DIAMETER_URI:
            return "DiameterURI";
        case DiameterAVPDataType::ENUMERATED:
            return "Enumerated";
        case DiameterAVPDataType::IP_ADDRESS:
            return "IPAddress";
        case DiameterAVPDataType::TIME:
            return "Time";
        default:
            return "Unknown";
    }
}

std::string getCommandCodeName(uint32_t command_code) {
    switch (static_cast<DiameterCommandCode>(command_code)) {
        case DiameterCommandCode::CAPABILITIES_EXCHANGE:
            return "Capabilities-Exchange";
        case DiameterCommandCode::RE_AUTH:
            return "Re-Auth";
        case DiameterCommandCode::AA_REQUEST:
            return "AA";
        case DiameterCommandCode::ACCOUNTING:
            return "Accounting";
        case DiameterCommandCode::CREDIT_CONTROL:
            return "Credit-Control";
        case DiameterCommandCode::ABORT_SESSION:
            return "Abort-Session";
        case DiameterCommandCode::SESSION_TERMINATION:
            return "Session-Termination";
        case DiameterCommandCode::DEVICE_WATCHDOG:
            return "Device-Watchdog";
        case DiameterCommandCode::DISCONNECT_PEER:
            return "Disconnect-Peer";
        case DiameterCommandCode::USER_AUTHORIZATION:
            return "User-Authorization";
        case DiameterCommandCode::SERVER_ASSIGNMENT:
            return "Server-Assignment";
        case DiameterCommandCode::LOCATION_INFO:
            return "Location-Info";
        case DiameterCommandCode::MULTIMEDIA_AUTH:
            return "Multimedia-Auth";
        case DiameterCommandCode::REGISTRATION_TERMINATION:
            return "Registration-Termination";
        case DiameterCommandCode::PUSH_PROFILE:
            return "Push-Profile";
        case DiameterCommandCode::USER_DATA:
            return "User-Data";
        case DiameterCommandCode::PROFILE_UPDATE:
            return "Profile-Update";
        case DiameterCommandCode::SUBSCRIBE_NOTIFICATIONS:
            return "Subscribe-Notifications";
        case DiameterCommandCode::PUSH_NOTIFICATION:
            return "Push-Notification";
        case DiameterCommandCode::UPDATE_LOCATION:
            return "Update-Location";
        case DiameterCommandCode::CANCEL_LOCATION:
            return "Cancel-Location";
        case DiameterCommandCode::AUTHENTICATION_INFORMATION:
            return "Authentication-Information";
        case DiameterCommandCode::INSERT_SUBSCRIBER_DATA:
            return "Insert-Subscriber-Data";
        case DiameterCommandCode::DELETE_SUBSCRIBER_DATA:
            return "Delete-Subscriber-Data";
        case DiameterCommandCode::PURGE_UE:
            return "Purge-UE";
        case DiameterCommandCode::RESET:
            return "Reset";
        case DiameterCommandCode::NOTIFY:
            return "Notify";
        default:
            return "Unknown-" + std::to_string(command_code);
    }
}

std::string getApplicationIDName(uint32_t app_id) {
    switch (static_cast<DiameterApplicationID>(app_id)) {
        case DiameterApplicationID::DIAMETER_COMMON_MESSAGES:
            return "Diameter Common Messages";
        case DiameterApplicationID::NASREQ:
            return "NASREQ";
        case DiameterApplicationID::MOBILE_IP:
            return "Mobile IP";
        case DiameterApplicationID::BASE_ACCOUNTING:
            return "Base Accounting";
        case DiameterApplicationID::CREDIT_CONTROL:
            return "Credit Control";
        case DiameterApplicationID::EAP:
            return "EAP";
        case DiameterApplicationID::SIP_APPLICATION:
            return "SIP";
        case DiameterApplicationID::TGPP_CX:
            return "3GPP Cx";
        case DiameterApplicationID::TGPP_SH:
            return "3GPP Sh";
        case DiameterApplicationID::TGPP_GX:
            return "3GPP Gx";
        case DiameterApplicationID::TGPP_S6A_S6D:
            return "3GPP S6a/S6d";
        case DiameterApplicationID::TGPP_S13_S13:
            return "3GPP S13";
        case DiameterApplicationID::TGPP_SLG:
            return "3GPP SLg";
        case DiameterApplicationID::TGPP_SWX:
            return "3GPP SWx";
        case DiameterApplicationID::TGPP_S6B:
            return "3GPP S6b";
        case DiameterApplicationID::TGPP_RX:
            return "3GPP Rx";
        default:
            return "Unknown-" + std::to_string(app_id);
    }
}

DiameterInterface getInterfaceFromApplicationID(uint32_t app_id) {
    switch (static_cast<DiameterApplicationID>(app_id)) {
        case DiameterApplicationID::DIAMETER_COMMON_MESSAGES:
        case DiameterApplicationID::NASREQ:
        case DiameterApplicationID::MOBILE_IP:
        case DiameterApplicationID::BASE_ACCOUNTING:
        case DiameterApplicationID::CREDIT_CONTROL:
        case DiameterApplicationID::EAP:
        case DiameterApplicationID::SIP_APPLICATION:
            return DiameterInterface::BASE;
        case DiameterApplicationID::TGPP_CX:
            return DiameterInterface::CX;
        case DiameterApplicationID::TGPP_SH:
            return DiameterInterface::SH;
        case DiameterApplicationID::TGPP_GX:

            return DiameterInterface::GX;
        case DiameterApplicationID::TGPP_S6A_S6D:
            return DiameterInterface::S6A;
        case DiameterApplicationID::TGPP_S13_S13:
            return DiameterInterface::S6A;  // S13 uses similar structure
        case DiameterApplicationID::TGPP_SLG:
            return DiameterInterface::SLG;
        case DiameterApplicationID::TGPP_SWX:
            return DiameterInterface::SWX;
        case DiameterApplicationID::TGPP_S6B:
            return DiameterInterface::S6B;
        case DiameterApplicationID::TGPP_RX:
            return DiameterInterface::RX;
        default:
            return DiameterInterface::UNKNOWN;
    }
}

std::string getInterfaceName(DiameterInterface interface) {
    switch (interface) {
        case DiameterInterface::BASE:
            return "Base";
        case DiameterInterface::CX:
            return "Cx";
        case DiameterInterface::SH:
            return "Sh";
        case DiameterInterface::S6A:
            return "S6a";
        case DiameterInterface::S13:
            return "S13";
        case DiameterInterface::GX:
            return "Gx";
        case DiameterInterface::RX:
            return "Rx";
        case DiameterInterface::GY:
            return "Gy";
        case DiameterInterface::RO:
            return "Ro";
        case DiameterInterface::SWX:
            return "SWx";
        case DiameterInterface::S6B:
            return "S6b";
        case DiameterInterface::SLG:
            return "SLg";
        case DiameterInterface::UNKNOWN:
        default:
            return "Unknown";
    }
}

}  // namespace diameter
}  // namespace callflow
