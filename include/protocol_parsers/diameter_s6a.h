#pragma once

#include "protocol_parsers/diameter_parser.h"
#include "common/types.h"
#include <optional>
#include <vector>
#include <array>
#include <nlohmann/json.hpp>

namespace callflow {

/**
 * S6a Application ID (3GPP TS 29.272)
 */
constexpr uint32_t DIAMETER_S6A_APPLICATION_ID = 16777251;
constexpr uint32_t DIAMETER_VENDOR_ID_3GPP = 10415;

/**
 * S6a-specific AVP Codes (3GPP TS 29.272)
 */
enum class DiameterS6aAvpCode : uint32_t {
    // Subscriber data
    SUBSCRIPTION_DATA = 1400,
    TERMINAL_INFORMATION = 1401,
    IMEI = 1402,
    SOFTWARE_VERSION = 1403,

    // Location updates
    ULR_FLAGS = 1405,
    ULA_FLAGS = 1406,
    VISITED_PLMN_ID = 1407,

    // Authentication
    REQUESTED_EUTRAN_AUTH_INFO = 1408,
    REQUESTED_UTRAN_GERAN_AUTH_INFO = 1409,
    NUMBER_OF_REQUESTED_VECTORS = 1410,
    RE_SYNCHRONIZATION_INFO = 1411,
    IMMEDIATE_RESPONSE_PREFERRED = 1412,
    AUTHENTICATION_INFO = 1413,
    E_UTRAN_VECTOR = 1414,
    UTRAN_VECTOR = 1415,
    GERAN_VECTOR = 1416,

    // Crypto
    RAND = 1447,
    XRES = 1448,
    AUTN = 1449,
    KASME = 1450,

    // Subscriber profile
    SUBSCRIBER_STATUS = 1424,
    OPERATOR_DETERMINED_BARRING = 1425,
    ACCESS_RESTRICTION_DATA = 1426,
    APN_OI_REPLACEMENT = 1427,
    ALL_APN_CONFIG_INC_IND = 1428,
    APN_CONFIGURATION_PROFILE = 1429,
    APN_CONFIGURATION = 1430,

    // QoS
    EPS_SUBSCRIBED_QOS_PROFILE = 1431,
    ALLOCATION_RETENTION_PRIORITY = 1034,
    PRIORITY_LEVEL = 1046,
    PRE_EMPTION_CAPABILITY = 1047,
    PRE_EMPTION_VULNERABILITY = 1048,

    // AMBR
    AMBR = 1435,
    MAX_REQUESTED_BANDWIDTH_UL_EXTENDED = 1516,
    MAX_REQUESTED_BANDWIDTH_DL_EXTENDED = 1515,

    // PDN
    PDN_TYPE = 1456,
    PDN_GW_ALLOCATION_TYPE = 1438,
    VPLMN_DYNAMIC_ADDRESS_ALLOWED = 1432,
    MIP6_AGENT_INFO = 486,
    PDN_GW_NAME = 1427,

    // Cancellation
    CANCELLATION_TYPE = 1420,
    CLR_FLAGS = 1638,

    // Context
    CONTEXT_IDENTIFIER = 1423,

    // Network access
    SUBSCRIBER_STATUS_VALUE = 1424,
    NETWORK_ACCESS_MODE = 1417,
    ROAMING_RESTRICTED_DUE_TO_UNSUPPORTED_FEATURE = 1457,

    // PUA/PUR
    PUR_FLAGS = 1635,
    PUA_FLAGS = 1442,

    // IDA/IDR
    IDA_FLAGS = 1490,
    IDR_FLAGS = 1490,

    // Supported Features
    SUPPORTED_FEATURES = 628,
    FEATURE_LIST_ID = 629,
    FEATURE_LIST = 630,

    // MSISDN
    MSISDN = 701,

    // Regional Subscription
    REGIONAL_SUBSCRIPTION_ZONE_CODE = 1446,

    // UE-SRVCC-CAPABILITY
    UE_SRVCC_CAPABILITY = 1615,

    // Homogeneous Support of IMS Voice Over PS Sessions
    HOMOGENEOUS_SUPPORT_OF_IMS_VOICE_OVER_PS_SESSIONS = 1493,
};

/**
 * RAT-Type values (3GPP TS 29.212)
 */
enum class RATType : uint32_t {
    WLAN = 0,
    VIRTUAL = 1,
    UTRAN = 1000,
    GERAN = 1001,
    GAN = 1002,
    HSPA_EVOLUTION = 1003,
    EUTRAN = 1004,
    CDMA2000_1X = 2000,
    HRPD = 2001,
    UMB = 2002,
    EHRPD = 2003,
};

/**
 * PDN-Type values
 */
enum class PDNType : uint32_t {
    IPv4 = 0,
    IPv6 = 1,
    IPv4v6 = 2,
    IPv4_OR_IPv6 = 3,
};

/**
 * Subscriber-Status values
 */
enum class SubscriberStatus : uint32_t {
    SERVICE_GRANTED = 0,
    OPERATOR_DETERMINED_BARRING = 1,
};

/**
 * Network-Access-Mode values
 */
enum class NetworkAccessMode : uint32_t {
    PACKET_AND_CIRCUIT = 0,
    ONLY_PACKET = 2,
};

/**
 * Cancellation-Type values
 */
enum class CancellationType : uint32_t {
    MME_UPDATE_PROCEDURE = 0,
    SGSN_UPDATE_PROCEDURE = 1,
    SUBSCRIPTION_WITHDRAWAL = 2,
    UPDATE_PROCEDURE_IWF = 3,
    INITIAL_ATTACH_PROCEDURE = 4,
};

/**
 * ULR-Flags (bit field)
 */
struct ULRFlags {
    bool single_registration_indication;
    bool s6a_s6d_indicator;
    bool skip_subscriber_data;
    bool gprs_subscription_data_indicator;
    bool node_type_indicator;
    bool initial_attach_indicator;
    bool ps_lcs_not_supported_by_ue;

    nlohmann::json toJson() const;
};

/**
 * ULA-Flags (bit field)
 */
struct ULAFlags {
    bool separation_indication;

    nlohmann::json toJson() const;
};

/**
 * E-UTRAN Authentication Vector
 */
struct EUTRANVector {
    std::array<uint8_t, 16> rand;    // Random challenge
    std::array<uint8_t, 16> xres;    // Expected response
    std::array<uint8_t, 16> autn;    // Authentication token
    std::array<uint8_t, 32> kasme;   // Key for MME

    nlohmann::json toJson() const;
};

/**
 * Authentication Info
 */
struct AuthenticationInfo {
    std::vector<EUTRANVector> eutran_vectors;

    nlohmann::json toJson() const;
};

/**
 * Allocation-Retention-Priority
 */
struct AllocationRetentionPriority {
    uint32_t priority_level;          // 1-15
    bool pre_emption_capability;      // MAY or MAY_NOT
    bool pre_emption_vulnerability;   // ENABLED or DISABLED

    nlohmann::json toJson() const;
};

/**
 * EPS-Subscribed-QoS-Profile
 */
struct EPSSubscribedQoSProfile {
    uint32_t qos_class_identifier;    // QCI (1-9)
    AllocationRetentionPriority allocation_retention_priority;

    nlohmann::json toJson() const;
};

/**
 * AMBR (Aggregate Maximum Bit Rate)
 */
struct AMBR {
    uint32_t max_requested_bandwidth_ul;  // bits per second
    uint32_t max_requested_bandwidth_dl;  // bits per second

    nlohmann::json toJson() const;
};

/**
 * APN-Configuration
 */
struct APNConfiguration {
    uint32_t context_identifier;
    std::string service_selection;    // APN
    PDNType pdn_type;
    EPSSubscribedQoSProfile qos_profile;
    std::optional<AMBR> ambr;
    std::optional<std::string> served_party_ip_address;
    std::optional<bool> vplmn_dynamic_address_allowed;

    nlohmann::json toJson() const;
};

/**
 * APN-Configuration-Profile
 */
struct APNConfigurationProfile {
    uint32_t context_identifier;
    std::vector<APNConfiguration> apn_configs;
    bool all_apn_config_inc_ind;

    nlohmann::json toJson() const;
};

/**
 * Subscription-Data
 */
struct SubscriptionData {
    std::optional<SubscriberStatus> subscriber_status;
    std::optional<std::string> msisdn;
    std::optional<NetworkAccessMode> network_access_mode;
    std::optional<uint32_t> operator_determined_barring;
    std::optional<AMBR> ambr;
    std::optional<APNConfigurationProfile> apn_configuration_profile;
    std::optional<uint32_t> access_restriction_data;
    std::optional<uint32_t> subscribed_periodic_rau_tau_timer;

    nlohmann::json toJson() const;
};

/**
 * Update Location Request (ULR)
 */
struct UpdateLocationRequest {
    std::string user_name;           // IMSI
    std::string visited_plmn_id;
    RATType rat_type;
    ULRFlags ulr_flags;
    std::optional<uint32_t> ue_srvcc_capability;
    std::optional<std::string> terminal_information;

    nlohmann::json toJson() const;
};

/**
 * Update Location Answer (ULA)
 */
struct UpdateLocationAnswer {
    uint32_t result_code;
    std::optional<ULAFlags> ula_flags;
    std::optional<SubscriptionData> subscription_data;

    nlohmann::json toJson() const;
};

/**
 * Authentication Information Request (AIR)
 */
struct AuthenticationInformationRequest {
    std::string user_name;           // IMSI
    std::string visited_plmn_id;
    uint32_t number_of_requested_vectors;
    std::optional<std::vector<uint8_t>> resync_info;
    std::optional<bool> immediate_response_preferred;

    nlohmann::json toJson() const;
};

/**
 * Authentication Information Answer (AIA)
 */
struct AuthenticationInformationAnswer {
    uint32_t result_code;
    std::optional<AuthenticationInfo> auth_info;

    nlohmann::json toJson() const;
};

/**
 * Purge UE Request (PUR)
 */
struct PurgeUERequest {
    std::string user_name;           // IMSI
    std::optional<uint32_t> pur_flags;

    nlohmann::json toJson() const;
};

/**
 * Purge UE Answer (PUA)
 */
struct PurgeUEAnswer {
    uint32_t result_code;
    std::optional<uint32_t> pua_flags;

    nlohmann::json toJson() const;
};

/**
 * Cancel Location Request (CLR)
 */
struct CancelLocationRequest {
    std::string user_name;           // IMSI
    CancellationType cancellation_type;
    std::optional<uint32_t> clr_flags;

    nlohmann::json toJson() const;
};

/**
 * Cancel Location Answer (CLA)
 */
struct CancelLocationAnswer {
    uint32_t result_code;

    nlohmann::json toJson() const;
};

/**
 * Insert Subscriber Data Request (IDR)
 */
struct InsertSubscriberDataRequest {
    std::string user_name;           // IMSI
    SubscriptionData subscription_data;
    std::optional<uint32_t> idr_flags;

    nlohmann::json toJson() const;
};

/**
 * Insert Subscriber Data Answer (IDA)
 */
struct InsertSubscriberDataAnswer {
    uint32_t result_code;
    std::optional<uint32_t> ida_flags;
    std::optional<bool> ims_voice_over_ps_sessions_supported;

    nlohmann::json toJson() const;
};

/**
 * Delete Subscriber Data Request (DSR)
 */
struct DeleteSubscriberDataRequest {
    std::string user_name;           // IMSI
    std::vector<uint32_t> context_identifiers;

    nlohmann::json toJson() const;
};

/**
 * Delete Subscriber Data Answer (DSA)
 */
struct DeleteSubscriberDataAnswer {
    uint32_t result_code;

    nlohmann::json toJson() const;
};

/**
 * S6a Message (extends Diameter base message)
 */
struct DiameterS6aMessage {
    DiameterMessage base;

    // Parsed message-specific data
    std::optional<UpdateLocationRequest> ulr;
    std::optional<UpdateLocationAnswer> ula;
    std::optional<AuthenticationInformationRequest> air;
    std::optional<AuthenticationInformationAnswer> aia;
    std::optional<PurgeUERequest> pur;
    std::optional<PurgeUEAnswer> pua;
    std::optional<CancelLocationRequest> clr;
    std::optional<CancelLocationAnswer> cla;
    std::optional<InsertSubscriberDataRequest> idr;
    std::optional<InsertSubscriberDataAnswer> ida;
    std::optional<DeleteSubscriberDataRequest> dsr;
    std::optional<DeleteSubscriberDataAnswer> dsa;

    // Common extracted fields
    std::optional<std::string> imsi;
    std::optional<std::string> visited_plmn_id;

    nlohmann::json toJson() const;
};

/**
 * Diameter S6a Parser
 *
 * Parses S6a-specific Diameter messages for the MME-HSS interface.
 */
class DiameterS6aParser {
public:
    DiameterS6aParser() = default;
    ~DiameterS6aParser() = default;

    /**
     * Parse S6a message from Diameter base message
     * @param msg Diameter base message
     * @return Parsed S6a message or nullopt if not S6a
     */
    std::optional<DiameterS6aMessage> parse(const DiameterMessage& msg);

    /**
     * Check if message is S6a
     */
    static bool isS6aMessage(const DiameterMessage& msg);

private:
    // Message-specific parsers
    UpdateLocationRequest parseULR(const DiameterMessage& msg);
    UpdateLocationAnswer parseULA(const DiameterMessage& msg);
    AuthenticationInformationRequest parseAIR(const DiameterMessage& msg);
    AuthenticationInformationAnswer parseAIA(const DiameterMessage& msg);
    PurgeUERequest parsePUR(const DiameterMessage& msg);
    PurgeUEAnswer parsePUA(const DiameterMessage& msg);
    CancelLocationRequest parseCLR(const DiameterMessage& msg);
    CancelLocationAnswer parseCLA(const DiameterMessage& msg);
    InsertSubscriberDataRequest parseIDR(const DiameterMessage& msg);
    InsertSubscriberDataAnswer parseIDA(const DiameterMessage& msg);
    DeleteSubscriberDataRequest parseDSR(const DiameterMessage& msg);
    DeleteSubscriberDataAnswer parseDSA(const DiameterMessage& msg);

    // AVP parsers
    std::optional<SubscriptionData> parseSubscriptionData(const DiameterAvp& avp);
    std::optional<APNConfigurationProfile> parseAPNConfigurationProfile(const DiameterAvp& avp);
    std::optional<APNConfiguration> parseAPNConfiguration(const DiameterAvp& avp);
    std::optional<AuthenticationInfo> parseAuthenticationInfo(const DiameterAvp& avp);
    std::optional<EUTRANVector> parseEUTRANVector(const DiameterAvp& avp);
    std::optional<EPSSubscribedQoSProfile> parseEPSSubscribedQoSProfile(const DiameterAvp& avp);
    std::optional<AMBR> parseAMBR(const DiameterAvp& avp);
    std::optional<AllocationRetentionPriority> parseAllocationRetentionPriority(const DiameterAvp& avp);
    std::optional<ULRFlags> parseULRFlags(const DiameterAvp& avp);
    std::optional<ULAFlags> parseULAFlags(const DiameterAvp& avp);

    // Helper functions
    std::optional<DiameterAvp> findAVP(const std::vector<DiameterAvp>& avps, uint32_t code);
    std::vector<DiameterAvp> findAllAVPs(const std::vector<DiameterAvp>& avps, uint32_t code);
    std::optional<std::string> getAVPString(const DiameterAvp& avp);
    std::optional<uint32_t> getAVPUint32(const DiameterAvp& avp);
    std::optional<std::vector<uint8_t>> getAVPOctetString(const DiameterAvp& avp);
    std::vector<DiameterAvp> parseGroupedAVP(const DiameterAvp& avp);
};

}  // namespace callflow
