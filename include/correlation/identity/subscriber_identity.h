#pragma once

#include <string>
#include <optional>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <cstdint>

namespace callflow {
namespace correlation {

/**
 * @brief Normalized MSISDN with multiple representations
 */
struct NormalizedMsisdn {
    std::string raw;              // Original input
    std::string digits_only;      // All digits extracted
    std::string national;         // Without country code, leading zeros stripped
    std::string international;    // With country code (E.164)
    std::string country_code;     // Detected country code

    bool operator==(const NormalizedMsisdn& other) const;
    bool matches(const NormalizedMsisdn& other) const;  // Fuzzy matching
};

/**
 * @brief Normalized IMSI with PLMN extraction
 */
struct NormalizedImsi {
    std::string raw;              // Original input
    std::string digits;           // 15-digit IMSI
    std::string mcc;              // Mobile Country Code (3 digits)
    std::string mnc;              // Mobile Network Code (2-3 digits)
    std::string msin;             // Mobile Subscriber Identification Number

    bool operator==(const NormalizedImsi& other) const;
    std::string getPlmn() const;  // MCC + MNC
};

/**
 * @brief Normalized IMEI/IMEISV
 */
struct NormalizedImei {
    std::string raw;              // Original input
    std::string imei;             // 14-digit IMEI
    std::optional<std::string> imeisv;  // 16-digit IMEISV if available
    std::string tac;              // Type Allocation Code (8 digits)
    std::string snr;              // Serial Number (6 digits)

    bool operator==(const NormalizedImei& other) const;
};

/**
 * @brief 4G GUTI structure
 */
struct Guti4G {
    std::string mcc;              // 3 digits
    std::string mnc;              // 2-3 digits
    uint16_t mme_group_id;
    uint8_t mme_code;
    uint32_t m_tmsi;

    std::string toString() const;
    static std::optional<Guti4G> parse(const uint8_t* data, size_t length);
};

/**
 * @brief 5G-GUTI structure
 */
struct Guti5G {
    std::string mcc;              // 3 digits
    std::string mnc;              // 2-3 digits
    uint8_t amf_region_id;
    uint16_t amf_set_id;          // 10 bits
    uint8_t amf_pointer;          // 6 bits
    uint32_t fiveG_tmsi;

    std::string toString() const;
    static std::optional<Guti5G> parse(const uint8_t* data, size_t length);
};

/**
 * @brief Network endpoint information
 */
struct NetworkEndpoint {
    std::string ipv4;
    std::string ipv6;
    uint16_t port = 0;

    // GTP-U tunnel info
    std::optional<std::string> gtpu_peer_ip;
    std::optional<uint32_t> gtpu_teid;

    bool hasIpv4() const { return !ipv4.empty(); }
    bool hasIpv6() const { return !ipv6.empty(); }
    std::string getIpv6Prefix(int prefix_len = 64) const;
    bool matchesIp(const std::string& ip) const;
    bool matchesIpPrefix(const std::string& prefix) const;
};

/**
 * @brief Complete subscriber identity container
 */
struct SubscriberIdentity {
    // Primary identifiers
    std::optional<NormalizedImsi> imsi;
    std::optional<NormalizedMsisdn> msisdn;
    std::optional<NormalizedImei> imei;

    // Temporary identifiers (4G)
    std::optional<Guti4G> guti;
    std::optional<uint32_t> tmsi;
    std::optional<uint32_t> p_tmsi;

    // Temporary identifiers (5G)
    std::optional<Guti5G> guti_5g;
    std::optional<uint32_t> tmsi_5g;

    // Network endpoints associated with this subscriber
    std::vector<NetworkEndpoint> endpoints;

    // APN/DNN information
    std::string apn;
    std::string pdn_type;  // "ipv4", "ipv6", "ipv4v6"

    // Confidence scores (0.0 to 1.0)
    std::unordered_map<std::string, float> confidence;

    // Timestamps
    std::chrono::steady_clock::time_point first_seen;
    std::chrono::steady_clock::time_point last_seen;

    // Methods
    bool hasImsi() const { return imsi.has_value(); }
    bool hasMsisdn() const { return msisdn.has_value(); }
    bool hasImei() const { return imei.has_value(); }

    bool matches(const SubscriberIdentity& other) const;
    void merge(const SubscriberIdentity& other);

    std::string getPrimaryKey() const;  // Best available identifier
};

/**
 * @brief Identity source tracking
 */
enum class IdentitySource {
    SIP_FROM_HEADER,
    SIP_TO_HEADER,
    SIP_PAI_HEADER,
    SIP_PPI_HEADER,
    SIP_CONTACT_HEADER,
    DIAMETER_USER_NAME,
    DIAMETER_3GPP_IMSI,
    DIAMETER_PUBLIC_IDENTITY,
    DIAMETER_FRAMED_IP,
    GTP_IMSI_IE,
    GTP_MSISDN_IE,
    GTP_MEI_IE,
    GTP_PDN_ADDRESS,
    GTP_FTEID,
    NAS_MOBILE_IDENTITY,
    NAS_GUTI,
    S1AP_NAS_PDU,
    UNKNOWN
};

} // namespace correlation
} // namespace callflow
