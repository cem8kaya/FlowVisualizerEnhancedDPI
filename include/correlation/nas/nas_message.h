#pragma once

#include "correlation/nas/nas_types.h"
#include "correlation/identity/subscriber_identity.h"
#include <cstdint>
#include <string>
#include <vector>
#include <optional>

namespace callflow {
namespace correlation {

/**
 * @brief Parsed NAS message container
 *
 * Represents a decoded NAS message (EMM or ESM) with extracted
 * information elements.
 */
class NasMessage {
public:
    NasMessage() = default;
    ~NasMessage() = default;

    /**
     * @brief Parse NAS message from raw bytes
     * @param data Raw NAS message data
     * @param length Length of data
     * @param frame_num Frame number
     * @param timestamp Timestamp
     * @return Parsed NAS message, or nullopt if parsing fails
     */
    static std::optional<NasMessage> parse(const uint8_t* data,
                                           size_t length,
                                           uint32_t frame_num,
                                           double timestamp);

    // Message metadata
    uint32_t getFrameNum() const { return frame_num_; }
    double getTimestamp() const { return timestamp_; }

    // Protocol discriminator
    NasProtocolDiscriminator getProtocolDiscriminator() const { return protocol_discriminator_; }
    bool isEmm() const { return protocol_discriminator_ == NasProtocolDiscriminator::EPS_MOBILITY_MANAGEMENT; }
    bool isEsm() const { return protocol_discriminator_ == NasProtocolDiscriminator::EPS_SESSION_MANAGEMENT; }

    // Security header
    NasSecurityHeaderType getSecurityHeaderType() const { return security_header_type_; }
    bool isPlainNas() const { return security_header_type_ == NasSecurityHeaderType::PLAIN_NAS; }
    bool isIntegrityProtected() const;
    bool isCiphered() const;

    // Message types
    std::optional<NasEmmMessageType> getEmmMessageType() const { return emm_message_type_; }
    std::optional<NasEsmMessageType> getEsmMessageType() const { return esm_message_type_; }

    // Procedure Transaction Identifier (for ESM)
    std::optional<uint8_t> getPti() const { return pti_; }

    // EPS Bearer Identity (for ESM)
    std::optional<uint8_t> getEpsBearerId() const { return eps_bearer_id_; }

    // Subscriber identifiers
    std::optional<std::string> getImsi() const { return imsi_; }
    std::optional<std::string> getImei() const { return imei_; }
    std::optional<std::string> getImeisv() const { return imeisv_; }
    std::optional<Guti4G> getGuti() const { return guti_; }
    std::optional<uint32_t> getTmsi() const { return tmsi_; }

    // APN (for ESM)
    std::optional<std::string> getApn() const { return apn_; }

    // PDN Address (for ESM)
    std::optional<std::string> getPdnAddress() const { return pdn_address_; }
    std::optional<NasPdnType> getPdnType() const { return pdn_type_; }

    // QoS (for ESM)
    std::optional<uint8_t> getQci() const { return qci_; }

    // Linked EPS Bearer ID (for ESM dedicated bearer)
    std::optional<uint8_t> getLinkedEpsBearerId() const { return linked_eps_bearer_id_; }

    // Causes
    std::optional<EmmCause> getEmmCause() const { return emm_cause_; }
    std::optional<EsmCause> getEsmCause() const { return esm_cause_; }

    // Attach Type (for EMM Attach Request)
    std::optional<EpsAttachType> getAttachType() const { return attach_type_; }

    // Update Type (for EMM TAU Request)
    std::optional<EpsUpdateType> getUpdateType() const { return update_type_; }

    // PDN Request Type (for ESM PDN Connectivity Request)
    std::optional<PdnRequestType> getRequestType() const { return request_type_; }

    // ESM Message Container (for EMM messages containing ESM)
    std::optional<std::vector<uint8_t>> getEsmMessageContainer() const { return esm_message_container_; }

    // Tracking Area Identity
    struct TrackingAreaIdentity {
        std::string mcc;
        std::string mnc;
        uint16_t tac;
        std::string toString() const;
    };
    std::optional<TrackingAreaIdentity> getTai() const { return tai_; }

    // Direction (derived from message type)
    enum class Direction {
        UPLINK,      // UE -> MME
        DOWNLINK,    // MME -> UE
        UNKNOWN
    };
    Direction getDirection() const;

    // Raw data
    const std::vector<uint8_t>& getRawData() const { return raw_data_; }

    // Setters (for parser)
    void setProtocolDiscriminator(NasProtocolDiscriminator pd) { protocol_discriminator_ = pd; }
    void setSecurityHeaderType(NasSecurityHeaderType sht) { security_header_type_ = sht; }
    void setEmmMessageType(NasEmmMessageType type) { emm_message_type_ = type; }
    void setEsmMessageType(NasEsmMessageType type) { esm_message_type_ = type; }
    void setPti(uint8_t pti) { pti_ = pti; }
    void setEpsBearerId(uint8_t ebi) { eps_bearer_id_ = ebi; }
    void setImsi(const std::string& imsi) { imsi_ = imsi; }
    void setImei(const std::string& imei) { imei_ = imei; }
    void setImeisv(const std::string& imeisv) { imeisv_ = imeisv; }
    void setGuti(const Guti4G& guti) { guti_ = guti; }
    void setTmsi(uint32_t tmsi) { tmsi_ = tmsi; }
    void setApn(const std::string& apn) { apn_ = apn; }
    void setPdnAddress(const std::string& addr) { pdn_address_ = addr; }
    void setPdnType(NasPdnType type) { pdn_type_ = type; }
    void setQci(uint8_t qci) { qci_ = qci; }
    void setLinkedEpsBearerId(uint8_t lbi) { linked_eps_bearer_id_ = lbi; }
    void setEmmCause(EmmCause cause) { emm_cause_ = cause; }
    void setEsmCause(EsmCause cause) { esm_cause_ = cause; }
    void setAttachType(EpsAttachType type) { attach_type_ = type; }
    void setUpdateType(EpsUpdateType type) { update_type_ = type; }
    void setRequestType(PdnRequestType type) { request_type_ = type; }
    void setEsmMessageContainer(const std::vector<uint8_t>& container) { esm_message_container_ = container; }
    void setTai(const TrackingAreaIdentity& tai) { tai_ = tai; }
    void setRawData(const uint8_t* data, size_t length) { raw_data_.assign(data, data + length); }

    // String representation
    std::string toString() const;

private:
    // Metadata
    uint32_t frame_num_ = 0;
    double timestamp_ = 0.0;

    // NAS header
    NasProtocolDiscriminator protocol_discriminator_ = NasProtocolDiscriminator::EPS_MOBILITY_MANAGEMENT;
    NasSecurityHeaderType security_header_type_ = NasSecurityHeaderType::PLAIN_NAS;

    // Message type
    std::optional<NasEmmMessageType> emm_message_type_;
    std::optional<NasEsmMessageType> esm_message_type_;

    // ESM-specific
    std::optional<uint8_t> pti_;
    std::optional<uint8_t> eps_bearer_id_;

    // Subscriber identifiers
    std::optional<std::string> imsi_;
    std::optional<std::string> imei_;
    std::optional<std::string> imeisv_;
    std::optional<Guti4G> guti_;
    std::optional<uint32_t> tmsi_;

    // PDN information (ESM)
    std::optional<std::string> apn_;
    std::optional<std::string> pdn_address_;
    std::optional<NasPdnType> pdn_type_;
    std::optional<uint8_t> qci_;
    std::optional<uint8_t> linked_eps_bearer_id_;

    // Causes
    std::optional<EmmCause> emm_cause_;
    std::optional<EsmCause> esm_cause_;

    // Procedure-specific
    std::optional<EpsAttachType> attach_type_;
    std::optional<EpsUpdateType> update_type_;
    std::optional<PdnRequestType> request_type_;

    // ESM message container (inside EMM messages)
    std::optional<std::vector<uint8_t>> esm_message_container_;

    // Tracking Area
    std::optional<TrackingAreaIdentity> tai_;

    // Raw data
    std::vector<uint8_t> raw_data_;
};

} // namespace correlation
} // namespace callflow
