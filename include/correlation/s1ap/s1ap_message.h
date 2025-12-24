#pragma once

#include "correlation/s1ap/s1ap_types.h"
#include "correlation/nas/nas_message.h"
#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <memory>

namespace callflow {
namespace correlation {

/**
 * @brief Parsed S1AP message container
 *
 * Represents a decoded S1AP message with extracted IEs and
 * any embedded NAS-PDU.
 */
class S1apMessage {
public:
    S1apMessage() = default;
    ~S1apMessage() = default;

    /**
     * @brief Parse S1AP message from raw bytes
     * @param data Raw S1AP message data
     * @param length Length of data
     * @param frame_num Frame number
     * @param timestamp Timestamp
     * @return Parsed S1AP message, or nullopt if parsing fails
     */
    static std::optional<S1apMessage> parse(const uint8_t* data,
                                            size_t length,
                                            uint32_t frame_num,
                                            double timestamp);

    // Message metadata
    uint32_t getFrameNum() const { return frame_num_; }
    double getTimestamp() const { return timestamp_; }

    // Procedure code and message type
    S1apProcedureCode getProcedureCode() const { return procedure_code_; }
    S1apMessageType getMessageType() const { return message_type_; }

    // UE S1AP IDs
    std::optional<uint32_t> getMmeUeS1apId() const { return mme_ue_s1ap_id_; }
    std::optional<uint32_t> getEnbUeS1apId() const { return enb_ue_s1ap_id_; }

    // NAS-PDU (embedded NAS message)
    bool hasNasPdu() const { return nas_pdu_.has_value(); }
    std::optional<NasMessage> getNasPdu() const { return nas_pdu_; }

    // E-RAB information
    struct ErabInfo {
        uint8_t erab_id;
        std::optional<uint8_t> qci;
        std::optional<std::string> transport_layer_address;
        std::optional<uint32_t> gtp_teid;
    };
    const std::vector<ErabInfo>& getErabList() const { return erab_list_; }

    // Cause
    std::optional<S1apCauseType> getCauseType() const { return cause_type_; }
    std::optional<uint8_t> getCauseValue() const { return cause_value_; }

    // RRC Establishment Cause (from Initial UE Message)
    std::optional<RrcEstablishmentCause> getRrcEstablishmentCause() const { return rrc_establishment_cause_; }

    // Tracking Area Identity (TAI)
    struct TrackingAreaIdentity {
        std::string mcc;
        std::string mnc;
        uint16_t tac;
        std::string toString() const;
    };
    std::optional<TrackingAreaIdentity> getTai() const { return tai_; }

    // E-UTRAN CGI (Cell Global Identifier)
    struct EcgiInfo {
        std::string mcc;
        std::string mnc;
        uint32_t cell_id;
        std::string toString() const;
    };
    std::optional<EcgiInfo> getEcgi() const { return ecgi_; }

    // S-TMSI
    struct STmsi {
        uint8_t mmec;      // MME Code
        uint32_t m_tmsi;   // M-TMSI
        std::string toString() const;
    };
    std::optional<STmsi> getStmsi() const { return stmsi_; }

    // Direction
    enum class Direction {
        UPLINK,      // eNB -> MME
        DOWNLINK,    // MME -> eNB
        UNKNOWN
    };
    Direction getDirection() const;

    // Check if this is UE-associated signalling
    bool isUeAssociated() const;

    // Check if message contains NAS-PDU
    bool containsNasPdu() const;

    // Raw data
    const std::vector<uint8_t>& getRawData() const { return raw_data_; }

    // Setters (for parser)
    void setProcedureCode(S1apProcedureCode code) { procedure_code_ = code; }
    void setMessageType(S1apMessageType type) { message_type_ = type; }
    void setMmeUeS1apId(uint32_t id) { mme_ue_s1ap_id_ = id; }
    void setEnbUeS1apId(uint32_t id) { enb_ue_s1ap_id_ = id; }
    void setNasPdu(const NasMessage& nas_pdu) { nas_pdu_ = nas_pdu; }
    void addErab(const ErabInfo& erab) { erab_list_.push_back(erab); }
    void setCause(S1apCauseType type, uint8_t value) { cause_type_ = type; cause_value_ = value; }
    void setRrcEstablishmentCause(RrcEstablishmentCause cause) { rrc_establishment_cause_ = cause; }
    void setTai(const TrackingAreaIdentity& tai) { tai_ = tai; }
    void setEcgi(const EcgiInfo& ecgi) { ecgi_ = ecgi; }
    void setStmsi(const STmsi& stmsi) { stmsi_ = stmsi; }
    void setRawData(const uint8_t* data, size_t length) { raw_data_.assign(data, data + length); }

    // String representation
    std::string toString() const;

private:
    // Metadata
    uint32_t frame_num_ = 0;
    double timestamp_ = 0.0;

    // S1AP header
    S1apProcedureCode procedure_code_ = S1apProcedureCode::INITIAL_UE_MESSAGE;
    S1apMessageType message_type_ = S1apMessageType::UNKNOWN;

    // UE context IDs
    std::optional<uint32_t> mme_ue_s1ap_id_;
    std::optional<uint32_t> enb_ue_s1ap_id_;

    // NAS-PDU
    std::optional<NasMessage> nas_pdu_;

    // E-RAB information
    std::vector<ErabInfo> erab_list_;

    // Cause
    std::optional<S1apCauseType> cause_type_;
    std::optional<uint8_t> cause_value_;

    // RRC Establishment Cause
    std::optional<RrcEstablishmentCause> rrc_establishment_cause_;

    // Location information
    std::optional<TrackingAreaIdentity> tai_;
    std::optional<EcgiInfo> ecgi_;
    std::optional<STmsi> stmsi_;

    // Raw data
    std::vector<uint8_t> raw_data_;
};

} // namespace correlation
} // namespace callflow
