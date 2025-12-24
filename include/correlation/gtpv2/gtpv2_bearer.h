#pragma once

#include "correlation/gtpv2/gtpv2_types.h"
#include <string>
#include <optional>

namespace callflow {
namespace correlation {

/**
 * @brief Represents a GTP bearer (EPS Bearer)
 *
 * A bearer is a tunnel for user plane traffic.
 * - Default bearer: Created during PDN connection setup (EBI == LBI)
 * - Dedicated bearer: Created for specific QoS requirements (linked via LBI)
 */
class GtpBearer {
public:
    GtpBearer() = default;
    explicit GtpBearer(uint8_t ebi);
    ~GtpBearer() = default;

    // ========================================================================
    // Bearer Identification
    // ========================================================================

    /**
     * @brief EPS Bearer ID (5-15)
     */
    uint8_t getEbi() const { return ebi_; }
    void setEbi(uint8_t ebi) { ebi_ = ebi; }

    /**
     * @brief Linked Bearer ID (for dedicated bearers)
     */
    std::optional<uint8_t> getLbi() const { return lbi_; }
    void setLbi(uint8_t lbi) { lbi_ = lbi; }

    /**
     * @brief Bearer type
     */
    BearerType getType() const { return type_; }
    void setType(BearerType type) { type_ = type; }

    /**
     * @brief Check if this is a default bearer
     */
    bool isDefault() const { return type_ == BearerType::DEFAULT; }

    /**
     * @brief Check if this is a dedicated bearer
     */
    bool isDedicated() const { return type_ == BearerType::DEDICATED; }

    // ========================================================================
    // QoS Information
    // ========================================================================

    /**
     * @brief QoS Class Identifier (1-9)
     */
    std::optional<uint8_t> getQci() const { return qci_; }
    void setQci(uint8_t qci) { qci_ = qci; }

    /**
     * @brief Max Bitrate Uplink (bps)
     */
    std::optional<uint64_t> getMbrUl() const { return mbr_ul_; }
    void setMbrUl(uint64_t mbr) { mbr_ul_ = mbr; }

    /**
     * @brief Max Bitrate Downlink (bps)
     */
    std::optional<uint64_t> getMbrDl() const { return mbr_dl_; }
    void setMbrDl(uint64_t mbr) { mbr_dl_ = mbr; }

    /**
     * @brief Guaranteed Bitrate Uplink (bps)
     */
    std::optional<uint64_t> getGbrUl() const { return gbr_ul_; }
    void setGbrUl(uint64_t gbr) { gbr_ul_ = gbr; }

    /**
     * @brief Guaranteed Bitrate Downlink (bps)
     */
    std::optional<uint64_t> getGbrDl() const { return gbr_dl_; }
    void setGbrDl(uint64_t gbr) { gbr_dl_ = gbr; }

    /**
     * @brief Check if bearer has GBR QoS
     */
    bool isGbr() const {
        return gbr_ul_.has_value() || gbr_dl_.has_value();
    }

    // ========================================================================
    // GTP-U Tunnel Information
    // ========================================================================

    /**
     * @brief S1-U eNodeB endpoint
     */
    std::optional<std::string> getS1uEnbIp() const { return s1u_enb_ip_; }
    void setS1uEnbIp(const std::string& ip) { s1u_enb_ip_ = ip; }

    std::optional<uint32_t> getS1uEnbTeid() const { return s1u_enb_teid_; }
    void setS1uEnbTeid(uint32_t teid) { s1u_enb_teid_ = teid; }

    /**
     * @brief S1-U SGW endpoint
     */
    std::optional<std::string> getS1uSgwIp() const { return s1u_sgw_ip_; }
    void setS1uSgwIp(const std::string& ip) { s1u_sgw_ip_ = ip; }

    std::optional<uint32_t> getS1uSgwTeid() const { return s1u_sgw_teid_; }
    void setS1uSgwTeid(uint32_t teid) { s1u_sgw_teid_ = teid; }

    /**
     * @brief S5/S8 PGW endpoint
     */
    std::optional<std::string> getS5PgwIp() const { return s5_pgw_ip_; }
    void setS5PgwIp(const std::string& ip) { s5_pgw_ip_ = ip; }

    std::optional<uint32_t> getS5PgwTeid() const { return s5_pgw_teid_; }
    void setS5PgwTeid(uint32_t teid) { s5_pgw_teid_ = teid; }

    /**
     * @brief S5/S8 SGW endpoint
     */
    std::optional<std::string> getS5SgwIp() const { return s5_sgw_ip_; }
    void setS5SgwIp(const std::string& ip) { s5_sgw_ip_ = ip; }

    std::optional<uint32_t> getS5SgwTeid() const { return s5_sgw_teid_; }
    void setS5SgwTeid(uint32_t teid) { s5_sgw_teid_ = teid; }

    // ========================================================================
    // Lifecycle
    // ========================================================================

    /**
     * @brief Time window
     */
    double getStartTime() const { return start_time_; }
    void setStartTime(double time) { start_time_ = time; }

    double getEndTime() const { return end_time_; }
    void setEndTime(double time) { end_time_ = time; }

    uint32_t getStartFrame() const { return start_frame_; }
    void setStartFrame(uint32_t frame) { start_frame_ = frame; }

    uint32_t getEndFrame() const { return end_frame_; }
    void setEndFrame(uint32_t frame) { end_frame_ = frame; }

    /**
     * @brief Bearer state
     */
    enum class State {
        CREATING,
        ACTIVE,
        MODIFYING,
        DELETING,
        DELETED
    };

    State getState() const { return state_; }
    void setState(State state) { state_ = state; }

    // ========================================================================
    // Charging
    // ========================================================================

    std::optional<uint32_t> getChargingId() const { return charging_id_; }
    void setChargingId(uint32_t id) { charging_id_ = id; }

    // ========================================================================
    // Update from Bearer Context
    // ========================================================================

    /**
     * @brief Update bearer information from GTPv2 Bearer Context IE
     */
    void updateFromBearerContext(const gtp::GtpV2BearerContext& ctx);

    /**
     * @brief Update F-TEID information
     */
    void updateFteid(const GtpV2FTEID& fteid);

private:
    uint8_t ebi_ = 0;
    std::optional<uint8_t> lbi_;
    BearerType type_ = BearerType::DEFAULT;
    State state_ = State::CREATING;

    // QoS
    std::optional<uint8_t> qci_;
    std::optional<uint64_t> mbr_ul_;
    std::optional<uint64_t> mbr_dl_;
    std::optional<uint64_t> gbr_ul_;
    std::optional<uint64_t> gbr_dl_;

    // GTP-U tunnels
    std::optional<std::string> s1u_enb_ip_;
    std::optional<uint32_t> s1u_enb_teid_;
    std::optional<std::string> s1u_sgw_ip_;
    std::optional<uint32_t> s1u_sgw_teid_;
    std::optional<std::string> s5_pgw_ip_;
    std::optional<uint32_t> s5_pgw_teid_;
    std::optional<std::string> s5_sgw_ip_;
    std::optional<uint32_t> s5_sgw_teid_;

    // Lifecycle
    double start_time_ = 0.0;
    double end_time_ = 0.0;
    uint32_t start_frame_ = 0;
    uint32_t end_frame_ = 0;

    // Charging
    std::optional<uint32_t> charging_id_;
};

} // namespace correlation
} // namespace callflow
