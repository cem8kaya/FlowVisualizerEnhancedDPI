#include "correlation/gtpv2/gtpv2_bearer.h"

namespace callflow {
namespace correlation {

GtpBearer::GtpBearer(uint8_t ebi) : ebi_(ebi) {
    // Default bearers typically have EBI 5-9
    // Dedicated bearers have EBI 6-15 and link to default
    if (ebi >= 5 && ebi <= 15) {
        // Will be determined later by LBI
        type_ = BearerType::DEFAULT;
    }
}

void GtpBearer::updateFromBearerContext(const gtp::GtpV2BearerContext& ctx) {
    // Update EPS Bearer ID
    if (ctx.eps_bearer_id.has_value()) {
        ebi_ = ctx.eps_bearer_id.value();
    }

    // Update QoS
    if (ctx.qos.has_value()) {
        qci_ = ctx.qos->qci;
        mbr_ul_ = ctx.qos->max_bitrate_uplink;
        mbr_dl_ = ctx.qos->max_bitrate_downlink;
        gbr_ul_ = ctx.qos->guaranteed_bitrate_uplink;
        gbr_dl_ = ctx.qos->guaranteed_bitrate_downlink;
    }

    // Update F-TEIDs
    for (const auto& fteid : ctx.fteids) {
        updateFteid(fteid);
    }

    // Update charging ID
    if (ctx.charging_id.has_value()) {
        charging_id_ = ctx.charging_id.value();
    }

    // Update state based on cause
    if (ctx.cause.has_value()) {
        if (isSuccessCause(ctx.cause.value())) {
            state_ = State::ACTIVE;
        }
    }
}

void GtpBearer::updateFteid(const GtpV2FTEID& fteid) {
    switch (fteid.interface_type) {
        case FTEIDInterfaceType::S1_U_ENODEB_GTP_U:
            if (fteid.ipv4_address.has_value()) {
                s1u_enb_ip_ = fteid.ipv4_address.value();
            }
            s1u_enb_teid_ = fteid.teid;
            break;

        case FTEIDInterfaceType::S1_U_SGW_GTP_U:
            if (fteid.ipv4_address.has_value()) {
                s1u_sgw_ip_ = fteid.ipv4_address.value();
            }
            s1u_sgw_teid_ = fteid.teid;
            break;

        case FTEIDInterfaceType::S5_S8_PGW_GTP_U:
            if (fteid.ipv4_address.has_value()) {
                s5_pgw_ip_ = fteid.ipv4_address.value();
            }
            s5_pgw_teid_ = fteid.teid;
            break;

        case FTEIDInterfaceType::S5_S8_SGW_GTP_U:
            if (fteid.ipv4_address.has_value()) {
                s5_sgw_ip_ = fteid.ipv4_address.value();
            }
            s5_sgw_teid_ = fteid.teid;
            break;

        default:
            // Other interface types not relevant for user plane
            break;
    }
}

} // namespace correlation
} // namespace callflow
