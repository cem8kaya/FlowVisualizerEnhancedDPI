#include "correlation/gtpv2/gtpv2_session.h"
#include <sstream>
#include <iomanip>

namespace callflow {
namespace correlation {

Gtpv2Session::Gtpv2Session(uint32_t control_teid, uint32_t sequence)
    : control_teid_(control_teid), sequence_(sequence) {
}

std::string Gtpv2Session::getSessionKey() const {
    std::stringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(8) << control_teid_
       << "_" << std::setw(8) << sequence_;
    return ss.str();
}

void Gtpv2Session::addMessage(const Gtpv2Message& msg) {
    messages_.push_back(msg);
    updateTimeWindow(msg);
    updateState(msg);
    extractSubscriberInfo(msg);
    extractNetworkInfo(msg);
    extractBearerInfo(msg);
    extractFteids(msg);
}

const Gtpv2Message* Gtpv2Session::findResponse(const Gtpv2Message& request) const {
    for (const auto& msg : messages_) {
        if (msg.matchesRequest(request)) {
            return &msg;
        }
    }
    return nullptr;
}

void Gtpv2Session::addBearer(const GtpBearer& bearer) {
    // Check if bearer already exists
    for (auto& existing : bearers_) {
        if (existing.getEbi() == bearer.getEbi()) {
            // Update existing bearer
            existing = bearer;
            return;
        }
    }
    bearers_.push_back(bearer);
}

GtpBearer* Gtpv2Session::getDefaultBearer() {
    for (auto& bearer : bearers_) {
        if (bearer.isDefault()) {
            return &bearer;
        }
    }
    // First bearer is usually default
    if (!bearers_.empty()) {
        return &bearers_[0];
    }
    return nullptr;
}

const GtpBearer* Gtpv2Session::getDefaultBearer() const {
    for (const auto& bearer : bearers_) {
        if (bearer.isDefault()) {
            return &bearer;
        }
    }
    if (!bearers_.empty()) {
        return &bearers_[0];
    }
    return nullptr;
}

GtpBearer* Gtpv2Session::getBearer(uint8_t ebi) {
    for (auto& bearer : bearers_) {
        if (bearer.getEbi() == ebi) {
            return &bearer;
        }
    }
    return nullptr;
}

const GtpBearer* Gtpv2Session::getBearer(uint8_t ebi) const {
    for (const auto& bearer : bearers_) {
        if (bearer.getEbi() == ebi) {
            return &bearer;
        }
    }
    return nullptr;
}

std::vector<GtpBearer*> Gtpv2Session::getBearers() {
    std::vector<GtpBearer*> result;
    for (auto& bearer : bearers_) {
        result.push_back(&bearer);
    }
    return result;
}

std::vector<const GtpBearer*> Gtpv2Session::getBearers() const {
    std::vector<const GtpBearer*> result;
    for (const auto& bearer : bearers_) {
        result.push_back(&bearer);
    }
    return result;
}

std::vector<GtpBearer*> Gtpv2Session::getDedicatedBearers() {
    std::vector<GtpBearer*> result;
    for (auto& bearer : bearers_) {
        if (bearer.isDedicated()) {
            result.push_back(&bearer);
        }
    }
    return result;
}

std::vector<const GtpBearer*> Gtpv2Session::getDedicatedBearers() const {
    std::vector<const GtpBearer*> result;
    for (const auto& bearer : bearers_) {
        if (bearer.isDedicated()) {
            result.push_back(&bearer);
        }
    }
    return result;
}

bool Gtpv2Session::hasDedicatedBearers() const {
    for (const auto& bearer : bearers_) {
        if (bearer.isDedicated()) {
            return true;
        }
    }
    return false;
}

void Gtpv2Session::setApn(const std::string& apn) {
    apn_ = apn;
    detectPdnClass();
}

void Gtpv2Session::addFteid(const GtpV2FTEID& fteid) {
    // Check if this F-TEID already exists
    for (const auto& existing : fteids_) {
        if (existing.interface_type == fteid.interface_type &&
            existing.teid == fteid.teid) {
            return; // Already have this F-TEID
        }
    }
    fteids_.push_back(fteid);
}

std::optional<GtpV2FTEID> Gtpv2Session::getFteidByInterface(FTEIDInterfaceType iface_type) const {
    for (const auto& fteid : fteids_) {
        if (fteid.interface_type == iface_type) {
            return fteid;
        }
    }
    return std::nullopt;
}

void Gtpv2Session::finalize() {
    if (finalized_) {
        return;
    }

    detectPdnClass();
    linkDedicatedBearers();

    // Create subsessions for each bearer
    for (const auto& bearer : bearers_) {
        Subsession sub;
        sub.type = bearer.isDefault() ? "dflt_ebi" : "ded_ebi";
        sub.idx = std::to_string(bearer.getEbi());
        sub.start_frame = bearer.getStartFrame();
        sub.end_frame = bearer.getEndFrame();
        subsessions_.push_back(sub);
    }

    finalized_ = true;
}

void Gtpv2Session::extractSubscriberInfo(const Gtpv2Message& msg) {
    // Extract IMSI
    if (!imsi_.has_value()) {
        auto imsi = msg.extractImsi();
        if (imsi.has_value()) {
            imsi_ = imsi.value();
        }
    }

    // Extract MSISDN
    if (!msisdn_.has_value()) {
        auto msisdn = msg.extractMsisdn();
        if (msisdn.has_value()) {
            msisdn_ = msisdn.value();
        }
    }

    // Extract MEI
    if (!mei_.has_value()) {
        auto mei = msg.extractMei();
        if (mei.has_value()) {
            mei_ = mei.value();
        }
    }
}

void Gtpv2Session::extractNetworkInfo(const Gtpv2Message& msg) {
    // Extract APN
    if (apn_.empty()) {
        auto apn = msg.extractApn();
        if (apn.has_value()) {
            setApn(apn.value());
        }
    }

    // Extract PDN Address
    auto pdn = msg.extractPdnAddress();
    if (pdn.has_value()) {
        if (pdn->ipv4_address.has_value()) {
            pdn_addr_v4_ = pdn->ipv4_address.value();
        }
        if (pdn->ipv6_address.has_value()) {
            pdn_addr_v6_ = pdn->ipv6_address.value();
        }
    }

    // Extract RAT Type
    if (!rat_type_.has_value()) {
        auto rat = msg.extractRatType();
        if (rat.has_value()) {
            rat_type_ = rat.value();
        }
    }

    // Extract Serving Network
    if (!serving_network_.has_value()) {
        auto network = msg.extractServingNetwork();
        if (network.has_value()) {
            serving_network_ = network->getPlmnId();
        }
    }
}

void Gtpv2Session::extractBearerInfo(const Gtpv2Message& msg) {
    auto bearer_contexts = msg.extractBearerContexts();

    for (const auto& ctx : bearer_contexts) {
        if (!ctx.eps_bearer_id.has_value()) {
            continue;
        }

        uint8_t ebi = ctx.eps_bearer_id.value();
        GtpBearer* bearer = getBearer(ebi);

        if (!bearer) {
            // Create new bearer
            GtpBearer new_bearer(ebi);
            new_bearer.setStartTime(msg.getTimestamp());
            new_bearer.setStartFrame(msg.getFrameNumber());
            new_bearer.updateFromBearerContext(ctx);
            addBearer(new_bearer);
        } else {
            // Update existing bearer
            bearer->updateFromBearerContext(ctx);
            bearer->setEndTime(msg.getTimestamp());
            bearer->setEndFrame(msg.getFrameNumber());
        }
    }
}

void Gtpv2Session::extractFteids(const Gtpv2Message& msg) {
    auto fteids = msg.extractAllFteids();
    for (const auto& fteid : fteids) {
        addFteid(fteid);

        // Also update bearers with F-TEID info
        auto bearer_contexts = msg.extractBearerContexts();
        for (const auto& ctx : bearer_contexts) {
            if (ctx.eps_bearer_id.has_value()) {
                auto* bearer = getBearer(ctx.eps_bearer_id.value());
                if (bearer) {
                    for (const auto& ctx_fteid : ctx.fteids) {
                        bearer->updateFteid(ctx_fteid);
                    }
                }
            }
        }
    }
}

void Gtpv2Session::detectPdnClass() {
    if (!apn_.empty()) {
        pdn_class_ = classifyPdnFromApn(apn_);
    }
}

void Gtpv2Session::updateTimeWindow(const Gtpv2Message& msg) {
    double timestamp = msg.getTimestamp();
    uint32_t frame = msg.getFrameNumber();

    if (start_time_ == 0.0 || timestamp < start_time_) {
        start_time_ = timestamp;
    }
    if (end_time_ == 0.0 || timestamp > end_time_) {
        end_time_ = timestamp;
    }

    if (start_frame_ == 0 || frame < start_frame_) {
        start_frame_ = frame;
    }
    if (end_frame_ == 0 || frame > end_frame_) {
        end_frame_ = frame;
    }
}

void Gtpv2Session::updateState(const Gtpv2Message& msg) {
    auto msg_type = msg.getMessageType();

    switch (msg_type) {
        case GtpV2MessageType::CREATE_SESSION_REQUEST:
            state_ = State::CREATING;
            break;

        case GtpV2MessageType::CREATE_SESSION_RESPONSE:
            if (msg.isSuccess()) {
                state_ = State::ACTIVE;
            }
            break;

        case GtpV2MessageType::MODIFY_BEARER_REQUEST:
        case GtpV2MessageType::UPDATE_BEARER_REQUEST:
        case GtpV2MessageType::MODIFY_ACCESS_BEARERS_REQUEST:
            if (state_ == State::ACTIVE) {
                state_ = State::MODIFYING;
            }
            break;

        case GtpV2MessageType::MODIFY_BEARER_RESPONSE:
        case GtpV2MessageType::UPDATE_BEARER_RESPONSE:
        case GtpV2MessageType::MODIFY_ACCESS_BEARERS_RESPONSE:
            if (state_ == State::MODIFYING && msg.isSuccess()) {
                state_ = State::ACTIVE;
            }
            break;

        case GtpV2MessageType::DELETE_SESSION_REQUEST:
            state_ = State::DELETING;
            break;

        case GtpV2MessageType::DELETE_SESSION_RESPONSE:
            state_ = State::DELETED;
            break;

        default:
            break;
    }
}

void Gtpv2Session::linkDedicatedBearers() {
    // Identify default bearer (typically the first one or lowest EBI)
    if (bearers_.empty()) {
        return;
    }

    // Find bearer with lowest EBI - this is usually the default
    uint8_t min_ebi = 255;
    GtpBearer* default_bearer = nullptr;
    for (auto& bearer : bearers_) {
        if (bearer.getEbi() < min_ebi) {
            min_ebi = bearer.getEbi();
            default_bearer = &bearer;
        }
    }

    if (default_bearer) {
        default_bearer->setType(BearerType::DEFAULT);

        // All other bearers are dedicated and link to default
        for (auto& bearer : bearers_) {
            if (bearer.getEbi() != min_ebi) {
                bearer.setType(BearerType::DEDICATED);
                bearer.setLbi(min_ebi);
            }
        }
    }
}

} // namespace correlation
} // namespace callflow
