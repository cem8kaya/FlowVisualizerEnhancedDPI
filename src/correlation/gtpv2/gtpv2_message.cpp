#include "correlation/gtpv2/gtpv2_message.h"
#include "protocol_parsers/gtp/gtpv2_ie_parser.h"

namespace callflow {
namespace correlation {

bool Gtpv2Message::isSuccess() const {
    if (cause_.has_value()) {
        return isSuccessCause(cause_->cause_value);
    }
    return false;
}

bool Gtpv2Message::isError() const {
    if (cause_.has_value()) {
        return !isSuccessCause(cause_->cause_value);
    }
    return false;
}

std::optional<gtp::GtpV2IE> Gtpv2Message::findIE(GtpV2IEType type) const {
    for (const auto& ie : ies_) {
        if (ie.header.type == type) {
            return ie;
        }
    }
    return std::nullopt;
}

std::vector<gtp::GtpV2IE> Gtpv2Message::findAllIEs(GtpV2IEType type) const {
    std::vector<gtp::GtpV2IE> result;
    for (const auto& ie : ies_) {
        if (ie.header.type == type) {
            result.push_back(ie);
        }
    }
    return result;
}

std::optional<std::string> Gtpv2Message::extractImsi() const {
    auto ie = findIE(GtpV2IEType::IMSI);
    if (!ie.has_value()) {
        return std::nullopt;
    }

    auto imsi = gtp::GtpV2IEParser::parseIMSI(ie.value());
    if (imsi.has_value()) {
        return imsi->imsi;
    }

    return std::nullopt;
}

std::optional<std::string> Gtpv2Message::extractMsisdn() const {
    auto ie = findIE(GtpV2IEType::MSISDN);
    if (!ie.has_value()) {
        return std::nullopt;
    }

    return gtp::GtpV2IEParser::parseMSISDN(ie.value());
}

std::optional<std::string> Gtpv2Message::extractMei() const {
    auto ie = findIE(GtpV2IEType::MEI);
    if (!ie.has_value()) {
        return std::nullopt;
    }

    return gtp::GtpV2IEParser::parseMEI(ie.value());
}

std::optional<std::string> Gtpv2Message::extractApn() const {
    auto ie = findIE(GtpV2IEType::APN);
    if (!ie.has_value()) {
        return std::nullopt;
    }

    return gtp::GtpV2IEParser::parseAPN(ie.value());
}

std::optional<GtpV2PDNAddressAllocation> Gtpv2Message::extractPdnAddress() const {
    auto ie = findIE(GtpV2IEType::PAA);
    if (!ie.has_value()) {
        return std::nullopt;
    }

    return gtp::GtpV2IEParser::parsePAA(ie.value());
}

std::optional<RATType> Gtpv2Message::extractRatType() const {
    auto ie = findIE(GtpV2IEType::RAT_TYPE);
    if (!ie.has_value()) {
        return std::nullopt;
    }

    return gtp::GtpV2IEParser::parseRATType(ie.value());
}

std::optional<gtp::GtpV2ServingNetwork> Gtpv2Message::extractServingNetwork() const {
    auto ie = findIE(GtpV2IEType::SERVING_NETWORK);
    if (!ie.has_value()) {
        return std::nullopt;
    }

    return gtp::GtpV2IEParser::parseServingNetwork(ie.value());
}

std::vector<gtp::GtpV2BearerContext> Gtpv2Message::extractBearerContexts() const {
    std::vector<gtp::GtpV2BearerContext> contexts;
    auto ies = findAllIEs(GtpV2IEType::BEARER_CONTEXT);

    for (const auto& ie : ies) {
        auto ctx = gtp::GtpV2IEParser::parseBearerContext(ie);
        if (ctx.has_value()) {
            contexts.push_back(ctx.value());
        }
    }

    return contexts;
}

std::optional<uint8_t> Gtpv2Message::extractEpsBearerId() const {
    auto ie = findIE(GtpV2IEType::EPS_BEARER_ID);
    if (!ie.has_value()) {
        return std::nullopt;
    }

    return gtp::GtpV2IEParser::parseEPSBearerID(ie.value());
}

std::vector<GtpV2FTEID> Gtpv2Message::extractAllFteids() const {
    std::vector<GtpV2FTEID> fteids;

    // Extract F-TEIDs from top-level IEs
    auto fteid_ies = findAllIEs(GtpV2IEType::F_TEID);
    for (const auto& ie : fteid_ies) {
        auto fteid = gtp::GtpV2IEParser::parseFTEID(ie);
        if (fteid.has_value()) {
            fteids.push_back(fteid.value());
        }
    }

    // Extract F-TEIDs from Bearer Contexts
    auto bearer_contexts = extractBearerContexts();
    for (const auto& ctx : bearer_contexts) {
        for (const auto& fteid : ctx.fteids) {
            fteids.push_back(fteid);
        }
    }

    return fteids;
}

std::optional<GtpV2FTEID> Gtpv2Message::extractFteidByInterface(FTEIDInterfaceType type) const {
    auto fteids = extractAllFteids();
    for (const auto& fteid : fteids) {
        if (fteid.interface_type == type) {
            return fteid;
        }
    }
    return std::nullopt;
}

bool Gtpv2Message::matchesRequest(const Gtpv2Message& request) const {
    // Response matches request if sequence numbers match
    // and this is a response while the other is a request
    return isResponse() && request.isRequest() &&
           sequence_ == request.sequence_;
}

} // namespace correlation
} // namespace callflow
