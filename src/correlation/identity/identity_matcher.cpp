#include "correlation/identity/identity_matcher.h"
#include <algorithm>

namespace callflow {
namespace correlation {

MatchResult IdentityMatcher::match(const SubscriberIdentity& id1, const SubscriberIdentity& id2) {
    // Try exact matches first (highest confidence)
    auto imsi_match = matchByImsi(id1, id2);
    if (imsi_match.isMatch()) {
        return imsi_match;
    }

    auto imei_match = matchByImei(id1, id2);
    if (imei_match.isMatch()) {
        return imei_match;
    }

    // Try GUTI match
    auto guti_match = matchByGuti(id1, id2);
    if (guti_match.isMatch()) {
        return guti_match;
    }

    // Try MSISDN match (fuzzy)
    auto msisdn_match = matchByMsisdn(id1, id2);
    if (msisdn_match.isMatch()) {
        return msisdn_match;
    }

    // Try IP+APN match (high confidence)
    auto ip_apn_match = matchByIpAndApn(id1, id2);
    if (ip_apn_match.isHighConfidence()) {
        return ip_apn_match;
    }

    // Try TEID match
    auto teid_match = matchByTeid(id1, id2);
    if (teid_match.isMatch()) {
        return teid_match;
    }

    // Try IP-only match (lower confidence)
    auto ip_match = matchByIp(id1, id2);
    if (ip_match.isMatch()) {
        return ip_match;
    }

    // No match
    return {MatchConfidence::NONE, "No matching identifiers found", 0.0f};
}

MatchResult IdentityMatcher::matchByImsi(const SubscriberIdentity& id1, const SubscriberIdentity& id2) {
    if (!id1.hasImsi() || !id2.hasImsi()) {
        return {MatchConfidence::NONE, "IMSI not available", 0.0f};
    }

    if (*id1.imsi == *id2.imsi) {
        return {MatchConfidence::EXACT, "IMSI exact match: " + id1.imsi->digits, 1.0f};
    }

    return {MatchConfidence::NONE, "IMSI mismatch", 0.0f};
}

MatchResult IdentityMatcher::matchByMsisdn(const SubscriberIdentity& id1, const SubscriberIdentity& id2) {
    if (!id1.hasMsisdn() || !id2.hasMsisdn()) {
        return {MatchConfidence::NONE, "MSISDN not available", 0.0f};
    }

    const auto& m1 = *id1.msisdn;
    const auto& m2 = *id2.msisdn;

    // Exact international match
    if (!m1.international.empty() && !m2.international.empty() &&
        m1.international == m2.international) {
        return {MatchConfidence::EXACT, "MSISDN international exact match: " + m1.international, 1.0f};
    }

    // Exact national match
    if (!m1.national.empty() && !m2.national.empty() &&
        m1.national == m2.national) {
        return {MatchConfidence::HIGH, "MSISDN national exact match: " + m1.national, 0.95f};
    }

    // Fuzzy suffix match (last 9 digits)
    if (MsisdnNormalizer::matches(m1, m2, 9)) {
        return {MatchConfidence::MEDIUM, "MSISDN suffix match (9 digits)", 0.8f};
    }

    // Fuzzy suffix match (last 7 digits) - lower confidence
    if (MsisdnNormalizer::matches(m1, m2, 7)) {
        return {MatchConfidence::LOW, "MSISDN suffix match (7 digits)", 0.6f};
    }

    return {MatchConfidence::NONE, "MSISDN mismatch", 0.0f};
}

MatchResult IdentityMatcher::matchByImei(const SubscriberIdentity& id1, const SubscriberIdentity& id2) {
    if (!id1.hasImei() || !id2.hasImei()) {
        return {MatchConfidence::NONE, "IMEI not available", 0.0f};
    }

    if (*id1.imei == *id2.imei) {
        return {MatchConfidence::EXACT, "IMEI exact match: " + id1.imei->imei, 1.0f};
    }

    // Check if TAC matches (same device type, but different device)
    if (id1.imei->tac == id2.imei->tac && !id1.imei->tac.empty()) {
        return {MatchConfidence::LOW, "IMEI TAC match (same device type): " + id1.imei->tac, 0.3f};
    }

    return {MatchConfidence::NONE, "IMEI mismatch", 0.0f};
}

MatchResult IdentityMatcher::matchByGuti(const SubscriberIdentity& id1, const SubscriberIdentity& id2) {
    // Check 4G GUTI
    if (id1.guti.has_value() && id2.guti.has_value()) {
        const auto& g1 = *id1.guti;
        const auto& g2 = *id2.guti;

        if (g1.m_tmsi == g2.m_tmsi && g1.mcc == g2.mcc && g1.mnc == g2.mnc) {
            return {MatchConfidence::EXACT, "4G GUTI exact match (M-TMSI)", 1.0f};
        }

        // Same MME pool but different M-TMSI (possible handover)
        if (GutiParser::isSameMmePool(g1, g2)) {
            return {MatchConfidence::LOW, "4G GUTI same MME pool", 0.4f};
        }
    }

    // Check 5G-GUTI
    if (id1.guti_5g.has_value() && id2.guti_5g.has_value()) {
        const auto& g1 = *id1.guti_5g;
        const auto& g2 = *id2.guti_5g;

        if (g1.fiveG_tmsi == g2.fiveG_tmsi && g1.mcc == g2.mcc && g1.mnc == g2.mnc) {
            return {MatchConfidence::EXACT, "5G-GUTI exact match (5G-TMSI)", 1.0f};
        }

        // Same AMF set but different 5G-TMSI
        if (GutiParser::isSameAmfSet(g1, g2)) {
            return {MatchConfidence::LOW, "5G-GUTI same AMF set", 0.4f};
        }
    }

    // Check TMSI (standalone)
    if (id1.tmsi.has_value() && id2.tmsi.has_value() &&
        *id1.tmsi == *id2.tmsi) {
        return {MatchConfidence::MEDIUM, "TMSI match", 0.7f};
    }

    if (id1.tmsi_5g.has_value() && id2.tmsi_5g.has_value() &&
        *id1.tmsi_5g == *id2.tmsi_5g) {
        return {MatchConfidence::MEDIUM, "5G-TMSI match", 0.7f};
    }

    return {MatchConfidence::NONE, "GUTI not available or mismatch", 0.0f};
}

MatchResult IdentityMatcher::matchByIp(const SubscriberIdentity& id1, const SubscriberIdentity& id2) {
    if (id1.endpoints.empty() || id2.endpoints.empty()) {
        return {MatchConfidence::NONE, "IP endpoints not available", 0.0f};
    }

    // Check for exact IP match
    for (const auto& ep1 : id1.endpoints) {
        for (const auto& ep2 : id2.endpoints) {
            // IPv4 exact match
            if (ep1.hasIpv4() && ep2.hasIpv4() && ep1.ipv4 == ep2.ipv4) {
                return {MatchConfidence::MEDIUM, "IPv4 exact match: " + ep1.ipv4, 0.75f};
            }

            // IPv6 exact match
            if (ep1.hasIpv6() && ep2.hasIpv6() && ep1.ipv6 == ep2.ipv6) {
                return {MatchConfidence::MEDIUM, "IPv6 exact match: " + ep1.ipv6, 0.75f};
            }

            // IPv6 prefix match (/64)
            if (ep1.hasIpv6() && ep2.hasIpv6()) {
                std::string prefix1 = ep1.getIpv6Prefix(64);
                std::string prefix2 = ep2.getIpv6Prefix(64);
                if (!prefix1.empty() && !prefix2.empty() &&
                    ep1.ipv6.find(prefix2.substr(0, prefix2.find("::/")) ) == 0) {
                    return {MatchConfidence::LOW, "IPv6 prefix match (/64)", 0.5f};
                }
            }
        }
    }

    return {MatchConfidence::NONE, "IP mismatch", 0.0f};
}

MatchResult IdentityMatcher::matchByIpAndApn(const SubscriberIdentity& id1, const SubscriberIdentity& id2) {
    // IP+APN match is stronger than IP alone
    auto ip_match = matchByIp(id1, id2);
    if (!ip_match.isMatch()) {
        return {MatchConfidence::NONE, "IP not matching", 0.0f};
    }

    // Check APN match
    if (!id1.apn.empty() && !id2.apn.empty() && id1.apn == id2.apn) {
        return {MatchConfidence::HIGH, "IP and APN match: " + id1.apn, 0.9f};
    }

    // IP matches but no APN, or APN mismatch
    return ip_match;
}

MatchResult IdentityMatcher::matchByTeid(const SubscriberIdentity& id1, const SubscriberIdentity& id2) {
    if (id1.endpoints.empty() || id2.endpoints.empty()) {
        return {MatchConfidence::NONE, "Endpoints not available", 0.0f};
    }

    // Check for GTP-U TEID match
    for (const auto& ep1 : id1.endpoints) {
        for (const auto& ep2 : id2.endpoints) {
            if (ep1.gtpu_teid.has_value() && ep2.gtpu_teid.has_value() &&
                *ep1.gtpu_teid == *ep2.gtpu_teid) {
                return {MatchConfidence::HIGH, "GTP-U TEID exact match", 0.85f};
            }
        }
    }

    return {MatchConfidence::NONE, "TEID not available or mismatch", 0.0f};
}

float IdentityMatcher::calculateMatchScore(const SubscriberIdentity& id1, const SubscriberIdentity& id2) {
    float max_score = 0.0f;

    // Try all matching methods and take the highest score
    auto imsi_match = matchByImsi(id1, id2);
    max_score = std::max(max_score, imsi_match.score);

    auto imei_match = matchByImei(id1, id2);
    max_score = std::max(max_score, imei_match.score);

    auto guti_match = matchByGuti(id1, id2);
    max_score = std::max(max_score, guti_match.score);

    auto msisdn_match = matchByMsisdn(id1, id2);
    max_score = std::max(max_score, msisdn_match.score);

    auto ip_apn_match = matchByIpAndApn(id1, id2);
    max_score = std::max(max_score, ip_apn_match.score);

    auto teid_match = matchByTeid(id1, id2);
    max_score = std::max(max_score, teid_match.score);

    auto ip_match = matchByIp(id1, id2);
    max_score = std::max(max_score, ip_match.score);

    return max_score;
}

float IdentityMatcher::confidenceToScore(MatchConfidence confidence) {
    switch (confidence) {
        case MatchConfidence::EXACT:  return 1.0f;
        case MatchConfidence::HIGH:   return 0.85f;
        case MatchConfidence::MEDIUM: return 0.65f;
        case MatchConfidence::LOW:    return 0.4f;
        case MatchConfidence::NONE:   return 0.0f;
        default:                      return 0.0f;
    }
}

MatchConfidence IdentityMatcher::scoreToConfidence(float score) {
    if (score >= 0.95f) return MatchConfidence::EXACT;
    if (score >= 0.75f) return MatchConfidence::HIGH;
    if (score >= 0.5f)  return MatchConfidence::MEDIUM;
    if (score >= 0.3f)  return MatchConfidence::LOW;
    return MatchConfidence::NONE;
}

} // namespace correlation
} // namespace callflow
