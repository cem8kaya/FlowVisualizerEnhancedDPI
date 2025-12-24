#pragma once

#include "subscriber_identity.h"
#include "msisdn_normalizer.h"
#include "imsi_normalizer.h"
#include "imei_normalizer.h"
#include "guti_parser.h"

namespace callflow {
namespace correlation {

/**
 * @brief Match confidence levels
 */
enum class MatchConfidence {
    EXACT,      // Perfect match (IMSI, IMEI, etc.)
    HIGH,       // High confidence (MSISDN international match, IP+APN match)
    MEDIUM,     // Medium confidence (MSISDN national match, IP match)
    LOW,        // Low confidence (suffix match, IP prefix match)
    NONE        // No match
};

/**
 * @brief Match result with details
 */
struct MatchResult {
    MatchConfidence confidence;
    std::string reason;
    float score;  // 0.0 to 1.0

    bool isMatch() const {
        return confidence != MatchConfidence::NONE;
    }

    bool isHighConfidence() const {
        return confidence == MatchConfidence::EXACT || confidence == MatchConfidence::HIGH;
    }
};

/**
 * @brief Identity matching algorithms for VoLTE correlation
 */
class IdentityMatcher {
public:
    /**
     * @brief Match two subscriber identities
     * @param id1 First subscriber identity
     * @param id2 Second subscriber identity
     * @return Match result with confidence and reason
     */
    static MatchResult match(const SubscriberIdentity& id1, const SubscriberIdentity& id2);

    /**
     * @brief Match by IMSI (exact match only)
     */
    static MatchResult matchByImsi(const SubscriberIdentity& id1, const SubscriberIdentity& id2);

    /**
     * @brief Match by MSISDN (fuzzy matching)
     */
    static MatchResult matchByMsisdn(const SubscriberIdentity& id1, const SubscriberIdentity& id2);

    /**
     * @brief Match by IMEI (exact match)
     */
    static MatchResult matchByImei(const SubscriberIdentity& id1, const SubscriberIdentity& id2);

    /**
     * @brief Match by GUTI (4G or 5G)
     */
    static MatchResult matchByGuti(const SubscriberIdentity& id1, const SubscriberIdentity& id2);

    /**
     * @brief Match by IP address (IPv4 or IPv6)
     */
    static MatchResult matchByIp(const SubscriberIdentity& id1, const SubscriberIdentity& id2);

    /**
     * @brief Match by IP address and APN (stronger than IP alone)
     */
    static MatchResult matchByIpAndApn(const SubscriberIdentity& id1, const SubscriberIdentity& id2);

    /**
     * @brief Match by GTP-U TEID (tunnel endpoint identifier)
     */
    static MatchResult matchByTeid(const SubscriberIdentity& id1, const SubscriberIdentity& id2);

    /**
     * @brief Calculate overall match score between two identities
     * @return Score from 0.0 (no match) to 1.0 (perfect match)
     */
    static float calculateMatchScore(const SubscriberIdentity& id1, const SubscriberIdentity& id2);

private:
    static float confidenceToScore(MatchConfidence confidence);
    static MatchConfidence scoreToConfidence(float score);
};

} // namespace correlation
} // namespace callflow
