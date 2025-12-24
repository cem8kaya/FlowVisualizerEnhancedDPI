#include <gtest/gtest.h>
#include "correlation/identity/identity_matcher.h"
#include "correlation/identity/msisdn_normalizer.h"
#include "correlation/identity/imsi_normalizer.h"
#include "correlation/identity/imei_normalizer.h"

using namespace callflow::correlation;

class IdentityMatcherTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}

    SubscriberIdentity createIdentityWithImsi(const std::string& imsi_str) {
        SubscriberIdentity id;
        id.imsi = ImsiNormalizer::normalize(imsi_str);
        return id;
    }

    SubscriberIdentity createIdentityWithMsisdn(const std::string& msisdn_str) {
        SubscriberIdentity id;
        id.msisdn = MsisdnNormalizer::normalize(msisdn_str);
        return id;
    }

    SubscriberIdentity createIdentityWithImei(const std::string& imei_str) {
        SubscriberIdentity id;
        id.imei = ImeiNormalizer::normalize(imei_str);
        return id;
    }

    SubscriberIdentity createIdentityWithIp(const std::string& ip) {
        SubscriberIdentity id;
        NetworkEndpoint ep;
        ep.ipv4 = ip;
        id.endpoints.push_back(ep);
        return id;
    }
};

TEST_F(IdentityMatcherTest, MatchByImsiExact) {
    auto id1 = createIdentityWithImsi("310260123456789");
    auto id2 = createIdentityWithImsi("310260123456789");

    auto result = IdentityMatcher::matchByImsi(id1, id2);
    EXPECT_TRUE(result.isMatch());
    EXPECT_EQ(result.confidence, MatchConfidence::EXACT);
    EXPECT_EQ(result.score, 1.0f);
}

TEST_F(IdentityMatcherTest, MatchByImsiNoMatch) {
    auto id1 = createIdentityWithImsi("310260123456789");
    auto id2 = createIdentityWithImsi("310260987654321");

    auto result = IdentityMatcher::matchByImsi(id1, id2);
    EXPECT_FALSE(result.isMatch());
    EXPECT_EQ(result.confidence, MatchConfidence::NONE);
}

TEST_F(IdentityMatcherTest, MatchByImsiNotAvailable) {
    SubscriberIdentity id1, id2;
    auto result = IdentityMatcher::matchByImsi(id1, id2);
    EXPECT_FALSE(result.isMatch());
}

TEST_F(IdentityMatcherTest, MatchByMsisdnExact) {
    auto id1 = createIdentityWithMsisdn("+14155551234");
    auto id2 = createIdentityWithMsisdn("sip:+14155551234@domain");

    auto result = IdentityMatcher::matchByMsisdn(id1, id2);
    EXPECT_TRUE(result.isMatch());
    EXPECT_TRUE(result.isHighConfidence());
}

TEST_F(IdentityMatcherTest, MatchByMsisdnNational) {
    auto id1 = createIdentityWithMsisdn("4155551234");
    auto id2 = createIdentityWithMsisdn("04155551234");

    auto result = IdentityMatcher::matchByMsisdn(id1, id2);
    EXPECT_TRUE(result.isMatch());
    EXPECT_EQ(result.confidence, MatchConfidence::HIGH);
}

TEST_F(IdentityMatcherTest, MatchByMsisdnSuffix) {
    auto id1 = createIdentityWithMsisdn("+14155551234");
    auto id2 = createIdentityWithMsisdn("+84155551234");  // Different country code

    auto result = IdentityMatcher::matchByMsisdn(id1, id2);
    EXPECT_TRUE(result.isMatch());
    EXPECT_EQ(result.confidence, MatchConfidence::MEDIUM);
}

TEST_F(IdentityMatcherTest, MatchByImeiExact) {
    auto id1 = createIdentityWithImei("35123456789012");
    auto id2 = createIdentityWithImei("35123456789012");

    auto result = IdentityMatcher::matchByImei(id1, id2);
    EXPECT_TRUE(result.isMatch());
    EXPECT_EQ(result.confidence, MatchConfidence::EXACT);
}

TEST_F(IdentityMatcherTest, MatchByImeiSameTac) {
    auto id1 = createIdentityWithImei("35123456789012");
    auto id2 = createIdentityWithImei("35123456999999");  // Same TAC, different SNR

    auto result = IdentityMatcher::matchByImei(id1, id2);
    EXPECT_TRUE(result.isMatch());
    EXPECT_EQ(result.confidence, MatchConfidence::LOW);
}

TEST_F(IdentityMatcherTest, MatchByIpExact) {
    auto id1 = createIdentityWithIp("192.168.1.100");
    auto id2 = createIdentityWithIp("192.168.1.100");

    auto result = IdentityMatcher::matchByIp(id1, id2);
    EXPECT_TRUE(result.isMatch());
    EXPECT_EQ(result.confidence, MatchConfidence::MEDIUM);
}

TEST_F(IdentityMatcherTest, MatchByIpNoMatch) {
    auto id1 = createIdentityWithIp("192.168.1.100");
    auto id2 = createIdentityWithIp("192.168.1.200");

    auto result = IdentityMatcher::matchByIp(id1, id2);
    EXPECT_FALSE(result.isMatch());
}

TEST_F(IdentityMatcherTest, MatchByIpAndApnHigh) {
    SubscriberIdentity id1, id2;

    NetworkEndpoint ep1, ep2;
    ep1.ipv4 = "192.168.1.100";
    ep2.ipv4 = "192.168.1.100";

    id1.endpoints.push_back(ep1);
    id2.endpoints.push_back(ep2);

    id1.apn = "internet";
    id2.apn = "internet";

    auto result = IdentityMatcher::matchByIpAndApn(id1, id2);
    EXPECT_TRUE(result.isMatch());
    EXPECT_EQ(result.confidence, MatchConfidence::HIGH);
}

TEST_F(IdentityMatcherTest, MatchByIpAndApnDifferentApn) {
    SubscriberIdentity id1, id2;

    NetworkEndpoint ep1, ep2;
    ep1.ipv4 = "192.168.1.100";
    ep2.ipv4 = "192.168.1.100";

    id1.endpoints.push_back(ep1);
    id2.endpoints.push_back(ep2);

    id1.apn = "internet";
    id2.apn = "ims";

    auto result = IdentityMatcher::matchByIpAndApn(id1, id2);
    EXPECT_TRUE(result.isMatch());
    // Should match by IP but not get HIGH confidence due to APN mismatch
    EXPECT_NE(result.confidence, MatchConfidence::HIGH);
}

TEST_F(IdentityMatcherTest, MatchByTeid) {
    SubscriberIdentity id1, id2;

    NetworkEndpoint ep1, ep2;
    ep1.gtpu_teid = 0x12345678;
    ep2.gtpu_teid = 0x12345678;

    id1.endpoints.push_back(ep1);
    id2.endpoints.push_back(ep2);

    auto result = IdentityMatcher::matchByTeid(id1, id2);
    EXPECT_TRUE(result.isMatch());
    EXPECT_EQ(result.confidence, MatchConfidence::HIGH);
}

TEST_F(IdentityMatcherTest, MatchByGutiExact4G) {
    SubscriberIdentity id1, id2;

    Guti4G guti1, guti2;
    guti1.mcc = "310";
    guti1.mnc = "260";
    guti1.m_tmsi = 0x12345678;

    guti2.mcc = "310";
    guti2.mnc = "260";
    guti2.m_tmsi = 0x12345678;

    id1.guti = guti1;
    id2.guti = guti2;

    auto result = IdentityMatcher::matchByGuti(id1, id2);
    EXPECT_TRUE(result.isMatch());
    EXPECT_EQ(result.confidence, MatchConfidence::EXACT);
}

TEST_F(IdentityMatcherTest, MatchByGutiSameMmePool) {
    SubscriberIdentity id1, id2;

    Guti4G guti1, guti2;
    guti1.mcc = "310";
    guti1.mnc = "260";
    guti1.mme_group_id = 1;
    guti1.m_tmsi = 0x12345678;

    guti2.mcc = "310";
    guti2.mnc = "260";
    guti2.mme_group_id = 1;
    guti2.m_tmsi = 0x87654321;  // Different M-TMSI

    id1.guti = guti1;
    id2.guti = guti2;

    auto result = IdentityMatcher::matchByGuti(id1, id2);
    EXPECT_TRUE(result.isMatch());
    EXPECT_EQ(result.confidence, MatchConfidence::LOW);
}

TEST_F(IdentityMatcherTest, MatchOverallImsiPreferred) {
    SubscriberIdentity id1, id2;

    // Both have IMSI and MSISDN, IMSI should take precedence
    id1.imsi = ImsiNormalizer::normalize("310260123456789");
    id1.msisdn = MsisdnNormalizer::normalize("+14155551234");

    id2.imsi = ImsiNormalizer::normalize("310260123456789");
    id2.msisdn = MsisdnNormalizer::normalize("+14155559999");  // Different MSISDN

    auto result = IdentityMatcher::match(id1, id2);
    EXPECT_TRUE(result.isMatch());
    EXPECT_EQ(result.confidence, MatchConfidence::EXACT);
    EXPECT_NE(result.reason.find("IMSI"), std::string::npos);
}

TEST_F(IdentityMatcherTest, CalculateMatchScoreExact) {
    auto id1 = createIdentityWithImsi("310260123456789");
    auto id2 = createIdentityWithImsi("310260123456789");

    float score = IdentityMatcher::calculateMatchScore(id1, id2);
    EXPECT_EQ(score, 1.0f);
}

TEST_F(IdentityMatcherTest, CalculateMatchScoreNoMatch) {
    auto id1 = createIdentityWithImsi("310260123456789");
    auto id2 = createIdentityWithImsi("310260987654321");

    float score = IdentityMatcher::calculateMatchScore(id1, id2);
    EXPECT_EQ(score, 0.0f);
}

TEST_F(IdentityMatcherTest, CalculateMatchScoreMedium) {
    auto id1 = createIdentityWithMsisdn("+14155551234");
    auto id2 = createIdentityWithMsisdn("+84155551234");  // Suffix match

    float score = IdentityMatcher::calculateMatchScore(id1, id2);
    EXPECT_GT(score, 0.5f);
    EXPECT_LT(score, 1.0f);
}

TEST_F(IdentityMatcherTest, MatchResultIsMatch) {
    MatchResult result{MatchConfidence::HIGH, "Test", 0.9f};
    EXPECT_TRUE(result.isMatch());
    EXPECT_TRUE(result.isHighConfidence());

    result.confidence = MatchConfidence::NONE;
    EXPECT_FALSE(result.isMatch());
    EXPECT_FALSE(result.isHighConfidence());
}

TEST_F(IdentityMatcherTest, MatchMultipleEndpoints) {
    SubscriberIdentity id1, id2;

    NetworkEndpoint ep1a, ep1b, ep2;
    ep1a.ipv4 = "192.168.1.100";
    ep1b.ipv4 = "192.168.1.200";
    ep2.ipv4 = "192.168.1.200";

    id1.endpoints.push_back(ep1a);
    id1.endpoints.push_back(ep1b);
    id2.endpoints.push_back(ep2);

    auto result = IdentityMatcher::matchByIp(id1, id2);
    EXPECT_TRUE(result.isMatch());
}
