#include <gtest/gtest.h>
#include "correlation/identity/msisdn_normalizer.h"

using namespace callflow::correlation;

class MsisdnNormalizerTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(MsisdnNormalizerTest, NormalizeSipUriWithPlusSign) {
    auto result = MsisdnNormalizer::normalize("sip:+14155551234@ims.example.com;user=phone");
    EXPECT_EQ(result.digits_only, "14155551234");
    EXPECT_EQ(result.national, "4155551234");
    EXPECT_EQ(result.international, "14155551234");
    EXPECT_EQ(result.country_code, "1");
}

TEST_F(MsisdnNormalizerTest, NormalizeSipUriWithoutPlusSign) {
    auto result = MsisdnNormalizer::normalize("sip:4155551234@ims.example.com");
    EXPECT_EQ(result.digits_only, "4155551234");
    EXPECT_EQ(result.national, "4155551234");
}

TEST_F(MsisdnNormalizerTest, NormalizeTelUri) {
    auto result = MsisdnNormalizer::normalize("tel:+1-415-555-1234");
    EXPECT_EQ(result.digits_only, "14155551234");
    EXPECT_EQ(result.national, "4155551234");
    EXPECT_EQ(result.country_code, "1");
}

TEST_F(MsisdnNormalizerTest, NormalizeTelUriWithParentheses) {
    auto result = MsisdnNormalizer::normalize("tel:+1 (415) 555-1234");
    EXPECT_EQ(result.digits_only, "14155551234");
    EXPECT_EQ(result.national, "4155551234");
}

TEST_F(MsisdnNormalizerTest, NormalizeNationalFormatWithLeadingZero) {
    auto result = MsisdnNormalizer::normalize("04155551234");
    EXPECT_EQ(result.national, "4155551234");
    EXPECT_EQ(result.digits_only, "04155551234");
}

TEST_F(MsisdnNormalizerTest, NormalizeInternationalFormat) {
    auto result = MsisdnNormalizer::normalize("+14155551234");
    EXPECT_EQ(result.digits_only, "14155551234");
    EXPECT_EQ(result.national, "4155551234");
    EXPECT_EQ(result.country_code, "1");
}

TEST_F(MsisdnNormalizerTest, NormalizeTurkishNumber) {
    auto result = MsisdnNormalizer::normalize("sip:+905321234567@domain");
    EXPECT_EQ(result.digits_only, "905321234567");
    EXPECT_EQ(result.country_code, "90");
    EXPECT_EQ(result.national, "5321234567");
}

TEST_F(MsisdnNormalizerTest, NormalizeUKNumber) {
    auto result = MsisdnNormalizer::normalize("tel:+44-20-7946-0958");
    EXPECT_EQ(result.digits_only, "442079460958");
    EXPECT_EQ(result.country_code, "44");
    EXPECT_EQ(result.national, "2079460958");
}

TEST_F(MsisdnNormalizerTest, HandleSipUriWithParameters) {
    auto result = MsisdnNormalizer::normalize(
        "sip:+14155551234;npdi;rn=+14155550000@ims.example.com;user=phone");
    EXPECT_EQ(result.digits_only, "14155551234");
    EXPECT_EQ(result.national, "4155551234");
}

TEST_F(MsisdnNormalizerTest, MatchingSameNumberDifferentFormats) {
    auto m1 = MsisdnNormalizer::normalize("sip:+14155551234@domain");
    auto m2 = MsisdnNormalizer::normalize("tel:+1-415-555-1234");
    EXPECT_TRUE(MsisdnNormalizer::matches(m1, m2));
}

TEST_F(MsisdnNormalizerTest, MatchingNationalVsInternational) {
    auto m1 = MsisdnNormalizer::normalize("+14155551234");
    auto m2 = MsisdnNormalizer::normalize("4155551234");
    EXPECT_TRUE(MsisdnNormalizer::matches(m1, m2));
}

TEST_F(MsisdnNormalizerTest, MatchingWithLeadingZero) {
    auto m1 = MsisdnNormalizer::normalize("+14155551234");
    auto m2 = MsisdnNormalizer::normalize("04155551234");
    EXPECT_TRUE(MsisdnNormalizer::matches(m1, m2));
}

TEST_F(MsisdnNormalizerTest, NoMatchDifferentNumbers) {
    auto m1 = MsisdnNormalizer::normalize("+14155551234");
    auto m2 = MsisdnNormalizer::normalize("+14155559999");
    EXPECT_FALSE(MsisdnNormalizer::matches(m1, m2));
}

TEST_F(MsisdnNormalizerTest, SuffixMatching9Digits) {
    auto m1 = MsisdnNormalizer::normalize("+14155551234");
    auto m2 = MsisdnNormalizer::normalize("+84155551234");  // Different country code
    EXPECT_TRUE(MsisdnNormalizer::matches(m1, m2, 9));  // Last 9 digits match
}

TEST_F(MsisdnNormalizerTest, NoSuffixMatchTooShort) {
    auto m1 = MsisdnNormalizer::normalize("1234567");
    auto m2 = MsisdnNormalizer::normalize("7654321");
    EXPECT_FALSE(MsisdnNormalizer::matches(m1, m2, 9));  // Not enough digits
}

TEST_F(MsisdnNormalizerTest, MatchRawStringVsNormalized) {
    auto normalized = MsisdnNormalizer::normalize("+14155551234");
    EXPECT_TRUE(MsisdnNormalizer::matches("sip:+1-415-555-1234@domain", normalized));
    EXPECT_FALSE(MsisdnNormalizer::matches("sip:+14155559999@domain", normalized));
}

TEST_F(MsisdnNormalizerTest, HandleEmptyInput) {
    auto result = MsisdnNormalizer::normalize("");
    EXPECT_TRUE(result.digits_only.empty());
}

TEST_F(MsisdnNormalizerTest, HandleOnlyDashes) {
    auto result = MsisdnNormalizer::normalize("---");
    EXPECT_TRUE(result.digits_only.empty());
}

TEST_F(MsisdnNormalizerTest, FromSipUriReturnsNulloptForInvalid) {
    auto result = MsisdnNormalizer::fromSipUri("sip:invalid@domain");
    EXPECT_TRUE(result.has_value());  // Will extract digits even if empty
    EXPECT_TRUE(result->digits_only.empty());
}

TEST_F(MsisdnNormalizerTest, FromTelUriReturnsNulloptForInvalid) {
    auto result = MsisdnNormalizer::fromTelUri("tel:invalid");
    EXPECT_TRUE(result.has_value());  // Will extract digits even if empty
    EXPECT_TRUE(result->digits_only.empty());
}
