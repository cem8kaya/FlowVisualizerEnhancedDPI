#include <gtest/gtest.h>
#include "correlation/identity/imsi_normalizer.h"

using namespace callflow::correlation;

class ImsiNormalizerTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(ImsiNormalizerTest, NormalizeValidImsi) {
    auto result = ImsiNormalizer::normalize("310260123456789");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->digits, "310260123456789");
    EXPECT_EQ(result->mcc, "310");
    EXPECT_EQ(result->mnc, "260");
    EXPECT_EQ(result->msin, "123456789");
}

TEST_F(ImsiNormalizerTest, NormalizeImsiWithPrefix) {
    auto result = ImsiNormalizer::normalize("imsi-310260123456789");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->digits, "310260123456789");
    EXPECT_EQ(result->mcc, "310");
}

TEST_F(ImsiNormalizerTest, NormalizeImsiWithColonPrefix) {
    auto result = ImsiNormalizer::normalize("imsi:310260123456789");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->digits, "310260123456789");
}

TEST_F(ImsiNormalizerTest, GetPlmn) {
    auto result = ImsiNormalizer::normalize("310260123456789");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->getPlmn(), "310260");
}

TEST_F(ImsiNormalizerTest, InvalidImsiTooShort) {
    auto result = ImsiNormalizer::normalize("12345");
    EXPECT_FALSE(result.has_value());
}

TEST_F(ImsiNormalizerTest, InvalidImsiTooLong) {
    auto result = ImsiNormalizer::normalize("1234567890123456");
    EXPECT_FALSE(result.has_value());
}

TEST_F(ImsiNormalizerTest, InvalidImsiWithLetters) {
    auto result = ImsiNormalizer::normalize("310260ABCDEFGHI");
    EXPECT_FALSE(result.has_value());
}

TEST_F(ImsiNormalizerTest, FromDiameterUsername) {
    auto result = ImsiNormalizer::fromDiameterUsername(
        "310260123456789@ims.mnc260.mcc310.3gppnetwork.org");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->digits, "310260123456789");
}

TEST_F(ImsiNormalizerTest, FromDiameterUsernameWithImsiPrefix) {
    auto result = ImsiNormalizer::fromDiameterUsername(
        "imsi-310260123456789@realm.example.com");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->digits, "310260123456789");
}

TEST_F(ImsiNormalizerTest, FromBcdEncoding) {
    // IMSI: 310260123456789
    // BCD: 13 02 06 21 43 65 87 F9
    uint8_t bcd_data[] = {0x13, 0x02, 0x06, 0x21, 0x43, 0x65, 0x87, 0xF9};
    auto result = ImsiNormalizer::fromBcd(bcd_data, sizeof(bcd_data));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->digits, "310260123456789");
    EXPECT_EQ(result->mcc, "310");
    EXPECT_EQ(result->mnc, "260");
}

TEST_F(ImsiNormalizerTest, FromBcdEncodingWithFiller) {
    // IMSI: 310260123456789 (filler at end)
    uint8_t bcd_data[] = {0x13, 0x02, 0x06, 0x21, 0x43, 0x65, 0x87, 0xF9};
    auto result = ImsiNormalizer::fromBcd(bcd_data, sizeof(bcd_data));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->digits, "310260123456789");
}

TEST_F(ImsiNormalizerTest, FromBcdInvalidData) {
    uint8_t bcd_data[] = {0xFF, 0xFF, 0xFF};
    auto result = ImsiNormalizer::fromBcd(bcd_data, sizeof(bcd_data));
    EXPECT_FALSE(result.has_value());
}

TEST_F(ImsiNormalizerTest, IsValidTrue) {
    EXPECT_TRUE(ImsiNormalizer::isValid("310260123456789"));
}

TEST_F(ImsiNormalizerTest, IsValidFalseWrongLength) {
    EXPECT_FALSE(ImsiNormalizer::isValid("12345"));
    EXPECT_FALSE(ImsiNormalizer::isValid("1234567890123456"));
}

TEST_F(ImsiNormalizerTest, IsValidFalseInvalidMcc) {
    EXPECT_FALSE(ImsiNormalizer::isValid("100260123456789"));  // MCC < 200
    EXPECT_FALSE(ImsiNormalizer::isValid("900260123456789"));  // MCC > 799
}

TEST_F(ImsiNormalizerTest, ExtractMcc) {
    EXPECT_EQ(ImsiNormalizer::extractMcc("310260123456789"), "310");
    EXPECT_EQ(ImsiNormalizer::extractMcc("123"), "123");
    EXPECT_EQ(ImsiNormalizer::extractMcc("12"), "");
}

TEST_F(ImsiNormalizerTest, ExtractMnc2Digit) {
    // Most countries use 2-digit MNC
    EXPECT_EQ(ImsiNormalizer::extractMnc("440201234567890"), "20");
}

TEST_F(ImsiNormalizerTest, ExtractMnc3DigitUSA) {
    // USA (MCC 310) uses 3-digit MNC
    EXPECT_EQ(ImsiNormalizer::extractMnc("310260123456789"), "260");
}

TEST_F(ImsiNormalizerTest, ExtractMsin) {
    auto result = ImsiNormalizer::normalize("310260123456789");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->msin, "123456789");
}

TEST_F(ImsiNormalizerTest, TurkishImsi) {
    // Turkey MCC 286, typically 2-digit MNC
    auto result = ImsiNormalizer::normalize("286011234567890");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->mcc, "286");
    EXPECT_EQ(result->mnc, "01");
}

TEST_F(ImsiNormalizerTest, EqualityOperator) {
    auto imsi1 = ImsiNormalizer::normalize("310260123456789");
    auto imsi2 = ImsiNormalizer::normalize("310260123456789");
    auto imsi3 = ImsiNormalizer::normalize("310260987654321");

    ASSERT_TRUE(imsi1.has_value() && imsi2.has_value() && imsi3.has_value());
    EXPECT_TRUE(*imsi1 == *imsi2);
    EXPECT_FALSE(*imsi1 == *imsi3);
}

TEST_F(ImsiNormalizerTest, HandleEmptyInput) {
    auto result = ImsiNormalizer::normalize("");
    EXPECT_FALSE(result.has_value());
}

TEST_F(ImsiNormalizerTest, HandleNullBcd) {
    auto result = ImsiNormalizer::fromBcd(nullptr, 0);
    EXPECT_FALSE(result.has_value());
}
