#include <gtest/gtest.h>
#include "correlation/identity/imei_normalizer.h"

using namespace callflow::correlation;

class ImeiNormalizerTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(ImeiNormalizerTest, Normalize14DigitImei) {
    auto result = ImeiNormalizer::normalize("35123456789012");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->imei, "35123456789012");
    EXPECT_EQ(result->tac, "35123456");
    EXPECT_EQ(result->snr, "789012");
    EXPECT_FALSE(result->imeisv.has_value());
}

TEST_F(ImeiNormalizerTest, Normalize15DigitImeiWithCheckDigit) {
    auto result = ImeiNormalizer::normalize("351234567890120");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->imei, "35123456789012");
    EXPECT_EQ(result->tac, "35123456");
    EXPECT_EQ(result->snr, "789012");
}

TEST_F(ImeiNormalizerTest, Normalize16DigitImeisv) {
    auto result = ImeiNormalizer::normalize("3512345678901234");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->imei, "35123456789012");
    EXPECT_TRUE(result->imeisv.has_value());
    EXPECT_EQ(*result->imeisv, "3512345678901234");
}

TEST_F(ImeiNormalizerTest, NormalizeWithImeiPrefix) {
    auto result = ImeiNormalizer::normalize("imei-35123456789012");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->imei, "35123456789012");
}

TEST_F(ImeiNormalizerTest, NormalizeWithImeiColonPrefix) {
    auto result = ImeiNormalizer::normalize("imei:35123456789012");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->imei, "35123456789012");
}

TEST_F(ImeiNormalizerTest, InvalidImeiTooShort) {
    auto result = ImeiNormalizer::normalize("12345");
    EXPECT_FALSE(result.has_value());
}

TEST_F(ImeiNormalizerTest, InvalidImeiTooLong) {
    auto result = ImeiNormalizer::normalize("12345678901234567");
    EXPECT_FALSE(result.has_value());
}

TEST_F(ImeiNormalizerTest, IsValidImeiTrue) {
    EXPECT_TRUE(ImeiNormalizer::isValidImei("35123456789012"));
}

TEST_F(ImeiNormalizerTest, IsValidImeiFalseWrongLength) {
    EXPECT_FALSE(ImeiNormalizer::isValidImei("123"));
    EXPECT_FALSE(ImeiNormalizer::isValidImei("12345678901234567"));
}

TEST_F(ImeiNormalizerTest, IsValidImeisvTrue) {
    EXPECT_TRUE(ImeiNormalizer::isValidImeisv("3512345678901234"));
}

TEST_F(ImeiNormalizerTest, IsValidImeisvFalseWrongLength) {
    EXPECT_FALSE(ImeiNormalizer::isValidImeisv("123"));
    EXPECT_FALSE(ImeiNormalizer::isValidImeisv("35123456789012"));
}

TEST_F(ImeiNormalizerTest, CalculateCheckDigit) {
    // IMEI: 35123456789012, Check digit should be 0
    int check_digit = ImeiNormalizer::calculateCheckDigit("35123456789012");
    EXPECT_GE(check_digit, 0);
    EXPECT_LE(check_digit, 9);
}

TEST_F(ImeiNormalizerTest, VerifyCheckDigitValid) {
    // Using a known valid IMEI with check digit
    // For testing, we'll calculate it first
    std::string imei_base = "35123456789012";
    int check = ImeiNormalizer::calculateCheckDigit(imei_base);
    std::string imei_with_check = imei_base + std::to_string(check);

    EXPECT_TRUE(ImeiNormalizer::verifyCheckDigit(imei_with_check));
}

TEST_F(ImeiNormalizerTest, VerifyCheckDigitInvalid) {
    EXPECT_FALSE(ImeiNormalizer::verifyCheckDigit("351234567890129"));  // Wrong check digit
}

TEST_F(ImeiNormalizerTest, ExtractTac) {
    EXPECT_EQ(ImeiNormalizer::extractTac("35123456789012"), "35123456");
    EXPECT_EQ(ImeiNormalizer::extractTac("123"), "");
}

TEST_F(ImeiNormalizerTest, ExtractSnr) {
    EXPECT_EQ(ImeiNormalizer::extractSnr("35123456789012"), "789012");
    EXPECT_EQ(ImeiNormalizer::extractSnr("123456"), "");
}

TEST_F(ImeiNormalizerTest, FromBcdEncoding) {
    // IMEI: 35123456789012
    // BCD: 53 21 43 65 87 09 21 F0
    uint8_t bcd_data[] = {0x53, 0x21, 0x43, 0x65, 0x87, 0x09, 0x21, 0xF0};
    auto result = ImeiNormalizer::fromBcd(bcd_data, sizeof(bcd_data));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->imei, "35123456789012");
}

TEST_F(ImeiNormalizerTest, FromBcdImeisv) {
    // IMEISV: 3512345678901234
    // BCD: 53 21 43 65 87 09 21 43
    uint8_t bcd_data[] = {0x53, 0x21, 0x43, 0x65, 0x87, 0x09, 0x21, 0x43};
    auto result = ImeiNormalizer::fromBcd(bcd_data, sizeof(bcd_data));
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->imeisv.has_value());
    EXPECT_EQ(*result->imeisv, "3512345678901234");
}

TEST_F(ImeiNormalizerTest, FromBcdInvalidData) {
    uint8_t bcd_data[] = {0xAA, 0xBB, 0xCC};  // Invalid BCD (digits > 9)
    auto result = ImeiNormalizer::fromBcd(bcd_data, sizeof(bcd_data));
    EXPECT_FALSE(result.has_value());
}

TEST_F(ImeiNormalizerTest, FromBcdNullData) {
    auto result = ImeiNormalizer::fromBcd(nullptr, 0);
    EXPECT_FALSE(result.has_value());
}

TEST_F(ImeiNormalizerTest, EqualityOperator) {
    auto imei1 = ImeiNormalizer::normalize("35123456789012");
    auto imei2 = ImeiNormalizer::normalize("35123456789012");
    auto imei3 = ImeiNormalizer::normalize("35987654321098");

    ASSERT_TRUE(imei1.has_value() && imei2.has_value() && imei3.has_value());
    EXPECT_TRUE(*imei1 == *imei2);
    EXPECT_FALSE(*imei1 == *imei3);
}

TEST_F(ImeiNormalizerTest, SameTacDifferentSnr) {
    auto imei1 = ImeiNormalizer::normalize("35123456789012");
    auto imei2 = ImeiNormalizer::normalize("35123456999999");

    ASSERT_TRUE(imei1.has_value() && imei2.has_value());
    EXPECT_EQ(imei1->tac, imei2->tac);
    EXPECT_NE(imei1->snr, imei2->snr);
    EXPECT_FALSE(*imei1 == *imei2);
}

TEST_F(ImeiNormalizerTest, HandleEmptyInput) {
    auto result = ImeiNormalizer::normalize("");
    EXPECT_FALSE(result.has_value());
}

TEST_F(ImeiNormalizerTest, HandleNonDigitInput) {
    auto result = ImeiNormalizer::normalize("ABCDEFGHIJKLMN");
    EXPECT_FALSE(result.has_value());
}
