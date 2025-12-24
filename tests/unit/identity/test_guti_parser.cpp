#include <gtest/gtest.h>
#include "correlation/identity/guti_parser.h"

using namespace callflow::correlation;

class GutiParserTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(GutiParserTest, Parse4GGutiFromBcd) {
    // GUTI: MCC=310, MNC=260, MME-GID=1, MME-CODE=2, M-TMSI=0x12345678
    // BCD: MCC/MNC (3 bytes) + MME-GID (2) + MME-CODE (1) + M-TMSI (4)
    uint8_t guti_data[] = {
        0x13, 0x02, 0x06,           // MCC=310, MNC=260
        0x00, 0x01,                 // MME Group ID = 1
        0x02,                       // MME Code = 2
        0x12, 0x34, 0x56, 0x78,     // M-TMSI = 0x12345678
        0xFF                        // Padding
    };

    auto result = GutiParser::parse4G(guti_data, sizeof(guti_data));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->mcc, "310");
    EXPECT_EQ(result->mnc, "260");
    EXPECT_EQ(result->mme_group_id, 1);
    EXPECT_EQ(result->mme_code, 2);
    EXPECT_EQ(result->m_tmsi, 0x12345678);
}

TEST_F(GutiParserTest, Parse4GGutiInvalidLength) {
    uint8_t guti_data[] = {0x13, 0x02, 0x06};  // Too short
    auto result = GutiParser::parse4G(guti_data, sizeof(guti_data));
    EXPECT_FALSE(result.has_value());
}

TEST_F(GutiParserTest, Parse5GGutiFromBcd) {
    // 5G-GUTI: MCC=310, MNC=260, AMF-REGION=1, AMF-SET=512, AMF-PTR=32, 5G-TMSI=0x87654321
    uint8_t guti_data[] = {
        0x13, 0x02, 0x06,           // MCC=310, MNC=260
        0x01,                       // AMF Region ID = 1
        0x02, 0x20,                 // AMF Set ID (10 bits) = 512, AMF Pointer (6 bits) = 32
        0x87, 0x65, 0x43, 0x21,     // 5G-TMSI = 0x87654321
        0xFF                        // Padding
    };

    auto result = GutiParser::parse5G(guti_data, sizeof(guti_data));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->mcc, "310");
    EXPECT_EQ(result->mnc, "260");
    EXPECT_EQ(result->amf_region_id, 1);
    EXPECT_EQ(result->amf_set_id, 128);  // (0x0220 >> 6) = 128
    EXPECT_EQ(result->fiveG_tmsi, 0x87654321);
}

TEST_F(GutiParserTest, Encode4GGuti) {
    Guti4G guti;
    guti.mcc = "310";
    guti.mnc = "260";
    guti.mme_group_id = 1;
    guti.mme_code = 2;
    guti.m_tmsi = 0x12345678;

    uint8_t output[11];
    size_t written = GutiParser::encode4G(guti, output);

    EXPECT_EQ(written, 11);
    EXPECT_EQ(output[0], 0x13);  // MCC BCD
    EXPECT_EQ(output[1], 0x02);  // MCC/MNC BCD
    EXPECT_EQ(output[2], 0x06);  // MNC BCD
    EXPECT_EQ(output[5], 2);     // MME Code
}

TEST_F(GutiParserTest, Encode5GGuti) {
    Guti5G guti;
    guti.mcc = "310";
    guti.mnc = "260";
    guti.amf_region_id = 1;
    guti.amf_set_id = 512;
    guti.amf_pointer = 32;
    guti.fiveG_tmsi = 0x87654321;

    uint8_t output[11];
    size_t written = GutiParser::encode5G(guti, output);

    EXPECT_EQ(written, 11);
    EXPECT_EQ(output[0], 0x13);  // MCC BCD
    EXPECT_EQ(output[3], 1);     // AMF Region ID
}

TEST_F(GutiParserTest, IsSameMmePoolTrue) {
    Guti4G guti1;
    guti1.mcc = "310";
    guti1.mnc = "260";
    guti1.mme_group_id = 1;
    guti1.mme_code = 2;
    guti1.m_tmsi = 0x12345678;

    Guti4G guti2;
    guti2.mcc = "310";
    guti2.mnc = "260";
    guti2.mme_group_id = 1;
    guti2.mme_code = 3;  // Different MME code
    guti2.m_tmsi = 0x87654321;  // Different M-TMSI

    EXPECT_TRUE(GutiParser::isSameMmePool(guti1, guti2));
}

TEST_F(GutiParserTest, IsSameMmePoolFalseDifferentGroup) {
    Guti4G guti1;
    guti1.mcc = "310";
    guti1.mnc = "260";
    guti1.mme_group_id = 1;
    guti1.m_tmsi = 0x12345678;

    Guti4G guti2;
    guti2.mcc = "310";
    guti2.mnc = "260";
    guti2.mme_group_id = 2;  // Different group
    guti2.m_tmsi = 0x87654321;

    EXPECT_FALSE(GutiParser::isSameMmePool(guti1, guti2));
}

TEST_F(GutiParserTest, IsSameAmfSetTrue) {
    Guti5G guti1;
    guti1.mcc = "310";
    guti1.mnc = "260";
    guti1.amf_region_id = 1;
    guti1.amf_set_id = 512;
    guti1.amf_pointer = 10;
    guti1.fiveG_tmsi = 0x12345678;

    Guti5G guti2;
    guti2.mcc = "310";
    guti2.mnc = "260";
    guti2.amf_region_id = 1;
    guti2.amf_set_id = 512;
    guti2.amf_pointer = 20;  // Different pointer
    guti2.fiveG_tmsi = 0x87654321;  // Different TMSI

    EXPECT_TRUE(GutiParser::isSameAmfSet(guti1, guti2));
}

TEST_F(GutiParserTest, IsSameAmfSetFalseDifferentSet) {
    Guti5G guti1;
    guti1.mcc = "310";
    guti1.mnc = "260";
    guti1.amf_region_id = 1;
    guti1.amf_set_id = 512;
    guti1.fiveG_tmsi = 0x12345678;

    Guti5G guti2;
    guti2.mcc = "310";
    guti2.mnc = "260";
    guti2.amf_region_id = 1;
    guti2.amf_set_id = 256;  // Different set
    guti2.fiveG_tmsi = 0x87654321;

    EXPECT_FALSE(GutiParser::isSameAmfSet(guti1, guti2));
}

TEST_F(GutiParserTest, ExtractMTmsi) {
    Guti4G guti;
    guti.m_tmsi = 0x12345678;
    EXPECT_EQ(GutiParser::extractMTmsi(guti), 0x12345678);
}

TEST_F(GutiParserTest, Extract5GTmsi) {
    Guti5G guti;
    guti.fiveG_tmsi = 0x87654321;
    EXPECT_EQ(GutiParser::extract5GTmsi(guti), 0x87654321);
}

TEST_F(GutiParserTest, Guti4GToString) {
    Guti4G guti;
    guti.mcc = "310";
    guti.mnc = "260";
    guti.mme_group_id = 1;
    guti.mme_code = 2;
    guti.m_tmsi = 0x12345678;

    std::string str = guti.toString();
    EXPECT_NE(str.find("310"), std::string::npos);
    EXPECT_NE(str.find("260"), std::string::npos);
    EXPECT_NE(str.find("12345678"), std::string::npos);
}

TEST_F(GutiParserTest, Guti5GToString) {
    Guti5G guti;
    guti.mcc = "310";
    guti.mnc = "260";
    guti.amf_region_id = 1;
    guti.amf_set_id = 512;
    guti.amf_pointer = 32;
    guti.fiveG_tmsi = 0x87654321;

    std::string str = guti.toString();
    EXPECT_NE(str.find("310"), std::string::npos);
    EXPECT_NE(str.find("260"), std::string::npos);
    EXPECT_NE(str.find("87654321"), std::string::npos);
}

TEST_F(GutiParserTest, Parse4GFrom2DigitMnc) {
    // MCC=440, MNC=20 (UK)
    uint8_t guti_data[] = {
        0x44, 0xF0, 0x02,           // MCC=440, MNC=20 (2-digit, filler=F)
        0x00, 0x01,                 // MME Group ID = 1
        0x02,                       // MME Code = 2
        0x11, 0x22, 0x33, 0x44,     // M-TMSI
        0xFF
    };

    auto result = GutiParser::parse4G(guti_data, sizeof(guti_data));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->mcc, "440");
    EXPECT_EQ(result->mnc, "20");
}

TEST_F(GutiParserTest, EncodeNullOutput) {
    Guti4G guti;
    guti.mcc = "310";
    guti.mnc = "260";
    size_t written = GutiParser::encode4G(guti, nullptr);
    EXPECT_EQ(written, 0);
}
