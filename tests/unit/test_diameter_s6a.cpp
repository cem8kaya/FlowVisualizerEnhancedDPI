#include "protocol_parsers/diameter_parser.h"
#include "protocol_parsers/diameter_s6a.h"
#include <gtest/gtest.h>
#include <vector>
#include <cstring>
#include <arpa/inet.h>

using namespace callflow;

/**
 * Helper function to build a Diameter message with AVPs
 */
class DiameterMessageBuilder {
public:
    DiameterMessageBuilder(uint32_t command_code, uint32_t app_id, bool is_request = true) {
        header_.version = 1;
        header_.request_flag = is_request;
        header_.proxiable_flag = true;
        header_.error_flag = false;
        header_.retransmit_flag = false;
        header_.command_code = command_code;
        header_.application_id = app_id;
        header_.hop_by_hop_id = 0x12345678;
        header_.end_to_end_id = 0x87654321;
    }

    DiameterMessageBuilder& addStringAvp(uint32_t code, const std::string& value, bool vendor = false, uint32_t vendor_id = 0) {
        DiameterAvp avp;
        avp.code = code;
        avp.vendor_flag = vendor;
        avp.mandatory_flag = true;
        avp.protected_flag = false;
        avp.vendor_id = vendor_id;
        avp.data.assign(value.begin(), value.end());
        avp.length = (vendor ? 12 : 8) + avp.data.size();
        avps_.push_back(avp);
        return *this;
    }

    DiameterMessageBuilder& addUint32Avp(uint32_t code, uint32_t value, bool vendor = false, uint32_t vendor_id = 0) {
        DiameterAvp avp;
        avp.code = code;
        avp.vendor_flag = vendor;
        avp.mandatory_flag = true;
        avp.protected_flag = false;
        avp.vendor_id = vendor_id;
        uint32_t net_value = htonl(value);
        avp.data.resize(4);
        std::memcpy(avp.data.data(), &net_value, 4);
        avp.length = (vendor ? 12 : 8) + 4;
        avps_.push_back(avp);
        return *this;
    }

    DiameterMessageBuilder& addOctetStringAvp(uint32_t code, const std::vector<uint8_t>& value, bool vendor = false, uint32_t vendor_id = 0) {
        DiameterAvp avp;
        avp.code = code;
        avp.vendor_flag = vendor;
        avp.mandatory_flag = true;
        avp.protected_flag = false;
        avp.vendor_id = vendor_id;
        avp.data = value;
        avp.length = (vendor ? 12 : 8) + avp.data.size();
        avps_.push_back(avp);
        return *this;
    }

    DiameterMessageBuilder& addGroupedAvp(uint32_t code, const std::vector<DiameterAvp>& nested_avps, bool vendor = false, uint32_t vendor_id = 0) {
        DiameterAvp avp;
        avp.code = code;
        avp.vendor_flag = vendor;
        avp.mandatory_flag = true;
        avp.protected_flag = false;
        avp.vendor_id = vendor_id;

        // Serialize nested AVPs
        for (const auto& nested : nested_avps) {
            // AVP code (4 bytes)
            uint32_t net_code = htonl(nested.code);
            avp.data.insert(avp.data.end(),
                           reinterpret_cast<const uint8_t*>(&net_code),
                           reinterpret_cast<const uint8_t*>(&net_code) + 4);

            // Flags (1 byte)
            uint8_t flags = 0;
            if (nested.vendor_flag) flags |= 0x80;
            if (nested.mandatory_flag) flags |= 0x40;
            if (nested.protected_flag) flags |= 0x20;
            avp.data.push_back(flags);

            // Length (3 bytes)
            size_t nested_len = nested.data.size() + (nested.vendor_flag ? 12 : 8);
            avp.data.push_back((nested_len >> 16) & 0xFF);
            avp.data.push_back((nested_len >> 8) & 0xFF);
            avp.data.push_back(nested_len & 0xFF);

            // Vendor ID if needed
            if (nested.vendor_flag) {
                uint32_t net_vendor = htonl(nested.vendor_id);
                avp.data.insert(avp.data.end(),
                               reinterpret_cast<const uint8_t*>(&net_vendor),
                               reinterpret_cast<const uint8_t*>(&net_vendor) + 4);
            }

            // Data
            avp.data.insert(avp.data.end(), nested.data.begin(), nested.data.end());

            // Padding
            size_t padding = (4 - (nested_len % 4)) % 4;
            for (size_t i = 0; i < padding; ++i) {
                avp.data.push_back(0);
            }
        }

        avp.length = (vendor ? 12 : 8) + avp.data.size();
        avps_.push_back(avp);
        return *this;
    }

    DiameterMessage build() {
        DiameterMessage msg;
        msg.header = header_;
        msg.avps = avps_;

        // Calculate message length
        size_t total_len = 20;  // Header
        for (const auto& avp : avps_) {
            total_len += avp.length;
            // Add padding
            size_t padding = (4 - (avp.length % 4)) % 4;
            total_len += padding;
        }
        msg.header.message_length = total_len;

        return msg;
    }

private:
    DiameterHeader header_;
    std::vector<DiameterAvp> avps_;
};

// ============================================================================
// S6a Message Parsing Tests
// ============================================================================

TEST(DiameterS6aTest, IsS6aMessage) {
    DiameterMessage msg;
    msg.header.application_id = DIAMETER_S6A_APPLICATION_ID;

    EXPECT_TRUE(DiameterS6aParser::isS6aMessage(msg));

    msg.header.application_id = 0;
    EXPECT_FALSE(DiameterS6aParser::isS6aMessage(msg));
}

TEST(DiameterS6aTest, ParseUpdateLocationRequest) {
    auto builder = DiameterMessageBuilder(
        static_cast<uint32_t>(DiameterCommandCode::UPDATE_LOCATION),
        DIAMETER_S6A_APPLICATION_ID,
        true  // Request
    );

    builder.addStringAvp(static_cast<uint32_t>(DiameterAvpCode::USER_NAME), "123456789012345")  // IMSI
           .addOctetStringAvp(static_cast<uint32_t>(DiameterS6aAvpCode::VISITED_PLMN_ID),
                             {0x12, 0xF3, 0x45}, true, DIAMETER_VENDOR_ID_3GPP)  // PLMN ID
           .addUint32Avp(static_cast<uint32_t>(DiameterAvpCode::RAT_TYPE),
                        static_cast<uint32_t>(RATType::EUTRAN))
           .addUint32Avp(static_cast<uint32_t>(DiameterS6aAvpCode::ULR_FLAGS),
                        0x21, true, DIAMETER_VENDOR_ID_3GPP);  // Flags: initial attach, single reg

    auto msg = builder.build();
    DiameterS6aParser parser;
    auto s6a_msg = parser.parse(msg);

    ASSERT_TRUE(s6a_msg.has_value());
    EXPECT_EQ(s6a_msg->imsi.value_or(""), "123456789012345");
    ASSERT_TRUE(s6a_msg->ulr.has_value());
    EXPECT_EQ(s6a_msg->ulr->user_name, "123456789012345");
    EXPECT_EQ(s6a_msg->ulr->rat_type, RATType::EUTRAN);
    EXPECT_TRUE(s6a_msg->ulr->ulr_flags.single_registration_indication);
    EXPECT_TRUE(s6a_msg->ulr->ulr_flags.initial_attach_indicator);
}

TEST(DiameterS6aTest, ParseUpdateLocationAnswer) {
    // Build subscription data
    std::vector<DiameterAvp> sub_data_avps;

    DiameterAvp subscriber_status;
    subscriber_status.code = static_cast<uint32_t>(DiameterS6aAvpCode::SUBSCRIBER_STATUS);
    subscriber_status.mandatory_flag = true;
    subscriber_status.vendor_flag = true;
    subscriber_status.vendor_id = DIAMETER_VENDOR_ID_3GPP;
    uint32_t status = htonl(static_cast<uint32_t>(SubscriberStatus::SERVICE_GRANTED));
    subscriber_status.data.resize(4);
    std::memcpy(subscriber_status.data.data(), &status, 4);
    sub_data_avps.push_back(subscriber_status);

    auto builder = DiameterMessageBuilder(
        static_cast<uint32_t>(DiameterCommandCode::UPDATE_LOCATION),
        DIAMETER_S6A_APPLICATION_ID,
        false  // Answer
    );

    builder.addUint32Avp(static_cast<uint32_t>(DiameterAvpCode::RESULT_CODE), 2001)  // DIAMETER_SUCCESS
           .addGroupedAvp(static_cast<uint32_t>(DiameterS6aAvpCode::SUBSCRIPTION_DATA),
                         sub_data_avps, true, DIAMETER_VENDOR_ID_3GPP);

    auto msg = builder.build();
    DiameterS6aParser parser;
    auto s6a_msg = parser.parse(msg);

    ASSERT_TRUE(s6a_msg.has_value());
    ASSERT_TRUE(s6a_msg->ula.has_value());
    EXPECT_EQ(s6a_msg->ula->result_code, 2001);
    ASSERT_TRUE(s6a_msg->ula->subscription_data.has_value());
    EXPECT_EQ(s6a_msg->ula->subscription_data->subscriber_status.value_or(SubscriberStatus::OPERATOR_DETERMINED_BARRING),
             SubscriberStatus::SERVICE_GRANTED);
}

TEST(DiameterS6aTest, ParseAuthenticationInformationRequest) {
    auto builder = DiameterMessageBuilder(
        static_cast<uint32_t>(DiameterCommandCode::AUTHENTICATION_INFORMATION),
        DIAMETER_S6A_APPLICATION_ID,
        true
    );

    builder.addStringAvp(static_cast<uint32_t>(DiameterAvpCode::USER_NAME), "123456789012345")
           .addOctetStringAvp(static_cast<uint32_t>(DiameterS6aAvpCode::VISITED_PLMN_ID),
                             {0x12, 0xF3, 0x45}, true, DIAMETER_VENDOR_ID_3GPP)
           .addUint32Avp(static_cast<uint32_t>(DiameterS6aAvpCode::NUMBER_OF_REQUESTED_VECTORS),
                        3, true, DIAMETER_VENDOR_ID_3GPP);

    auto msg = builder.build();
    DiameterS6aParser parser;
    auto s6a_msg = parser.parse(msg);

    ASSERT_TRUE(s6a_msg.has_value());
    ASSERT_TRUE(s6a_msg->air.has_value());
    EXPECT_EQ(s6a_msg->air->user_name, "123456789012345");
    EXPECT_EQ(s6a_msg->air->number_of_requested_vectors, 3);
}

TEST(DiameterS6aTest, ParseAuthenticationInformationAnswer) {
    // Build E-UTRAN vector
    std::vector<DiameterAvp> vector_avps;

    DiameterAvp rand_avp;
    rand_avp.code = static_cast<uint32_t>(DiameterS6aAvpCode::RAND);
    rand_avp.mandatory_flag = true;
    rand_avp.vendor_flag = true;
    rand_avp.vendor_id = DIAMETER_VENDOR_ID_3GPP;
    rand_avp.data.resize(16);
    for (int i = 0; i < 16; ++i) rand_avp.data[i] = 0xAA;
    vector_avps.push_back(rand_avp);

    DiameterAvp xres_avp;
    xres_avp.code = static_cast<uint32_t>(DiameterS6aAvpCode::XRES);
    xres_avp.mandatory_flag = true;
    xres_avp.vendor_flag = true;
    xres_avp.vendor_id = DIAMETER_VENDOR_ID_3GPP;
    xres_avp.data.resize(16);
    for (int i = 0; i < 16; ++i) xres_avp.data[i] = 0xBB;
    vector_avps.push_back(xres_avp);

    DiameterAvp autn_avp;
    autn_avp.code = static_cast<uint32_t>(DiameterS6aAvpCode::AUTN);
    autn_avp.mandatory_flag = true;
    autn_avp.vendor_flag = true;
    autn_avp.vendor_id = DIAMETER_VENDOR_ID_3GPP;
    autn_avp.data.resize(16);
    for (int i = 0; i < 16; ++i) autn_avp.data[i] = 0xCC;
    vector_avps.push_back(autn_avp);

    DiameterAvp kasme_avp;
    kasme_avp.code = static_cast<uint32_t>(DiameterS6aAvpCode::KASME);
    kasme_avp.mandatory_flag = true;
    kasme_avp.vendor_flag = true;
    kasme_avp.vendor_id = DIAMETER_VENDOR_ID_3GPP;
    kasme_avp.data.resize(32);
    for (int i = 0; i < 32; ++i) kasme_avp.data[i] = 0xDD;
    vector_avps.push_back(kasme_avp);

    // Build authentication info
    std::vector<DiameterAvp> auth_info_avps;

    DiameterMessageBuilder vector_builder(0, 0);
    vector_builder.addGroupedAvp(static_cast<uint32_t>(DiameterS6aAvpCode::E_UTRAN_VECTOR),
                                vector_avps, true, DIAMETER_VENDOR_ID_3GPP);
    auto temp_msg = vector_builder.build();
    auth_info_avps = temp_msg.avps;

    auto builder = DiameterMessageBuilder(
        static_cast<uint32_t>(DiameterCommandCode::AUTHENTICATION_INFORMATION),
        DIAMETER_S6A_APPLICATION_ID,
        false
    );

    builder.addUint32Avp(static_cast<uint32_t>(DiameterAvpCode::RESULT_CODE), 2001)
           .addGroupedAvp(static_cast<uint32_t>(DiameterS6aAvpCode::AUTHENTICATION_INFO),
                         auth_info_avps, true, DIAMETER_VENDOR_ID_3GPP);

    auto msg = builder.build();
    DiameterS6aParser parser;
    auto s6a_msg = parser.parse(msg);

    ASSERT_TRUE(s6a_msg.has_value());
    ASSERT_TRUE(s6a_msg->aia.has_value());
    EXPECT_EQ(s6a_msg->aia->result_code, 2001);
    ASSERT_TRUE(s6a_msg->aia->auth_info.has_value());
    ASSERT_EQ(s6a_msg->aia->auth_info->eutran_vectors.size(), 1);

    const auto& vector = s6a_msg->aia->auth_info->eutran_vectors[0];
    EXPECT_EQ(vector.rand[0], 0xAA);
    EXPECT_EQ(vector.xres[0], 0xBB);
    EXPECT_EQ(vector.autn[0], 0xCC);
    EXPECT_EQ(vector.kasme[0], 0xDD);
}

TEST(DiameterS6aTest, ParsePurgeUERequest) {
    auto builder = DiameterMessageBuilder(
        static_cast<uint32_t>(DiameterCommandCode::PURGE_UE),
        DIAMETER_S6A_APPLICATION_ID,
        true
    );

    builder.addStringAvp(static_cast<uint32_t>(DiameterAvpCode::USER_NAME), "123456789012345");

    auto msg = builder.build();
    DiameterS6aParser parser;
    auto s6a_msg = parser.parse(msg);

    ASSERT_TRUE(s6a_msg.has_value());
    ASSERT_TRUE(s6a_msg->pur.has_value());
    EXPECT_EQ(s6a_msg->pur->user_name, "123456789012345");
}

TEST(DiameterS6aTest, ParsePurgeUEAnswer) {
    auto builder = DiameterMessageBuilder(
        static_cast<uint32_t>(DiameterCommandCode::PURGE_UE),
        DIAMETER_S6A_APPLICATION_ID,
        false
    );

    builder.addUint32Avp(static_cast<uint32_t>(DiameterAvpCode::RESULT_CODE), 2001);

    auto msg = builder.build();
    DiameterS6aParser parser;
    auto s6a_msg = parser.parse(msg);

    ASSERT_TRUE(s6a_msg.has_value());
    ASSERT_TRUE(s6a_msg->pua.has_value());
    EXPECT_EQ(s6a_msg->pua->result_code, 2001);
}

TEST(DiameterS6aTest, ParseCancelLocationRequest) {
    auto builder = DiameterMessageBuilder(
        static_cast<uint32_t>(DiameterCommandCode::CANCEL_LOCATION),
        DIAMETER_S6A_APPLICATION_ID,
        true
    );

    builder.addStringAvp(static_cast<uint32_t>(DiameterAvpCode::USER_NAME), "123456789012345")
           .addUint32Avp(static_cast<uint32_t>(DiameterS6aAvpCode::CANCELLATION_TYPE),
                        static_cast<uint32_t>(CancellationType::SUBSCRIPTION_WITHDRAWAL),
                        true, DIAMETER_VENDOR_ID_3GPP);

    auto msg = builder.build();
    DiameterS6aParser parser;
    auto s6a_msg = parser.parse(msg);

    ASSERT_TRUE(s6a_msg.has_value());
    ASSERT_TRUE(s6a_msg->clr.has_value());
    EXPECT_EQ(s6a_msg->clr->user_name, "123456789012345");
    EXPECT_EQ(s6a_msg->clr->cancellation_type, CancellationType::SUBSCRIPTION_WITHDRAWAL);
}

TEST(DiameterS6aTest, ParseCancelLocationAnswer) {
    auto builder = DiameterMessageBuilder(
        static_cast<uint32_t>(DiameterCommandCode::CANCEL_LOCATION),
        DIAMETER_S6A_APPLICATION_ID,
        false
    );

    builder.addUint32Avp(static_cast<uint32_t>(DiameterAvpCode::RESULT_CODE), 2001);

    auto msg = builder.build();
    DiameterS6aParser parser;
    auto s6a_msg = parser.parse(msg);

    ASSERT_TRUE(s6a_msg.has_value());
    ASSERT_TRUE(s6a_msg->cla.has_value());
    EXPECT_EQ(s6a_msg->cla->result_code, 2001);
}

TEST(DiameterS6aTest, IMSIExtraction) {
    auto builder = DiameterMessageBuilder(
        static_cast<uint32_t>(DiameterCommandCode::UPDATE_LOCATION),
        DIAMETER_S6A_APPLICATION_ID,
        true
    );

    std::string imsi = "310150123456789";
    builder.addStringAvp(static_cast<uint32_t>(DiameterAvpCode::USER_NAME), imsi);

    auto msg = builder.build();
    DiameterS6aParser parser;
    auto s6a_msg = parser.parse(msg);

    ASSERT_TRUE(s6a_msg.has_value());
    ASSERT_TRUE(s6a_msg->imsi.has_value());
    EXPECT_EQ(s6a_msg->imsi.value(), imsi);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
