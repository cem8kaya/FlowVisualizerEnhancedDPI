#include "protocol_parsers/diameter_parser.h"
#include "protocol_parsers/diameter_s6a.h"
#include <gtest/gtest.h>
#include <vector>
#include <cstring>
#include <arpa/inet.h>

using namespace callflow;

/**
 * Helper to create a simple AVP
 */
DiameterAvp createUint32Avp(uint32_t code, uint32_t value, bool vendor = false, uint32_t vendor_id = 0) {
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
    return avp;
}

DiameterAvp createStringAvp(uint32_t code, const std::string& value, bool vendor = false, uint32_t vendor_id = 0) {
    DiameterAvp avp;
    avp.code = code;
    avp.vendor_flag = vendor;
    avp.mandatory_flag = true;
    avp.protected_flag = false;
    avp.vendor_id = vendor_id;
    avp.data.assign(value.begin(), value.end());
    avp.length = (vendor ? 12 : 8) + avp.data.size();
    return avp;
}

/**
 * Create a grouped AVP from nested AVPs
 */
DiameterAvp createGroupedAvp(uint32_t code, const std::vector<DiameterAvp>& nested_avps, bool vendor = false, uint32_t vendor_id = 0) {
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
    return avp;
}

// ============================================================================
// Subscription Data Parsing Tests
// ============================================================================

TEST(DiameterS6aSubscriptionTest, ParseAMBR) {
    std::vector<DiameterAvp> ambr_avps;
    ambr_avps.push_back(createUint32Avp(
        static_cast<uint32_t>(DiameterAvpCode::MAX_REQUESTED_BANDWIDTH_UL),
        100000000  // 100 Mbps
    ));
    ambr_avps.push_back(createUint32Avp(
        static_cast<uint32_t>(DiameterAvpCode::MAX_REQUESTED_BANDWIDTH_DL),
        200000000  // 200 Mbps
    ));

    auto ambr_avp = createGroupedAvp(
        static_cast<uint32_t>(DiameterS6aAvpCode::AMBR),
        ambr_avps,
        true,
        DIAMETER_VENDOR_ID_3GPP
    );

    DiameterS6aParser parser;
    // Use a private method workaround - create a full message instead
    DiameterMessage msg;
    msg.header.application_id = DIAMETER_S6A_APPLICATION_ID;
    msg.header.command_code = static_cast<uint32_t>(DiameterCommandCode::UPDATE_LOCATION);
    msg.header.request_flag = false;
    msg.avps.push_back(createUint32Avp(static_cast<uint32_t>(DiameterAvpCode::RESULT_CODE), 2001));

    std::vector<DiameterAvp> sub_data_avps;
    sub_data_avps.push_back(ambr_avp);
    auto sub_data_avp = createGroupedAvp(
        static_cast<uint32_t>(DiameterS6aAvpCode::SUBSCRIPTION_DATA),
        sub_data_avps,
        true,
        DIAMETER_VENDOR_ID_3GPP
    );
    msg.avps.push_back(sub_data_avp);

    auto s6a_msg = parser.parse(msg);
    ASSERT_TRUE(s6a_msg.has_value());
    ASSERT_TRUE(s6a_msg->ula.has_value());
    ASSERT_TRUE(s6a_msg->ula->subscription_data.has_value());
    ASSERT_TRUE(s6a_msg->ula->subscription_data->ambr.has_value());

    const auto& ambr = s6a_msg->ula->subscription_data->ambr.value();
    EXPECT_EQ(ambr.max_requested_bandwidth_ul, 100000000);
    EXPECT_EQ(ambr.max_requested_bandwidth_dl, 200000000);
}

TEST(DiameterS6aSubscriptionTest, ParseAllocationRetentionPriority) {
    std::vector<DiameterAvp> arp_avps;
    arp_avps.push_back(createUint32Avp(
        static_cast<uint32_t>(DiameterS6aAvpCode::PRIORITY_LEVEL),
        5,
        true,
        DIAMETER_VENDOR_ID_3GPP
    ));
    arp_avps.push_back(createUint32Avp(
        static_cast<uint32_t>(DiameterS6aAvpCode::PRE_EMPTION_CAPABILITY),
        0,  // ENABLED
        true,
        DIAMETER_VENDOR_ID_3GPP
    ));
    arp_avps.push_back(createUint32Avp(
        static_cast<uint32_t>(DiameterS6aAvpCode::PRE_EMPTION_VULNERABILITY),
        1,  // DISABLED
        true,
        DIAMETER_VENDOR_ID_3GPP
    ));

    auto arp_avp = createGroupedAvp(
        static_cast<uint32_t>(DiameterS6aAvpCode::ALLOCATION_RETENTION_PRIORITY),
        arp_avps,
        true,
        DIAMETER_VENDOR_ID_3GPP
    );

    // Create QoS profile with ARP
    std::vector<DiameterAvp> qos_avps;
    qos_avps.push_back(createUint32Avp(
        static_cast<uint32_t>(DiameterAvpCode::QOS_CLASS_IDENTIFIER),
        9  // QCI 9
    ));
    qos_avps.push_back(arp_avp);

    auto qos_avp = createGroupedAvp(
        static_cast<uint32_t>(DiameterS6aAvpCode::EPS_SUBSCRIBED_QOS_PROFILE),
        qos_avps,
        true,
        DIAMETER_VENDOR_ID_3GPP
    );

    // Create APN configuration with QoS
    std::vector<DiameterAvp> apn_config_avps;
    apn_config_avps.push_back(createUint32Avp(
        static_cast<uint32_t>(DiameterS6aAvpCode::CONTEXT_IDENTIFIER),
        1,
        true,
        DIAMETER_VENDOR_ID_3GPP
    ));
    apn_config_avps.push_back(createStringAvp(
        static_cast<uint32_t>(DiameterAvpCode::SERVICE_SELECTION),
        "internet"
    ));
    apn_config_avps.push_back(createUint32Avp(
        static_cast<uint32_t>(DiameterS6aAvpCode::PDN_TYPE),
        static_cast<uint32_t>(PDNType::IPv4v6),
        true,
        DIAMETER_VENDOR_ID_3GPP
    ));
    apn_config_avps.push_back(qos_avp);

    auto apn_config_avp = createGroupedAvp(
        static_cast<uint32_t>(DiameterS6aAvpCode::APN_CONFIGURATION),
        apn_config_avps,
        true,
        DIAMETER_VENDOR_ID_3GPP
    );

    // Create full message
    DiameterMessage msg;
    msg.header.application_id = DIAMETER_S6A_APPLICATION_ID;
    msg.header.command_code = static_cast<uint32_t>(DiameterCommandCode::UPDATE_LOCATION);
    msg.header.request_flag = false;
    msg.avps.push_back(createUint32Avp(static_cast<uint32_t>(DiameterAvpCode::RESULT_CODE), 2001));

    std::vector<DiameterAvp> apn_profile_avps;
    apn_profile_avps.push_back(createUint32Avp(
        static_cast<uint32_t>(DiameterS6aAvpCode::CONTEXT_IDENTIFIER),
        1,
        true,
        DIAMETER_VENDOR_ID_3GPP
    ));
    apn_profile_avps.push_back(apn_config_avp);

    auto apn_profile_avp = createGroupedAvp(
        static_cast<uint32_t>(DiameterS6aAvpCode::APN_CONFIGURATION_PROFILE),
        apn_profile_avps,
        true,
        DIAMETER_VENDOR_ID_3GPP
    );

    std::vector<DiameterAvp> sub_data_avps;
    sub_data_avps.push_back(apn_profile_avp);

    auto sub_data_avp = createGroupedAvp(
        static_cast<uint32_t>(DiameterS6aAvpCode::SUBSCRIPTION_DATA),
        sub_data_avps,
        true,
        DIAMETER_VENDOR_ID_3GPP
    );
    msg.avps.push_back(sub_data_avp);

    DiameterS6aParser parser;
    auto s6a_msg = parser.parse(msg);

    ASSERT_TRUE(s6a_msg.has_value());
    ASSERT_TRUE(s6a_msg->ula.has_value());
    ASSERT_TRUE(s6a_msg->ula->subscription_data.has_value());
    ASSERT_TRUE(s6a_msg->ula->subscription_data->apn_configuration_profile.has_value());

    const auto& profile = s6a_msg->ula->subscription_data->apn_configuration_profile.value();
    ASSERT_EQ(profile.apn_configs.size(), 1);

    const auto& apn = profile.apn_configs[0];
    EXPECT_EQ(apn.service_selection, "internet");
    EXPECT_EQ(apn.pdn_type, PDNType::IPv4v6);
    EXPECT_EQ(apn.qos_profile.qos_class_identifier, 9);

    const auto& arp = apn.qos_profile.allocation_retention_priority;
    EXPECT_EQ(arp.priority_level, 5);
    EXPECT_TRUE(arp.pre_emption_capability);
    EXPECT_FALSE(arp.pre_emption_vulnerability);
}

TEST(DiameterS6aSubscriptionTest, ParseMultipleAPNConfigurations) {
    // Create multiple APN configurations
    std::vector<DiameterAvp> apn_profile_avps;
    apn_profile_avps.push_back(createUint32Avp(
        static_cast<uint32_t>(DiameterS6aAvpCode::CONTEXT_IDENTIFIER),
        1,
        true,
        DIAMETER_VENDOR_ID_3GPP
    ));

    // APN 1: internet
    std::vector<DiameterAvp> apn1_avps;
    apn1_avps.push_back(createUint32Avp(
        static_cast<uint32_t>(DiameterS6aAvpCode::CONTEXT_IDENTIFIER),
        1,
        true,
        DIAMETER_VENDOR_ID_3GPP
    ));
    apn1_avps.push_back(createStringAvp(
        static_cast<uint32_t>(DiameterAvpCode::SERVICE_SELECTION),
        "internet"
    ));
    apn1_avps.push_back(createUint32Avp(
        static_cast<uint32_t>(DiameterS6aAvpCode::PDN_TYPE),
        static_cast<uint32_t>(PDNType::IPv4),
        true,
        DIAMETER_VENDOR_ID_3GPP
    ));

    // Create minimal QoS for APN 1
    std::vector<DiameterAvp> qos1_avps;
    qos1_avps.push_back(createUint32Avp(
        static_cast<uint32_t>(DiameterAvpCode::QOS_CLASS_IDENTIFIER),
        9
    ));
    std::vector<DiameterAvp> arp1_avps;
    arp1_avps.push_back(createUint32Avp(
        static_cast<uint32_t>(DiameterS6aAvpCode::PRIORITY_LEVEL),
        8,
        true,
        DIAMETER_VENDOR_ID_3GPP
    ));
    qos1_avps.push_back(createGroupedAvp(
        static_cast<uint32_t>(DiameterS6aAvpCode::ALLOCATION_RETENTION_PRIORITY),
        arp1_avps,
        true,
        DIAMETER_VENDOR_ID_3GPP
    ));
    apn1_avps.push_back(createGroupedAvp(
        static_cast<uint32_t>(DiameterS6aAvpCode::EPS_SUBSCRIBED_QOS_PROFILE),
        qos1_avps,
        true,
        DIAMETER_VENDOR_ID_3GPP
    ));

    apn_profile_avps.push_back(createGroupedAvp(
        static_cast<uint32_t>(DiameterS6aAvpCode::APN_CONFIGURATION),
        apn1_avps,
        true,
        DIAMETER_VENDOR_ID_3GPP
    ));

    // APN 2: ims
    std::vector<DiameterAvp> apn2_avps;
    apn2_avps.push_back(createUint32Avp(
        static_cast<uint32_t>(DiameterS6aAvpCode::CONTEXT_IDENTIFIER),
        2,
        true,
        DIAMETER_VENDOR_ID_3GPP
    ));
    apn2_avps.push_back(createStringAvp(
        static_cast<uint32_t>(DiameterAvpCode::SERVICE_SELECTION),
        "ims"
    ));
    apn2_avps.push_back(createUint32Avp(
        static_cast<uint32_t>(DiameterS6aAvpCode::PDN_TYPE),
        static_cast<uint32_t>(PDNType::IPv6),
        true,
        DIAMETER_VENDOR_ID_3GPP
    ));

    // Create minimal QoS for APN 2
    std::vector<DiameterAvp> qos2_avps;
    qos2_avps.push_back(createUint32Avp(
        static_cast<uint32_t>(DiameterAvpCode::QOS_CLASS_IDENTIFIER),
        5  // Conversational voice
    ));
    std::vector<DiameterAvp> arp2_avps;
    arp2_avps.push_back(createUint32Avp(
        static_cast<uint32_t>(DiameterS6aAvpCode::PRIORITY_LEVEL),
        2,
        true,
        DIAMETER_VENDOR_ID_3GPP
    ));
    qos2_avps.push_back(createGroupedAvp(
        static_cast<uint32_t>(DiameterS6aAvpCode::ALLOCATION_RETENTION_PRIORITY),
        arp2_avps,
        true,
        DIAMETER_VENDOR_ID_3GPP
    ));
    apn2_avps.push_back(createGroupedAvp(
        static_cast<uint32_t>(DiameterS6aAvpCode::EPS_SUBSCRIBED_QOS_PROFILE),
        qos2_avps,
        true,
        DIAMETER_VENDOR_ID_3GPP
    ));

    apn_profile_avps.push_back(createGroupedAvp(
        static_cast<uint32_t>(DiameterS6aAvpCode::APN_CONFIGURATION),
        apn2_avps,
        true,
        DIAMETER_VENDOR_ID_3GPP
    ));

    auto apn_profile_avp = createGroupedAvp(
        static_cast<uint32_t>(DiameterS6aAvpCode::APN_CONFIGURATION_PROFILE),
        apn_profile_avps,
        true,
        DIAMETER_VENDOR_ID_3GPP
    );

    // Create full message
    DiameterMessage msg;
    msg.header.application_id = DIAMETER_S6A_APPLICATION_ID;
    msg.header.command_code = static_cast<uint32_t>(DiameterCommandCode::UPDATE_LOCATION);
    msg.header.request_flag = false;
    msg.avps.push_back(createUint32Avp(static_cast<uint32_t>(DiameterAvpCode::RESULT_CODE), 2001));

    std::vector<DiameterAvp> sub_data_avps;
    sub_data_avps.push_back(apn_profile_avp);

    auto sub_data_avp = createGroupedAvp(
        static_cast<uint32_t>(DiameterS6aAvpCode::SUBSCRIPTION_DATA),
        sub_data_avps,
        true,
        DIAMETER_VENDOR_ID_3GPP
    );
    msg.avps.push_back(sub_data_avp);

    DiameterS6aParser parser;
    auto s6a_msg = parser.parse(msg);

    ASSERT_TRUE(s6a_msg.has_value());
    ASSERT_TRUE(s6a_msg->ula.has_value());
    ASSERT_TRUE(s6a_msg->ula->subscription_data.has_value());
    ASSERT_TRUE(s6a_msg->ula->subscription_data->apn_configuration_profile.has_value());

    const auto& profile = s6a_msg->ula->subscription_data->apn_configuration_profile.value();
    ASSERT_EQ(profile.apn_configs.size(), 2);

    // Verify APN 1
    const auto& apn1 = profile.apn_configs[0];
    EXPECT_EQ(apn1.context_identifier, 1);
    EXPECT_EQ(apn1.service_selection, "internet");
    EXPECT_EQ(apn1.pdn_type, PDNType::IPv4);
    EXPECT_EQ(apn1.qos_profile.qos_class_identifier, 9);
    EXPECT_EQ(apn1.qos_profile.allocation_retention_priority.priority_level, 8);

    // Verify APN 2
    const auto& apn2 = profile.apn_configs[1];
    EXPECT_EQ(apn2.context_identifier, 2);
    EXPECT_EQ(apn2.service_selection, "ims");
    EXPECT_EQ(apn2.pdn_type, PDNType::IPv6);
    EXPECT_EQ(apn2.qos_profile.qos_class_identifier, 5);
    EXPECT_EQ(apn2.qos_profile.allocation_retention_priority.priority_level, 2);
}

TEST(DiameterS6aSubscriptionTest, ParseCompleteSubscriptionData) {
    // Build complete subscription data with all fields
    std::vector<DiameterAvp> sub_data_avps;

    // Subscriber status
    sub_data_avps.push_back(createUint32Avp(
        static_cast<uint32_t>(DiameterS6aAvpCode::SUBSCRIBER_STATUS),
        static_cast<uint32_t>(SubscriberStatus::SERVICE_GRANTED),
        true,
        DIAMETER_VENDOR_ID_3GPP
    ));

    // MSISDN
    sub_data_avps.push_back(createStringAvp(
        static_cast<uint32_t>(DiameterS6aAvpCode::MSISDN),
        "+14155551234",
        true,
        DIAMETER_VENDOR_ID_3GPP
    ));

    // Network access mode
    sub_data_avps.push_back(createUint32Avp(
        static_cast<uint32_t>(DiameterS6aAvpCode::NETWORK_ACCESS_MODE),
        static_cast<uint32_t>(NetworkAccessMode::ONLY_PACKET),
        true,
        DIAMETER_VENDOR_ID_3GPP
    ));

    // AMBR
    std::vector<DiameterAvp> ambr_avps;
    ambr_avps.push_back(createUint32Avp(
        static_cast<uint32_t>(DiameterAvpCode::MAX_REQUESTED_BANDWIDTH_UL),
        50000000
    ));
    ambr_avps.push_back(createUint32Avp(
        static_cast<uint32_t>(DiameterAvpCode::MAX_REQUESTED_BANDWIDTH_DL),
        100000000
    ));
    sub_data_avps.push_back(createGroupedAvp(
        static_cast<uint32_t>(DiameterS6aAvpCode::AMBR),
        ambr_avps,
        true,
        DIAMETER_VENDOR_ID_3GPP
    ));

    auto sub_data_avp = createGroupedAvp(
        static_cast<uint32_t>(DiameterS6aAvpCode::SUBSCRIPTION_DATA),
        sub_data_avps,
        true,
        DIAMETER_VENDOR_ID_3GPP
    );

    // Create full message
    DiameterMessage msg;
    msg.header.application_id = DIAMETER_S6A_APPLICATION_ID;
    msg.header.command_code = static_cast<uint32_t>(DiameterCommandCode::UPDATE_LOCATION);
    msg.header.request_flag = false;
    msg.avps.push_back(createUint32Avp(static_cast<uint32_t>(DiameterAvpCode::RESULT_CODE), 2001));
    msg.avps.push_back(sub_data_avp);

    DiameterS6aParser parser;
    auto s6a_msg = parser.parse(msg);

    ASSERT_TRUE(s6a_msg.has_value());
    ASSERT_TRUE(s6a_msg->ula.has_value());
    ASSERT_TRUE(s6a_msg->ula->subscription_data.has_value());

    const auto& sub_data = s6a_msg->ula->subscription_data.value();
    ASSERT_TRUE(sub_data.subscriber_status.has_value());
    EXPECT_EQ(sub_data.subscriber_status.value(), SubscriberStatus::SERVICE_GRANTED);

    ASSERT_TRUE(sub_data.msisdn.has_value());
    EXPECT_EQ(sub_data.msisdn.value(), "+14155551234");

    ASSERT_TRUE(sub_data.network_access_mode.has_value());
    EXPECT_EQ(sub_data.network_access_mode.value(), NetworkAccessMode::ONLY_PACKET);

    ASSERT_TRUE(sub_data.ambr.has_value());
    EXPECT_EQ(sub_data.ambr->max_requested_bandwidth_ul, 50000000);
    EXPECT_EQ(sub_data.ambr->max_requested_bandwidth_dl, 100000000);
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
