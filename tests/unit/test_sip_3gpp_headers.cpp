#include <gtest/gtest.h>
#include "protocol_parsers/sip_parser.h"
#include "protocol_parsers/sip_3gpp_headers.h"

using namespace callflow;

// ============================================================================
// P-Asserted-Identity Tests
// ============================================================================

TEST(SipPAssertedIdentityTest, ParseSingleIdentity) {
    std::string value = "\"Alice\" <sip:alice@example.com>";
    auto result = SipPAssertedIdentity::parse(value);

    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->size(), 1);
    EXPECT_EQ(result->at(0).display_name, "Alice");
    EXPECT_EQ(result->at(0).uri, "sip:alice@example.com");
}

TEST(SipPAssertedIdentityTest, ParseMultipleIdentities) {
    std::string value = "\"Alice\" <sip:alice@example.com>, <tel:+1234567890>";
    auto result = SipPAssertedIdentity::parse(value);

    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->size(), 2);
    EXPECT_EQ(result->at(0).display_name, "Alice");
    EXPECT_EQ(result->at(0).uri, "sip:alice@example.com");
    EXPECT_EQ(result->at(1).display_name, "");
    EXPECT_EQ(result->at(1).uri, "tel:+1234567890");
}

TEST(SipPAssertedIdentityTest, ParseWithoutDisplayName) {
    std::string value = "<sip:alice@example.com>";
    auto result = SipPAssertedIdentity::parse(value);

    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->size(), 1);
    EXPECT_EQ(result->at(0).display_name, "");
    EXPECT_EQ(result->at(0).uri, "sip:alice@example.com");
}

// ============================================================================
// P-Access-Network-Info Tests
// ============================================================================

TEST(SipPAccessNetworkInfoTest, ParseLteFdd) {
    std::string value = "3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=234150999999999";
    auto result = SipPAccessNetworkInfo::parse(value);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->access_type, SipPAccessNetworkInfo::AccessType::THREEGPP_E_UTRAN_FDD);
    ASSERT_TRUE(result->cell_id.has_value());
    EXPECT_EQ(result->cell_id.value(), "234150999999999");
}

TEST(SipPAccessNetworkInfoTest, ParseLteTdd) {
    std::string value = "3GPP-E-UTRAN-TDD; utran-cell-id-3gpp=234150888888888";
    auto result = SipPAccessNetworkInfo::parse(value);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->access_type, SipPAccessNetworkInfo::AccessType::THREEGPP_E_UTRAN_TDD);
    ASSERT_TRUE(result->cell_id.has_value());
    EXPECT_EQ(result->cell_id.value(), "234150888888888");
}

TEST(SipPAccessNetworkInfoTest, Parse5gNr) {
    std::string value = "3GPP-NR; nrcgi=001010000000001";
    auto result = SipPAccessNetworkInfo::parse(value);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->access_type, SipPAccessNetworkInfo::AccessType::THREEGPP_NR);
    ASSERT_TRUE(result->cell_id.has_value());
    EXPECT_EQ(result->cell_id.value(), "001010000000001");
}

TEST(SipPAccessNetworkInfoTest, ParseWifi) {
    std::string value = "IEEE-802.11";
    auto result = SipPAccessNetworkInfo::parse(value);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->access_type, SipPAccessNetworkInfo::AccessType::IEEE_802_11);
    EXPECT_FALSE(result->cell_id.has_value());
}

TEST(SipPAccessNetworkInfoTest, AccessTypeToString) {
    EXPECT_EQ(SipPAccessNetworkInfo::accessTypeToString(
                  SipPAccessNetworkInfo::AccessType::THREEGPP_E_UTRAN_FDD),
              "3GPP-E-UTRAN-FDD");
    EXPECT_EQ(SipPAccessNetworkInfo::accessTypeToString(
                  SipPAccessNetworkInfo::AccessType::THREEGPP_NR),
              "3GPP-NR");
}

// ============================================================================
// P-Charging-Vector Tests
// ============================================================================

TEST(SipPChargingVectorTest, ParseComplete) {
    std::string value =
        "icid-value=AyretyU0dm+6O2IrT5tAFrbHLso=; icid-generated-at=192.0.2.1; orig-ioi=home1.net; "
        "term-ioi=home2.net";
    auto result = SipPChargingVector::parse(value);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->icid_value, "AyretyU0dm+6O2IrT5tAFrbHLso=");
    ASSERT_TRUE(result->icid_generated_at.has_value());
    EXPECT_EQ(result->icid_generated_at.value(), "192.0.2.1");
    ASSERT_TRUE(result->orig_ioi.has_value());
    EXPECT_EQ(result->orig_ioi.value(), "home1.net");
    ASSERT_TRUE(result->term_ioi.has_value());
    EXPECT_EQ(result->term_ioi.value(), "home2.net");
}

TEST(SipPChargingVectorTest, ParseMinimal) {
    std::string value = "icid-value=1234567890";
    auto result = SipPChargingVector::parse(value);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->icid_value, "1234567890");
    EXPECT_FALSE(result->icid_generated_at.has_value());
    EXPECT_FALSE(result->orig_ioi.has_value());
    EXPECT_FALSE(result->term_ioi.has_value());
}

TEST(SipPChargingVectorTest, ParseMissingIcid) {
    std::string value = "orig-ioi=home1.net";
    auto result = SipPChargingVector::parse(value);

    EXPECT_FALSE(result.has_value());  // ICID is mandatory
}

// ============================================================================
// P-Charging-Function-Addresses Tests
// ============================================================================

TEST(SipPChargingFunctionAddressesTest, ParseMultipleCcf) {
    std::string value = "ccf=192.0.2.10; ccf=192.0.2.11; ecf=192.0.2.20";
    auto result = SipPChargingFunctionAddresses::parse(value);

    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->ccf_addresses.size(), 2);
    EXPECT_EQ(result->ccf_addresses[0], "192.0.2.10");
    EXPECT_EQ(result->ccf_addresses[1], "192.0.2.11");
    ASSERT_EQ(result->ecf_addresses.size(), 1);
    EXPECT_EQ(result->ecf_addresses[0], "192.0.2.20");
}

TEST(SipPChargingFunctionAddressesTest, ParseOnlyCcf) {
    std::string value = "ccf=192.0.2.10";
    auto result = SipPChargingFunctionAddresses::parse(value);

    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->ccf_addresses.size(), 1);
    EXPECT_EQ(result->ccf_addresses[0], "192.0.2.10");
    EXPECT_TRUE(result->ecf_addresses.empty());
}

// ============================================================================
// P-Served-User Tests
// ============================================================================

TEST(SipPServedUserTest, ParseComplete) {
    std::string value = "<sip:user@example.com>; sescase=orig; regstate=reg";
    auto result = SipPServedUser::parse(value);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->user_uri, "sip:user@example.com");
    ASSERT_TRUE(result->sescase.has_value());
    EXPECT_EQ(result->sescase.value(), "orig");
    ASSERT_TRUE(result->regstate.has_value());
    EXPECT_EQ(result->regstate.value(), "reg");
}

TEST(SipPServedUserTest, ParseUriOnly) {
    std::string value = "<sip:user@example.com>";
    auto result = SipPServedUser::parse(value);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->user_uri, "sip:user@example.com");
    EXPECT_FALSE(result->sescase.has_value());
    EXPECT_FALSE(result->regstate.has_value());
}

// ============================================================================
// Security-Client/Server/Verify Tests
// ============================================================================

TEST(SipSecurityInfoTest, ParseIpsec3gpp) {
    std::string value =
        "ipsec-3gpp; alg=hmac-sha-1-96; spi-c=1234; spi-s=5678; port-c=5062; port-s=5064";
    auto result = SipSecurityInfo::parse(value);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->mechanism, "ipsec-3gpp");
    ASSERT_TRUE(result->algorithm.has_value());
    EXPECT_EQ(result->algorithm.value(), "hmac-sha-1-96");
    ASSERT_TRUE(result->spi_c.has_value());
    EXPECT_EQ(result->spi_c.value(), 1234);
    ASSERT_TRUE(result->spi_s.has_value());
    EXPECT_EQ(result->spi_s.value(), 5678);
    ASSERT_TRUE(result->port_c.has_value());
    EXPECT_EQ(result->port_c.value(), 5062);
    ASSERT_TRUE(result->port_s.has_value());
    EXPECT_EQ(result->port_s.value(), 5064);
}

TEST(SipSecurityInfoTest, ParseTls) {
    std::string value = "tls";
    auto result = SipSecurityInfo::parse(value);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->mechanism, "tls");
    EXPECT_FALSE(result->algorithm.has_value());
}

// ============================================================================
// Session-Expires Tests
// ============================================================================

TEST(SipSessionExpiresTest, ParseWithRefresher) {
    std::string value = "1800; refresher=uac";
    auto result = SipSessionExpires::parse(value);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->expires, 1800);
    ASSERT_TRUE(result->refresher.has_value());
    EXPECT_EQ(result->refresher.value(), "uac");
}

TEST(SipSessionExpiresTest, ParseWithoutRefresher) {
    std::string value = "3600";
    auto result = SipSessionExpires::parse(value);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->expires, 3600);
    EXPECT_FALSE(result->refresher.has_value());
}

// ============================================================================
// SDP QoS Precondition Tests
// ============================================================================

TEST(SipSdpQosPreconditionTest, ParseCurrent) {
    std::string value = "qos local sendrecv";
    auto result = SipSdpQosPrecondition::parseCurrent(value);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->direction, SipSdpQosPrecondition::Direction::LOCAL);
    EXPECT_EQ(result->status, SipSdpQosPrecondition::Status::SENDRECV);
}

TEST(SipSdpQosPreconditionTest, ParseCurrentNone) {
    std::string value = "qos remote none";
    auto result = SipSdpQosPrecondition::parseCurrent(value);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->direction, SipSdpQosPrecondition::Direction::REMOTE);
    EXPECT_EQ(result->status, SipSdpQosPrecondition::Status::NONE);
}

TEST(SipSdpQosPreconditionTest, ParseDesired) {
    std::string value = "qos mandatory local sendrecv";
    auto result = SipSdpQosPrecondition::parseDesired(value);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->strength, SipSdpQosPrecondition::Strength::MANDATORY);
    EXPECT_EQ(result->direction, SipSdpQosPrecondition::Direction::LOCAL);
    EXPECT_EQ(result->status, SipSdpQosPrecondition::Status::SENDRECV);
}

TEST(SipSdpQosPreconditionTest, ParseDesiredOptional) {
    std::string value = "qos optional remote send";
    auto result = SipSdpQosPrecondition::parseDesired(value);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->strength, SipSdpQosPrecondition::Strength::OPTIONAL);
    EXPECT_EQ(result->direction, SipSdpQosPrecondition::Direction::REMOTE);
    EXPECT_EQ(result->status, SipSdpQosPrecondition::Status::SEND);
}

// ============================================================================
// SDP Bandwidth Tests
// ============================================================================

TEST(SipSdpBandwidthTest, ParseAs) {
    SipSdpBandwidth bandwidth;
    SipSdpBandwidth::parseLine("b=AS:64", bandwidth);

    ASSERT_TRUE(bandwidth.as.has_value());
    EXPECT_EQ(bandwidth.as.value(), 64);
}

TEST(SipSdpBandwidthTest, ParseTias) {
    SipSdpBandwidth bandwidth;
    SipSdpBandwidth::parseLine("b=TIAS:64000", bandwidth);

    ASSERT_TRUE(bandwidth.tias.has_value());
    EXPECT_EQ(bandwidth.tias.value(), 64000);
}

TEST(SipSdpBandwidthTest, ParseRsRr) {
    SipSdpBandwidth bandwidth;
    SipSdpBandwidth::parseLine("b=RS:800", bandwidth);
    SipSdpBandwidth::parseLine("b=RR:2000", bandwidth);

    ASSERT_TRUE(bandwidth.rs.has_value());
    EXPECT_EQ(bandwidth.rs.value(), 800);
    ASSERT_TRUE(bandwidth.rr.has_value());
    EXPECT_EQ(bandwidth.rr.value(), 2000);
}

// ============================================================================
// SDP Codec Tests
// ============================================================================

TEST(SipSdpCodecTest, ParseRtpmapAmr) {
    std::string value = "97 AMR/8000/1";
    auto result = SipSdpCodec::parseRtpmap(value);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->payload_type, 97);
    EXPECT_EQ(result->encoding_name, "AMR");
    EXPECT_EQ(result->clock_rate, 8000);
    ASSERT_TRUE(result->channels.has_value());
    EXPECT_EQ(result->channels.value(), 1);
}

TEST(SipSdpCodecTest, ParseRtpmapTelephoneEvent) {
    std::string value = "98 telephone-event/8000";
    auto result = SipSdpCodec::parseRtpmap(value);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->payload_type, 98);
    EXPECT_EQ(result->encoding_name, "telephone-event");
    EXPECT_EQ(result->clock_rate, 8000);
    EXPECT_FALSE(result->channels.has_value());
}

TEST(SipSdpCodecTest, ParseFmtp) {
    SipSdpCodec codec;
    codec.payload_type = 97;
    codec.parseFmtp("97 mode-set=0,2,4,7; mode-change-period=2");

    EXPECT_EQ(codec.format_parameters.size(), 2);
    EXPECT_EQ(codec.format_parameters["mode-set"], "0,2,4,7");
    EXPECT_EQ(codec.format_parameters["mode-change-period"], "2");
}

// ============================================================================
// Privacy Tests
// ============================================================================

TEST(SipPrivacyTest, ParseMultipleValues) {
    std::string value = "id; header; user";
    auto result = SipPrivacy::parse(value);

    EXPECT_TRUE(result.id);
    EXPECT_TRUE(result.header);
    EXPECT_TRUE(result.user);
    EXPECT_FALSE(result.session);
    EXPECT_FALSE(result.none);
    EXPECT_FALSE(result.critical);
}

TEST(SipPrivacyTest, ParseNone) {
    std::string value = "none";
    auto result = SipPrivacy::parse(value);

    EXPECT_FALSE(result.id);
    EXPECT_TRUE(result.none);
}

TEST(SipPrivacyTest, ParseCritical) {
    std::string value = "id; critical";
    auto result = SipPrivacy::parse(value);

    EXPECT_TRUE(result.id);
    EXPECT_TRUE(result.critical);
}

// ============================================================================
// Subscription-State Tests
// ============================================================================

TEST(SipSubscriptionStateTest, ParseActive) {
    std::string value = "active;expires=3600";
    auto result = SipSubscriptionState::parse(value);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->state, SipSubscriptionState::State::ACTIVE);
    ASSERT_TRUE(result->expires.has_value());
    EXPECT_EQ(result->expires.value(), 3600);
}

TEST(SipSubscriptionStateTest, ParseTerminated) {
    std::string value = "terminated;reason=timeout";
    auto result = SipSubscriptionState::parse(value);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->state, SipSubscriptionState::State::TERMINATED);
    ASSERT_TRUE(result->reason.has_value());
    EXPECT_EQ(result->reason.value(), "timeout");
}

TEST(SipSubscriptionStateTest, ParsePending) {
    std::string value = "pending";
    auto result = SipSubscriptionState::parse(value);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->state, SipSubscriptionState::State::PENDING);
    EXPECT_FALSE(result->expires.has_value());
    EXPECT_FALSE(result->reason.has_value());
}
