#include <gtest/gtest.h>
#include "protocol_parsers/sip_parser.h"

using namespace callflow;

// ============================================================================
// VoLTE REGISTER Test
// ============================================================================

TEST(SipVoLTETest, ParseRegisterWithPHeaders) {
    const char* volte_register =
        "REGISTER sip:ims.example.com SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 192.0.2.100:5060;branch=z9hG4bK776asdhds\r\n"
        "From: <sip:user@ims.example.com>;tag=1928301774\r\n"
        "To: <sip:user@ims.example.com>\r\n"
        "Call-ID: a84b4c76e66710@192.0.2.100\r\n"
        "CSeq: 314159 REGISTER\r\n"
        "Contact: <sip:user@192.0.2.100:5060>;expires=600000\r\n"
        "P-Access-Network-Info: 3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=234150999999999\r\n"
        "P-Visited-Network-ID: \"Visited Network\"\r\n"
        "Path: <sip:pcscf.example.com;lr>\r\n"
        "Require: path, sec-agree\r\n"
        "Supported: 100rel, timer, gruu\r\n"
        "Security-Client: ipsec-3gpp; alg=hmac-sha-1-96; spi-c=1234; spi-s=5678; port-c=5062; "
        "port-s=5064\r\n"
        "Content-Length: 0\r\n\r\n";

    SipParser parser;
    auto result = parser.parse(reinterpret_cast<const uint8_t*>(volte_register),
                               strlen(volte_register));

    ASSERT_TRUE(result.has_value());
    auto& msg = result.value();

    // Basic SIP fields
    EXPECT_TRUE(msg.is_request);
    EXPECT_EQ(msg.method, "REGISTER");
    EXPECT_EQ(msg.request_uri, "sip:ims.example.com");
    EXPECT_EQ(msg.call_id, "a84b4c76e66710@192.0.2.100");

    // P-Access-Network-Info (LTE)
    ASSERT_TRUE(msg.p_access_network_info.has_value());
    EXPECT_EQ(msg.p_access_network_info->access_type,
              SipPAccessNetworkInfo::AccessType::THREEGPP_E_UTRAN_FDD);
    ASSERT_TRUE(msg.p_access_network_info->cell_id.has_value());
    EXPECT_EQ(msg.p_access_network_info->cell_id.value(), "234150999999999");

    // P-Visited-Network-ID
    ASSERT_TRUE(msg.p_visited_network_id.has_value());
    EXPECT_EQ(msg.p_visited_network_id.value(), "\"Visited Network\"");

    // Path
    ASSERT_EQ(msg.path.size(), 1);
    EXPECT_EQ(msg.path[0], "<sip:pcscf.example.com;lr>");

    // Require
    ASSERT_EQ(msg.require.size(), 2);
    EXPECT_EQ(msg.require[0], "path");
    EXPECT_EQ(msg.require[1], "sec-agree");

    // Supported
    ASSERT_EQ(msg.supported.size(), 3);
    EXPECT_EQ(msg.supported[0], "100rel");
    EXPECT_EQ(msg.supported[1], "timer");
    EXPECT_EQ(msg.supported[2], "gruu");

    // Security-Client
    ASSERT_TRUE(msg.security_client.has_value());
    EXPECT_EQ(msg.security_client->mechanism, "ipsec-3gpp");
    ASSERT_TRUE(msg.security_client->algorithm.has_value());
    EXPECT_EQ(msg.security_client->algorithm.value(), "hmac-sha-1-96");
    ASSERT_TRUE(msg.security_client->spi_c.has_value());
    EXPECT_EQ(msg.security_client->spi_c.value(), 1234);
    ASSERT_TRUE(msg.security_client->port_c.has_value());
    EXPECT_EQ(msg.security_client->port_c.value(), 5062);
}

// ============================================================================
// VoLTE INVITE Test
// ============================================================================

TEST(SipVoLTETest, ParseInviteWithPHeadersAndSdp) {
    const char* volte_invite =
        "INVITE sip:+1234567890@ims.example.com SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 192.0.2.100:5060;branch=z9hG4bKnashds8\r\n"
        "From: <sip:alice@ims.example.com>;tag=1928301774\r\n"
        "To: <tel:+1234567890>\r\n"
        "Call-ID: volte-call-12345@192.0.2.100\r\n"
        "CSeq: 1 INVITE\r\n"
        "Contact: <sip:alice@192.0.2.100:5060>\r\n"
        "P-Asserted-Identity: \"Alice\" <sip:alice@ims.example.com>, <tel:+1987654321>\r\n"
        "P-Access-Network-Info: 3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=234150999999999\r\n"
        "P-Charging-Vector: icid-value=AyretyU0dm+6O2IrT5tAFrbHLso=; icid-generated-at=192.0.2.1; "
        "orig-ioi=home1.net; term-ioi=home2.net\r\n"
        "P-Charging-Function-Addresses: ccf=192.0.2.10; ecf=192.0.2.20\r\n"
        "Session-Expires: 1800; refresher=uac\r\n"
        "Min-SE: 90\r\n"
        "Supported: 100rel, timer, precondition\r\n"
        "Require: 100rel, precondition\r\n"
        "Content-Type: application/sdp\r\n"
        "Content-Length: 450\r\n\r\n"
        "v=0\r\n"
        "o=alice 2890844526 2890844526 IN IP4 192.0.2.100\r\n"
        "s=VoLTE Call\r\n"
        "c=IN IP4 192.0.2.100\r\n"
        "b=AS:64\r\n"
        "b=TIAS:64000\r\n"
        "t=0 0\r\n"
        "m=audio 49170 RTP/AVP 97 98\r\n"
        "a=rtpmap:97 AMR/8000/1\r\n"
        "a=fmtp:97 mode-set=0,2,4,7; mode-change-period=2\r\n"
        "a=rtpmap:98 telephone-event/8000\r\n"
        "a=fmtp:98 0-15\r\n"
        "a=ptime:20\r\n"
        "a=maxptime:40\r\n"
        "a=curr:qos local none\r\n"
        "a=curr:qos remote none\r\n"
        "a=des:qos mandatory local sendrecv\r\n"
        "a=des:qos mandatory remote sendrecv\r\n"
        "a=sendrecv\r\n";

    SipParser parser;
    auto result =
        parser.parse(reinterpret_cast<const uint8_t*>(volte_invite), strlen(volte_invite));

    ASSERT_TRUE(result.has_value());
    auto& msg = result.value();

    // Basic SIP fields
    EXPECT_TRUE(msg.is_request);
    EXPECT_EQ(msg.method, "INVITE");
    EXPECT_EQ(msg.call_id, "volte-call-12345@192.0.2.100");

    // P-Asserted-Identity
    ASSERT_TRUE(msg.p_asserted_identity.has_value());
    ASSERT_EQ(msg.p_asserted_identity->size(), 2);
    EXPECT_EQ(msg.p_asserted_identity->at(0).display_name, "Alice");
    EXPECT_EQ(msg.p_asserted_identity->at(0).uri, "sip:alice@ims.example.com");
    EXPECT_EQ(msg.p_asserted_identity->at(1).uri, "tel:+1987654321");

    // P-Access-Network-Info
    ASSERT_TRUE(msg.p_access_network_info.has_value());
    EXPECT_EQ(msg.p_access_network_info->access_type,
              SipPAccessNetworkInfo::AccessType::THREEGPP_E_UTRAN_FDD);

    // P-Charging-Vector (CRITICAL)
    ASSERT_TRUE(msg.p_charging_vector.has_value());
    EXPECT_EQ(msg.p_charging_vector->icid_value, "AyretyU0dm+6O2IrT5tAFrbHLso=");
    ASSERT_TRUE(msg.p_charging_vector->icid_generated_at.has_value());
    EXPECT_EQ(msg.p_charging_vector->icid_generated_at.value(), "192.0.2.1");
    ASSERT_TRUE(msg.p_charging_vector->orig_ioi.has_value());
    EXPECT_EQ(msg.p_charging_vector->orig_ioi.value(), "home1.net");
    ASSERT_TRUE(msg.p_charging_vector->term_ioi.has_value());
    EXPECT_EQ(msg.p_charging_vector->term_ioi.value(), "home2.net");

    // P-Charging-Function-Addresses
    ASSERT_TRUE(msg.p_charging_function_addresses.has_value());
    ASSERT_EQ(msg.p_charging_function_addresses->ccf_addresses.size(), 1);
    EXPECT_EQ(msg.p_charging_function_addresses->ccf_addresses[0], "192.0.2.10");
    ASSERT_EQ(msg.p_charging_function_addresses->ecf_addresses.size(), 1);
    EXPECT_EQ(msg.p_charging_function_addresses->ecf_addresses[0], "192.0.2.20");

    // Session-Expires
    ASSERT_TRUE(msg.session_expires.has_value());
    EXPECT_EQ(msg.session_expires->expires, 1800);
    ASSERT_TRUE(msg.session_expires->refresher.has_value());
    EXPECT_EQ(msg.session_expires->refresher.value(), "uac");

    // Min-SE
    ASSERT_TRUE(msg.min_se.has_value());
    EXPECT_EQ(msg.min_se.value(), 90);

    // SDP
    ASSERT_TRUE(msg.sdp.has_value());
    auto& sdp = msg.sdp.value();

    EXPECT_EQ(sdp.session_name, "VoLTE Call");
    EXPECT_EQ(sdp.connection_address, "192.0.2.100");
    EXPECT_EQ(sdp.rtp_port, 49170);

    // Bandwidth
    ASSERT_TRUE(sdp.bandwidth.as.has_value());
    EXPECT_EQ(sdp.bandwidth.as.value(), 64);
    ASSERT_TRUE(sdp.bandwidth.tias.has_value());
    EXPECT_EQ(sdp.bandwidth.tias.value(), 64000);

    // Codecs
    ASSERT_EQ(sdp.codecs.size(), 2);
    EXPECT_EQ(sdp.codecs[0].payload_type, 97);
    EXPECT_EQ(sdp.codecs[0].encoding_name, "AMR");
    EXPECT_EQ(sdp.codecs[0].clock_rate, 8000);
    EXPECT_EQ(sdp.codecs[0].format_parameters["mode-set"], "0,2,4,7");
    EXPECT_EQ(sdp.codecs[0].format_parameters["mode-change-period"], "2");

    EXPECT_EQ(sdp.codecs[1].payload_type, 98);
    EXPECT_EQ(sdp.codecs[1].encoding_name, "telephone-event");
    EXPECT_EQ(sdp.codecs[1].format_parameters["0-15"], "");

    // QoS Preconditions
    ASSERT_TRUE(sdp.qos_current_local.has_value());
    EXPECT_EQ(sdp.qos_current_local->direction, SipSdpQosPrecondition::Direction::LOCAL);
    EXPECT_EQ(sdp.qos_current_local->status, SipSdpQosPrecondition::Status::NONE);

    ASSERT_TRUE(sdp.qos_current_remote.has_value());
    EXPECT_EQ(sdp.qos_current_remote->direction, SipSdpQosPrecondition::Direction::REMOTE);
    EXPECT_EQ(sdp.qos_current_remote->status, SipSdpQosPrecondition::Status::NONE);

    ASSERT_TRUE(sdp.qos_desired_local.has_value());
    EXPECT_EQ(sdp.qos_desired_local->strength, SipSdpQosPrecondition::Strength::MANDATORY);
    EXPECT_EQ(sdp.qos_desired_local->direction, SipSdpQosPrecondition::Direction::LOCAL);
    EXPECT_EQ(sdp.qos_desired_local->status, SipSdpQosPrecondition::Status::SENDRECV);

    ASSERT_TRUE(sdp.qos_desired_remote.has_value());
    EXPECT_EQ(sdp.qos_desired_remote->strength, SipSdpQosPrecondition::Strength::MANDATORY);
    EXPECT_EQ(sdp.qos_desired_remote->direction, SipSdpQosPrecondition::Direction::REMOTE);
    EXPECT_EQ(sdp.qos_desired_remote->status, SipSdpQosPrecondition::Status::SENDRECV);

    // Media direction
    ASSERT_TRUE(sdp.media_direction.has_value());
    EXPECT_EQ(sdp.media_direction.value(), "sendrecv");
}

// ============================================================================
// VoNR (5G) Test
// ============================================================================

TEST(SipVoNRTest, Parse5gInviteWith3gppNr) {
    const char* vonr_invite =
        "INVITE sip:+1234567890@ims.5g.example.com SIP/2.0\r\n"
        "Via: SIP/2.0/UDP [2001:db8::100]:5060;branch=z9hG4bK5gnr\r\n"
        "From: <sip:alice@ims.5g.example.com>;tag=5gnr001\r\n"
        "To: <tel:+1234567890>\r\n"
        "Call-ID: vonr-call-67890@5g.example.com\r\n"
        "CSeq: 1 INVITE\r\n"
        "Contact: <sip:alice@[2001:db8::100]:5060>\r\n"
        "P-Asserted-Identity: \"Alice 5G\" <sip:alice@ims.5g.example.com>\r\n"
        "P-Access-Network-Info: 3GPP-NR; nrcgi=001010000000001\r\n"
        "P-Charging-Vector: icid-value=5GNR1234567890; orig-ioi=5g.home1.net\r\n"
        "Session-Expires: 1800; refresher=uac\r\n"
        "Supported: 100rel, timer, precondition\r\n"
        "Content-Type: application/sdp\r\n"
        "Content-Length: 200\r\n\r\n"
        "v=0\r\n"
        "o=alice 2890844527 2890844527 IN IP6 2001:db8::100\r\n"
        "s=VoNR 5G Call\r\n"
        "c=IN IP6 2001:db8::100\r\n"
        "b=AS:128\r\n"
        "t=0 0\r\n"
        "m=audio 50000 RTP/AVP 96\r\n"
        "a=rtpmap:96 EVS/16000\r\n"
        "a=sendrecv\r\n";

    SipParser parser;
    auto result = parser.parse(reinterpret_cast<const uint8_t*>(vonr_invite), strlen(vonr_invite));

    ASSERT_TRUE(result.has_value());
    auto& msg = result.value();

    // Basic SIP fields
    EXPECT_TRUE(msg.is_request);
    EXPECT_EQ(msg.method, "INVITE");
    EXPECT_EQ(msg.call_id, "vonr-call-67890@5g.example.com");

    // P-Asserted-Identity
    ASSERT_TRUE(msg.p_asserted_identity.has_value());
    ASSERT_EQ(msg.p_asserted_identity->size(), 1);
    EXPECT_EQ(msg.p_asserted_identity->at(0).display_name, "Alice 5G");
    EXPECT_EQ(msg.p_asserted_identity->at(0).uri, "sip:alice@ims.5g.example.com");

    // P-Access-Network-Info (5G NR)
    ASSERT_TRUE(msg.p_access_network_info.has_value());
    EXPECT_EQ(msg.p_access_network_info->access_type,
              SipPAccessNetworkInfo::AccessType::THREEGPP_NR);
    ASSERT_TRUE(msg.p_access_network_info->cell_id.has_value());
    EXPECT_EQ(msg.p_access_network_info->cell_id.value(), "001010000000001");

    // P-Charging-Vector
    ASSERT_TRUE(msg.p_charging_vector.has_value());
    EXPECT_EQ(msg.p_charging_vector->icid_value, "5GNR1234567890");
    ASSERT_TRUE(msg.p_charging_vector->orig_ioi.has_value());
    EXPECT_EQ(msg.p_charging_vector->orig_ioi.value(), "5g.home1.net");

    // SDP
    ASSERT_TRUE(msg.sdp.has_value());
    auto& sdp = msg.sdp.value();

    EXPECT_EQ(sdp.session_name, "VoNR 5G Call");
    EXPECT_EQ(sdp.rtp_port, 50000);

    // Bandwidth
    ASSERT_TRUE(sdp.bandwidth.as.has_value());
    EXPECT_EQ(sdp.bandwidth.as.value(), 128);

    // Codecs (EVS for 5G)
    ASSERT_EQ(sdp.codecs.size(), 1);
    EXPECT_EQ(sdp.codecs[0].payload_type, 96);
    EXPECT_EQ(sdp.codecs[0].encoding_name, "EVS");
    EXPECT_EQ(sdp.codecs[0].clock_rate, 16000);

    // Media direction
    ASSERT_TRUE(sdp.media_direction.has_value());
    EXPECT_EQ(sdp.media_direction.value(), "sendrecv");
}

// ============================================================================
// JSON Serialization Test
// ============================================================================

TEST(SipVoLTETest, JsonSerializationComplete) {
    const char* volte_invite =
        "INVITE sip:+1234567890@ims.example.com SIP/2.0\r\n"
        "Call-ID: test-call-id\r\n"
        "From: <sip:alice@example.com>\r\n"
        "To: <tel:+1234567890>\r\n"
        "Via: SIP/2.0/UDP 192.0.2.1\r\n"
        "Contact: <sip:alice@192.0.2.1>\r\n"
        "CSeq: 1 INVITE\r\n"
        "P-Asserted-Identity: \"Alice\" <sip:alice@example.com>\r\n"
        "P-Access-Network-Info: 3GPP-E-UTRAN-FDD; utran-cell-id-3gpp=234150999999999\r\n"
        "P-Charging-Vector: icid-value=ICID123456\r\n"
        "Content-Length: 0\r\n\r\n";

    SipParser parser;
    auto result =
        parser.parse(reinterpret_cast<const uint8_t*>(volte_invite), strlen(volte_invite));

    ASSERT_TRUE(result.has_value());
    auto json = result->toJson();

    // Verify JSON structure
    EXPECT_TRUE(json.contains("is_request"));
    EXPECT_TRUE(json.contains("method"));
    EXPECT_TRUE(json.contains("p_asserted_identity"));
    EXPECT_TRUE(json.contains("p_access_network_info"));
    EXPECT_TRUE(json.contains("p_charging_vector"));

    // Verify P-Asserted-Identity in JSON
    EXPECT_TRUE(json["p_asserted_identity"].is_array());
    EXPECT_EQ(json["p_asserted_identity"][0]["uri"], "sip:alice@example.com");

    // Verify P-Access-Network-Info in JSON
    EXPECT_EQ(json["p_access_network_info"]["access_type"], "3GPP-E-UTRAN-FDD");
    EXPECT_EQ(json["p_access_network_info"]["cell_id"], "234150999999999");

    // Verify P-Charging-Vector in JSON
    EXPECT_EQ(json["p_charging_vector"]["icid_value"], "ICID123456");
}

// ============================================================================
// Message Type Detection Test
// ============================================================================

TEST(SipVoLTETest, MessageTypeDetection) {
    SipParser parser;

    // Test REGISTER
    const char* reg = "REGISTER sip:ims.example.com SIP/2.0\r\nCall-ID: r1\r\nFrom: <sip:u@d>\r\nTo: "
                      "<sip:u@d>\r\nVia: SIP/2.0/UDP 1.2.3.4\r\nCSeq: 1 REGISTER\r\nContact: "
                      "<sip:u@1.2.3.4>\r\nContent-Length: 0\r\n\r\n";
    auto result = parser.parse(reinterpret_cast<const uint8_t*>(reg), strlen(reg));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(SipParser::getMessageType(result.value()), MessageType::SIP_REGISTER);

    // Test INVITE
    const char* inv = "INVITE sip:user@example.com SIP/2.0\r\nCall-ID: i1\r\nFrom: <sip:u@d>\r\nTo: "
                      "<sip:u@d>\r\nVia: SIP/2.0/UDP 1.2.3.4\r\nCSeq: 1 INVITE\r\nContact: "
                      "<sip:u@1.2.3.4>\r\nContent-Length: 0\r\n\r\n";
    result = parser.parse(reinterpret_cast<const uint8_t*>(inv), strlen(inv));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(SipParser::getMessageType(result.value()), MessageType::SIP_INVITE);

    // Test PRACK
    const char* prack = "PRACK sip:user@example.com SIP/2.0\r\nCall-ID: p1\r\nFrom: "
                        "<sip:u@d>\r\nTo: <sip:u@d>\r\nVia: SIP/2.0/UDP 1.2.3.4\r\nCSeq: 1 "
                        "PRACK\r\nContact: <sip:u@1.2.3.4>\r\nContent-Length: 0\r\n\r\n";
    result = parser.parse(reinterpret_cast<const uint8_t*>(prack), strlen(prack));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(SipParser::getMessageType(result.value()), MessageType::SIP_PRACK);
}
