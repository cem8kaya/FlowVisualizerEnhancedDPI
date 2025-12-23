#include <gtest/gtest.h>

#include "common/field_registry.h"
#include "common/parsed_packet.h"
#include "protocol_parsers/diameter_parser.h"
#include "protocol_parsers/gtp_parser.h"
#include "protocol_parsers/sip_parser.h"

using namespace callflow;

class ParserFieldsTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Register fields for all parsers
        // In a real app, this might be called at startup.
        // We call it here to ensure test environment is ready.
        // Use a static flag guard if double reg is an issue (FieldRegistry overwrites usually)
        SipParser::registerFields();
        GtpParser::registerFields();
        DiameterParser::registerFields();
    }
};

TEST_F(ParserFieldsTest, SipFields) {
    SipMessage msg;
    msg.is_request = true;
    msg.method = "INVITE";
    msg.call_id = "test-call-id";

    // Simulate P-Asserted-Identity
    SipPAssertedIdentity pai;
    pai.uri = "sip:+1234567890@ims.mnc.mcc.3gppnetwork.org";
    msg.p_asserted_identity = std::vector<SipPAssertedIdentity>{pai};

    ParsedPacket pkt(&msg);
    auto& registry = FieldRegistry::getInstance();

    EXPECT_EQ(std::get<std::string>(registry.getValue("sip.call_id", &pkt)), "test-call-id");
    EXPECT_EQ(std::get<std::string>(registry.getValue("sip.method", &pkt)), "INVITE");
    EXPECT_EQ(std::get<std::string>(registry.getValue("sip.pai.msisdn", &pkt)), "1234567890");

    // Check missing field safe return
    EXPECT_EQ(std::get<int64_t>(registry.getValue("sip.status_code", &pkt)), 0);
}

TEST_F(ParserFieldsTest, GtpFields) {
    GtpMessage msg;
    msg.header.message_type = 32;  // Create Session Request
    msg.header.teid_present = true;
    msg.header.teid = 12345;
    msg.imsi = "999001123456789";

    ParsedPacket pkt(&msg);
    auto& registry = FieldRegistry::getInstance();

    EXPECT_EQ(std::get<int64_t>(registry.getValue("gtpv2.message_type", &pkt)), 32);
    EXPECT_EQ(std::get<int64_t>(registry.getValue("gtpv2.teid", &pkt)), 12345);
    EXPECT_EQ(std::get<std::string>(registry.getValue("gtpv2.imsi", &pkt)), "999001123456789");
}

TEST_F(ParserFieldsTest, DiameterFields) {
    DiameterMessage msg;
    msg.header.command_code = 316;  // ULR
    msg.result_code = 2001;         // Success
    msg.subscription_id = "123456789";

    ParsedPacket pkt(&msg);
    auto& registry = FieldRegistry::getInstance();

    EXPECT_EQ(std::get<int64_t>(registry.getValue("diameter.cmd.code", &pkt)), 316);
    EXPECT_EQ(std::get<int64_t>(registry.getValue("diameter.result_code", &pkt)), 2001);
    EXPECT_EQ(std::get<std::string>(registry.getValue("diameter.subscription_id", &pkt)),
              "123456789");
}

TEST_F(ParserFieldsTest, CrossProtocolSafety) {
    SipMessage sip_msg;
    sip_msg.call_id = "safe-check";
    ParsedPacket sip_pkt(&sip_msg);

    auto& registry = FieldRegistry::getInstance();

    // Accessing GTP field on SIP packet
    // The accessor casts to ParsedPacket*, checks variant holding GtpMessage*, finds it null,
    // returns default.
    EXPECT_EQ(std::get<std::string>(registry.getValue("gtpv2.imsi", &sip_pkt)), "");
    EXPECT_EQ(std::get<int64_t>(registry.getValue("gtpv2.teid", &sip_pkt)), 0);
}
