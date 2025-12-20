#include <gtest/gtest.h>
#include "protocol_parsers/diameter/diameter_base.h"
#include "protocol_parsers/diameter/diameter_avp_parser.h"
#include "protocol_parsers/diameter/diameter_session.h"
#include <arpa/inet.h>
#include <cstring>
#include <vector>

using namespace callflow::diameter;

// ============================================================================
// Helper Functions for Test Data Creation
// ============================================================================

/**
 * Create a test Diameter header
 */
std::vector<uint8_t> createDiameterHeader(
    bool request = true,
    uint32_t command_code = 257,  // CER
    uint32_t app_id = 0,
    uint32_t hop_by_hop = 0x12345678,
    uint32_t end_to_end = 0x87654321,
    uint32_t message_length = 20
) {
    std::vector<uint8_t> header(20);

    // Version (1 byte)
    header[0] = 1;

    // Message Length (3 bytes, 24 bits)
    header[1] = (message_length >> 16) & 0xFF;
    header[2] = (message_length >> 8) & 0xFF;
    header[3] = message_length & 0xFF;

    // Flags (1 byte)
    uint8_t flags = 0;
    if (request) flags |= 0x80;  // R bit
    flags |= 0x40;  // P bit (proxyable)
    header[4] = flags;

    // Command Code (3 bytes, 24 bits)
    header[5] = (command_code >> 16) & 0xFF;
    header[6] = (command_code >> 8) & 0xFF;
    header[7] = command_code & 0xFF;

    // Application ID (4 bytes)
    uint32_t app_id_net = htonl(app_id);
    std::memcpy(&header[8], &app_id_net, 4);

    // Hop-by-Hop Identifier (4 bytes)
    uint32_t hop_net = htonl(hop_by_hop);
    std::memcpy(&header[12], &hop_net, 4);

    // End-to-End Identifier (4 bytes)
    uint32_t end_net = htonl(end_to_end);
    std::memcpy(&header[16], &end_net, 4);

    return header;
}

/**
 * Create a test Diameter AVP
 */
std::vector<uint8_t> createDiameterAVP(
    uint32_t code,
    const std::vector<uint8_t>& data,
    bool vendor_specific = false,
    bool mandatory = false,
    uint32_t vendor_id = 0
) {
    size_t header_size = vendor_specific ? 12 : 8;
    size_t total_length = header_size + data.size();
    size_t padding = (4 - (total_length % 4)) % 4;

    std::vector<uint8_t> avp(total_length + padding, 0);

    // AVP Code (4 bytes)
    uint32_t code_net = htonl(code);
    std::memcpy(&avp[0], &code_net, 4);

    // Flags (1 byte)
    uint8_t flags = 0;
    if (vendor_specific) flags |= 0x80;  // V bit
    if (mandatory) flags |= 0x40;        // M bit
    avp[4] = flags;

    // AVP Length (3 bytes, 24 bits)
    avp[5] = (total_length >> 16) & 0xFF;
    avp[6] = (total_length >> 8) & 0xFF;
    avp[7] = total_length & 0xFF;

    // Vendor ID (if V flag set)
    size_t data_offset = 8;
    if (vendor_specific) {
        uint32_t vendor_net = htonl(vendor_id);
        std::memcpy(&avp[8], &vendor_net, 4);
        data_offset = 12;
    }

    // Data
    std::memcpy(&avp[data_offset], data.data(), data.size());

    return avp;
}

/**
 * Create Unsigned32 AVP data
 */
std::vector<uint8_t> createUint32Data(uint32_t value) {
    std::vector<uint8_t> data(4);
    uint32_t net_value = htonl(value);
    std::memcpy(data.data(), &net_value, 4);
    return data;
}

/**
 * Create UTF8String AVP data
 */
std::vector<uint8_t> createStringData(const std::string& str) {
    return std::vector<uint8_t>(str.begin(), str.end());
}

// ============================================================================
// Diameter Header Tests
// ============================================================================

TEST(DiameterHeaderTest, DefaultConstruction) {
    DiameterHeader header;
    EXPECT_EQ(header.version, 1);
    EXPECT_EQ(header.message_length, 0);
    EXPECT_FALSE(header.request);
    EXPECT_FALSE(header.proxyable);
    EXPECT_FALSE(header.error);
    EXPECT_FALSE(header.potentially_retransmitted);
}

TEST(DiameterHeaderTest, GetCommandName) {
    DiameterHeader header;
    header.command_code = 257;  // CER
    header.request = true;
    EXPECT_EQ(header.getCommandName(), "Capabilities-Exchange (Request)");

    header.request = false;
    EXPECT_EQ(header.getCommandName(), "Capabilities-Exchange (Answer)");
}

TEST(DiameterHeaderTest, ToJson) {
    DiameterHeader header;
    header.version = 1;
    header.command_code = 280;  // DWR
    header.request = true;
    header.application_id = 0;

    auto json = header.toJson();
    EXPECT_EQ(json["version"], 1);
    EXPECT_EQ(json["command_code"], 280);
    EXPECT_TRUE(json["flags"]["request"]);
}

// ============================================================================
// Diameter AVP Tests
// ============================================================================

TEST(DiameterAVPTest, DefaultConstruction) {
    DiameterAVP avp;
    EXPECT_EQ(avp.code, 0);
    EXPECT_FALSE(avp.vendor_specific);
    EXPECT_FALSE(avp.mandatory);
    EXPECT_FALSE(avp.protected_);
}

TEST(DiameterAVPTest, GetDataAsString) {
    DiameterAVP avp;
    std::string test_str = "test.example.com";
    avp.data = std::vector<uint8_t>(test_str.begin(), test_str.end());

    EXPECT_EQ(avp.getDataAsString(), test_str);
}

TEST(DiameterAVPTest, GetDataAsUint32) {
    DiameterAVP avp;
    uint32_t value = 2001;
    uint32_t net_value = htonl(value);
    avp.data.resize(4);
    std::memcpy(avp.data.data(), &net_value, 4);

    auto result = avp.getDataAsUint32();
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), value);
}

TEST(DiameterAVPTest, GetAVPName) {
    DiameterAVP avp;

    avp.code = static_cast<uint32_t>(DiameterAVPCode::SESSION_ID);
    EXPECT_EQ(avp.getAVPName(), "Session-Id");

    avp.code = static_cast<uint32_t>(DiameterAVPCode::ORIGIN_HOST);
    EXPECT_EQ(avp.getAVPName(), "Origin-Host");

    avp.code = static_cast<uint32_t>(DiameterAVPCode::RESULT_CODE);
    EXPECT_EQ(avp.getAVPName(), "Result-Code");
}

// ============================================================================
// AVP Parser Tests
// ============================================================================

TEST(DiameterAVPParserTest, ParseUnsigned32) {
    std::vector<uint8_t> data = createUint32Data(2001);
    auto result = DiameterAVPParser::parseUnsigned32(data);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), 2001);
}

TEST(DiameterAVPParserTest, ParseUTF8String) {
    std::string test_str = "test.example.com";
    std::vector<uint8_t> data = createStringData(test_str);
    auto result = DiameterAVPParser::parseUTF8String(data);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), test_str);
}

TEST(DiameterAVPParserTest, ParseIPv4Address) {
    std::vector<uint8_t> data(6);
    // Address Family: IPv4 (1)
    uint16_t af = htons(1);
    std::memcpy(data.data(), &af, 2);
    // IP: 192.168.1.1
    data[2] = 192;
    data[3] = 168;
    data[4] = 1;
    data[5] = 1;

    auto result = DiameterAVPParser::parseIPAddress(data);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value(), "192.168.1.1");
}

TEST(DiameterAVPParserTest, ParseAVP) {
    // Create Session-Id AVP
    std::string session_id = "test-session-123";
    auto avp_data = createDiameterAVP(
        static_cast<uint32_t>(DiameterAVPCode::SESSION_ID),
        createStringData(session_id),
        false,  // not vendor-specific
        true    // mandatory
    );

    size_t offset = 0;
    auto avp = DiameterAVPParser::parseAVP(avp_data.data(), avp_data.size(), offset);

    ASSERT_NE(avp, nullptr);
    EXPECT_EQ(avp->code, static_cast<uint32_t>(DiameterAVPCode::SESSION_ID));
    EXPECT_TRUE(avp->mandatory);
    EXPECT_FALSE(avp->vendor_specific);
    EXPECT_EQ(avp->getDataAsString(), session_id);
}

TEST(DiameterAVPParserTest, ParseVendorSpecificAVP) {
    // Create vendor-specific AVP
    auto avp_data = createDiameterAVP(
        1000,  // Custom code
        createUint32Data(12345),
        true,   // vendor-specific
        true,   // mandatory
        10415   // 3GPP vendor ID
    );

    size_t offset = 0;
    auto avp = DiameterAVPParser::parseAVP(avp_data.data(), avp_data.size(), offset);

    ASSERT_NE(avp, nullptr);
    EXPECT_EQ(avp->code, 1000);
    EXPECT_TRUE(avp->vendor_specific);
    EXPECT_TRUE(avp->vendor_id.has_value());
    EXPECT_EQ(avp->vendor_id.value(), 10415);
}

TEST(DiameterAVPParserTest, ParseGroupedAVP) {
    // Create nested AVPs
    auto nested_avp1 = createDiameterAVP(
        static_cast<uint32_t>(DiameterAVPCode::VENDOR_ID),
        createUint32Data(10415)
    );
    auto nested_avp2 = createDiameterAVP(
        static_cast<uint32_t>(DiameterAVPCode::AUTH_APPLICATION_ID),
        createUint32Data(16777251)
    );

    // Combine nested AVPs
    std::vector<uint8_t> grouped_data;
    grouped_data.insert(grouped_data.end(), nested_avp1.begin(), nested_avp1.end());
    grouped_data.insert(grouped_data.end(), nested_avp2.begin(), nested_avp2.end());

    // Parse as grouped AVP
    auto result = DiameterAVPParser::parseGrouped(grouped_data);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result.value().size(), 2);
    EXPECT_EQ(result.value()[0]->code, static_cast<uint32_t>(DiameterAVPCode::VENDOR_ID));
    EXPECT_EQ(result.value()[1]->code, static_cast<uint32_t>(DiameterAVPCode::AUTH_APPLICATION_ID));
}

TEST(DiameterAVPParserTest, CalculatePadding) {
    EXPECT_EQ(DiameterAVPParser::calculatePadding(8), 0);   // Already aligned
    EXPECT_EQ(DiameterAVPParser::calculatePadding(9), 3);   // Need 3 bytes
    EXPECT_EQ(DiameterAVPParser::calculatePadding(10), 2);  // Need 2 bytes
    EXPECT_EQ(DiameterAVPParser::calculatePadding(11), 1);  // Need 1 byte
    EXPECT_EQ(DiameterAVPParser::calculatePadding(12), 0);  // Already aligned
}

TEST(DiameterAVPParserTest, GetAVPDataType) {
    // Test base protocol AVP types
    EXPECT_EQ(
        DiameterAVPParser::getAVPDataType(static_cast<uint32_t>(DiameterAVPCode::RESULT_CODE)),
        DiameterAVPDataType::UNSIGNED32
    );

    EXPECT_EQ(
        DiameterAVPParser::getAVPDataType(static_cast<uint32_t>(DiameterAVPCode::SESSION_ID)),
        DiameterAVPDataType::UTF8STRING
    );

    EXPECT_EQ(
        DiameterAVPParser::getAVPDataType(static_cast<uint32_t>(DiameterAVPCode::HOST_IP_ADDRESS)),
        DiameterAVPDataType::IP_ADDRESS
    );

    EXPECT_EQ(
        DiameterAVPParser::getAVPDataType(static_cast<uint32_t>(DiameterAVPCode::VENDOR_SPECIFIC_APPLICATION_ID)),
        DiameterAVPDataType::GROUPED
    );
}

// ============================================================================
// Diameter Message Tests
// ============================================================================

TEST(DiameterMessageTest, DefaultConstruction) {
    DiameterMessage msg;
    EXPECT_EQ(msg.avps.size(), 0);
    EXPECT_FALSE(msg.session_id.has_value());
    EXPECT_FALSE(msg.result_code.has_value());
}

TEST(DiameterMessageTest, FindAVP) {
    DiameterMessage msg;

    // Add some AVPs
    auto avp1 = std::make_shared<DiameterAVP>();
    avp1->code = static_cast<uint32_t>(DiameterAVPCode::SESSION_ID);
    avp1->data = createStringData("test-session");

    auto avp2 = std::make_shared<DiameterAVP>();
    avp2->code = static_cast<uint32_t>(DiameterAVPCode::RESULT_CODE);
    avp2->data = createUint32Data(2001);

    msg.avps.push_back(avp1);
    msg.avps.push_back(avp2);

    // Find Session-Id
    auto found = msg.findAVP(static_cast<uint32_t>(DiameterAVPCode::SESSION_ID));
    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->code, static_cast<uint32_t>(DiameterAVPCode::SESSION_ID));

    // Find non-existent AVP
    auto not_found = msg.findAVP(999);
    EXPECT_EQ(not_found, nullptr);
}

TEST(DiameterMessageTest, ExtractCommonFields) {
    DiameterMessage msg;

    // Add common AVPs
    auto session_avp = std::make_shared<DiameterAVP>();
    session_avp->code = static_cast<uint32_t>(DiameterAVPCode::SESSION_ID);
    session_avp->data = createStringData("test-session-123");
    msg.avps.push_back(session_avp);

    auto origin_host_avp = std::make_shared<DiameterAVP>();
    origin_host_avp->code = static_cast<uint32_t>(DiameterAVPCode::ORIGIN_HOST);
    origin_host_avp->data = createStringData("mme.example.com");
    msg.avps.push_back(origin_host_avp);

    auto result_code_avp = std::make_shared<DiameterAVP>();
    result_code_avp->code = static_cast<uint32_t>(DiameterAVPCode::RESULT_CODE);
    result_code_avp->data = createUint32Data(2001);
    msg.avps.push_back(result_code_avp);

    // Extract common fields
    msg.extractCommonFields();

    ASSERT_TRUE(msg.session_id.has_value());
    EXPECT_EQ(msg.session_id.value(), "test-session-123");

    ASSERT_TRUE(msg.origin_host.has_value());
    EXPECT_EQ(msg.origin_host.value(), "mme.example.com");

    ASSERT_TRUE(msg.result_code.has_value());
    EXPECT_EQ(msg.result_code.value(), 2001);
}

TEST(DiameterMessageTest, IsSuccess) {
    DiameterMessage msg;

    msg.result_code = 2001;
    EXPECT_TRUE(msg.isSuccess());

    msg.result_code = 5003;
    EXPECT_FALSE(msg.isSuccess());
}

TEST(DiameterMessageTest, GetInterface) {
    DiameterMessage msg;

    msg.header.application_id = static_cast<uint32_t>(DiameterApplicationID::TGPP_S6A_S6D);
    EXPECT_EQ(msg.getInterface(), DiameterInterface::S6A);

    msg.header.application_id = static_cast<uint32_t>(DiameterApplicationID::TGPP_GX);
    EXPECT_EQ(msg.getInterface(), DiameterInterface::GX);

    msg.header.application_id = 0;
    EXPECT_EQ(msg.getInterface(), DiameterInterface::BASE);
}

// ============================================================================
// Session Manager Tests
// ============================================================================

TEST(DiameterSessionManagerTest, ProcessMessage) {
    DiameterSessionManager manager;

    auto msg = std::make_shared<DiameterMessage>();
    msg->session_id = "test-session-456";
    msg->origin_host = "hss.example.com";
    msg->header.request = true;
    msg->header.command_code = 316;  // ULR
    msg->header.application_id = static_cast<uint32_t>(DiameterApplicationID::TGPP_S6A_S6D);
    msg->header.hop_by_hop_id = 0x11223344;

    auto timestamp = std::chrono::system_clock::now();
    auto session_id = manager.processMessage(msg, timestamp);

    ASSERT_TRUE(session_id.has_value());
    EXPECT_EQ(session_id.value(), "test-session-456");

    // Verify session was created
    auto session = manager.findSession("test-session-456");
    ASSERT_TRUE(session.has_value());
    EXPECT_EQ(session->session_id, "test-session-456");
    EXPECT_EQ(session->origin_host, "hss.example.com");
    EXPECT_EQ(session->interface, DiameterInterface::S6A);
}

TEST(DiameterSessionManagerTest, CorrelateRequestResponse) {
    DiameterSessionManager manager;

    // Create request
    auto request = std::make_shared<DiameterMessage>();
    request->session_id = "test-correlation";
    request->header.request = true;
    request->header.command_code = 316;  // ULR
    request->header.hop_by_hop_id = 0xAABBCCDD;
    request->header.end_to_end_id = 0x11223344;

    auto req_time = std::chrono::system_clock::now();
    manager.processMessage(request, req_time);

    // Create answer
    auto answer = std::make_shared<DiameterMessage>();
    answer->session_id = "test-correlation";
    answer->header.request = false;
    answer->header.command_code = 316;  // ULA
    answer->header.hop_by_hop_id = 0xAABBCCDD;  // Same hop-by-hop
    answer->header.end_to_end_id = 0x11223344;
    answer->result_code = 2001;

    auto ans_time = std::chrono::system_clock::now();
    manager.processMessage(answer, ans_time);

    // Verify correlation
    auto session = manager.findSession("test-correlation");
    ASSERT_TRUE(session.has_value());
    ASSERT_EQ(session->message_pairs.size(), 1);
    EXPECT_TRUE(session->message_pairs[0].isComplete());
    EXPECT_NE(session->message_pairs[0].answer, nullptr);
}

TEST(DiameterSessionManagerTest, GetStatistics) {
    DiameterSessionManager manager;

    // Add some test messages
    for (int i = 0; i < 3; i++) {
        auto msg = std::make_shared<DiameterMessage>();
        msg->session_id = "session-" + std::to_string(i);
        msg->header.request = true;
        msg->header.hop_by_hop_id = 0x1000 + i;

        manager.processMessage(msg, std::chrono::system_clock::now());
    }

    auto stats = manager.getStatistics();
    EXPECT_EQ(stats.total_sessions, 3);
    EXPECT_EQ(stats.active_sessions, 3);
}

TEST(DiameterSessionManagerTest, CleanupOldSessions) {
    DiameterSessionManager manager;

    auto msg = std::make_shared<DiameterMessage>();
    msg->session_id = "old-session";
    msg->header.request = true;

    manager.processMessage(msg, std::chrono::system_clock::now());

    // Mark session as ended
    auto session_opt = manager.findSession("old-session");
    ASSERT_TRUE(session_opt.has_value());

    // Initially, no cleanup should happen with 0 max age
    size_t cleaned = manager.cleanupOldSessions(std::chrono::seconds(1000));
    EXPECT_EQ(cleaned, 0);  // Session is still active

    EXPECT_EQ(manager.getSessionCount(), 1);
}

// ============================================================================
// Helper Function Tests
// ============================================================================

TEST(DiameterHelpersTest, GetResultCodeName) {
    EXPECT_EQ(getResultCodeName(2001), "DIAMETER_SUCCESS");
    EXPECT_EQ(getResultCodeName(5003), "DIAMETER_AUTHORIZATION_REJECTED");
    EXPECT_EQ(getResultCodeName(3001), "DIAMETER_COMMAND_UNSUPPORTED");
}

TEST(DiameterHelpersTest, GetResultCodeCategory) {
    EXPECT_EQ(getResultCodeCategory(2001), "Success");
    EXPECT_EQ(getResultCodeCategory(3001), "Protocol Error");
    EXPECT_EQ(getResultCodeCategory(4001), "Transient Failure");
    EXPECT_EQ(getResultCodeCategory(5001), "Permanent Failure");
}

TEST(DiameterHelpersTest, GetCommandCodeName) {
    EXPECT_EQ(getCommandCodeName(257), "Capabilities-Exchange");
    EXPECT_EQ(getCommandCodeName(280), "Device-Watchdog");
    EXPECT_EQ(getCommandCodeName(316), "Update-Location");
    EXPECT_EQ(getCommandCodeName(318), "Authentication-Information");
}

TEST(DiameterHelpersTest, GetApplicationIDName) {
    EXPECT_EQ(
        getApplicationIDName(static_cast<uint32_t>(DiameterApplicationID::DIAMETER_COMMON_MESSAGES)),
        "Diameter Common Messages"
    );
    EXPECT_EQ(
        getApplicationIDName(static_cast<uint32_t>(DiameterApplicationID::TGPP_S6A_S6D)),
        "3GPP S6a/S6d"
    );
    EXPECT_EQ(
        getApplicationIDName(static_cast<uint32_t>(DiameterApplicationID::TGPP_GX)),
        "3GPP Gx"
    );
}

TEST(DiameterHelpersTest, GetInterfaceFromApplicationID) {
    EXPECT_EQ(
        getInterfaceFromApplicationID(static_cast<uint32_t>(DiameterApplicationID::TGPP_S6A_S6D)),
        DiameterInterface::S6A
    );
    EXPECT_EQ(
        getInterfaceFromApplicationID(static_cast<uint32_t>(DiameterApplicationID::TGPP_GX)),
        DiameterInterface::GX
    );
    EXPECT_EQ(
        getInterfaceFromApplicationID(static_cast<uint32_t>(DiameterApplicationID::TGPP_CX)),
        DiameterInterface::CX
    );
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
