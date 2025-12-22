#include <gtest/gtest.h>
#include "../../include/correlation/ladder_diagram_generator.h"
#include "../../include/session/session_types.h"
#include <thread>
#include <chrono>

using namespace flowviz;

class LadderDiagramGeneratorTest : public ::testing::Test {
protected:
    void SetUp() override {
        generator = std::make_unique<LadderDiagramGenerator>();
        base_time = std::chrono::system_clock::now();
    }

    SessionMessageRef createMessage(
        const std::string& src_ip,
        uint16_t src_port,
        const std::string& dst_ip,
        uint16_t dst_port,
        ProtocolType protocol,
        MessageType msg_type,
        std::chrono::milliseconds offset = std::chrono::milliseconds(0)
    ) {
        SessionMessageRef msg;
        msg.message_id = "msg_" + std::to_string(msg_counter_++);
        msg.timestamp = base_time + offset;
        msg.src_ip = src_ip;
        msg.src_port = src_port;
        msg.dst_ip = dst_ip;
        msg.dst_port = dst_port;
        msg.protocol = protocol;
        msg.message_type = msg_type;
        msg.correlation_key.imsi = "001010000000001";
        return msg;
    }

    std::unique_ptr<LadderDiagramGenerator> generator;
    std::chrono::system_clock::time_point base_time;
    static int msg_counter_;
};

int LadderDiagramGeneratorTest::msg_counter_ = 0;

TEST_F(LadderDiagramGeneratorTest, EmptyMessages) {
    std::vector<SessionMessageRef> messages;
    auto diagram = generator->generate(messages, "test_session", "Empty Test");

    EXPECT_EQ(diagram.session_id, "test_session");
    EXPECT_EQ(diagram.title, "Empty Test");
    EXPECT_EQ(diagram.events.size(), 0);
    EXPECT_EQ(diagram.participants.size(), 0);
    EXPECT_EQ(diagram.duration_ms.count(), 0);
}

TEST_F(LadderDiagramGeneratorTest, SingleMessage) {
    std::vector<SessionMessageRef> messages;
    messages.push_back(createMessage(
        "10.0.1.50", 36412,
        "10.0.2.10", 36412,
        ProtocolType::S1AP,
        MessageType::S1AP_INITIAL_UE_MESSAGE
    ));

    auto diagram = generator->generate(messages, "test_session", "Single Message Test");

    EXPECT_EQ(diagram.events.size(), 1);
    EXPECT_EQ(diagram.participants.size(), 2);  // eNodeB and MME

    const auto& event = diagram.events[0];
    EXPECT_EQ(event.interface, "S1-MME");
    EXPECT_EQ(event.protocol, ProtocolType::S1AP);
    EXPECT_EQ(event.direction, MessageDirection::REQUEST);
}

TEST_F(LadderDiagramGeneratorTest, GlobalTimestampOrdering) {
    std::vector<SessionMessageRef> messages;

    // Create messages with specific timestamps
    messages.push_back(createMessage(
        "10.0.2.10", 2123, "10.0.3.10", 2123,
        ProtocolType::GTP_C, MessageType::GTP_CREATE_SESSION_REQUEST,
        std::chrono::milliseconds(100)
    ));

    messages.push_back(createMessage(
        "10.0.1.50", 36412, "10.0.2.10", 36412,
        ProtocolType::S1AP, MessageType::S1AP_INITIAL_UE_MESSAGE,
        std::chrono::milliseconds(0)  // Earlier timestamp
    ));

    messages.push_back(createMessage(
        "10.0.3.10", 2123, "10.0.2.10", 2123,
        ProtocolType::GTP_C, MessageType::GTP_CREATE_SESSION_RESPONSE,
        std::chrono::milliseconds(250)
    ));

    auto diagram = generator->generate(messages);

    ASSERT_EQ(diagram.events.size(), 3);

    // Verify sorted by timestamp
    EXPECT_EQ(diagram.events[0].message_type, MessageType::S1AP_INITIAL_UE_MESSAGE);
    EXPECT_EQ(diagram.events[1].message_type, MessageType::GTP_CREATE_SESSION_REQUEST);
    EXPECT_EQ(diagram.events[2].message_type, MessageType::GTP_CREATE_SESSION_RESPONSE);

    // Verify timestamps are in order
    EXPECT_LT(diagram.events[0].timestamp, diagram.events[1].timestamp);
    EXPECT_LT(diagram.events[1].timestamp, diagram.events[2].timestamp);
}

TEST_F(LadderDiagramGeneratorTest, InterfaceIdentificationS1MME) {
    std::vector<SessionMessageRef> messages;
    messages.push_back(createMessage(
        "10.0.1.50", 36412,
        "10.0.2.10", 36412,
        ProtocolType::S1AP,
        MessageType::S1AP_INITIAL_UE_MESSAGE
    ));

    auto diagram = generator->generate(messages);

    ASSERT_EQ(diagram.events.size(), 1);
    EXPECT_EQ(diagram.events[0].interface, "S1-MME");
}

TEST_F(LadderDiagramGeneratorTest, InterfaceIdentificationS11) {
    std::vector<SessionMessageRef> messages;

    // MME -> S-GW (GTP-C on S11)
    messages.push_back(createMessage(
        "10.0.2.10", 2123,
        "10.0.3.10", 2123,
        ProtocolType::GTP_C,
        MessageType::GTP_CREATE_SESSION_REQUEST
    ));

    auto diagram = generator->generate(messages);

    ASSERT_EQ(diagram.events.size(), 1);
    EXPECT_EQ(diagram.events[0].interface, "S11");
}

TEST_F(LadderDiagramGeneratorTest, InterfaceIdentificationDiameterS6a) {
    std::vector<SessionMessageRef> messages;

    auto msg = createMessage(
        "10.0.2.10", 3868,
        "10.0.5.10", 3868,
        ProtocolType::DIAMETER,
        MessageType::DIAMETER_AAR
    );
    msg.parsed_data["application_id"] = 16777251;  // S6a Application-ID
    messages.push_back(msg);

    auto diagram = generator->generate(messages);

    ASSERT_EQ(diagram.events.size(), 1);
    EXPECT_EQ(diagram.events[0].interface, "S6a");
}

TEST_F(LadderDiagramGeneratorTest, InterfaceIdentificationDiameterGx) {
    std::vector<SessionMessageRef> messages;

    auto msg = createMessage(
        "10.0.4.10", 3868,
        "10.0.6.10", 3868,
        ProtocolType::DIAMETER,
        MessageType::DIAMETER_CCR
    );
    msg.parsed_data["application_id"] = 16777238;  // Gx Application-ID
    messages.push_back(msg);

    auto diagram = generator->generate(messages);

    ASSERT_EQ(diagram.events.size(), 1);
    EXPECT_EQ(diagram.events[0].interface, "Gx");
}

TEST_F(LadderDiagramGeneratorTest, InterfaceIdentificationNGAP) {
    std::vector<SessionMessageRef> messages;
    messages.push_back(createMessage(
        "10.0.1.60", 38412,
        "10.0.2.20", 38412,
        ProtocolType::NGAP,
        MessageType::NGAP_INITIAL_UE_MESSAGE
    ));

    auto diagram = generator->generate(messages);

    ASSERT_EQ(diagram.events.size(), 1);
    EXPECT_EQ(diagram.events[0].interface, "N2");
}

TEST_F(LadderDiagramGeneratorTest, InterfaceIdentificationPFCP) {
    std::vector<SessionMessageRef> messages;
    messages.push_back(createMessage(
        "10.0.7.10", 8805,
        "10.0.8.10", 8805,
        ProtocolType::PFCP,
        MessageType::PFCP_SESSION_ESTABLISHMENT_REQUEST
    ));

    auto diagram = generator->generate(messages);

    ASSERT_EQ(diagram.events.size(), 1);
    EXPECT_EQ(diagram.events[0].interface, "N4");
}

TEST_F(LadderDiagramGeneratorTest, LatencyCalculationGTPCreateSession) {
    std::vector<SessionMessageRef> messages;

    // GTP Create Session Request
    messages.push_back(createMessage(
        "10.0.2.10", 2123, "10.0.3.10", 2123,
        ProtocolType::GTP_C, MessageType::GTP_CREATE_SESSION_REQUEST,
        std::chrono::milliseconds(0)
    ));

    // GTP Create Session Response (100ms later)
    messages.push_back(createMessage(
        "10.0.3.10", 2123, "10.0.2.10", 2123,
        ProtocolType::GTP_C, MessageType::GTP_CREATE_SESSION_RESPONSE,
        std::chrono::milliseconds(100)
    ));

    auto diagram = generator->generate(messages);

    ASSERT_EQ(diagram.events.size(), 2);

    // Request should have no latency
    EXPECT_FALSE(diagram.events[0].latency_us.has_value());

    // Response should have latency
    ASSERT_TRUE(diagram.events[1].latency_us.has_value());
    EXPECT_GE(diagram.events[1].latency_us.value(), 100000);  // >= 100ms in microseconds
}

TEST_F(LadderDiagramGeneratorTest, LatencyCalculationPFCP) {
    std::vector<SessionMessageRef> messages;

    // PFCP Session Establishment Request
    messages.push_back(createMessage(
        "10.0.7.10", 8805, "10.0.8.10", 8805,
        ProtocolType::PFCP, MessageType::PFCP_SESSION_ESTABLISHMENT_REQUEST,
        std::chrono::milliseconds(0)
    ));

    // PFCP Session Establishment Response (50ms later)
    messages.push_back(createMessage(
        "10.0.8.10", 8805, "10.0.7.10", 8805,
        ProtocolType::PFCP, MessageType::PFCP_SESSION_ESTABLISHMENT_RESPONSE,
        std::chrono::milliseconds(50)
    ));

    auto diagram = generator->generate(messages);

    ASSERT_EQ(diagram.events.size(), 2);
    ASSERT_TRUE(diagram.events[1].latency_us.has_value());
    EXPECT_GE(diagram.events[1].latency_us.value(), 50000);  // >= 50ms in microseconds
}

TEST_F(LadderDiagramGeneratorTest, ParticipantDetection) {
    std::vector<SessionMessageRef> messages;

    // S1AP: eNodeB -> MME
    messages.push_back(createMessage(
        "10.0.1.50", 36412, "10.0.2.10", 36412,
        ProtocolType::S1AP, MessageType::S1AP_INITIAL_UE_MESSAGE
    ));

    // GTP-C: MME -> S-GW
    messages.push_back(createMessage(
        "10.0.2.10", 2123, "10.0.3.10", 2123,
        ProtocolType::GTP_C, MessageType::GTP_CREATE_SESSION_REQUEST,
        std::chrono::milliseconds(100)
    ));

    auto diagram = generator->generate(messages);

    EXPECT_EQ(diagram.participants.size(), 3);  // eNodeB, MME, S-GW

    // Find each participant type
    bool found_enodeb = false;
    bool found_mme = false;
    bool found_sgw = false;

    for (const auto& p : diagram.participants) {
        if (p.type == ParticipantType::ENODEB) found_enodeb = true;
        if (p.type == ParticipantType::MME) found_mme = true;
        if (p.type == ParticipantType::SGW) found_sgw = true;
    }

    EXPECT_TRUE(found_enodeb);
    EXPECT_TRUE(found_mme);
    EXPECT_TRUE(found_sgw);
}

TEST_F(LadderDiagramGeneratorTest, MessageDirection) {
    std::vector<SessionMessageRef> messages;

    // Request
    messages.push_back(createMessage(
        "10.0.2.10", 2123, "10.0.3.10", 2123,
        ProtocolType::GTP_C, MessageType::GTP_CREATE_SESSION_REQUEST
    ));

    // Response
    messages.push_back(createMessage(
        "10.0.3.10", 2123, "10.0.2.10", 2123,
        ProtocolType::GTP_C, MessageType::GTP_CREATE_SESSION_RESPONSE,
        std::chrono::milliseconds(100)
    ));

    auto diagram = generator->generate(messages);

    ASSERT_EQ(diagram.events.size(), 2);
    EXPECT_EQ(diagram.events[0].direction, MessageDirection::REQUEST);
    EXPECT_EQ(diagram.events[1].direction, MessageDirection::RESPONSE);
}

TEST_F(LadderDiagramGeneratorTest, ProcedureGrouping) {
    std::vector<SessionMessageRef> messages;

    // Create messages for LTE Attach procedure
    auto msg1 = createMessage(
        "10.0.1.50", 36412, "10.0.2.10", 36412,
        ProtocolType::S1AP, MessageType::S1AP_INITIAL_UE_MESSAGE,
        std::chrono::milliseconds(0)
    );
    msg1.correlation_key.procedure_type = ProcedureType::LTE_ATTACH;
    messages.push_back(msg1);

    auto msg2 = createMessage(
        "10.0.2.10", 2123, "10.0.3.10", 2123,
        ProtocolType::GTP_C, MessageType::GTP_CREATE_SESSION_REQUEST,
        std::chrono::milliseconds(100)
    );
    msg2.correlation_key.procedure_type = ProcedureType::LTE_ATTACH;
    messages.push_back(msg2);

    auto msg3 = createMessage(
        "10.0.3.10", 2123, "10.0.2.10", 2123,
        ProtocolType::GTP_C, MessageType::GTP_CREATE_SESSION_RESPONSE,
        std::chrono::milliseconds(250)
    );
    msg3.correlation_key.procedure_type = ProcedureType::LTE_ATTACH;
    messages.push_back(msg3);

    auto diagram = generator->generate(messages);

    EXPECT_EQ(diagram.procedures.size(), 1);
    const auto& proc = diagram.procedures[0];
    EXPECT_EQ(proc.procedure_name, "LTE_ATTACH");
    EXPECT_EQ(proc.total_events, 3);
    EXPECT_GE(proc.duration.count(), 250);  // >= 250ms
}

TEST_F(LadderDiagramGeneratorTest, MetricsCalculation) {
    std::vector<SessionMessageRef> messages;

    for (int i = 0; i < 10; ++i) {
        messages.push_back(createMessage(
            "10.0.1.50", 36412, "10.0.2.10", 36412,
            ProtocolType::S1AP, MessageType::S1AP_INITIAL_UE_MESSAGE,
            std::chrono::milliseconds(i * 100)
        ));
    }

    auto diagram = generator->generate(messages);

    EXPECT_EQ(diagram.metrics.total_events, 10);
    EXPECT_GE(diagram.metrics.total_duration.count(), 900);  // >= 900ms
}

TEST_F(LadderDiagramGeneratorTest, JSONSerialization) {
    std::vector<SessionMessageRef> messages;
    messages.push_back(createMessage(
        "10.0.1.50", 36412, "10.0.2.10", 36412,
        ProtocolType::S1AP, MessageType::S1AP_INITIAL_UE_MESSAGE
    ));

    auto diagram = generator->generate(messages, "test_session", "Test Diagram");
    auto json = diagram.toJson();

    EXPECT_EQ(json["diagram_type"], "ladder");
    EXPECT_EQ(json["session_id"], "test_session");
    EXPECT_EQ(json["title"], "Test Diagram");
    EXPECT_TRUE(json.contains("participants"));
    EXPECT_TRUE(json.contains("events"));
    EXPECT_TRUE(json.contains("procedures"));
    EXPECT_TRUE(json.contains("metrics"));

    EXPECT_TRUE(json["participants"].is_array());
    EXPECT_TRUE(json["events"].is_array());
    EXPECT_EQ(json["events"].size(), 1);
}

TEST_F(LadderDiagramGeneratorTest, LargeEventSet) {
    std::vector<SessionMessageRef> messages;

    // Create 1000 events
    for (int i = 0; i < 1000; ++i) {
        messages.push_back(createMessage(
            "10.0.1.50", 36412, "10.0.2.10", 36412,
            ProtocolType::S1AP, MessageType::S1AP_INITIAL_UE_MESSAGE,
            std::chrono::milliseconds(i)
        ));
    }

    auto start = std::chrono::high_resolution_clock::now();
    auto diagram = generator->generate(messages);
    auto end = std::chrono::high_resolution_clock::now();

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    EXPECT_EQ(diagram.events.size(), 1000);
    EXPECT_LT(duration.count(), 100);  // Should complete in < 100ms

    // Verify JSON serialization
    auto json = diagram.toJson();
    EXPECT_EQ(json["events"].size(), 1000);
}

TEST_F(LadderDiagramGeneratorTest, ExplicitParticipantMapping) {
    generator->addParticipantMapping("10.0.1.50", "MyENodeB", ParticipantType::ENODEB);

    std::vector<SessionMessageRef> messages;
    messages.push_back(createMessage(
        "10.0.1.50", 36412, "10.0.2.10", 36412,
        ProtocolType::S1AP, MessageType::S1AP_INITIAL_UE_MESSAGE
    ));

    auto diagram = generator->generate(messages);

    bool found_custom = false;
    for (const auto& p : diagram.participants) {
        if (p.id == "MyENodeB") {
            found_custom = true;
            EXPECT_EQ(p.type, ParticipantType::ENODEB);
            EXPECT_EQ(p.ip_address, "10.0.1.50");
        }
    }

    EXPECT_TRUE(found_custom);
}

TEST_F(LadderDiagramGeneratorTest, CompleteLTEAttachFlow) {
    std::vector<SessionMessageRef> messages;

    // 1. S1AP Initial UE Message
    auto msg1 = createMessage(
        "10.0.1.50", 36412, "10.0.2.10", 36412,
        ProtocolType::S1AP, MessageType::S1AP_INITIAL_UE_MESSAGE,
        std::chrono::milliseconds(0)
    );
    msg1.correlation_key.procedure_type = ProcedureType::LTE_ATTACH;
    messages.push_back(msg1);

    // 2. Diameter S6a AIR (MME -> HSS)
    auto msg2 = createMessage(
        "10.0.2.10", 3868, "10.0.5.10", 3868,
        ProtocolType::DIAMETER, MessageType::DIAMETER_AAR,
        std::chrono::milliseconds(50)
    );
    msg2.parsed_data["application_id"] = 16777251;
    msg2.correlation_key.procedure_type = ProcedureType::LTE_ATTACH;
    messages.push_back(msg2);

    // 3. Diameter S6a AIA (HSS -> MME)
    auto msg3 = createMessage(
        "10.0.5.10", 3868, "10.0.2.10", 3868,
        ProtocolType::DIAMETER, MessageType::DIAMETER_AAA,
        std::chrono::milliseconds(150)
    );
    msg3.parsed_data["application_id"] = 16777251;
    msg3.correlation_key.procedure_type = ProcedureType::LTE_ATTACH;
    messages.push_back(msg3);

    // 4. GTP Create Session Request (MME -> S-GW)
    auto msg4 = createMessage(
        "10.0.2.10", 2123, "10.0.3.10", 2123,
        ProtocolType::GTP_C, MessageType::GTP_CREATE_SESSION_REQUEST,
        std::chrono::milliseconds(200)
    );
    msg4.correlation_key.procedure_type = ProcedureType::LTE_ATTACH;
    messages.push_back(msg4);

    // 5. GTP Create Session Response (S-GW -> MME)
    auto msg5 = createMessage(
        "10.0.3.10", 2123, "10.0.2.10", 2123,
        ProtocolType::GTP_C, MessageType::GTP_CREATE_SESSION_RESPONSE,
        std::chrono::milliseconds(350)
    );
    msg5.correlation_key.procedure_type = ProcedureType::LTE_ATTACH;
    messages.push_back(msg5);

    auto diagram = generator->generate(messages, "lte_attach_001", "LTE Attach Procedure");

    // Verify diagram structure
    EXPECT_EQ(diagram.events.size(), 5);
    EXPECT_GE(diagram.participants.size(), 4);  // eNodeB, MME, HSS, S-GW

    // Verify interfaces
    EXPECT_EQ(diagram.events[0].interface, "S1-MME");
    EXPECT_EQ(diagram.events[1].interface, "S6a");
    EXPECT_EQ(diagram.events[2].interface, "S6a");
    EXPECT_EQ(diagram.events[3].interface, "S11");
    EXPECT_EQ(diagram.events[4].interface, "S11");

    // Verify latencies
    EXPECT_TRUE(diagram.events[2].latency_us.has_value());  // AIR/AIA
    EXPECT_TRUE(diagram.events[4].latency_us.has_value());  // Create Session

    // Verify procedure grouping
    EXPECT_EQ(diagram.procedures.size(), 1);
    EXPECT_EQ(diagram.procedures[0].procedure_name, "LTE_ATTACH");
    EXPECT_EQ(diagram.procedures[0].total_events, 5);

    // Verify JSON output
    auto json = diagram.toJson();
    EXPECT_TRUE(json.is_object());
    EXPECT_EQ(json["title"], "LTE Attach Procedure");
}
