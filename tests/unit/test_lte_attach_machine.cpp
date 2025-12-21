#include <gtest/gtest.h>

#include "correlation/lte_attach_machine.h"
#include "correlation/procedure_state_machine.h"
#include "session/session_types.h"

using namespace callflow;
using namespace callflow::correlation;

class LteAttachMachineTest : public ::testing::Test {
protected:
    void SetUp() override {
        machine = std::make_unique<LteAttachMachine>();
    }

    SessionMessageRef createMessage(MessageType msg_type, const std::string& nas_type = "") {
        SessionMessageRef msg;
        msg.message_id = "msg_" + std::to_string(msg_counter_++);
        msg.timestamp = std::chrono::system_clock::now();
        msg.message_type = msg_type;
        msg.protocol = ProtocolType::SCTP;
        msg.interface = InterfaceType::S1_MME;

        // Set correlation key with IMSI
        msg.correlation_key.imsi = "001010000000001";
        msg.correlation_key.mme_ue_s1ap_id = 12345;
        msg.correlation_key.enb_ue_s1ap_id = 67890;

        // Add NAS PDU if specified
        if (!nas_type.empty()) {
            msg.parsed_data["nas"]["message_type"] = nas_type;
            msg.parsed_data["nas"]["mobile_identity"]["imsi"] = "001010000000001";
        }

        return msg;
    }

    std::unique_ptr<LteAttachMachine> machine;
    static int msg_counter_;
};

int LteAttachMachineTest::msg_counter_ = 0;

TEST_F(LteAttachMachineTest, InitialStateIsIdle) {
    EXPECT_EQ(machine->getCurrentState(), LteAttachMachine::State::IDLE);
    EXPECT_FALSE(machine->isComplete());
    EXPECT_FALSE(machine->isFailed());
}

TEST_F(LteAttachMachineTest, AttachRequestStartsProcedure) {
    auto msg = createMessage(MessageType::S1AP_INITIAL_UE_MESSAGE, "ATTACH_REQUEST");

    bool changed = machine->processMessage(msg);

    EXPECT_TRUE(changed);
    EXPECT_EQ(machine->getCurrentState(), LteAttachMachine::State::ATTACH_REQUESTED);
    EXPECT_FALSE(machine->isComplete());
    EXPECT_FALSE(machine->isFailed());
}

TEST_F(LteAttachMachineTest, CompleteAttachProcedure) {
    // Step 1: Attach Request
    auto msg1 = createMessage(MessageType::S1AP_INITIAL_UE_MESSAGE, "ATTACH_REQUEST");
    EXPECT_TRUE(machine->processMessage(msg1));
    EXPECT_EQ(machine->getCurrentState(), LteAttachMachine::State::ATTACH_REQUESTED);

    // Step 2: Authentication Request
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    auto msg2 = createMessage(MessageType::S1AP_DOWNLINK_NAS_TRANSPORT, "AUTHENTICATION_REQUEST");
    EXPECT_TRUE(machine->processMessage(msg2));
    EXPECT_EQ(machine->getCurrentState(), LteAttachMachine::State::AUTHENTICATION_IN_PROGRESS);

    // Step 3: Authentication Response
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    auto msg3 = createMessage(MessageType::S1AP_UPLINK_NAS_TRANSPORT, "AUTHENTICATION_RESPONSE");
    EXPECT_TRUE(machine->processMessage(msg3));
    EXPECT_EQ(machine->getCurrentState(), LteAttachMachine::State::AUTHENTICATION_COMPLETE);

    // Step 4: Security Mode Command
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    auto msg4 = createMessage(MessageType::S1AP_DOWNLINK_NAS_TRANSPORT, "SECURITY_MODE_COMMAND");
    EXPECT_TRUE(machine->processMessage(msg4));
    EXPECT_EQ(machine->getCurrentState(), LteAttachMachine::State::SECURITY_MODE_IN_PROGRESS);

    // Step 5: Security Mode Complete
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    auto msg5 = createMessage(MessageType::S1AP_UPLINK_NAS_TRANSPORT, "SECURITY_MODE_COMPLETE");
    EXPECT_TRUE(machine->processMessage(msg5));
    EXPECT_EQ(machine->getCurrentState(), LteAttachMachine::State::SECURITY_MODE_COMPLETE);

    // Step 6: GTP Create Session Request
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    auto msg6 = createMessage(MessageType::GTP_CREATE_SESSION_REQ);
    EXPECT_TRUE(machine->processMessage(msg6));
    EXPECT_EQ(machine->getCurrentState(), LteAttachMachine::State::GTP_SESSION_CREATION_IN_PROGRESS);

    // Step 7: GTP Create Session Response
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    auto msg7 = createMessage(MessageType::GTP_CREATE_SESSION_RESP);
    msg7.parsed_data["fteids"] = nlohmann::json::array();
    msg7.parsed_data["fteids"].push_back({{"interface_type", "S1-U eNodeB"}, {"teid", 0x12345678}});
    msg7.parsed_data["ue_ip_address"]["ipv4"] = "10.1.2.3";
    EXPECT_TRUE(machine->processMessage(msg7));
    EXPECT_EQ(machine->getCurrentState(), LteAttachMachine::State::GTP_SESSION_CREATED);

    // Step 8: Initial Context Setup Request
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    auto msg8 = createMessage(MessageType::S1AP_INITIAL_CONTEXT_SETUP_REQ);
    EXPECT_TRUE(machine->processMessage(msg8));
    EXPECT_EQ(machine->getCurrentState(), LteAttachMachine::State::INITIAL_CONTEXT_SETUP_IN_PROGRESS);

    // Step 9: Attach Accept
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    auto msg9 = createMessage(MessageType::S1AP_DOWNLINK_NAS_TRANSPORT, "ATTACH_ACCEPT");
    EXPECT_TRUE(machine->processMessage(msg9));
    EXPECT_EQ(machine->getCurrentState(), LteAttachMachine::State::ATTACH_ACCEPTED);

    // Step 10: Attach Complete
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    auto msg10 = createMessage(MessageType::S1AP_UPLINK_NAS_TRANSPORT, "ATTACH_COMPLETE");
    EXPECT_TRUE(machine->processMessage(msg10));
    EXPECT_EQ(machine->getCurrentState(), LteAttachMachine::State::ATTACHED);

    // Verify completion
    EXPECT_TRUE(machine->isComplete());
    EXPECT_FALSE(machine->isFailed());

    // Verify metrics
    const auto& metrics = machine->getAttachMetrics();
    EXPECT_TRUE(metrics.imsi.has_value());
    EXPECT_EQ(metrics.imsi.value(), "001010000000001");
    EXPECT_TRUE(metrics.mme_ue_s1ap_id.has_value());
    EXPECT_TRUE(metrics.teid_s1u.has_value());
    EXPECT_TRUE(metrics.ue_ip.has_value());

    // Verify total time
    EXPECT_GT(metrics.total_attach_time.count(), 0);

    // Verify steps
    auto steps = machine->getSteps();
    EXPECT_EQ(steps.size(), 10);
}

TEST_F(LteAttachMachineTest, ExportToJson) {
    // Create a simple attach procedure
    auto msg1 = createMessage(MessageType::S1AP_INITIAL_UE_MESSAGE, "ATTACH_REQUEST");
    machine->processMessage(msg1);

    // Export to JSON
    nlohmann::json j = machine->toJson();

    EXPECT_EQ(j["procedure"].get<std::string>(), "LTE_ATTACH");
    EXPECT_EQ(j["state"].get<std::string>(), "ATTACH_REQUESTED");
    EXPECT_FALSE(j["complete"].get<bool>());
    EXPECT_FALSE(j["failed"].get<bool>());
    EXPECT_TRUE(j.contains("metrics"));
    EXPECT_TRUE(j.contains("steps"));
}

TEST_F(LteAttachMachineTest, ProcedureTypeIsCorrect) {
    EXPECT_EQ(machine->getProcedureType(), ProcedureType::LTE_ATTACH);
}

TEST_F(LteAttachMachineTest, StepsAreRecorded) {
    auto msg1 = createMessage(MessageType::S1AP_INITIAL_UE_MESSAGE, "ATTACH_REQUEST");
    machine->processMessage(msg1);

    auto steps = machine->getSteps();
    EXPECT_EQ(steps.size(), 1);
    EXPECT_EQ(steps[0].step_name, "Attach Request");
    EXPECT_EQ(steps[0].message_type, MessageType::S1AP_INITIAL_UE_MESSAGE);
    EXPECT_TRUE(steps[0].expected);
}
