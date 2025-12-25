#include <gtest/gtest.h>
#include "correlation/s1ap/s1ap_correlator.h"
#include "correlation/s1ap/s1ap_message.h"
#include "correlation/s1ap/s1ap_context.h"
#include "correlation/identity/subscriber_context_manager.h"
#include <vector>

using namespace callflow::correlation;

/**
 * Test fixture for S1AP correlator tests
 */
class S1apCorrelatorTest : public ::testing::Test {
protected:
    void SetUp() override {
        ctx_manager = std::make_unique<SubscriberContextManager>();
        correlator = std::make_unique<S1apCorrelator>(ctx_manager.get());
    }

    void TearDown() override {
        correlator.reset();
        ctx_manager.reset();
    }

    /**
     * Create a simple Initial UE Message
     */
    S1apMessage createInitialUeMessage(uint32_t enb_ue_id, uint32_t frame_num, double timestamp) {
        (void)frame_num;   // Reserved for future use
        (void)timestamp;   // Reserved for future use
        S1apMessage msg;
        msg.setProcedureCode(S1apProcedureCode::INITIAL_UE_MESSAGE);
        msg.setMessageType(S1apMessageType::INITIAL_UE_MESSAGE);
        msg.setEnbUeS1apId(enb_ue_id);
        msg.setRrcEstablishmentCause(RrcEstablishmentCause::MO_SIGNALLING);
        // Frame and timestamp would be set during parsing

        return msg;
    }

    /**
     * Create an Initial Context Setup Request
     */
    S1apMessage createInitialContextSetupRequest(uint32_t mme_ue_id, uint32_t enb_ue_id,
                                                  uint32_t frame_num, double timestamp) {
        (void)frame_num;   // Reserved for future use
        (void)timestamp;   // Reserved for future use
        S1apMessage msg;
        msg.setProcedureCode(S1apProcedureCode::INITIAL_CONTEXT_SETUP);
        msg.setMessageType(S1apMessageType::INITIAL_CONTEXT_SETUP_REQUEST);
        msg.setMmeUeS1apId(mme_ue_id);
        msg.setEnbUeS1apId(enb_ue_id);

        // Add E-RAB
        S1apMessage::ErabInfo erab;
        erab.erab_id = 5;
        erab.qci = 9;
        msg.addErab(erab);

        return msg;
    }

    /**
     * Create a UE Context Release Command
     */
    S1apMessage createUeContextReleaseCommand(uint32_t mme_ue_id, uint32_t enb_ue_id,
                                               uint32_t frame_num, double timestamp) {
        (void)frame_num;   // Reserved for future use
        (void)timestamp;   // Reserved for future use
        S1apMessage msg;
        msg.setProcedureCode(S1apProcedureCode::UE_CONTEXT_RELEASE);
        msg.setMessageType(S1apMessageType::UE_CONTEXT_RELEASE_COMMAND);
        msg.setMmeUeS1apId(mme_ue_id);
        msg.setEnbUeS1apId(enb_ue_id);
        msg.setCause(S1apCauseType::NAS, static_cast<uint8_t>(S1apNasCause::NORMAL_RELEASE));

        return msg;
    }

    std::unique_ptr<SubscriberContextManager> ctx_manager;
    std::unique_ptr<S1apCorrelator> correlator;
};

TEST_F(S1apCorrelatorTest, AddInitialUeMessage) {
    auto msg = createInitialUeMessage(100, 1, 1.0);

    correlator->addMessage(msg);

    auto contexts = correlator->getContexts();
    EXPECT_GE(contexts.size(), 1);
}

TEST_F(S1apCorrelatorTest, CorrelateByUeS1apIds) {
    auto msg1 = createInitialUeMessage(100, 1, 1.0);
    auto msg2 = createInitialContextSetupRequest(200, 100, 2, 2.0);

    correlator->addMessage(msg1);
    correlator->addMessage(msg2);

    auto* context = correlator->findContext(200, 100);
    EXPECT_NE(context, nullptr);

    if (context) {
        EXPECT_EQ(context->getMessageCount(), 2);
    }
}

TEST_F(S1apCorrelatorTest, FindContextByMmeUeId) {
    auto msg = createInitialContextSetupRequest(200, 100, 1, 1.0);

    correlator->addMessage(msg);

    auto* context = correlator->findContextByMmeUeId(200);
    EXPECT_NE(context, nullptr);

    if (context) {
        EXPECT_EQ(context->getMmeUeS1apId(), 200);
        EXPECT_EQ(context->getEnbUeS1apId(), 100);
    }
}

TEST_F(S1apCorrelatorTest, FindContextByEnbUeId) {
    auto msg = createInitialContextSetupRequest(200, 100, 1, 1.0);

    correlator->addMessage(msg);

    auto* context = correlator->findContextByEnbUeId(100);
    EXPECT_NE(context, nullptr);

    if (context) {
        EXPECT_EQ(context->getMmeUeS1apId(), 200);
        EXPECT_EQ(context->getEnbUeS1apId(), 100);
    }
}

TEST_F(S1apCorrelatorTest, ContextLifecycle) {
    auto msg1 = createInitialUeMessage(100, 1, 1.0);
    auto msg2 = createInitialContextSetupRequest(200, 100, 2, 2.0);
    auto msg3 = createUeContextReleaseCommand(200, 100, 3, 3.0);

    correlator->addMessage(msg1);
    correlator->addMessage(msg2);
    correlator->addMessage(msg3);

    auto* context = correlator->findContext(200, 100);
    EXPECT_NE(context, nullptr);

    if (context) {
        EXPECT_EQ(context->getMessageCount(), 3);
        EXPECT_EQ(context->getState(), S1apContext::State::RELEASE_PENDING);
    }
}

TEST_F(S1apCorrelatorTest, GetStatistics) {
    auto msg1 = createInitialUeMessage(100, 1, 1.0);
    auto msg2 = createInitialContextSetupRequest(200, 100, 2, 2.0);

    correlator->addMessage(msg1);
    correlator->addMessage(msg2);

    correlator->finalize();

    auto stats = correlator->getStats();
    EXPECT_EQ(stats.total_messages, 2);
    EXPECT_GE(stats.total_contexts, 1);
    EXPECT_EQ(stats.initial_ue_messages, 1);
    EXPECT_EQ(stats.context_setups, 1);
}

TEST_F(S1apCorrelatorTest, GetActiveContexts) {
    auto msg1 = createInitialUeMessage(100, 1, 1.0);
    auto msg2 = createInitialContextSetupRequest(200, 100, 2, 2.0);

    correlator->addMessage(msg1);
    correlator->addMessage(msg2);

    correlator->finalize();

    auto active_contexts = correlator->getActiveContexts();
    EXPECT_GE(active_contexts.size(), 1);
}

TEST_F(S1apCorrelatorTest, ErabTracking) {
    auto msg = createInitialContextSetupRequest(200, 100, 1, 1.0);

    correlator->addMessage(msg);

    auto* context = correlator->findContext(200, 100);
    EXPECT_NE(context, nullptr);

    if (context) {
        const auto& erabs = context->getErabs();
        EXPECT_GE(erabs.size(), 1);

        if (!erabs.empty()) {
            EXPECT_EQ(erabs[0].erab_id, 5);
            EXPECT_EQ(erabs[0].qci, 9);
            EXPECT_TRUE(erabs[0].active);
        }
    }
}

// Test S1AP Context
TEST(S1apContextTest, AddMessages) {
    S1apContext context(100, 200);

    S1apMessage msg1;
    msg1.setMessageType(S1apMessageType::INITIAL_UE_MESSAGE);

    S1apMessage msg2;
    msg2.setMessageType(S1apMessageType::DOWNLINK_NAS_TRANSPORT);

    context.addMessage(msg1);
    context.addMessage(msg2);

    EXPECT_EQ(context.getMessageCount(), 2);
}

TEST(S1apContextTest, StateTransition) {
    S1apContext context(100, 200);

    S1apMessage msg1;
    msg1.setMessageType(S1apMessageType::INITIAL_UE_MESSAGE);
    context.addMessage(msg1);
    EXPECT_EQ(context.getState(), S1apContext::State::INITIAL);

    S1apMessage msg2;
    msg2.setMessageType(S1apMessageType::INITIAL_CONTEXT_SETUP_REQUEST);
    context.addMessage(msg2);
    EXPECT_EQ(context.getState(), S1apContext::State::CONTEXT_SETUP);

    S1apMessage msg3;
    msg3.setMessageType(S1apMessageType::INITIAL_CONTEXT_SETUP_RESPONSE);
    context.addMessage(msg3);
    EXPECT_EQ(context.getState(), S1apContext::State::ACTIVE);
}

TEST(S1apContextTest, UeS1apIds) {
    S1apContext context(100, 200);

    EXPECT_EQ(context.getMmeUeS1apId(), 100);
    EXPECT_EQ(context.getEnbUeS1apId(), 200);
}

// Test S1AP Message
TEST(S1apMessageTest, GetDirection) {
    S1apMessage msg;

    msg.setMessageType(S1apMessageType::INITIAL_UE_MESSAGE);
    EXPECT_EQ(msg.getDirection(), S1apMessage::Direction::UPLINK);

    msg.setMessageType(S1apMessageType::DOWNLINK_NAS_TRANSPORT);
    EXPECT_EQ(msg.getDirection(), S1apMessage::Direction::DOWNLINK);

    msg.setMessageType(S1apMessageType::PAGING);
    EXPECT_EQ(msg.getDirection(), S1apMessage::Direction::DOWNLINK);
}

TEST(S1apMessageTest, IsUeAssociated) {
    S1apMessage msg;

    msg.setProcedureCode(S1apProcedureCode::INITIAL_UE_MESSAGE);
    EXPECT_TRUE(msg.isUeAssociated());

    msg.setProcedureCode(S1apProcedureCode::S1_SETUP);
    EXPECT_FALSE(msg.isUeAssociated());
}

TEST(S1apMessageTest, ContainsNasPdu) {
    S1apMessage msg;

    msg.setProcedureCode(S1apProcedureCode::DOWNLINK_NAS_TRANSPORT);
    EXPECT_TRUE(msg.containsNasPdu());

    msg.setProcedureCode(S1apProcedureCode::INITIAL_CONTEXT_SETUP);
    EXPECT_FALSE(msg.containsNasPdu());
}

TEST(S1apTypesTest, GetProcedureCodeName) {
    std::string name = getS1apProcedureCodeName(S1apProcedureCode::INITIAL_UE_MESSAGE);
    EXPECT_EQ(name, "Initial UE Message");

    name = getS1apProcedureCodeName(S1apProcedureCode::DOWNLINK_NAS_TRANSPORT);
    EXPECT_EQ(name, "Downlink NAS Transport");
}

TEST(S1apTypesTest, IsUeAssociated) {
    EXPECT_TRUE(isUeAssociated(S1apProcedureCode::INITIAL_UE_MESSAGE));
    EXPECT_TRUE(isUeAssociated(S1apProcedureCode::UPLINK_NAS_TRANSPORT));
    EXPECT_FALSE(isUeAssociated(S1apProcedureCode::PAGING));
    EXPECT_FALSE(isUeAssociated(S1apProcedureCode::S1_SETUP));
}

TEST(S1apTypesTest, ContainsNasPdu) {
    EXPECT_TRUE(containsNasPdu(S1apProcedureCode::INITIAL_UE_MESSAGE));
    EXPECT_TRUE(containsNasPdu(S1apProcedureCode::DOWNLINK_NAS_TRANSPORT));
    EXPECT_TRUE(containsNasPdu(S1apProcedureCode::UPLINK_NAS_TRANSPORT));
    EXPECT_FALSE(containsNasPdu(S1apProcedureCode::INITIAL_CONTEXT_SETUP));
}
