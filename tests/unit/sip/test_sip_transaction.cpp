#include <gtest/gtest.h>
#include "correlation/sip/sip_transaction.h"
#include "correlation/sip/sip_message.h"

using namespace callflow::correlation;

class SipTransactionTest : public ::testing::Test {
protected:
    SipMessage createInvite() {
        SipMessage msg;
        msg.setRequest(true);
        msg.setMethod("INVITE");
        msg.setCallId("call-1@example.com");
        msg.setCSeq(1);
        msg.setCSeqMethod("INVITE");
        msg.setTimestamp(1000.0);
        msg.setFrameNumber(100);

        SipViaHeader via;
        via.protocol = "SIP/2.0/UDP";
        via.sent_by = "192.168.1.100:5060";
        via.branch = "z9hG4bK-test-branch";
        via.index = 0;
        msg.addViaHeader(via);

        return msg;
    }

    SipMessage createResponse(int status_code) {
        SipMessage msg;
        msg.setRequest(false);
        msg.setStatusCode(status_code);
        msg.setCallId("call-1@example.com");
        msg.setCSeq(1);
        msg.setCSeqMethod("INVITE");
        msg.setTimestamp(1001.0);
        msg.setFrameNumber(101);
        return msg;
    }
};

TEST_F(SipTransactionTest, CreateTransaction) {
    auto invite = createInvite();
    SipTransaction txn("txn-1", invite);

    EXPECT_EQ(txn.getTransactionId(), "txn-1");
    EXPECT_EQ(txn.getMethod(), "INVITE");
    EXPECT_EQ(txn.getCSeq(), 1);
    EXPECT_EQ(txn.getBranch(), "z9hG4bK-test-branch");
    EXPECT_EQ(txn.getState(), SipTransactionState::TRYING);
}

TEST_F(SipTransactionTest, AddProvisionalResponse) {
    auto invite = createInvite();
    SipTransaction txn("txn-1", invite);

    auto trying = createResponse(100);
    txn.addResponse(trying);

    EXPECT_EQ(txn.getState(), SipTransactionState::PROCEEDING);
    EXPECT_TRUE(txn.hasProvisionalResponse());
    EXPECT_FALSE(txn.hasFinalResponse());
}

TEST_F(SipTransactionTest, AddFinalResponse) {
    auto invite = createInvite();
    SipTransaction txn("txn-1", invite);

    auto ok = createResponse(200);
    txn.addResponse(ok);

    EXPECT_EQ(txn.getState(), SipTransactionState::COMPLETED);
    EXPECT_TRUE(txn.hasFinalResponse());

    auto final = txn.getFinalResponse();
    ASSERT_TRUE(final.has_value());
    EXPECT_EQ(final->getStatusCode(), 200);
    EXPECT_EQ(txn.getFinalStatusCode(), 200);
}

TEST_F(SipTransactionTest, MultipleResponses) {
    auto invite = createInvite();
    SipTransaction txn("txn-1", invite);

    auto trying = createResponse(100);
    auto ringing = createResponse(180);
    auto ok = createResponse(200);

    txn.addResponse(trying);
    txn.addResponse(ringing);
    txn.addResponse(ok);

    EXPECT_EQ(txn.getResponses().size(), 3);
    EXPECT_EQ(txn.getState(), SipTransactionState::COMPLETED);
    EXPECT_TRUE(txn.hasProvisionalResponse());
    EXPECT_TRUE(txn.hasFinalResponse());
    EXPECT_EQ(txn.getFinalStatusCode(), 200);
}

TEST_F(SipTransactionTest, ErrorResponse) {
    auto invite = createInvite();
    SipTransaction txn("txn-1", invite);

    auto busy = createResponse(486);
    txn.addResponse(busy);

    EXPECT_EQ(txn.getState(), SipTransactionState::COMPLETED);
    EXPECT_EQ(txn.getFinalStatusCode(), 486);
}

TEST_F(SipTransactionTest, TimeTracking) {
    auto invite = createInvite();
    SipTransaction txn("txn-1", invite);

    EXPECT_EQ(txn.getStartTime(), 1000.0);

    auto ok = createResponse(200);
    txn.addResponse(ok);

    EXPECT_EQ(txn.getEndTime(), 1001.0);
    EXPECT_EQ(txn.getDuration(), 1.0);
}

TEST_F(SipTransactionTest, FrameRange) {
    auto invite = createInvite();
    SipTransaction txn("txn-1", invite);

    EXPECT_EQ(txn.getStartFrame(), 100);

    auto ok = createResponse(200);
    txn.addResponse(ok);

    EXPECT_EQ(txn.getEndFrame(), 101);
}

TEST_F(SipTransactionTest, NonInviteTransaction) {
    SipMessage register_msg;
    register_msg.setRequest(true);
    register_msg.setMethod("REGISTER");
    register_msg.setCSeq(1);
    register_msg.setCSeqMethod("REGISTER");
    register_msg.setTimestamp(1000.0);
    register_msg.setFrameNumber(100);

    SipViaHeader via;
    via.branch = "z9hG4bK-reg-branch";
    register_msg.addViaHeader(via);

    SipTransaction txn("txn-reg", register_msg);

    EXPECT_EQ(txn.getMethod(), "REGISTER");
    EXPECT_EQ(txn.getState(), SipTransactionState::TRYING);

    SipMessage ok;
    ok.setRequest(false);
    ok.setStatusCode(200);
    ok.setCSeqMethod("REGISTER");
    ok.setTimestamp(1001.0);
    ok.setFrameNumber(101);

    txn.addResponse(ok);
    EXPECT_EQ(txn.getState(), SipTransactionState::COMPLETED);
}
