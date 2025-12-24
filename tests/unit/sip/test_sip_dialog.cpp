#include <gtest/gtest.h>
#include "correlation/sip/sip_dialog.h"
#include "correlation/sip/sip_message.h"

using namespace callflow::correlation;

class SipDialogTest : public ::testing::Test {
protected:
    void SetUp() override {
        dialog = std::make_unique<SipDialog>("dialog-1", "from-tag-123", "");
    }

    std::unique_ptr<SipDialog> dialog;

    SipMessage createInvite() {
        SipMessage msg;
        msg.setRequest(true);
        msg.setMethod("INVITE");
        msg.setCallId("call-1@example.com");
        msg.setFromTag("from-tag-123");
        msg.setToTag("");
        msg.setCSeq(1);
        msg.setCSeqMethod("INVITE");
        msg.setTimestamp(1000.0);
        msg.setFrameNumber(100);
        return msg;
    }

    SipMessage createResponse(int status_code, const std::string& to_tag) {
        SipMessage msg;
        msg.setRequest(false);
        msg.setStatusCode(status_code);
        msg.setCallId("call-1@example.com");
        msg.setFromTag("from-tag-123");
        msg.setToTag(to_tag);
        msg.setCSeq(1);
        msg.setCSeqMethod("INVITE");
        msg.setTimestamp(1001.0);
        msg.setFrameNumber(101);
        return msg;
    }
};

TEST_F(SipDialogTest, InitialState) {
    EXPECT_EQ(dialog->getDialogId(), "dialog-1");
    EXPECT_EQ(dialog->getFromTag(), "from-tag-123");
    EXPECT_EQ(dialog->getToTag(), "");
    EXPECT_EQ(dialog->getState(), SipDialogState::INIT);
    EXPECT_TRUE(dialog->isEarly());
    EXPECT_FALSE(dialog->isConfirmed());
}

TEST_F(SipDialogTest, AddInviteMessage) {
    auto invite = createInvite();
    dialog->addMessage(invite);

    EXPECT_EQ(dialog->getMessages().size(), 1);
    EXPECT_EQ(dialog->getState(), SipDialogState::CALLING);
    EXPECT_EQ(dialog->getStartTime(), 1000.0);
    EXPECT_EQ(dialog->getStartFrame(), 100);
}

TEST_F(SipDialogTest, DialogProgression) {
    auto invite = createInvite();
    dialog->addMessage(invite);
    EXPECT_EQ(dialog->getState(), SipDialogState::CALLING);

    // 180 Ringing with To-tag (early dialog)
    auto ringing = createResponse(180, "to-tag-456");
    dialog->addMessage(ringing);
    EXPECT_EQ(dialog->getState(), SipDialogState::EARLY);
    EXPECT_FALSE(dialog->isEarly());  // Now has To-tag
    EXPECT_EQ(dialog->getToTag(), "to-tag-456");

    // 200 OK (confirmed dialog)
    auto ok = createResponse(200, "to-tag-456");
    dialog->addMessage(ok);
    EXPECT_EQ(dialog->getState(), SipDialogState::CONFIRMED);
    EXPECT_TRUE(dialog->isConfirmed());
}

TEST_F(SipDialogTest, EarlyDialogWithoutToTag) {
    auto invite = createInvite();
    dialog->addMessage(invite);

    // 100 Trying without To-tag
    auto trying = createResponse(100, "");
    dialog->addMessage(trying);

    EXPECT_EQ(dialog->getState(), SipDialogState::PROCEEDING);
    EXPECT_TRUE(dialog->isEarly());  // Still no To-tag
}

TEST_F(SipDialogTest, DialogTermination) {
    auto invite = createInvite();
    dialog->addMessage(invite);

    // 486 Busy Here
    auto busy = createResponse(486, "");
    dialog->addMessage(busy);

    EXPECT_EQ(dialog->getState(), SipDialogState::TERMINATED);
    EXPECT_TRUE(dialog->isTerminated());
}

TEST_F(SipDialogTest, ByeTermination) {
    auto invite = createInvite();
    dialog->addMessage(invite);

    auto ok = createResponse(200, "to-tag-456");
    dialog->addMessage(ok);

    // BYE
    SipMessage bye;
    bye.setRequest(true);
    bye.setMethod("BYE");
    bye.setCallId("call-1@example.com");
    bye.setFromTag("from-tag-123");
    bye.setToTag("to-tag-456");
    bye.setTimestamp(1010.0);
    bye.setFrameNumber(110);

    dialog->addMessage(bye);
    EXPECT_EQ(dialog->getState(), SipDialogState::TERMINATED);
}

TEST_F(SipDialogTest, GetInitialRequest) {
    auto invite = createInvite();
    dialog->addMessage(invite);

    auto ok = createResponse(200, "to-tag-456");
    dialog->addMessage(ok);

    auto initial = dialog->getInitialRequest();
    ASSERT_NE(initial, nullptr);
    EXPECT_EQ(initial->getMethod(), "INVITE");
}

TEST_F(SipDialogTest, GetDialogEstablishingResponse) {
    auto invite = createInvite();
    dialog->addMessage(invite);

    auto ringing = createResponse(180, "to-tag-456");
    dialog->addMessage(ringing);

    auto ok = createResponse(200, "to-tag-456");
    dialog->addMessage(ok);

    auto establishing = dialog->getDialogEstablishingResponse();
    ASSERT_NE(establishing, nullptr);
    EXPECT_EQ(establishing->getStatusCode(), 200);
}

TEST_F(SipDialogTest, TimeWindow) {
    auto invite = createInvite();
    dialog->addMessage(invite);

    auto ok = createResponse(200, "to-tag-456");
    dialog->addMessage(ok);

    EXPECT_EQ(dialog->getStartTime(), 1000.0);
    EXPECT_EQ(dialog->getEndTime(), 1001.0);
    EXPECT_EQ(dialog->getDuration(), 1.0);
}

TEST_F(SipDialogTest, FrameRange) {
    auto invite = createInvite();
    dialog->addMessage(invite);

    auto ok = createResponse(200, "to-tag-456");
    dialog->addMessage(ok);

    EXPECT_EQ(dialog->getStartFrame(), 100);
    EXPECT_EQ(dialog->getEndFrame(), 101);
}
