
#include <gtest/gtest.h>

#include <chrono>
#include <memory>
#include <string>
#include <vector>

#include "correlation/sip_dialog_tracker.h"
#include "protocol_parsers/sip_parser.h"

using namespace callflow;

class SipCorrelationTest : public ::testing::Test {
protected:
    SipDialogTracker tracker;

    SipMessage createInvite() {
        SipMessage msg;
        msg.is_request = true;
        msg.method = "INVITE";
        msg.call_id = "call-123";
        msg.from_tag = "tag-from";
        msg.via_branch = "branch-1";
        msg.cseq = "1 INVITE";
        msg.from = "sip:alice@example.com";
        msg.to = "sip:bob@example.com";
        return msg;
    }

    SipMessage createResponse(int code, const std::string& branch, const std::string& to_tag = "") {
        SipMessage msg;
        msg.is_request = false;
        msg.status_code = code;
        msg.call_id = "call-123";
        msg.from_tag = "tag-from";
        msg.to_tag = to_tag;
        msg.via_branch = branch;
        msg.cseq = "1 INVITE";  // Simplify matching logic
        return msg;
    }
};

TEST_F(SipCorrelationTest, TransactionMatching) {
    auto invite = createInvite();
    auto now = std::chrono::system_clock::now();
    tracker.processMessage(invite, "1.2.3.4", "5.6.7.8", now);

    // 100 Trying
    auto trying = createResponse(100, "branch-1");
    tracker.processMessage(trying, "5.6.7.8", "1.2.3.4", now + std::chrono::milliseconds(10));

    // 180 Ringing (establishes early dialog)
    auto ringing = createResponse(180, "branch-1", "tag-to-A");
    tracker.processMessage(ringing, "5.6.7.8", "1.2.3.4", now + std::chrono::milliseconds(100));

    auto dialog = tracker.getDialogByCallId("call-123");
    ASSERT_TRUE(dialog != nullptr);
    EXPECT_EQ(dialog->state, SipDialog::State::EARLY);
    EXPECT_EQ(dialog->to_tag, "tag-to-A");

    // 200 OK (Confirms dialog)
    auto ok = createResponse(200, "branch-1", "tag-to-A");
    tracker.processMessage(ok, "5.6.7.8", "1.2.3.4", now + std::chrono::milliseconds(200));

    EXPECT_EQ(dialog->state, SipDialog::State::CONFIRMED);

    auto stats = tracker.getStats();
    EXPECT_EQ(stats.active_dialogs, 1);
    EXPECT_EQ(stats.completed_transactions, 1);
}

TEST_F(SipCorrelationTest, ForkingDetection) {
    auto invite = createInvite();
    auto now = std::chrono::system_clock::now();
    tracker.processMessage(invite, "1.2.3.4", "5.6.7.8", now);

    // Branch A (Early Dialog)
    auto ringingA = createResponse(180, "branch-1", "tag-to-A");
    tracker.processMessage(ringingA, "5.6.7.8", "1.2.3.4", now + std::chrono::milliseconds(50));

    // Branch B (Another Early Dialog from same request)
    // Note: In real scenarios, forking might happen downstream, but response comes back with same
    // branch? RFC 3261 says responses to same request have same branch. Forking is distinguished by
    // To-tag.

    auto ringingB = createResponse(180, "branch-1", "tag-to-B");
    tracker.processMessage(ringingB, "5.6.7.9", "1.2.3.4", now + std::chrono::milliseconds(60));

    // We should have 2 dialogs now
    auto dialogs = tracker.getAllDialogs();
    EXPECT_GE(dialogs.size(), 2);

    bool foundA = false;
    bool foundB = false;
    for (const auto& d : dialogs) {
        if (d->to_tag == "tag-to-A")
            foundA = true;
        if (d->to_tag == "tag-to-B")
            foundB = true;
    }
    EXPECT_TRUE(foundA);
    EXPECT_TRUE(foundB);

    // Check forking
    auto mainDialog = tracker.getDialogById("call-123:tag-from:tag-to-A");
    if (mainDialog) {
        EXPECT_TRUE(mainDialog->isForked());
    }
}
