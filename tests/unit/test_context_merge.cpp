#include <gtest/gtest.h>

#include "correlation/subscriber_context.h"

using namespace callflow::correlation;

// ============================================================================
// Test Fixture
// ============================================================================

class ContextMergeTest : public ::testing::Test {
protected:
    void SetUp() override {
        manager_ = std::make_unique<SubscriberContextManager>(10000);
    }

    void TearDown() override {
        manager_.reset();
    }

    std::unique_ptr<SubscriberContextManager> manager_;
};

// ============================================================================
// Basic Merge Tests
// ============================================================================

TEST_F(ContextMergeTest, MergeBasicContexts) {
    // Create two contexts
    auto ctx1 = manager_->getOrCreate("310410111111111");
    auto ctx2 = manager_->getOrCreate("310410222222222");

    std::string ctx1_id = ctx1->context_id;
    std::string ctx2_id = ctx2->context_id;

    // Merge ctx2 into ctx1
    bool result = manager_->mergeContexts(ctx1_id, ctx2_id);

    EXPECT_TRUE(result);

    // ctx1 should still exist
    auto found_ctx1 = manager_->findByContextId(ctx1_id);
    ASSERT_NE(found_ctx1, nullptr);

    // ctx2 should be removed
    auto found_ctx2 = manager_->findByContextId(ctx2_id);
    EXPECT_EQ(found_ctx2, nullptr);

    // Stats should reflect one less context
    auto stats = manager_->getStats();
    EXPECT_EQ(stats.total_contexts, 1);
    EXPECT_EQ(stats.merges_total, 1);
}

TEST_F(ContextMergeTest, MergeNonExistentContext) {
    auto ctx1 = manager_->getOrCreate("310410111111111");

    bool result = manager_->mergeContexts(ctx1->context_id, "ctx_nonexistent");

    EXPECT_FALSE(result);  // Should fail
}

// ============================================================================
// Merge with Identifiers
// ============================================================================

TEST_F(ContextMergeTest, MergePreservesImsi) {
    auto ctx1 = manager_->getOrCreate("310410111111111");
    auto ctx2 = manager_->createTemporaryContext();

    manager_->updateMsisdn(ctx2->context_id, "14155551234");

    std::string ctx1_id = ctx1->context_id;
    std::string ctx2_id = ctx2->context_id;

    manager_->mergeContexts(ctx1_id, ctx2_id);

    auto merged = manager_->findByContextId(ctx1_id);
    ASSERT_NE(merged, nullptr);
    ASSERT_TRUE(merged->imsi.has_value());
    EXPECT_EQ(merged->imsi.value(), "310410111111111");
    ASSERT_TRUE(merged->msisdn.has_value());
    EXPECT_EQ(merged->msisdn.value(), "14155551234");

    // Should be able to lookup by both identifiers
    auto by_imsi = manager_->findByImsi("310410111111111");
    auto by_msisdn = manager_->findByMsisdn("14155551234");
    ASSERT_NE(by_imsi, nullptr);
    ASSERT_NE(by_msisdn, nullptr);
    EXPECT_EQ(by_imsi->context_id, ctx1_id);
    EXPECT_EQ(by_msisdn->context_id, ctx1_id);
}

TEST_F(ContextMergeTest, MergeFillsMissingImsi) {
    auto ctx1 = manager_->createTemporaryContext();
    auto ctx2 = manager_->getOrCreate("310410222222222");

    std::string ctx1_id = ctx1->context_id;
    std::string ctx2_id = ctx2->context_id;

    // ctx1 has no IMSI, ctx2 has IMSI
    manager_->mergeContexts(ctx1_id, ctx2_id);

    auto merged = manager_->findByContextId(ctx1_id);
    ASSERT_NE(merged, nullptr);
    ASSERT_TRUE(merged->imsi.has_value());
    EXPECT_EQ(merged->imsi.value(), "310410222222222");

    // Should be able to lookup by IMSI
    auto by_imsi = manager_->findByImsi("310410222222222");
    ASSERT_NE(by_imsi, nullptr);
    EXPECT_EQ(by_imsi->context_id, ctx1_id);
}

TEST_F(ContextMergeTest, MergeFillsMissingMsisdn) {
    auto ctx1 = manager_->getOrCreate("310410111111111");
    auto ctx2 = manager_->createTemporaryContext();
    manager_->updateMsisdn(ctx2->context_id, "14155551234");

    std::string ctx1_id = ctx1->context_id;
    std::string ctx2_id = ctx2->context_id;

    manager_->mergeContexts(ctx1_id, ctx2_id);

    auto merged = manager_->findByContextId(ctx1_id);
    ASSERT_NE(merged, nullptr);
    ASSERT_TRUE(merged->msisdn.has_value());
    EXPECT_EQ(merged->msisdn.value(), "14155551234");
}

// ============================================================================
// Merge with GUTI
// ============================================================================

TEST_F(ContextMergeTest, MergePreservesGuti) {
    auto ctx1 = manager_->getOrCreate("310410111111111");
    auto ctx2 = manager_->createTemporaryContext();

    SubscriberContext::GUTI guti1;
    guti1.mcc_mnc = "310410";
    guti1.mme_group_id = 0x1234;
    guti1.mme_code = 0x56;
    guti1.m_tmsi = 0x11111111;

    SubscriberContext::GUTI guti2;
    guti2.mcc_mnc = "310410";
    guti2.mme_group_id = 0x1234;
    guti2.mme_code = 0x56;
    guti2.m_tmsi = 0x22222222;

    manager_->updateGuti(ctx1->context_id, guti1);
    manager_->updateGuti(ctx2->context_id, guti2);

    std::string ctx1_id = ctx1->context_id;
    std::string ctx2_id = ctx2->context_id;

    manager_->mergeContexts(ctx1_id, ctx2_id);

    auto merged = manager_->findByContextId(ctx1_id);
    ASSERT_NE(merged, nullptr);
    ASSERT_TRUE(merged->current_guti.has_value());
    EXPECT_EQ(merged->current_guti.value(), guti1);  // Keeps first
}

TEST_F(ContextMergeTest, MergeGutiHistory) {
    auto ctx1 = manager_->createTemporaryContext();
    auto ctx2 = manager_->createTemporaryContext();

    SubscriberContext::GUTI guti1;
    guti1.mcc_mnc = "310410";
    guti1.mme_group_id = 0x1234;
    guti1.mme_code = 0x56;
    guti1.m_tmsi = 0x11111111;

    SubscriberContext::GUTI guti2;
    guti2.mcc_mnc = "310410";
    guti2.mme_group_id = 0x1234;
    guti2.mme_code = 0x56;
    guti2.m_tmsi = 0x22222222;

    SubscriberContext::GUTI guti3;
    guti3.mcc_mnc = "310410";
    guti3.mme_group_id = 0x1234;
    guti3.mme_code = 0x56;
    guti3.m_tmsi = 0x33333333;

    // ctx1 has guti1, then guti2 (guti1 in history)
    manager_->updateGuti(ctx1->context_id, guti1);
    manager_->updateGuti(ctx1->context_id, guti2);

    // ctx2 has guti3
    manager_->updateGuti(ctx2->context_id, guti3);

    std::string ctx1_id = ctx1->context_id;
    std::string ctx2_id = ctx2->context_id;

    manager_->mergeContexts(ctx1_id, ctx2_id);

    auto merged = manager_->findByContextId(ctx1_id);
    ASSERT_NE(merged, nullptr);

    // Should have history from both contexts
    // ctx1 had guti1 in history, ctx2 had no history
    EXPECT_GE(merged->guti_history.size(), 1);
}

// ============================================================================
// Merge with UE IP Addresses
// ============================================================================

TEST_F(ContextMergeTest, MergeUeIpAddresses) {
    auto ctx1 = manager_->getOrCreate("310410111111111");
    auto ctx2 = manager_->createTemporaryContext();

    manager_->updateUeIp(ctx1->context_id, "10.45.1.100");
    manager_->updateUeIp(ctx2->context_id, "10.45.1.101");

    std::string ctx1_id = ctx1->context_id;
    std::string ctx2_id = ctx2->context_id;

    manager_->mergeContexts(ctx1_id, ctx2_id);

    auto merged = manager_->findByContextId(ctx1_id);
    ASSERT_NE(merged, nullptr);

    // Should have both IPs
    EXPECT_EQ(merged->ue_ipv4_addresses.size(), 2);
    EXPECT_TRUE(merged->ue_ipv4_addresses.count("10.45.1.100"));
    EXPECT_TRUE(merged->ue_ipv4_addresses.count("10.45.1.101"));

    // Both IPs should lookup to merged context
    auto by_ip1 = manager_->findByUeIp("10.45.1.100");
    auto by_ip2 = manager_->findByUeIp("10.45.1.101");
    ASSERT_NE(by_ip1, nullptr);
    ASSERT_NE(by_ip2, nullptr);
    EXPECT_EQ(by_ip1->context_id, ctx1_id);
    EXPECT_EQ(by_ip2->context_id, ctx1_id);
}

TEST_F(ContextMergeTest, MergeIpv6Addresses) {
    auto ctx1 = manager_->getOrCreate("310410111111111");
    auto ctx2 = manager_->createTemporaryContext();

    manager_->updateUeIp(ctx1->context_id, "", "2001:db8::1");
    manager_->updateUeIp(ctx2->context_id, "", "2001:db8::2");

    std::string ctx1_id = ctx1->context_id;
    std::string ctx2_id = ctx2->context_id;

    manager_->mergeContexts(ctx1_id, ctx2_id);

    auto merged = manager_->findByContextId(ctx1_id);
    ASSERT_NE(merged, nullptr);

    EXPECT_EQ(merged->ue_ipv6_addresses.size(), 2);
    EXPECT_TRUE(merged->ue_ipv6_addresses.count("2001:db8::1"));
    EXPECT_TRUE(merged->ue_ipv6_addresses.count("2001:db8::2"));
}

// ============================================================================
// Merge with Bearers
// ============================================================================

TEST_F(ContextMergeTest, MergeBearers) {
    auto ctx1 = manager_->getOrCreate("310410111111111");
    auto ctx2 = manager_->createTemporaryContext();

    SubscriberContext::BearerInfo bearer1;
    bearer1.teid = 0x11111111;
    bearer1.eps_bearer_id = 5;
    bearer1.interface = "S1-U";
    bearer1.pgw_ip = "192.168.1.1";
    bearer1.qci = 9;
    bearer1.created = std::chrono::system_clock::now();

    SubscriberContext::BearerInfo bearer2;
    bearer2.teid = 0x22222222;
    bearer2.eps_bearer_id = 6;
    bearer2.interface = "S1-U";
    bearer2.pgw_ip = "192.168.1.1";
    bearer2.qci = 1;
    bearer2.created = std::chrono::system_clock::now();

    manager_->addBearer(ctx1->context_id, bearer1);
    manager_->addBearer(ctx2->context_id, bearer2);

    std::string ctx1_id = ctx1->context_id;
    std::string ctx2_id = ctx2->context_id;

    manager_->mergeContexts(ctx1_id, ctx2_id);

    auto merged = manager_->findByContextId(ctx1_id);
    ASSERT_NE(merged, nullptr);

    // Should have both bearers
    EXPECT_EQ(merged->bearers.size(), 2);

    // Both TEIDs should lookup to merged context
    auto by_teid1 = manager_->findByTeid(0x11111111);
    auto by_teid2 = manager_->findByTeid(0x22222222);
    ASSERT_NE(by_teid1, nullptr);
    ASSERT_NE(by_teid2, nullptr);
    EXPECT_EQ(by_teid1->context_id, ctx1_id);
    EXPECT_EQ(by_teid2->context_id, ctx1_id);
}

// ============================================================================
// Merge with PDU Sessions
// ============================================================================

TEST_F(ContextMergeTest, MergePduSessions) {
    auto ctx1 = manager_->getOrCreateBySupi("imsi-310410111111111");
    auto ctx2 = manager_->createTemporaryContext();

    SubscriberContext::PduSessionInfo session1;
    session1.pdu_session_id = 1;
    session1.uplink_teid = 0x11111111;
    session1.downlink_teid = 0x22222222;
    session1.dnn = "internet";
    session1.sst = 1;
    session1.created = std::chrono::system_clock::now();

    SubscriberContext::PduSessionInfo session2;
    session2.pdu_session_id = 2;
    session2.uplink_teid = 0x33333333;
    session2.downlink_teid = 0x44444444;
    session2.dnn = "ims";
    session2.sst = 1;
    session2.created = std::chrono::system_clock::now();

    manager_->addPduSession(ctx1->context_id, session1);
    manager_->addPduSession(ctx2->context_id, session2);

    std::string ctx1_id = ctx1->context_id;
    std::string ctx2_id = ctx2->context_id;

    manager_->mergeContexts(ctx1_id, ctx2_id);

    auto merged = manager_->findByContextId(ctx1_id);
    ASSERT_NE(merged, nullptr);

    EXPECT_EQ(merged->pdu_sessions.size(), 2);
}

// ============================================================================
// Merge with SEIDs
// ============================================================================

TEST_F(ContextMergeTest, MergeSeids) {
    auto ctx1 = manager_->getOrCreate("310410111111111");
    auto ctx2 = manager_->createTemporaryContext();

    manager_->addSeid(ctx1->context_id, 0x1111111111111111);
    manager_->addSeid(ctx2->context_id, 0x2222222222222222);

    std::string ctx1_id = ctx1->context_id;
    std::string ctx2_id = ctx2->context_id;

    manager_->mergeContexts(ctx1_id, ctx2_id);

    auto merged = manager_->findByContextId(ctx1_id);
    ASSERT_NE(merged, nullptr);

    EXPECT_EQ(merged->seids.size(), 2);
    EXPECT_TRUE(merged->seids.count(0x1111111111111111));
    EXPECT_TRUE(merged->seids.count(0x2222222222222222));

    // Both SEIDs should lookup to merged context
    auto by_seid1 = manager_->findBySeid(0x1111111111111111);
    auto by_seid2 = manager_->findBySeid(0x2222222222222222);
    ASSERT_NE(by_seid1, nullptr);
    ASSERT_NE(by_seid2, nullptr);
    EXPECT_EQ(by_seid1->context_id, ctx1_id);
    EXPECT_EQ(by_seid2->context_id, ctx1_id);
}

// ============================================================================
// Merge with Control Plane IDs
// ============================================================================

TEST_F(ContextMergeTest, MergeControlPlaneIds) {
    auto ctx1 = manager_->getOrCreate("310410111111111");
    auto ctx2 = manager_->createTemporaryContext();

    manager_->updateMmeUeId(ctx1->context_id, 12345);
    manager_->updateEnbUeId(ctx2->context_id, 67890);

    std::string ctx1_id = ctx1->context_id;
    std::string ctx2_id = ctx2->context_id;

    manager_->mergeContexts(ctx1_id, ctx2_id);

    auto merged = manager_->findByContextId(ctx1_id);
    ASSERT_NE(merged, nullptr);

    // ctx1 already had MME UE ID, should keep it
    ASSERT_TRUE(merged->mme_ue_s1ap_id.has_value());
    EXPECT_EQ(merged->mme_ue_s1ap_id.value(), 12345);

    // ctx2 had eNB UE ID, should be added
    ASSERT_TRUE(merged->enb_ue_s1ap_id.has_value());
    EXPECT_EQ(merged->enb_ue_s1ap_id.value(), 67890);

    // Both IDs should lookup to merged context
    auto by_mme = manager_->findByMmeUeId(12345);
    auto by_enb = manager_->findByEnbUeId(67890);
    ASSERT_NE(by_mme, nullptr);
    ASSERT_NE(by_enb, nullptr);
    EXPECT_EQ(by_mme->context_id, ctx1_id);
    EXPECT_EQ(by_enb->context_id, ctx1_id);
}

// ============================================================================
// Merge with IMS/VoLTE Identifiers
// ============================================================================

TEST_F(ContextMergeTest, MergeSipUris) {
    auto ctx1 = manager_->getOrCreate("310410111111111");
    auto ctx2 = manager_->createTemporaryContext();

    manager_->updateSipUri(ctx1->context_id, "sip:user1@ims.example.com");
    manager_->updateSipUri(ctx2->context_id, "sip:user2@ims.example.com");

    std::string ctx1_id = ctx1->context_id;
    std::string ctx2_id = ctx2->context_id;

    manager_->mergeContexts(ctx1_id, ctx2_id);

    auto merged = manager_->findByContextId(ctx1_id);
    ASSERT_NE(merged, nullptr);

    EXPECT_EQ(merged->sip_uris.size(), 2);
    EXPECT_TRUE(merged->sip_uris.count("sip:user1@ims.example.com"));
    EXPECT_TRUE(merged->sip_uris.count("sip:user2@ims.example.com"));

    // Both URIs should lookup to merged context
    auto by_uri1 = manager_->findBySipUri("sip:user1@ims.example.com");
    auto by_uri2 = manager_->findBySipUri("sip:user2@ims.example.com");
    ASSERT_NE(by_uri1, nullptr);
    ASSERT_NE(by_uri2, nullptr);
    EXPECT_EQ(by_uri1->context_id, ctx1_id);
    EXPECT_EQ(by_uri2->context_id, ctx1_id);
}

TEST_F(ContextMergeTest, MergeSipCallIds) {
    auto ctx1 = manager_->getOrCreate("310410111111111");
    auto ctx2 = manager_->createTemporaryContext();

    manager_->addSipCallId(ctx1->context_id, "call1@192.0.2.4");
    manager_->addSipCallId(ctx2->context_id, "call2@192.0.2.4");

    std::string ctx1_id = ctx1->context_id;
    std::string ctx2_id = ctx2->context_id;

    manager_->mergeContexts(ctx1_id, ctx2_id);

    auto merged = manager_->findByContextId(ctx1_id);
    ASSERT_NE(merged, nullptr);

    EXPECT_EQ(merged->sip_call_ids.size(), 2);
    EXPECT_TRUE(merged->sip_call_ids.count("call1@192.0.2.4"));
    EXPECT_TRUE(merged->sip_call_ids.count("call2@192.0.2.4"));
}

// ============================================================================
// Merge with Session IDs
// ============================================================================

TEST_F(ContextMergeTest, MergeSessionIds) {
    auto ctx1 = manager_->getOrCreate("310410111111111");
    auto ctx2 = manager_->createTemporaryContext();

    manager_->addSessionId(ctx1->context_id, "session_1");
    manager_->addSessionId(ctx2->context_id, "session_2");

    std::string ctx1_id = ctx1->context_id;
    std::string ctx2_id = ctx2->context_id;

    manager_->mergeContexts(ctx1_id, ctx2_id);

    auto merged = manager_->findByContextId(ctx1_id);
    ASSERT_NE(merged, nullptr);

    EXPECT_EQ(merged->session_ids.size(), 2);
    EXPECT_TRUE(merged->session_ids.count("session_1"));
    EXPECT_TRUE(merged->session_ids.count("session_2"));
}

// ============================================================================
// Merge Lifecycle
// ============================================================================

TEST_F(ContextMergeTest, MergePreservesEarliestFirstSeen) {
    auto ctx1 = manager_->getOrCreate("310410111111111");
    auto first_seen1 = ctx1->first_seen;

    // Wait a bit
    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    auto ctx2 = manager_->createTemporaryContext();
    auto first_seen2 = ctx2->first_seen;

    EXPECT_LT(first_seen1, first_seen2);  // ctx1 is older

    std::string ctx1_id = ctx1->context_id;
    std::string ctx2_id = ctx2->context_id;

    manager_->mergeContexts(ctx1_id, ctx2_id);

    auto merged = manager_->findByContextId(ctx1_id);
    ASSERT_NE(merged, nullptr);

    // Should keep earlier first_seen (from ctx1)
    EXPECT_EQ(merged->first_seen, first_seen1);
}

TEST_F(ContextMergeTest, MergePreservesEarliestFirstSeenReversed) {
    auto ctx1 = manager_->getOrCreate("310410111111111");
    auto first_seen1 = ctx1->first_seen;

    // Wait a bit
    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    auto ctx2 = manager_->createTemporaryContext();
    auto first_seen2 = ctx2->first_seen;

    EXPECT_LT(first_seen1, first_seen2);  // ctx1 is older

    std::string ctx1_id = ctx1->context_id;
    std::string ctx2_id = ctx2->context_id;

    // Merge in reverse order (ctx1 into ctx2)
    manager_->mergeContexts(ctx2_id, ctx1_id);

    auto merged = manager_->findByContextId(ctx2_id);
    ASSERT_NE(merged, nullptr);

    // Should still keep earlier first_seen (from ctx1)
    EXPECT_EQ(merged->first_seen, first_seen1);
}

TEST_F(ContextMergeTest, MergeUpdatesLastUpdated) {
    auto ctx1 = manager_->getOrCreate("310410111111111");
    auto ctx2 = manager_->createTemporaryContext();

    auto last_updated_before = ctx1->last_updated;

    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    std::string ctx1_id = ctx1->context_id;
    std::string ctx2_id = ctx2->context_id;

    manager_->mergeContexts(ctx1_id, ctx2_id);

    auto merged = manager_->findByContextId(ctx1_id);
    ASSERT_NE(merged, nullptr);

    // last_updated should be updated to merge time
    EXPECT_GT(merged->last_updated, last_updated_before);
}

// ============================================================================
// Complex Merge Scenarios
// ============================================================================

TEST_F(ContextMergeTest, CompleteVoLTEMerge) {
    // Simulate real-world scenario:
    // - ctx1 created from GTP with IMSI, TEID, UE IP
    // - ctx2 created from SIP with SIP URI (using same UE IP, but correlation missed)
    // - Merge them when correlation is discovered

    auto ctx1 = manager_->getOrCreate("310410123456789");
    manager_->updateMsisdn(ctx1->context_id, "14155551234");
    manager_->updateUeIp(ctx1->context_id, "10.45.1.100");

    SubscriberContext::BearerInfo bearer;
    bearer.teid = 0x12345678;
    bearer.eps_bearer_id = 5;
    bearer.interface = "S1-U";
    bearer.pgw_ip = "192.168.1.1";
    bearer.qci = 9;
    bearer.created = std::chrono::system_clock::now();
    manager_->addBearer(ctx1->context_id, bearer);

    auto ctx2 = manager_->createTemporaryContext();
    manager_->updateUeIp(ctx2->context_id, "10.45.1.100");  // Same IP
    manager_->updateSipUri(ctx2->context_id, "sip:+14155551234@ims.mnc410.mcc310.3gppnetwork.org");
    manager_->addSipCallId(ctx2->context_id, "a84b4c76e66710@192.0.2.4");

    std::string ctx1_id = ctx1->context_id;
    std::string ctx2_id = ctx2->context_id;

    // Merge
    manager_->mergeContexts(ctx1_id, ctx2_id);

    auto merged = manager_->findByContextId(ctx1_id);
    ASSERT_NE(merged, nullptr);

    // Should have all identifiers
    ASSERT_TRUE(merged->imsi.has_value());
    EXPECT_EQ(merged->imsi.value(), "310410123456789");
    ASSERT_TRUE(merged->msisdn.has_value());
    EXPECT_EQ(merged->msisdn.value(), "14155551234");
    EXPECT_EQ(merged->current_ue_ipv4, "10.45.1.100");
    EXPECT_EQ(merged->bearers.size(), 1);
    EXPECT_EQ(merged->sip_uris.size(), 1);
    EXPECT_EQ(merged->sip_call_ids.size(), 1);

    // All lookups should work
    auto by_imsi = manager_->findByImsi("310410123456789");
    auto by_msisdn = manager_->findByMsisdn("14155551234");
    auto by_ip = manager_->findByUeIp("10.45.1.100");
    auto by_teid = manager_->findByTeid(0x12345678);
    auto by_sip = manager_->findBySipUri("sip:+14155551234@ims.mnc410.mcc310.3gppnetwork.org");
    auto by_call = manager_->findBySipCallId("a84b4c76e66710@192.0.2.4");

    ASSERT_NE(by_imsi, nullptr);
    ASSERT_NE(by_msisdn, nullptr);
    ASSERT_NE(by_ip, nullptr);
    ASSERT_NE(by_teid, nullptr);
    ASSERT_NE(by_sip, nullptr);
    ASSERT_NE(by_call, nullptr);

    EXPECT_EQ(by_imsi->context_id, ctx1_id);
    EXPECT_EQ(by_msisdn->context_id, ctx1_id);
    EXPECT_EQ(by_ip->context_id, ctx1_id);
    EXPECT_EQ(by_teid->context_id, ctx1_id);
    EXPECT_EQ(by_sip->context_id, ctx1_id);
    EXPECT_EQ(by_call->context_id, ctx1_id);
}
