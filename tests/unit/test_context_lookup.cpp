#include <gtest/gtest.h>

#include "correlation/subscriber_context.h"

using namespace callflow::correlation;

// ============================================================================
// Test Fixture
// ============================================================================

class ContextLookupTest : public ::testing::Test {
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
// IMSI Lookup Tests
// ============================================================================

TEST_F(ContextLookupTest, FindByImsi) {
    std::string imsi = "310410123456789";
    auto context = manager_->getOrCreate(imsi);

    auto found = manager_->findByImsi(imsi);

    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->context_id, context->context_id);
    EXPECT_EQ(found.get(), context.get());
}

TEST_F(ContextLookupTest, FindByImsiNotFound) {
    auto found = manager_->findByImsi("999999999999999");
    EXPECT_EQ(found, nullptr);
}

TEST_F(ContextLookupTest, FindByImsiMultipleContexts) {
    std::string imsi1 = "310410111111111";
    std::string imsi2 = "310410222222222";
    std::string imsi3 = "310410333333333";

    auto ctx1 = manager_->getOrCreate(imsi1);
    auto ctx2 = manager_->getOrCreate(imsi2);
    auto ctx3 = manager_->getOrCreate(imsi3);

    auto found1 = manager_->findByImsi(imsi1);
    auto found2 = manager_->findByImsi(imsi2);
    auto found3 = manager_->findByImsi(imsi3);

    ASSERT_NE(found1, nullptr);
    ASSERT_NE(found2, nullptr);
    ASSERT_NE(found3, nullptr);

    EXPECT_EQ(found1->context_id, ctx1->context_id);
    EXPECT_EQ(found2->context_id, ctx2->context_id);
    EXPECT_EQ(found3->context_id, ctx3->context_id);
}

// ============================================================================
// SUPI Lookup Tests
// ============================================================================

TEST_F(ContextLookupTest, FindBySupi) {
    std::string supi = "imsi-310410123456789";
    auto context = manager_->getOrCreateBySupi(supi);

    auto found = manager_->findBySupi(supi);

    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->context_id, context->context_id);
}

TEST_F(ContextLookupTest, FindBySupiNotFound) {
    auto found = manager_->findBySupi("imsi-999999999999999");
    EXPECT_EQ(found, nullptr);
}

// ============================================================================
// MSISDN Lookup Tests
// ============================================================================

TEST_F(ContextLookupTest, FindByMsisdn) {
    std::string imsi = "310410123456789";
    std::string msisdn = "14155551234";

    auto context = manager_->getOrCreate(imsi);
    manager_->updateMsisdn(context->context_id, msisdn);

    auto found = manager_->findByMsisdn(msisdn);

    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->context_id, context->context_id);
}

TEST_F(ContextLookupTest, FindByMsisdnNotFound) {
    auto found = manager_->findByMsisdn("19999999999");
    EXPECT_EQ(found, nullptr);
}

// ============================================================================
// GUTI Lookup Tests
// ============================================================================

TEST_F(ContextLookupTest, FindByGuti) {
    std::string imsi = "310410123456789";
    auto context = manager_->getOrCreate(imsi);

    SubscriberContext::GUTI guti;
    guti.mcc_mnc = "310410";
    guti.mme_group_id = 0x1234;
    guti.mme_code = 0x56;
    guti.m_tmsi = 0x789ABCDE;

    manager_->updateGuti(context->context_id, guti);

    auto found = manager_->findByGuti(guti);

    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->context_id, context->context_id);
}

TEST_F(ContextLookupTest, FindByGutiNotFound) {
    SubscriberContext::GUTI guti;
    guti.mcc_mnc = "310410";
    guti.mme_group_id = 0xFFFF;
    guti.mme_code = 0xFF;
    guti.m_tmsi = 0xFFFFFFFF;

    auto found = manager_->findByGuti(guti);
    EXPECT_EQ(found, nullptr);
}

TEST_F(ContextLookupTest, FindByGutiAfterUpdate) {
    std::string imsi = "310410123456789";
    auto context = manager_->getOrCreate(imsi);

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

    manager_->updateGuti(context->context_id, guti1);
    manager_->updateGuti(context->context_id, guti2);

    // Should find by new GUTI
    auto found_new = manager_->findByGuti(guti2);
    ASSERT_NE(found_new, nullptr);
    EXPECT_EQ(found_new->context_id, context->context_id);

    // Old GUTI should not be indexed anymore (moved to history)
    auto found_old = manager_->findByGuti(guti1);
    EXPECT_EQ(found_old, nullptr);
}

// ============================================================================
// 5G-GUTI Lookup Tests
// ============================================================================

TEST_F(ContextLookupTest, FindByGuti5G) {
    std::string supi = "imsi-310410123456789";
    auto context = manager_->getOrCreateBySupi(supi);

    SubscriberContext::GUTI5G guti;
    guti.mcc_mnc = "310410";
    guti.amf_region_id = 0x12;
    guti.amf_set_id = 0x345;
    guti.amf_pointer = 0x06;
    guti.tmsi_5g = 0x789ABCDE;

    manager_->updateGuti5G(context->context_id, guti);

    auto found = manager_->findByGuti5G(guti);

    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->context_id, context->context_id);
}

// ============================================================================
// UE IP Lookup Tests
// ============================================================================

TEST_F(ContextLookupTest, FindByUeIpv4) {
    std::string imsi = "310410123456789";
    std::string ipv4 = "10.45.1.100";

    auto context = manager_->getOrCreate(imsi);
    manager_->updateUeIp(context->context_id, ipv4);

    auto found = manager_->findByUeIp(ipv4);

    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->context_id, context->context_id);
}

TEST_F(ContextLookupTest, FindByUeIpv6) {
    std::string imsi = "310410123456789";
    std::string ipv6 = "2001:db8::1";

    auto context = manager_->getOrCreate(imsi);
    manager_->updateUeIp(context->context_id, "", ipv6);

    auto found = manager_->findByUeIp(ipv6);

    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->context_id, context->context_id);
}

TEST_F(ContextLookupTest, FindByUeIpNotFound) {
    auto found = manager_->findByUeIp("192.168.1.1");
    EXPECT_EQ(found, nullptr);
}

TEST_F(ContextLookupTest, FindByUeIpAfterChange) {
    std::string imsi = "310410123456789";
    std::string ipv4_old = "10.45.1.100";
    std::string ipv4_new = "10.45.1.101";

    auto context = manager_->getOrCreate(imsi);
    manager_->updateUeIp(context->context_id, ipv4_old);
    manager_->updateUeIp(context->context_id, ipv4_new);

    // Should find by both old and new IP (both are indexed)
    auto found_old = manager_->findByUeIp(ipv4_old);
    auto found_new = manager_->findByUeIp(ipv4_new);

    ASSERT_NE(found_old, nullptr);
    ASSERT_NE(found_new, nullptr);
    EXPECT_EQ(found_old->context_id, context->context_id);
    EXPECT_EQ(found_new->context_id, context->context_id);
}

// ============================================================================
// TEID Lookup Tests
// ============================================================================

TEST_F(ContextLookupTest, FindByTeid) {
    std::string imsi = "310410123456789";
    auto context = manager_->getOrCreate(imsi);

    SubscriberContext::BearerInfo bearer;
    bearer.teid = 0x12345678;
    bearer.eps_bearer_id = 5;
    bearer.interface = "S1-U";
    bearer.pgw_ip = "192.168.1.1";
    bearer.qci = 9;
    bearer.created = std::chrono::system_clock::now();

    manager_->addBearer(context->context_id, bearer);

    auto found = manager_->findByTeid(0x12345678);

    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->context_id, context->context_id);
}

TEST_F(ContextLookupTest, FindByTeidNotFound) {
    auto found = manager_->findByTeid(0xFFFFFFFF);
    EXPECT_EQ(found, nullptr);
}

TEST_F(ContextLookupTest, FindByTeidMultipleBearers) {
    std::string imsi = "310410123456789";
    auto context = manager_->getOrCreate(imsi);

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

    manager_->addBearer(context->context_id, bearer1);
    manager_->addBearer(context->context_id, bearer2);

    auto found1 = manager_->findByTeid(0x11111111);
    auto found2 = manager_->findByTeid(0x22222222);

    ASSERT_NE(found1, nullptr);
    ASSERT_NE(found2, nullptr);
    EXPECT_EQ(found1->context_id, context->context_id);
    EXPECT_EQ(found2->context_id, context->context_id);
    EXPECT_EQ(found1->context_id, found2->context_id);  // Same context
}

// ============================================================================
// SEID Lookup Tests
// ============================================================================

TEST_F(ContextLookupTest, FindBySeid) {
    std::string imsi = "310410123456789";
    auto context = manager_->getOrCreate(imsi);

    uint64_t seid = 0x123456789ABCDEF0;
    manager_->addSeid(context->context_id, seid);

    auto found = manager_->findBySeid(seid);

    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->context_id, context->context_id);
}

TEST_F(ContextLookupTest, FindBySeidNotFound) {
    auto found = manager_->findBySeid(0xFFFFFFFFFFFFFFFF);
    EXPECT_EQ(found, nullptr);
}

// ============================================================================
// SIP URI Lookup Tests
// ============================================================================

TEST_F(ContextLookupTest, FindBySipUri) {
    std::string imsi = "310410123456789";
    std::string sip_uri = "sip:+14155551234@ims.mnc410.mcc310.3gppnetwork.org";

    auto context = manager_->getOrCreate(imsi);
    manager_->updateSipUri(context->context_id, sip_uri);

    auto found = manager_->findBySipUri(sip_uri);

    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->context_id, context->context_id);
}

TEST_F(ContextLookupTest, FindBySipUriNotFound) {
    auto found = manager_->findBySipUri("sip:unknown@example.com");
    EXPECT_EQ(found, nullptr);
}

// ============================================================================
// SIP Call-ID Lookup Tests
// ============================================================================

TEST_F(ContextLookupTest, FindBySipCallId) {
    std::string imsi = "310410123456789";
    std::string call_id = "a84b4c76e66710@192.0.2.4";

    auto context = manager_->getOrCreate(imsi);
    manager_->addSipCallId(context->context_id, call_id);

    auto found = manager_->findBySipCallId(call_id);

    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->context_id, context->context_id);
}

TEST_F(ContextLookupTest, FindBySipCallIdMultipleCalls) {
    std::string imsi = "310410123456789";
    std::string call_id1 = "call1@192.0.2.4";
    std::string call_id2 = "call2@192.0.2.4";

    auto context = manager_->getOrCreate(imsi);
    manager_->addSipCallId(context->context_id, call_id1);
    manager_->addSipCallId(context->context_id, call_id2);

    auto found1 = manager_->findBySipCallId(call_id1);
    auto found2 = manager_->findBySipCallId(call_id2);

    ASSERT_NE(found1, nullptr);
    ASSERT_NE(found2, nullptr);
    EXPECT_EQ(found1->context_id, context->context_id);
    EXPECT_EQ(found2->context_id, context->context_id);
}

// ============================================================================
// Control Plane ID Lookup Tests
// ============================================================================

TEST_F(ContextLookupTest, FindByMmeUeId) {
    std::string imsi = "310410123456789";
    uint32_t mme_ue_id = 12345;

    auto context = manager_->getOrCreate(imsi);
    manager_->updateMmeUeId(context->context_id, mme_ue_id);

    auto found = manager_->findByMmeUeId(mme_ue_id);

    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->context_id, context->context_id);
}

TEST_F(ContextLookupTest, FindByEnbUeId) {
    std::string imsi = "310410123456789";
    uint32_t enb_ue_id = 67890;

    auto context = manager_->getOrCreate(imsi);
    manager_->updateEnbUeId(context->context_id, enb_ue_id);

    auto found = manager_->findByEnbUeId(enb_ue_id);

    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->context_id, context->context_id);
}

TEST_F(ContextLookupTest, FindByAmfUeId) {
    std::string supi = "imsi-310410123456789";
    uint64_t amf_ue_id = 0x123456789ABCDEF0;

    auto context = manager_->getOrCreateBySupi(supi);
    manager_->updateAmfUeId(context->context_id, amf_ue_id);

    auto found = manager_->findByAmfUeId(amf_ue_id);

    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->context_id, context->context_id);
}

TEST_F(ContextLookupTest, FindByRanUeId) {
    std::string supi = "imsi-310410123456789";
    uint64_t ran_ue_id = 0xFEDCBA9876543210;

    auto context = manager_->getOrCreateBySupi(supi);
    manager_->updateRanUeId(context->context_id, ran_ue_id);

    auto found = manager_->findByRanUeId(ran_ue_id);

    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->context_id, context->context_id);
}

// ============================================================================
// Context ID Lookup Tests
// ============================================================================

TEST_F(ContextLookupTest, FindByContextId) {
    std::string imsi = "310410123456789";
    auto context = manager_->getOrCreate(imsi);

    auto found = manager_->findByContextId(context->context_id);

    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->context_id, context->context_id);
}

TEST_F(ContextLookupTest, FindByContextIdNotFound) {
    auto found = manager_->findByContextId("ctx_nonexistent");
    EXPECT_EQ(found, nullptr);
}

// ============================================================================
// Cross-Identifier Lookup Tests
// ============================================================================

TEST_F(ContextLookupTest, LookupByDifferentIdentifiers) {
    // Create context with IMSI
    std::string imsi = "310410123456789";
    auto context = manager_->getOrCreate(imsi);

    // Add MSISDN
    std::string msisdn = "14155551234";
    manager_->updateMsisdn(context->context_id, msisdn);

    // Add UE IP
    std::string ue_ip = "10.45.1.100";
    manager_->updateUeIp(context->context_id, ue_ip);

    // Add TEID
    SubscriberContext::BearerInfo bearer;
    bearer.teid = 0x12345678;
    bearer.eps_bearer_id = 5;
    bearer.interface = "S1-U";
    bearer.pgw_ip = "192.168.1.1";
    bearer.qci = 9;
    bearer.created = std::chrono::system_clock::now();
    manager_->addBearer(context->context_id, bearer);

    // Add SIP URI
    std::string sip_uri = "sip:+14155551234@ims.mnc410.mcc310.3gppnetwork.org";
    manager_->updateSipUri(context->context_id, sip_uri);

    // All lookups should return the same context
    auto by_imsi = manager_->findByImsi(imsi);
    auto by_msisdn = manager_->findByMsisdn(msisdn);
    auto by_ip = manager_->findByUeIp(ue_ip);
    auto by_teid = manager_->findByTeid(0x12345678);
    auto by_sip = manager_->findBySipUri(sip_uri);

    ASSERT_NE(by_imsi, nullptr);
    ASSERT_NE(by_msisdn, nullptr);
    ASSERT_NE(by_ip, nullptr);
    ASSERT_NE(by_teid, nullptr);
    ASSERT_NE(by_sip, nullptr);

    EXPECT_EQ(by_imsi->context_id, context->context_id);
    EXPECT_EQ(by_msisdn->context_id, context->context_id);
    EXPECT_EQ(by_ip->context_id, context->context_id);
    EXPECT_EQ(by_teid->context_id, context->context_id);
    EXPECT_EQ(by_sip->context_id, context->context_id);
}

// ============================================================================
// Lookup Statistics Tests
// ============================================================================

TEST_F(ContextLookupTest, LookupStats) {
    std::string imsi = "310410123456789";
    manager_->getOrCreate(imsi);

    // Perform lookups
    manager_->findByImsi(imsi);  // Hit
    manager_->findByImsi("999999999999999");  // Miss
    manager_->findByImsi(imsi);  // Hit

    auto stats = manager_->getStats();

    EXPECT_EQ(stats.lookups_total, 3);
    EXPECT_EQ(stats.lookups_hit, 2);
    EXPECT_DOUBLE_EQ(stats.getHitRate(), 2.0 / 3.0);
}

TEST_F(ContextLookupTest, ResetStats) {
    std::string imsi = "310410123456789";
    manager_->getOrCreate(imsi);

    manager_->findByImsi(imsi);
    auto stats1 = manager_->getStats();
    EXPECT_GT(stats1.lookups_total, 0);

    manager_->resetStats();
    auto stats2 = manager_->getStats();
    EXPECT_EQ(stats2.lookups_total, 0);
    EXPECT_EQ(stats2.lookups_hit, 0);
}

// ============================================================================
// Performance Tests
// ============================================================================

TEST_F(ContextLookupTest, DISABLED_PerformanceManyContexts) {
    // Create 10,000 contexts
    for (int i = 0; i < 10000; i++) {
        std::string imsi = "31041" + std::to_string(1000000000 + i);
        manager_->getOrCreate(imsi);
    }

    // Lookup should still be fast
    auto start = std::chrono::high_resolution_clock::now();
    auto found = manager_->findByImsi("310411000005000");
    auto end = std::chrono::high_resolution_clock::now();

    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);

    ASSERT_NE(found, nullptr);
    EXPECT_LT(duration.count(), 1000);  // Less than 1 microsecond
}

TEST_F(ContextLookupTest, DISABLED_PerformanceManyLookups) {
    std::string imsi = "310410123456789";
    manager_->getOrCreate(imsi);

    // Perform 1 million lookups
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000000; i++) {
        auto found = manager_->findByImsi(imsi);
        (void)found;  // Suppress unused warning
    }
    auto end = std::chrono::high_resolution_clock::now();

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    // Should complete in reasonable time (< 1 second for 1M lookups)
    EXPECT_LT(duration.count(), 1000);
}
