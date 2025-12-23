#include <gtest/gtest.h>

#include "correlation/subscriber_context.h"

using namespace callflow::correlation;

// ============================================================================
// Test Fixture
// ============================================================================

class LteAttachCorrelationTest : public ::testing::Test {
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
// Full LTE Attach Procedure Test
// ============================================================================

TEST_F(LteAttachCorrelationTest, CompleteLteAttachProcedure) {
    std::string imsi = "310410123456789";
    std::string msisdn = "14155551234";

    // Step 1: S1AP Initial UE Message / NAS Attach Request
    // - We learn IMSI from NAS Attach Request
    auto context = manager_->getOrCreate(imsi);
    ASSERT_NE(context, nullptr);

    // Step 2: S1AP context is established
    // - MME assigns MME UE S1AP ID
    // - eNodeB assigns eNB UE S1AP ID
    uint32_t mme_ue_s1ap_id = 12345;
    uint32_t enb_ue_s1ap_id = 67890;
    manager_->updateMmeUeId(context->context_id, mme_ue_s1ap_id);
    manager_->updateEnbUeId(context->context_id, enb_ue_s1ap_id);

    // Step 3: Authentication and Security (AKA)
    // - No new identifiers in this test

    // Step 4: NAS Attach Accept
    // - MME assigns GUTI
    SubscriberContext::GUTI guti;
    guti.mcc_mnc = "310410";
    guti.mme_group_id = 0x1234;
    guti.mme_code = 0x56;
    guti.m_tmsi = 0x789ABCDE;
    manager_->updateGuti(context->context_id, guti);

    // Step 5: GTPv2-C Create Session Request/Response
    // - P-GW assigns UE IP address
    // - S-GW assigns TEID for S1-U
    std::string ue_ipv4 = "10.45.1.100";
    manager_->updateUeIp(context->context_id, ue_ipv4);

    SubscriberContext::BearerInfo bearer;
    bearer.teid = 0x87654321;
    bearer.eps_bearer_id = 5;  // Default bearer
    bearer.interface = "S1-U";
    bearer.pgw_ip = "192.168.1.1";
    bearer.qci = 9;  // Best effort
    bearer.uplink_teid = 0x11111111;
    bearer.downlink_teid = 0x22222222;
    bearer.created = std::chrono::system_clock::now();
    manager_->addBearer(context->context_id, bearer);

    // Step 6: S1AP Initial Context Setup Request/Response
    // - Radio bearers established

    // Step 7: NAS Attach Complete
    // - UE confirms attach

    // Verification: All lookups should work
    auto by_imsi = manager_->findByImsi(imsi);
    ASSERT_NE(by_imsi, nullptr);
    EXPECT_EQ(by_imsi->context_id, context->context_id);

    auto by_guti = manager_->findByGuti(guti);
    ASSERT_NE(by_guti, nullptr);
    EXPECT_EQ(by_guti->context_id, context->context_id);

    auto by_ip = manager_->findByUeIp(ue_ipv4);
    ASSERT_NE(by_ip, nullptr);
    EXPECT_EQ(by_ip->context_id, context->context_id);

    auto by_teid = manager_->findByTeid(bearer.teid);
    ASSERT_NE(by_teid, nullptr);
    EXPECT_EQ(by_teid->context_id, context->context_id);

    auto by_mme_id = manager_->findByMmeUeId(mme_ue_s1ap_id);
    ASSERT_NE(by_mme_id, nullptr);
    EXPECT_EQ(by_mme_id->context_id, context->context_id);

    auto by_enb_id = manager_->findByEnbUeId(enb_ue_s1ap_id);
    ASSERT_NE(by_enb_id, nullptr);
    EXPECT_EQ(by_enb_id->context_id, context->context_id);

    // Verify context state
    EXPECT_TRUE(context->imsi.has_value());
    EXPECT_TRUE(context->current_guti.has_value());
    EXPECT_TRUE(context->mme_ue_s1ap_id.has_value());
    EXPECT_TRUE(context->enb_ue_s1ap_id.has_value());
    EXPECT_EQ(context->current_ue_ipv4, ue_ipv4);
    EXPECT_EQ(context->bearers.size(), 1);
    EXPECT_EQ(context->getActiveBearerCount(), 1);
}

// ============================================================================
// TAU with GUTI Update Test
// ============================================================================

TEST_F(LteAttachCorrelationTest, TrackingAreaUpdateWithGutiChange) {
    std::string imsi = "310410123456789";

    // Initial attach
    auto context = manager_->getOrCreate(imsi);

    SubscriberContext::GUTI guti_old;
    guti_old.mcc_mnc = "310410";
    guti_old.mme_group_id = 0x1234;
    guti_old.mme_code = 0x56;
    guti_old.m_tmsi = 0x11111111;
    manager_->updateGuti(context->context_id, guti_old);

    // TAU procedure - MME assigns new GUTI
    SubscriberContext::GUTI guti_new;
    guti_new.mcc_mnc = "310410";
    guti_new.mme_group_id = 0x1234;
    guti_new.mme_code = 0x56;
    guti_new.m_tmsi = 0x22222222;
    manager_->updateGuti(context->context_id, guti_new);

    // Verification
    EXPECT_TRUE(context->current_guti.has_value());
    EXPECT_EQ(context->current_guti.value(), guti_new);
    EXPECT_EQ(context->guti_history.size(), 1);
    EXPECT_EQ(context->guti_history[0], guti_old);

    // New GUTI should be indexed
    auto by_new_guti = manager_->findByGuti(guti_new);
    ASSERT_NE(by_new_guti, nullptr);
    EXPECT_EQ(by_new_guti->context_id, context->context_id);

    // Old GUTI should not be indexed (moved to history)
    auto by_old_guti = manager_->findByGuti(guti_old);
    EXPECT_EQ(by_old_guti, nullptr);
}

// ============================================================================
// Handover with IP Change Test
// ============================================================================

TEST_F(LteAttachCorrelationTest, HandoverWithIpChange) {
    std::string imsi = "310410123456789";

    auto context = manager_->getOrCreate(imsi);

    // Initial IP
    std::string ip_old = "10.45.1.100";
    manager_->updateUeIp(context->context_id, ip_old);

    SubscriberContext::BearerInfo bearer_old;
    bearer_old.teid = 0x11111111;
    bearer_old.eps_bearer_id = 5;
    bearer_old.interface = "S1-U";
    bearer_old.pgw_ip = "192.168.1.1";
    bearer_old.qci = 9;
    bearer_old.created = std::chrono::system_clock::now();
    manager_->addBearer(context->context_id, bearer_old);

    // Handover - new IP assigned, new TEID
    std::string ip_new = "10.45.1.101";
    manager_->updateUeIp(context->context_id, ip_new);

    // Old bearer is deleted
    manager_->removeBearer(context->context_id, bearer_old.teid);

    // New bearer created
    SubscriberContext::BearerInfo bearer_new;
    bearer_new.teid = 0x22222222;
    bearer_new.eps_bearer_id = 5;
    bearer_new.interface = "S1-U";
    bearer_new.pgw_ip = "192.168.1.1";
    bearer_new.qci = 9;
    bearer_new.created = std::chrono::system_clock::now();
    manager_->addBearer(context->context_id, bearer_new);

    // Verification
    EXPECT_EQ(context->current_ue_ipv4, ip_new);
    EXPECT_EQ(context->ue_ipv4_addresses.size(), 2);  // Both old and new
    EXPECT_TRUE(context->ue_ipv4_addresses.count(ip_old));
    EXPECT_TRUE(context->ue_ipv4_addresses.count(ip_new));

    // Both IPs should still lookup to same context
    auto by_old_ip = manager_->findByUeIp(ip_old);
    auto by_new_ip = manager_->findByUeIp(ip_new);
    ASSERT_NE(by_old_ip, nullptr);
    ASSERT_NE(by_new_ip, nullptr);
    EXPECT_EQ(by_old_ip->context_id, context->context_id);
    EXPECT_EQ(by_new_ip->context_id, context->context_id);

    // New TEID should lookup to context
    auto by_new_teid = manager_->findByTeid(bearer_new.teid);
    ASSERT_NE(by_new_teid, nullptr);
    EXPECT_EQ(by_new_teid->context_id, context->context_id);

    // Old TEID should not be found (removed from index)
    auto by_old_teid = manager_->findByTeid(bearer_old.teid);
    EXPECT_EQ(by_old_teid, nullptr);

    // Should have 1 active bearer
    EXPECT_EQ(context->getActiveBearerCount(), 1);
    EXPECT_EQ(context->bearers.size(), 2);  // Both in list, one deleted
}

// ============================================================================
// Dedicated Bearer Establishment Test
// ============================================================================

TEST_F(LteAttachCorrelationTest, DedicatedBearerEstablishment) {
    std::string imsi = "310410123456789";

    auto context = manager_->getOrCreate(imsi);
    manager_->updateUeIp(context->context_id, "10.45.1.100");

    // Default bearer (QCI 9)
    SubscriberContext::BearerInfo default_bearer;
    default_bearer.teid = 0x11111111;
    default_bearer.eps_bearer_id = 5;
    default_bearer.interface = "S1-U";
    default_bearer.pgw_ip = "192.168.1.1";
    default_bearer.qci = 9;
    default_bearer.created = std::chrono::system_clock::now();
    manager_->addBearer(context->context_id, default_bearer);

    EXPECT_EQ(context->getActiveBearerCount(), 1);

    // Dedicated bearer for VoLTE (QCI 1)
    SubscriberContext::BearerInfo dedicated_bearer;
    dedicated_bearer.teid = 0x22222222;
    dedicated_bearer.eps_bearer_id = 6;
    dedicated_bearer.interface = "S1-U";
    dedicated_bearer.pgw_ip = "192.168.1.1";
    dedicated_bearer.qci = 1;  // GBR for voice
    dedicated_bearer.created = std::chrono::system_clock::now();
    manager_->addBearer(context->context_id, dedicated_bearer);

    EXPECT_EQ(context->getActiveBearerCount(), 2);
    EXPECT_EQ(context->bearers.size(), 2);

    // Both TEIDs should lookup to same context
    auto by_default_teid = manager_->findByTeid(default_bearer.teid);
    auto by_dedicated_teid = manager_->findByTeid(dedicated_bearer.teid);
    ASSERT_NE(by_default_teid, nullptr);
    ASSERT_NE(by_dedicated_teid, nullptr);
    EXPECT_EQ(by_default_teid->context_id, context->context_id);
    EXPECT_EQ(by_dedicated_teid->context_id, context->context_id);
}

// ============================================================================
// Late IMSI Discovery Test
// ============================================================================

TEST_F(LteAttachCorrelationTest, LateImsiDiscovery) {
    // Scenario: Initial messages only have MME/eNB UE IDs, IMSI discovered later

    // Create temporary context from S1AP context setup
    auto context = manager_->createTemporaryContext();

    uint32_t mme_ue_s1ap_id = 12345;
    uint32_t enb_ue_s1ap_id = 67890;
    manager_->updateMmeUeId(context->context_id, mme_ue_s1ap_id);
    manager_->updateEnbUeId(context->context_id, enb_ue_s1ap_id);

    // Can lookup by control plane IDs
    auto by_mme = manager_->findByMmeUeId(mme_ue_s1ap_id);
    ASSERT_NE(by_mme, nullptr);
    EXPECT_EQ(by_mme->context_id, context->context_id);

    // Later, IMSI is discovered from NAS message
    std::string imsi = "310410123456789";
    manager_->updateImsi(context->context_id, imsi);

    // Now can lookup by IMSI
    auto by_imsi = manager_->findByImsi(imsi);
    ASSERT_NE(by_imsi, nullptr);
    EXPECT_EQ(by_imsi->context_id, context->context_id);

    // Still can lookup by control plane IDs
    by_mme = manager_->findByMmeUeId(mme_ue_s1ap_id);
    ASSERT_NE(by_mme, nullptr);
    EXPECT_EQ(by_mme->context_id, context->context_id);
}

// ============================================================================
// Multiple Attach/Detach Cycles Test
// ============================================================================

TEST_F(LteAttachCorrelationTest, MultipleAttachDetachCycles) {
    std::string imsi = "310410123456789";

    // First attach
    auto context = manager_->getOrCreate(imsi);
    manager_->updateUeIp(context->context_id, "10.45.1.100");

    SubscriberContext::BearerInfo bearer1;
    bearer1.teid = 0x11111111;
    bearer1.eps_bearer_id = 5;
    bearer1.interface = "S1-U";
    bearer1.pgw_ip = "192.168.1.1";
    bearer1.qci = 9;
    bearer1.created = std::chrono::system_clock::now();
    manager_->addBearer(context->context_id, bearer1);

    EXPECT_EQ(context->getActiveBearerCount(), 1);

    // Detach - bearer removed
    manager_->removeBearer(context->context_id, bearer1.teid);
    EXPECT_EQ(context->getActiveBearerCount(), 0);

    // Second attach - new IP, new bearer
    manager_->updateUeIp(context->context_id, "10.45.1.101");

    SubscriberContext::BearerInfo bearer2;
    bearer2.teid = 0x22222222;
    bearer2.eps_bearer_id = 5;
    bearer2.interface = "S1-U";
    bearer2.pgw_ip = "192.168.1.1";
    bearer2.qci = 9;
    bearer2.created = std::chrono::system_clock::now();
    manager_->addBearer(context->context_id, bearer2);

    EXPECT_EQ(context->getActiveBearerCount(), 1);
    EXPECT_EQ(context->bearers.size(), 2);  // Both in list

    // Should have both IPs in history
    EXPECT_EQ(context->ue_ipv4_addresses.size(), 2);
    EXPECT_TRUE(context->ue_ipv4_addresses.count("10.45.1.100"));
    EXPECT_TRUE(context->ue_ipv4_addresses.count("10.45.1.101"));

    // Current IP should be the latest
    EXPECT_EQ(context->current_ue_ipv4, "10.45.1.101");
}

// ============================================================================
// Dual Stack (IPv4 + IPv6) Test
// ============================================================================

TEST_F(LteAttachCorrelationTest, DualStackIpv4AndIpv6) {
    std::string imsi = "310410123456789";

    auto context = manager_->getOrCreate(imsi);

    // UE gets both IPv4 and IPv6
    std::string ipv4 = "10.45.1.100";
    std::string ipv6 = "2001:db8::/64";
    manager_->updateUeIp(context->context_id, ipv4, ipv6);

    EXPECT_EQ(context->current_ue_ipv4, ipv4);
    EXPECT_EQ(context->current_ue_ipv6, ipv6);

    // Both should lookup to same context
    auto by_ipv4 = manager_->findByUeIp(ipv4);
    auto by_ipv6 = manager_->findByUeIp(ipv6);
    ASSERT_NE(by_ipv4, nullptr);
    ASSERT_NE(by_ipv6, nullptr);
    EXPECT_EQ(by_ipv4->context_id, context->context_id);
    EXPECT_EQ(by_ipv6->context_id, context->context_id);
}

// ============================================================================
// Cleanup Test
// ============================================================================

TEST_F(LteAttachCorrelationTest, CleanupStaleContexts) {
    // Create contexts at different times
    auto ctx1 = manager_->getOrCreate("310410111111111");
    auto ctx1_id = ctx1->context_id;

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    auto ctx2 = manager_->getOrCreate("310410222222222");
    auto ctx2_id = ctx2->context_id;

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    auto ctx3 = manager_->getOrCreate("310410333333333");
    auto ctx3_id = ctx3->context_id;

    // Cleanup contexts older than 150ms ago
    auto cutoff = std::chrono::system_clock::now() - std::chrono::milliseconds(150);
    size_t removed = manager_->cleanupStaleContexts(cutoff);

    // Should remove ctx1
    EXPECT_EQ(removed, 1);

    // ctx1 should be gone
    auto found_ctx1 = manager_->findByContextId(ctx1_id);
    EXPECT_EQ(found_ctx1, nullptr);

    // ctx2 and ctx3 should still exist
    auto found_ctx2 = manager_->findByContextId(ctx2_id);
    auto found_ctx3 = manager_->findByContextId(ctx3_id);
    ASSERT_NE(found_ctx2, nullptr);
    ASSERT_NE(found_ctx3, nullptr);
}

// ============================================================================
// Statistics Test
// ============================================================================

TEST_F(LteAttachCorrelationTest, Statistics) {
    // Create multiple contexts
    for (int i = 0; i < 10; i++) {
        std::string imsi = "31041" + std::to_string(1000000000 + i);
        auto context = manager_->getOrCreate(imsi);

        // Some with MSISDN
        if (i % 2 == 0) {
            manager_->updateMsisdn(context->context_id, "1415555" + std::to_string(1000 + i));
        }

        // Some with UE IP
        if (i % 3 == 0) {
            manager_->updateUeIp(context->context_id, "10.45.1." + std::to_string(100 + i));
        }

        // Some with bearers
        if (i % 2 == 0) {
            SubscriberContext::BearerInfo bearer;
            bearer.teid = 0x10000000 + i;
            bearer.eps_bearer_id = 5;
            bearer.interface = "S1-U";
            bearer.pgw_ip = "192.168.1.1";
            bearer.qci = 9;
            bearer.created = std::chrono::system_clock::now();
            manager_->addBearer(context->context_id, bearer);
        }
    }

    auto stats = manager_->getStats();

    EXPECT_EQ(stats.total_contexts, 10);
    EXPECT_EQ(stats.with_imsi, 10);  // All have IMSI
    EXPECT_EQ(stats.with_msisdn, 5);  // Half have MSISDN
    EXPECT_EQ(stats.with_ue_ip, 4);  // i=0,3,6,9
    EXPECT_EQ(stats.with_active_bearers, 5);  // Half have bearers

    // Perform some lookups
    manager_->findByImsi("310411000000000");  // Hit
    manager_->findByImsi("999999999999999");  // Miss

    stats = manager_->getStats();
    EXPECT_EQ(stats.lookups_total, 2);
    EXPECT_EQ(stats.lookups_hit, 1);
}
