#include <gtest/gtest.h>
#include "correlation/identity/subscriber_context_manager.h"

using namespace callflow::correlation;

// ============================================================================
// Test Fixture
// ============================================================================

class SubscriberContextManagerTest : public ::testing::Test {
protected:
    void SetUp() override {
        manager_ = std::make_unique<SubscriberContextManager>();
    }

    void TearDown() override {
        manager_->clear();
        manager_.reset();
    }

    std::unique_ptr<SubscriberContextManager> manager_;
};

// ============================================================================
// Basic Context Creation Tests
// ============================================================================

TEST_F(SubscriberContextManagerTest, CreateContextByImsi) {
    std::string imsi = "310410123456789";

    auto context = manager_->getOrCreateByImsi(imsi);

    ASSERT_NE(context, nullptr);
    ASSERT_TRUE(context->imsi.has_value());
    EXPECT_EQ(context->imsi->digits, imsi);
}

TEST_F(SubscriberContextManagerTest, CreateContextByMsisdn) {
    std::string msisdn = "+12345678901";

    auto context = manager_->getOrCreateByMsisdn(msisdn);

    ASSERT_NE(context, nullptr);
    ASSERT_TRUE(context->msisdn.has_value());
    EXPECT_FALSE(context->msisdn->national.empty());
}

TEST_F(SubscriberContextManagerTest, CreateContextByImei) {
    std::string imei = "35209900176148";

    auto context = manager_->getOrCreateByImei(imei);

    ASSERT_NE(context, nullptr);
    ASSERT_TRUE(context->imei.has_value());
    EXPECT_EQ(context->imei->imei, imei);
}

TEST_F(SubscriberContextManagerTest, CreateContextByUeIp) {
    std::string ip = "10.1.2.3";

    auto context = manager_->getOrCreateByUeIp(ip);

    ASSERT_NE(context, nullptr);
    EXPECT_FALSE(context->endpoints.empty());
    EXPECT_EQ(context->endpoints[0].ipv4, ip);
}

TEST_F(SubscriberContextManagerTest, CreateContextByIpv6) {
    std::string ip = "2001:db8::1";

    auto context = manager_->getOrCreateByUeIp(ip);

    ASSERT_NE(context, nullptr);
    EXPECT_FALSE(context->endpoints.empty());
    EXPECT_EQ(context->endpoints[0].ipv6, ip);
}

TEST_F(SubscriberContextManagerTest, GetOrCreateIsIdempotent) {
    std::string imsi = "310410123456789";

    auto context1 = manager_->getOrCreateByImsi(imsi);
    auto context2 = manager_->getOrCreateByImsi(imsi);

    ASSERT_NE(context1, nullptr);
    ASSERT_NE(context2, nullptr);
    EXPECT_EQ(context1.get(), context2.get());  // Same object
}

// ============================================================================
// Find Tests
// ============================================================================

TEST_F(SubscriberContextManagerTest, FindByImsi) {
    std::string imsi = "310410123456789";

    // Initially not found
    auto context = manager_->findByImsi(imsi);
    EXPECT_EQ(context, nullptr);

    // Create and find
    manager_->getOrCreateByImsi(imsi);
    context = manager_->findByImsi(imsi);
    ASSERT_NE(context, nullptr);
    EXPECT_EQ(context->imsi->digits, imsi);
}

TEST_F(SubscriberContextManagerTest, FindByMsisdn) {
    std::string msisdn = "+12345678901";

    auto context = manager_->findByMsisdn(msisdn);
    EXPECT_EQ(context, nullptr);

    manager_->getOrCreateByMsisdn(msisdn);
    context = manager_->findByMsisdn(msisdn);
    ASSERT_NE(context, nullptr);
}

TEST_F(SubscriberContextManagerTest, FindByUeIp) {
    std::string ip = "10.1.2.3";

    auto context = manager_->findByUeIp(ip);
    EXPECT_EQ(context, nullptr);

    manager_->getOrCreateByUeIp(ip);
    context = manager_->findByUeIp(ip);
    ASSERT_NE(context, nullptr);
    EXPECT_EQ(context->endpoints[0].ipv4, ip);
}

TEST_F(SubscriberContextManagerTest, FindByTmsi) {
    uint32_t tmsi = 0x12345678;
    std::string imsi = "310410123456789";

    auto context = manager_->findByTmsi(tmsi);
    EXPECT_EQ(context, nullptr);

    manager_->linkImsiTmsi(imsi, tmsi);
    context = manager_->findByTmsi(tmsi);
    ASSERT_NE(context, nullptr);
    EXPECT_EQ(*context->tmsi, tmsi);
}

// ============================================================================
// Linking Tests
// ============================================================================

TEST_F(SubscriberContextManagerTest, LinkImsiMsisdn_BothNew) {
    std::string imsi = "310410123456789";
    std::string msisdn = "+12345678901";

    manager_->linkImsiMsisdn(imsi, msisdn);

    auto context_by_imsi = manager_->findByImsi(imsi);
    auto context_by_msisdn = manager_->findByMsisdn(msisdn);

    ASSERT_NE(context_by_imsi, nullptr);
    ASSERT_NE(context_by_msisdn, nullptr);
    EXPECT_EQ(context_by_imsi.get(), context_by_msisdn.get());  // Same context

    EXPECT_TRUE(context_by_imsi->imsi.has_value());
    EXPECT_TRUE(context_by_imsi->msisdn.has_value());
}

TEST_F(SubscriberContextManagerTest, LinkImsiMsisdn_ImsiExists) {
    std::string imsi = "310410123456789";
    std::string msisdn = "+12345678901";

    auto context = manager_->getOrCreateByImsi(imsi);
    manager_->linkImsiMsisdn(imsi, msisdn);

    auto context_by_msisdn = manager_->findByMsisdn(msisdn);
    ASSERT_NE(context_by_msisdn, nullptr);
    EXPECT_EQ(context.get(), context_by_msisdn.get());
    EXPECT_TRUE(context->msisdn.has_value());
}

TEST_F(SubscriberContextManagerTest, LinkImsiMsisdn_MsisdnExists) {
    std::string imsi = "310410123456789";
    std::string msisdn = "+12345678901";

    auto context = manager_->getOrCreateByMsisdn(msisdn);
    manager_->linkImsiMsisdn(imsi, msisdn);

    auto context_by_imsi = manager_->findByImsi(imsi);
    ASSERT_NE(context_by_imsi, nullptr);
    EXPECT_EQ(context.get(), context_by_imsi.get());
    EXPECT_TRUE(context->imsi.has_value());
}

TEST_F(SubscriberContextManagerTest, LinkImsiMsisdn_MergeDifferentContexts) {
    std::string imsi = "310410123456789";
    std::string msisdn = "+12345678901";

    // Create separate contexts
    auto imsi_context = manager_->getOrCreateByImsi(imsi);
    auto msisdn_context = manager_->getOrCreateByMsisdn(msisdn);

    ASSERT_NE(imsi_context.get(), msisdn_context.get());

    // Link them - should merge
    manager_->linkImsiMsisdn(imsi, msisdn);

    auto context_by_imsi = manager_->findByImsi(imsi);
    auto context_by_msisdn = manager_->findByMsisdn(msisdn);

    ASSERT_NE(context_by_imsi, nullptr);
    ASSERT_NE(context_by_msisdn, nullptr);
    EXPECT_EQ(context_by_imsi.get(), context_by_msisdn.get());

    // Verify stats
    auto stats = manager_->getStats();
    EXPECT_GE(stats.merge_operations, 1);
}

TEST_F(SubscriberContextManagerTest, LinkImsiImei) {
    std::string imsi = "310410123456789";
    std::string imei = "35209900176148";

    manager_->linkImsiImei(imsi, imei);

    auto context_by_imsi = manager_->findByImsi(imsi);
    auto context_by_imei = manager_->findByImei(imei);

    ASSERT_NE(context_by_imsi, nullptr);
    ASSERT_NE(context_by_imei, nullptr);
    EXPECT_EQ(context_by_imsi.get(), context_by_imei.get());

    EXPECT_TRUE(context_by_imsi->imsi.has_value());
    EXPECT_TRUE(context_by_imsi->imei.has_value());
}

TEST_F(SubscriberContextManagerTest, LinkMsisdnUeIp) {
    std::string msisdn = "+12345678901";
    std::string ip = "10.1.2.3";

    manager_->linkMsisdnUeIp(msisdn, ip);

    auto context_by_msisdn = manager_->findByMsisdn(msisdn);
    auto context_by_ip = manager_->findByUeIp(ip);

    ASSERT_NE(context_by_msisdn, nullptr);
    ASSERT_NE(context_by_ip, nullptr);
    EXPECT_EQ(context_by_msisdn.get(), context_by_ip.get());

    EXPECT_TRUE(context_by_msisdn->msisdn.has_value());
    EXPECT_FALSE(context_by_msisdn->endpoints.empty());
}

TEST_F(SubscriberContextManagerTest, LinkImsiUeIp) {
    std::string imsi = "310410123456789";
    std::string ip = "10.1.2.3";

    manager_->linkImsiUeIp(imsi, ip);

    auto context_by_imsi = manager_->findByImsi(imsi);
    auto context_by_ip = manager_->findByUeIp(ip);

    ASSERT_NE(context_by_imsi, nullptr);
    ASSERT_NE(context_by_ip, nullptr);
    EXPECT_EQ(context_by_imsi.get(), context_by_ip.get());
}

TEST_F(SubscriberContextManagerTest, LinkImsiGuti) {
    std::string imsi = "310410123456789";
    Guti4G guti;
    guti.mcc = "310";
    guti.mnc = "410";
    guti.mme_group_id = 0x1234;
    guti.mme_code = 0x56;
    guti.m_tmsi = 0x789ABCDE;

    manager_->linkImsiGuti(imsi, guti);

    auto context = manager_->findByImsi(imsi);
    ASSERT_NE(context, nullptr);
    EXPECT_TRUE(context->guti.has_value());
    EXPECT_EQ(context->guti->m_tmsi, guti.m_tmsi);

    auto context_by_guti = manager_->findByGuti(guti);
    ASSERT_NE(context_by_guti, nullptr);
    EXPECT_EQ(context.get(), context_by_guti.get());
}

TEST_F(SubscriberContextManagerTest, LinkImsiTmsi) {
    std::string imsi = "310410123456789";
    uint32_t tmsi = 0x12345678;

    manager_->linkImsiTmsi(imsi, tmsi);

    auto context = manager_->findByImsi(imsi);
    ASSERT_NE(context, nullptr);
    EXPECT_TRUE(context->tmsi.has_value());
    EXPECT_EQ(*context->tmsi, tmsi);

    auto context_by_tmsi = manager_->findByTmsi(tmsi);
    ASSERT_NE(context_by_tmsi, nullptr);
    EXPECT_EQ(context.get(), context_by_tmsi.get());
}

// ============================================================================
// GTP-U Tunnel Tests
// ============================================================================

TEST_F(SubscriberContextManagerTest, AddGtpuTunnelByImsi) {
    std::string imsi = "310410123456789";
    std::string peer_ip = "192.168.1.1";
    uint32_t teid = 0x11223344;

    manager_->getOrCreateByImsi(imsi);
    manager_->addGtpuTunnel(imsi, peer_ip, teid);

    auto context = manager_->findByImsi(imsi);
    ASSERT_NE(context, nullptr);
    EXPECT_FALSE(context->endpoints.empty());

    bool found = false;
    for (const auto& ep : context->endpoints) {
        if (ep.gtpu_peer_ip && *ep.gtpu_peer_ip == peer_ip &&
            ep.gtpu_teid && *ep.gtpu_teid == teid) {
            found = true;
            break;
        }
    }
    EXPECT_TRUE(found);
}

TEST_F(SubscriberContextManagerTest, AddGtpuTunnelByMsisdn) {
    std::string msisdn = "+12345678901";
    std::string peer_ip = "192.168.1.1";
    uint32_t teid = 0x11223344;

    manager_->getOrCreateByMsisdn(msisdn);
    manager_->addGtpuTunnel(msisdn, peer_ip, teid);

    auto context = manager_->findByMsisdn(msisdn);
    ASSERT_NE(context, nullptr);

    bool found = false;
    for (const auto& ep : context->endpoints) {
        if (ep.gtpu_peer_ip && *ep.gtpu_peer_ip == peer_ip &&
            ep.gtpu_teid && *ep.gtpu_teid == teid) {
            found = true;
            break;
        }
    }
    EXPECT_TRUE(found);
}

// ============================================================================
// Identity Propagation Tests
// ============================================================================

TEST_F(SubscriberContextManagerTest, PropagateIdentitiesBySharedIp) {
    std::string imsi = "310410123456789";
    std::string msisdn = "+12345678901";
    std::string shared_ip = "10.1.2.3";

    // Create two separate contexts with the same IP
    auto ctx1 = manager_->getOrCreateByImsi(imsi);
    auto ctx2 = manager_->getOrCreateByMsisdn(msisdn);

    manager_->linkImsiUeIp(imsi, shared_ip);
    manager_->linkMsisdnUeIp(msisdn, shared_ip);

    // Run propagation
    manager_->propagateIdentities();

    // Both identifiers should now be in the same context
    auto context_by_imsi = manager_->findByImsi(imsi);
    auto context_by_msisdn = manager_->findByMsisdn(msisdn);

    ASSERT_NE(context_by_imsi, nullptr);
    ASSERT_NE(context_by_msisdn, nullptr);
    EXPECT_EQ(context_by_imsi.get(), context_by_msisdn.get());
}

TEST_F(SubscriberContextManagerTest, PropagateIdentitiesCalculatesConfidence) {
    std::string imsi = "310410123456789";
    std::string msisdn = "+12345678901";
    std::string imei = "35209900176148";
    std::string ip = "10.1.2.3";

    manager_->linkImsiMsisdn(imsi, msisdn);
    manager_->linkImsiImei(imsi, imei);
    manager_->linkImsiUeIp(imsi, ip);

    manager_->propagateIdentities();

    auto context = manager_->findByImsi(imsi);
    ASSERT_NE(context, nullptr);

    // Should have high confidence due to complete identity
    auto it = context->confidence.find("identity_completeness");
    ASSERT_NE(it, context->confidence.end());
    EXPECT_GT(it->second, 0.8f);  // Should be > 80%
}

// ============================================================================
// SubscriberContextBuilder Tests
// ============================================================================

TEST_F(SubscriberContextManagerTest, BuilderFromGtp) {
    std::string imsi = "310410123456789";
    std::string msisdn = "+12345678901";
    std::string mei = "35209900176148";
    std::string ip = "10.1.2.3";

    auto context = SubscriberContextBuilder(*manager_)
        .fromGtpImsi(imsi)
        .fromGtpMsisdn(msisdn)
        .fromGtpMei(mei)
        .fromGtpPdnAddress(ip)
        .build();

    ASSERT_NE(context, nullptr);
    EXPECT_TRUE(context->imsi.has_value());
    EXPECT_TRUE(context->msisdn.has_value());
    EXPECT_TRUE(context->imei.has_value());
    EXPECT_FALSE(context->endpoints.empty());

    // All lookups should find the same context
    auto ctx_by_imsi = manager_->findByImsi(imsi);
    auto ctx_by_msisdn = manager_->findByMsisdn(msisdn);
    auto ctx_by_imei = manager_->findByImei(mei);
    auto ctx_by_ip = manager_->findByUeIp(ip);

    EXPECT_EQ(context.get(), ctx_by_imsi.get());
    EXPECT_EQ(context.get(), ctx_by_msisdn.get());
    EXPECT_EQ(context.get(), ctx_by_imei.get());
    EXPECT_EQ(context.get(), ctx_by_ip.get());
}

TEST_F(SubscriberContextManagerTest, BuilderFromSip) {
    std::string from_uri = "sip:+12345678901@ims.example.com";
    std::string ip = "10.1.2.3";

    auto context = SubscriberContextBuilder(*manager_)
        .fromSipFrom(from_uri)
        .fromSipContact(from_uri, ip)
        .build();

    ASSERT_NE(context, nullptr);
    EXPECT_TRUE(context->msisdn.has_value());
}

TEST_F(SubscriberContextManagerTest, BuilderFromDiameter) {
    std::string imsi = "310410123456789";
    std::string msisdn = "+12345678901";
    std::string ip = "10.1.2.3";

    auto context = SubscriberContextBuilder(*manager_)
        .fromDiameterImsi(imsi)
        .fromDiameterMsisdn(msisdn)
        .fromDiameterFramedIp(ip)
        .build();

    ASSERT_NE(context, nullptr);
    EXPECT_TRUE(context->imsi.has_value());
    EXPECT_TRUE(context->msisdn.has_value());
}

TEST_F(SubscriberContextManagerTest, BuilderFromNas) {
    std::string imsi = "310410123456789";
    std::string imei = "35209900176148";
    uint32_t tmsi = 0x12345678;

    Guti4G guti;
    guti.mcc = "310";
    guti.mnc = "410";
    guti.mme_group_id = 0x1234;
    guti.mme_code = 0x56;
    guti.m_tmsi = tmsi;

    auto context = SubscriberContextBuilder(*manager_)
        .fromNasImsi(imsi)
        .fromNasImei(imei)
        .fromNasGuti(guti)
        .fromNasTmsi(tmsi)
        .build();

    ASSERT_NE(context, nullptr);
    EXPECT_TRUE(context->imsi.has_value());
    EXPECT_TRUE(context->imei.has_value());
    EXPECT_TRUE(context->guti.has_value());
    EXPECT_TRUE(context->tmsi.has_value());
}

TEST_F(SubscriberContextManagerTest, BuilderWithGtpTunnels) {
    std::string imsi = "310410123456789";
    std::string peer_ip = "192.168.1.1";
    uint32_t teid = 0x11223344;

    auto context = SubscriberContextBuilder(*manager_)
        .fromGtpImsi(imsi)
        .fromGtpFteid(peer_ip, teid)
        .build();

    ASSERT_NE(context, nullptr);

    bool found = false;
    for (const auto& ep : context->endpoints) {
        if (ep.gtpu_peer_ip && *ep.gtpu_peer_ip == peer_ip &&
            ep.gtpu_teid && *ep.gtpu_teid == teid) {
            found = true;
            break;
        }
    }
    EXPECT_TRUE(found);
}

TEST_F(SubscriberContextManagerTest, BuilderWithApn) {
    std::string imsi = "310410123456789";
    std::string apn = "internet";

    auto context = SubscriberContextBuilder(*manager_)
        .fromGtpImsi(imsi)
        .fromGtpApn(apn)
        .build();

    ASSERT_NE(context, nullptr);
    EXPECT_EQ(context->apn, apn);
}

// ============================================================================
// Statistics Tests
// ============================================================================

TEST_F(SubscriberContextManagerTest, GetStats) {
    manager_->getOrCreateByImsi("310410123456789");
    manager_->getOrCreateByMsisdn("+12345678901");
    manager_->getOrCreateByImei("35209900176148");
    manager_->getOrCreateByUeIp("10.1.2.3");

    auto stats = manager_->getStats();

    EXPECT_GE(stats.total_contexts, 4);
    EXPECT_GE(stats.contexts_with_imsi, 1);
    EXPECT_GE(stats.contexts_with_msisdn, 1);
    EXPECT_GE(stats.contexts_with_imei, 1);
    EXPECT_GE(stats.contexts_with_ue_ip, 1);
}

TEST_F(SubscriberContextManagerTest, GetStatsMergeOperations) {
    std::string imsi = "310410123456789";
    std::string msisdn = "+12345678901";

    manager_->getOrCreateByImsi(imsi);
    manager_->getOrCreateByMsisdn(msisdn);
    manager_->linkImsiMsisdn(imsi, msisdn);

    auto stats = manager_->getStats();
    EXPECT_GE(stats.merge_operations, 1);
}

TEST_F(SubscriberContextManagerTest, GetAllContexts) {
    manager_->getOrCreateByImsi("310410123456789");
    manager_->getOrCreateByImsi("310410987654321");
    manager_->getOrCreateByMsisdn("+12345678901");

    auto contexts = manager_->getAllContexts();
    EXPECT_GE(contexts.size(), 3);
}

TEST_F(SubscriberContextManagerTest, Clear) {
    manager_->getOrCreateByImsi("310410123456789");
    manager_->getOrCreateByMsisdn("+12345678901");

    auto stats_before = manager_->getStats();
    EXPECT_GT(stats_before.total_contexts, 0);

    manager_->clear();

    auto stats_after = manager_->getStats();
    EXPECT_EQ(stats_after.total_contexts, 0);
    EXPECT_EQ(stats_after.contexts_with_imsi, 0);
    EXPECT_EQ(stats_after.contexts_with_msisdn, 0);

    auto context = manager_->findByImsi("310410123456789");
    EXPECT_EQ(context, nullptr);
}

// ============================================================================
// Complex Scenario Tests
// ============================================================================

TEST_F(SubscriberContextManagerTest, CompleteSubscriberLifecycle) {
    // Simulating a complete subscriber lifecycle across multiple protocols

    std::string imsi = "310410123456789";
    std::string msisdn = "+12345678901";
    std::string imei = "35209900176148";
    std::string ue_ip = "10.1.2.3";
    uint32_t tmsi = 0x12345678;

    // 1. Initial attach - GTP-C Create Session Request
    SubscriberContextBuilder(*manager_)
        .fromGtpImsi(imsi)
        .fromGtpMsisdn(msisdn)
        .fromGtpMei(imei)
        .fromGtpPdnAddress(ue_ip)
        .fromGtpApn("internet")
        .build();

    // 2. NAS attach - link TMSI
    manager_->linkImsiTmsi(imsi, tmsi);

    // 3. SIP REGISTER - link SIP URI
    SubscriberContextBuilder(*manager_)
        .fromSipFrom("sip:+12345678901@ims.example.com")
        .fromSipContact("sip:+12345678901@10.1.2.3:5060", ue_ip)
        .build();

    // Verify everything is linked
    auto context = manager_->findByImsi(imsi);
    ASSERT_NE(context, nullptr);

    EXPECT_TRUE(context->imsi.has_value());
    EXPECT_TRUE(context->msisdn.has_value());
    EXPECT_TRUE(context->imei.has_value());
    EXPECT_TRUE(context->tmsi.has_value());
    EXPECT_FALSE(context->endpoints.empty());
    EXPECT_EQ(context->apn, "internet");

    // All lookups should return the same context
    EXPECT_EQ(context.get(), manager_->findByMsisdn(msisdn).get());
    EXPECT_EQ(context.get(), manager_->findByImei(imei).get());
    EXPECT_EQ(context.get(), manager_->findByUeIp(ue_ip).get());
    EXPECT_EQ(context.get(), manager_->findByTmsi(tmsi).get());

    // Run propagation
    manager_->propagateIdentities();

    // Check confidence score
    auto it = context->confidence.find("identity_completeness");
    ASSERT_NE(it, context->confidence.end());
    EXPECT_GT(it->second, 0.8f);
}

TEST_F(SubscriberContextManagerTest, MultipleSubscribersNoMerge) {
    // Create 3 distinct subscribers
    std::string imsi1 = "310410123456789";
    std::string imsi2 = "310410987654321";
    std::string imsi3 = "310410111111111";

    manager_->getOrCreateByImsi(imsi1);
    manager_->getOrCreateByImsi(imsi2);
    manager_->getOrCreateByImsi(imsi3);

    auto contexts = manager_->getAllContexts();
    EXPECT_GE(contexts.size(), 3);

    auto stats = manager_->getStats();
    EXPECT_EQ(stats.merge_operations, 0);
}

TEST_F(SubscriberContextManagerTest, MultipleEndpoints) {
    std::string imsi = "310410123456789";
    std::string default_ip = "10.1.2.3";
    std::string ims_ip = "10.5.6.7";

    // Default bearer
    manager_->linkImsiUeIp(imsi, default_ip);

    // IMS dedicated bearer
    manager_->linkImsiUeIp(imsi, ims_ip);

    auto context = manager_->findByImsi(imsi);
    ASSERT_NE(context, nullptr);
    EXPECT_GE(context->endpoints.size(), 2);

    bool found_default = false;
    bool found_ims = false;

    for (const auto& ep : context->endpoints) {
        if (ep.ipv4 == default_ip) found_default = true;
        if (ep.ipv4 == ims_ip) found_ims = true;
    }

    EXPECT_TRUE(found_default);
    EXPECT_TRUE(found_ims);
}

// ============================================================================
// Edge Cases and Error Handling
// ============================================================================

TEST_F(SubscriberContextManagerTest, EmptyIdentifiers) {
    auto context = manager_->getOrCreateByImsi("");
    EXPECT_NE(context, nullptr);  // Should still create a context
}

TEST_F(SubscriberContextManagerTest, BuilderNoIdentifiers) {
    auto context = SubscriberContextBuilder(*manager_).build();
    EXPECT_EQ(context, nullptr);  // No identifiers provided
}

TEST_F(SubscriberContextManagerTest, LinkSameContextTwice) {
    std::string imsi = "310410123456789";
    std::string msisdn = "+12345678901";

    // Create and link
    manager_->linkImsiMsisdn(imsi, msisdn);

    size_t contexts_before = manager_->getAllContexts().size();
    size_t merges_before = manager_->getStats().merge_operations;

    // Link again - should be idempotent
    manager_->linkImsiMsisdn(imsi, msisdn);

    size_t contexts_after = manager_->getAllContexts().size();
    size_t merges_after = manager_->getStats().merge_operations;

    EXPECT_EQ(contexts_before, contexts_after);
    EXPECT_EQ(merges_before, merges_after);
}

TEST_F(SubscriberContextManagerTest, PropagateIdentitiesMultipleTimes) {
    std::string imsi = "310410123456789";
    manager_->getOrCreateByImsi(imsi);

    // Run propagation multiple times
    manager_->propagateIdentities();
    manager_->propagateIdentities();
    manager_->propagateIdentities();

    // Should not cause issues
    auto context = manager_->findByImsi(imsi);
    ASSERT_NE(context, nullptr);
}
