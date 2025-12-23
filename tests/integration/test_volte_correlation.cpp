#include <gtest/gtest.h>

#include "correlation/subscriber_context.h"

using namespace callflow::correlation;

// ============================================================================
// Test Fixture
// ============================================================================

class VoLTECorrelationTest : public ::testing::Test {
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
// Complete VoLTE Call Test
// ============================================================================

TEST_F(VoLTECorrelationTest, CompleteVoLTECallFlow) {
    std::string imsi = "310410123456789";
    std::string msisdn = "14155551234";

    // Phase 1: LTE Attach (data context establishment)
    auto context = manager_->getOrCreate(imsi);
    manager_->updateMsisdn(context->context_id, msisdn);
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

    // Phase 2: IMS Registration (SIP REGISTER)
    std::string sip_uri = "sip:+14155551234@ims.mnc410.mcc310.3gppnetwork.org";
    manager_->updateSipUri(context->context_id, sip_uri);

    // IMS Charging ID
    std::string icid = "ab84b4c76e66710192.0.2.4-1234567890";
    manager_->addIcid(context->context_id, icid);

    // Phase 3: VoLTE Call Setup (SIP INVITE)
    std::string call_id = "a84b4c76e66710@192.0.2.4";
    manager_->addSipCallId(context->context_id, call_id);

    // Dedicated bearer for VoLTE (QCI 1)
    SubscriberContext::BearerInfo volte_bearer;
    volte_bearer.teid = 0x22222222;
    volte_bearer.eps_bearer_id = 6;
    volte_bearer.interface = "S1-U";
    volte_bearer.pgw_ip = "192.168.1.1";
    volte_bearer.qci = 1;  // GBR for voice
    volte_bearer.created = std::chrono::system_clock::now();
    manager_->addBearer(context->context_id, volte_bearer);

    // Verification: All correlation paths work
    auto by_imsi = manager_->findByImsi(imsi);
    auto by_msisdn = manager_->findByMsisdn(msisdn);
    auto by_ip = manager_->findByUeIp("10.45.1.100");
    auto by_sip_uri = manager_->findBySipUri(sip_uri);
    auto by_call_id = manager_->findBySipCallId(call_id);
    auto by_default_teid = manager_->findByTeid(default_bearer.teid);
    auto by_volte_teid = manager_->findByTeid(volte_bearer.teid);

    ASSERT_NE(by_imsi, nullptr);
    ASSERT_NE(by_msisdn, nullptr);
    ASSERT_NE(by_ip, nullptr);
    ASSERT_NE(by_sip_uri, nullptr);
    ASSERT_NE(by_call_id, nullptr);
    ASSERT_NE(by_default_teid, nullptr);
    ASSERT_NE(by_volte_teid, nullptr);

    // All should point to same context
    EXPECT_EQ(by_imsi->context_id, context->context_id);
    EXPECT_EQ(by_msisdn->context_id, context->context_id);
    EXPECT_EQ(by_ip->context_id, context->context_id);
    EXPECT_EQ(by_sip_uri->context_id, context->context_id);
    EXPECT_EQ(by_call_id->context_id, context->context_id);
    EXPECT_EQ(by_default_teid->context_id, context->context_id);
    EXPECT_EQ(by_volte_teid->context_id, context->context_id);

    // Verify context has complete profile
    EXPECT_TRUE(context->imsi.has_value());
    EXPECT_TRUE(context->msisdn.has_value());
    EXPECT_EQ(context->current_ue_ipv4, "10.45.1.100");
    EXPECT_EQ(context->current_sip_uri, sip_uri);
    EXPECT_EQ(context->sip_call_ids.size(), 1);
    EXPECT_EQ(context->icids.size(), 1);
    EXPECT_EQ(context->bearers.size(), 2);
    EXPECT_EQ(context->getActiveBearerCount(), 2);
}

// ============================================================================
// Correlation Gap: SIP Before GTP Test
// ============================================================================

TEST_F(VoLTECorrelationTest, CorrelationGapSipBeforeGtp) {
    // Scenario from the requirements:
    // - SIP messages arrive first (e.g., from SGi tap)
    // - GTP messages arrive later (e.g., from S11 tap)
    // - Need to correlate them via UE IP

    std::string ue_ip = "10.45.1.100";

    // Step 1: SIP REGISTER arrives first
    // - We don't know IMSI yet, create temporary context
    auto sip_context = manager_->createTemporaryContext();
    manager_->updateUeIp(sip_context->context_id, ue_ip);

    std::string sip_uri = "sip:+14155551234@ims.mnc410.mcc310.3gppnetwork.org";
    manager_->updateSipUri(sip_context->context_id, sip_uri);

    // Can lookup by SIP URI
    auto by_sip_1 = manager_->findBySipUri(sip_uri);
    ASSERT_NE(by_sip_1, nullptr);
    EXPECT_EQ(by_sip_1->context_id, sip_context->context_id);

    // But cannot lookup by IMSI yet
    auto by_imsi_1 = manager_->findByImsi("310410123456789");
    EXPECT_EQ(by_imsi_1, nullptr);

    // Step 2: GTP Create Session Response arrives
    // - We learn IMSI from GTP-C message
    std::string imsi = "310410123456789";
    auto gtp_context = manager_->getOrCreate(imsi);
    manager_->updateUeIp(gtp_context->context_id, ue_ip);  // Same IP!

    SubscriberContext::BearerInfo bearer;
    bearer.teid = 0x12345678;
    bearer.eps_bearer_id = 5;
    bearer.interface = "S1-U";
    bearer.pgw_ip = "192.168.1.1";
    bearer.qci = 9;
    bearer.created = std::chrono::system_clock::now();
    manager_->addBearer(gtp_context->context_id, bearer);

    // Step 3: Detect correlation via UE IP and merge contexts
    auto ctx_by_ip = manager_->findByUeIp(ue_ip);
    // Note: In real implementation, there would be logic to detect
    // duplicate contexts with same IP and merge them

    // For this test, manually merge
    bool merged = manager_->mergeContexts(gtp_context->context_id, sip_context->context_id);
    EXPECT_TRUE(merged);

    // Step 4: Verify unified context
    auto unified = manager_->findByImsi(imsi);
    ASSERT_NE(unified, nullptr);

    // Should have both IMSI and SIP URI
    ASSERT_TRUE(unified->imsi.has_value());
    EXPECT_EQ(unified->imsi.value(), imsi);
    EXPECT_EQ(unified->current_sip_uri, sip_uri);

    // All lookups should work
    auto by_imsi = manager_->findByImsi(imsi);
    auto by_sip = manager_->findBySipUri(sip_uri);
    auto by_ip = manager_->findByUeIp(ue_ip);
    auto by_teid = manager_->findByTeid(bearer.teid);

    ASSERT_NE(by_imsi, nullptr);
    ASSERT_NE(by_sip, nullptr);
    ASSERT_NE(by_ip, nullptr);
    ASSERT_NE(by_teid, nullptr);

    EXPECT_EQ(by_imsi->context_id, gtp_context->context_id);
    EXPECT_EQ(by_sip->context_id, gtp_context->context_id);
    EXPECT_EQ(by_ip->context_id, gtp_context->context_id);
    EXPECT_EQ(by_teid->context_id, gtp_context->context_id);
}

// ============================================================================
// Multiple Simultaneous Calls Test
// ============================================================================

TEST_F(VoLTECorrelationTest, MultipleSimultaneousCalls) {
    std::string imsi = "310410123456789";

    auto context = manager_->getOrCreate(imsi);
    manager_->updateUeIp(context->context_id, "10.45.1.100");

    std::string sip_uri = "sip:+14155551234@ims.mnc410.mcc310.3gppnetwork.org";
    manager_->updateSipUri(context->context_id, sip_uri);

    // First call
    std::string call_id_1 = "call1@192.0.2.4";
    manager_->addSipCallId(context->context_id, call_id_1);

    // Second call (call waiting)
    std::string call_id_2 = "call2@192.0.2.4";
    manager_->addSipCallId(context->context_id, call_id_2);

    // Third call (conference)
    std::string call_id_3 = "call3@192.0.2.4";
    manager_->addSipCallId(context->context_id, call_id_3);

    EXPECT_EQ(context->sip_call_ids.size(), 3);

    // All Call-IDs should lookup to same context
    auto by_call_1 = manager_->findBySipCallId(call_id_1);
    auto by_call_2 = manager_->findBySipCallId(call_id_2);
    auto by_call_3 = manager_->findBySipCallId(call_id_3);

    ASSERT_NE(by_call_1, nullptr);
    ASSERT_NE(by_call_2, nullptr);
    ASSERT_NE(by_call_3, nullptr);

    EXPECT_EQ(by_call_1->context_id, context->context_id);
    EXPECT_EQ(by_call_2->context_id, context->context_id);
    EXPECT_EQ(by_call_3->context_id, context->context_id);
}

// ============================================================================
// IMS Re-Registration Test
// ============================================================================

TEST_F(VoLTECorrelationTest, ImsReregistration) {
    std::string imsi = "310410123456789";

    auto context = manager_->getOrCreate(imsi);
    manager_->updateUeIp(context->context_id, "10.45.1.100");

    // Initial registration
    std::string sip_uri_1 = "sip:+14155551234@ims.mnc410.mcc310.3gppnetwork.org";
    manager_->updateSipUri(context->context_id, sip_uri_1);

    EXPECT_EQ(context->sip_uris.size(), 1);
    EXPECT_EQ(context->current_sip_uri, sip_uri_1);

    // Re-registration with different domain (e.g., after network change)
    std::string sip_uri_2 = "sip:+14155551234@ims.att.net";
    manager_->updateSipUri(context->context_id, sip_uri_2);

    // Should have both URIs in history
    EXPECT_EQ(context->sip_uris.size(), 2);
    EXPECT_TRUE(context->sip_uris.count(sip_uri_1));
    EXPECT_TRUE(context->sip_uris.count(sip_uri_2));

    // Current should be the latest
    EXPECT_EQ(context->current_sip_uri, sip_uri_2);

    // Both URIs should lookup to same context
    auto by_uri_1 = manager_->findBySipUri(sip_uri_1);
    auto by_uri_2 = manager_->findBySipUri(sip_uri_2);

    ASSERT_NE(by_uri_1, nullptr);
    ASSERT_NE(by_uri_2, nullptr);

    EXPECT_EQ(by_uri_1->context_id, context->context_id);
    EXPECT_EQ(by_uri_2->context_id, context->context_id);
}

// ============================================================================
// VoLTE During Handover Test
// ============================================================================

TEST_F(VoLTECorrelationTest, VoLTEDuringHandover) {
    std::string imsi = "310410123456789";

    auto context = manager_->getOrCreate(imsi);

    // Initial state
    manager_->updateUeIp(context->context_id, "10.45.1.100");
    std::string sip_uri = "sip:+14155551234@ims.mnc410.mcc310.3gppnetwork.org";
    manager_->updateSipUri(context->context_id, sip_uri);

    // Active call
    std::string call_id = "active_call@192.0.2.4";
    manager_->addSipCallId(context->context_id, call_id);

    // VoLTE bearer
    SubscriberContext::BearerInfo bearer_old;
    bearer_old.teid = 0x11111111;
    bearer_old.eps_bearer_id = 6;
    bearer_old.interface = "S1-U";
    bearer_old.pgw_ip = "192.168.1.1";
    bearer_old.qci = 1;
    bearer_old.created = std::chrono::system_clock::now();
    manager_->addBearer(context->context_id, bearer_old);

    // Handover occurs - new IP, new TEID
    manager_->updateUeIp(context->context_id, "10.45.1.101");

    manager_->removeBearer(context->context_id, bearer_old.teid);

    SubscriberContext::BearerInfo bearer_new;
    bearer_new.teid = 0x22222222;
    bearer_new.eps_bearer_id = 6;
    bearer_new.interface = "S1-U";
    bearer_new.pgw_ip = "192.168.1.1";
    bearer_new.qci = 1;
    bearer_new.created = std::chrono::system_clock::now();
    manager_->addBearer(context->context_id, bearer_new);

    // Verification: Call-ID still associated with context
    auto by_call = manager_->findBySipCallId(call_id);
    ASSERT_NE(by_call, nullptr);
    EXPECT_EQ(by_call->context_id, context->context_id);

    // New IP and TEID also lookup to same context
    auto by_new_ip = manager_->findByUeIp("10.45.1.101");
    auto by_new_teid = manager_->findByTeid(bearer_new.teid);
    ASSERT_NE(by_new_ip, nullptr);
    ASSERT_NE(by_new_teid, nullptr);
    EXPECT_EQ(by_new_ip->context_id, context->context_id);
    EXPECT_EQ(by_new_teid->context_id, context->context_id);

    // Old IP still in history
    EXPECT_EQ(context->ue_ipv4_addresses.size(), 2);
    EXPECT_TRUE(context->ue_ipv4_addresses.count("10.45.1.100"));
    EXPECT_TRUE(context->ue_ipv4_addresses.count("10.45.1.101"));
}

// ============================================================================
// Emergency Call Test
// ============================================================================

TEST_F(VoLTECorrelationTest, EmergencyCall) {
    // Emergency calls may not have IMSI initially
    auto context = manager_->createTemporaryContext();

    manager_->updateUeIp(context->context_id, "10.45.1.200");

    // Emergency SIP URI
    std::string emergency_uri = "sip:sos@ims.mnc410.mcc310.3gppnetwork.org";
    manager_->updateSipUri(context->context_id, emergency_uri);

    // Emergency call
    std::string call_id = "emergency_911@192.0.2.4";
    manager_->addSipCallId(context->context_id, call_id);

    // Emergency bearer (QCI 1, high priority)
    SubscriberContext::BearerInfo emergency_bearer;
    emergency_bearer.teid = 0xE911E911;
    emergency_bearer.eps_bearer_id = 7;
    emergency_bearer.interface = "S1-U";
    emergency_bearer.pgw_ip = "192.168.1.1";
    emergency_bearer.qci = 1;
    emergency_bearer.created = std::chrono::system_clock::now();
    manager_->addBearer(context->context_id, emergency_bearer);

    // IMSI might be discovered later
    std::string imsi = "310410123456789";
    manager_->updateImsi(context->context_id, imsi);

    // Verify all lookups work
    auto by_imsi = manager_->findByImsi(imsi);
    auto by_ip = manager_->findByUeIp("10.45.1.200");
    auto by_sip = manager_->findBySipUri(emergency_uri);
    auto by_call = manager_->findBySipCallId(call_id);
    auto by_teid = manager_->findByTeid(emergency_bearer.teid);

    ASSERT_NE(by_imsi, nullptr);
    ASSERT_NE(by_ip, nullptr);
    ASSERT_NE(by_sip, nullptr);
    ASSERT_NE(by_call, nullptr);
    ASSERT_NE(by_teid, nullptr);

    EXPECT_EQ(by_imsi->context_id, context->context_id);
    EXPECT_EQ(by_ip->context_id, context->context_id);
    EXPECT_EQ(by_sip->context_id, context->context_id);
    EXPECT_EQ(by_call->context_id, context->context_id);
    EXPECT_EQ(by_teid->context_id, context->context_id);
}

// ============================================================================
// VoWiFi to VoLTE Handover Test
// ============================================================================

TEST_F(VoLTECorrelationTest, VoWiFiToVoLTEHandover) {
    std::string imsi = "310410123456789";

    auto context = manager_->getOrCreate(imsi);

    // Initially on WiFi (different IP allocation)
    manager_->updateUeIp(context->context_id, "192.168.100.50");

    std::string sip_uri = "sip:+14155551234@ims.mnc410.mcc310.3gppnetwork.org";
    manager_->updateSipUri(context->context_id, sip_uri);

    std::string call_id = "vowifi_call@192.0.2.4";
    manager_->addSipCallId(context->context_id, call_id);

    // Handover to LTE
    manager_->updateUeIp(context->context_id, "10.45.1.100");

    // VoLTE bearer established
    SubscriberContext::BearerInfo volte_bearer;
    volte_bearer.teid = 0x12345678;
    volte_bearer.eps_bearer_id = 6;
    volte_bearer.interface = "S1-U";
    volte_bearer.pgw_ip = "192.168.1.1";
    volte_bearer.qci = 1;
    volte_bearer.created = std::chrono::system_clock::now();
    manager_->addBearer(context->context_id, volte_bearer);

    // Verification: Call continues across handover
    auto by_call = manager_->findBySipCallId(call_id);
    ASSERT_NE(by_call, nullptr);
    EXPECT_EQ(by_call->context_id, context->context_id);

    // Both IPs in history
    EXPECT_EQ(context->ue_ipv4_addresses.size(), 2);
    EXPECT_TRUE(context->ue_ipv4_addresses.count("192.168.100.50"));  // WiFi
    EXPECT_TRUE(context->ue_ipv4_addresses.count("10.45.1.100"));     // LTE

    // Current IP is LTE
    EXPECT_EQ(context->current_ue_ipv4, "10.45.1.100");
}

// ============================================================================
// Multiple ICID Tracking Test
// ============================================================================

TEST_F(VoLTECorrelationTest, MultipleIcidTracking) {
    std::string imsi = "310410123456789";

    auto context = manager_->getOrCreate(imsi);

    // Registration generates ICID
    std::string icid_register = "icid_reg_123456";
    manager_->addIcid(context->context_id, icid_register);

    // First call generates ICID
    std::string icid_call_1 = "icid_call1_789012";
    manager_->addIcid(context->context_id, icid_call_1);

    // Second call generates ICID
    std::string icid_call_2 = "icid_call2_345678";
    manager_->addIcid(context->context_id, icid_call_2);

    EXPECT_EQ(context->icids.size(), 3);
    EXPECT_TRUE(context->icids.count(icid_register));
    EXPECT_TRUE(context->icids.count(icid_call_1));
    EXPECT_TRUE(context->icids.count(icid_call_2));

    // All ICIDs should be searchable
    // (Note: Current implementation doesn't have findByIcid, but has icid_index_)
}

// ============================================================================
// VoLTE Statistics Test
// ============================================================================

TEST_F(VoLTECorrelationTest, VoLTEStatistics) {
    // Create multiple subscribers with VoLTE
    for (int i = 0; i < 5; i++) {
        std::string imsi = "31041" + std::to_string(1000000000 + i);
        auto context = manager_->getOrCreate(imsi);

        manager_->updateUeIp(context->context_id, "10.45.1." + std::to_string(100 + i));

        std::string sip_uri = "sip:+141555512" + std::to_string(30 + i) + "@ims.example.com";
        manager_->updateSipUri(context->context_id, sip_uri);

        // Some have active calls
        if (i % 2 == 0) {
            std::string call_id = "call_" + std::to_string(i) + "@192.0.2.4";
            manager_->addSipCallId(context->context_id, call_id);
        }

        // All have VoLTE bearers
        SubscriberContext::BearerInfo bearer;
        bearer.teid = 0x10000000 + i;
        bearer.eps_bearer_id = 6;
        bearer.interface = "S1-U";
        bearer.pgw_ip = "192.168.1.1";
        bearer.qci = 1;
        bearer.created = std::chrono::system_clock::now();
        manager_->addBearer(context->context_id, bearer);
    }

    auto stats = manager_->getStats();

    EXPECT_EQ(stats.total_contexts, 5);
    EXPECT_EQ(stats.with_imsi, 5);
    EXPECT_EQ(stats.with_ue_ip, 5);
    EXPECT_EQ(stats.with_sip_sessions, 5);
    EXPECT_EQ(stats.with_active_bearers, 5);
}
