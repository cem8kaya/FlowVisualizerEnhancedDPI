#include <gtest/gtest.h>

#include "correlation/subscriber_context.h"

using namespace callflow::correlation;

// ============================================================================
// Test Fixture
// ============================================================================

class SubscriberContextTest : public ::testing::Test {
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
// Basic Context Creation Tests
// ============================================================================

TEST_F(SubscriberContextTest, CreateContextWithImsi) {
    std::string imsi = "310410123456789";

    auto context = manager_->getOrCreate(imsi);

    ASSERT_NE(context, nullptr);
    EXPECT_FALSE(context->context_id.empty());
    ASSERT_TRUE(context->imsi.has_value());
    EXPECT_EQ(context->imsi.value(), imsi);
    EXPECT_EQ(context->getPrimaryIdentifier(), imsi);
}

TEST_F(SubscriberContextTest, CreateContextWithSupi) {
    std::string supi = "imsi-310410123456789";

    auto context = manager_->getOrCreateBySupi(supi);

    ASSERT_NE(context, nullptr);
    EXPECT_FALSE(context->context_id.empty());
    ASSERT_TRUE(context->supi.has_value());
    EXPECT_EQ(context->supi.value(), supi);
    EXPECT_EQ(context->getPrimaryIdentifier(), supi);
}

TEST_F(SubscriberContextTest, CreateTemporaryContext) {
    auto context = manager_->createTemporaryContext();

    ASSERT_NE(context, nullptr);
    EXPECT_FALSE(context->context_id.empty());
    EXPECT_FALSE(context->imsi.has_value());
    EXPECT_FALSE(context->supi.has_value());
    EXPECT_EQ(context->getPrimaryIdentifier(), context->context_id);
}

TEST_F(SubscriberContextTest, GetOrCreateIsIdempotent) {
    std::string imsi = "310410123456789";

    auto context1 = manager_->getOrCreate(imsi);
    auto context2 = manager_->getOrCreate(imsi);

    ASSERT_NE(context1, nullptr);
    ASSERT_NE(context2, nullptr);
    EXPECT_EQ(context1->context_id, context2->context_id);
    EXPECT_EQ(context1.get(), context2.get());  // Same object
}

// ============================================================================
// GUTI Tests
// ============================================================================

TEST_F(SubscriberContextTest, GutiToString) {
    SubscriberContext::GUTI guti;
    guti.mcc_mnc = "310410";
    guti.mme_group_id = 0x1234;
    guti.mme_code = 0x56;
    guti.m_tmsi = 0x789ABCDE;

    std::string guti_str = guti.toString();

    EXPECT_FALSE(guti_str.empty());
    EXPECT_NE(guti_str.find("310410"), std::string::npos);
}

TEST_F(SubscriberContextTest, GutiEquality) {
    SubscriberContext::GUTI guti1;
    guti1.mcc_mnc = "310410";
    guti1.mme_group_id = 0x1234;
    guti1.mme_code = 0x56;
    guti1.m_tmsi = 0x789ABCDE;

    SubscriberContext::GUTI guti2 = guti1;
    SubscriberContext::GUTI guti3 = guti1;
    guti3.m_tmsi = 0x11111111;

    EXPECT_EQ(guti1, guti2);
    EXPECT_NE(guti1, guti3);
}

TEST_F(SubscriberContextTest, UpdateGuti) {
    std::string imsi = "310410123456789";
    auto context = manager_->getOrCreate(imsi);

    SubscriberContext::GUTI guti;
    guti.mcc_mnc = "310410";
    guti.mme_group_id = 0x1234;
    guti.mme_code = 0x56;
    guti.m_tmsi = 0x789ABCDE;

    manager_->updateGuti(context->context_id, guti);

    ASSERT_TRUE(context->current_guti.has_value());
    EXPECT_EQ(context->current_guti.value(), guti);
}

TEST_F(SubscriberContextTest, GutiHistory) {
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
    manager_->updateGuti(context->context_id, guti2);  // Should move guti1 to history

    ASSERT_TRUE(context->current_guti.has_value());
    EXPECT_EQ(context->current_guti.value(), guti2);
    EXPECT_EQ(context->guti_history.size(), 1);
    EXPECT_EQ(context->guti_history[0], guti1);
}

// ============================================================================
// 5G-GUTI Tests
// ============================================================================

TEST_F(SubscriberContextTest, Guti5GToString) {
    SubscriberContext::GUTI5G guti;
    guti.mcc_mnc = "310410";
    guti.amf_region_id = 0x12;
    guti.amf_set_id = 0x345;
    guti.amf_pointer = 0x06;
    guti.tmsi_5g = 0x789ABCDE;

    std::string guti_str = guti.toString();

    EXPECT_FALSE(guti_str.empty());
    EXPECT_NE(guti_str.find("310410"), std::string::npos);
}

TEST_F(SubscriberContextTest, UpdateGuti5G) {
    std::string supi = "imsi-310410123456789";
    auto context = manager_->getOrCreateBySupi(supi);

    SubscriberContext::GUTI5G guti;
    guti.mcc_mnc = "310410";
    guti.amf_region_id = 0x12;
    guti.amf_set_id = 0x345;
    guti.amf_pointer = 0x06;
    guti.tmsi_5g = 0x789ABCDE;

    manager_->updateGuti5G(context->context_id, guti);

    ASSERT_TRUE(context->current_5g_guti.has_value());
    EXPECT_EQ(context->current_5g_guti.value(), guti);
}

// ============================================================================
// UE IP Address Tests
// ============================================================================

TEST_F(SubscriberContextTest, UpdateUeIpv4) {
    std::string imsi = "310410123456789";
    auto context = manager_->getOrCreate(imsi);

    std::string ipv4 = "10.45.1.100";
    manager_->updateUeIp(context->context_id, ipv4);

    EXPECT_EQ(context->current_ue_ipv4, ipv4);
    EXPECT_EQ(context->ue_ipv4_addresses.size(), 1);
    EXPECT_TRUE(context->ue_ipv4_addresses.count(ipv4));
}

TEST_F(SubscriberContextTest, UpdateUeIpv4AndIpv6) {
    std::string imsi = "310410123456789";
    auto context = manager_->getOrCreate(imsi);

    std::string ipv4 = "10.45.1.100";
    std::string ipv6 = "2001:db8::1";
    manager_->updateUeIp(context->context_id, ipv4, ipv6);

    EXPECT_EQ(context->current_ue_ipv4, ipv4);
    EXPECT_EQ(context->current_ue_ipv6, ipv6);
    EXPECT_EQ(context->ue_ipv4_addresses.size(), 1);
    EXPECT_EQ(context->ue_ipv6_addresses.size(), 1);
}

TEST_F(SubscriberContextTest, MultipleUeIpAddresses) {
    std::string imsi = "310410123456789";
    auto context = manager_->getOrCreate(imsi);

    std::string ipv4_1 = "10.45.1.100";
    std::string ipv4_2 = "10.45.1.101";  // IP changed during handover

    manager_->updateUeIp(context->context_id, ipv4_1);
    manager_->updateUeIp(context->context_id, ipv4_2);

    EXPECT_EQ(context->current_ue_ipv4, ipv4_2);  // Most recent
    EXPECT_EQ(context->ue_ipv4_addresses.size(), 2);  // Both preserved
    EXPECT_TRUE(context->ue_ipv4_addresses.count(ipv4_1));
    EXPECT_TRUE(context->ue_ipv4_addresses.count(ipv4_2));
}

// ============================================================================
// Bearer Management Tests
// ============================================================================

TEST_F(SubscriberContextTest, AddBearer) {
    std::string imsi = "310410123456789";
    auto context = manager_->getOrCreate(imsi);

    SubscriberContext::BearerInfo bearer;
    bearer.teid = 0x12345678;
    bearer.eps_bearer_id = 5;
    bearer.interface = "S1-U";
    bearer.pgw_ip = "192.168.1.1";
    bearer.qci = 9;
    bearer.uplink_teid = 0x11111111;
    bearer.downlink_teid = 0x22222222;
    bearer.created = std::chrono::system_clock::now();

    manager_->addBearer(context->context_id, bearer);

    EXPECT_EQ(context->bearers.size(), 1);
    EXPECT_EQ(context->bearers[0].teid, 0x12345678);
    EXPECT_EQ(context->bearers[0].eps_bearer_id, 5);
    EXPECT_TRUE(context->bearers[0].is_active());
    EXPECT_EQ(context->getActiveBearerCount(), 1);
}

TEST_F(SubscriberContextTest, RemoveBearer) {
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
    EXPECT_EQ(context->getActiveBearerCount(), 1);

    manager_->removeBearer(context->context_id, 0x12345678);
    EXPECT_EQ(context->bearers.size(), 1);  // Still in list
    EXPECT_FALSE(context->bearers[0].is_active());  // But marked deleted
    EXPECT_EQ(context->getActiveBearerCount(), 0);
}

TEST_F(SubscriberContextTest, MultipleBearers) {
    std::string imsi = "310410123456789";
    auto context = manager_->getOrCreate(imsi);

    // Add default bearer
    SubscriberContext::BearerInfo bearer1;
    bearer1.teid = 0x11111111;
    bearer1.eps_bearer_id = 5;
    bearer1.interface = "S1-U";
    bearer1.pgw_ip = "192.168.1.1";
    bearer1.qci = 9;
    bearer1.created = std::chrono::system_clock::now();

    // Add dedicated bearer for VoLTE
    SubscriberContext::BearerInfo bearer2;
    bearer2.teid = 0x22222222;
    bearer2.eps_bearer_id = 6;
    bearer2.interface = "S1-U";
    bearer2.pgw_ip = "192.168.1.1";
    bearer2.qci = 1;  // GBR for voice
    bearer2.created = std::chrono::system_clock::now();

    manager_->addBearer(context->context_id, bearer1);
    manager_->addBearer(context->context_id, bearer2);

    EXPECT_EQ(context->bearers.size(), 2);
    EXPECT_EQ(context->getActiveBearerCount(), 2);
}

// ============================================================================
// PDU Session Tests
// ============================================================================

TEST_F(SubscriberContextTest, AddPduSession) {
    std::string supi = "imsi-310410123456789";
    auto context = manager_->getOrCreateBySupi(supi);

    SubscriberContext::PduSessionInfo session;
    session.pdu_session_id = 1;
    session.uplink_teid = 0x11111111;
    session.downlink_teid = 0x22222222;
    session.dnn = "internet";
    session.sst = 1;
    session.sd = 0x000001;
    session.created = std::chrono::system_clock::now();

    manager_->addPduSession(context->context_id, session);

    EXPECT_EQ(context->pdu_sessions.size(), 1);
    EXPECT_EQ(context->pdu_sessions[0].pdu_session_id, 1);
    EXPECT_TRUE(context->pdu_sessions[0].is_active());
    EXPECT_EQ(context->getActivePduSessionCount(), 1);
}

TEST_F(SubscriberContextTest, RemovePduSession) {
    std::string supi = "imsi-310410123456789";
    auto context = manager_->getOrCreateBySupi(supi);

    SubscriberContext::PduSessionInfo session;
    session.pdu_session_id = 1;
    session.uplink_teid = 0x11111111;
    session.downlink_teid = 0x22222222;
    session.dnn = "internet";
    session.sst = 1;
    session.created = std::chrono::system_clock::now();

    manager_->addPduSession(context->context_id, session);
    EXPECT_EQ(context->getActivePduSessionCount(), 1);

    manager_->removePduSession(context->context_id, 1);
    EXPECT_EQ(context->pdu_sessions.size(), 1);
    EXPECT_FALSE(context->pdu_sessions[0].is_active());
    EXPECT_EQ(context->getActivePduSessionCount(), 0);
}

// ============================================================================
// Control Plane Context ID Tests
// ============================================================================

TEST_F(SubscriberContextTest, UpdateControlPlaneIds) {
    std::string imsi = "310410123456789";
    auto context = manager_->getOrCreate(imsi);

    manager_->updateMmeUeId(context->context_id, 12345);
    manager_->updateEnbUeId(context->context_id, 67890);

    ASSERT_TRUE(context->mme_ue_s1ap_id.has_value());
    EXPECT_EQ(context->mme_ue_s1ap_id.value(), 12345);

    ASSERT_TRUE(context->enb_ue_s1ap_id.has_value());
    EXPECT_EQ(context->enb_ue_s1ap_id.value(), 67890);
}

TEST_F(SubscriberContextTest, Update5GControlPlaneIds) {
    std::string supi = "imsi-310410123456789";
    auto context = manager_->getOrCreateBySupi(supi);

    manager_->updateAmfUeId(context->context_id, 0x123456789ABCDEF0);
    manager_->updateRanUeId(context->context_id, 0xFEDCBA9876543210);

    ASSERT_TRUE(context->amf_ue_ngap_id.has_value());
    EXPECT_EQ(context->amf_ue_ngap_id.value(), 0x123456789ABCDEF0);

    ASSERT_TRUE(context->ran_ue_ngap_id.has_value());
    EXPECT_EQ(context->ran_ue_ngap_id.value(), 0xFEDCBA9876543210);
}

// ============================================================================
// IMS/VoLTE Identifier Tests
// ============================================================================

TEST_F(SubscriberContextTest, UpdateSipUri) {
    std::string imsi = "310410123456789";
    auto context = manager_->getOrCreate(imsi);

    std::string sip_uri = "sip:+14155551234@ims.mnc410.mcc310.3gppnetwork.org";
    manager_->updateSipUri(context->context_id, sip_uri);

    EXPECT_EQ(context->current_sip_uri, sip_uri);
    EXPECT_EQ(context->sip_uris.size(), 1);
    EXPECT_TRUE(context->sip_uris.count(sip_uri));
}

TEST_F(SubscriberContextTest, AddSipCallId) {
    std::string imsi = "310410123456789";
    auto context = manager_->getOrCreate(imsi);

    std::string call_id = "a84b4c76e66710@192.0.2.4";
    manager_->addSipCallId(context->context_id, call_id);

    EXPECT_EQ(context->sip_call_ids.size(), 1);
    EXPECT_TRUE(context->sip_call_ids.count(call_id));
}

TEST_F(SubscriberContextTest, AddIcid) {
    std::string imsi = "310410123456789";
    auto context = manager_->getOrCreate(imsi);

    std::string icid = "ab84b4c76e66710192.0.2.4-1234567890";
    manager_->addIcid(context->context_id, icid);

    EXPECT_EQ(context->icids.size(), 1);
    EXPECT_TRUE(context->icids.count(icid));
}

// ============================================================================
// Session ID Tests
// ============================================================================

TEST_F(SubscriberContextTest, AddSessionId) {
    std::string imsi = "310410123456789";
    auto context = manager_->getOrCreate(imsi);

    std::string session_id = "session_123456";
    manager_->addSessionId(context->context_id, session_id);

    EXPECT_EQ(context->session_ids.size(), 1);
    EXPECT_TRUE(context->session_ids.count(session_id));
}

// ============================================================================
// JSON Serialization Tests
// ============================================================================

TEST_F(SubscriberContextTest, ToJsonBasic) {
    std::string imsi = "310410123456789";
    auto context = manager_->getOrCreate(imsi);

    auto json = context->toJson();

    EXPECT_TRUE(json.contains("context_id"));
    EXPECT_TRUE(json.contains("imsi"));
    EXPECT_EQ(json["imsi"], imsi);
    EXPECT_TRUE(json.contains("first_seen"));
    EXPECT_TRUE(json.contains("last_updated"));
}

TEST_F(SubscriberContextTest, ToJsonWithBearers) {
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

    auto json = context->toJson();

    EXPECT_TRUE(json.contains("bearers"));
    EXPECT_TRUE(json["bearers"].is_array());
    EXPECT_EQ(json["bearers"].size(), 1);
    EXPECT_EQ(json["bearers"][0]["teid"], 0x12345678);
    EXPECT_EQ(json["bearers"][0]["eps_bearer_id"], 5);
}

// ============================================================================
// Lifecycle Tests
// ============================================================================

TEST_F(SubscriberContextTest, FirstSeenAndLastUpdated) {
    std::string imsi = "310410123456789";
    auto context = manager_->getOrCreate(imsi);

    auto first_seen = context->first_seen;
    auto last_updated = context->last_updated;

    EXPECT_EQ(first_seen, last_updated);  // Initially the same

    // Wait a bit and update
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    manager_->updateMsisdn(context->context_id, "14155551234");

    EXPECT_GT(context->last_updated, first_seen);
}

// ============================================================================
// Statistics Tests
// ============================================================================

TEST_F(SubscriberContextTest, Stats) {
    auto stats = manager_->getStats();
    EXPECT_EQ(stats.total_contexts, 0);
    EXPECT_EQ(stats.with_imsi, 0);

    manager_->getOrCreate("310410123456789");

    stats = manager_->getStats();
    EXPECT_EQ(stats.total_contexts, 1);
    EXPECT_EQ(stats.with_imsi, 1);
}

TEST_F(SubscriberContextTest, StatsJson) {
    manager_->getOrCreate("310410123456789");

    auto stats = manager_->getStats();
    auto json = stats.toJson();

    EXPECT_TRUE(json.contains("total_contexts"));
    EXPECT_EQ(json["total_contexts"], 1);
    EXPECT_TRUE(json.contains("with_imsi"));
    EXPECT_EQ(json["with_imsi"], 1);
}

// ============================================================================
// Helper Method Tests
// ============================================================================

TEST_F(SubscriberContextTest, HasIdentifier) {
    std::string imsi = "310410123456789";
    auto context = manager_->getOrCreate(imsi);

    EXPECT_TRUE(context->hasIdentifier(imsi));
    EXPECT_FALSE(context->hasIdentifier("999999999999999"));
}

TEST_F(SubscriberContextTest, GetPrimaryIdentifierPreference) {
    auto context = manager_->createTemporaryContext();

    // No identifiers - should return context_id
    EXPECT_EQ(context->getPrimaryIdentifier(), context->context_id);

    // Add MSISDN
    manager_->updateMsisdn(context->context_id, "14155551234");
    EXPECT_EQ(context->getPrimaryIdentifier(), "14155551234");

    // Add IMSI - should prefer IMSI
    manager_->updateImsi(context->context_id, "310410123456789");
    EXPECT_EQ(context->getPrimaryIdentifier(), "310410123456789");
}

TEST_F(SubscriberContextTest, GetDisplayName) {
    auto context = manager_->createTemporaryContext();

    // No identifiers
    EXPECT_EQ(context->getDisplayName(), context->context_id);

    // IMSI only
    manager_->updateImsi(context->context_id, "310410123456789");
    EXPECT_EQ(context->getDisplayName(), "310410123456789");

    // Add MSISDN - should prefer MSISDN for display
    manager_->updateMsisdn(context->context_id, "14155551234");
    EXPECT_EQ(context->getDisplayName(), "14155551234");
}
