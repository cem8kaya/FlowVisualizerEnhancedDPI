#include <gtest/gtest.h>
#include "correlation/gtpv2/gtpv2_fteid_manager.h"
#include "correlation/gtpv2/gtpv2_session.h"

using namespace callflow::correlation;

class Gtpv2FteidManagerTest : public ::testing::Test {
protected:
    void SetUp() override {
        manager = std::make_unique<Gtpv2FteidManager>();
        session1 = std::make_unique<Gtpv2Session>(0x11111111, 1);
        session2 = std::make_unique<Gtpv2Session>(0x22222222, 2);
    }

    void TearDown() override {
        manager.reset();
        session1.reset();
        session2.reset();
    }

    std::unique_ptr<Gtpv2FteidManager> manager;
    std::unique_ptr<Gtpv2Session> session1;
    std::unique_ptr<Gtpv2Session> session2;
};

TEST_F(Gtpv2FteidManagerTest, RegisterAndFindFteid) {
    GtpV2FTEID fteid;
    fteid.interface_type = FTEIDInterfaceType::S1_U_ENODEB_GTP_U;
    fteid.teid = 0x12345678;
    fteid.ipv4_address = "192.168.1.1";

    manager->registerFteid(fteid, session1.get());

    auto* found = manager->findSessionByFteid("192.168.1.1", 0x12345678);
    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->getControlTeid(), session1->getControlTeid());
}

TEST_F(Gtpv2FteidManagerTest, FindNonExistentFteid) {
    auto* not_found = manager->findSessionByFteid("10.0.0.1", 0x99999999);
    EXPECT_EQ(not_found, nullptr);
}

TEST_F(Gtpv2FteidManagerTest, MultipleFteids) {
    GtpV2FTEID fteid1;
    fteid1.interface_type = FTEIDInterfaceType::S1_U_ENODEB_GTP_U;
    fteid1.teid = 0x11111111;
    fteid1.ipv4_address = "192.168.1.1";

    GtpV2FTEID fteid2;
    fteid2.interface_type = FTEIDInterfaceType::S1_U_SGW_GTP_U;
    fteid2.teid = 0x22222222;
    fteid2.ipv4_address = "192.168.1.2";

    manager->registerFteid(fteid1, session1.get());
    manager->registerFteid(fteid2, session2.get());

    auto* found1 = manager->findSessionByFteid("192.168.1.1", 0x11111111);
    ASSERT_NE(found1, nullptr);
    EXPECT_EQ(found1->getControlTeid(), session1->getControlTeid());

    auto* found2 = manager->findSessionByFteid("192.168.1.2", 0x22222222);
    ASSERT_NE(found2, nullptr);
    EXPECT_EQ(found2->getControlTeid(), session2->getControlTeid());
}

TEST_F(Gtpv2FteidManagerTest, UnregisterFteid) {
    GtpV2FTEID fteid;
    fteid.interface_type = FTEIDInterfaceType::S1_U_ENODEB_GTP_U;
    fteid.teid = 0x12345678;
    fteid.ipv4_address = "192.168.1.1";

    manager->registerFteid(fteid, session1.get());

    auto* found = manager->findSessionByFteid("192.168.1.1", 0x12345678);
    ASSERT_NE(found, nullptr);

    manager->unregisterFteid(fteid);

    auto* not_found = manager->findSessionByFteid("192.168.1.1", 0x12345678);
    EXPECT_EQ(not_found, nullptr);
}

TEST_F(Gtpv2FteidManagerTest, FindByGtpuPacketDownlink) {
    // Downlink: eNodeB -> SGW
    GtpV2FTEID fteid_enb;
    fteid_enb.interface_type = FTEIDInterfaceType::S1_U_ENODEB_GTP_U;
    fteid_enb.teid = 0x12345678;
    fteid_enb.ipv4_address = "192.168.1.1";

    manager->registerFteid(fteid_enb, session1.get());

    // GTP-U packet going to eNodeB (destination matches F-TEID)
    auto* found = manager->findSessionByGtpuPacket("10.0.0.1", "192.168.1.1", 0x12345678);
    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->getControlTeid(), session1->getControlTeid());
}

TEST_F(Gtpv2FteidManagerTest, FindByGtpuPacketUplink) {
    // Uplink: SGW -> PGW
    GtpV2FTEID fteid_sgw;
    fteid_sgw.interface_type = FTEIDInterfaceType::S5_S8_SGW_GTP_U;
    fteid_sgw.teid = 0xAABBCCDD;
    fteid_sgw.ipv4_address = "10.0.0.2";

    manager->registerFteid(fteid_sgw, session1.get());

    // GTP-U packet from SGW (source matches F-TEID)
    auto* found = manager->findSessionByGtpuPacket("10.0.0.2", "10.0.0.3", 0xAABBCCDD);
    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->getControlTeid(), session1->getControlTeid());
}

TEST_F(Gtpv2FteidManagerTest, GetImsiForGtpuPacket) {
    GtpV2FTEID fteid;
    fteid.interface_type = FTEIDInterfaceType::S1_U_ENODEB_GTP_U;
    fteid.teid = 0x12345678;
    fteid.ipv4_address = "192.168.1.1";

    session1->setImsi("001010123456789");
    manager->registerFteid(fteid, session1.get());

    auto imsi = manager->getImsiForGtpuPacket("10.0.0.1", "192.168.1.1", 0x12345678);
    ASSERT_TRUE(imsi.has_value());
    EXPECT_EQ(imsi.value(), "001010123456789");
}

TEST_F(Gtpv2FteidManagerTest, GetImsiNotFound) {
    auto imsi = manager->getImsiForGtpuPacket("10.0.0.1", "10.0.0.2", 0x99999999);
    EXPECT_FALSE(imsi.has_value());
}

TEST_F(Gtpv2FteidManagerTest, GetPdnAddressForGtpuPacket) {
    GtpV2FTEID fteid;
    fteid.interface_type = FTEIDInterfaceType::S1_U_ENODEB_GTP_U;
    fteid.teid = 0x12345678;
    fteid.ipv4_address = "192.168.1.1";

    session1->setPdnAddressV4("10.1.2.3");
    manager->registerFteid(fteid, session1.get());

    auto pdn = manager->getPdnAddressForGtpuPacket("10.0.0.1", "192.168.1.1", 0x12345678);
    ASSERT_TRUE(pdn.has_value());
    EXPECT_EQ(pdn.value(), "10.1.2.3");
}

TEST_F(Gtpv2FteidManagerTest, IPv6Support) {
    GtpV2FTEID fteid;
    fteid.interface_type = FTEIDInterfaceType::S1_U_ENODEB_GTP_U;
    fteid.teid = 0x12345678;
    fteid.ipv6_address = "2001:db8::1";

    manager->registerFteid(fteid, session1.get());

    auto* found = manager->findSessionByFteid("2001:db8::1", 0x12345678);
    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->getControlTeid(), session1->getControlTeid());
}

TEST_F(Gtpv2FteidManagerTest, DualStackSupport) {
    GtpV2FTEID fteid;
    fteid.interface_type = FTEIDInterfaceType::S1_U_ENODEB_GTP_U;
    fteid.teid = 0x12345678;
    fteid.ipv4_address = "192.168.1.1";
    fteid.ipv6_address = "2001:db8::1";

    manager->registerFteid(fteid, session1.get());

    auto* found_v4 = manager->findSessionByFteid("192.168.1.1", 0x12345678);
    ASSERT_NE(found_v4, nullptr);
    EXPECT_EQ(found_v4->getControlTeid(), session1->getControlTeid());

    auto* found_v6 = manager->findSessionByFteid("2001:db8::1", 0x12345678);
    ASSERT_NE(found_v6, nullptr);
    EXPECT_EQ(found_v6->getControlTeid(), session1->getControlTeid());
}

TEST_F(Gtpv2FteidManagerTest, Clear) {
    GtpV2FTEID fteid;
    fteid.interface_type = FTEIDInterfaceType::S1_U_ENODEB_GTP_U;
    fteid.teid = 0x12345678;
    fteid.ipv4_address = "192.168.1.1";

    manager->registerFteid(fteid, session1.get());
    EXPECT_GT(manager->getCount(), 0);

    manager->clear();
    EXPECT_EQ(manager->getCount(), 0);

    auto* not_found = manager->findSessionByFteid("192.168.1.1", 0x12345678);
    EXPECT_EQ(not_found, nullptr);
}

TEST_F(Gtpv2FteidManagerTest, GetCount) {
    EXPECT_EQ(manager->getCount(), 0);

    GtpV2FTEID fteid1;
    fteid1.interface_type = FTEIDInterfaceType::S1_U_ENODEB_GTP_U;
    fteid1.teid = 0x11111111;
    fteid1.ipv4_address = "192.168.1.1";

    GtpV2FTEID fteid2;
    fteid2.interface_type = FTEIDInterfaceType::S1_U_SGW_GTP_U;
    fteid2.teid = 0x22222222;
    fteid2.ipv4_address = "192.168.1.2";

    manager->registerFteid(fteid1, session1.get());
    EXPECT_EQ(manager->getCount(), 1);

    manager->registerFteid(fteid2, session2.get());
    EXPECT_EQ(manager->getCount(), 2);
}
