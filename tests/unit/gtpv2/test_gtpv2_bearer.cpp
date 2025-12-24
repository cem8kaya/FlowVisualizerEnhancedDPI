#include <gtest/gtest.h>
#include "correlation/gtpv2/gtpv2_bearer.h"

using namespace callflow::correlation;

class Gtpv2BearerTest : public ::testing::Test {
protected:
    void SetUp() override {
        bearer = std::make_unique<GtpBearer>(5);
    }

    void TearDown() override {
        bearer.reset();
    }

    std::unique_ptr<GtpBearer> bearer;
};

TEST_F(Gtpv2BearerTest, BasicProperties) {
    EXPECT_EQ(bearer->getEbi(), 5);
    EXPECT_EQ(bearer->getType(), BearerType::DEFAULT);
}

TEST_F(Gtpv2BearerTest, SetEbi) {
    bearer->setEbi(6);
    EXPECT_EQ(bearer->getEbi(), 6);
}

TEST_F(Gtpv2BearerTest, BearerType) {
    EXPECT_TRUE(bearer->isDefault());
    EXPECT_FALSE(bearer->isDedicated());

    bearer->setType(BearerType::DEDICATED);
    EXPECT_FALSE(bearer->isDefault());
    EXPECT_TRUE(bearer->isDedicated());
}

TEST_F(Gtpv2BearerTest, LinkedBearer) {
    EXPECT_FALSE(bearer->getLbi().has_value());

    bearer->setLbi(5);
    EXPECT_TRUE(bearer->getLbi().has_value());
    EXPECT_EQ(bearer->getLbi().value(), 5);
}

TEST_F(Gtpv2BearerTest, QoSParameters) {
    bearer->setQci(1);
    EXPECT_EQ(bearer->getQci().value(), 1);

    bearer->setMbrUl(10000000);
    bearer->setMbrDl(50000000);
    EXPECT_EQ(bearer->getMbrUl().value(), 10000000);
    EXPECT_EQ(bearer->getMbrDl().value(), 50000000);

    bearer->setGbrUl(5000000);
    bearer->setGbrDl(25000000);
    EXPECT_EQ(bearer->getGbrUl().value(), 5000000);
    EXPECT_EQ(bearer->getGbrDl().value(), 25000000);
    EXPECT_TRUE(bearer->isGbr());
}

TEST_F(Gtpv2BearerTest, S1uEndpoints) {
    bearer->setS1uEnbIp("192.168.1.1");
    bearer->setS1uEnbTeid(0x11111111);

    EXPECT_EQ(bearer->getS1uEnbIp().value(), "192.168.1.1");
    EXPECT_EQ(bearer->getS1uEnbTeid().value(), 0x11111111);

    bearer->setS1uSgwIp("192.168.1.2");
    bearer->setS1uSgwTeid(0x22222222);

    EXPECT_EQ(bearer->getS1uSgwIp().value(), "192.168.1.2");
    EXPECT_EQ(bearer->getS1uSgwTeid().value(), 0x22222222);
}

TEST_F(Gtpv2BearerTest, S5Endpoints) {
    bearer->setS5PgwIp("10.0.0.1");
    bearer->setS5PgwTeid(0x33333333);

    EXPECT_EQ(bearer->getS5PgwIp().value(), "10.0.0.1");
    EXPECT_EQ(bearer->getS5PgwTeid().value(), 0x33333333);

    bearer->setS5SgwIp("10.0.0.2");
    bearer->setS5SgwTeid(0x44444444);

    EXPECT_EQ(bearer->getS5SgwIp().value(), "10.0.0.2");
    EXPECT_EQ(bearer->getS5SgwTeid().value(), 0x44444444);
}

TEST_F(Gtpv2BearerTest, TimeWindow) {
    bearer->setStartTime(100.0);
    bearer->setEndTime(200.0);
    bearer->setStartFrame(1);
    bearer->setEndFrame(100);

    EXPECT_DOUBLE_EQ(bearer->getStartTime(), 100.0);
    EXPECT_DOUBLE_EQ(bearer->getEndTime(), 200.0);
    EXPECT_EQ(bearer->getStartFrame(), 1);
    EXPECT_EQ(bearer->getEndFrame(), 100);
}

TEST_F(Gtpv2BearerTest, State) {
    EXPECT_EQ(bearer->getState(), GtpBearer::State::CREATING);

    bearer->setState(GtpBearer::State::ACTIVE);
    EXPECT_EQ(bearer->getState(), GtpBearer::State::ACTIVE);

    bearer->setState(GtpBearer::State::MODIFYING);
    EXPECT_EQ(bearer->getState(), GtpBearer::State::MODIFYING);

    bearer->setState(GtpBearer::State::DELETING);
    EXPECT_EQ(bearer->getState(), GtpBearer::State::DELETING);

    bearer->setState(GtpBearer::State::DELETED);
    EXPECT_EQ(bearer->getState(), GtpBearer::State::DELETED);
}

TEST_F(Gtpv2BearerTest, ChargingId) {
    EXPECT_FALSE(bearer->getChargingId().has_value());

    bearer->setChargingId(12345);
    EXPECT_TRUE(bearer->getChargingId().has_value());
    EXPECT_EQ(bearer->getChargingId().value(), 12345);
}

TEST_F(Gtpv2BearerTest, UpdateFromFteid) {
    GtpV2FTEID fteid;
    fteid.interface_type = FTEIDInterfaceType::S1_U_ENODEB_GTP_U;
    fteid.teid = 0xABCDEF12;
    fteid.ipv4_address = "192.168.10.10";

    bearer->updateFteid(fteid);

    EXPECT_EQ(bearer->getS1uEnbTeid().value(), 0xABCDEF12);
    EXPECT_EQ(bearer->getS1uEnbIp().value(), "192.168.10.10");
}

TEST_F(Gtpv2BearerTest, UpdateFromBearerContext) {
    gtp::GtpV2BearerContext ctx;
    ctx.eps_bearer_id = 7;

    gtp::GtpV2BearerQoS qos;
    qos.qci = 1;
    qos.max_bitrate_uplink = 10000000;
    qos.max_bitrate_downlink = 50000000;
    qos.guaranteed_bitrate_uplink = 5000000;
    qos.guaranteed_bitrate_downlink = 25000000;
    ctx.qos = qos;

    ctx.charging_id = 98765;
    ctx.cause = CauseValue::REQUEST_ACCEPTED;

    bearer->updateFromBearerContext(ctx);

    EXPECT_EQ(bearer->getEbi(), 7);
    EXPECT_EQ(bearer->getQci().value(), 1);
    EXPECT_EQ(bearer->getMbrUl().value(), 10000000);
    EXPECT_EQ(bearer->getMbrDl().value(), 50000000);
    EXPECT_EQ(bearer->getGbrUl().value(), 5000000);
    EXPECT_EQ(bearer->getGbrDl().value(), 25000000);
    EXPECT_EQ(bearer->getChargingId().value(), 98765);
    EXPECT_EQ(bearer->getState(), GtpBearer::State::ACTIVE);
}

TEST_F(Gtpv2BearerTest, DedicatedBearerSetup) {
    GtpBearer dedicated(6);
    dedicated.setType(BearerType::DEDICATED);
    dedicated.setLbi(5);
    dedicated.setQci(1);  // Voice QCI

    EXPECT_TRUE(dedicated.isDedicated());
    EXPECT_EQ(dedicated.getLbi().value(), 5);
    EXPECT_EQ(dedicated.getQci().value(), 1);
}
