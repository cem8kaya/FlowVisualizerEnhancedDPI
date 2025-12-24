#include <gtest/gtest.h>
#include "correlation/gtpv2/gtpv2_session.h"
#include "correlation/gtpv2/gtpv2_message.h"
#include "correlation/gtpv2/gtpv2_bearer.h"

using namespace callflow::correlation;

class Gtpv2SessionTest : public ::testing::Test {
protected:
    void SetUp() override {
        session = std::make_unique<Gtpv2Session>(0x12345678, 1);
    }

    void TearDown() override {
        session.reset();
    }

    std::unique_ptr<Gtpv2Session> session;
};

TEST_F(Gtpv2SessionTest, BasicProperties) {
    EXPECT_EQ(session->getControlTeid(), 0x12345678);
    EXPECT_EQ(session->getSequence(), 1);
    EXPECT_FALSE(session->getSessionKey().empty());
}

TEST_F(Gtpv2SessionTest, AddMessage) {
    Gtpv2Message msg;
    msg.setMessageType(GtpV2MessageType::CREATE_SESSION_REQUEST);
    msg.setTeid(0x12345678);
    msg.setSequence(1);
    msg.setTimestamp(100.0);
    msg.setFrameNumber(1);

    session->addMessage(msg);

    EXPECT_EQ(session->getMessageCount(), 1);
    const auto& messages = session->getMessages();
    EXPECT_EQ(messages.size(), 1);
}

TEST_F(Gtpv2SessionTest, TimeWindow) {
    Gtpv2Message msg1;
    msg1.setMessageType(GtpV2MessageType::CREATE_SESSION_REQUEST);
    msg1.setTeid(0x12345678);
    msg1.setSequence(1);
    msg1.setTimestamp(100.0);
    msg1.setFrameNumber(1);

    Gtpv2Message msg2;
    msg2.setMessageType(GtpV2MessageType::CREATE_SESSION_RESPONSE);
    msg2.setTeid(0x12345678);
    msg2.setSequence(1);
    msg2.setTimestamp(100.5);
    msg2.setFrameNumber(2);

    session->addMessage(msg1);
    session->addMessage(msg2);

    EXPECT_DOUBLE_EQ(session->getStartTime(), 100.0);
    EXPECT_DOUBLE_EQ(session->getEndTime(), 100.5);
    EXPECT_EQ(session->getStartFrame(), 1);
    EXPECT_EQ(session->getEndFrame(), 2);
    EXPECT_DOUBLE_EQ(session->getDuration(), 0.5);
}

TEST_F(Gtpv2SessionTest, BearerManagement) {
    GtpBearer bearer1(5);
    bearer1.setType(BearerType::DEFAULT);

    GtpBearer bearer2(6);
    bearer2.setType(BearerType::DEDICATED);
    bearer2.setLbi(5);

    session->addBearer(bearer1);
    session->addBearer(bearer2);

    auto* default_bearer = session->getDefaultBearer();
    ASSERT_NE(default_bearer, nullptr);
    EXPECT_EQ(default_bearer->getEbi(), 5);
    EXPECT_TRUE(default_bearer->isDefault());

    auto dedicated = session->getDedicatedBearers();
    EXPECT_EQ(dedicated.size(), 1);
    EXPECT_EQ(dedicated[0]->getEbi(), 6);
    EXPECT_TRUE(dedicated[0]->isDedicated());

    EXPECT_TRUE(session->hasDedicatedBearers());
}

TEST_F(Gtpv2SessionTest, GetBearerByEbi) {
    GtpBearer bearer(5);
    session->addBearer(bearer);

    auto* found = session->getBearer(5);
    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->getEbi(), 5);

    auto* not_found = session->getBearer(99);
    EXPECT_EQ(not_found, nullptr);
}

TEST_F(Gtpv2SessionTest, SubscriberInfo) {
    session->setImsi("001010123456789");
    session->setMsisdn("1234567890");
    session->setMei("123456789012345");

    EXPECT_EQ(session->getImsi().value(), "001010123456789");
    EXPECT_EQ(session->getMsisdn().value(), "1234567890");
    EXPECT_EQ(session->getMei().value(), "123456789012345");
}

TEST_F(Gtpv2SessionTest, NetworkInfo) {
    session->setApn("internet.mnc001.mcc001.gprs");
    session->setPdnAddressV4("10.1.2.3");
    session->setRatType(RATType::EUTRAN);

    EXPECT_EQ(session->getApn(), "internet.mnc001.mcc001.gprs");
    EXPECT_EQ(session->getPdnAddressV4().value(), "10.1.2.3");
    EXPECT_EQ(session->getRatType().value(), RATType::EUTRAN);
}

TEST_F(Gtpv2SessionTest, PdnClassification) {
    session->setApn("ims");
    EXPECT_EQ(session->getPdnClass(), PdnClass::IMS);
    EXPECT_TRUE(session->isIms());
    EXPECT_FALSE(session->isEmergency());

    session->setApn("emergency");
    EXPECT_EQ(session->getPdnClass(), PdnClass::EMERGENCY);
    EXPECT_TRUE(session->isEmergency());
    EXPECT_FALSE(session->isIms());

    session->setApn("internet");
    EXPECT_EQ(session->getPdnClass(), PdnClass::INTERNET);
    EXPECT_FALSE(session->isIms());
    EXPECT_FALSE(session->isEmergency());
}

TEST_F(Gtpv2SessionTest, SessionState) {
    EXPECT_EQ(session->getState(), Gtpv2Session::State::CREATING);

    session->setState(Gtpv2Session::State::ACTIVE);
    EXPECT_EQ(session->getState(), Gtpv2Session::State::ACTIVE);
    EXPECT_TRUE(session->isActive());

    session->setState(Gtpv2Session::State::DELETED);
    EXPECT_EQ(session->getState(), Gtpv2Session::State::DELETED);
    EXPECT_FALSE(session->isActive());
}

TEST_F(Gtpv2SessionTest, FteidManagement) {
    GtpV2FTEID fteid1;
    fteid1.interface_type = FTEIDInterfaceType::S11_MME_GTP_C;
    fteid1.teid = 0x11111111;
    fteid1.ipv4_address = "10.0.0.1";

    GtpV2FTEID fteid2;
    fteid2.interface_type = FTEIDInterfaceType::S11_S4_SGW_GTP_C;
    fteid2.teid = 0x22222222;
    fteid2.ipv4_address = "10.0.0.2";

    session->addFteid(fteid1);
    session->addFteid(fteid2);

    const auto& fteids = session->getFteids();
    EXPECT_EQ(fteids.size(), 2);

    auto found = session->getFteidByInterface(FTEIDInterfaceType::S11_MME_GTP_C);
    ASSERT_TRUE(found.has_value());
    EXPECT_EQ(found->teid, 0x11111111);

    auto not_found = session->getFteidByInterface(FTEIDInterfaceType::S1_U_ENODEB_GTP_U);
    EXPECT_FALSE(not_found.has_value());
}

TEST_F(Gtpv2SessionTest, Correlation) {
    session->setIntraCorrelator("gtpv2_session_1");
    session->setInterCorrelator("volte_call_1");

    EXPECT_EQ(session->getIntraCorrelator(), "gtpv2_session_1");
    EXPECT_EQ(session->getInterCorrelator(), "volte_call_1");
}

TEST_F(Gtpv2SessionTest, Finalize) {
    GtpBearer bearer(5);
    bearer.setType(BearerType::DEFAULT);
    session->addBearer(bearer);

    session->setApn("ims");

    EXPECT_FALSE(session->isFinalized());

    session->finalize();

    EXPECT_TRUE(session->isFinalized());
    EXPECT_EQ(session->getPdnClass(), PdnClass::IMS);
}

TEST_F(Gtpv2SessionTest, Subsessions) {
    Gtpv2Session::Subsession sub1;
    sub1.type = "dflt_ebi";
    sub1.idx = "5";
    sub1.start_frame = 1;
    sub1.end_frame = 10;

    Gtpv2Session::Subsession sub2;
    sub2.type = "ded_ebi";
    sub2.idx = "6";
    sub2.start_frame = 5;
    sub2.end_frame = 15;

    session->addSubsession(sub1);
    session->addSubsession(sub2);

    const auto& subsessions = session->getSubsessions();
    EXPECT_EQ(subsessions.size(), 2);
    EXPECT_EQ(subsessions[0].type, "dflt_ebi");
    EXPECT_EQ(subsessions[1].type, "ded_ebi");
}
