#include <gtest/gtest.h>

#include "common/field_registry.h"
#include "common/packet_filter.h"

using namespace callflow;

// Mock packet structure for testing
struct TestPacket {
    std::string protocol;
    int64_t message_type;
    bool is_control;
    double timestamp;
};

class FieldRegistryTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Register fields only once (registry is singleton)
        // Note: In a real test suite, singleton state might persist,
        // so we check if already registered or use unique keys.
        auto& registry = FieldRegistry::getInstance();
        if (!registry.hasField("test.protocol")) {
            registry.registerField("test.protocol", [](const void* p) -> FieldValue {
                return static_cast<const TestPacket*>(p)->protocol;
            });
            registry.registerField("test.message_type", [](const void* p) -> FieldValue {
                return static_cast<const TestPacket*>(p)->message_type;
            });
            registry.registerField("test.is_control", [](const void* p) -> FieldValue {
                return static_cast<const TestPacket*>(p)->is_control;
            });
            registry.registerField("test.timestamp", [](const void* p) -> FieldValue {
                return static_cast<const TestPacket*>(p)->timestamp;
            });
        }
    }
};

TEST_F(FieldRegistryTest, GetValue) {
    TestPacket pkt{"GTP", 1, true, 123.456};
    auto& registry = FieldRegistry::getInstance();

    auto val_proto = registry.getValue("test.protocol", &pkt);
    EXPECT_EQ(std::get<std::string>(val_proto), "GTP");

    auto val_type = registry.getValue("test.message_type", &pkt);
    EXPECT_EQ(std::get<int64_t>(val_type), 1);

    auto val_bool = registry.getValue("test.is_control", &pkt);
    EXPECT_EQ(std::get<bool>(val_bool), true);

    auto val_double = registry.getValue("test.timestamp", &pkt);
    EXPECT_DOUBLE_EQ(std::get<double>(val_double), 123.456);
}

TEST(PacketFilterTest, EvaluateRules) {
    // Ensure fields are registered (re-using setup logic simpler to just call it)
    auto& registry = FieldRegistry::getInstance();
    if (!registry.hasField("test.protocol")) {
        registry.registerField("test.protocol", [](const void* p) -> FieldValue {
            return static_cast<const TestPacket*>(p)->protocol;
        });
        registry.registerField("test.message_type", [](const void* p) -> FieldValue {
            return static_cast<const TestPacket*>(p)->message_type;
        });
    }

    TestPacket pkt{"GTP", 1, true, 123.456};

    PacketFilter filter;

    // Case 1: Match String
    filter.addRule("test.protocol == \"GTP\"");
    EXPECT_TRUE(filter.evaluate(&pkt));

    // Case 2: Match Int
    PacketFilter filter2;
    filter2.addRule("test.message_type == 1");
    EXPECT_TRUE(filter2.evaluate(&pkt));

    // Case 3: No Match
    PacketFilter filter3;
    filter3.addRule("test.message_type == 2");
    EXPECT_FALSE(filter3.evaluate(&pkt));

    // Case 4: Operator >
    PacketFilter filter4;
    filter4.addRule("test.message_type > 0");
    EXPECT_TRUE(filter4.evaluate(&pkt));

    // Case 5: Invalid field
    PacketFilter filter5;
    filter5.addRule("invalid.field == 1");
    EXPECT_FALSE(filter5.evaluate(&pkt));
}
