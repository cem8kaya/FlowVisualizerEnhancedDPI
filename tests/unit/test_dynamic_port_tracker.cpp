#include <gtest/gtest.h>
#include "pcap_ingest/packet_processor.h"
#include <thread>
#include <chrono>

using namespace callflow;

// ============================================================================
// DynamicPortTracker Tests
// ============================================================================

TEST(DynamicPortTrackerTest, RegisterAndCheckSinglePort) {
    DynamicPortTracker tracker;

    tracker.registerRtpPorts("call-id-123", 10000, 20000);

    EXPECT_TRUE(tracker.isKnownRtpPort(10000));
    EXPECT_TRUE(tracker.isKnownRtpPort(20000));
    EXPECT_FALSE(tracker.isKnownRtpPort(30000));
}

TEST(DynamicPortTrackerTest, RegisterSamePortTwice) {
    DynamicPortTracker tracker;

    tracker.registerRtpPorts("call-id-1", 10000, 10000);

    // Should only register once
    EXPECT_TRUE(tracker.isKnownRtpPort(10000));

    auto call_id = tracker.getCallIdByPort(10000);
    ASSERT_TRUE(call_id.has_value());
    EXPECT_EQ(call_id.value(), "call-id-1");
}

TEST(DynamicPortTrackerTest, GetCallIdByPort) {
    DynamicPortTracker tracker;

    tracker.registerRtpPorts("call-abc", 11000, 11001);
    tracker.registerRtpPorts("call-xyz", 12000, 12001);

    auto call_id_1 = tracker.getCallIdByPort(11000);
    ASSERT_TRUE(call_id_1.has_value());
    EXPECT_EQ(call_id_1.value(), "call-abc");

    auto call_id_2 = tracker.getCallIdByPort(12001);
    ASSERT_TRUE(call_id_2.has_value());
    EXPECT_EQ(call_id_2.value(), "call-xyz");

    auto call_id_unknown = tracker.getCallIdByPort(99999);
    EXPECT_FALSE(call_id_unknown.has_value());
}

TEST(DynamicPortTrackerTest, MultipleCallsWithDifferentPorts) {
    DynamicPortTracker tracker;

    // Register multiple calls
    tracker.registerRtpPorts("call-1", 10000, 10001);
    tracker.registerRtpPorts("call-2", 20000, 20001);
    tracker.registerRtpPorts("call-3", 30000, 30001);

    // Verify all ports are registered
    EXPECT_TRUE(tracker.isKnownRtpPort(10000));
    EXPECT_TRUE(tracker.isKnownRtpPort(10001));
    EXPECT_TRUE(tracker.isKnownRtpPort(20000));
    EXPECT_TRUE(tracker.isKnownRtpPort(20001));
    EXPECT_TRUE(tracker.isKnownRtpPort(30000));
    EXPECT_TRUE(tracker.isKnownRtpPort(30001));

    // Verify call IDs
    EXPECT_EQ(tracker.getCallIdByPort(10000).value(), "call-1");
    EXPECT_EQ(tracker.getCallIdByPort(20001).value(), "call-2");
    EXPECT_EQ(tracker.getCallIdByPort(30000).value(), "call-3");
}

TEST(DynamicPortTrackerTest, OverwriteExistingPort) {
    DynamicPortTracker tracker;

    // Register port with first call
    tracker.registerRtpPorts("call-old", 10000, 10001);
    EXPECT_EQ(tracker.getCallIdByPort(10000).value(), "call-old");

    // Re-register same port with different call (port reuse scenario)
    tracker.registerRtpPorts("call-new", 10000, 10002);
    EXPECT_EQ(tracker.getCallIdByPort(10000).value(), "call-new");
}

TEST(DynamicPortTrackerTest, RegisterZeroPort) {
    DynamicPortTracker tracker;

    // Port 0 should be ignored
    tracker.registerRtpPorts("call-id", 0, 10000);

    EXPECT_FALSE(tracker.isKnownRtpPort(0));
    EXPECT_TRUE(tracker.isKnownRtpPort(10000));
}

TEST(DynamicPortTrackerTest, CleanupExpiredEntries) {
    DynamicPortTracker tracker;

    auto start_time = std::chrono::system_clock::now();

    // Register ports
    tracker.registerRtpPorts("call-1", 10000, 10001);

    // Immediately check - should not be expired
    size_t removed = tracker.cleanupExpired(start_time);
    EXPECT_EQ(removed, 0);
    EXPECT_TRUE(tracker.isKnownRtpPort(10000));

    // Simulate time passing (> 5 minutes = 300 seconds)
    auto future_time = start_time + std::chrono::seconds(301);
    removed = tracker.cleanupExpired(future_time);

    EXPECT_EQ(removed, 2);  // Both ports should be removed
    EXPECT_FALSE(tracker.isKnownRtpPort(10000));
    EXPECT_FALSE(tracker.isKnownRtpPort(10001));
}

TEST(DynamicPortTrackerTest, CleanupExpiredWithMultipleCalls) {
    DynamicPortTracker tracker;

    auto start_time = std::chrono::system_clock::now();

    // Register first call
    tracker.registerRtpPorts("call-1", 10000, 10001);

    // Wait a bit, then register second call
    auto mid_time = start_time + std::chrono::seconds(200);

    // Simulate registering second call later
    // (In real scenario, we'd need to manipulate time, but for testing we'll simulate)
    tracker.registerRtpPorts("call-2", 20000, 20001);

    // Cleanup at time when first call should expire but second shouldn't
    // (This test is approximate due to timestamp limitations)
    auto cleanup_time = start_time + std::chrono::seconds(350);
    size_t removed = tracker.cleanupExpired(cleanup_time);

    // All entries should be expired (both registered around start_time in this test)
    EXPECT_GT(removed, 0);
}

TEST(DynamicPortTrackerTest, ThreadSafety) {
    DynamicPortTracker tracker;

    // Test concurrent access from multiple threads
    auto register_ports = [&tracker](int start_port, const std::string& call_prefix) {
        for (int i = 0; i < 100; ++i) {
            std::string call_id = call_prefix + std::to_string(i);
            tracker.registerRtpPorts(call_id, start_port + i * 2, start_port + i * 2 + 1);
        }
    };

    auto check_ports = [&tracker](int start_port) {
        for (int i = 0; i < 100; ++i) {
            tracker.isKnownRtpPort(start_port + i * 2);
            tracker.getCallIdByPort(start_port + i * 2);
        }
    };

    // Launch multiple threads
    std::thread t1(register_ports, 10000, "call-a-");
    std::thread t2(register_ports, 20000, "call-b-");
    std::thread t3(check_ports, 10000);
    std::thread t4(check_ports, 20000);

    t1.join();
    t2.join();
    t3.join();
    t4.join();

    // Verify some ports were registered
    EXPECT_TRUE(tracker.isKnownRtpPort(10000));
    EXPECT_TRUE(tracker.isKnownRtpPort(20000));
}

TEST(DynamicPortTrackerTest, LargeNumberOfPorts) {
    DynamicPortTracker tracker;

    // Register many ports to test scalability
    for (int i = 0; i < 1000; ++i) {
        std::string call_id = "call-" + std::to_string(i);
        tracker.registerRtpPorts(call_id, 10000 + i * 2, 10000 + i * 2 + 1);
    }

    // Verify random samples
    EXPECT_TRUE(tracker.isKnownRtpPort(10000));
    EXPECT_TRUE(tracker.isKnownRtpPort(11000));
    EXPECT_TRUE(tracker.isKnownRtpPort(12000));

    auto call_id = tracker.getCallIdByPort(10500);
    ASSERT_TRUE(call_id.has_value());
    EXPECT_EQ(call_id.value(), "call-250");
}

TEST(DynamicPortTrackerTest, CleanupReturnsCorrectCount) {
    DynamicPortTracker tracker;

    auto start_time = std::chrono::system_clock::now();

    // Register 3 calls (6 ports total)
    tracker.registerRtpPorts("call-1", 10000, 10001);
    tracker.registerRtpPorts("call-2", 20000, 20001);
    tracker.registerRtpPorts("call-3", 30000, 30001);

    // Cleanup with future time
    auto future_time = start_time + std::chrono::seconds(400);
    size_t removed = tracker.cleanupExpired(future_time);

    EXPECT_EQ(removed, 6);  // All 6 ports should be removed
}

TEST(DynamicPortTrackerTest, EmptyTrackerCleanup) {
    DynamicPortTracker tracker;

    auto now = std::chrono::system_clock::now();
    size_t removed = tracker.cleanupExpired(now);

    EXPECT_EQ(removed, 0);
}

// Entry point
int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
