#include <cstdint>
#include <cstring>
#include <iostream>
#include <vector>

#include "pcap_ingest/pcapng_reader.h"

// Mock for PcapngInterface to test getTimestampResolutionNs directly
// since it's defined in the header, we can test it easily.

void test_resolution_calculation() {
    std::cout << "Testing timestamp resolution calculation..." << std::endl;

    callflow::PcapngInterface iface;

    // Case 1: Default (no value)
    iface.timestamp_resolution = std::nullopt;
    uint64_t def = iface.getTimestampResolutionNs();
    std::cout << "Default resolution (expected 1000 ns for 1us): " << def << " ns" << std::endl;
    if (def != 1000) {
        std::cout << "FAIL: Default should be 1000 (1us), got " << def << std::endl;
    }

    // Case 2: Explicit 6 (10^-6 = 1us)
    iface.timestamp_resolution = 6;
    uint64_t res6 = iface.getTimestampResolutionNs();
    std::cout << "Resolution 6 (expected 1000 ns): " << res6 << " ns" << std::endl;

    // Case 3: Explicit 3 (10^-3 = 1ms)
    iface.timestamp_resolution = 3;
    uint64_t res3 = iface.getTimestampResolutionNs();
    std::cout << "Resolution 3 (expected 1000000 ns): " << res3 << " ns" << std::endl;

    // Case 4: Explicit 9 (10^-9 = 1ns)
    iface.timestamp_resolution = 9;
    uint64_t res9 = iface.getTimestampResolutionNs();
    std::cout << "Resolution 9 (expected 1 ns): " << res9 << " ns" << std::endl;

    // Case 5: Binary 10^-3 (roughly)? Base 2?
    // 2^-10 = 1/1024 approx 1ms.
    // 0x80 | 10 = 0x8A
    iface.timestamp_resolution = 0x8A;  // 2^-10
    uint64_t resBin = iface.getTimestampResolutionNs();
    std::cout << "Resolution 2^-10 (1/1024 s, approx 976562 ns): " << resBin << " ns" << std::endl;
}

int main() {
    test_resolution_calculation();
    return 0;
}
