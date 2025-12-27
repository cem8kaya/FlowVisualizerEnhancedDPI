#include <cstdint>
#include <iomanip>
#include <iostream>

int main() {
    double ts_sec = 1686843087.724962;  // From JSON events
    uint64_t ts_ms_correct = static_cast<uint64_t>(ts_sec * 1000);

    std::cout << "Original sec: " << std::fixed << std::setprecision(6) << ts_sec << std::endl;
    std::cout << "Correct ms (uint64): " << ts_ms_correct << std::endl;

    // Cast to int32 (simulating truncation after conversion)
    int32_t truncated_after = static_cast<int32_t>(ts_ms_correct);
    std::cout << "Truncated to int32: " << truncated_after << std::endl;

    // Cast intermediate to int (simulating truncation before multiplication? Unlikely)
    int32_t truncated_before = static_cast<int32_t>(ts_sec);
    int64_t ms_from_truncated_sec = static_cast<int64_t>(truncated_before) * 1000;
    std::cout << "Truncated sec * 1000: " << ms_from_truncated_sec << std::endl;

    // What gives -1079059604?
    int32_t target = -1079059604;
    std::cout << "Target negative value: " << target << std::endl;
    std::cout << "Target as uint32: " << (uint32_t)target << std::endl;  // 3215907692
    std::cout << "Target Hex: " << std::hex << (uint32_t)target << std::dec
              << std::endl;  // BFAED26C

    // Let's look at ts_ms_correct in hex
    std::cout << "Correct ms Hex: " << std::hex << ts_ms_correct << std::dec << std::endl;
    // 1686843087724 -> 0x188BBFAED6C

    // Does 0x...BFAED26C match?
    // 0x188BBFAED6C vs 0xBFAED26C...
    // The mismatch is D6C vs 26C.
    // Wait.
    // Let's run this code to be sure.

    return 0;
}
