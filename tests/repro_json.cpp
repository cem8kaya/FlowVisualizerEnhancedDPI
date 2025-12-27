#include <cstdint>
#include <iostream>
#include <nlohmann/json.hpp>

int main() {
    uint64_t large_ts = 1686843087724;  // 1.68e12
    nlohmann::json j;

    // Test assigning uint64_t
    j["test_uint64"] = large_ts;
    std::cout << "Original uint64: " << large_ts << std::endl;
    std::cout << "JSON dump: " << j.dump() << std::endl;

    // Check if it got truncated
    if (j["test_uint64"].is_number_integer()) {
        std::cout << "Stored as integer: " << j["test_uint64"].get<int64_t>() << std::endl;
    } else if (j["test_uint64"].is_number_unsigned()) {
        std::cout << "Stored as unsigned: " << j["test_uint64"].get<uint64_t>() << std::endl;
    } else if (j["test_uint64"].is_number_float()) {
        std::cout << "Stored as float: " << j["test_uint64"].get<double>() << std::endl;
        std::cout << "Float cast to int64: " << (int64_t)j["test_uint64"].get<double>()
                  << std::endl;
    } else {
        std::cout << "Stored as unknown type" << std::endl;
    }

    // Reproduction of the bug pattern
    double start_time_sec = 1686843087.724962;
    j["bug_repro"] = static_cast<uint64_t>(start_time_sec * 1000);
    std::cout << "Bug Repro JSON: " << j["bug_repro"] << std::endl;

    return 0;
}
