#pragma once

#include <functional>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <variant>

namespace callflow {

using FieldValue = std::variant<std::string, int64_t, bool, double>;
using Accessor = std::function<FieldValue(const void* packet_ptr)>;

class FieldRegistry {
public:
    static FieldRegistry& getInstance() {
        static FieldRegistry instance;
        return instance;
    }

    void registerField(const std::string& key, Accessor accessor) {
        registry_[key] = std::move(accessor);
    }

    FieldValue getValue(const std::string& key, const void* packet_ptr) const {
        auto it = registry_.find(key);
        if (it == registry_.end()) {
            throw std::runtime_error("Field not found: " + key);
        }
        return it->second(packet_ptr);
    }

    bool hasField(const std::string& key) const { return registry_.find(key) != registry_.end(); }

private:
    FieldRegistry() = default;
    ~FieldRegistry() = default;
    FieldRegistry(const FieldRegistry&) = delete;
    FieldRegistry& operator=(const FieldRegistry&) = delete;

    std::unordered_map<std::string, Accessor> registry_;
};

}  // namespace callflow
