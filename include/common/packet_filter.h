#pragma once

#include <optional>
#include <string>
#include <variant>
#include <vector>

#include "common/field_registry.h"

namespace callflow {

enum class FilterOperator {
    EQ,   // ==
    NEQ,  // !=
    GT,   // >
    LT,   // <
    GTE,  // >=
    LTE   // <=
};

struct FilterRule {
    std::string field_key;
    FilterOperator op;
    FieldValue value;
};

class PacketFilter {
public:
    PacketFilter() = default;
    ~PacketFilter() = default;

    // Load rules from a file (one rule per line)
    // Format: key operator value (e.g. "gtpv2.msg_type == 1")
    void loadRules(const std::string& config_path);

    // Add a single rule string
    void addRule(const std::string& rule_str);

    // Evaluate packet against all rules.
    // Returns true if ANY rule matches (OR logic) - or typically filters are "drop if match"
    // Let's assume for now: returns true if the packet matches the filter (and thus should be
    // dropped/kept depends on caller context). The user requirement said: "If true, drop the
    // packet."
    bool evaluate(const void* packet_ptr) const;

private:
    std::vector<FilterRule> rules_;

    std::optional<FilterRule> parseRule(const std::string& rule_str);
    bool compare(const FieldValue& lhs, const FieldValue& rhs, FilterOperator op) const;
};

}  // namespace callflow
