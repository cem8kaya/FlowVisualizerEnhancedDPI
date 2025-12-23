#include "common/packet_filter.h"

#include <algorithm>
#include <fstream>
#include <regex>
#include <sstream>

namespace callflow {

void PacketFilter::loadRules(const std::string& config_path) {
    std::ifstream file(config_path);
    if (!file.is_open()) {
        throw std::runtime_error("Could not open filter config: " + config_path);
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#')
            continue;
        addRule(line);
    }
}

void PacketFilter::addRule(const std::string& rule_str) {
    auto rule = parseRule(rule_str);
    if (rule) {
        rules_.push_back(*rule);
    }
}

bool PacketFilter::evaluate(const void* packet_ptr) const {
    auto& registry = FieldRegistry::getInstance();

    for (const auto& rule : rules_) {
        try {
            FieldValue val = registry.getValue(rule.field_key, packet_ptr);
            if (compare(val, rule.value, rule.op)) {
                return true;  // Match found
            }
        } catch (...) {
            // If field lookup fails, we assume it doesn't match the rule (or could log warning)
            continue;
        }
    }
    return false;
}

std::optional<FilterRule> PacketFilter::parseRule(const std::string& rule_str) {
    // Basic regex for parsing: key operator value
    // Operators: ==, !=, >=, <=, >, <
    std::regex re(R"(^\s*([\w\.]+)\s*(==|!=|>=|<=|>|<)\s*(.+)\s*$)");
    std::smatch match;

    if (!std::regex_match(rule_str, match, re)) {
        std::cerr << "Invalid rule format: " << rule_str << std::endl;
        return std::nullopt;
    }

    FilterRule rule;
    rule.field_key = match[1];
    std::string op_str = match[2];
    std::string val_str = match[3];

    // Parse Operator
    if (op_str == "==")
        rule.op = FilterOperator::EQ;
    else if (op_str == "!=")
        rule.op = FilterOperator::NEQ;
    else if (op_str == ">")
        rule.op = FilterOperator::GT;
    else if (op_str == "<")
        rule.op = FilterOperator::LT;
    else if (op_str == ">=")
        rule.op = FilterOperator::GTE;
    else if (op_str == "<=")
        rule.op = FilterOperator::LTE;
    else
        return std::nullopt;

    // Parse Value (Simple heuristics)
    // Try integer
    try {
        size_t pos;
        int64_t i = std::stoll(val_str, &pos);
        if (pos == val_str.length()) {
            rule.value = i;
            return rule;
        }
    } catch (...) {
    }

    // Try double
    try {
        size_t pos;
        double d = std::stod(val_str, &pos);
        if (pos == val_str.length()) {
            rule.value = d;
            return rule;
        }
    } catch (...) {
    }

    // Try bool
    if (val_str == "true" || val_str == "TRUE") {
        rule.value = true;
        return rule;
    }
    if (val_str == "false" || val_str == "FALSE") {
        rule.value = false;
        return rule;
    }

    // Default to string (remove quotes if present)
    if (val_str.size() >= 2 && val_str.front() == '"' && val_str.back() == '"') {
        val_str = val_str.substr(1, val_str.size() - 2);
    }
    rule.value = val_str;

    return rule;
}

// Helper to compare variants
struct VariantVisitor {
    const FieldValue& rhs;
    FilterOperator op;

    template <typename T>
    bool operator()(const T& lhs_val) {
        if (std::holds_alternative<T>(rhs)) {
            const T& rhs_val = std::get<T>(rhs);
            switch (op) {
                case FilterOperator::EQ:
                    return lhs_val == rhs_val;
                case FilterOperator::NEQ:
                    return lhs_val != rhs_val;
                case FilterOperator::GT:
                    return lhs_val > rhs_val;
                case FilterOperator::LT:
                    return lhs_val < rhs_val;
                case FilterOperator::GTE:
                    return lhs_val >= rhs_val;
                case FilterOperator::LTE:
                    return lhs_val <= rhs_val;
            }
        }
        // If types mismatch, return false (or handle specific cross-type comparisons if needed)
        return false;
    }
};

bool PacketFilter::compare(const FieldValue& lhs, const FieldValue& rhs, FilterOperator op) const {
    return std::visit(VariantVisitor{rhs, op}, lhs);
}

}  // namespace callflow
