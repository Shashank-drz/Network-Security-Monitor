// SPDX-License-Identifier: MIT
#include <iostream>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>
#include <thread>
#include <chrono>
#include <sstream>
#include <unordered_map>
#include <variant>
#include <algorithm>
#include <random>
#include <array>
#include <iomanip>
#include <cstdint>

#include "nlohmann/json.hpp"
#include "yaml-cpp/yaml.h"

// forward declarations
class Rule;
class CorrelationEngine;

using json = nlohmann::json;

using RuleValue = std::variant<std::string, double>;

struct SimpleCondition {
    std::string key;
    std::string op;
    RuleValue value;
};

struct SequenceCondition {
    std::vector<std::string> rule_names;
    int time_window_seconds;
};

using Condition = std::variant<SimpleCondition, SequenceCondition>;

struct RecentEvent {
    std::string rule_name;
    std::chrono::system_clock::time_point timestamp;
};

// UUIDv4 generator (no external deps)
static std::string uuid_v4() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> dis(0, 0xffffffff);

    std::array<uint8_t, 16> b{};
    for (int i = 0; i < 16; i += 4) {
        uint32_t r = dis(gen);
        b[i + 0] = static_cast<uint8_t>((r >> 24) & 0xFF);
        b[i + 1] = static_cast<uint8_t>((r >> 16) & 0xFF);
        b[i + 2] = static_cast<uint8_t>((r >> 8) & 0xFF);
        b[i + 3] = static_cast<uint8_t>(r & 0xFF);
    }
    // Set version (4) and variant (10xx)
    b[6] = static_cast<uint8_t>((b[6] & 0x0F) | 0x40);
    b[8] = static_cast<uint8_t>((b[8] & 0x3F) | 0x80);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (int i = 0; i < 16; ++i) {
        oss << std::setw(2) << static_cast<int>(b[i]);
        if (i == 3 || i == 5 || i == 7 || i == 9) oss << '-';
    }
    return oss.str();
}

class Rule {
public:
    Rule(std::string name, Condition condition)
        : name_(std::move(name)), condition_(std::move(condition)) {}

    const std::string& GetName() const { return name_; }
    const Condition& GetCondition() const { return condition_; }

private:
    std::string name_;
    Condition condition_;
};

class CorrelationEngine {
public:
    void LoadRules(const std::string& rules_path);
    void ProcessEvent(const std::string& line, std::ofstream& findings_out);

private:
    bool EvaluateSimpleCondition(const SimpleCondition& cond, const json& event);
    void EvaluateSequenceRules(const std::string& matched_rule_name, const json& event, std::ofstream& findings_out);
    void CleanupOldEvents();

    std::vector<Rule> rules_;
    std::unordered_map<std::string, std::vector<RecentEvent>> state_by_ip_;
};

RuleValue ParseRuleValue(const std::string& value_str) {
    if (value_str.front() == '"' && value_str.back() == '"') {
        return value_str.substr(1, value_str.length() - 2);
    }
    try {
        return std::stod(value_str);
    } catch (const std::invalid_argument&) {
        return value_str;
    }
}

SimpleCondition ParseSimpleCondition(const std::string& condition_str) {
    std::string key, op, value_str;
    size_t op_pos = std::string::npos;

    const std::vector<std::string> operators = {"==", "!=", ">=", "<=", ">", "<"};
    for (const auto& o : operators) {
        op_pos = condition_str.find(o);
        if (op_pos != std::string::npos) {
            op = o;
            break;
        }
    }

    if (op_pos == std::string::npos) {
        throw std::runtime_error("Invalid condition format: no operator found in '" + condition_str + "'");
    }

    key = condition_str.substr(0, op_pos);
    value_str = condition_str.substr(op_pos + op.length());

    // trim
    key.erase(0, key.find_first_not_of(" \t\n\r"));
    key.erase(key.find_last_not_of(" \t\n\r") + 1);
    value_str.erase(0, value_str.find_first_not_of(" \t\n\r"));
    value_str.erase(value_str.find_last_not_of(" \t\n\r") + 1);

    return {key, op, ParseRuleValue(value_str)};
}

void CorrelationEngine::LoadRules(const std::string& rules_path) {
    try {
        YAML::Node config = YAML::LoadFile(rules_path);
        for (const auto& rule_node : config["rules"]) {
            std::string name = rule_node["name"].as<std::string>();
            if (rule_node["condition"]) {
                Condition cond = ParseSimpleCondition(rule_node["condition"].as<std::string>());
                rules_.emplace_back(name, cond);
            } else if (rule_node["sequence"]) {
                SequenceCondition seq;
                seq.time_window_seconds = rule_node["sequence"]["time_window"].as<int>();
                for (const auto& rule_name_node : rule_node["sequence"]["rules"]) {
                    seq.rule_names.push_back(rule_name_node.as<std::string>());
                }
                rules_.emplace_back(name, seq);
            }
        }
        std::cout << "[INFO] Loaded " << rules_.size() << " rules." << std::endl;
    } catch (const YAML::Exception& e) {
        std::cerr << "[ERROR] Failed to load or parse rules file: " << e.what() << std::endl;
        throw;
    }
}

bool CorrelationEngine::EvaluateSimpleCondition(const SimpleCondition& cond, const json& event) {
    try {
        json alert_value = event;
        std::string key_path = cond.key;
        size_t pos = 0;
        while ((pos = key_path.find('.')) != std::string::npos) {
            std::string part = key_path.substr(0, pos);
            if (!alert_value.contains(part)) return false;
            alert_value = alert_value.at(part);
            key_path.erase(0, pos + 1);
        }
        if (!alert_value.contains(key_path)) return false;
        alert_value = alert_value.at(key_path);

        if (std::holds_alternative<std::string>(cond.value)) {
            if (!alert_value.is_string()) return false;
            const std::string& rule_val = std::get<std::string>(cond.value);
            const std::string& alert_val = alert_value.get<std::string>();
            if (cond.op == "==") return alert_val == rule_val;
            if (cond.op == "!=") return alert_val != rule_val;
        } else if (std::holds_alternative<double>(cond.value)) {
            if (!alert_value.is_number()) return false;
            double rule_val = std::get<double>(cond.value);
            double alert_val = alert_value.get<double>();
            if (cond.op == "==") return alert_val == rule_val;
            if (cond.op == "!=") return alert_val != rule_val;
            if (cond.op == ">")  return alert_val > rule_val;
            if (cond.op == "<")  return alert_val < rule_val;
            if (cond.op == ">=") return alert_val >= rule_val;
            if (cond.op == "<=") return alert_val <= rule_val;
        }
    } catch (const json::exception&) {
        return false;
    }
    return false;
}

void CorrelationEngine::EvaluateSequenceRules(const std::string& matched_rule_name, const json& event, std::ofstream& findings_out) {
    if (!event.contains("src_ip")) return;
    std::string src_ip = event["src_ip"];
    auto now = std::chrono::system_clock::now();

    state_by_ip_[src_ip].push_back({matched_rule_name, now});

    for (const auto& rule : rules_) {
        if (!std::holds_alternative<SequenceCondition>(rule.GetCondition())) continue;

        const auto& seq = std::get<SequenceCondition>(rule.GetCondition());
        const auto& required_rules = seq.rule_names;
        auto& recent_events = state_by_ip_[src_ip];

        if (recent_events.size() < required_rules.size()) continue;

        bool sequence_matched = true;
        size_t event_offset = recent_events.size() - required_rules.size();
        for (size_t i = 0; i < required_rules.size(); ++i) {
            if (recent_events[event_offset + i].rule_name != required_rules[i]) {
                sequence_matched = false;
                break;
            }
        }

        if (sequence_matched) {
            auto time_diff = now - recent_events[event_offset].timestamp;
            auto seconds_diff = std::chrono::duration_cast<std::chrono::seconds>(time_diff).count();

            if (seconds_diff <= seq.time_window_seconds) {
                json finding;
                finding["timestamp"] = event["timestamp"];
                finding["rule_name"] = rule.GetName();
                finding["original_event"] = event;
                finding["details"] = "Matched event sequence: " + required_rules[0] + " -> " + required_rules[1];
                finding["correlation_id"] = uuid_v4();
                findings_out << finding.dump() << std::endl;
                std::cout << "[MATCH] Sequence Rule '" << rule.GetName() << "' matched for IP " << src_ip << std::endl;

                recent_events.clear();
            }
        }
    }
}

void CorrelationEngine::CleanupOldEvents() {
    static auto last_cleanup = std::chrono::system_clock::now();
    auto now = std::chrono::system_clock::now();
    if (std::chrono::duration_cast<std::chrono::seconds>(now - last_cleanup).count() < 60) {
        return;
    }

    int max_window = 0;
    for (const auto& rule : rules_) {
        if (std::holds_alternative<SequenceCondition>(rule.GetCondition())) {
            const auto& seq = std::get<SequenceCondition>(rule.GetCondition());
            if (seq.time_window_seconds > max_window) {
                max_window = seq.time_window_seconds;
            }
        }
    }

    for (auto& pair : state_by_ip_) {
        auto& events = pair.second;
        events.erase(std::remove_if(events.begin(), events.end(),
            [now, max_window](const RecentEvent& event) {
                return std::chrono::duration_cast<std::chrono::seconds>(now - event.timestamp).count() > max_window;
            }), events.end());
    }
    last_cleanup = now;
}

void CorrelationEngine::ProcessEvent(const std::string& line, std::ofstream& findings_out) {
    try {
        json event = json::parse(line);
        if (event.value("event_type", "") != "alert") {
            return;
        }

        for (const auto& rule : rules_) {
            if (std::holds_alternative<SimpleCondition>(rule.GetCondition())) {
                const auto& cond = std::get<SimpleCondition>(rule.GetCondition());
                if (EvaluateSimpleCondition(cond, event)) {
                    json finding;
                    finding["timestamp"] = event["timestamp"];
                    finding["rule_name"] = rule.GetName();
                    finding["original_event"] = event;
                    finding["correlation_id"] = uuid_v4();
                    findings_out << finding.dump() << std::endl;
                    std::cout << "[MATCH] Simple Rule '" << rule.GetName() << "' matched." << std::endl;

                    EvaluateSequenceRules(rule.GetName(), event, findings_out);
                }
            }
        }
        CleanupOldEvents();
    } catch (const json::parse_error&) {
        // ignore invalid JSON lines
    }
}

void MonitorLogFile(const std::string& log_path, CorrelationEngine& engine, std::ofstream& findings_out) {
    std::ifstream log_stream(log_path);
    if (!log_stream.is_open()) {
        std::cerr << "[ERROR] Cannot open log file: " << log_path << ". Retrying..." << std::endl;
        return;
    }

    log_stream.seekg(0, std::ios::end);

    while (true) {
        std::string line;
        while (std::getline(log_stream, line)) {
            engine.ProcessEvent(line, findings_out);
        }

        if (log_stream.eof()) {
            log_stream.clear();
        }

        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <rules.yaml> <suricata_log_dir> <output_dir>" << std::endl;
        return 1;
    }

    std::string rules_path = argv[1];
    std::string suricata_log_path = std::string(argv[2]) + "/eve.json";
    std::string output_path = std::string(argv[3]) + "/findings.json";

    CorrelationEngine engine;
    try {
        engine.LoadRules(rules_path);
    } catch (...) {
        return 1;
    }

    std::ofstream findings_out(output_path, std::ios_base::app);
    if (!findings_out.is_open()) {
        std::cerr << "[ERROR] Failed to open output file: " << output_path << std::endl;
        return 1;
    }

    std::cout << "[INFO] Starting persistent monitoring of " << suricata_log_path << std::endl;

    while (true) {
        MonitorLogFile(suricata_log_path, engine, findings_out);
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }

    return 0;
}
