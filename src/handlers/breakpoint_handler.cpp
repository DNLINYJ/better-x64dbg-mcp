#include "handlers/breakpoint_handler.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

namespace handlers::breakpoints {

static std::vector<std::string> apply_bp_config(c_bridge_executor& bridge, const std::string& addr_str, const nlohmann::json& body) {
    std::vector<std::string> warnings;
    auto try_cmd = [&](const char* desc, const std::string& cmd) {
        if (!bridge.exec_command(cmd)) warnings.push_back(std::string(desc) + " failed");
    };
    if (body.contains("break_condition"))
        try_cmd("break_condition", "SetBreakpointCondition " + addr_str + ", \"" + body["break_condition"].get<std::string>() + "\"");
    if (body.contains("command_condition"))
        try_cmd("command_condition", "SetBreakpointCommandCondition " + addr_str + ", \"" + body["command_condition"].get<std::string>() + "\"");
    if (body.contains("command_text"))
        try_cmd("command_text", "SetBreakpointCommand " + addr_str + ", \"" + body["command_text"].get<std::string>() + "\"");
    if (body.contains("log_text"))
        try_cmd("log_text", "SetBreakpointLog " + addr_str + ", \"" + body["log_text"].get<std::string>() + "\"");
    if (body.contains("log_condition"))
        try_cmd("log_condition", "SetBreakpointLogCondition " + addr_str + ", \"" + body["log_condition"].get<std::string>() + "\"");
    if (body.contains("silent"))
        try_cmd("silent", "SetBreakpointSilent " + addr_str + ", " + (body["silent"].get<bool>() ? "1" : "0"));
    if (body.contains("fast_resume"))
        try_cmd("fast_resume", "SetBreakpointFastResume " + addr_str + ", " + (body["fast_resume"].get<bool>() ? "1" : "0"));
    if (body.contains("name"))
        try_cmd("name", "SetBreakpointName " + addr_str + ", \"" + body["name"].get<std::string>() + "\"");
    return warnings;
}

nlohmann::json list() {
    auto& bridge = get_bridge();
    nlohmann::json all_bps = nlohmann::json::array();
    auto add_bps = [&](BPXTYPE type, const char* type_name) {
        auto bps = bridge.get_breakpoint_list(type);
        if (!bps.has_value()) return;
        for (auto& bp : bps.value()) {
            if (bp["name"].get<std::string>().empty()) {
                auto addr = bridge.eval_expression(bp["address"].get<std::string>());
                bp["label"] = bridge.get_label_at(addr);
            } else {
                bp["label"] = bp["name"].get<std::string>();
            }
            bp["type_name"] = type_name;
            all_bps.push_back(bp);
        }
    };
    add_bps(bp_normal, "software");
    add_bps(bp_hardware, "hardware");
    add_bps(bp_memory, "memory");
    return {{"breakpoints", all_bps}, {"count", all_bps.size()}};
}

nlohmann::json get(const std::string& address_str) {
    auto& bridge = get_bridge();
    auto address = bridge.eval_expression(address_str);
    auto addr_hex = format_utils::format_address(address);
    for (auto type : {bp_normal, bp_hardware, bp_memory}) {
        auto bps = bridge.get_breakpoint_list(type);
        if (!bps.has_value()) continue;
        for (auto& bp : bps.value()) {
            if (bp["address"] == addr_hex) {
                bp["label"] = bp["name"].get<std::string>().empty() ? bridge.get_label_at(address) : bp["name"].get<std::string>();
                return bp;
            }
        }
    }
    throw std::runtime_error("No breakpoint at " + address_str);
}

nlohmann::json set_software(const std::string& address, bool singleshot) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    if (!bridge.exec_command(singleshot ? "bp " + address + ", ss" : "bp " + address))
        throw std::runtime_error("Failed to set software breakpoint at " + address);
    return {{"address", address}, {"type", "software"}, {"singleshot", singleshot}};
}

nlohmann::json set_hardware(const std::string& address, const std::string& type, const std::string& size) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    if (!bridge.exec_command("bphws " + address + ", " + type + ", " + size))
        throw std::runtime_error("Failed to set hardware breakpoint at " + address);
    return {{"address", address}, {"type", "hardware"}, {"hw_type", type}, {"hw_size", size}};
}

nlohmann::json set_memory(const std::string& address, const std::string& type) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    if (!bridge.exec_command("bpm " + address + ", " + type))
        throw std::runtime_error("Failed to set memory breakpoint at " + address);
    return {{"address", address}, {"type", "memory"}, {"mem_type", type}};
}

nlohmann::json delete_bp(const std::string& address, const std::string& type) {
    auto& bridge = get_bridge();
    bool ok;
    if (type == "hardware") ok = bridge.exec_command("bphwc " + address);
    else if (type == "memory") ok = bridge.exec_command("bpmc " + address);
    else ok = bridge.exec_command("bc " + address);
    if (!ok) throw std::runtime_error("Failed to delete breakpoint at " + address);
    return {{"address", address}, {"deleted", true}};
}

nlohmann::json enable(const std::string& address) {
    if (!get_bridge().exec_command("bpe " + address))
        throw std::runtime_error("Failed to enable breakpoint at " + address);
    return {{"address", address}, {"enabled", true}};
}

nlohmann::json disable(const std::string& address) {
    if (!get_bridge().exec_command("bpd " + address))
        throw std::runtime_error("Failed to disable breakpoint at " + address);
    return {{"address", address}, {"enabled", false}};
}

nlohmann::json toggle(const std::string& address) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    if (!bridge.exec_command("bptoggle " + address))
        throw std::runtime_error("Failed to toggle breakpoint at " + address);
    return {{"address", address}, {"toggled", true}};
}

nlohmann::json set_condition(const std::string& address, const std::string& condition) {
    if (!get_bridge().exec_command("SetBreakpointCondition " + address + ", \"" + condition + "\""))
        throw std::runtime_error("Failed to set breakpoint condition at " + address);
    return {{"address", address}, {"condition", condition}};
}

nlohmann::json set_log(const std::string& address, const std::string& text) {
    if (!get_bridge().exec_command("SetBreakpointLog " + address + ", \"" + text + "\""))
        throw std::runtime_error("Failed to set breakpoint log at " + address);
    return {{"address", address}, {"log", text}};
}

nlohmann::json reset_hit_count(const std::string& address) {
    if (!get_bridge().exec_command("ResetBreakpointHitCount " + address))
        throw std::runtime_error("Failed to reset hit count at " + address);
    return {{"address", address}, {"hit_count", 0}};
}

nlohmann::json configure(const nlohmann::json& args) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto address = args["address"].get<std::string>();
    auto bp_type = args.value("bp_type", "software");
    bool setup_ok;
    if (bp_type == "hardware") {
        setup_ok = bridge.exec_command("bphws " + address + ", " + args.value("hw_type", "x") + ", " + args.value("hw_size", "1"));
    } else if (bp_type == "memory") {
        setup_ok = bridge.exec_command("bpm " + address + ", " + args.value("mem_type", "a"));
    } else {
        setup_ok = bridge.exec_command(args.value("singleshot", false) ? "bp " + address + ", ss" : "bp " + address);
    }
    if (!setup_ok) throw std::runtime_error("Failed to set " + bp_type + " breakpoint at " + address);
    auto warnings = apply_bp_config(bridge, address, args);
    nlohmann::json result = {{"address", address}, {"bp_type", bp_type}, {"configured", true}};
    if (!warnings.empty()) result["warnings"] = warnings;
    return result;
}

nlohmann::json configure_batch(const nlohmann::json& breakpoints_array) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto results = nlohmann::json::array();
    int succeeded = 0, failed = 0;
    for (const auto& entry : breakpoints_array) {
        if (!entry.contains("address")) {
            results.push_back({{"error", "missing address"}, {"success", false}});
            ++failed;
            continue;
        }
        auto address = entry["address"].get<std::string>();
        auto bp_type = entry.value("bp_type", "software");
        bool setup_ok;
        if (bp_type == "hardware")
            setup_ok = bridge.exec_command("bphws " + address + ", " + entry.value("hw_type", "x") + ", " + entry.value("hw_size", "1"));
        else if (bp_type == "memory")
            setup_ok = bridge.exec_command("bpm " + address + ", " + entry.value("mem_type", "a"));
        else
            setup_ok = bridge.exec_command(entry.value("singleshot", false) ? "bp " + address + ", ss" : "bp " + address);
        if (!setup_ok) {
            results.push_back({{"address", address}, {"error", "Failed to set " + bp_type + " breakpoint"}, {"success", false}});
            ++failed;
            continue;
        }
        auto warnings = apply_bp_config(bridge, address, entry);
        nlohmann::json item = {{"address", address}, {"success", true}};
        if (!warnings.empty()) item["warnings"] = warnings;
        results.push_back(item);
        ++succeeded;
    }
    return {{"results", results}, {"total", breakpoints_array.size()}, {"succeeded", succeeded}, {"failed", failed}};
}

} // namespace handlers::breakpoints
