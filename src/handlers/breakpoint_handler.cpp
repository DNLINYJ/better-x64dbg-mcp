#include "handlers/breakpoint_handler.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

namespace handlers::breakpoints {

static void apply_bp_config(c_bridge_executor& bridge, const std::string& addr_str, const nlohmann::json& body) {
    if (body.contains("break_condition"))
        bridge.exec_command("SetBreakpointCondition " + addr_str + ", \"" + body["break_condition"].get<std::string>() + "\"");
    if (body.contains("command_condition"))
        bridge.exec_command("SetBreakpointCommandCondition " + addr_str + ", \"" + body["command_condition"].get<std::string>() + "\"");
    if (body.contains("command_text"))
        bridge.exec_command("SetBreakpointCommand " + addr_str + ", \"" + body["command_text"].get<std::string>() + "\"");
    if (body.contains("log_text"))
        bridge.exec_command("SetBreakpointLog " + addr_str + ", \"" + body["log_text"].get<std::string>() + "\"");
    if (body.contains("log_condition"))
        bridge.exec_command("SetBreakpointLogCondition " + addr_str + ", \"" + body["log_condition"].get<std::string>() + "\"");
    if (body.contains("silent"))
        bridge.exec_command("SetBreakpointSilent " + addr_str + ", " + (body["silent"].get<bool>() ? "1" : "0"));
    if (body.contains("fast_resume"))
        bridge.exec_command("SetBreakpointFastResume " + addr_str + ", " + (body["fast_resume"].get<bool>() ? "1" : "0"));
    if (body.contains("name"))
        bridge.exec_command("SetBreakpointName " + addr_str + ", \"" + body["name"].get<std::string>() + "\"");
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
    bridge.exec_command(singleshot ? "bp " + address + ", ss" : "bp " + address);
    return {{"address", address}, {"type", "software"}, {"singleshot", singleshot}};
}

nlohmann::json set_hardware(const std::string& address, const std::string& type, const std::string& size) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    bridge.exec_command("bphws " + address + ", " + type + ", " + size);
    return {{"address", address}, {"type", "hardware"}, {"hw_type", type}, {"hw_size", size}};
}

nlohmann::json set_memory(const std::string& address, const std::string& type) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    bridge.exec_command("bpm " + address + ", " + type);
    return {{"address", address}, {"type", "memory"}, {"mem_type", type}};
}

nlohmann::json delete_bp(const std::string& address, const std::string& type) {
    auto& bridge = get_bridge();
    if (type == "hardware") bridge.exec_command("bphwc " + address);
    else if (type == "memory") bridge.exec_command("bpmc " + address);
    else bridge.exec_command("bc " + address);
    return {{"address", address}, {"deleted", true}};
}

nlohmann::json enable(const std::string& address) {
    get_bridge().exec_command("bpe " + address);
    return {{"address", address}, {"enabled", true}};
}

nlohmann::json disable(const std::string& address) {
    get_bridge().exec_command("bpd " + address);
    return {{"address", address}, {"enabled", false}};
}

nlohmann::json toggle(const std::string& address) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    bridge.exec_command("bptoggle " + address);
    return {{"address", address}, {"toggled", true}};
}

nlohmann::json set_condition(const std::string& address, const std::string& condition) {
    get_bridge().exec_command("SetBreakpointCondition " + address + ", \"" + condition + "\"");
    return {{"address", address}, {"condition", condition}};
}

nlohmann::json set_log(const std::string& address, const std::string& text) {
    get_bridge().exec_command("SetBreakpointLog " + address + ", \"" + text + "\"");
    return {{"address", address}, {"log", text}};
}

nlohmann::json reset_hit_count(const std::string& address) {
    get_bridge().exec_command("ResetBreakpointHitCount " + address);
    return {{"address", address}, {"hit_count", 0}};
}

nlohmann::json configure(const nlohmann::json& args) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto address = args["address"].get<std::string>();
    auto bp_type = args.value("bp_type", "software");
    if (bp_type == "hardware") {
        bridge.exec_command("bphws " + address + ", " + args.value("hw_type", "x") + ", " + args.value("hw_size", "1"));
    } else if (bp_type == "memory") {
        bridge.exec_command("bpm " + address + ", " + args.value("mem_type", "a"));
    } else {
        bridge.exec_command(args.value("singleshot", false) ? "bp " + address + ", ss" : "bp " + address);
    }
    apply_bp_config(bridge, address, args);
    return {{"address", address}, {"bp_type", bp_type}, {"configured", true}};
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
        if (bp_type == "hardware")
            bridge.exec_command("bphws " + address + ", " + entry.value("hw_type", "x") + ", " + entry.value("hw_size", "1"));
        else if (bp_type == "memory")
            bridge.exec_command("bpm " + address + ", " + entry.value("mem_type", "a"));
        else
            bridge.exec_command(entry.value("singleshot", false) ? "bp " + address + ", ss" : "bp " + address);
        apply_bp_config(bridge, address, entry);
        results.push_back({{"address", address}, {"success", true}});
        ++succeeded;
    }
    return {{"results", results}, {"total", breakpoints_array.size()}, {"succeeded", succeeded}, {"failed", failed}};
}

} // namespace handlers::breakpoints
