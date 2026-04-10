#include "handlers/debug_handler.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <thread>
#include <chrono>

namespace handlers::debug {

nlohmann::json state() {
    auto& bridge = get_bridge();
    auto s = bridge.get_state_string();
    nlohmann::json data = {{"state", s}};
    if (bridge.is_debugging() && !bridge.is_running()) {
        auto cip = bridge.eval_expression("cip");
        data["cip"] = format_utils::format_address(cip);
        auto mod = bridge.get_module_at(cip);
        if (!mod.empty()) data["module"] = mod;
        auto label = bridge.get_label_at(cip);
        if (!label.empty()) data["label"] = label;
    }
    return data;
}

nlohmann::json run() {
    auto& bridge = get_bridge();
    if (!bridge.require_paused()) throw std::runtime_error("Debugger must be paused");
    bridge.exec_command("run");
    return {{"message", "Execution resumed"}};
}

nlohmann::json pause() {
    auto& bridge = get_bridge();
    if (!bridge.is_debugging()) throw std::runtime_error("No active debug session");
    if (!bridge.is_running()) return {{"message", "Already paused"}};
    bridge.exec_command("pause");
    return {{"message", "Pause requested"}};
}

nlohmann::json force_pause() {
    auto& bridge = get_bridge();
    if (!bridge.is_debugging()) throw std::runtime_error("No active debug session");
    if (!bridge.is_running()) return {{"message", "Already paused"}};
    std::vector<std::string> fast_resume_addrs;
    for (auto type : {bp_normal, bp_hardware, bp_memory}) {
        auto bps = bridge.get_breakpoint_list(type);
        if (!bps.has_value()) continue;
        for (const auto& bp : bps.value()) {
            if (bp.value("fast_resume", false)) {
                auto addr_str = bp["address"].get<std::string>();
                fast_resume_addrs.push_back(addr_str);
                bridge.exec_command("SetBreakpointFastResume " + addr_str + ", 0");
            }
        }
    }
    bridge.exec_command("pause");
    bool paused = false;
    for (int i = 0; i < 300 && !paused; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        paused = !bridge.is_running();
    }
    for (const auto& addr_str : fast_resume_addrs) {
        bridge.exec_command("SetBreakpointFastResume " + addr_str + ", 1");
    }
    if (!paused) throw std::runtime_error("Force pause timed out after 3s");
    return {{"message", "Debuggee forcefully paused"}, {"fast_resume_count", fast_resume_addrs.size()}};
}

nlohmann::json step_into() {
    auto& bridge = get_bridge();
    if (!bridge.require_paused()) throw std::runtime_error("Debugger must be paused");
    if (!bridge.exec_command_and_wait("StepInto")) throw std::runtime_error("Step into timed out");
    auto cip = bridge.eval_expression("cip");
    return {{"cip", format_utils::format_address(cip)}, {"message", "Stepped into"}};
}

nlohmann::json step_over() {
    auto& bridge = get_bridge();
    if (!bridge.require_paused()) throw std::runtime_error("Debugger must be paused");
    if (!bridge.exec_command_and_wait("StepOver")) throw std::runtime_error("Step over timed out");
    auto cip = bridge.eval_expression("cip");
    return {{"cip", format_utils::format_address(cip)}, {"message", "Stepped over"}};
}

nlohmann::json step_out() {
    auto& bridge = get_bridge();
    if (!bridge.require_paused()) throw std::runtime_error("Debugger must be paused");
    if (!bridge.exec_command_and_wait("StepOut", 30000)) throw std::runtime_error("Step out timed out");
    auto cip = bridge.eval_expression("cip");
    return {{"cip", format_utils::format_address(cip)}, {"message", "Stepped out"}};
}

nlohmann::json stop_debug() {
    auto& bridge = get_bridge();
    if (!bridge.is_debugging()) return {{"message", "Not debugging"}};
    bridge.exec_command("stop");
    return {{"message", "Debug session stopped"}};
}

nlohmann::json restart_debug() {
    auto& bridge = get_bridge();
    if (!bridge.is_debugging()) throw std::runtime_error("No active debug session");
    bridge.exec_command("restart");
    return {{"message", "Restart initiated"}};
}

nlohmann::json run_to_address(const std::string& address) {
    auto& bridge = get_bridge();
    if (!bridge.require_paused()) throw std::runtime_error("Debugger must be paused");
    bridge.exec_command("bp " + address + ", ss");
    bridge.exec_command("run");
    return {{"message", "Running to " + address}, {"target", address}};
}

} // namespace handlers::debug
