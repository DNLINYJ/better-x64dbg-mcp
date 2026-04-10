#include "handlers/thread_handler.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers::threads {

nlohmann::json list() {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto result = bridge.get_thread_list();
    if (!result.has_value()) throw std::runtime_error(result.error());
    return result.value();
}

nlohmann::json current() {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto result = bridge.get_thread_list();
    if (!result.has_value()) throw std::runtime_error(result.error());
    auto current_idx = result.value()["current_thread"].get<int>();
    for (const auto& t : result.value()["threads"]) {
        if (t["number"].get<int>() == current_idx) return t;
    }
    if (!result.value()["threads"].empty()) return result.value()["threads"][0];
    throw std::runtime_error("No current thread");
}

nlohmann::json get_by_id(uint32_t tid) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto result = bridge.get_thread_list();
    if (!result.has_value()) throw std::runtime_error(result.error());
    for (const auto& t : result.value()["threads"]) {
        if (t["id"].get<DWORD>() == tid) return t;
    }
    throw std::runtime_error("Thread not found: " + std::to_string(tid));
}

nlohmann::json switch_thread(uint32_t tid) {
    auto& bridge = get_bridge();
    if (!bridge.require_paused()) throw std::runtime_error("Debugger must be paused");
    bridge.exec_command("switchthread " + std::to_string(tid));
    return {{"switched_to", tid}, {"message", "Switched to thread " + std::to_string(tid)}};
}

nlohmann::json suspend(uint32_t tid) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    bridge.exec_command("suspendthread " + std::to_string(tid));
    return {{"id", tid}, {"suspended", true}};
}

nlohmann::json resume(uint32_t tid) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    bridge.exec_command("resumethread " + std::to_string(tid));
    return {{"id", tid}, {"resumed", true}};
}

nlohmann::json count() {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto result = bridge.get_thread_list();
    if (!result.has_value()) throw std::runtime_error(result.error());
    return {{"count", result.value()["count"]}};
}

nlohmann::json teb(uint32_t tid) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto t = DbgGetTebAddress(tid);
    return {{"tid", tid}, {"teb", format_utils::format_address(t)}, {"found", t != 0}};
}

nlohmann::json name(uint32_t tid) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    char n[MAX_THREAD_NAME_SIZE] = {};
    auto found = DbgFunctions()->ThreadGetName(tid, n);
    return {{"tid", tid}, {"name", std::string(n)}, {"found", found}};
}

} // namespace handlers::threads
