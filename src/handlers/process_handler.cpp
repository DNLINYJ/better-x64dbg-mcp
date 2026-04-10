#include "handlers/process_handler.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers::process {

nlohmann::json details() {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto pid = bridge.eval_expression("$pid");
    return {{"pid", pid}, {"peb_address", format_utils::format_address(DbgGetPebAddress(static_cast<DWORD>(pid)))},
        {"process_handle", format_utils::format_address(reinterpret_cast<duint>(DbgGetProcessHandle()))},
        {"entry_point", format_utils::format_address(bridge.eval_expression("mod.entry(0)"))},
        {"debugger_state", bridge.get_state_string()},
        {"is_elevated", DbgFunctions()->IsProcessElevated()}, {"dep_enabled", DbgFunctions()->IsDepEnabled()}};
}

nlohmann::json cmdline() {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    size_t size = 0; DbgFunctions()->GetCmdline(nullptr, &size);
    if (size == 0) return {{"cmdline", ""}};
    std::vector<char> buffer(size + 1, 0);
    DbgFunctions()->GetCmdline(buffer.data(), &size);
    return {{"cmdline", std::string(buffer.data())}};
}

nlohmann::json set_cmdline(const std::string& cl) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    return {{"success", DbgFunctions()->SetCmdline(cl.c_str())}, {"cmdline", cl}};
}

nlohmann::json elevated() {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    return {{"elevated", DbgFunctions()->IsProcessElevated()}};
}

nlohmann::json dbversion() {
    return {{"version", BridgeGetDbgVersion()}};
}

} // namespace handlers::process
