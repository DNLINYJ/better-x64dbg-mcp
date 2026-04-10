#include "handlers/exceptions_handler.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"
#include "bridgemain.h"
#include "_dbgfunctions.h"
#include "bridgelist.h"

namespace handlers::exceptions {

nlohmann::json set_bp(const std::string& code, const std::string& chance) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto cmd = "SetExceptionBPX " + code;
    if (chance == "second") cmd += ", 1";
    return {{"success", bridge.exec_command(cmd)}, {"code", code}, {"chance", chance}};
}

nlohmann::json delete_bp(const std::string& code) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    return {{"success", bridge.exec_command("DeleteExceptionBPX " + code)}, {"code", code}};
}

nlohmann::json list_bps() {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto result = bridge.get_breakpoint_list(bp_exception);
    if (!result.has_value()) throw std::runtime_error(result.error());
    return {{"breakpoints", result.value()}, {"count", result.value().size()}};
}

nlohmann::json list_codes() {
    BridgeList<CONSTANTINFO> constants;
    DbgFunctions()->EnumExceptions(&constants);
    auto result = nlohmann::json::array();
    for (int i = 0; i < constants.Count(); ++i)
        result.push_back({{"name", constants[i].name}, {"value", format_utils::format_address(constants[i].value)}});
    return {{"exceptions", result}, {"count", result.size()}};
}

nlohmann::json skip() {
    auto& bridge = get_bridge();
    if (!bridge.require_paused()) throw std::runtime_error("Debugger must be paused");
    return {{"success", bridge.exec_command("skip")}, {"message", "Exception skipped"}};
}

} // namespace handlers::exceptions
