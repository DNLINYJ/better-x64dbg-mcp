#include "handlers/command_handler.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"
#include "_dbgfunctions.h"

namespace handlers::command {

nlohmann::json exec(const std::string& command) {
    return {{"command", command}, {"success", get_bridge().exec_command(command)}};
}

nlohmann::json eval(const std::string& expression) {
    auto& bridge = get_bridge();
    if (!bridge.is_valid_expression(expression)) throw std::runtime_error("Invalid expression: " + expression);
    auto result = bridge.eval_expression(expression);
    return {{"expression", expression}, {"value", format_utils::format_address(result)}, {"decimal", result}};
}

nlohmann::json format_str(const std::string& fmt) {
    auto& bridge = get_bridge();
    if (!bridge.require_paused()) throw std::runtime_error("Debugger must be paused");
    char result[1024] = {};
    auto success = DbgFunctions()->StringFormatInline(fmt.c_str(), sizeof(result), result);
    return {{"success", success}, {"format", fmt}, {"result", std::string(result)}};
}

nlohmann::json events() {
    return {{"event_count", DbgFunctions()->GetDbgEvents()}};
}

nlohmann::json set_init_script(const std::string& file) {
    DbgFunctions()->DbgSetDebuggeeInitScript(file.c_str());
    return {{"file", file}, {"message", "Init script set"}};
}

nlohmann::json get_init_script() {
    auto* script = DbgFunctions()->DbgGetDebuggeeInitScript();
    return {{"file", script ? std::string(script) : ""}};
}

nlohmann::json hash() {
    return {{"hash", format_utils::format_address(DbgFunctions()->DbGetHash())}};
}

nlohmann::json script(const std::vector<std::string>& commands) {
    auto& bridge = get_bridge();
    auto results = nlohmann::json::array();
    int succeeded = 0, failed = 0;
    for (const auto& cmd : commands) {
        auto success = bridge.exec_command(cmd);
        results.push_back({{"command", cmd}, {"success", success}});
        if (success) ++succeeded; else ++failed;
    }
    return {{"results", results}, {"total", commands.size()}, {"succeeded", succeeded}, {"failed", failed}};
}

} // namespace handlers::command
