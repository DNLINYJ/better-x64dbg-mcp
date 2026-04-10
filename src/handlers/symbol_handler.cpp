#include "handlers/symbol_handler.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

namespace handlers::symbols {

nlohmann::json resolve(const std::string& name) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    if (!bridge.is_valid_expression(name)) throw std::runtime_error("Cannot resolve: " + name);
    auto address = bridge.eval_expression(name);
    if (address == 0) throw std::runtime_error("Symbol not found: " + name);
    return {{"name", name}, {"address", format_utils::format_address(address)}};
}

nlohmann::json at(const std::string& address_str) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto address = bridge.eval_expression(address_str);
    return {{"address", format_utils::format_address(address)}, {"label", bridge.get_label_at(address)}, {"module", bridge.get_module_at(address)}};
}

nlohmann::json search(const std::string& pattern, const std::string& module) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto search_expr = module.empty() ? pattern : module + "." + pattern;
    bridge.exec_command("symfind " + search_expr);
    return {{"pattern", pattern}, {"module", module}, {"message", "Symbol search initiated. Check x64dbg symbol view for results."}};
}

nlohmann::json list_module(const std::string& module) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto base = bridge.get_module_base(module);
    if (base == 0) throw std::runtime_error("Module not found: " + module);
    bridge.exec_command("symload " + module);
    return {{"module", module}, {"base", format_utils::format_address(base)}, {"message", "Symbols loaded."}};
}

} // namespace handlers::symbols
