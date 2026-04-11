#include "handlers/symbol_handler.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"
#include "_scriptapi_symbol.h"
#include "bridgelist.h"

#include <algorithm>
#include <cctype>

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

    BridgeList<Script::Symbol::SymbolInfo> symbols;
    if (!Script::Symbol::GetList(&symbols))
        return {{"pattern", pattern}, {"module", module}, {"results", nlohmann::json::array()}, {"count", 0}};

    // Case-insensitive substring match on name, optional module filter
    std::string pattern_lower = pattern;
    std::transform(pattern_lower.begin(), pattern_lower.end(), pattern_lower.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    std::string module_lower = module;
    std::transform(module_lower.begin(), module_lower.end(), module_lower.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    auto results = nlohmann::json::array();
    constexpr int MAX_RESULTS = 200;
    for (int i = 0; i < symbols.Count() && static_cast<int>(results.size()) < MAX_RESULTS; ++i) {
        const auto& sym = symbols[i];
        if (!module_lower.empty()) {
            std::string sym_mod_lower = sym.mod;
            std::transform(sym_mod_lower.begin(), sym_mod_lower.end(), sym_mod_lower.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            if (sym_mod_lower.find(module_lower) == std::string::npos) continue;
        }
        std::string name_lower = sym.name;
        std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (name_lower.find(pattern_lower) != std::string::npos) {
            results.push_back({
                {"name", sym.name},
                {"module", sym.mod},
                {"rva", format_utils::format_address(sym.rva)},
                {"type", sym.type == Script::Symbol::Function ? "function" : sym.type == Script::Symbol::Import ? "import" : "export"}
            });
        }
    }
    return {{"pattern", pattern}, {"module", module}, {"results", results}, {"count", results.size()}};
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
