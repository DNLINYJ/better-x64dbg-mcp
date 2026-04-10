#include "handlers/module_handler.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"
#include "_dbgfunctions.h"
#include <unordered_map>

namespace handlers::modules {

nlohmann::json list() {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto memmap = bridge.get_memory_map();
    if (!memmap.has_value()) throw std::runtime_error(memmap.error());
    std::unordered_map<std::string, nlohmann::json> mods;
    for (const auto& page : memmap.value()) {
        auto base_str = page["base"].get<std::string>();
        auto b = format_utils::parse_address(base_str);
        auto mod_name = bridge.get_module_at(b);
        if (mod_name.empty()) continue;
        if (mods.find(mod_name) == mods.end()) {
            auto mod_base = bridge.get_module_base(mod_name);
            mods[mod_name] = {{"name", mod_name}, {"base", format_utils::format_address(mod_base)},
                {"size", bridge.eval_expression("mod.size(" + mod_name + ")")},
                {"entry", format_utils::format_address(bridge.eval_expression("mod.entry(" + mod_name + ")"))}};
        }
    }
    auto result = nlohmann::json::array();
    for (const auto& [n, info] : mods) result.push_back(info);
    return {{"modules", result}, {"count", result.size()}};
}

nlohmann::json get(const std::string& name) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto b = bridge.get_module_base(name);
    if (b == 0) throw std::runtime_error("Module not found: " + name);
    return {{"name", name}, {"base", format_utils::format_address(b)},
        {"size", bridge.eval_expression("mod.size(" + name + ")")},
        {"entry", format_utils::format_address(bridge.eval_expression("mod.entry(" + name + ")"))},
        {"party", static_cast<int>(bridge.eval_expression("mod.party(" + name + ")"))}};
}

nlohmann::json base(const std::string& name) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto b = bridge.get_module_base(name);
    if (b == 0) throw std::runtime_error("Module not found: " + name);
    return {{"name", name}, {"base", format_utils::format_address(b)}};
}

nlohmann::json section(const std::string& address_str) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto address = bridge.eval_expression(address_str);
    char sec[MAX_SECTION_SIZE * 5] = {};
    auto found = DbgFunctions()->SectionFromAddr(address, sec);
    return {{"address", format_utils::format_address(address)}, {"found", found}, {"section", std::string(sec)}};
}

nlohmann::json party(const std::string& base_str) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto b = bridge.eval_expression(base_str);
    auto p = DbgFunctions()->ModGetParty(b);
    std::string ps;
    switch (p) { case mod_user: ps = "user"; break; case mod_system: ps = "system"; break; default: ps = "unknown"; }
    return {{"base", format_utils::format_address(b)}, {"party", ps}, {"party_id", static_cast<int>(p)}};
}

} // namespace handlers::modules
