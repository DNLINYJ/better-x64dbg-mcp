#include "handlers/patch_handler.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers::patches {

nlohmann::json list() {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    size_t count = 0;
    DbgFunctions()->PatchEnum(nullptr, &count);
    if (count == 0) return {{"patches", nlohmann::json::array()}, {"count", 0}};
    std::vector<DBGPATCHINFO> patches(count);
    DbgFunctions()->PatchEnum(patches.data(), &count);
    auto result = nlohmann::json::array();
    for (size_t i = 0; i < count; ++i) {
        result.push_back({
            {"address", format_utils::format_address(patches[i].addr)},
            {"module", patches[i].mod},
            {"original_byte", format_utils::format_bytes_hex(&patches[i].oldbyte, 1)},
            {"patched_byte", format_utils::format_bytes_hex(&patches[i].newbyte, 1)}
        });
    }
    return {{"patches", result}, {"count", result.size()}};
}

nlohmann::json apply(const std::string& address_str, const std::string& hex_str) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto address = bridge.eval_expression(address_str);
    auto bytes = format_utils::parse_hex_bytes(hex_str);
    if (bytes.empty()) throw std::runtime_error("No valid bytes to patch");
    auto original = bridge.read_memory(address, bytes.size());
    auto result = bridge.write_memory(address, bytes);
    if (!result.has_value()) throw std::runtime_error(result.error());
    nlohmann::json data = {{"address", format_utils::format_address(address)}, {"bytes_patched", bytes.size()},
        {"new_bytes", format_utils::format_bytes_hex(bytes.data(), bytes.size())}};
    if (original.has_value())
        data["original_bytes"] = format_utils::format_bytes_hex(original->data(), original->size());
    return data;
}

nlohmann::json restore(const std::string& address) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto addr = bridge.eval_expression(address);
    if (!DbgFunctions()->PatchRestore(addr))
        throw std::runtime_error("Failed to restore patch at " + address);
    GuiUpdatePatches();
    return {{"address", format_utils::format_address(addr)}, {"restored", true}};
}

nlohmann::json export_module(const std::string& module_name, const std::string& path) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    std::string cmd;
    if (!module_name.empty()) {
        auto base = bridge.get_module_base(module_name);
        auto size = bridge.eval_expression("mod.size(" + module_name + ")");
        cmd = "savedata \"" + path + "\", " + format_utils::format_address(base) + ", " + format_utils::format_hex(size);
    } else {
        cmd = "savedata \"" + path + "\"";
    }
    bridge.exec_command(cmd);
    return {{"module", module_name}, {"path", path}, {"message", "Module export initiated"}};
}

} // namespace handlers::patches
