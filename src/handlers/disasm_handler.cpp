#include "handlers/disasm_handler.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

namespace handlers::disasm {

nlohmann::json at(const std::string& address_str, int count) {
    auto& bridge = get_bridge();
    if (!bridge.require_paused()) throw std::runtime_error("Debugger must be paused");
    auto address = bridge.eval_expression(address_str);
    if (count < 1) count = 1;
    if (count > 1000) count = 1000;
    auto result = bridge.disassemble_at(address, count);
    if (!result.has_value()) throw std::runtime_error(result.error());
    return {{"address", format_utils::format_address(address)}, {"count", result->size()}, {"instructions", result.value()}};
}

nlohmann::json function(const std::string& address_str, int max_instructions) {
    auto& bridge = get_bridge();
    if (!bridge.require_paused()) throw std::runtime_error("Debugger must be paused");
    auto address = bridge.eval_expression(address_str);
    if (max_instructions < 1) max_instructions = 1;
    if (max_instructions > 5000) max_instructions = 5000;
    auto bounds = bridge.get_function_bounds(address);
    if (!bounds.has_value()) {
        auto result = bridge.disassemble_at(address, max_instructions);
        if (!result.has_value()) throw std::runtime_error(result.error());
        return {{"address", format_utils::format_address(address)},
                {"note", "No function boundary found. Showing " + std::to_string(max_instructions) + " instructions."},
                {"fallback_count", max_instructions}, {"instructions", result.value()}};
    }
    auto start = format_utils::parse_address(bounds.value()["start"].get<std::string>());
    auto end_addr = format_utils::parse_address(bounds.value()["end"].get<std::string>());
    auto estimated_count = static_cast<int>((end_addr - start) / 2) + 1;
    if (estimated_count > 5000) estimated_count = 5000;
    auto result = bridge.disassemble_at(start, estimated_count);
    if (!result.has_value()) throw std::runtime_error(result.error());
    auto filtered = nlohmann::json::array();
    for (const auto& instr : result.value()) {
        auto instr_addr = format_utils::parse_address(instr["address"].get<std::string>());
        if (instr_addr > end_addr) break;
        filtered.push_back(instr);
    }
    return {{"function_start", bounds.value()["start"]}, {"function_end", bounds.value()["end"]},
            {"function_size", bounds.value()["size"]}, {"count", filtered.size()}, {"instructions", filtered}};
}

nlohmann::json basic(const std::string& address_str) {
    auto& bridge = get_bridge();
    if (!bridge.require_paused()) throw std::runtime_error("Debugger must be paused");
    auto address = bridge.eval_expression(address_str);
    auto result = bridge.get_basic_info(address);
    if (!result.has_value()) throw std::runtime_error(result.error());
    return result.value();
}

nlohmann::json assemble(const std::string& address, const std::string& instruction) {
    auto& bridge = get_bridge();
    if (!bridge.require_paused()) throw std::runtime_error("Debugger must be paused");
    if (!bridge.exec_command("asm " + address + ", \"" + instruction + "\""))
        throw std::runtime_error("Failed to assemble instruction");
    return {{"address", address}, {"instruction", instruction}};
}

} // namespace handlers::disasm
