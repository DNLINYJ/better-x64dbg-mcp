#include "handlers/memory_handler.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"
#include "_dbgfunctions.h"

namespace handlers::memory {

nlohmann::json read(const std::string& address_str, size_t size) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto address = bridge.eval_expression(address_str);
    auto result = bridge.read_memory(address, size);
    if (!result.has_value()) throw std::runtime_error(result.error());
    const auto& bytes = result.value();
    std::string ascii;
    ascii.reserve(bytes.size());
    for (auto b : bytes) ascii += (b >= 0x20 && b < 0x7F) ? static_cast<char>(b) : '.';
    return {
        {"address", format_utils::format_address(address)},
        {"size", bytes.size()},
        {"hex", format_utils::format_bytes_hex(bytes.data(), bytes.size())},
        {"ascii", ascii}
    };
}

nlohmann::json write(const std::string& address_str, const std::string& hex_str, bool verify) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto address = bridge.eval_expression(address_str);
    auto bytes = format_utils::parse_hex_bytes(hex_str);
    if (bytes.empty()) throw std::runtime_error("No valid bytes to write");
    auto result = bridge.write_memory(address, bytes);
    if (!result.has_value()) throw std::runtime_error(result.error());
    nlohmann::json data = {{"address", format_utils::format_address(address)}, {"bytes_written", bytes.size()}};
    if (verify) {
        auto readback = bridge.read_memory(address, bytes.size());
        if (!readback.has_value()) {
            data["verified"] = false;
            data["verify_error"] = "Could not read back memory after write";
        } else if (readback.value() != bytes) {
            data["verified"] = false;
            data["verify_error"] = "Read-back mismatch";
        } else {
            data["verified"] = true;
        }
    }
    return data;
}

nlohmann::json is_valid(const std::string& address_str) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto address = bridge.eval_expression(address_str);
    return {{"address", format_utils::format_address(address)}, {"valid", bridge.is_valid_read_ptr(address)}};
}

nlohmann::json page_info(const std::string& address_str) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto address = bridge.eval_expression(address_str);
    duint region_size = 0;
    auto base = DbgMemFindBaseAddr(address, &region_size);
    if (base == 0) throw std::runtime_error("No memory region at " + address_str);
    return {
        {"address", format_utils::format_address(address)},
        {"base", format_utils::format_address(base)},
        {"region_size", region_size},
        {"module", bridge.get_module_at(address)}
    };
}

nlohmann::json allocate(const std::string& size) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    // Atomically exec + eval to prevent concurrent requests from racing on $result
    auto result = bridge.exec_command_and_eval("alloc " + size, "$result");
    if (result == 0) throw std::runtime_error("Memory allocation failed");
    return {{"address", format_utils::format_address(result)}, {"size", size}};
}

nlohmann::json free_mem(const std::string& address) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    bridge.exec_command("free " + address);
    return {{"message", "Memory freed at " + address}};
}

nlohmann::json protect(const std::string& address, const std::string& size, const std::string& protection) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto addr = bridge.eval_expression(address);
    auto len = bridge.eval_expression(size);
    // setpagerights operates on the page containing the address; align to page boundaries
    constexpr duint page_granularity = 0x1000;
    duint page_start = addr & ~(page_granularity - 1);
    duint page_end = (addr + (std::max)(len, static_cast<duint>(1)) + page_granularity - 1) & ~(page_granularity - 1);
    int pages_changed = 0;
    for (duint page = page_start; page < page_end; page += page_granularity) {
        if (!bridge.exec_command("setpagerights " + format_utils::format_address(page) + ", " + protection))
            throw std::runtime_error("Failed to set page rights at " + format_utils::format_address(page));
        ++pages_changed;
    }
    return {{"address", format_utils::format_address(addr)}, {"size", format_utils::format_hex(len)}, {"protection", protection}, {"pages_changed", pages_changed}};
}

nlohmann::json is_code(const std::string& address_str) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto address = bridge.eval_expression(address_str);
    return {{"address", format_utils::format_address(address)}, {"is_code", DbgFunctions()->MemIsCodePage(address, true)}};
}

nlohmann::json update_map() {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    DbgFunctions()->MemUpdateMap();
    return {{"message", "Memory map updated"}};
}

} // namespace handlers::memory
