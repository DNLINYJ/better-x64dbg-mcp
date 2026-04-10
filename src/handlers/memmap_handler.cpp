#include "handlers/memmap_handler.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"
#include "bridgemain.h"

namespace handlers::memmap {

nlohmann::json list() {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto result = bridge.get_memory_map();
    if (!result.has_value()) throw std::runtime_error(result.error());
    return {{"regions", result.value()}, {"count", result->size()}};
}

nlohmann::json at(const std::string& address_str) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto address = bridge.eval_expression(address_str);
    duint region_size = 0;
    auto base = DbgMemFindBaseAddr(address, &region_size);
    if (base == 0) throw std::runtime_error("No memory region at " + address_str);
    return {{"address", format_utils::format_address(address)}, {"base", format_utils::format_address(base)},
            {"region_size", region_size}, {"module", bridge.get_module_at(base)}};
}

} // namespace handlers::memmap
