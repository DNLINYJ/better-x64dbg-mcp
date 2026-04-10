#include "handlers/stack_handler.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers::stack {

nlohmann::json trace() {
    auto& bridge = get_bridge();
    if (!bridge.require_paused()) throw std::runtime_error("Debugger must be paused");
    DBGCALLSTACK callstack{};
    DbgFunctions()->GetCallStackEx(&callstack, false);
    auto frames = nlohmann::json::array();
    for (int i = 0; i < callstack.total; ++i) {
        const auto& e = callstack.entries[i];
        frames.push_back({{"index", i}, {"address", format_utils::format_address(e.addr)},
            {"from", format_utils::format_address(e.from)}, {"to", format_utils::format_address(e.to)},
            {"label", bridge.get_label_at(e.to)}, {"module", bridge.get_module_at(e.to)}, {"comment", e.comment}});
    }
    if (callstack.entries) BridgeFree(callstack.entries);
    return {{"frames", frames}, {"count", frames.size()}};
}

nlohmann::json read(const std::string& address_str, size_t size) {
    auto& bridge = get_bridge();
    if (!bridge.require_paused()) throw std::runtime_error("Debugger must be paused");
    auto address = bridge.eval_expression(address_str);
    auto result = bridge.read_memory(address, size);
    if (!result.has_value()) throw std::runtime_error(result.error());
    const auto& bytes = result.value();
    auto entries = nlohmann::json::array();
    auto ptr_size = sizeof(duint);
    for (size_t offset = 0; offset + ptr_size <= bytes.size(); offset += ptr_size) {
        duint value = 0;
        memcpy(&value, bytes.data() + offset, ptr_size);
        auto entry_addr = address + offset;
        entries.push_back({{"address", format_utils::format_address(entry_addr)}, {"value", format_utils::format_address(value)},
            {"label", bridge.get_label_at(value)}, {"module", bridge.get_module_at(value)}});
    }
    return {{"base", format_utils::format_address(address)}, {"size", bytes.size()}, {"entries", entries}};
}

nlohmann::json pointers() {
    auto& bridge = get_bridge();
    if (!bridge.require_paused()) throw std::runtime_error("Debugger must be paused");
    auto csp = bridge.eval_expression("csp");
    auto cbp = bridge.eval_expression("cbp");
    return {
#ifdef _WIN64
        {"rsp", format_utils::format_address(csp)}, {"rbp", format_utils::format_address(cbp)}
#else
        {"esp", format_utils::format_address(csp)}, {"ebp", format_utils::format_address(cbp)}
#endif
    };
}

nlohmann::json comment(const std::string& address_str) {
    auto& bridge = get_bridge();
    if (!bridge.require_paused()) throw std::runtime_error("Debugger must be paused");
    auto address = bridge.eval_expression(address_str);
    STACK_COMMENT sc{};
    auto found = DbgStackCommentGet(address, &sc);
    return {{"address", format_utils::format_address(address)}, {"found", found}, {"comment", std::string(sc.comment)}, {"color", std::string(sc.color)}};
}

nlohmann::json callstack_thread(const std::string& handle_str) {
    auto& bridge = get_bridge();
    if (!bridge.require_paused()) throw std::runtime_error("Debugger must be paused");
    auto handle = bridge.eval_expression(handle_str);
    DBGCALLSTACK callstack{};
    DbgFunctions()->GetCallStackByThread(reinterpret_cast<HANDLE>(handle), &callstack);
    auto frames = nlohmann::json::array();
    for (int i = 0; i < callstack.total; ++i) {
        const auto& e = callstack.entries[i];
        frames.push_back({{"index", i}, {"address", format_utils::format_address(e.addr)},
            {"from", format_utils::format_address(e.from)}, {"to", format_utils::format_address(e.to)},
            {"label", bridge.get_label_at(e.to)}, {"module", bridge.get_module_at(e.to)}, {"comment", e.comment}});
    }
    if (callstack.entries) BridgeFree(callstack.entries);
    return {{"frames", frames}, {"count", frames.size()}};
}

nlohmann::json return_address() {
    auto& bridge = get_bridge();
    if (!bridge.require_paused()) throw std::runtime_error("Debugger must be paused");
    auto sp = bridge.eval_expression("csp");
    auto mem = bridge.read_memory(sp, sizeof(duint));
    if (!mem.has_value()) throw std::runtime_error("Failed to read stack pointer");
    duint ret = 0;
    memcpy(&ret, mem.value().data(), sizeof(duint));
    return {{"stack_pointer", format_utils::format_address(sp)}, {"return_address", format_utils::format_address(ret)},
            {"label", bridge.get_label_at(ret)}, {"module", bridge.get_module_at(ret)}};
}

nlohmann::json seh_chain() {
    auto& bridge = get_bridge();
    if (!bridge.require_paused()) throw std::runtime_error("Debugger must be paused");
    DBGSEHCHAIN sc{};
    DbgFunctions()->GetSEHChain(&sc);
    auto chain = nlohmann::json::array();
    for (duint i = 0; i < sc.total; ++i) {
        chain.push_back({{"address", format_utils::format_address(sc.records[i].addr)},
            {"handler", format_utils::format_address(sc.records[i].handler)},
            {"label", bridge.get_label_at(sc.records[i].handler)}, {"module", bridge.get_module_at(sc.records[i].handler)}});
    }
    if (sc.records) BridgeFree(sc.records);
    return {{"chain", chain}, {"count", chain.size()}};
}

} // namespace handlers::stack
