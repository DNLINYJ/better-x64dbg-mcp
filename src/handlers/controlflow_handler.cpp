#include "handlers/controlflow_handler.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"
#include "bridgemain.h"
#include "_dbgfunctions.h"
#include "bridgegraph.h"

namespace handlers::controlflow {

nlohmann::json cfg_function(const std::string& address_str) {
    auto& bridge = get_bridge();
    if (!bridge.require_paused()) throw std::runtime_error("Debugger must be paused");
    auto address = bridge.eval_expression(address_str);
    BridgeCFGraphList graph_list{};
    if (!DbgAnalyzeFunction(address, &graph_list))
        throw std::runtime_error("Failed to analyze function at " + address_str);
    BridgeCFGraph graph(&graph_list, true);
    auto nodes = nlohmann::json::array();
    for (const auto& [start, node] : graph.nodes) {
        auto exits = nlohmann::json::array();
        for (auto ea : node.exits) exits.push_back(format_utils::format_address(ea));
        auto instrs = nlohmann::json::array();
        for (const auto& instr : node.instrs)
            instrs.push_back({{"address", format_utils::format_address(instr.addr)}, {"data", format_utils::format_bytes_hex(instr.data, sizeof(instr.data))}});
        nodes.push_back({{"start", format_utils::format_address(node.start)}, {"end", format_utils::format_address(node.end)},
            {"brtrue", format_utils::format_address(node.brtrue)}, {"brfalse", format_utils::format_address(node.brfalse)},
            {"terminal", node.terminal}, {"split", node.split}, {"indirectcall", node.indirectcall},
            {"exits", exits}, {"instructions", instrs}});
    }
    return {{"entry_point", format_utils::format_address(graph.entryPoint)}, {"nodes", nodes}, {"node_count", nodes.size()}};
}

nlohmann::json branch_dest(const std::string& address_str) {
    auto& bridge = get_bridge();
    if (!bridge.require_paused()) throw std::runtime_error("Debugger must be paused");
    auto address = bridge.eval_expression(address_str);
    auto dest = DbgGetBranchDestination(address);
    return {{"address", format_utils::format_address(address)}, {"destination", format_utils::format_address(dest)},
            {"label", bridge.get_label_at(dest)}, {"module", bridge.get_module_at(dest)}, {"has_dest", dest != 0}};
}

nlohmann::json is_jump_taken(const std::string& address_str) {
    auto& bridge = get_bridge();
    if (!bridge.require_paused()) throw std::runtime_error("Debugger must be paused");
    auto address = bridge.eval_expression(address_str);
    return {{"address", format_utils::format_address(address)}, {"will_execute", DbgIsJumpGoingToExecute(address)}};
}

nlohmann::json loops(const std::string& address_str) {
    auto& bridge = get_bridge();
    if (!bridge.require_paused()) throw std::runtime_error("Debugger must be paused");
    auto address = bridge.eval_expression(address_str);
    auto result = nlohmann::json::array();
    for (int depth = 0; depth < 10; ++depth) {
        duint ls = 0, le = 0;
        if (!DbgLoopGet(depth, address, &ls, &le)) break;
        result.push_back({{"depth", depth}, {"start", format_utils::format_address(ls)}, {"end", format_utils::format_address(le)}, {"size", le - ls}});
    }
    return {{"address", format_utils::format_address(address)}, {"loops", result}, {"count", result.size()}};
}

nlohmann::json add_function(const std::string& start_str, const std::string& end_str) {
    auto& bridge = get_bridge();
    if (!bridge.require_paused()) throw std::runtime_error("Debugger must be paused");
    auto s = bridge.eval_expression(start_str), e = bridge.eval_expression(end_str);
    return {{"success", DbgFunctionAdd(s, e)}, {"start", format_utils::format_address(s)}, {"end", format_utils::format_address(e)}};
}

nlohmann::json delete_function(const std::string& address_str) {
    auto& bridge = get_bridge();
    if (!bridge.require_paused()) throw std::runtime_error("Debugger must be paused");
    auto address = bridge.eval_expression(address_str);
    return {{"success", DbgFunctionDel(address)}, {"address", format_utils::format_address(address)}};
}

nlohmann::json func_type(const std::string& address_str) {
    auto& bridge = get_bridge();
    if (!bridge.require_paused()) throw std::runtime_error("Debugger must be paused");
    auto address = bridge.eval_expression(address_str);
    auto ft = DbgGetFunctionTypeAt(address);
    const char* names[] = {"none", "begin", "middle", "end", "single"};
    auto ts = (static_cast<int>(ft) < 5) ? names[static_cast<int>(ft)] : "unknown";
    return {{"address", format_utils::format_address(address)}, {"func_type", ts}, {"type_id", static_cast<int>(ft)}};
}

} // namespace handlers::controlflow
