#include "handlers/handles_handler.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"
#include "bridgemain.h"
#include "_dbgfunctions.h"
#include "bridgelist.h"

namespace handlers::handles {

nlohmann::json list() {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    BridgeList<HANDLEINFO> hs;
    if (!DbgFunctions()->EnumHandles(&hs)) return {{"handles", nlohmann::json::array()}, {"count", 0}};
    auto result = nlohmann::json::array();
    for (int i = 0; i < hs.Count(); ++i) {
        char name[256] = {}, type_name[256] = {};
        DbgFunctions()->GetHandleName(hs[i].Handle, name, sizeof(name), type_name, sizeof(type_name));
        result.push_back({{"handle", format_utils::format_address(hs[i].Handle)}, {"type_number", hs[i].TypeNumber},
            {"granted_access", format_utils::format_address(hs[i].GrantedAccess)}, {"name", std::string(name)}, {"type_name", std::string(type_name)}});
    }
    return {{"handles", result}, {"count", result.size()}};
}

nlohmann::json get(const std::string& handle_str) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto handle = bridge.eval_expression(handle_str);
    char name[256] = {}, type_name[256] = {};
    auto found = DbgFunctions()->GetHandleName(handle, name, sizeof(name), type_name, sizeof(type_name));
    return {{"handle", format_utils::format_address(handle)}, {"name", std::string(name)}, {"type_name", std::string(type_name)}, {"found", found}};
}

nlohmann::json tcp() {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    BridgeList<TCPCONNECTIONINFO> conns;
    if (!DbgFunctions()->EnumTcpConnections(&conns)) return {{"connections", nlohmann::json::array()}, {"count", 0}};
    auto result = nlohmann::json::array();
    for (int i = 0; i < conns.Count(); ++i)
        result.push_back({{"remote_address", std::string(conns[i].RemoteAddress)}, {"remote_port", conns[i].RemotePort},
            {"local_address", std::string(conns[i].LocalAddress)}, {"local_port", conns[i].LocalPort},
            {"state_text", std::string(conns[i].StateText)}, {"state", conns[i].State}});
    return {{"connections", result}, {"count", result.size()}};
}

nlohmann::json windows() {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    BridgeList<WINDOW_INFO> wins;
    if (!DbgFunctions()->EnumWindows(&wins)) return {{"windows", nlohmann::json::array()}, {"count", 0}};
    auto result = nlohmann::json::array();
    for (int i = 0; i < wins.Count(); ++i)
        result.push_back({{"handle", format_utils::format_address(wins[i].handle)}, {"parent", format_utils::format_address(wins[i].parent)},
            {"thread_id", wins[i].threadId}, {"style", format_utils::format_address(wins[i].style)},
            {"enabled", wins[i].enabled}, {"title", std::string(wins[i].windowTitle)}, {"class_name", std::string(wins[i].windowClass)}});
    return {{"windows", result}, {"count", result.size()}};
}

nlohmann::json heaps() {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    BridgeList<HEAPINFO> hs;
    if (!DbgFunctions()->EnumHeaps(&hs)) return {{"heaps", nlohmann::json::array()}, {"count", 0}};
    auto result = nlohmann::json::array();
    for (int i = 0; i < hs.Count(); ++i)
        result.push_back({{"address", format_utils::format_address(hs[i].addr)}, {"size", hs[i].size}, {"flags", format_utils::format_address(hs[i].flags)}});
    return {{"heaps", result}, {"count", result.size()}};
}

nlohmann::json close_handle(const std::string& handle) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    return {{"success", bridge.exec_command("HandleClose " + handle)}, {"handle", handle}};
}

} // namespace handlers::handles
