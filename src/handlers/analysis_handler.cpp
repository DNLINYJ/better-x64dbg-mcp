#include "handlers/analysis_handler.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"
#include "bridgemain.h"
#include "_dbgfunctions.h"
#include "bridgelist.h"

namespace handlers::analysis {

nlohmann::json function_bounds(const std::string& address_str) {
    auto& bridge = get_bridge();
    if (!bridge.require_paused()) throw std::runtime_error("Debugger must be paused");
    auto address = bridge.eval_expression(address_str);
    auto bounds = bridge.get_function_bounds(address);
    if (!bounds.has_value()) throw std::runtime_error("No function at " + address_str);
    auto start_addr = format_utils::parse_address(bounds.value()["start"].get<std::string>());
    auto data = bounds.value();
    data["label"] = bridge.get_label_at(start_addr);
    data["module"] = bridge.get_module_at(start_addr);
    return data;
}

nlohmann::json xrefs_to(const std::string& address_str) {
    auto& bridge = get_bridge();
    if (!bridge.require_paused()) throw std::runtime_error("Debugger must be paused");
    auto address = bridge.eval_expression(address_str);
    auto xrefs = nlohmann::json::array();
    if (DbgGetXrefCountAt(address) > 0) {
        XREF_INFO xi{};
        if (DbgXrefGet(address, &xi)) {
            for (duint i = 0; i < xi.refcount; ++i) {
                const char* ts = "unknown";
                switch (xi.references[i].type) { case XREF_CALL: ts = "call"; break; case XREF_JMP: ts = "jmp"; break; case XREF_DATA: ts = "data"; break; }
                xrefs.push_back({{"address", format_utils::format_address(xi.references[i].addr)}, {"type", ts},
                    {"label", bridge.get_label_at(xi.references[i].addr)}, {"module", bridge.get_module_at(xi.references[i].addr)}});
            }
            if (xi.references) BridgeFree(xi.references);
        }
    }
    return {{"target", format_utils::format_address(address)}, {"xrefs", xrefs}, {"count", xrefs.size()}};
}

nlohmann::json xrefs_from(const std::string& address_str) {
    auto& bridge = get_bridge();
    if (!bridge.require_paused()) throw std::runtime_error("Debugger must be paused");
    auto address = bridge.eval_expression(address_str);
    auto basic = bridge.get_basic_info(address);
    if (!basic.has_value()) throw std::runtime_error(basic.error());
    auto refs = nlohmann::json::array();
    if (basic.value()["is_call"].get<bool>() || basic.value()["is_branch"].get<bool>()) {
        auto target = bridge.eval_expression("dis.branchtarget(" + address_str + ")");
        if (target != 0)
            refs.push_back({{"address", format_utils::format_address(target)},
                {"type", basic.value()["is_call"].get<bool>() ? "call" : "branch"},
                {"label", bridge.get_label_at(target)}, {"module", bridge.get_module_at(target)}});
    }
    return {{"source", format_utils::format_address(address)}, {"refs", refs}, {"count", refs.size()}};
}

nlohmann::json basic_blocks(const std::string& address_str) {
    auto& bridge = get_bridge();
    if (!bridge.require_paused()) throw std::runtime_error("Debugger must be paused");
    auto address = bridge.eval_expression(address_str);
    auto bounds = bridge.get_function_bounds(address);
    if (!bounds.has_value()) throw std::runtime_error("No function at " + address_str);
    auto func_start = format_utils::parse_address(bounds.value()["start"].get<std::string>());
    auto func_end = format_utils::parse_address(bounds.value()["end"].get<std::string>());
    auto blocks = nlohmann::json::array();
    auto block_start = func_start, cur = func_start;
    while (cur <= func_end) {
        BASIC_INSTRUCTION_INFO info{};
        DbgDisasmFastAt(cur, &info);
        if (info.size == 0) break;
        if (info.branch || info.call || cur + info.size > func_end) {
            blocks.push_back({{"start", format_utils::format_address(block_start)}, {"end", format_utils::format_address(cur)}, {"size", cur + info.size - block_start}});
            block_start = cur + info.size;
        }
        cur += info.size;
    }
    return {{"function_start", bounds.value()["start"]}, {"function_end", bounds.value()["end"]}, {"blocks", blocks}, {"count", blocks.size()}};
}

nlohmann::json constants() {
    BridgeList<CONSTANTINFO> cs;
    DbgFunctions()->EnumConstants(&cs);
    auto result = nlohmann::json::array();
    for (int i = 0; i < cs.Count(); ++i) result.push_back({{"name", cs[i].name}, {"value", format_utils::format_address(cs[i].value)}});
    return {{"constants", result}, {"count", result.size()}};
}

nlohmann::json error_codes() {
    BridgeList<CONSTANTINFO> cs;
    DbgFunctions()->EnumErrorCodes(&cs);
    auto result = nlohmann::json::array();
    for (int i = 0; i < cs.Count(); ++i) result.push_back({{"name", cs[i].name}, {"value", format_utils::format_address(cs[i].value)}});
    return {{"error_codes", result}, {"count", result.size()}};
}

nlohmann::json watch(unsigned int id) {
    return {{"id", id}, {"triggered", DbgFunctions()->WatchIsWatchdogTriggered(id)}};
}

nlohmann::json structs() {
    auto result = nlohmann::json::array();
    DbgFunctions()->EnumStructs([](const char* str, void* ud) { static_cast<nlohmann::json*>(ud)->push_back(str); }, &result);
    return {{"structs", result}, {"count", result.size()}};
}

nlohmann::json source(const std::string& address_str) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto address = bridge.eval_expression(address_str);
    char file[MAX_PATH] = {}; int line = 0;
    auto found = DbgFunctions()->GetSourceFromAddr(address, file, &line);
    return {{"address", format_utils::format_address(address)}, {"found", found}, {"file", std::string(file)}, {"line", line}};
}

nlohmann::json va_to_file(const std::string& address_str) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto va = bridge.eval_expression(address_str);
    auto fo = DbgFunctions()->VaToFileOffset(va);
    return {{"va", format_utils::format_address(va)}, {"file_offset", format_utils::format_address(fo)}, {"found", fo != 0}};
}

nlohmann::json file_to_va(const std::string& module, const std::string& offset_str) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto offset = bridge.eval_expression(offset_str);
    auto va = DbgFunctions()->FileOffsetToVa(module.c_str(), offset);
    return {{"module", module}, {"file_offset", format_utils::format_address(offset)}, {"va", format_utils::format_address(va)}, {"found", va != 0}};
}

nlohmann::json mnemonic_brief(const std::string& mnemonic) {
    char result[256] = {};
    DbgFunctions()->GetMnemonicBrief(mnemonic.c_str(), sizeof(result), result);
    return {{"mnemonic", mnemonic}, {"description", std::string(result)}};
}

nlohmann::json find_strings(const std::string& module) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto base = bridge.get_module_base(module);
    if (base == 0) throw std::runtime_error("Module not found: " + module);
    bridge.exec_command("strref " + format_utils::format_address(base));
    return {{"module", module}, {"base", format_utils::format_address(base)}, {"message", "String references in x64dbg references view"}};
}

} // namespace handlers::analysis
