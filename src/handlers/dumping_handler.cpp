#include "handlers/dumping_handler.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"
#include "bridgemain.h"
#include "_dbgfunctions.h"
#include "bridgelist.h"
#include "_scriptapi_module.h"

namespace handlers::dumping {

nlohmann::json dump_module(const std::string& module_name, const std::string& file_path) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto base = bridge.get_module_base(module_name);
    if (base == 0) throw std::runtime_error("Module not found: " + module_name);
    auto size = bridge.eval_expression("mod.size(" + module_name + ")");
    std::string cmd;
    if (!file_path.empty()) cmd = "savedata " + file_path + ", " + format_utils::format_address(base) + ", " + format_utils::format_hex(size);
    else cmd = "savedata :memdump:, " + format_utils::format_address(base) + ", " + format_utils::format_hex(size);
    return {{"success", bridge.exec_command(cmd)}, {"module", module_name}, {"base", format_utils::format_address(base)}, {"size", size}};
}

nlohmann::json pe_header(const std::string& address_str) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto base = bridge.eval_expression(address_str);
    auto dos = bridge.read_memory(base, 64);
    if (!dos.has_value() || dos->size() < 64 || (*dos)[0] != 'M' || (*dos)[1] != 'Z')
        throw std::runtime_error("Not a valid PE file");
    DWORD e_lfanew = 0; memcpy(&e_lfanew, dos->data() + 0x3C, 4);
    auto pe = bridge.read_memory(base + e_lfanew, 264);
    if (!pe.has_value() || pe->size() < 4 || (*pe)[0] != 'P' || (*pe)[1] != 'E')
        throw std::runtime_error("Invalid PE signature");
    WORD machine = 0, num_sec = 0, opt_size = 0, chars = 0;
    DWORD timestamp = 0;
    memcpy(&machine, pe->data() + 4, 2); memcpy(&num_sec, pe->data() + 6, 2);
    memcpy(&timestamp, pe->data() + 8, 4); memcpy(&opt_size, pe->data() + 20, 2);
    memcpy(&chars, pe->data() + 22, 2);
    nlohmann::json data = {{"base", format_utils::format_address(base)}, {"e_lfanew", format_utils::format_address(e_lfanew)},
        {"machine", format_utils::format_address(machine)}, {"number_of_sections", num_sec},
        {"timestamp", timestamp}, {"characteristics", format_utils::format_address(chars)}, {"size_of_optional_header", opt_size}};
    if (pe->size() >= 28) {
        WORD magic = 0; memcpy(&magic, pe->data() + 24, 2);
        data["magic"] = format_utils::format_address(magic); data["is_pe32plus"] = (magic == 0x20B);
        if (magic == 0x10B && pe->size() >= 84) {
            DWORD ep = 0, ib32 = 0, soi = 0;
            memcpy(&ep, pe->data() + 40, 4); memcpy(&ib32, pe->data() + 52, 4); memcpy(&soi, pe->data() + 80, 4);
            data["address_of_entry_point"] = format_utils::format_address(ep);
            data["image_base"] = format_utils::format_address(ib32); data["size_of_image"] = soi;
        } else if (magic == 0x20B && pe->size() >= 88) {
            DWORD ep = 0, soi = 0; uint64_t ib64 = 0;
            memcpy(&ep, pe->data() + 40, 4); memcpy(&ib64, pe->data() + 48, 8); memcpy(&soi, pe->data() + 80, 4);
            data["address_of_entry_point"] = format_utils::format_address(ep);
            data["image_base"] = format_utils::format_address(static_cast<duint>(ib64)); data["size_of_image"] = soi;
        }
    }
    return data;
}

nlohmann::json sections(const std::string& module_name) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto base = bridge.get_module_base(module_name);
    if (base == 0) throw std::runtime_error("Module not found: " + module_name);
    auto dos = bridge.read_memory(base, 64);
    if (!dos.has_value()) throw std::runtime_error("Failed to read DOS header");
    DWORD e_lfanew = 0; memcpy(&e_lfanew, dos->data() + 0x3C, 4);
    auto pe = bridge.read_memory(base + e_lfanew, 24);
    if (!pe.has_value()) throw std::runtime_error("Failed to read PE header");
    WORD num_sec = 0, opt_size = 0;
    memcpy(&num_sec, pe->data() + 6, 2); memcpy(&opt_size, pe->data() + 20, 2);
    auto sec_data = bridge.read_memory(base + e_lfanew + 24 + opt_size, num_sec * 40);
    if (!sec_data.has_value()) throw std::runtime_error("Failed to read section headers");
    auto secs = nlohmann::json::array();
    for (WORD i = 0; i < num_sec; ++i) {
        auto* s = sec_data->data() + (i * 40);
        char name[9] = {}; memcpy(name, s, 8);
        DWORD vs = 0, va = 0, rs = 0, rp = 0, ch = 0;
        memcpy(&vs, s + 8, 4); memcpy(&va, s + 12, 4); memcpy(&rs, s + 16, 4); memcpy(&rp, s + 20, 4); memcpy(&ch, s + 36, 4);
        secs.push_back({{"name", std::string(name)}, {"virtual_address", format_utils::format_address(va)},
            {"virtual_size", vs}, {"raw_size", rs}, {"raw_offset", format_utils::format_address(rp)}, {"characteristics", format_utils::format_address(ch)}});
    }
    return {{"module", module_name}, {"base", format_utils::format_address(base)}, {"sections", secs}, {"count", secs.size()}};
}

nlohmann::json imports(const std::string& module_name) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto base = bridge.get_module_base(module_name);
    if (base == 0) throw std::runtime_error("Module not found: " + module_name);

    Script::Module::ModuleInfo mod_info{};
    if (!Script::Module::InfoFromAddr(base, &mod_info))
        throw std::runtime_error("Failed to get module info for " + module_name);

    BridgeList<Script::Module::ModuleImport> import_list;
    if (!Script::Module::GetImports(&mod_info, &import_list))
        return {{"module", module_name}, {"base", format_utils::format_address(base)}, {"imports", nlohmann::json::array()}, {"count", 0}};

    auto result = nlohmann::json::array();
    for (int i = 0; i < import_list.Count(); ++i) {
        const auto& imp = import_list[i];
        nlohmann::json entry = {
            {"name", imp.name},
            {"iat_rva", format_utils::format_address(imp.iatRva)},
            {"iat_va", format_utils::format_address(imp.iatVa)}
        };
        if (imp.ordinal != static_cast<duint>(-1))
            entry["ordinal"] = imp.ordinal;
        if (imp.undecoratedName[0] != '\0')
            entry["undecorated_name"] = imp.undecoratedName;
        result.push_back(entry);
    }
    return {{"module", module_name}, {"base", format_utils::format_address(base)}, {"imports", result}, {"count", result.size()}};
}

nlohmann::json exports(const std::string& module_name) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto base = bridge.get_module_base(module_name);
    if (base == 0) throw std::runtime_error("Module not found: " + module_name);

    Script::Module::ModuleInfo mod_info{};
    if (!Script::Module::InfoFromAddr(base, &mod_info))
        throw std::runtime_error("Failed to get module info for " + module_name);

    BridgeList<Script::Module::ModuleExport> export_list;
    if (!Script::Module::GetExports(&mod_info, &export_list))
        return {{"module", module_name}, {"base", format_utils::format_address(base)}, {"exports", nlohmann::json::array()}, {"count", 0}};

    auto result = nlohmann::json::array();
    for (int i = 0; i < export_list.Count(); ++i) {
        const auto& exp = export_list[i];
        nlohmann::json entry = {
            {"name", exp.name},
            {"ordinal", exp.ordinal},
            {"rva", format_utils::format_address(exp.rva)},
            {"va", format_utils::format_address(exp.va)}
        };
        if (exp.forwarded)
            entry["forward"] = exp.forwardName;
        if (exp.undecoratedName[0] != '\0')
            entry["undecorated_name"] = exp.undecoratedName;
        result.push_back(entry);
    }
    return {{"module", module_name}, {"base", format_utils::format_address(base)}, {"exports", result}, {"count", result.size()}};
}

nlohmann::json fix_iat(const std::string& oep) {
    auto& bridge = get_bridge();
    if (!bridge.require_paused()) throw std::runtime_error("Debugger must be paused");
    return {{"success", bridge.exec_command("scylla iatAutoFix " + oep)}, {"oep", oep}, {"message", "IAT fix attempted via Scylla"}};
}

nlohmann::json relocations(const std::string& address_str) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto address = bridge.eval_expression(address_str);
    BridgeList<DBGRELOCATIONINFO> relocs;
    if (!DbgFunctions()->ModRelocationsFromAddr(address, &relocs))
        return {{"address", format_utils::format_address(address)}, {"relocations", nlohmann::json::array()}, {"count", 0}};
    auto result = nlohmann::json::array();
    for (int i = 0; i < relocs.Count(); ++i)
        result.push_back({{"rva", format_utils::format_address(relocs[i].rva)}, {"type", relocs[i].type}, {"size", relocs[i].size}});
    return {{"address", format_utils::format_address(address)}, {"relocations", result}, {"count", result.size()}};
}

nlohmann::json export_patches(const std::string& filename) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    size_t count = 0; DbgFunctions()->PatchEnum(nullptr, &count);
    if (count == 0) return {{"success", false}, {"message", "No patches to export"}};
    std::vector<DBGPATCHINFO> patches(count);
    DbgFunctions()->PatchEnum(patches.data(), &count);
    char error[MAX_ERROR_SIZE] = {};
    auto result = DbgFunctions()->PatchFile(patches.data(), static_cast<int>(count), filename.c_str(), error);
    return {{"success", result > 0}, {"patch_count", count}, {"filename", filename}, {"error", std::string(error)}};
}

nlohmann::json entry_point(const std::string& module_name) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto base = bridge.get_module_base(module_name);
    if (base == 0) throw std::runtime_error("Module not found: " + module_name);
    auto entry = bridge.eval_expression("mod.entry(" + module_name + ")");
    return {{"module", module_name}, {"base", format_utils::format_address(base)},
            {"entry_point", format_utils::format_address(entry)}, {"rva", format_utils::format_address(entry - base)}};
}

} // namespace handlers::dumping
