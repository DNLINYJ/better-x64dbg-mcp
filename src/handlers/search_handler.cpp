#include "handlers/search_handler.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"
#include "bridgemain.h"
#include "_dbgfunctions.h"
#include "_scriptapi_symbol.h"
#include "bridgelist.h"

#include <algorithm>
#include <cctype>

namespace handlers::search {

struct pattern_byte { uint8_t value = 0; bool is_wildcard = false; };

static std::vector<pattern_byte> parse_byte_pattern(const std::string& pattern_str) {
    std::string cleaned;
    for (char c : pattern_str) if (c != ' ') cleaned += c;
    if (cleaned.empty() || (cleaned.size() % 2) != 0) return {};
    std::vector<pattern_byte> result;
    for (size_t i = 0; i + 1 < cleaned.size(); i += 2) {
        char hi = cleaned[i], lo = cleaned[i + 1];
        if (hi == '?' || hi == '*' || lo == '?' || lo == '*') {
            result.push_back({0, true});
        } else {
            auto is_hex = [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'); };
            if (!is_hex(hi) || !is_hex(lo)) return {};
            char hex[3] = {hi, lo, '\0'};
            result.push_back({static_cast<uint8_t>(std::stoul(hex, nullptr, 16)), false});
        }
    }
    return result;
}

static void search_buffer(const std::vector<uint8_t>& buf, const std::vector<pattern_byte>& pat,
                          duint region_base, int max_results, nlohmann::json& hits) {
    if (pat.empty() || buf.size() < pat.size()) return;
    for (size_t i = 0; i <= buf.size() - pat.size() && static_cast<int>(hits.size()) < max_results; ++i) {
        bool match = true;
        for (size_t j = 0; j < pat.size(); ++j) {
            if (!pat[j].is_wildcard && buf[i + j] != pat[j].value) { match = false; break; }
        }
        if (match) hits.push_back(format_utils::format_address(region_base + i));
    }
}

// Search a memory region in 10MB chunks with overlap to catch cross-boundary matches.
static void search_region(c_bridge_executor& bridge, const std::vector<pattern_byte>& pat,
                          duint region_base, duint region_size, int max_results, nlohmann::json& hits) {
    constexpr duint CHUNK_SIZE = 10 * 1024 * 1024;
    auto overlap = pat.size() > 1 ? static_cast<duint>(pat.size() - 1) : static_cast<duint>(0);
    duint offset = 0;
    while (offset < region_size && static_cast<int>(hits.size()) < max_results) {
        auto read_size = (std::min)(region_size - offset, CHUNK_SIZE);
        auto mem = bridge.read_memory(region_base + offset, static_cast<size_t>(read_size));
        if (!mem.has_value()) break;
        search_buffer(mem.value(), pat, region_base + offset, max_results, hits);
        if (read_size <= overlap) break;
        offset += read_size - overlap;
    }
}

nlohmann::json pattern(const nlohmann::json& args) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto pattern_str = args["pattern"].get<std::string>();
    auto pat = parse_byte_pattern(pattern_str);
    if (pat.empty()) throw std::runtime_error("Invalid pattern: " + pattern_str);
    auto base_str = args.value("base", "");
    auto size_val = args.value("size", 0);
    auto max_results = args.value("max_results", 100);
    auto hits = nlohmann::json::array();
    if (!base_str.empty()) {
        auto search_base = bridge.eval_expression(base_str);
        duint search_size = size_val > 0 ? static_cast<duint>(size_val) : 0x1000;
        search_region(bridge, pat, search_base, search_size, max_results, hits);
        return {{"pattern", pattern_str}, {"base", format_utils::format_address(search_base)}, {"hits", hits}, {"count", hits.size()}};
    }
    // No base specified — iterate each committed memory region individually.
    auto memmap = bridge.get_memory_map();
    if (!memmap.has_value()) throw std::runtime_error("Cannot get memory map");
    for (const auto& page : memmap.value()) {
        if (static_cast<int>(hits.size()) >= max_results) break;
        if (page["state"].get<std::string>() != "MEM_COMMIT") continue;
        auto region_base = format_utils::parse_address(page["base"].get<std::string>());
        auto region_size = page["size"].get<duint>();
        search_region(bridge, pat, region_base, region_size, max_results, hits);
    }
    return {{"pattern", pattern_str}, {"hits", hits}, {"count", hits.size()}};
}

nlohmann::json strings(const std::string& address_str, size_t size) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto address = bridge.eval_expression(address_str);
    auto mem = bridge.read_memory(address, size);
    if (!mem.has_value()) throw std::runtime_error(mem.error());
    auto found = nlohmann::json::array();
    const auto& buf = mem.value();
    std::string current;
    duint string_start = 0;
    for (size_t i = 0; i < buf.size(); ++i) {
        if (buf[i] >= 0x20 && buf[i] < 0x7F) {
            if (current.empty()) string_start = address + i;
            current += static_cast<char>(buf[i]);
        } else {
            if (current.size() >= 4) found.push_back({{"address", format_utils::format_address(string_start)}, {"string", current}});
            current.clear();
        }
    }
    if (current.size() >= 4) found.push_back({{"address", format_utils::format_address(string_start)}, {"string", current}});
    return {{"strings", found}, {"count", found.size()}};
}

nlohmann::json string_at(const std::string& address_str) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto address = bridge.eval_expression(address_str);
    auto mem = bridge.read_memory(address, 256);
    if (!mem.has_value()) throw std::runtime_error(mem.error());
    std::string result;
    for (auto b : mem.value()) { if (b == 0) break; result += static_cast<char>(b); }
    return {{"address", format_utils::format_address(address)}, {"string", result}};
}

nlohmann::json autocomplete(const std::string& query) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");

    BridgeList<Script::Symbol::SymbolInfo> symbols;
    if (!Script::Symbol::GetList(&symbols))
        return {{"query", query}, {"results", nlohmann::json::array()}, {"count", 0}};

    // Case-insensitive substring match
    std::string query_lower = query;
    std::transform(query_lower.begin(), query_lower.end(), query_lower.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    auto results = nlohmann::json::array();
    constexpr int MAX_RESULTS = 100;
    for (int i = 0; i < symbols.Count() && static_cast<int>(results.size()) < MAX_RESULTS; ++i) {
        const auto& sym = symbols[i];
        std::string name_lower = sym.name;
        std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (name_lower.find(query_lower) != std::string::npos) {
            results.push_back({
                {"name", sym.name},
                {"module", sym.mod},
                {"rva", format_utils::format_address(sym.rva)},
                {"type", sym.type == Script::Symbol::Function ? "function" : sym.type == Script::Symbol::Import ? "import" : "export"}
            });
        }
    }
    return {{"query", query}, {"results", results}, {"count", results.size()}};
}

nlohmann::json find_strings_module(const std::string& module) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto b = bridge.get_module_base(module);
    if (b == 0) throw std::runtime_error("Module not found: " + module);
    bridge.exec_command("strref " + format_utils::format_address(b));
    return {{"module", module}, {"base", format_utils::format_address(b)}, {"message", "String references in x64dbg references view"}};
}

nlohmann::json encoding(const std::string& address_str) {
    auto& bridge = get_bridge();
    if (!bridge.require_debugging()) throw std::runtime_error("No active debug session");
    auto address = bridge.eval_expression(address_str);
    auto mem = bridge.read_memory(address, 4);
    if (!mem.has_value()) throw std::runtime_error(mem.error());
    const auto& buf = mem.value();
    std::string enc = "ASCII";
    if (buf.size() >= 2 && buf[0] == 0xFF && buf[1] == 0xFE) enc = "UTF-16LE";
    else if (buf.size() >= 2 && buf[0] == 0xFE && buf[1] == 0xFF) enc = "UTF-16BE";
    else if (buf.size() >= 3 && buf[0] == 0xEF && buf[1] == 0xBB && buf[2] == 0xBF) enc = "UTF-8 (BOM)";
    return {{"address", format_utils::format_address(address)}, {"encoding", enc}};
}

} // namespace handlers::search
