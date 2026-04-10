#include "mcp/c_mcp_tools.h"

#include "handlers/debug_handler.h"
#include "handlers/register_handler.h"
#include "handlers/memory_handler.h"
#include "handlers/breakpoint_handler.h"
#include "handlers/disasm_handler.h"
#include "handlers/symbol_handler.h"
#include "handlers/stack_handler.h"
#include "handlers/thread_handler.h"
#include "handlers/module_handler.h"
#include "handlers/search_handler.h"
#include "handlers/command_handler.h"
#include "handlers/tracing_handler.h"
#include "handlers/dumping_handler.h"
#include "handlers/exceptions_handler.h"
#include "handlers/controlflow_handler.h"
#include "handlers/patch_handler.h"
#include "handlers/annotation_handler.h"
#include "handlers/memmap_handler.h"
#include "handlers/process_handler.h"
#include "handlers/handles_handler.h"
#include "handlers/analysis_handler.h"

using json = nlohmann::json;

// Helper to build a single action variant for oneOf
static json make_action(const std::string& name,
                        const std::vector<std::pair<std::string, json>>& fields = {},
                        const std::vector<std::string>& required_extra = {}) {
    json props = {{"action", {{"type", "string"}, {"const", name}}}};
    json req = json::array({"action"});
    for (const auto& [key, schema] : fields) {
        props[key] = schema;
    }
    for (const auto& r : required_extra) {
        req.push_back(r);
    }
    return {{"type", "object"}, {"properties", props}, {"required", req}, {"additionalProperties", false}};
}

static json str_field(const std::string& desc = "") {
    json s = {{"type", "string"}};
    if (!desc.empty()) s["description"] = desc;
    return s;
}

static json int_field(const std::string& desc = "") {
    json s = {{"type", "integer"}};
    if (!desc.empty()) s["description"] = desc;
    return s;
}

static json bool_field(const std::string& desc = "") {
    json s = {{"type", "boolean"}};
    if (!desc.empty()) s["description"] = desc;
    return s;
}

static json str_enum(const std::vector<std::string>& values, const std::string& desc = "") {
    json s = {{"type", "string"}, {"enum", values}};
    if (!desc.empty()) s["description"] = desc;
    return s;
}

static json make_tool(const std::string& name, const std::string& description, const json& input_schema) {
    return {{"name", name}, {"description", description}, {"inputSchema", input_schema}};
}

static json oneOf_schema(const std::vector<json>& variants) {
    return {{"type", "object"}, {"properties", {{"action", {{"type", "string"}}}}}, {"required", json::array({"action"})}, {"oneOf", variants}};
}

json mcp_tools::build_tools_list() {
    json tools = json::array();

    // x64dbg_debug
    tools.push_back(make_tool("x64dbg_debug", "Execute core debugger actions (run, pause, step, state, etc.)", oneOf_schema({
        make_action("run"), make_action("pause"), make_action("force_pause"),
        make_action("step_into"), make_action("step_over"), make_action("step_out"),
        make_action("stop_debug"), make_action("restart_debug"),
        make_action("run_to_address", {{"address", str_field("Target address")}}, {"address"}),
        make_action("state")
    })));

    // x64dbg_registers
    tools.push_back(make_tool("x64dbg_registers", "Read/write CPU registers and flags", oneOf_schema({
        make_action("get_all"),
        make_action("get", {{"name", str_field("Register name")}}, {"name"}),
        make_action("set", {{"name", str_field()}, {"value", str_field()}}, {"name", "value"}),
        make_action("flags"),
        make_action("avx512")
    })));

    // x64dbg_memory
    tools.push_back(make_tool("x64dbg_memory", "Read/write/query memory in debugged process", oneOf_schema({
        make_action("read", {{"address", str_field()}, {"size", int_field()}}, {"address"}),
        make_action("write", {{"address", str_field()}, {"bytes", str_field("Hex bytes")}, {"verify", bool_field()}}, {"address", "bytes"}),
        make_action("is_valid", {{"address", str_field()}}, {"address"}),
        make_action("page_info", {{"address", str_field()}}, {"address"}),
        make_action("allocate", {{"size", str_field("Size expression, e.g. 0x1000")}}, {}),
        make_action("free", {{"address", str_field()}}, {"address"}),
        make_action("protect", {{"address", str_field()}, {"size", str_field()}, {"protection", str_field()}}, {"address", "protection"}),
        make_action("is_code", {{"address", str_field()}}, {"address"}),
        make_action("update_map")
    })));

    // x64dbg_breakpoints
    tools.push_back(make_tool("x64dbg_breakpoints", "Breakpoint management (set, delete, configure, list)", oneOf_schema({
        make_action("set_software", {{"address", str_field()}, {"singleshot", bool_field()}}, {"address"}),
        make_action("set_hardware", {{"address", str_field()}, {"type", str_enum({"r","w","x"})}, {"size", str_enum({"1","2","4","8"})}}, {"address"}),
        make_action("set_memory", {{"address", str_field()}, {"type", str_enum({"a","r","w","x"})}}, {"address"}),
        make_action("delete", {{"address", str_field()}, {"type", str_enum({"software","hardware","memory"})}}, {"address"}),
        make_action("enable", {{"address", str_field()}}, {"address"}),
        make_action("disable", {{"address", str_field()}}, {"address"}),
        make_action("toggle", {{"address", str_field()}}, {"address"}),
        make_action("set_condition", {{"address", str_field()}, {"condition", str_field()}}, {"address", "condition"}),
        make_action("set_log", {{"address", str_field()}, {"text", str_field()}}, {"address", "text"}),
        make_action("reset_hit_count", {{"address", str_field()}}, {"address"}),
        make_action("get", {{"address", str_field()}}, {"address"}),
        make_action("list"),
        make_action("configure", {{"address", str_field()}, {"bp_type", str_enum({"software","hardware","memory"})},
            {"singleshot", bool_field()}, {"hw_type", str_enum({"r","w","x"})}, {"hw_size", str_enum({"1","2","4","8"})},
            {"mem_type", str_enum({"a","r","w","x"})}, {"break_condition", str_field()}, {"command_condition", str_field()},
            {"command_text", str_field()}, {"log_text", str_field()}, {"log_condition", str_field()},
            {"silent", bool_field()}, {"fast_resume", bool_field()}, {"name", str_field()}}, {"address"}),
        make_action("configure_batch", {{"breakpoints", {{"type", "array"}, {"items", {{"type", "object"}}}}}}, {"breakpoints"})
    })));

    // x64dbg_disassembly
    tools.push_back(make_tool("x64dbg_disassembly", "Disassemble instructions at address or function", oneOf_schema({
        make_action("at", {{"address", str_field()}, {"count", int_field()}}, {"address"}),
        make_action("function", {{"address", str_field()}, {"max_instructions", int_field()}}, {"address"}),
        make_action("basic", {{"address", str_field()}}, {"address"}),
        make_action("assemble", {{"address", str_field()}, {"instruction", str_field()}}, {"address", "instruction"})
    })));

    // x64dbg_symbols
    tools.push_back(make_tool("x64dbg_symbols", "Resolve, search, and list symbols", oneOf_schema({
        make_action("resolve", {{"name", str_field("Symbol name or expression")}}, {"name"}),
        make_action("at", {{"address", str_field()}}, {"address"}),
        make_action("search", {{"pattern", str_field()}, {"module", str_field()}}, {"pattern"}),
        make_action("list", {{"module", str_field()}}, {"module"})
    })));

    // x64dbg_stack
    tools.push_back(make_tool("x64dbg_stack", "Call stack, stack memory, SEH chain", oneOf_schema({
        make_action("trace"),
        make_action("read", {{"address", str_field()}, {"size", int_field()}}, {}),
        make_action("pointers"),
        make_action("comment", {{"address", str_field()}}, {"address"}),
        make_action("callstack_thread", {{"handle", str_field()}}, {"handle"}),
        make_action("return_address"),
        make_action("seh_chain")
    })));

    // x64dbg_threads
    tools.push_back(make_tool("x64dbg_threads", "Thread enumeration and control", oneOf_schema({
        make_action("list"), make_action("current"),
        make_action("get", {{"id", int_field("Thread ID")}}, {"id"}),
        make_action("switch", {{"id", int_field()}}, {"id"}),
        make_action("suspend", {{"id", int_field()}}, {"id"}),
        make_action("resume", {{"id", int_field()}}, {"id"}),
        make_action("count"),
        make_action("teb", {{"tid", int_field()}}, {"tid"}),
        make_action("name", {{"tid", int_field()}}, {"tid"})
    })));

    // x64dbg_modules
    tools.push_back(make_tool("x64dbg_modules", "Module enumeration and info", oneOf_schema({
        make_action("list"),
        make_action("get", {{"name", str_field()}}, {"name"}),
        make_action("base", {{"name", str_field()}}, {"name"}),
        make_action("section", {{"address", str_field()}}, {"address"}),
        make_action("party", {{"base", str_field()}}, {"base"})
    })));

    // x64dbg_search
    tools.push_back(make_tool("x64dbg_search", "Pattern/string/byte search in memory", oneOf_schema({
        make_action("pattern", {{"pattern", str_field("Hex bytes, e.g. 'C4 CB ?? 5B'")}, {"base", str_field()}, {"size", int_field()}, {"max_results", int_field()}}, {"pattern"}),
        make_action("strings", {{"address", str_field()}, {"size", int_field()}}, {"address"}),
        make_action("string_at", {{"address", str_field()}}, {"address"}),
        make_action("autocomplete", {{"query", str_field()}}, {"query"}),
        make_action("find_strings_module", {{"module", str_field()}}, {"module"}),
        make_action("encoding", {{"address", str_field()}}, {"address"})
    })));

    // x64dbg_command
    tools.push_back(make_tool("x64dbg_command", "Execute x64dbg commands and evaluate expressions", oneOf_schema({
        make_action("exec", {{"command", str_field()}}, {"command"}),
        make_action("eval", {{"expression", str_field()}}, {"expression"}),
        make_action("format", {{"format", str_field()}}, {"format"}),
        make_action("events"),
        make_action("set_init_script", {{"file", str_field()}}, {"file"}),
        make_action("get_init_script"),
        make_action("hash"),
        make_action("script", {{"commands", {{"type", "array"}, {"items", {{"type", "string"}}}}}}, {"commands"})
    })));

    // x64dbg_tracing
    tools.push_back(make_tool("x64dbg_tracing", "Trace execution, recording, and conditional tracing", oneOf_schema({
        make_action("trace_into", {{"condition", str_field()}, {"max_steps", str_field()}, {"log_text", str_field()}}, {}),
        make_action("trace_over", {{"condition", str_field()}, {"max_steps", str_field()}, {"log_text", str_field()}}, {}),
        make_action("run_to_party", {{"party", str_field("0=user, 1=system")}}, {}),
        make_action("stop"),
        make_action("record_hitcount", {{"address", str_field()}}, {"address"}),
        make_action("record_type", {{"address", str_field()}}, {"address"}),
        make_action("set_record_type", {{"address", str_field()}, {"type", int_field()}}, {"address", "type"}),
        make_action("animate", {{"command", str_field()}}, {"command"}),
        make_action("conditional_run", {{"type", str_enum({"into","over"})}, {"break_condition", str_field()}}, {}),
        make_action("log", {{"file", str_field()}, {"text", str_field()}}, {"file"})
    })));

    // x64dbg_dumping
    tools.push_back(make_tool("x64dbg_dumping", "Module dumping, PE header parsing, imports/exports", oneOf_schema({
        make_action("dump_module", {{"module", str_field()}, {"file", str_field()}}, {"module"}),
        make_action("pe_header", {{"address", str_field()}}, {"address"}),
        make_action("sections", {{"module", str_field()}}, {"module"}),
        make_action("imports", {{"module", str_field()}}, {"module"}),
        make_action("exports", {{"module", str_field()}}, {"module"}),
        make_action("fix_iat", {{"oep", str_field("Original entry point")}}, {"oep"}),
        make_action("relocations", {{"address", str_field()}}, {"address"}),
        make_action("export_patches", {{"filename", str_field()}}, {"filename"}),
        make_action("entry_point", {{"module", str_field()}}, {"module"})
    })));

    // x64dbg_exceptions
    tools.push_back(make_tool("x64dbg_exceptions", "Exception breakpoint management", oneOf_schema({
        make_action("set_bp", {{"code", str_field()}, {"chance", str_enum({"first","second","all"})}}, {"code"}),
        make_action("delete_bp", {{"code", str_field()}}, {"code"}),
        make_action("list_bps"),
        make_action("list_codes"),
        make_action("skip")
    })));

    // x64dbg_controlflow
    tools.push_back(make_tool("x64dbg_controlflow", "Control flow graph analysis, branch info, loops", oneOf_schema({
        make_action("cfg", {{"address", str_field()}}, {"address"}),
        make_action("branch_dest", {{"address", str_field()}}, {"address"}),
        make_action("is_jump_taken", {{"address", str_field()}}, {"address"}),
        make_action("loops", {{"address", str_field()}}, {"address"}),
        make_action("add_function", {{"start", str_field()}, {"end", str_field()}}, {"start", "end"}),
        make_action("delete_function", {{"address", str_field()}}, {"address"}),
        make_action("func_type", {{"address", str_field()}}, {"address"})
    })));

    // x64dbg_patches
    tools.push_back(make_tool("x64dbg_patches", "Byte patching and patch management", oneOf_schema({
        make_action("list"),
        make_action("apply", {{"address", str_field()}, {"bytes", str_field("Hex bytes")}}, {"address", "bytes"}),
        make_action("restore", {{"address", str_field()}}, {"address"}),
        make_action("export", {{"module", str_field()}, {"path", str_field()}}, {"path"})
    })));

    // x64dbg_annotations
    tools.push_back(make_tool("x64dbg_annotations", "Labels, comments, and bookmarks", oneOf_schema({
        make_action("get_label", {{"address", str_field()}}, {"address"}),
        make_action("set_label", {{"address", str_field()}, {"text", str_field()}}, {"address", "text"}),
        make_action("get_comment", {{"address", str_field()}}, {"address"}),
        make_action("set_comment", {{"address", str_field()}, {"text", str_field()}}, {"address", "text"}),
        make_action("set_bookmark", {{"address", str_field()}, {"set", bool_field()}}, {"address"})
    })));

    // x64dbg_memmap
    tools.push_back(make_tool("x64dbg_memmap", "Memory map listing and region queries", oneOf_schema({
        make_action("list"),
        make_action("at", {{"address", str_field()}}, {"address"})
    })));

    // x64dbg_process
    tools.push_back(make_tool("x64dbg_process", "Process info, command line, elevation status", oneOf_schema({
        make_action("details"), make_action("cmdline"),
        make_action("set_cmdline", {{"cmdline", str_field()}}, {"cmdline"}),
        make_action("elevated"), make_action("dbversion")
    })));

    // x64dbg_handles
    tools.push_back(make_tool("x64dbg_handles", "Handle, TCP connection, window, and heap enumeration", oneOf_schema({
        make_action("list"),
        make_action("get", {{"handle", str_field()}}, {"handle"}),
        make_action("tcp"), make_action("windows"), make_action("heaps"),
        make_action("close", {{"handle", str_field()}}, {"handle"})
    })));

    // x64dbg_analysis
    tools.push_back(make_tool("x64dbg_analysis", "Function analysis, xrefs, basic blocks, constants, source mapping", oneOf_schema({
        make_action("function", {{"address", str_field()}}, {"address"}),
        make_action("xrefs_to", {{"address", str_field()}}, {"address"}),
        make_action("xrefs_from", {{"address", str_field()}}, {"address"}),
        make_action("basic_blocks", {{"address", str_field()}}, {"address"}),
        make_action("constants"), make_action("error_codes"),
        make_action("watch", {{"id", int_field()}}, {"id"}),
        make_action("structs"),
        make_action("source", {{"address", str_field()}}, {"address"}),
        make_action("va_to_file", {{"address", str_field()}}, {"address"}),
        make_action("file_to_va", {{"module", str_field()}, {"offset", str_field()}}, {"module", "offset"}),
        make_action("mnemonic_brief", {{"mnemonic", str_field()}}, {"mnemonic"}),
        make_action("find_strings", {{"module", str_field()}}, {"module"})
    })));

    return tools;
}

// ============================================================================
// Tool call dispatcher
// ============================================================================

json mcp_tools::dispatch_tool_call(const std::string& tool, const json& args) {
    auto action = args.value("action", "");

    if (tool == "x64dbg_debug") {
        if (action == "run")              return handlers::debug::run();
        if (action == "pause")            return handlers::debug::pause();
        if (action == "force_pause")      return handlers::debug::force_pause();
        if (action == "step_into")        return handlers::debug::step_into();
        if (action == "step_over")        return handlers::debug::step_over();
        if (action == "step_out")         return handlers::debug::step_out();
        if (action == "stop_debug")       return handlers::debug::stop_debug();
        if (action == "restart_debug")    return handlers::debug::restart_debug();
        if (action == "run_to_address")   return handlers::debug::run_to_address(args["address"]);
        if (action == "state")            return handlers::debug::state();
    }
    else if (tool == "x64dbg_registers") {
        if (action == "get_all")  return handlers::registers::get_all();
        if (action == "get")      return handlers::registers::get_single(args["name"]);
        if (action == "set")      return handlers::registers::set_register(args["name"], args["value"]);
        if (action == "flags")    return handlers::registers::get_flags();
        if (action == "avx512")   return handlers::registers::get_avx512();
    }
    else if (tool == "x64dbg_memory") {
        if (action == "read")       return handlers::memory::read(args["address"], args.value("size", 256));
        if (action == "write")      return handlers::memory::write(args["address"], args["bytes"], args.value("verify", false));
        if (action == "is_valid")   return handlers::memory::is_valid(args["address"]);
        if (action == "page_info")  return handlers::memory::page_info(args["address"]);
        if (action == "allocate")   return handlers::memory::allocate(args.value("size", "0x1000"));
        if (action == "free")       return handlers::memory::free_mem(args["address"]);
        if (action == "protect")    return handlers::memory::protect(args["address"], args.value("size", "0x1000"), args["protection"]);
        if (action == "is_code")    return handlers::memory::is_code(args["address"]);
        if (action == "update_map") return handlers::memory::update_map();
    }
    else if (tool == "x64dbg_breakpoints") {
        if (action == "set_software")    return handlers::breakpoints::set_software(args["address"], args.value("singleshot", false));
        if (action == "set_hardware")    return handlers::breakpoints::set_hardware(args["address"], args.value("type", "x"), args.value("size", "1"));
        if (action == "set_memory")      return handlers::breakpoints::set_memory(args["address"], args.value("type", "a"));
        if (action == "delete")          return handlers::breakpoints::delete_bp(args["address"], args.value("type", "software"));
        if (action == "enable")          return handlers::breakpoints::enable(args["address"]);
        if (action == "disable")         return handlers::breakpoints::disable(args["address"]);
        if (action == "toggle")          return handlers::breakpoints::toggle(args["address"]);
        if (action == "set_condition")   return handlers::breakpoints::set_condition(args["address"], args["condition"]);
        if (action == "set_log")         return handlers::breakpoints::set_log(args["address"], args["text"]);
        if (action == "reset_hit_count") return handlers::breakpoints::reset_hit_count(args["address"]);
        if (action == "get")             return handlers::breakpoints::get(args["address"]);
        if (action == "list")            return handlers::breakpoints::list();
        if (action == "configure")       return handlers::breakpoints::configure(args);
        if (action == "configure_batch") return handlers::breakpoints::configure_batch(args["breakpoints"]);
    }
    else if (tool == "x64dbg_disassembly") {
        if (action == "at")       return handlers::disasm::at(args["address"], args.value("count", 10));
        if (action == "function") return handlers::disasm::function(args["address"], args.value("max_instructions", 50));
        if (action == "basic")    return handlers::disasm::basic(args["address"]);
        if (action == "assemble") return handlers::disasm::assemble(args["address"], args["instruction"]);
    }
    else if (tool == "x64dbg_symbols") {
        if (action == "resolve") return handlers::symbols::resolve(args["name"]);
        if (action == "at")      return handlers::symbols::at(args["address"]);
        if (action == "search")  return handlers::symbols::search(args["pattern"], args.value("module", ""));
        if (action == "list")    return handlers::symbols::list_module(args["module"]);
    }
    else if (tool == "x64dbg_stack") {
        if (action == "trace")            return handlers::stack::trace();
        if (action == "read")             return handlers::stack::read(args.value("address", "csp"), args.value("size", 256));
        if (action == "pointers")         return handlers::stack::pointers();
        if (action == "comment")          return handlers::stack::comment(args["address"]);
        if (action == "callstack_thread") return handlers::stack::callstack_thread(args["handle"]);
        if (action == "return_address")   return handlers::stack::return_address();
        if (action == "seh_chain")        return handlers::stack::seh_chain();
    }
    else if (tool == "x64dbg_threads") {
        if (action == "list")    return handlers::threads::list();
        if (action == "current") return handlers::threads::current();
        if (action == "get")     return handlers::threads::get_by_id(args["id"]);
        if (action == "switch")  return handlers::threads::switch_thread(args["id"]);
        if (action == "suspend") return handlers::threads::suspend(args["id"]);
        if (action == "resume")  return handlers::threads::resume(args["id"]);
        if (action == "count")   return handlers::threads::count();
        if (action == "teb")     return handlers::threads::teb(args["tid"]);
        if (action == "name")    return handlers::threads::name(args["tid"]);
    }
    else if (tool == "x64dbg_modules") {
        if (action == "list")    return handlers::modules::list();
        if (action == "get")     return handlers::modules::get(args["name"]);
        if (action == "base")    return handlers::modules::base(args["name"]);
        if (action == "section") return handlers::modules::section(args["address"]);
        if (action == "party")   return handlers::modules::party(args["base"]);
    }
    else if (tool == "x64dbg_search") {
        if (action == "pattern")              return handlers::search::pattern(args);
        if (action == "strings")              return handlers::search::strings(args["address"], args.value("size", 4096));
        if (action == "string_at")            return handlers::search::string_at(args["address"]);
        if (action == "autocomplete")         return handlers::search::autocomplete(args["query"]);
        if (action == "find_strings_module")  return handlers::search::find_strings_module(args["module"]);
        if (action == "encoding")             return handlers::search::encoding(args["address"]);
    }
    else if (tool == "x64dbg_command") {
        if (action == "exec")            return handlers::command::exec(args["command"]);
        if (action == "eval")            return handlers::command::eval(args["expression"]);
        if (action == "format")          return handlers::command::format_str(args["format"]);
        if (action == "events")          return handlers::command::events();
        if (action == "set_init_script") return handlers::command::set_init_script(args["file"]);
        if (action == "get_init_script") return handlers::command::get_init_script();
        if (action == "hash")            return handlers::command::hash();
        if (action == "script") {
            std::vector<std::string> cmds;
            for (const auto& c : args["commands"]) cmds.push_back(c.get<std::string>());
            return handlers::command::script(cmds);
        }
    }
    else if (tool == "x64dbg_tracing") {
        if (action == "trace_into")      return handlers::tracing::trace_into(args);
        if (action == "trace_over")      return handlers::tracing::trace_over(args);
        if (action == "run_to_party")    return handlers::tracing::run_to_party(args.value("party", "0"));
        if (action == "stop")            return handlers::tracing::stop_trace();
        if (action == "record_hitcount") return handlers::tracing::record_hitcount(args["address"]);
        if (action == "record_type")     return handlers::tracing::record_type(args["address"]);
        if (action == "set_record_type") return handlers::tracing::set_record_type(args["address"], args["type"]);
        if (action == "animate")         return handlers::tracing::animate(args["command"]);
        if (action == "conditional_run") return handlers::tracing::conditional_run(args);
        if (action == "log")             return handlers::tracing::log_trace(args);
    }
    else if (tool == "x64dbg_dumping") {
        if (action == "dump_module")     return handlers::dumping::dump_module(args["module"], args.value("file", ""));
        if (action == "pe_header")       return handlers::dumping::pe_header(args["address"]);
        if (action == "sections")        return handlers::dumping::sections(args["module"]);
        if (action == "imports")         return handlers::dumping::imports(args["module"]);
        if (action == "exports")         return handlers::dumping::exports(args["module"]);
        if (action == "fix_iat")         return handlers::dumping::fix_iat(args["oep"]);
        if (action == "relocations")     return handlers::dumping::relocations(args["address"]);
        if (action == "export_patches")  return handlers::dumping::export_patches(args["filename"]);
        if (action == "entry_point")     return handlers::dumping::entry_point(args["module"]);
    }
    else if (tool == "x64dbg_exceptions") {
        if (action == "set_bp")     return handlers::exceptions::set_bp(args["code"], args.value("chance", "first"));
        if (action == "delete_bp")  return handlers::exceptions::delete_bp(args["code"]);
        if (action == "list_bps")   return handlers::exceptions::list_bps();
        if (action == "list_codes") return handlers::exceptions::list_codes();
        if (action == "skip")       return handlers::exceptions::skip();
    }
    else if (tool == "x64dbg_controlflow") {
        if (action == "cfg")             return handlers::controlflow::cfg_function(args["address"]);
        if (action == "branch_dest")     return handlers::controlflow::branch_dest(args["address"]);
        if (action == "is_jump_taken")   return handlers::controlflow::is_jump_taken(args["address"]);
        if (action == "loops")           return handlers::controlflow::loops(args["address"]);
        if (action == "add_function")    return handlers::controlflow::add_function(args["start"], args["end"]);
        if (action == "delete_function") return handlers::controlflow::delete_function(args["address"]);
        if (action == "func_type")       return handlers::controlflow::func_type(args["address"]);
    }
    else if (tool == "x64dbg_patches") {
        if (action == "list")    return handlers::patches::list();
        if (action == "apply")   return handlers::patches::apply(args["address"], args["bytes"]);
        if (action == "restore") return handlers::patches::restore(args["address"]);
        if (action == "export")  return handlers::patches::export_module(args.value("module", ""), args["path"]);
    }
    else if (tool == "x64dbg_annotations") {
        if (action == "get_label")    return handlers::annotations::get_label(args["address"]);
        if (action == "set_label")    return handlers::annotations::set_label(args["address"], args["text"]);
        if (action == "get_comment")  return handlers::annotations::get_comment(args["address"]);
        if (action == "set_comment")  return handlers::annotations::set_comment(args["address"], args["text"]);
        if (action == "set_bookmark") return handlers::annotations::set_bookmark(args["address"], args.value("set", true));
    }
    else if (tool == "x64dbg_memmap") {
        if (action == "list") return handlers::memmap::list();
        if (action == "at")   return handlers::memmap::at(args["address"]);
    }
    else if (tool == "x64dbg_process") {
        if (action == "details")     return handlers::process::details();
        if (action == "cmdline")     return handlers::process::cmdline();
        if (action == "set_cmdline") return handlers::process::set_cmdline(args["cmdline"]);
        if (action == "elevated")    return handlers::process::elevated();
        if (action == "dbversion")   return handlers::process::dbversion();
    }
    else if (tool == "x64dbg_handles") {
        if (action == "list")    return handlers::handles::list();
        if (action == "get")     return handlers::handles::get(args["handle"]);
        if (action == "tcp")     return handlers::handles::tcp();
        if (action == "windows") return handlers::handles::windows();
        if (action == "heaps")   return handlers::handles::heaps();
        if (action == "close")   return handlers::handles::close_handle(args["handle"]);
    }
    else if (tool == "x64dbg_analysis") {
        if (action == "function")       return handlers::analysis::function_bounds(args["address"]);
        if (action == "xrefs_to")       return handlers::analysis::xrefs_to(args["address"]);
        if (action == "xrefs_from")     return handlers::analysis::xrefs_from(args["address"]);
        if (action == "basic_blocks")   return handlers::analysis::basic_blocks(args["address"]);
        if (action == "constants")      return handlers::analysis::constants();
        if (action == "error_codes")    return handlers::analysis::error_codes();
        if (action == "watch")          return handlers::analysis::watch(args["id"]);
        if (action == "structs")        return handlers::analysis::structs();
        if (action == "source")         return handlers::analysis::source(args["address"]);
        if (action == "va_to_file")     return handlers::analysis::va_to_file(args["address"]);
        if (action == "file_to_va")     return handlers::analysis::file_to_va(args["module"], args["offset"]);
        if (action == "mnemonic_brief") return handlers::analysis::mnemonic_brief(args["mnemonic"]);
        if (action == "find_strings")   return handlers::analysis::find_strings(args["module"]);
    }

    throw std::runtime_error("Unknown tool '" + tool + "' or action '" + action + "'");
}
