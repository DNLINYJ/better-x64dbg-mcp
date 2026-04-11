#include "mcp/c_mcp_events.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

c_mcp_events::~c_mcp_events() {
    stop();
}

void c_mcp_events::start(c_mcp_session* session_mgr) {
    m_session_mgr = session_mgr;
    m_running.store(true);
    m_push_thread = std::thread(&c_mcp_events::push_loop, this);
}

void c_mcp_events::stop() {
    // Use exchange to prevent concurrent calls from both attempting to join the thread
    if (!m_running.exchange(false)) return;
    m_queue_cv.notify_all();
    if (m_push_thread.joinable()) {
        m_push_thread.join();
    }
}

void c_mcp_events::push_loop() {
    while (m_running.load()) {
        std::unique_lock lock(m_queue_mutex);
        m_queue_cv.wait(lock, [this] {
            return !m_event_queue.empty() || !m_running.load();
        });

        while (!m_event_queue.empty()) {
            auto event = std::move(m_event_queue.front());
            m_event_queue.pop();
            lock.unlock();

            if (m_session_mgr) {
                m_session_mgr->broadcast_event(event);
            }

            lock.lock();
        }
    }
}

void c_mcp_events::enqueue(nlohmann::json event) {
    {
        std::lock_guard lock(m_queue_mutex);
        m_event_queue.push(std::move(event));
    }
    m_queue_cv.notify_one();
}

void c_mcp_events::on_breakpoint(PLUG_CB_BREAKPOINT* info) {
    if (!info) return;
    nlohmann::json event = {
        {"jsonrpc", "2.0"},
        {"method", "notifications/x64dbg/breakpoint"},
        {"params", {
            {"address",    format_utils::format_address(info->breakpoint->addr)},
            {"type",       static_cast<int>(info->breakpoint->type)},
            {"name",       info->breakpoint->name},
            {"module",     info->breakpoint->mod},
            {"hit_count",  info->breakpoint->hitCount},
            {"enabled",    info->breakpoint->enabled},
            {"singleshoot", info->breakpoint->singleshoot}
        }}
    };
    enqueue(std::move(event));
}

void c_mcp_events::on_pause(PLUG_CB_PAUSEDEBUG* /*info*/) {
    nlohmann::json event = {
        {"jsonrpc", "2.0"},
        {"method", "notifications/x64dbg/paused"},
        {"params", nlohmann::json::object()}
    };
    enqueue(std::move(event));
}

void c_mcp_events::on_exception(PLUG_CB_EXCEPTION* info) {
    if (!info) return;
    const auto& exc = info->Exception->ExceptionRecord;
    bool first_chance = info->Exception->dwFirstChance != 0;

    // Only persist crash context for second-chance (unhandled) exceptions.
    // First-chance exceptions are typically caught and handled by the target process
    // (e.g. C++ throw/catch, SEH) and do not indicate a crash.
    if (!first_chance) {
        capture_crash_context(exc, first_chance);
    }

    nlohmann::json event = {
        {"jsonrpc", "2.0"},
        {"method", "notifications/x64dbg/exception"},
        {"params", {
            {"code",          format_utils::format_address(exc.ExceptionCode)},
            {"address",       format_utils::format_address(reinterpret_cast<duint>(exc.ExceptionAddress))},
            {"first_chance",  first_chance},
            {"flags",         exc.ExceptionFlags}
        }}
    };
    enqueue(std::move(event));
}

void c_mcp_events::on_stepped(PLUG_CB_STEPPED* /*info*/) {
    nlohmann::json event = {
        {"jsonrpc", "2.0"},
        {"method", "notifications/x64dbg/stepped"},
        {"params", nlohmann::json::object()}
    };
    enqueue(std::move(event));
}

void c_mcp_events::on_stop_debug(PLUG_CB_STOPDEBUG* /*info*/) {
    nlohmann::json event = {
        {"jsonrpc", "2.0"},
        {"method", "notifications/x64dbg/stopped"},
        {"params", nlohmann::json::object()}
    };
    enqueue(std::move(event));
}

void c_mcp_events::on_create_process(PLUG_CB_CREATEPROCESS* info) {
    // Clear crash record from previous session
    {
        std::lock_guard lock(m_crash_mutex);
        m_last_crash = s_crash_record{};
    }

    if (!info) return;
    nlohmann::json event = {
        {"jsonrpc", "2.0"},
        {"method", "notifications/x64dbg/process_created"},
        {"params", {
            {"image_base", format_utils::format_address(reinterpret_cast<duint>(info->CreateProcessInfo->lpBaseOfImage))},
            {"file_name",  info->modInfo->ModuleName}
        }}
    };
    enqueue(std::move(event));
}

void c_mcp_events::on_exit_process(PLUG_CB_EXITPROCESS* info) {
    if (!info) return;

    nlohmann::json params = {
        {"exit_code", info->ExitProcess->dwExitCode}
    };

    // Fill exit code into crash record and attach crash info to the event
    {
        std::lock_guard lock(m_crash_mutex);
        if (m_last_crash.valid) {
            m_last_crash.exit_code = info->ExitProcess->dwExitCode;
            m_last_crash.exited = true;
            params["last_exception"] = get_last_crash_unlocked();
        }
    }

    nlohmann::json event = {
        {"jsonrpc", "2.0"},
        {"method", "notifications/x64dbg/process_exited"},
        {"params", std::move(params)}
    };
    enqueue(std::move(event));
}

void c_mcp_events::on_load_dll(PLUG_CB_LOADDLL* info) {
    if (!info) return;
    nlohmann::json event = {
        {"jsonrpc", "2.0"},
        {"method", "notifications/x64dbg/dll_loaded"},
        {"params", {
            {"base", format_utils::format_address(reinterpret_cast<duint>(info->LoadDll->lpBaseOfDll))},
            {"name", info->modInfo->ModuleName}
        }}
    };
    enqueue(std::move(event));
}

void c_mcp_events::on_unload_dll(PLUG_CB_UNLOADDLL* info) {
    if (!info) return;
    nlohmann::json event = {
        {"jsonrpc", "2.0"},
        {"method", "notifications/x64dbg/dll_unloaded"},
        {"params", {
            {"base", format_utils::format_address(reinterpret_cast<duint>(info->UnloadDll->lpBaseOfDll))}
        }}
    };
    enqueue(std::move(event));
}

// ============================================================================
// Crash record
// ============================================================================

void c_mcp_events::capture_crash_context(const EXCEPTION_RECORD& rec, bool first_chance) {
    auto& bridge = get_bridge();

    s_crash_record crash;
    crash.valid = true;
    crash.exception_code = rec.ExceptionCode;
    crash.exception_name = exception_code_to_name(rec.ExceptionCode);
    crash.exception_address = format_utils::format_address(reinterpret_cast<duint>(rec.ExceptionAddress));
    crash.first_chance = first_chance;
    crash.exception_flags = rec.ExceptionFlags;
    crash.timestamp = format_timestamp();

    // Access violation details
    if (rec.ExceptionCode == EXCEPTION_ACCESS_VIOLATION && rec.NumberParameters >= 2) {
        switch (rec.ExceptionInformation[0]) {
            case 0: crash.access_type = "read";    break;
            case 1: crash.access_type = "write";   break;
            case 8: crash.access_type = "execute";  break;
            default: crash.access_type = "unknown"; break;
        }
        crash.access_address = format_utils::format_address(static_cast<duint>(rec.ExceptionInformation[1]));
    }

    // Module at exception address
    auto exc_addr = reinterpret_cast<duint>(rec.ExceptionAddress);
    crash.module_name = bridge.get_module_at(exc_addr);

    // RVA = exception address - module base
    if (!crash.module_name.empty()) {
        auto mod_base = bridge.get_module_base(crash.module_name);
        if (mod_base != 0 && exc_addr >= mod_base) {
            crash.rva = format_utils::format_address(exc_addr - mod_base);
        }
    }

    // Disassembly around exception address (~5 instructions)
    auto disasm_result = bridge.disassemble_at(exc_addr, 5);
    if (disasm_result.has_value()) {
        for (const auto& instr : disasm_result.value()) {
            std::string line = instr.value("address", "") + "  " + instr.value("instruction", "");
            auto instr_addr = format_utils::parse_address(instr.value("address", "0"));
            if (instr_addr == exc_addr) {
                line += "       <<<";
            }
            crash.disassembly.push_back(std::move(line));
        }
    }

    // Key register snapshot (GPR + IP + SP + FLAGS)
    auto dump_result = bridge.get_register_dump();
    if (dump_result.has_value()) {
        const auto& ctx = dump_result->regcontext;
        nlohmann::json regs;
#ifdef _WIN64
        regs["rax"] = format_utils::format_address(ctx.cax);
        regs["rcx"] = format_utils::format_address(ctx.ccx);
        regs["rdx"] = format_utils::format_address(ctx.cdx);
        regs["rbx"] = format_utils::format_address(ctx.cbx);
        regs["rsp"] = format_utils::format_address(ctx.csp);
        regs["rbp"] = format_utils::format_address(ctx.cbp);
        regs["rsi"] = format_utils::format_address(ctx.csi);
        regs["rdi"] = format_utils::format_address(ctx.cdi);
        regs["r8"]  = format_utils::format_address(ctx.r8);
        regs["r9"]  = format_utils::format_address(ctx.r9);
        regs["r10"] = format_utils::format_address(ctx.r10);
        regs["r11"] = format_utils::format_address(ctx.r11);
        regs["r12"] = format_utils::format_address(ctx.r12);
        regs["r13"] = format_utils::format_address(ctx.r13);
        regs["r14"] = format_utils::format_address(ctx.r14);
        regs["r15"] = format_utils::format_address(ctx.r15);
        regs["rip"] = format_utils::format_address(ctx.cip);
#else
        regs["eax"] = format_utils::format_address(ctx.cax);
        regs["ecx"] = format_utils::format_address(ctx.ccx);
        regs["edx"] = format_utils::format_address(ctx.cdx);
        regs["ebx"] = format_utils::format_address(ctx.cbx);
        regs["esp"] = format_utils::format_address(ctx.csp);
        regs["ebp"] = format_utils::format_address(ctx.cbp);
        regs["esi"] = format_utils::format_address(ctx.csi);
        regs["edi"] = format_utils::format_address(ctx.cdi);
        regs["eip"] = format_utils::format_address(ctx.cip);
#endif
        regs["eflags"] = format_utils::format_address(ctx.eflags);
        crash.registers = std::move(regs);
    }

    // Process target path (from debug handler cached state)
    // We don't access s_launch_target directly — it's in debug_handler's static scope.
    // The target will be available in the query via handlers::debug::last_crash().

    std::lock_guard lock(m_crash_mutex);
    m_last_crash = std::move(crash);
}

nlohmann::json c_mcp_events::get_last_crash() const {
    std::lock_guard lock(m_crash_mutex);
    return get_last_crash_unlocked();
}

nlohmann::json c_mcp_events::get_last_crash_unlocked() const {
    if (!m_last_crash.valid) {
        return {{"has_crash", false}};
    }

    const auto& c = m_last_crash;

    // Build human-readable message
    std::string message = c.exception_name + " at " + c.exception_address;
    if (!c.access_type.empty()) {
        message = "Access violation " + c.access_type + "ing " + c.access_address;
    }

    nlohmann::json result = {
        {"has_crash", true},
        {"exception", {
            {"code",         format_utils::format_address(c.exception_code)},
            {"name",         c.exception_name},
            {"address",      c.exception_address},
            {"first_chance", c.first_chance},
            {"flags",        c.exception_flags},
            {"message",      message}
        }},
        {"registers",  c.registers},
        {"timestamp",  c.timestamp}
    };

    // Location context
    nlohmann::json location;
    if (!c.module_name.empty()) location["module"] = c.module_name;
    if (!c.rva.empty())         location["rva"] = c.rva;
    if (!c.disassembly.empty()) location["disassembly"] = c.disassembly;
    if (!location.empty()) result["location"] = std::move(location);

    // Access violation details
    if (!c.access_type.empty()) {
        result["exception"]["access_type"]    = c.access_type;
        result["exception"]["access_address"] = c.access_address;
    }

    // Process info (filled after exit)
    if (c.exited) {
        result["process"] = {
            {"exit_code", format_utils::format_address(c.exit_code)}
        };
    }

    return result;
}

std::string c_mcp_events::exception_code_to_name(uint32_t code) {
    switch (code) {
        case EXCEPTION_ACCESS_VIOLATION:         return "EXCEPTION_ACCESS_VIOLATION";
        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:    return "EXCEPTION_ARRAY_BOUNDS_EXCEEDED";
        case EXCEPTION_BREAKPOINT:               return "EXCEPTION_BREAKPOINT";
        case EXCEPTION_DATATYPE_MISALIGNMENT:    return "EXCEPTION_DATATYPE_MISALIGNMENT";
        case EXCEPTION_FLT_DENORMAL_OPERAND:     return "EXCEPTION_FLT_DENORMAL_OPERAND";
        case EXCEPTION_FLT_DIVIDE_BY_ZERO:       return "EXCEPTION_FLT_DIVIDE_BY_ZERO";
        case EXCEPTION_FLT_INEXACT_RESULT:       return "EXCEPTION_FLT_INEXACT_RESULT";
        case EXCEPTION_FLT_INVALID_OPERATION:    return "EXCEPTION_FLT_INVALID_OPERATION";
        case EXCEPTION_FLT_OVERFLOW:             return "EXCEPTION_FLT_OVERFLOW";
        case EXCEPTION_FLT_STACK_CHECK:          return "EXCEPTION_FLT_STACK_CHECK";
        case EXCEPTION_FLT_UNDERFLOW:            return "EXCEPTION_FLT_UNDERFLOW";
        case EXCEPTION_GUARD_PAGE:               return "EXCEPTION_GUARD_PAGE";
        case EXCEPTION_ILLEGAL_INSTRUCTION:      return "EXCEPTION_ILLEGAL_INSTRUCTION";
        case EXCEPTION_IN_PAGE_ERROR:            return "EXCEPTION_IN_PAGE_ERROR";
        case EXCEPTION_INT_DIVIDE_BY_ZERO:       return "EXCEPTION_INT_DIVIDE_BY_ZERO";
        case EXCEPTION_INT_OVERFLOW:             return "EXCEPTION_INT_OVERFLOW";
        case EXCEPTION_INVALID_DISPOSITION:      return "EXCEPTION_INVALID_DISPOSITION";
        case EXCEPTION_INVALID_HANDLE:           return "EXCEPTION_INVALID_HANDLE";
        case EXCEPTION_NONCONTINUABLE_EXCEPTION: return "EXCEPTION_NONCONTINUABLE_EXCEPTION";
        case EXCEPTION_PRIV_INSTRUCTION:         return "EXCEPTION_PRIV_INSTRUCTION";
        case EXCEPTION_SINGLE_STEP:              return "EXCEPTION_SINGLE_STEP";
        case EXCEPTION_STACK_OVERFLOW:           return "EXCEPTION_STACK_OVERFLOW";
        case 0xE06D7363:                         return "CPP_EXCEPTION";         // MSVC C++ exception
        case 0xE0434352:                         return "CLR_EXCEPTION";         // .NET CLR exception
        case 0xC0000194:                         return "POSSIBLE_DEADLOCK";
        default: {
            char buf[32];
            snprintf(buf, sizeof(buf), "UNKNOWN_0x%08X", code);
            return buf;
        }
    }
}

std::string c_mcp_events::format_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;

    std::tm tm_buf{};
    gmtime_s(&tm_buf, &time_t_now);

    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%S")
        << '.' << std::setfill('0') << std::setw(3) << ms.count() << 'Z';
    return oss.str();
}
