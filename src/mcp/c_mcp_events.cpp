#include "mcp/c_mcp_events.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"
#include "_dbgfunctions.h"

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

// Snapshot of the current thread's Cycles counter — used to detect whether the
// debuggee thread ran between CB_BREAKPOINT and CB_PAUSEDEBUG. Cycles comes from
// QueryThreadCycleTime (Win7+), has nanosecond-scale granularity, and only
// advances when the thread actually executes code. For a real CB_BREAKPOINT →
// CB_PAUSEDEBUG pair, the thread is suspended the whole time and Cycles is
// unchanged; for a skipped BP followed by a manual pause, Cycles advances.
struct thread_cycle_snapshot {
    DWORD   thread_id = 0;
    ULONG64 cycles    = 0;
    bool    valid     = false;
};

static thread_cycle_snapshot snapshot_current_thread_cycles() {
    THREADLIST list = {};
    DbgGetThreadList(&list);
    thread_cycle_snapshot snap;
    if (list.list && list.count > 0
        && list.CurrentThread >= 0
        && list.CurrentThread < list.count) {
        const auto& t = list.list[list.CurrentThread];
        snap.thread_id = t.BasicInfo.ThreadId;
        snap.cycles    = t.Cycles;
        snap.valid     = true;
    }
    if (list.list) BridgeFree(list.list);
    return snap;
}

static const char* bp_type_name(BPXTYPE t) {
    switch (t) {
        case bp_normal:    return "software";
        case bp_hardware:  return "hardware";
        case bp_memory:    return "memory";
        case bp_dll:       return "dll";
        case bp_exception: return "exception";
        default:           return "unknown";
    }
}

// Evaluate the breakpoint's log text exactly as x64dbg does at hit time (see
// reference/x64dbg/src/dbg/debugger.cpp:934-1046):
//   - logCondition is evaluated first; an evaluation error FORCES logging
//     (x64dbg treats eval failure as "log anyway"), a numeric 0 suppresses it
//   - logText is formatted via StringFormatInline BEFORE commandText runs, so
//     commandText-induced register/memory changes are not visible here
// Must be called from on_breakpoint() — calling it later (e.g. from on_pause)
// would observe post-commandText state and diverge from the actual log line.
static nlohmann::json evaluate_bp_log_fields(const BRIDGEBP& bp) {
    nlohmann::json out = nlohmann::json::object();
    if (bp.logText[0] == '\0') return out;

    bool should_log = true;
    if (bp.logCondition[0] != '\0') {
        duint cond_val = 0;
        bool ok = DbgFunctions()->ValFromString(bp.logCondition, &cond_val);
        should_log = !ok || (cond_val != 0);
    }
    if (!should_log) return out;

    char evaluated[2048] = {};
    if (DbgFunctions()->StringFormatInline(bp.logText, sizeof(evaluated), evaluated))
        out["log"] = std::string(evaluated);
    else
        out["log_raw"] = std::string(bp.logText);
    return out;
}

// Build breakpoint reason details JSON. Log fields (if any) are captured at
// CB_BREAKPOINT time and passed in via `log_fields` — do NOT re-evaluate here.
static nlohmann::json build_bp_details(const BRIDGEBP& bp, const nlohmann::json& log_fields) {
    nlohmann::json details = {
        {"type",      bp_type_name(bp.type)},
        {"address",   format_utils::format_address(bp.addr)},
        {"name",      std::string(bp.name)},
        {"module",    std::string(bp.mod)},
        {"hit_count", bp.hitCount}
    };
    for (auto it = log_fields.begin(); it != log_fields.end(); ++it) {
        details[it.key()] = it.value();
    }
    return details;
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

    // Refresh the pending cache on every CB_BREAKPOINT — so a run of
    // condition=false skips followed by a real pause leaves the cache
    // describing the most recent (actually-paused) hit. on_pause() uses
    // CIP + thread-cycles equality to tell "the last cached hit is the
    // one that produced this pause" from "the last cached hit was skipped
    // and something else caused this pause". A skip-counter is not needed:
    // both signals are refreshed per-hit and the validation still holds.
    //
    // NOTE: we do NOT pre-evaluate breakCondition — commandText can rewrite
    // $breakpointcondition after this callback, and an eval error forces a
    // break even when the expression looks false.
    m_pending_bp          = *info->breakpoint;
    m_pending_cip         = get_bridge().eval_expression("cip");
    m_pending_log_fields  = evaluate_bp_log_fields(*info->breakpoint);
    auto snap             = snapshot_current_thread_cycles();
    m_pending_thread_id     = snap.valid ? snap.thread_id : 0;
    m_pending_thread_cycles = snap.valid ? snap.cycles    : 0;
    m_last_was_breakpoint = true;
}

void c_mcp_events::on_pause(PLUG_CB_PAUSEDEBUG* /*info*/) {
    // Callback order (from x64dbg source debugger.cpp):
    //   All BP types  : CB_BREAKPOINT → CB_PAUSEDEBUG  (m_last_was_breakpoint consumed here)
    //   Steps         : CB_PAUSEDEBUG → CB_STEPPED      (on_stepped overrides "unknown" below)
    //   Exceptions    : CB_PAUSEDEBUG → CB_EXCEPTION    (on_exception overrides "unknown" below)
    //   Manual pause  : CB_PAUSEDEBUG only
    //   DLL event pause     : CB_PAUSEDEBUG only   (pauses from load/unload options)
    //   DebugString pause   : CB_PAUSEDEBUG only
    //   loadlib pause       : CB_PAUSEDEBUG only
    //
    // CB_PAUSEDEBUG by itself does NOT imply a user-initiated pause, so the
    // fallback reason is "unknown", not "manual" — a client that treats
    // "manual" as "safe to auto-resume" would mishandle the DLL/DebugString/
    // loadlib event pauses. Only on_stepped / on_exception / the BP branch
    // below positively identify their cases.

    auto& bridge = get_bridge();
    duint cip = bridge.eval_expression("cip");

    // Trust pending only if ALL of:
    //  - some CB_BREAKPOINT fired since the last clear (m_last_was_breakpoint)
    //  - the BP has no commandText: x64dbg runs commandText between
    //    CB_BREAKPOINT and the real CB_PAUSEDEBUG, and some commands (loadlib,
    //    pause, others) fire a nested CB_PAUSEDEBUG during their execution.
    //    cip+cycles can prove the original thread didn't run past the BP, but
    //    cannot prove this CB_PAUSEDEBUG is the BP's own pause rather than one
    //    triggered inside the command. Rejecting commandText-bearing BPs
    //    avoids misattributing those nested pauses; users still receive the
    //    breakpoint-hit SSE notification from on_breakpoint().
    //  - CIP is unchanged since that CB_BREAKPOINT
    //  - debuggee thread did not execute between: same thread id AND Cycles
    //    counter unchanged. Cycles (QueryThreadCycleTime) advances at
    //    nanosecond scale whenever the thread runs, so this catches every
    //    "skip → thread executed → something else paused" path, including
    //    x64dbg's `pause` command which goes SuspendThread → SetBPX(CIP,
    //    cbPauseBreakpoint) → ResumeThread and never fires CB_BREAKPOINT or
    //    CB_CREATETHREAD. Because both cip and cycles are refreshed on every
    //    CB_BREAKPOINT, a run of condition=false skips followed by a real
    //    pause at the same BP still validates correctly.
    //
    // No CIP-lookup fallback: looking up "is there an enabled BP at CIP" at
    // pause time cannot tell a real BP hit from a manual pause that happens to
    // land on a BP address.
    auto now_snap = snapshot_current_thread_cycles();
    bool thread_ran = !now_snap.valid
                   || now_snap.thread_id != m_pending_thread_id
                   || now_snap.cycles    != m_pending_thread_cycles;
    bool has_command_text = m_pending_bp.commandText[0] != '\0';

    bool use_pending = m_last_was_breakpoint
                    && !has_command_text
                    && (m_pending_cip == cip)
                    && !thread_ran;
    m_last_was_breakpoint = false;

    if (use_pending) {
        std::lock_guard lock(m_pause_mutex);
        m_pause_reason_type    = "breakpoint";
        m_pause_reason_details = build_bp_details(m_pending_bp, m_pending_log_fields);
    } else {
        // on_stepped/on_exception will override if this was actually a step
        // or an exception pause. Otherwise the cause is one of: user manual
        // pause, DLL load/unload event pause, DebugString event pause, or
        // loadlib pause — we can't positively distinguish these from plugin
        // callbacks alone, so report "unknown" rather than guessing "manual".
        std::lock_guard lock(m_pause_mutex);
        m_pause_reason_type    = "unknown";
        m_pause_reason_details = nlohmann::json::object();
    }

    nlohmann::json event = {
        {"jsonrpc", "2.0"},
        {"method", "notifications/x64dbg/paused"},
        {"params", nlohmann::json::object()}
    };
    enqueue(std::move(event));
}

void c_mcp_events::on_exception(PLUG_CB_EXCEPTION* info) {
    m_last_was_breakpoint = false;
    if (!info) return;
    const auto& exc = info->Exception->ExceptionRecord;
    bool first_chance = info->Exception->dwFirstChance != 0;

    // Only persist crash context for second-chance (unhandled) exceptions.
    // First-chance exceptions are typically caught and handled by the target process
    // (e.g. C++ throw/catch, SEH) and do not indicate a crash.
    if (!first_chance) {
        capture_crash_context(exc, first_chance);
    }

    // CB_EXCEPTION fires after CB_PAUSEDEBUG (x64dbg source: debugger.cpp).
    // Update m_pause_reason BEFORE enqueueing the SSE event so that any client
    // that polls state() immediately after receiving the notification sees the
    // correct reason rather than the "unknown" baseline set by on_pause().
    {
        std::lock_guard lock(m_pause_mutex);
        m_pause_reason_type = "exception";
        m_pause_reason_details = {
            {"code",         format_utils::format_address(exc.ExceptionCode)},
            {"name",         exception_code_to_name(exc.ExceptionCode)},
            {"address",      format_utils::format_address(reinterpret_cast<duint>(exc.ExceptionAddress))},
            {"first_chance", first_chance}
        };
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
    m_last_was_breakpoint = false;
    // CB_STEPPED fires after CB_PAUSEDEBUG (x64dbg source: debugger.cpp).
    // Update m_pause_reason BEFORE enqueueing the SSE event so that any client
    // that polls state() immediately after receiving the notification sees the
    // correct reason rather than the "unknown" baseline set by on_pause().
    {
        std::lock_guard lock(m_pause_mutex);
        m_pause_reason_type    = "step";
        m_pause_reason_details = nlohmann::json::object();
    }

    nlohmann::json event = {
        {"jsonrpc", "2.0"},
        {"method", "notifications/x64dbg/stepped"},
        {"params", nlohmann::json::object()}
    };
    enqueue(std::move(event));
}

void c_mcp_events::on_stop_debug(PLUG_CB_STOPDEBUG* /*info*/) {
    m_last_was_breakpoint = false;
    {
        std::lock_guard lock(m_pause_mutex);
        m_pause_reason_type.clear();
        m_pause_reason_details = nlohmann::json{};
    }

    nlohmann::json event = {
        {"jsonrpc", "2.0"},
        {"method", "notifications/x64dbg/stopped"},
        {"params", nlohmann::json::object()}
    };
    enqueue(std::move(event));
}

void c_mcp_events::on_create_process(PLUG_CB_CREATEPROCESS* info) {
    m_last_was_breakpoint = false;
    // Clear per-session state from any previous debug session
    {
        std::lock_guard lock(m_crash_mutex);
        m_last_crash = s_crash_record{};
    }
    {
        std::lock_guard lock(m_pause_mutex);
        m_pause_reason_type.clear();
        m_pause_reason_details = nlohmann::json{};
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
    m_last_was_breakpoint = false;
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
    m_last_was_breakpoint = false;
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
    m_last_was_breakpoint = false;
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

void c_mcp_events::on_create_thread(PLUG_CB_CREATETHREAD* /*info*/) {
    // Defensive: debuggee-created threads invalidate any stale pending. Note
    // that x64dbg's own `pause` command does NOT go through CreateRemoteThread
    // (it uses SuspendThread + SetBPX + ResumeThread and bypasses CB_CREATETHREAD),
    // so this handler does not fix manual-pause misattribution — the
    // cip + thread-cycles validation in on_breakpoint/on_pause does.
    m_last_was_breakpoint = false;
}

void c_mcp_events::on_resume_debug(PLUG_CB_RESUMEDEBUG* /*info*/) {
    // Defensive: clears pending on any user-initiated resume from a paused
    // state (e.g., run/step commands). Does not fire between a skipped BP
    // and the next pause, so it is not the load-bearing defense.
    m_last_was_breakpoint = false;
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

nlohmann::json c_mcp_events::get_pause_reason() const {
    std::lock_guard lock(m_pause_mutex);
    if (m_pause_reason_type.empty()) {
        return {{"reason", "unknown"}};
    }
    nlohmann::json result = {{"reason", m_pause_reason_type}};
    if (!m_pause_reason_details.empty()) {
        result[m_pause_reason_type] = m_pause_reason_details;
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
