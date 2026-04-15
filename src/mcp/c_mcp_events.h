#pragma once

#include <winsock2.h>  // Must precede any transitive windows.h include

#include "_plugins.h"
#include "mcp/c_mcp_session.h"

#include <queue>
#include <mutex>
#include <thread>
#include <atomic>
#include <condition_variable>
#include <vector>

#include <nlohmann/json.hpp>

// Persistent crash record — captured at exception time, completed at process exit.
struct s_crash_record {
    // Exception core info (from EXCEPTION_RECORD)
    uint32_t    exception_code = 0;
    std::string exception_name;
    std::string exception_address;
    bool        first_chance = true;
    uint32_t    exception_flags = 0;

    // Access violation details (only for 0xC0000005)
    std::string access_type;         // "read" / "write" / "execute"
    std::string access_address;      // target address that caused fault

    // Location context (queried from Bridge API while paused at exception)
    std::string module_name;
    std::string rva;
    std::vector<std::string> disassembly;

    // Key register snapshot (GPR + IP + SP + FLAGS)
    nlohmann::json registers;

    // Process info
    std::string target_path;
    uint32_t    exit_code = 0;

    // Metadata
    std::string timestamp;           // ISO 8601
    bool        valid = false;       // whether this record contains data
    bool        exited = false;      // whether process has exited after this exception
};

class c_mcp_events {
public:
    c_mcp_events() = default;
    ~c_mcp_events();

    c_mcp_events(const c_mcp_events&) = delete;
    c_mcp_events& operator=(const c_mcp_events&) = delete;

    // Start the event push thread
    void start(c_mcp_session* session_mgr);

    // Stop the event push thread
    void stop();

    // x64dbg callback handlers (called from plugin callbacks on debug thread)
    void on_breakpoint(PLUG_CB_BREAKPOINT* info);
    void on_pause(PLUG_CB_PAUSEDEBUG* info);
    void on_exception(PLUG_CB_EXCEPTION* info);
    void on_stepped(PLUG_CB_STEPPED* info);
    void on_stop_debug(PLUG_CB_STOPDEBUG* info);
    void on_create_process(PLUG_CB_CREATEPROCESS* info);
    void on_exit_process(PLUG_CB_EXITPROCESS* info);
    void on_load_dll(PLUG_CB_LOADDLL* info);
    void on_unload_dll(PLUG_CB_UNLOADDLL* info);
    void on_create_thread(PLUG_CB_CREATETHREAD* info);
    void on_resume_debug(PLUG_CB_RESUMEDEBUG* info);

    // Crash record access
    nlohmann::json get_last_crash() const;

    // Pause reason access (call when state is "paused")
    // Returns {"reason": "<type>", "<type>": {...details...}} or {"reason": "unknown"}
    nlohmann::json get_pause_reason() const;

private:
    c_mcp_session* m_session_mgr = nullptr;
    std::atomic<bool> m_running{false};
    std::thread m_push_thread;

    std::mutex m_queue_mutex;
    std::condition_variable m_queue_cv;
    std::queue<nlohmann::json> m_event_queue;

    mutable std::mutex m_crash_mutex;
    s_crash_record m_last_crash;

    // Pause reason — written from debug thread callbacks, read from HTTP thread.
    mutable std::mutex m_pause_mutex;
    std::string    m_pause_reason_type;     // "breakpoint" | "step" | "exception" | "unknown"
    nlohmann::json m_pause_reason_details;  // type-specific fields, may be empty

    // Breakpoint pending state — debug-thread-only (all plugin callbacks run sequentially
    // on the debug thread, so no mutex is needed between these fields).
    //
    // Populated on every CB_BREAKPOINT (refreshed on each hit, so the latest hit is
    // what on_pause sees) and consumed or rejected as stale by the next on_pause().
    // Trust requires ALL of:
    //
    //   1. m_last_was_breakpoint: some CB_BREAKPOINT fired since the last clear.
    //
    //   2. Empty commandText: some commands (loadlib, pause, others) fire nested
    //      CB_PAUSEDEBUG calls during commandText execution, and cip+cycles can
    //      only prove "the original thread did not run past the BP", not "this
    //      CB_PAUSEDEBUG is the BP's real pause rather than a command-triggered
    //      nested one". Rejecting commandText BPs avoids misattributing those.
    //
    //   3. m_pending_cip == cip: a real CB_BREAKPOINT→CB_PAUSEDEBUG pair has no
    //      execution between so CIP is unchanged; a skipped BP advances CIP past
    //      the trigger via x64dbg's restoration single-step.
    //
    //   4. m_pending_thread_id matches AND m_pending_thread_cycles == current cycles:
    //      the debuggee thread has not executed since CB_BREAKPOINT. Cycles
    //      (QueryThreadCycleTime) has nanosecond-scale granularity and advances
    //      only when the thread runs, so this reliably separates "real BP → pause
    //      with thread suspended the entire time" from "skipped BP → thread ran
    //      → later pause". Because both cip and cycles are refreshed on every
    //      CB_BREAKPOINT, a real pause after N condition=false skips still
    //      matches the last refreshed snapshot.
    //
    // Rejection reports the pause as "unknown". False positives (unrelated or
    // nested pause misreported as breakpoint) are worse than false negatives,
    // so we reject whenever any invariant fails.
    BRIDGEBP m_pending_bp{};
    duint    m_pending_cip = 0;
    DWORD    m_pending_thread_id = 0;
    ULONG64  m_pending_thread_cycles = 0;
    bool     m_last_was_breakpoint = false;
    // Log text evaluated at CB_BREAKPOINT time, matching x64dbg's actual log
    // semantics: format before commandText runs, so commandText-induced state
    // changes don't affect the captured text; treat logCondition eval failure
    // as force-log (x64dbg's behavior per debugger.cpp:934-1046). Either
    // {"log": "..."} or {"log_raw": "..."} or empty object.
    nlohmann::json m_pending_log_fields;

    void push_loop();
    void enqueue(nlohmann::json event);
    void capture_crash_context(const EXCEPTION_RECORD& rec, bool first_chance);
    nlohmann::json get_last_crash_unlocked() const;  // Must be called with m_crash_mutex held
    static std::string exception_code_to_name(uint32_t code);
    static std::string format_timestamp();
};

c_mcp_events& get_events();
