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

    // Crash record access
    nlohmann::json get_last_crash() const;

private:
    c_mcp_session* m_session_mgr = nullptr;
    std::atomic<bool> m_running{false};
    std::thread m_push_thread;

    std::mutex m_queue_mutex;
    std::condition_variable m_queue_cv;
    std::queue<nlohmann::json> m_event_queue;

    mutable std::mutex m_crash_mutex;
    s_crash_record m_last_crash;

    void push_loop();
    void enqueue(nlohmann::json event);
    void capture_crash_context(const EXCEPTION_RECORD& rec, bool first_chance);
    nlohmann::json get_last_crash_unlocked() const;  // Must be called with m_crash_mutex held
    static std::string exception_code_to_name(uint32_t code);
    static std::string format_timestamp();
};

c_mcp_events& get_events();
