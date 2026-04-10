#pragma once

#include <winsock2.h>  // Must precede any transitive windows.h include

#include "_plugins.h"
#include "mcp/c_mcp_session.h"

#include <queue>
#include <mutex>
#include <thread>
#include <atomic>
#include <condition_variable>

#include <nlohmann/json.hpp>

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

private:
    c_mcp_session* m_session_mgr = nullptr;
    std::atomic<bool> m_running{false};
    std::thread m_push_thread;

    std::mutex m_queue_mutex;
    std::condition_variable m_queue_cv;
    std::queue<nlohmann::json> m_event_queue;

    void push_loop();
    void enqueue(nlohmann::json event);
};
