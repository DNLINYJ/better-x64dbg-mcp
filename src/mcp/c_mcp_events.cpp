#include "mcp/c_mcp_events.h"
#include "util/format_utils.h"

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
    nlohmann::json event = {
        {"jsonrpc", "2.0"},
        {"method", "notifications/x64dbg/exception"},
        {"params", {
            {"code",          format_utils::format_address(exc.ExceptionCode)},
            {"address",       format_utils::format_address(reinterpret_cast<duint>(exc.ExceptionAddress))},
            {"first_chance",  info->Exception->dwFirstChance != 0},
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
    nlohmann::json event = {
        {"jsonrpc", "2.0"},
        {"method", "notifications/x64dbg/process_exited"},
        {"params", {
            {"exit_code", info->ExitProcess->dwExitCode}
        }}
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
