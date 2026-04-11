#include "handlers/debug_handler.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"
#include "_dbgfunctions.h"

#include <thread>
#include <chrono>
#include <mutex>

namespace handlers::debug {

// ---- Launch-time session state ----
// Captured once per debug session (from CBINITDEBUG and CBCREATEPROCESS callbacks)
// and consumed by restart_debug() to faithfully reproduce the original launch.
static std::mutex  s_launch_mutex;
static std::string s_launch_target;  // Original file passed to InitDebug (EXE or DLL)
static std::string s_launch_cwd;     // Working directory at process creation (UTF-8)
static bool        s_is_attached = false;  // True when session was started via AttachDebugger

// Read PEB->ProcessParameters->CurrentDirectory from the freshly-created debuggee.
// Must only be called while the debuggee is alive and before user code runs.
static std::string read_peb_cwd() {
    auto& bridge = get_bridge();
    if (!bridge.is_valid_expression("peb()")) return {};
    auto peb = bridge.eval_expression("peb()");
    if (peb == 0) return {};

#ifdef _WIN64
    constexpr duint off_params = 0x20;
    constexpr duint off_len    = 0x38;
    constexpr duint off_buf    = 0x40;
    constexpr size_t ptr_size  = 8;
#else
    constexpr duint off_params = 0x10;
    constexpr duint off_len    = 0x24;
    constexpr duint off_buf    = 0x28;
    constexpr size_t ptr_size  = 4;
#endif

    auto params_raw = bridge.read_memory(peb + off_params, ptr_size);
    if (!params_raw.has_value()) return {};
    duint params = 0;
    memcpy(&params, params_raw->data(), ptr_size);
    if (params == 0) return {};

    auto len_raw = bridge.read_memory(params + off_len, 2);
    if (!len_raw.has_value()) return {};
    uint16_t byte_len = 0;
    memcpy(&byte_len, len_raw->data(), 2);
    if (byte_len == 0 || byte_len > 0x1000) return {};

    auto buf_raw = bridge.read_memory(params + off_buf, ptr_size);
    if (!buf_raw.has_value()) return {};
    duint buf_ptr = 0;
    memcpy(&buf_ptr, buf_raw->data(), ptr_size);
    if (buf_ptr == 0) return {};

    auto wpath_raw = bridge.read_memory(buf_ptr, byte_len);
    if (!wpath_raw.has_value()) return {};

    int wchar_count = static_cast<int>(byte_len / sizeof(wchar_t));
    auto* wstr = reinterpret_cast<const wchar_t*>(wpath_raw->data());
    int needed = WideCharToMultiByte(CP_UTF8, 0, wstr, wchar_count, nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return {};
    std::string result(static_cast<size_t>(needed), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr, wchar_count, result.data(), needed, nullptr, nullptr);

    // Strip trailing separator, but preserve drive-root paths like "C:\"
    while (result.size() > 3 && (result.back() == '\\' || result.back() == '/'))
        result.pop_back();

    return result;
}

void capture_launch_target(const char* file_name) {
    if (!file_name || file_name[0] == '\0') return;
    std::lock_guard lock(s_launch_mutex);
    s_launch_target = file_name;
}

void mark_attached() {
    std::lock_guard lock(s_launch_mutex);
    s_is_attached = true;
}

void capture_launch_cwd() {
    auto dir = read_peb_cwd();
    std::lock_guard lock(s_launch_mutex);
    s_launch_cwd = std::move(dir);
}

void clear_launch_state() {
    std::lock_guard lock(s_launch_mutex);
    s_launch_target.clear();
    s_launch_cwd.clear();
    s_is_attached = false;
}

nlohmann::json state() {
    auto& bridge = get_bridge();
    auto s = bridge.get_state_string();
    nlohmann::json data = {{"state", s}};
    if (bridge.is_debugging() && !bridge.is_running()) {
        auto cip = bridge.eval_expression("cip");
        data["cip"] = format_utils::format_address(cip);
        auto mod = bridge.get_module_at(cip);
        if (!mod.empty()) data["module"] = mod;
        auto label = bridge.get_label_at(cip);
        if (!label.empty()) data["label"] = label;
    }
    return data;
}

nlohmann::json run() {
    auto& bridge = get_bridge();
    if (!bridge.require_paused()) throw std::runtime_error("Debugger must be paused");
    bridge.exec_command("run");
    return {{"message", "Execution resumed"}};
}

nlohmann::json pause() {
    auto& bridge = get_bridge();
    if (!bridge.is_debugging()) throw std::runtime_error("No active debug session");
    if (!bridge.is_running()) return {{"message", "Already paused"}};
    bridge.exec_command("pause");
    return {{"message", "Pause requested"}};
}

nlohmann::json force_pause() {
    auto& bridge = get_bridge();
    if (!bridge.is_debugging()) throw std::runtime_error("No active debug session");
    if (!bridge.is_running()) return {{"message", "Already paused"}};
    std::vector<std::string> fast_resume_addrs;
    for (auto type : {bp_normal, bp_hardware, bp_memory}) {
        auto bps = bridge.get_breakpoint_list(type);
        if (!bps.has_value()) continue;
        for (const auto& bp : bps.value()) {
            if (bp.value("fast_resume", false)) {
                auto addr_str = bp["address"].get<std::string>();
                fast_resume_addrs.push_back(addr_str);
                bridge.exec_command("SetBreakpointFastResume " + addr_str + ", 0");
            }
        }
    }
    bridge.exec_command("pause");
    bool paused = false;
    for (int i = 0; i < 300 && !paused; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        paused = !bridge.is_running();
    }
    for (const auto& addr_str : fast_resume_addrs) {
        bridge.exec_command("SetBreakpointFastResume " + addr_str + ", 1");
    }
    if (!paused) throw std::runtime_error("Force pause timed out after 3s");
    return {{"message", "Debuggee forcefully paused"}, {"fast_resume_count", fast_resume_addrs.size()}};
}

nlohmann::json step_into() {
    auto& bridge = get_bridge();
    if (!bridge.require_paused()) throw std::runtime_error("Debugger must be paused");
    if (!bridge.exec_command_and_wait("StepInto")) throw std::runtime_error("Step into timed out");
    auto cip = bridge.eval_expression("cip");
    return {{"cip", format_utils::format_address(cip)}, {"message", "Stepped into"}};
}

nlohmann::json step_over() {
    auto& bridge = get_bridge();
    if (!bridge.require_paused()) throw std::runtime_error("Debugger must be paused");
    if (!bridge.exec_command_and_wait("StepOver")) throw std::runtime_error("Step over timed out");
    auto cip = bridge.eval_expression("cip");
    return {{"cip", format_utils::format_address(cip)}, {"message", "Stepped over"}};
}

nlohmann::json step_out() {
    auto& bridge = get_bridge();
    if (!bridge.require_paused()) throw std::runtime_error("Debugger must be paused");
    if (!bridge.exec_command_and_wait("StepOut", 30000)) throw std::runtime_error("Step out timed out");
    auto cip = bridge.eval_expression("cip");
    return {{"cip", format_utils::format_address(cip)}, {"message", "Stepped out"}};
}

nlohmann::json stop_debug() {
    auto& bridge = get_bridge();
    if (!bridge.is_debugging()) return {{"message", "Not debugging"}};
    bridge.exec_command("stop");
    return {{"message", "Debug session stopped"}};
}

nlohmann::json restart_debug() {
    auto& bridge = get_bridge();
    if (!bridge.is_debugging()) throw std::runtime_error("No active debug session");

    // Attached sessions cannot be restarted — the process was not launched by x64dbg,
    // so there is no InitDebug invocation to replay.
    std::string target_path;
    std::string work_dir;
    {
        std::lock_guard lock(s_launch_mutex);
        if (s_is_attached)
            throw std::runtime_error("Cannot restart an attached process. Detach and re-attach instead.");
        target_path = s_launch_target;
        work_dir = s_launch_cwd;
    }

    // Fallback: resolve from main module if CBINITDEBUG was never received
    if (target_path.empty()) {
        auto main_base = bridge.eval_expression("mod.main()");
        char path[MAX_PATH] = {};
        DbgFunctions()->ModPathFromAddr(main_base, path, MAX_PATH);
        if (path[0] == '\0') throw std::runtime_error("Cannot determine debuggee path");
        target_path = path;
    }

    // Fallback working directory: parent of the target file
    if (work_dir.empty()) {
        auto sep = target_path.find_last_of("\\/");
        if (sep != std::string::npos) work_dir = target_path.substr(0, sep);
    }

    // Save command line (may contain arbitrary quotes/special chars)
    size_t cmdline_size = 0;
    DbgFunctions()->GetCmdline(nullptr, &cmdline_size);
    std::string cmdline;
    if (cmdline_size > 0) {
        cmdline.resize(cmdline_size);
        DbgFunctions()->GetCmdline(cmdline.data(), &cmdline_size);
        while (!cmdline.empty() && cmdline.back() == '\0') cmdline.pop_back();
    }

    // Stop current debug session and wait for it to end
    bridge.exec_command("stop");
    for (int i = 0; i < 300 && bridge.is_debugging(); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    if (bridge.is_debugging()) throw std::runtime_error("Failed to stop current debug session");

    // Re-init: pass original target and working directory via InitDebug.
    // x64dbg's cbDebugInit analyzes the PE header and automatically routes to the
    // DLL loader flow when the target is a DLL, so this works for both EXE and DLL sessions.
    // Leave cmdline empty here to avoid quote-escaping issues with the command parser.
    std::string init_cmd = "InitDebug \"" + target_path + "\", \"\"";
    if (!work_dir.empty()) init_cmd += ", \"" + work_dir + "\"";
    if (!bridge.exec_command(init_cmd))
        throw std::runtime_error("InitDebug command failed for " + target_path);

    // Wait for the new session to actually start
    for (int i = 0; i < 300 && !bridge.is_debugging(); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    if (!bridge.is_debugging())
        throw std::runtime_error("Debug session did not start after InitDebug");

    // Restore command line via API (bypasses command parser, no escaping needed)
    nlohmann::json warnings = nlohmann::json::array();
    if (!cmdline.empty() && !DbgFunctions()->SetCmdline(cmdline.c_str()))
        warnings.push_back("Failed to restore command line");

    nlohmann::json result = {{"message", "Restart initiated"}, {"path", target_path}, {"working_directory", work_dir}};
    if (!warnings.empty()) result["warnings"] = warnings;
    return result;
}

nlohmann::json run_to_address(const std::string& address) {
    auto& bridge = get_bridge();
    if (!bridge.require_paused()) throw std::runtime_error("Debugger must be paused");
    bridge.exec_command("bp " + address + ", ss");
    bridge.exec_command("run");
    return {{"message", "Running to " + address}, {"target", address}};
}

} // namespace handlers::debug
