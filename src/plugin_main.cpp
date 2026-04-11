#include "plugin_main.h"

#include <string>
#include <cstdio>
#include <cstring>

#include "resources/plugin_icon.h"
#include "ui/settings_dialog.h"
#include "ui/about_dialog.h"

// Globals
static int g_plugin_handle = -1;
static int g_menu_handle = -1;
static HWND g_hwnd_dlg = nullptr;
static c_http_server g_server;
static c_mcp_dispatcher g_dispatcher;
static c_mcp_session g_session_mgr;
static c_mcp_events g_events;
static s_plugin_settings g_settings;

// ============================================================================
// Menu helpers
// ============================================================================

static void update_menu_state() {
    const bool running = g_server.is_running();
    _plugin_menuentrysetchecked(g_plugin_handle, menu_start_server, running);
    _plugin_menuentrysetchecked(g_plugin_handle, menu_stop_server, !running);
}

// ============================================================================
// Settings persistence
// ============================================================================

static void load_settings() {
    char buf[256];
    if (BridgeSettingGet(SETTINGS_SECTION, SETTINGS_KEY_HOST, buf))
        strncpy_s(g_settings.host, buf, _TRUNCATE);

    duint port_val = 0;
    if (BridgeSettingGetUint(SETTINGS_SECTION, SETTINGS_KEY_PORT, &port_val))
        if (port_val >= 1 && port_val <= 65535)
            g_settings.port = static_cast<uint16_t>(port_val);

    duint autostart_val = 0;
    if (BridgeSettingGetUint(SETTINGS_SECTION, SETTINGS_KEY_AUTOSTART, &autostart_val))
        g_settings.auto_start = (autostart_val != 0);
}

static void save_settings() {
    BridgeSettingSet(SETTINGS_SECTION, SETTINGS_KEY_HOST, g_settings.host);
    BridgeSettingSetUint(SETTINGS_SECTION, SETTINGS_KEY_PORT, g_settings.port);
    BridgeSettingSetUint(SETTINGS_SECTION, SETTINGS_KEY_AUTOSTART, g_settings.auto_start ? 1 : 0);
    BridgeSettingFlush();
}

// ============================================================================
// Server start/stop
// ============================================================================

static bool start_server() {
    g_dispatcher.set_session_manager(&g_session_mgr);
    auto result = g_server.start(g_settings.host, g_settings.port, &g_dispatcher, &g_session_mgr);
    if (result.has_value()) {
        g_events.start(&g_session_mgr);
        return true;
    }
    _plugin_logprintf("[MCP] Failed to start server: %s\n", result.error().c_str());
    return false;
}

static void stop_server() {
    g_events.stop();
    g_server.stop();
}

// ============================================================================
// Command handler
// ============================================================================

static bool mcp_server_command(int argc, char* argv[]) {
    if (argc < 2) {
        _plugin_logputs("[MCP] Usage: mcpserver <start|stop|status>");
        return false;
    }
    std::string sub = argv[1];
    if (sub == "start") {
        if (g_server.is_running()) { _plugin_logputs("[MCP] Server is already running"); return true; }
        if (start_server()) {
            _plugin_logprintf("[MCP] Server started on %s:%u\n", g_settings.host, g_server.get_port());
            if (g_server.get_port() != g_settings.port)
                _plugin_logprintf("[MCP] Note: configured port %u was in use, fell back to %u\n", g_settings.port, g_server.get_port());
        }
        update_menu_state();
        return g_server.is_running();
    }
    if (sub == "stop") {
        if (!g_server.is_running()) { _plugin_logputs("[MCP] Server is not running"); return true; }
        stop_server();
        _plugin_logputs("[MCP] Server stopped");
        update_menu_state();
        return true;
    }
    if (sub == "status") {
        if (g_server.is_running())
            _plugin_logprintf("[MCP] Server is running on %s:%u\n", g_settings.host, g_server.get_port());
        else
            _plugin_logputs("[MCP] Server is not running");
        return true;
    }
    _plugin_logputs("[MCP] Unknown subcommand. Usage: mcpserver <start|stop|status>");
    return false;
}

// ============================================================================
// Plugin exports
// ============================================================================

PLUG_EXPORT bool pluginit(PLUG_INITSTRUCT* init_struct) {
    init_struct->sdkVersion = PLUG_SDKVERSION;
    init_struct->pluginVersion = PLUGIN_VERSION;
    strncpy_s(init_struct->pluginName, PLUGIN_NAME, _TRUNCATE);
    g_plugin_handle = init_struct->pluginHandle;
    _plugin_registercommand(g_plugin_handle, "mcpserver", mcp_server_command, false);
    return true;
}

PLUG_EXPORT bool plugstop() {
    _plugin_unregistercommand(g_plugin_handle, "mcpserver");
    stop_server();
    _plugin_logputs("[MCP] Plugin stopped");
    return true;
}

PLUG_EXPORT void plugsetup(PLUG_SETUPSTRUCT* setup_struct) {
    g_hwnd_dlg = setup_struct->hwndDlg;
    g_menu_handle = setup_struct->hMenu;

    load_settings();

    // Menu icon
    ICONDATA icon_data;
    icon_data.data = plugin_icon::png_data;
    icon_data.size = plugin_icon::png_size;
    _plugin_menuseticon(g_menu_handle, &icon_data);

    // Menu entries
    _plugin_menuaddentry(g_menu_handle, menu_start_server, "Start Server");
    _plugin_menuaddentry(g_menu_handle, menu_stop_server, "Stop Server");
    _plugin_menuaddseparator(g_menu_handle);
    _plugin_menuaddentry(g_menu_handle, menu_settings, "Settings...");
    _plugin_menuaddentry(g_menu_handle, menu_about, "About...");

    // Auto-start
    if (g_settings.auto_start) {
        if (start_server()) {
            _plugin_logprintf("[MCP] x64dbg MCP Server started on %s:%u (Streamable HTTP)\n", g_settings.host, g_server.get_port());
            _plugin_logprintf("[MCP] Connect: http://%s:%u/mcp\n", g_settings.host, g_server.get_port());
            if (g_server.get_port() != g_settings.port)
                _plugin_logprintf("[MCP] Note: configured port %u was in use, fell back to %u\n", g_settings.port, g_server.get_port());
        } else {
            _plugin_logputs("[MCP] Use 'mcpserver start' to retry");
        }
    } else {
        _plugin_logputs("[MCP] Auto-start disabled. Use 'mcpserver start' or menu to start.");
    }

    update_menu_state();
}

PLUG_EXPORT void CBMENUENTRY(CBTYPE, void* call_info) {
    auto* info = static_cast<PLUG_CB_MENUENTRY*>(call_info);
    switch (info->hEntry) {
    case menu_start_server:
        if (g_server.is_running()) {
            _plugin_logputs("[MCP] Server is already running");
        } else if (start_server()) {
            _plugin_logprintf("[MCP] Server started on %s:%u\n", g_settings.host, g_server.get_port());
            if (g_server.get_port() != g_settings.port)
                _plugin_logprintf("[MCP] Note: configured port %u was in use, fell back to %u\n", g_settings.port, g_server.get_port());
        }
        update_menu_state();
        break;
    case menu_stop_server:
        if (!g_server.is_running()) {
            _plugin_logputs("[MCP] Server is not running");
        } else {
            stop_server();
            _plugin_logputs("[MCP] Server stopped");
        }
        update_menu_state();
        break;
    case menu_settings: {
        const auto old_host = std::string(g_settings.host);
        const auto old_port = g_settings.port;
        if (show_settings_dialog(g_hwnd_dlg, g_settings) == IDOK) {
            save_settings();
            _plugin_logputs("[MCP] Settings saved");
            if (g_server.is_running() && (old_host != g_settings.host || old_port != g_settings.port)) {
                stop_server();
                if (start_server()) {
                    _plugin_logprintf("[MCP] Server restarted on %s:%u\n", g_settings.host, g_server.get_port());
                    if (g_server.get_port() != g_settings.port)
                        _plugin_logprintf("[MCP] Note: configured port %u was in use, fell back to %u\n", g_settings.port, g_server.get_port());
                }
                update_menu_state();
            }
        }
        break;
    }
    case menu_about:
        show_about_dialog(g_hwnd_dlg, g_server.is_running(), g_settings.host, g_server.get_port());
        break;
    }
}

// ============================================================================
// x64dbg Event Callbacks
// ============================================================================

PLUG_EXPORT void CBBREAKPOINT(CBTYPE, void* info) {
    g_events.on_breakpoint(static_cast<PLUG_CB_BREAKPOINT*>(info));
}

PLUG_EXPORT void CBPAUSEDEBUG(CBTYPE, void* info) {
    g_events.on_pause(static_cast<PLUG_CB_PAUSEDEBUG*>(info));
}

PLUG_EXPORT void CBEXCEPTION(CBTYPE, void* info) {
    g_events.on_exception(static_cast<PLUG_CB_EXCEPTION*>(info));
}

PLUG_EXPORT void CBSTEPPED(CBTYPE, void* info) {
    g_events.on_stepped(static_cast<PLUG_CB_STEPPED*>(info));
}

PLUG_EXPORT void CBSTOPDEBUG(CBTYPE, void* info) {
    g_events.on_stop_debug(static_cast<PLUG_CB_STOPDEBUG*>(info));
}

PLUG_EXPORT void CBCREATEPROCESS(CBTYPE, void* info) {
    g_events.on_create_process(static_cast<PLUG_CB_CREATEPROCESS*>(info));
}

PLUG_EXPORT void CBEXITPROCESS(CBTYPE, void* info) {
    g_events.on_exit_process(static_cast<PLUG_CB_EXITPROCESS*>(info));
}

PLUG_EXPORT void CBLOADDLL(CBTYPE, void* info) {
    g_events.on_load_dll(static_cast<PLUG_CB_LOADDLL*>(info));
}

PLUG_EXPORT void CBUNLOADDLL(CBTYPE, void* info) {
    g_events.on_unload_dll(static_cast<PLUG_CB_UNLOADDLL*>(info));
}
