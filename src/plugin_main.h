#pragma once

#include <winsock2.h>  // Must precede any transitive windows.h include

#include "_plugins.h"
#include "http/c_http_server.h"
#include "mcp/c_mcp_dispatcher.h"
#include "mcp/c_mcp_session.h"
#include "mcp/c_mcp_events.h"

// Plugin info
constexpr auto PLUGIN_NAME = "x64dbg MCP Server";
constexpr auto PLUGIN_VERSION = 1;
constexpr auto PLUGIN_VERSION_STR = "1.0.0";
constexpr auto PLUGIN_REPO_URL = "https://github.com/anthropics/x64dbg-mcp";
constexpr uint16_t DEFAULT_PORT = 27042;
constexpr auto DEFAULT_HOST = "127.0.0.1";

// Settings keys
constexpr auto SETTINGS_SECTION = "MCP";
constexpr auto SETTINGS_KEY_HOST = "Host";
constexpr auto SETTINGS_KEY_PORT = "Port";
constexpr auto SETTINGS_KEY_AUTOSTART = "AutoStart";

struct s_plugin_settings {
    char host[64] = "127.0.0.1";
    uint16_t port = 27042;
    bool auto_start = true;
};

// Menu entries
enum e_menu_entry : int {
    menu_start_server = 0,
    menu_stop_server  = 1,
    menu_settings     = 2,
    menu_about        = 3
};

#ifndef PLUG_EXPORT
#define PLUG_EXPORT extern "C" __declspec(dllexport)
#endif
