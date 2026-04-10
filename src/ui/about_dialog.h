#pragma once

#include <cstdint>
#include <windows.h>

void show_about_dialog(HWND parent, bool is_server_running, const char* host, uint16_t port);
