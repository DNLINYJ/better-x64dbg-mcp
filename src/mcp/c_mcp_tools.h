#pragma once

#include <nlohmann/json.hpp>

namespace mcp_tools {
    // Build the tools/list response (JSON array of tool definitions with JSON Schema)
    nlohmann::json build_tools_list();

    // Dispatch a tools/call request, return the result
    nlohmann::json dispatch_tool_call(const std::string& tool_name, const nlohmann::json& arguments);
}
