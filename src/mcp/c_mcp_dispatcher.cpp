#include "mcp/c_mcp_dispatcher.h"
#include "mcp/c_mcp_tools.h"
#include "plugin_main.h"

using json = nlohmann::json;

c_mcp_dispatcher::s_result c_mcp_dispatcher::handle_request(const std::string& body, const std::string& session_id) {
    s_result result;

    json request;
    try {
        request = json::parse(body);
    } catch (...) {
        result.response = make_error(nullptr, -32700, "Parse error");
        return result;
    }

    // Validate JSON-RPC 2.0
    if (!request.contains("jsonrpc") || request["jsonrpc"] != "2.0") {
        result.response = make_error(request.value("id", json(nullptr)), -32600, "Invalid Request: missing jsonrpc 2.0");
        return result;
    }

    if (!request.contains("method") || !request["method"].is_string()) {
        result.response = make_error(request.value("id", json(nullptr)), -32600, "Invalid Request: missing method");
        return result;
    }

    auto method = request["method"].get<std::string>();
    auto id = request.value("id", json(nullptr));
    auto params = request.value("params", json::object());

    // Check if this is a notification (no id field)
    bool is_notification = !request.contains("id");

    // Handle notifications (no response expected)
    if (is_notification) {
        // notifications/initialized - client acknowledges initialization
        if (method == "notifications/initialized") {
            if (m_session_mgr && !session_id.empty()) {
                m_session_mgr->mark_initialized(session_id);
            }
        }
        result.is_notification = true;
        return result;
    }

    // Session validation: after initialize, all requests must include a valid session ID
    if (method != "initialize") {
        if (session_id.empty() || (m_session_mgr && !m_session_mgr->has_session(session_id))) {
            result.response = make_error(id, -32600, "Invalid or missing Mcp-Session-Id");
            return result;
        }
    }

    // Dispatch method
    if (method == "initialize") {
        result.response = handle_initialize(params, id);
        // Create session
        if (m_session_mgr) {
            result.new_session_id = m_session_mgr->create_session();
        }
    }
    else if (method == "ping") {
        result.response = handle_ping(id);
    }
    else if (method == "tools/list") {
        result.response = handle_tools_list(id);
    }
    else if (method == "tools/call") {
        result.response = handle_tools_call(params, id);
    }
    else {
        result.response = make_error(id, -32601, "Method not found: " + method);
    }

    return result;
}

json c_mcp_dispatcher::handle_initialize(const json& /*params*/, const json& id) {
    json server_info = {
        {"name", PLUGIN_NAME},
        {"version", PLUGIN_VERSION_STR}
    };

    json capabilities = {
        {"tools", json::object()},       // We support tools
        {"logging", json::object()}      // We support logging
    };

    json result = {
        {"protocolVersion", "2025-03-26"},
        {"capabilities", capabilities},
        {"serverInfo", server_info}
    };

    return make_result(id, result);
}

json c_mcp_dispatcher::handle_ping(const json& id) {
    return make_result(id, json::object());
}

json c_mcp_dispatcher::handle_tools_list(const json& id) {
    json result = {
        {"tools", mcp_tools::build_tools_list()}
    };
    return make_result(id, result);
}

json c_mcp_dispatcher::handle_tools_call(const json& params, const json& id) {
    if (!params.contains("name") || !params["name"].is_string()) {
        return make_error(id, -32602, "Invalid params: missing 'name'");
    }

    auto tool_name = params["name"].get<std::string>();
    auto arguments = params.value("arguments", json::object());

    try {
        auto tool_result = mcp_tools::dispatch_tool_call(tool_name, arguments);
        // MCP tools/call result format
        json content = json::array();
        content.push_back({
            {"type", "text"},
            {"text", tool_result.dump(2)}
        });
        return make_result(id, {{"content", content}});
    } catch (const std::exception& e) {
        // Tool execution error - return as tool result with isError flag
        json content = json::array();
        content.push_back({
            {"type", "text"},
            {"text", std::string("Error: ") + e.what()}
        });
        return make_result(id, {{"content", content}, {"isError", true}});
    }
}

json c_mcp_dispatcher::make_error(const json& id, int code, const std::string& message) {
    return {
        {"jsonrpc", "2.0"},
        {"id", id},
        {"error", {{"code", code}, {"message", message}}}
    };
}

json c_mcp_dispatcher::make_result(const json& id, const json& result) {
    return {
        {"jsonrpc", "2.0"},
        {"id", id},
        {"result", result}
    };
}
