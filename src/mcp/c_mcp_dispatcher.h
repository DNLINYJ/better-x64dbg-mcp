#pragma once

#include <string>
#include <nlohmann/json.hpp>
#include "mcp/c_mcp_session.h"

class c_mcp_dispatcher {
public:
    c_mcp_dispatcher() = default;

    void set_session_manager(c_mcp_session* session_mgr) { m_session_mgr = session_mgr; }

    // Handle a JSON-RPC request (from POST /mcp)
    // Returns the JSON-RPC response to send back.
    // session_id is extracted from Mcp-Session-Id header (empty if not present).
    // new_session_id is set if initialize creates a new session.
    struct s_result {
        nlohmann::json response;        // JSON-RPC response body
        std::string new_session_id;     // Non-empty if a new session was created
        bool is_notification = false;   // True if this was a notification (no response needed)
    };

    [[nodiscard]] s_result handle_request(const std::string& body, const std::string& session_id);

private:
    c_mcp_session* m_session_mgr = nullptr;

    [[nodiscard]] nlohmann::json handle_initialize(const nlohmann::json& params, const nlohmann::json& id);
    [[nodiscard]] nlohmann::json handle_ping(const nlohmann::json& id);
    [[nodiscard]] nlohmann::json handle_tools_list(const nlohmann::json& id);
    [[nodiscard]] nlohmann::json handle_tools_call(const nlohmann::json& params, const nlohmann::json& id);

    static nlohmann::json make_error(const nlohmann::json& id, int code, const std::string& message);
    static nlohmann::json make_result(const nlohmann::json& id, const nlohmann::json& result);
};
