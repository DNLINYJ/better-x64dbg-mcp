#pragma once

#include <string>
#include <mutex>
#include <map>
#include <vector>
#include <random>
#include <atomic>
#include <memory>

#include <winsock2.h>
#include <nlohmann/json.hpp>

class c_mcp_session {
public:
    c_mcp_session() = default;
    ~c_mcp_session() = default;

    c_mcp_session(const c_mcp_session&) = delete;
    c_mcp_session& operator=(const c_mcp_session&) = delete;

    // Create a new session, return session ID
    [[nodiscard]] std::string create_session();

    // Check if a session exists
    [[nodiscard]] bool has_session(const std::string& session_id) const;

    // Delete a session and close its SSE socket if any
    void delete_session(const std::string& session_id);

    // Register an SSE socket for a session (GET /mcp)
    void register_sse(const std::string& session_id, SOCKET sock);

    // Unregister and close an SSE socket (client disconnected).
    // Returns the socket that was unregistered (already closed), or INVALID_SOCKET.
    void unregister_sse(const std::string& session_id);

    // Push a JSON-RPC notification to all sessions with active SSE
    void broadcast_event(const nlohmann::json& notification);

    // Push a JSON-RPC notification to a specific session
    void push_event(const std::string& session_id, const nlohmann::json& notification);

    // Close all SSE sockets (called on server stop)
    void close_all();

    // Mark session as initialized (MCP initialize handshake done)
    void mark_initialized(const std::string& session_id);
    [[nodiscard]] bool is_initialized(const std::string& session_id) const;

private:
    // Per-SSE-connection state with its own mutex.
    // This allows broadcast_event to release the global session mutex before
    // sending, preventing a stalled SSE client from blocking session operations.
    struct s_sse_connection {
        std::mutex mutex;
        SOCKET socket = INVALID_SOCKET;
    };

    struct s_session {
        std::string id;
        std::shared_ptr<s_sse_connection> sse_conn;
        bool initialized = false;
    };

    mutable std::mutex m_mutex;
    std::map<std::string, s_session> m_sessions;

    [[nodiscard]] static std::string generate_id();
    bool send_sse_data(SOCKET sock, const std::string& data);
};
