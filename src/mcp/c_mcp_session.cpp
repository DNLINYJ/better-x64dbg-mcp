#include "mcp/c_mcp_session.h"

#include <sstream>
#include <iomanip>
#include <chrono>

std::string c_mcp_session::create_session() {
    std::lock_guard lock(m_mutex);
    auto id = generate_id();
    s_session session;
    session.id = id;
    m_sessions[id] = std::move(session);
    return id;
}

bool c_mcp_session::has_session(const std::string& session_id) const {
    std::lock_guard lock(m_mutex);
    return m_sessions.contains(session_id);
}

void c_mcp_session::delete_session(const std::string& session_id) {
    std::shared_ptr<s_sse_connection> conn;
    {
        std::lock_guard lock(m_mutex);
        auto it = m_sessions.find(session_id);
        if (it == m_sessions.end()) return;
        conn = it->second.sse_conn;
        m_sessions.erase(it);
    }
    if (conn) {
        std::lock_guard conn_lock(conn->mutex);
        if (conn->socket != INVALID_SOCKET) {
            closesocket(conn->socket);
            conn->socket = INVALID_SOCKET;
        }
    }
}

void c_mcp_session::register_sse(const std::string& session_id, SOCKET sock) {
    std::shared_ptr<s_sse_connection> old_conn;
    {
        std::lock_guard lock(m_mutex);
        auto it = m_sessions.find(session_id);
        if (it == m_sessions.end()) return;
        old_conn = it->second.sse_conn;
        auto new_conn = std::make_shared<s_sse_connection>();
        new_conn->socket = sock;
        it->second.sse_conn = new_conn;
    }
    if (old_conn) {
        std::lock_guard conn_lock(old_conn->mutex);
        if (old_conn->socket != INVALID_SOCKET) {
            closesocket(old_conn->socket);
            old_conn->socket = INVALID_SOCKET;
        }
    }
}

void c_mcp_session::unregister_sse(const std::string& session_id) {
    std::shared_ptr<s_sse_connection> conn;
    {
        std::lock_guard lock(m_mutex);
        auto it = m_sessions.find(session_id);
        if (it == m_sessions.end()) return;
        conn = it->second.sse_conn;
        it->second.sse_conn.reset();
    }
    if (conn) {
        std::lock_guard conn_lock(conn->mutex);
        if (conn->socket != INVALID_SOCKET) {
            closesocket(conn->socket);
            conn->socket = INVALID_SOCKET;
        }
    }
}

void c_mcp_session::broadcast_event(const nlohmann::json& notification) {
    auto payload = notification.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
    // Snapshot connection shared_ptrs under the global lock (fast), then release.
    // Each send is serialized by the per-connection mutex, so a stalled client
    // only blocks its own send, not session operations or other clients.
    std::vector<std::shared_ptr<s_sse_connection>> connections;
    {
        std::lock_guard lock(m_mutex);
        for (auto& [id, session] : m_sessions) {
            if (session.sse_conn) connections.push_back(session.sse_conn);
        }
    }
    for (auto& conn : connections) {
        std::lock_guard conn_lock(conn->mutex);
        if (conn->socket != INVALID_SOCKET) {
            if (!send_sse_data(conn->socket, payload)) {
                closesocket(conn->socket);
                conn->socket = INVALID_SOCKET;
            }
        }
    }
}

void c_mcp_session::push_event(const std::string& session_id, const nlohmann::json& notification) {
    auto payload = notification.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
    std::shared_ptr<s_sse_connection> conn;
    {
        std::lock_guard lock(m_mutex);
        auto it = m_sessions.find(session_id);
        if (it == m_sessions.end()) return;
        conn = it->second.sse_conn;
    }
    if (!conn) return;
    std::lock_guard conn_lock(conn->mutex);
    if (conn->socket != INVALID_SOCKET) {
        if (!send_sse_data(conn->socket, payload)) {
            closesocket(conn->socket);
            conn->socket = INVALID_SOCKET;
        }
    }
}

void c_mcp_session::close_all() {
    std::vector<std::shared_ptr<s_sse_connection>> connections;
    {
        std::lock_guard lock(m_mutex);
        for (auto& [id, session] : m_sessions) {
            if (session.sse_conn) connections.push_back(session.sse_conn);
        }
        m_sessions.clear();
    }
    for (auto& conn : connections) {
        std::lock_guard conn_lock(conn->mutex);
        if (conn->socket != INVALID_SOCKET) {
            closesocket(conn->socket);
            conn->socket = INVALID_SOCKET;
        }
    }
}

void c_mcp_session::mark_initialized(const std::string& session_id) {
    std::lock_guard lock(m_mutex);
    auto it = m_sessions.find(session_id);
    if (it != m_sessions.end()) {
        it->second.initialized = true;
    }
}

bool c_mcp_session::is_initialized(const std::string& session_id) const {
    std::lock_guard lock(m_mutex);
    auto it = m_sessions.find(session_id);
    if (it == m_sessions.end()) return false;
    return it->second.initialized;
}

std::string c_mcp_session::generate_id() {
    static std::mutex rng_mutex;
    static std::mt19937_64 rng(
        static_cast<uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count()));

    std::lock_guard lock(rng_mutex);
    std::uniform_int_distribution<uint64_t> dist;
    auto val1 = dist(rng);
    auto val2 = dist(rng);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0') << std::setw(16) << val1 << std::setw(16) << val2;
    return oss.str();
}

bool c_mcp_session::send_sse_data(SOCKET sock, const std::string& data) {
    std::string frame = "data: " + data + "\n\n";
    auto remaining = frame.size();
    size_t sent = 0;
    while (remaining > 0) {
        auto chunk = static_cast<int>(remaining > INT_MAX ? INT_MAX : remaining);
        auto result = send(sock, frame.c_str() + sent, chunk, 0);
        if (result == SOCKET_ERROR) return false;
        sent += static_cast<size_t>(result);
        remaining -= static_cast<size_t>(result);
    }
    return true;
}
