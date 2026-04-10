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
    std::lock_guard lock(m_mutex);
    auto it = m_sessions.find(session_id);
    if (it == m_sessions.end()) return;
    if (it->second.sse_socket != INVALID_SOCKET) {
        closesocket(it->second.sse_socket);
    }
    m_sessions.erase(it);
}

void c_mcp_session::register_sse(const std::string& session_id, SOCKET sock) {
    std::lock_guard lock(m_mutex);
    auto it = m_sessions.find(session_id);
    if (it == m_sessions.end()) return;
    if (it->second.sse_socket != INVALID_SOCKET) {
        closesocket(it->second.sse_socket);
    }
    it->second.sse_socket = sock;
}

void c_mcp_session::unregister_sse(const std::string& session_id) {
    std::lock_guard lock(m_mutex);
    auto it = m_sessions.find(session_id);
    if (it == m_sessions.end()) return;
    if (it->second.sse_socket != INVALID_SOCKET) {
        closesocket(it->second.sse_socket);
        it->second.sse_socket = INVALID_SOCKET;
    }
}

void c_mcp_session::broadcast_event(const nlohmann::json& notification) {
    // Hold lock during sends to prevent TOCTOU race: without this, a socket handle
    // could be closed by unregister_sse() and reused by the OS for a different socket
    // between the snapshot and the send, causing data to be sent to the wrong client.
    // SSE messages are small and sockets have send timeouts, so contention is bounded.
    auto payload = notification.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
    std::lock_guard lock(m_mutex);
    for (auto& [id, session] : m_sessions) {
        if (session.sse_socket != INVALID_SOCKET) {
            if (!send_sse_data(session.sse_socket, payload)) {
                closesocket(session.sse_socket);
                session.sse_socket = INVALID_SOCKET;
            }
        }
    }
}

void c_mcp_session::push_event(const std::string& session_id, const nlohmann::json& notification) {
    auto payload = notification.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
    std::lock_guard lock(m_mutex);
    auto it = m_sessions.find(session_id);
    if (it == m_sessions.end()) return;
    if (it->second.sse_socket == INVALID_SOCKET) return;
    if (!send_sse_data(it->second.sse_socket, payload)) {
        closesocket(it->second.sse_socket);
        it->second.sse_socket = INVALID_SOCKET;
    }
}

void c_mcp_session::close_all() {
    std::lock_guard lock(m_mutex);
    for (auto& [id, session] : m_sessions) {
        if (session.sse_socket != INVALID_SOCKET) {
            closesocket(session.sse_socket);
            session.sse_socket = INVALID_SOCKET;
        }
    }
    m_sessions.clear();
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
