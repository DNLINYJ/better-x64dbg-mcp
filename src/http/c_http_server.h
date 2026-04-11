#pragma once

#include <string>
#include <thread>
#include <atomic>
#include <expected>
#include <cstdint>
#include <mutex>
#include <condition_variable>

#include <winsock2.h>
#include <ws2tcpip.h>

#include "mcp/c_mcp_dispatcher.h"
#include "mcp/c_mcp_session.h"

class c_http_server {
public:
    c_http_server() = default;
    ~c_http_server();

    c_http_server(const c_http_server&) = delete;
    c_http_server& operator=(const c_http_server&) = delete;

    [[nodiscard]] std::expected<void, std::string> start(
        const std::string& host, uint16_t port,
        c_mcp_dispatcher* dispatcher, c_mcp_session* session_mgr
    );

    void stop();

    [[nodiscard]] bool is_running() const { return m_running.load(); }
    [[nodiscard]] uint16_t get_port() const { return m_port; }

private:
    static constexpr size_t MAX_REQUEST_SIZE = 1024 * 1024;
    static constexpr int RECV_TIMEOUT_MS = 5000;
    static constexpr int MAX_CONNECTIONS = 64;
    static constexpr int SHUTDOWN_DRAIN_TIMEOUT_MS = 35000;
    static constexpr int PORT_RETRY_COUNT = 10;

    SOCKET m_listen_socket = INVALID_SOCKET;
    std::atomic<bool> m_running{false};
    std::thread m_listener_thread;
    c_mcp_dispatcher* m_dispatcher = nullptr;
    c_mcp_session* m_session_mgr = nullptr;
    uint16_t m_port = 0;

    // Connection tracking for graceful shutdown
    std::atomic<int> m_active_connections{0};
    std::mutex m_conn_mutex;
    std::condition_variable m_conn_cv;

    void listener_loop();
    void handle_connection(SOCKET client_socket);

    // HTTP request parsing
    struct s_parsed_request {
        std::string method;
        std::string path;
        std::unordered_map<std::string, std::string> headers;
        std::string body;
    };

    [[nodiscard]] static std::expected<s_parsed_request, std::string> parse_request(const std::string& raw);

    // HTTP response helpers
    static void send_response(SOCKET sock, int status, const std::string& content_type,
                              const std::string& body, const std::string& extra_headers = "");
    static void send_error(SOCKET sock, int status, const std::string& message);
};
