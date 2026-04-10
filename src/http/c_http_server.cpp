#include "http/c_http_server.h"

#include <algorithm>
#include <cctype>
#include <sstream>

#pragma comment(lib, "ws2_32.lib")

c_http_server::~c_http_server() {
    stop();
}

std::expected<void, std::string> c_http_server::start(
    const std::string& host, uint16_t port,
    c_mcp_dispatcher* dispatcher, c_mcp_session* session_mgr
) {
    if (m_running.load()) return std::unexpected("Server is already running");

    m_dispatcher = dispatcher;
    m_session_mgr = session_mgr;
    m_port = port;

    WSADATA wsa_data{};
    auto wsa_result = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (wsa_result != 0) return std::unexpected("WSAStartup failed: " + std::to_string(wsa_result));

    m_listen_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (m_listen_socket == INVALID_SOCKET) {
        auto err = WSAGetLastError();
        WSACleanup();
        return std::unexpected("socket() failed: " + std::to_string(err));
    }

    int opt_val = 1;
    setsockopt(m_listen_socket, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt_val), sizeof(opt_val));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host.c_str(), &addr.sin_addr);

    if (bind(m_listen_socket, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
        auto err = WSAGetLastError();
        closesocket(m_listen_socket);
        m_listen_socket = INVALID_SOCKET;
        WSACleanup();
        return std::unexpected("bind() failed: " + std::to_string(err));
    }

    if (listen(m_listen_socket, SOMAXCONN) == SOCKET_ERROR) {
        auto err = WSAGetLastError();
        closesocket(m_listen_socket);
        m_listen_socket = INVALID_SOCKET;
        WSACleanup();
        return std::unexpected("listen() failed: " + std::to_string(err));
    }

    m_running.store(true);
    m_listener_thread = std::thread(&c_http_server::listener_loop, this);
    return {};
}

void c_http_server::stop() {
    if (!m_running.load()) return;
    m_running.store(false);

    // Close all SSE connections — this wakes SSE handler threads so they can exit
    if (m_session_mgr) m_session_mgr->close_all();

    if (m_listen_socket != INVALID_SOCKET) {
        closesocket(m_listen_socket);
        m_listen_socket = INVALID_SOCKET;
    }
    if (m_listener_thread.joinable()) m_listener_thread.join();

    // Wait for active connection handler threads to finish before destroying state
    // they reference (dispatcher, session manager, etc.)
    {
        std::unique_lock lock(m_conn_mutex);
        m_conn_cv.wait_for(lock, std::chrono::milliseconds(SHUTDOWN_DRAIN_TIMEOUT_MS), [this] {
            return m_active_connections.load() == 0;
        });
    }

    WSACleanup();
}

void c_http_server::listener_loop() {
    while (m_running.load()) {
        fd_set read_set;
        FD_ZERO(&read_set);
        FD_SET(m_listen_socket, &read_set);

        timeval tv{};
        tv.tv_sec = 1;

        auto sel = select(0, &read_set, nullptr, nullptr, &tv);
        if (sel == SOCKET_ERROR) { if (!m_running.load()) break; continue; }
        if (sel == 0) continue;

        sockaddr_in client_addr{};
        int client_addr_len = sizeof(client_addr);
        SOCKET client = accept(m_listen_socket, reinterpret_cast<sockaddr*>(&client_addr), &client_addr_len);
        if (client == INVALID_SOCKET) { if (!m_running.load()) break; continue; }

        if (m_active_connections.load() >= MAX_CONNECTIONS) {
            closesocket(client);
            continue;
        }

        std::thread(&c_http_server::handle_connection, this, client).detach();
    }
}

void c_http_server::handle_connection(SOCKET client_socket) {
    // Track active connections for graceful shutdown and concurrency limiting.
    // The guard decrements the counter and notifies stop() when this thread exits.
    m_active_connections.fetch_add(1);
    struct s_conn_guard {
        c_http_server& server;
        ~s_conn_guard() {
            server.m_active_connections.fetch_sub(1);
            {
                std::lock_guard lock(server.m_conn_mutex);
            }
            server.m_conn_cv.notify_one();
        }
    } conn_guard{*this};

    // Timeouts
    DWORD timeout = RECV_TIMEOUT_MS;
    setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
    setsockopt(client_socket, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));

    int nodelay = 1;
    setsockopt(client_socket, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));

    // Read full request
    std::string raw_data;
    raw_data.reserve(4096);
    char buffer[4096];
    size_t content_length = 0;
    bool headers_complete = false;
    size_t header_end_pos = std::string::npos;

    while (true) {
        auto bytes_read = recv(client_socket, buffer, sizeof(buffer), 0);
        if (bytes_read <= 0) break;
        raw_data.append(buffer, static_cast<size_t>(bytes_read));

        if (!headers_complete) {
            header_end_pos = raw_data.find("\r\n\r\n");
            if (header_end_pos != std::string::npos) {
                headers_complete = true;
                // Case-insensitive search for Content-Length (HTTP headers are case-insensitive)
                std::string headers_lower = raw_data.substr(0, header_end_pos);
                std::transform(headers_lower.begin(), headers_lower.end(), headers_lower.begin(),
                              [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                auto cl_pos = headers_lower.find("content-length:");
                if (cl_pos != std::string::npos) {
                    auto val_start = cl_pos + 15;
                    auto val_end = raw_data.find("\r\n", val_start);
                    try {
                        content_length = std::stoull(raw_data.substr(val_start, val_end - val_start));
                    } catch (...) {
                        content_length = 0;
                    }
                }
            }
        }

        if (headers_complete) {
            auto body_start = header_end_pos + 4;
            if (raw_data.size() - body_start >= content_length) break;
        }
        if (raw_data.size() > MAX_REQUEST_SIZE) break;
    }

    auto parse_result = parse_request(raw_data);
    if (!parse_result.has_value()) {
        send_error(client_socket, 400, parse_result.error());
        shutdown(client_socket, SD_SEND);
        closesocket(client_socket);
        return;
    }

    const auto& req = parse_result.value();

    // CORS preflight
    if (req.method == "OPTIONS") {
        send_response(client_socket, 200, "text/plain", "",
            "Access-Control-Allow-Methods: GET, POST, DELETE, OPTIONS\r\n"
            "Access-Control-Allow-Headers: Content-Type, Mcp-Session-Id, Accept\r\n");
        shutdown(client_socket, SD_SEND);
        closesocket(client_socket);
        return;
    }

    // Only handle /mcp endpoint
    if (req.path != "/mcp") {
        send_error(client_socket, 404, "Not Found. Use /mcp endpoint.");
        shutdown(client_socket, SD_SEND);
        closesocket(client_socket);
        return;
    }

    // Extract session ID from header
    std::string session_id;
    auto sit = req.headers.find("mcp-session-id");
    if (sit != req.headers.end()) session_id = sit->second;

    // POST /mcp — JSON-RPC request
    if (req.method == "POST") {
        if (!m_dispatcher) {
            send_error(client_socket, 500, "Dispatcher not initialized");
            shutdown(client_socket, SD_SEND);
            closesocket(client_socket);
            return;
        }

        auto result = m_dispatcher->handle_request(req.body, session_id);

        if (result.is_notification) {
            // Notifications get 202 Accepted with no body
            send_response(client_socket, 202, "text/plain", "");
        } else {
            std::string extra;
            if (!result.new_session_id.empty()) {
                extra = "Mcp-Session-Id: " + result.new_session_id + "\r\n";
            }
            send_response(client_socket, 200, "application/json", result.response.dump(), extra);
        }

        shutdown(client_socket, SD_SEND);
        closesocket(client_socket);
        return;
    }

    // GET /mcp — SSE stream for server-initiated notifications
    if (req.method == "GET") {
        if (session_id.empty() || !m_session_mgr || !m_session_mgr->has_session(session_id)) {
            send_error(client_socket, 400, "Invalid or missing Mcp-Session-Id for SSE");
            shutdown(client_socket, SD_SEND);
            closesocket(client_socket);
            return;
        }

        // Send SSE headers — do NOT close the connection
        std::ostringstream oss;
        oss << "HTTP/1.1 200 OK\r\n";
        oss << "Content-Type: text/event-stream\r\n";
        oss << "Cache-Control: no-cache\r\n";
        oss << "Connection: keep-alive\r\n";
        oss << "Access-Control-Allow-Origin: *\r\n";
        oss << "Mcp-Session-Id: " << session_id << "\r\n";
        oss << "\r\n";

        auto header_str = oss.str();
        send(client_socket, header_str.c_str(), static_cast<int>(header_str.size()), 0);

        // Register this socket for SSE push
        m_session_mgr->register_sse(session_id, client_socket);

        // Keep connection alive — the push thread will write to it.
        // We block here checking if the server is still running and if the socket is still valid.
        while (m_running.load()) {
            // Check if socket is still alive by attempting a zero-byte recv
            char probe;
            fd_set read_set;
            FD_ZERO(&read_set);
            FD_SET(client_socket, &read_set);
            timeval tv{};
            tv.tv_sec = 2;
            auto sel = select(0, &read_set, nullptr, nullptr, &tv);
            if (sel > 0) {
                // Client sent data or disconnected
                auto r = recv(client_socket, &probe, 1, 0);
                if (r <= 0) break; // Client disconnected
            }
            if (sel == SOCKET_ERROR) break;
        }

        // Client disconnected or server stopping.
        // unregister_sse() closes the socket atomically to prevent the push
        // thread from writing to a closed handle.
        m_session_mgr->unregister_sse(session_id);
        return;
    }

    // DELETE /mcp — close session
    if (req.method == "DELETE") {
        if (!session_id.empty() && m_session_mgr) {
            m_session_mgr->delete_session(session_id);
        }
        send_response(client_socket, 200, "text/plain", "");
        shutdown(client_socket, SD_SEND);
        closesocket(client_socket);
        return;
    }

    send_error(client_socket, 405, "Method Not Allowed. Use POST, GET, or DELETE.");
    shutdown(client_socket, SD_SEND);
    closesocket(client_socket);
}

std::expected<c_http_server::s_parsed_request, std::string> c_http_server::parse_request(const std::string& raw) {
    if (raw.empty()) return std::unexpected("Empty request");

    s_parsed_request req;
    auto line_end = raw.find("\r\n");
    if (line_end == std::string::npos) return std::unexpected("Malformed request line");

    auto request_line = raw.substr(0, line_end);
    auto first_space = request_line.find(' ');
    if (first_space == std::string::npos) return std::unexpected("Malformed request line");
    req.method = request_line.substr(0, first_space);

    auto second_space = request_line.find(' ', first_space + 1);
    if (second_space == std::string::npos) return std::unexpected("Malformed request line");
    req.path = request_line.substr(first_space + 1, second_space - first_space - 1);

    // Strip query string if any
    auto qpos = req.path.find('?');
    if (qpos != std::string::npos) req.path = req.path.substr(0, qpos);

    auto header_end = raw.find("\r\n\r\n");
    if (header_end == std::string::npos) return std::unexpected("Malformed headers");

    auto headers_section = raw.substr(line_end + 2, header_end - line_end - 2);
    std::istringstream stream(headers_section);
    std::string line;
    while (std::getline(stream, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        auto colon = line.find(':');
        if (colon == std::string::npos) continue;
        auto key = line.substr(0, colon);
        auto value = line.substr(colon + 1);
        std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        auto val_start = value.find_first_not_of(" \t");
        if (val_start != std::string::npos) value = value.substr(val_start);
        req.headers[key] = value;
    }

    auto body_start = header_end + 4;
    if (body_start < raw.size()) req.body = raw.substr(body_start);

    return req;
}

void c_http_server::send_response(SOCKET sock, int status, const std::string& content_type,
                                   const std::string& body, const std::string& extra_headers) {
    const char* status_text = "OK";
    switch (status) {
        case 200: status_text = "OK"; break;
        case 202: status_text = "Accepted"; break;
        case 400: status_text = "Bad Request"; break;
        case 404: status_text = "Not Found"; break;
        case 405: status_text = "Method Not Allowed"; break;
        case 500: status_text = "Internal Server Error"; break;
    }

    std::ostringstream oss;
    oss << "HTTP/1.1 " << status << " " << status_text << "\r\n";
    oss << "Content-Type: " << content_type << "\r\n";
    oss << "Content-Length: " << body.size() << "\r\n";
    oss << "Connection: close\r\n";
    oss << "Access-Control-Allow-Origin: *\r\n";
    if (!extra_headers.empty()) oss << extra_headers;
    oss << "\r\n";
    oss << body;

    auto response_str = oss.str();
    auto total = static_cast<int>(response_str.size());
    int sent = 0;
    while (sent < total) {
        auto result = send(sock, response_str.c_str() + sent, total - sent, 0);
        if (result == SOCKET_ERROR) break;
        sent += result;
    }
}

void c_http_server::send_error(SOCKET sock, int status, const std::string& message) {
    nlohmann::json err = {{"error", message}};
    send_response(sock, status, "application/json", err.dump());
}
