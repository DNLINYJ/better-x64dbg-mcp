#pragma once

#include <string>
#include <expected>
#include <cstdint>
#include <mutex>
#include <vector>

#include <nlohmann/json.hpp>
#include "_plugin_types.h"

class c_bridge_executor {
public:
    [[nodiscard]] bool is_debugging() const;
    [[nodiscard]] bool is_running() const;
    [[nodiscard]] std::string get_state_string() const;

    bool exec_command(const std::string& cmd);
    bool exec_command_async(const std::string& cmd);
    [[nodiscard]] bool exec_command_and_wait(const std::string& cmd, int timeout_ms = 5000);

    [[nodiscard]] duint eval_expression(const std::string& expression);
    [[nodiscard]] bool is_valid_expression(const std::string& expression);

    [[nodiscard]] std::expected<std::vector<uint8_t>, std::string> read_memory(duint address, size_t size);
    [[nodiscard]] std::expected<void, std::string> write_memory(duint address, const std::vector<uint8_t>& data);
    [[nodiscard]] bool is_valid_read_ptr(duint address);

    [[nodiscard]] std::expected<REGDUMP, std::string> get_register_dump();
    [[nodiscard]] std::expected<nlohmann::json, std::string> get_memory_map();
    [[nodiscard]] std::expected<nlohmann::json, std::string> get_breakpoint_list(BPXTYPE type);
    [[nodiscard]] std::expected<nlohmann::json, std::string> get_thread_list();

    [[nodiscard]] std::string get_label_at(duint address);
    [[nodiscard]] bool set_label_at(duint address, const std::string& text);
    [[nodiscard]] std::string get_comment_at(duint address);
    [[nodiscard]] bool set_comment_at(duint address, const std::string& text);
    [[nodiscard]] bool set_bookmark_at(duint address, bool set);

    [[nodiscard]] std::expected<nlohmann::json, std::string> disassemble_at(duint address, int count);
    [[nodiscard]] std::expected<nlohmann::json, std::string> get_basic_info(duint address);
    [[nodiscard]] std::expected<nlohmann::json, std::string> get_function_bounds(duint address);

    [[nodiscard]] duint get_module_base(const std::string& name);
    [[nodiscard]] std::string get_module_at(duint address);

    [[nodiscard]] bool require_paused() const;
    [[nodiscard]] bool require_debugging() const;

private:
    mutable std::mutex m_mutex;
    [[nodiscard]] bool wait_for_pause(int timeout_ms);
};

c_bridge_executor& get_bridge();
