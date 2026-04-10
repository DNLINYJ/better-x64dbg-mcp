#pragma once

#include <string>
#include <nlohmann/json.hpp>

namespace handlers::memory {
    nlohmann::json read(const std::string& address, size_t size);
    nlohmann::json write(const std::string& address, const std::string& hex_bytes, bool verify);
    nlohmann::json is_valid(const std::string& address);
    nlohmann::json page_info(const std::string& address);
    nlohmann::json allocate(const std::string& size);
    nlohmann::json free_mem(const std::string& address);
    nlohmann::json protect(const std::string& address, const std::string& size, const std::string& protection);
    nlohmann::json is_code(const std::string& address);
    nlohmann::json update_map();
}
