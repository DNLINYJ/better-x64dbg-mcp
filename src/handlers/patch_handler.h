#pragma once

#include <string>
#include <nlohmann/json.hpp>

namespace handlers::patches {
    nlohmann::json list();
    nlohmann::json apply(const std::string& address, const std::string& hex_bytes);
    nlohmann::json restore(const std::string& address);
    nlohmann::json export_module(const std::string& module, const std::string& path);
}
