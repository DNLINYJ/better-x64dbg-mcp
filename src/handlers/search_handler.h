#pragma once

#include <string>
#include <nlohmann/json.hpp>

namespace handlers::search {
    nlohmann::json pattern(const nlohmann::json& args);
    nlohmann::json strings(const std::string& address, size_t size);
    nlohmann::json string_at(const std::string& address);
    nlohmann::json autocomplete(const std::string& query);
    nlohmann::json find_strings_module(const std::string& module);
    nlohmann::json encoding(const std::string& address);
}
