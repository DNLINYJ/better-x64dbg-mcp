#pragma once

#include <string>
#include <nlohmann/json.hpp>

namespace handlers::controlflow {
    nlohmann::json cfg_function(const std::string& address);
    nlohmann::json branch_dest(const std::string& address);
    nlohmann::json is_jump_taken(const std::string& address);
    nlohmann::json loops(const std::string& address);
    nlohmann::json add_function(const std::string& start, const std::string& end);
    nlohmann::json delete_function(const std::string& address);
    nlohmann::json func_type(const std::string& address);
}
