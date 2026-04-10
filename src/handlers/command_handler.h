#pragma once

#include <string>
#include <vector>
#include <nlohmann/json.hpp>

namespace handlers::command {
    nlohmann::json exec(const std::string& command);
    nlohmann::json eval(const std::string& expression);
    nlohmann::json format_str(const std::string& fmt);
    nlohmann::json events();
    nlohmann::json set_init_script(const std::string& file);
    nlohmann::json get_init_script();
    nlohmann::json hash();
    nlohmann::json script(const std::vector<std::string>& commands);
}
