#pragma once

#include <string>
#include <nlohmann/json.hpp>

namespace handlers::annotations {
    nlohmann::json get_label(const std::string& address);
    nlohmann::json set_label(const std::string& address, const std::string& text);
    nlohmann::json get_comment(const std::string& address);
    nlohmann::json set_comment(const std::string& address, const std::string& text);
    nlohmann::json set_bookmark(const std::string& address, bool set);
}
