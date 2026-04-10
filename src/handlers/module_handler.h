#pragma once

#include <string>
#include <nlohmann/json.hpp>

namespace handlers::modules {
    nlohmann::json list();
    nlohmann::json get(const std::string& name);
    nlohmann::json base(const std::string& name);
    nlohmann::json section(const std::string& address);
    nlohmann::json party(const std::string& base);
}
