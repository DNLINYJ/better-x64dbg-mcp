#pragma once

#include <string>
#include <nlohmann/json.hpp>

namespace handlers::symbols {
    nlohmann::json resolve(const std::string& name);
    nlohmann::json at(const std::string& address);
    nlohmann::json search(const std::string& pattern, const std::string& module);
    nlohmann::json list_module(const std::string& module);
}
