#pragma once

#include <string>
#include <nlohmann/json.hpp>

namespace handlers::memmap {
    nlohmann::json list();
    nlohmann::json at(const std::string& address);
}
