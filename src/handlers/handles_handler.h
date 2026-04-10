#pragma once

#include <string>
#include <nlohmann/json.hpp>

namespace handlers::handles {
    nlohmann::json list();
    nlohmann::json get(const std::string& handle);
    nlohmann::json tcp();
    nlohmann::json windows();
    nlohmann::json heaps();
    nlohmann::json close_handle(const std::string& handle);
}
