#pragma once

#include <string>
#include <nlohmann/json.hpp>

namespace handlers::registers {
    nlohmann::json get_all();
    nlohmann::json get_single(const std::string& name);
    nlohmann::json set_register(const std::string& name, const std::string& value);
    nlohmann::json get_flags();
    nlohmann::json get_avx512();
}
