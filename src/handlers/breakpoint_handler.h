#pragma once

#include <string>
#include <nlohmann/json.hpp>

namespace handlers::breakpoints {
    nlohmann::json list();
    nlohmann::json get(const std::string& address);
    nlohmann::json set_software(const std::string& address, bool singleshot);
    nlohmann::json set_hardware(const std::string& address, const std::string& type, const std::string& size);
    nlohmann::json set_memory(const std::string& address, const std::string& type);
    nlohmann::json delete_bp(const std::string& address, const std::string& type);
    nlohmann::json enable(const std::string& address);
    nlohmann::json disable(const std::string& address);
    nlohmann::json toggle(const std::string& address);
    nlohmann::json set_condition(const std::string& address, const std::string& condition);
    nlohmann::json set_log(const std::string& address, const std::string& text);
    nlohmann::json reset_hit_count(const std::string& address);
    nlohmann::json configure(const nlohmann::json& args);
    nlohmann::json configure_batch(const nlohmann::json& breakpoints_array);
}
