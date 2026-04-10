#pragma once

#include <string>
#include <nlohmann/json.hpp>

namespace handlers::exceptions {
    nlohmann::json set_bp(const std::string& code, const std::string& chance);
    nlohmann::json delete_bp(const std::string& code);
    nlohmann::json list_bps();
    nlohmann::json list_codes();
    nlohmann::json skip();
}
